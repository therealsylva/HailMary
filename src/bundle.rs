use crate::crypto::{parse_encryption_public_key, sign};
use crate::identity::{Identity, PublicIdentity};
use crate::trust::{TrustEntry, TrustStore};
use crate::util::{
    DEFAULT_MAX_BUNDLE_BYTES, atomic_write, canonical_json, read_limited, sha256_hex,
    validate_identifier,
};
use crate::{Error, Result};
use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use base64::Engine;
use chrono::{DateTime, Utc};
use hkdf::Hkdf;
use p256::PublicKey;
use p256::ecdh::{EphemeralSecret, diffie_hellman};
use p256::elliptic_curve::sec1::ToEncodedPoint;
use rand::RngCore;
use rand::rngs::OsRng;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::collections::BTreeSet;
use std::path::Path;
use uuid::Uuid;
use zeroize::Zeroizing;

const BUNDLE_FORMAT: &str = "hailmary.bundle";
const SIGNING_CONTEXT: &[u8] = b"HAILMARY-BUNDLE-SIGNATURE-V1\0";
const PAYLOAD_CONTEXT: &[u8] = b"HAILMARY-BUNDLE-PAYLOAD-V1\0";
const WRAP_CONTEXT: &[u8] = b"HAILMARY-CONTENT-KEY-WRAP-V1\0";

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum BundleKind {
    Hail,
    Mary,
}

impl BundleKind {
    pub fn extension(self) -> &'static str {
        match self {
            Self::Hail => "hail",
            Self::Mary => "mary",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecipientWrap {
    pub identity_id: String,
    pub key_id: String,
    pub ephemeral_public_key: String,
    pub salt: String,
    pub nonce: String,
    pub wrapped_key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProtectedHeader {
    pub bundle_id: String,
    pub job_id: String,
    pub kind: BundleKind,
    pub sender: String,
    pub created_at: DateTime<Utc>,
    pub not_before: Option<DateTime<Utc>>,
    pub expires_at: DateTime<Utc>,
    pub sequence: u64,
    pub payload_sha256: String,
    pub payload_nonce: String,
    pub cipher: String,
    pub key_agreement: String,
    pub signature_algorithm: String,
    pub recipients: Vec<RecipientWrap>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BundleSignature {
    pub key_id: String,
    pub identity_id: String,
    pub value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Bundle {
    pub format: String,
    pub version: u32,
    pub protected: ProtectedHeader,
    pub ciphertext: String,
    pub signatures: Vec<BundleSignature>,
}

impl Bundle {
    #[allow(clippy::too_many_arguments)]
    pub fn seal<T: Serialize>(
        kind: BundleKind,
        job_id: &str,
        sender: &Identity,
        recipients: &[PublicIdentity],
        payload: &T,
        sequence: u64,
        created_at: DateTime<Utc>,
        not_before: Option<DateTime<Utc>>,
        expires_at: DateTime<Utc>,
    ) -> Result<Self> {
        validate_identifier(job_id, "job ID")?;
        if recipients.is_empty() {
            return Err(Error::InvalidInput(
                "a bundle requires at least one recipient".into(),
            ));
        }
        if expires_at <= created_at || not_before.is_some_and(|value| value >= expires_at) {
            return Err(Error::InvalidInput("invalid bundle validity period".into()));
        }
        let plaintext = canonical_json(payload)?;
        if plaintext.len() as u64 > DEFAULT_MAX_BUNDLE_BYTES {
            return Err(Error::InvalidInput(format!(
                "bundle payload exceeds the {DEFAULT_MAX_BUNDLE_BYTES} byte limit"
            )));
        }
        let bundle_id = Uuid::new_v4().to_string();
        let mut content_key = Zeroizing::new([0_u8; 32]);
        OsRng.fill_bytes(content_key.as_mut());

        let mut seen = BTreeSet::new();
        let mut wraps = Vec::with_capacity(recipients.len());
        for recipient in recipients {
            recipient.validate()?;
            if !seen.insert(&recipient.encryption.key_id) {
                return Err(Error::InvalidInput(format!(
                    "duplicate recipient key {}",
                    recipient.encryption.key_id
                )));
            }
            wraps.push(wrap_content_key(&bundle_id, recipient, &content_key)?);
        }
        wraps.sort_by(|left, right| left.key_id.cmp(&right.key_id));

        let mut payload_nonce = [0_u8; 12];
        OsRng.fill_bytes(&mut payload_nonce);
        let protected = ProtectedHeader {
            bundle_id,
            job_id: job_id.into(),
            kind,
            sender: sender.public.identity_id.clone(),
            created_at,
            not_before,
            expires_at,
            sequence,
            payload_sha256: sha256_hex(&plaintext),
            payload_nonce: base64::engine::general_purpose::STANDARD.encode(payload_nonce),
            cipher: "aes-256-gcm".into(),
            key_agreement: "ecdh-p256-hkdf-sha256".into(),
            signature_algorithm: "ecdsa-p256-sha256".into(),
            recipients: wraps,
        };
        let aad = payload_aad(&protected)?;
        let cipher = Aes256Gcm::new_from_slice(content_key.as_ref())
            .map_err(|_| Error::Crypto("could not initialize payload cipher".into()))?;
        let nonce_value = Nonce::from(payload_nonce);
        let ciphertext = cipher
            .encrypt(
                &nonce_value,
                Payload {
                    msg: &plaintext,
                    aad: &aad,
                },
            )
            .map_err(|_| Error::Crypto("bundle payload encryption failed".into()))?;
        let mut bundle = Self {
            format: BUNDLE_FORMAT.into(),
            version: 1,
            protected,
            ciphertext: base64::engine::general_purpose::STANDARD.encode(ciphertext),
            signatures: Vec::new(),
        };
        bundle.add_signature(sender)?;
        Ok(bundle)
    }

    pub fn read(path: &Path) -> Result<Self> {
        let bundle: Self = serde_json::from_slice(&read_limited(path, DEFAULT_MAX_BUNDLE_BYTES)?)?;
        bundle.validate_structure()?;
        Ok(bundle)
    }

    pub fn write(&self, path: &Path) -> Result<()> {
        self.validate_structure()?;
        atomic_write(path, &canonical_json(self)?, false)
    }

    pub fn validate_structure(&self) -> Result<()> {
        if self.format != BUNDLE_FORMAT || self.version != 1 {
            return Err(Error::InvalidInput("unsupported bundle format".into()));
        }
        validate_identifier(&self.protected.bundle_id, "bundle ID")?;
        validate_identifier(&self.protected.job_id, "job ID")?;
        validate_identifier(&self.protected.sender, "sender ID")?;
        if self.protected.cipher != "aes-256-gcm"
            || self.protected.key_agreement != "ecdh-p256-hkdf-sha256"
            || self.protected.signature_algorithm != "ecdsa-p256-sha256"
        {
            return Err(Error::Crypto("unsupported bundle algorithm suite".into()));
        }
        if self.protected.recipients.is_empty() || self.signatures.is_empty() {
            return Err(Error::InvalidInput(
                "bundle is missing recipients or signatures".into(),
            ));
        }
        let mut recipients = BTreeSet::new();
        for recipient in &self.protected.recipients {
            validate_identifier(&recipient.identity_id, "recipient identity ID")?;
            if !recipients.insert(&recipient.key_id) {
                return Err(Error::InvalidInput("duplicate bundle recipient".into()));
            }
        }
        let mut signatures = BTreeSet::new();
        for signature in &self.signatures {
            if !signatures.insert(&signature.key_id) {
                return Err(Error::InvalidInput("duplicate bundle signature".into()));
            }
        }
        decode_b64(&self.ciphertext, "ciphertext")?;
        Ok(())
    }

    pub fn validate_time(&self, at: DateTime<Utc>) -> Result<()> {
        if at
            < self
                .protected
                .not_before
                .unwrap_or(self.protected.created_at)
        {
            return Err(Error::NotYetValid(
                self.protected
                    .not_before
                    .unwrap_or(self.protected.created_at)
                    .to_rfc3339(),
            ));
        }
        if at > self.protected.expires_at {
            return Err(Error::Expired);
        }
        Ok(())
    }

    pub fn add_signature(&mut self, signer: &Identity) -> Result<()> {
        if self
            .signatures
            .iter()
            .any(|signature| signature.key_id == signer.public.signing.key_id)
        {
            return Err(Error::InvalidInput(
                "this identity has already signed the bundle".into(),
            ));
        }
        let message = self.signature_message()?;
        let value = sign(signer.signing_key(), &message);
        self.signatures.push(BundleSignature {
            key_id: signer.public.signing.key_id.clone(),
            identity_id: signer.public.identity_id.clone(),
            value: base64::engine::general_purpose::STANDARD.encode(value),
        });
        self.signatures
            .sort_by(|left, right| left.key_id.cmp(&right.key_id));
        Ok(())
    }

    pub fn verify_signatures<'a>(&self, trust: &'a TrustStore) -> Result<Vec<&'a TrustEntry>> {
        let message = self.signature_message()?;
        let mut verified = Vec::new();
        for signature in &self.signatures {
            let bytes = decode_b64(&signature.value, "signature")?;
            let entry = trust.verify_signature(&signature.key_id, &message, &bytes)?;
            if entry.identity.identity_id != signature.identity_id {
                return Err(Error::Authentication(
                    "signature identity does not match trusted identity".into(),
                ));
            }
            verified.push(entry);
        }
        if !verified
            .iter()
            .any(|entry| entry.identity.identity_id == self.protected.sender)
        {
            return Err(Error::Authentication(
                "bundle sender did not provide a trusted signature".into(),
            ));
        }
        Ok(verified)
    }

    pub fn decrypt<T: DeserializeOwned>(&self, recipient: &Identity) -> Result<T> {
        self.validate_structure()?;
        let key_id = &recipient.public.encryption.key_id;
        let wrap = self
            .protected
            .recipients
            .iter()
            .find(|wrap| &wrap.key_id == key_id)
            .ok_or_else(|| Error::Authentication("identity is not a bundle recipient".into()))?;
        if wrap.identity_id != recipient.public.identity_id {
            return Err(Error::Authentication(
                "recipient identity and encryption key do not match".into(),
            ));
        }
        let content_key = unwrap_content_key(&self.protected.bundle_id, wrap, recipient)?;
        let nonce = decode_fixed::<12>(&self.protected.payload_nonce, "payload nonce")?;
        let ciphertext = decode_b64(&self.ciphertext, "ciphertext")?;
        let cipher = Aes256Gcm::new_from_slice(content_key.as_ref())
            .map_err(|_| Error::Crypto("could not initialize payload cipher".into()))?;
        let nonce_value = Nonce::from(nonce);
        let plaintext = cipher
            .decrypt(
                &nonce_value,
                Payload {
                    msg: &ciphertext,
                    aad: &payload_aad(&self.protected)?,
                },
            )
            .map_err(|_| Error::Authentication("bundle decryption failed".into()))?;
        if sha256_hex(&plaintext) != self.protected.payload_sha256 {
            return Err(Error::Crypto("bundle payload digest mismatch".into()));
        }
        Ok(serde_json::from_slice(&plaintext)?)
    }

    pub fn kind(&self) -> BundleKind {
        self.protected.kind
    }

    fn signature_message(&self) -> Result<Vec<u8>> {
        let ciphertext = decode_b64(&self.ciphertext, "ciphertext")?;
        let protected = canonical_json(&self.protected)?;
        let mut message =
            Vec::with_capacity(SIGNING_CONTEXT.len() + protected.len() + ciphertext.len());
        message.extend_from_slice(SIGNING_CONTEXT);
        message.extend_from_slice(&protected);
        message.extend_from_slice(&ciphertext);
        Ok(message)
    }
}

fn payload_aad(protected: &ProtectedHeader) -> Result<Vec<u8>> {
    let encoded = canonical_json(protected)?;
    let mut aad = Vec::with_capacity(PAYLOAD_CONTEXT.len() + encoded.len());
    aad.extend_from_slice(PAYLOAD_CONTEXT);
    aad.extend_from_slice(&encoded);
    Ok(aad)
}

fn wrap_aad(bundle_id: &str, identity_id: &str, key_id: &str) -> Vec<u8> {
    let mut aad = Vec::new();
    aad.extend_from_slice(WRAP_CONTEXT);
    aad.extend_from_slice(bundle_id.as_bytes());
    aad.push(0);
    aad.extend_from_slice(identity_id.as_bytes());
    aad.push(0);
    aad.extend_from_slice(key_id.as_bytes());
    aad
}

fn wrap_content_key(
    bundle_id: &str,
    recipient: &PublicIdentity,
    content_key: &[u8; 32],
) -> Result<RecipientWrap> {
    let public = parse_encryption_public_key(&recipient.encryption.der()?)?;
    let ephemeral = EphemeralSecret::random(&mut OsRng);
    let ephemeral_public = PublicKey::from(&ephemeral);
    let shared = ephemeral.diffie_hellman(&public);
    let mut salt = [0_u8; 32];
    let mut nonce = [0_u8; 12];
    OsRng.fill_bytes(&mut salt);
    OsRng.fill_bytes(&mut nonce);
    let key = derive_wrap_key(
        shared.raw_secret_bytes().as_ref(),
        &salt,
        bundle_id,
        &recipient.identity_id,
        &recipient.encryption.key_id,
    )?;
    let cipher = Aes256Gcm::new_from_slice(key.as_ref())
        .map_err(|_| Error::Crypto("could not initialize key-wrap cipher".into()))?;
    let nonce_value = Nonce::from(nonce);
    let wrapped = cipher
        .encrypt(
            &nonce_value,
            Payload {
                msg: content_key,
                aad: &wrap_aad(
                    bundle_id,
                    &recipient.identity_id,
                    &recipient.encryption.key_id,
                ),
            },
        )
        .map_err(|_| Error::Crypto("content-key wrapping failed".into()))?;
    Ok(RecipientWrap {
        identity_id: recipient.identity_id.clone(),
        key_id: recipient.encryption.key_id.clone(),
        ephemeral_public_key: base64::engine::general_purpose::STANDARD
            .encode(ephemeral_public.to_encoded_point(true).as_bytes()),
        salt: base64::engine::general_purpose::STANDARD.encode(salt),
        nonce: base64::engine::general_purpose::STANDARD.encode(nonce),
        wrapped_key: base64::engine::general_purpose::STANDARD.encode(wrapped),
    })
}

fn unwrap_content_key(
    bundle_id: &str,
    wrap: &RecipientWrap,
    recipient: &Identity,
) -> Result<Zeroizing<[u8; 32]>> {
    let ephemeral_bytes = decode_b64(&wrap.ephemeral_public_key, "ephemeral public key")?;
    let ephemeral_public = PublicKey::from_sec1_bytes(&ephemeral_bytes)
        .map_err(|_| Error::Crypto("invalid ephemeral public key".into()))?;
    let shared = diffie_hellman(
        recipient.encryption_key().to_nonzero_scalar(),
        ephemeral_public.as_affine(),
    );
    let salt = decode_fixed::<32>(&wrap.salt, "key-wrap salt")?;
    let nonce = decode_fixed::<12>(&wrap.nonce, "key-wrap nonce")?;
    let wrapped = decode_b64(&wrap.wrapped_key, "wrapped content key")?;
    let key = derive_wrap_key(
        shared.raw_secret_bytes().as_ref(),
        &salt,
        bundle_id,
        &wrap.identity_id,
        &wrap.key_id,
    )?;
    let cipher = Aes256Gcm::new_from_slice(key.as_ref())
        .map_err(|_| Error::Crypto("could not initialize key-wrap cipher".into()))?;
    let nonce_value = Nonce::from(nonce);
    let unwrapped = Zeroizing::new(
        cipher
            .decrypt(
                &nonce_value,
                Payload {
                    msg: &wrapped,
                    aad: &wrap_aad(bundle_id, &wrap.identity_id, &wrap.key_id),
                },
            )
            .map_err(|_| Error::Authentication("content-key unwrapping failed".into()))?,
    );
    if unwrapped.len() != 32 {
        return Err(Error::Crypto("invalid unwrapped content key".into()));
    }
    let mut result = Zeroizing::new([0_u8; 32]);
    result.copy_from_slice(&unwrapped);
    Ok(result)
}

fn derive_wrap_key(
    shared: &[u8],
    salt: &[u8],
    bundle_id: &str,
    identity_id: &str,
    key_id: &str,
) -> Result<Zeroizing<[u8; 32]>> {
    let mut info = Vec::new();
    info.extend_from_slice(WRAP_CONTEXT);
    info.extend_from_slice(bundle_id.as_bytes());
    info.push(0);
    info.extend_from_slice(identity_id.as_bytes());
    info.push(0);
    info.extend_from_slice(key_id.as_bytes());
    let mut key = Zeroizing::new([0_u8; 32]);
    Hkdf::<Sha256>::new(Some(salt), shared)
        .expand(&info, key.as_mut())
        .map_err(|_| Error::Crypto("HKDF expansion failed".into()))?;
    Ok(key)
}

fn decode_b64(value: &str, field: &str) -> Result<Vec<u8>> {
    base64::engine::general_purpose::STANDARD
        .decode(value)
        .map_err(|_| Error::InvalidInput(format!("invalid base64 in {field}")))
}

fn decode_fixed<const N: usize>(value: &str, field: &str) -> Result<[u8; N]> {
    let decoded = decode_b64(value, field)?;
    decoded
        .try_into()
        .map_err(|_| Error::InvalidInput(format!("invalid length for {field}")))
}
