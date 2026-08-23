use crate::crypto::{
    decode_public_der, decrypt_encryption_key, decrypt_signing_key, encode_public_der,
    encrypt_encryption_key, encrypt_signing_key, encryption_public_der, public_key_id,
    signing_public_der,
};
use crate::util::{atomic_write, canonical_json, now, read_limited, validate_identifier};
use crate::{Error, Result};
use chrono::{DateTime, Utc};
use p256::ecdsa::SigningKey;
use p256::{PublicKey, SecretKey};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

const PUBLIC_IDENTITY_FORMAT: &str = "hailmary.public-identity";
const SIGNING_KEY_FILE: &str = "signing.hmk";
const ENCRYPTION_KEY_FILE: &str = "encryption.hmk";
const PUBLIC_FILE: &str = "identity.hmpub";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PublicKeyRecord {
    pub key_id: String,
    pub algorithm: String,
    pub public_key: String,
}

impl PublicKeyRecord {
    pub fn der(&self) -> Result<Vec<u8>> {
        let der = decode_public_der(&self.public_key)?;
        if public_key_id(&der) != self.key_id {
            return Err(Error::Crypto("public-key fingerprint mismatch".into()));
        }
        Ok(der)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PublicIdentity {
    pub format: String,
    pub version: u32,
    pub identity_id: String,
    pub created_at: DateTime<Utc>,
    pub signing: PublicKeyRecord,
    pub encryption: PublicKeyRecord,
}

impl PublicIdentity {
    pub fn read(path: &Path) -> Result<Self> {
        let identity: Self = serde_json::from_slice(&read_limited(path, 1024 * 1024)?)?;
        identity.validate()?;
        Ok(identity)
    }

    pub fn validate(&self) -> Result<()> {
        if self.format != PUBLIC_IDENTITY_FORMAT || self.version != 1 {
            return Err(Error::InvalidInput(
                "unsupported public identity format".into(),
            ));
        }
        validate_identifier(&self.identity_id, "identity ID")?;
        if self.signing.algorithm != "ecdsa-p256-sha256"
            || self.encryption.algorithm != "ecdh-p256-hkdf-sha256"
        {
            return Err(Error::Crypto("unsupported identity algorithm".into()));
        }
        let signing = self.signing.der()?;
        crate::crypto::parse_verifying_key(&signing)?;
        let encryption = self.encryption.der()?;
        crate::crypto::parse_encryption_public_key(&encryption)?;
        Ok(())
    }

    pub fn encryption_public_key(&self) -> Result<PublicKey> {
        crate::crypto::parse_encryption_public_key(&self.encryption.der()?)
    }
}

pub struct Identity {
    pub public: PublicIdentity,
    signing: SigningKey,
    encryption: SecretKey,
}

impl Identity {
    pub fn generate(
        identity_id: &str,
        directory: &Path,
        password: &[u8],
    ) -> Result<PublicIdentity> {
        validate_identifier(identity_id, "identity ID")?;
        if directory.exists() && directory.read_dir()?.next().is_some() {
            return Err(Error::InvalidInput(format!(
                "identity directory {} is not empty",
                directory.display()
            )));
        }
        fs::create_dir_all(directory)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(directory, fs::Permissions::from_mode(0o700))?;
        }
        let signing = SigningKey::random(&mut OsRng);
        let encryption = SecretKey::random(&mut OsRng);
        let signing_der = signing_public_der(&signing)?;
        let encryption_der = encryption_public_der(&encryption)?;
        let public = PublicIdentity {
            format: PUBLIC_IDENTITY_FORMAT.into(),
            version: 1,
            identity_id: identity_id.into(),
            created_at: now(),
            signing: PublicKeyRecord {
                key_id: public_key_id(&signing_der),
                algorithm: "ecdsa-p256-sha256".into(),
                public_key: encode_public_der(&signing_der),
            },
            encryption: PublicKeyRecord {
                key_id: public_key_id(&encryption_der),
                algorithm: "ecdh-p256-hkdf-sha256".into(),
                public_key: encode_public_der(&encryption_der),
            },
        };
        atomic_write(
            &directory.join(SIGNING_KEY_FILE),
            &encrypt_signing_key(&signing, password)?,
            true,
        )?;
        atomic_write(
            &directory.join(ENCRYPTION_KEY_FILE),
            &encrypt_encryption_key(&encryption, password)?,
            true,
        )?;
        atomic_write(
            &directory.join(PUBLIC_FILE),
            &canonical_json(&public)?,
            false,
        )?;
        Ok(public)
    }

    pub fn load(directory: &Path, password: &[u8]) -> Result<Self> {
        let public = PublicIdentity::read(&directory.join(PUBLIC_FILE))?;
        let signing = decrypt_signing_key(
            &read_limited(&directory.join(SIGNING_KEY_FILE), 1024 * 1024)?,
            password,
        )?;
        let encryption = decrypt_encryption_key(
            &read_limited(&directory.join(ENCRYPTION_KEY_FILE), 1024 * 1024)?,
            password,
        )?;
        if signing_public_der(&signing)? != public.signing.der()?
            || encryption_public_der(&encryption)? != public.encryption.der()?
        {
            return Err(Error::Crypto(
                "identity public and private keys do not match".into(),
            ));
        }
        Ok(Self {
            public,
            signing,
            encryption,
        })
    }

    pub fn signing_key(&self) -> &SigningKey {
        &self.signing
    }

    pub fn encryption_key(&self) -> &SecretKey {
        &self.encryption
    }

    pub fn public_path(directory: &Path) -> PathBuf {
        directory.join(PUBLIC_FILE)
    }
}
