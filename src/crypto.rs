use crate::util::{canonical_json, sha256_hex};
use crate::{Error, Result};
use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use argon2::{Algorithm, Argon2, Params, Version};
use base64::Engine;
use p256::ecdsa::signature::{Signer, Verifier};
use p256::ecdsa::{Signature, SigningKey, VerifyingKey};
use p256::pkcs8::{DecodePrivateKey, DecodePublicKey, EncodePrivateKey, EncodePublicKey};
use p256::{PublicKey, SecretKey};
use rand::RngCore;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

const PRIVATE_KEY_FORMAT: &str = "hailmary.private-key";
const KDF_MEMORY_KIB: u32 = 65_536;
const KDF_ITERATIONS: u32 = 3;
const KDF_LANES: u32 = 1;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum KeyPurpose {
    Signing,
    Encryption,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct EncryptedPrivateKey {
    format: String,
    version: u32,
    purpose: KeyPurpose,
    key_id: String,
    public_key: String,
    kdf: KdfHeader,
    cipher: CipherHeader,
    ciphertext: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct KdfHeader {
    algorithm: String,
    memory_kib: u32,
    iterations: u32,
    lanes: u32,
    salt: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CipherHeader {
    algorithm: String,
    nonce: String,
}

pub fn public_key_id(der: &[u8]) -> String {
    format!("sha256:{}", sha256_hex(der))
}

pub fn signing_public_der(key: &SigningKey) -> Result<Vec<u8>> {
    key.verifying_key()
        .to_public_key_der()
        .map(|document| document.as_bytes().to_vec())
        .map_err(|error| Error::Crypto(error.to_string()))
}

pub fn encryption_public_der(key: &SecretKey) -> Result<Vec<u8>> {
    key.public_key()
        .to_public_key_der()
        .map(|document| document.as_bytes().to_vec())
        .map_err(|error| Error::Crypto(error.to_string()))
}

pub fn parse_verifying_key(der: &[u8]) -> Result<VerifyingKey> {
    VerifyingKey::from_public_key_der(der).map_err(|error| Error::Crypto(error.to_string()))
}

pub fn parse_encryption_public_key(der: &[u8]) -> Result<PublicKey> {
    PublicKey::from_public_key_der(der).map_err(|error| Error::Crypto(error.to_string()))
}

pub fn sign(key: &SigningKey, message: &[u8]) -> Vec<u8> {
    let signature: Signature = key.sign(message);
    signature.to_der().as_bytes().to_vec()
}

pub fn verify(key: &VerifyingKey, message: &[u8], signature: &[u8]) -> Result<()> {
    let signature = Signature::from_der(signature)
        .map_err(|_| Error::Authentication("malformed ECDSA signature".into()))?;
    key.verify(message, &signature)
        .map_err(|_| Error::Authentication("signature verification failed".into()))
}

pub fn encrypt_signing_key(key: &SigningKey, password: &[u8]) -> Result<Vec<u8>> {
    let private = key
        .to_pkcs8_der()
        .map_err(|error| Error::Crypto(error.to_string()))?;
    let public = signing_public_der(key)?;
    encrypt_private_key(KeyPurpose::Signing, private.as_bytes(), &public, password)
}

pub fn encrypt_encryption_key(key: &SecretKey, password: &[u8]) -> Result<Vec<u8>> {
    let private = key
        .to_pkcs8_der()
        .map_err(|error| Error::Crypto(error.to_string()))?;
    let public = encryption_public_der(key)?;
    encrypt_private_key(
        KeyPurpose::Encryption,
        private.as_bytes(),
        &public,
        password,
    )
}

fn encrypt_private_key(
    purpose: KeyPurpose,
    private_der: &[u8],
    public_der: &[u8],
    password: &[u8],
) -> Result<Vec<u8>> {
    if password.len() < 12 {
        return Err(Error::InvalidInput(
            "private-key password must contain at least 12 bytes".into(),
        ));
    }
    let mut salt = [0_u8; 16];
    let mut nonce = [0_u8; 12];
    OsRng.fill_bytes(&mut salt);
    OsRng.fill_bytes(&mut nonce);
    let key = derive_password_key(password, &salt)?;
    let cipher = Aes256Gcm::new_from_slice(key.as_ref())
        .map_err(|_| Error::Crypto("could not initialize AES-256-GCM".into()))?;
    let key_id = public_key_id(public_der);
    let aad = format!("{PRIVATE_KEY_FORMAT}\0{key_id}\0{purpose:?}");
    let nonce_value = Nonce::from(nonce);
    let ciphertext = cipher
        .encrypt(
            &nonce_value,
            Payload {
                msg: private_der,
                aad: aad.as_bytes(),
            },
        )
        .map_err(|_| Error::Crypto("private-key encryption failed".into()))?;
    let record = EncryptedPrivateKey {
        format: PRIVATE_KEY_FORMAT.into(),
        version: 1,
        purpose,
        key_id,
        public_key: base64::engine::general_purpose::STANDARD.encode(public_der),
        kdf: KdfHeader {
            algorithm: "argon2id-v1.3".into(),
            memory_kib: KDF_MEMORY_KIB,
            iterations: KDF_ITERATIONS,
            lanes: KDF_LANES,
            salt: base64::engine::general_purpose::STANDARD.encode(salt),
        },
        cipher: CipherHeader {
            algorithm: "aes-256-gcm".into(),
            nonce: base64::engine::general_purpose::STANDARD.encode(nonce),
        },
        ciphertext: base64::engine::general_purpose::STANDARD.encode(ciphertext),
    };
    canonical_json(&record)
}

pub fn decrypt_signing_key(contents: &[u8], password: &[u8]) -> Result<SigningKey> {
    let (purpose, private) = decrypt_private_key(contents, password)?;
    if purpose != KeyPurpose::Signing {
        return Err(Error::Crypto("expected a signing key".into()));
    }
    SigningKey::from_pkcs8_der(&private).map_err(|error| Error::Crypto(error.to_string()))
}

pub fn decrypt_encryption_key(contents: &[u8], password: &[u8]) -> Result<SecretKey> {
    let (purpose, private) = decrypt_private_key(contents, password)?;
    if purpose != KeyPurpose::Encryption {
        return Err(Error::Crypto("expected an encryption key".into()));
    }
    SecretKey::from_pkcs8_der(&private).map_err(|error| Error::Crypto(error.to_string()))
}

fn decrypt_private_key(
    contents: &[u8],
    password: &[u8],
) -> Result<(KeyPurpose, Zeroizing<Vec<u8>>)> {
    let record: EncryptedPrivateKey = serde_json::from_slice(contents)?;
    if record.format != PRIVATE_KEY_FORMAT
        || record.version != 1
        || record.kdf.algorithm != "argon2id-v1.3"
        || record.cipher.algorithm != "aes-256-gcm"
    {
        return Err(Error::Crypto("unsupported private-key format".into()));
    }
    if !(16_384..=262_144).contains(&record.kdf.memory_kib)
        || !(1..=10).contains(&record.kdf.iterations)
        || !(1..=8).contains(&record.kdf.lanes)
    {
        return Err(Error::Crypto(
            "private-key KDF parameters are outside permitted limits".into(),
        ));
    }
    let decode = |value: &str| {
        base64::engine::general_purpose::STANDARD
            .decode(value)
            .map_err(|_| Error::Crypto("invalid base64 in private-key file".into()))
    };
    let salt = decode(&record.kdf.salt)?;
    if !(16..=64).contains(&salt.len()) {
        return Err(Error::Crypto("invalid private-key salt length".into()));
    }
    let nonce: [u8; 12] = decode(&record.cipher.nonce)?
        .try_into()
        .map_err(|_| Error::Crypto("invalid private-key nonce length".into()))?;
    let public = decode(&record.public_key)?;
    let ciphertext = decode(&record.ciphertext)?;
    if public_key_id(&public) != record.key_id {
        return Err(Error::Crypto("private-key metadata is inconsistent".into()));
    }
    let params = Params::new(
        record.kdf.memory_kib,
        record.kdf.iterations,
        record.kdf.lanes,
        Some(32),
    )
    .map_err(|error| Error::Crypto(error.to_string()))?;
    let mut derived = Zeroizing::new([0_u8; 32]);
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(password, &salt, derived.as_mut())
        .map_err(|error| Error::Crypto(error.to_string()))?;
    let cipher = Aes256Gcm::new_from_slice(derived.as_ref())
        .map_err(|_| Error::Crypto("could not initialize AES-256-GCM".into()))?;
    let aad = format!(
        "{PRIVATE_KEY_FORMAT}\0{}\0{:?}",
        record.key_id, record.purpose
    );
    let nonce_value = Nonce::from(nonce);
    let private = cipher
        .decrypt(
            &nonce_value,
            Payload {
                msg: &ciphertext,
                aad: aad.as_bytes(),
            },
        )
        .map_err(|_| Error::Authentication("incorrect password or corrupted private key".into()))?;
    Ok((record.purpose, Zeroizing::new(private)))
}

fn derive_password_key(password: &[u8], salt: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
    let params = Params::new(KDF_MEMORY_KIB, KDF_ITERATIONS, KDF_LANES, Some(32))
        .map_err(|error| Error::Crypto(error.to_string()))?;
    let mut key = Zeroizing::new([0_u8; 32]);
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(password, salt, key.as_mut())
        .map_err(|error| Error::Crypto(error.to_string()))?;
    Ok(key)
}

pub fn decode_public_der(value: &str) -> Result<Vec<u8>> {
    base64::engine::general_purpose::STANDARD
        .decode(value)
        .map_err(|_| Error::Crypto("invalid public-key encoding".into()))
}

pub fn encode_public_der(value: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(value)
}

pub fn clear_password(password: &mut Vec<u8>) {
    password.zeroize();
}
