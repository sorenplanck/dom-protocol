#![forbid(unsafe_code)]

//! Versioned Option A at-rest envelope boundary.
//!
//! The profile preserves DOM Wallet continuity properties—Argon2id password
//! hardening, authenticated encryption, versioning, bounded parameters and
//! atomic caller-owned publication—without exposing raw keys across layers.

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce};
use hkdf::Hkdf;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt;
use thiserror::Error;
use zeroize::Zeroizing;

pub const PROFILE_NAME: &str = "HARDENED_DOM_WALLET_CONTINUITY_V1";
pub const ENVELOPE_MAGIC: [u8; 8] = *b"DOMWV3A1";
pub const ENVELOPE_VERSION: u16 = 1;
pub const MAX_ENVELOPE_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_KDF_MEMORY_KIB: u32 = 256 * 1024;
pub const MAX_KDF_TIME_COST: u32 = 10;
pub const MAX_KDF_PARALLELISM: u32 = 8;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct KdfParameters {
    pub memory_kib: u32,
    pub time_cost: u32,
    pub parallelism: u32,
}

impl KdfParameters {
    pub const DOM_CONTINUITY: Self = Self {
        memory_kib: 65_536,
        time_cost: 3,
        parallelism: 1,
    };
    pub const TEST: Self = Self {
        memory_kib: 64,
        time_cost: 1,
        parallelism: 1,
    };

    pub fn validate(self) -> Result<(), CryptoError> {
        if self.memory_kib == 0
            || self.memory_kib > MAX_KDF_MEMORY_KIB
            || self.time_cost == 0
            || self.time_cost > MAX_KDF_TIME_COST
            || self.parallelism == 0
            || self.parallelism > MAX_KDF_PARALLELISM
        {
            return Err(CryptoError::KdfParametersOutOfBounds);
        }
        Ok(())
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct SecretBytes(Zeroizing<Vec<u8>>);

impl SecretBytes {
    pub fn random(len: usize) -> Result<Self, CryptoError> {
        if len == 0 || len > 4096 {
            return Err(CryptoError::InvalidSecretLength);
        }
        let mut bytes = Zeroizing::new(vec![0; len]);
        rand::rngs::OsRng
            .try_fill_bytes(&mut bytes)
            .map_err(|_| CryptoError::RandomnessUnavailable)?;
        Ok(Self(bytes))
    }

    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self, CryptoError> {
        if bytes.is_empty() || bytes.len() > 4096 {
            return Err(CryptoError::InvalidSecretLength);
        }
        Ok(Self(Zeroizing::new(bytes)))
    }

    pub fn expose_for_crypto(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretBytes([REDACTED])")
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EnvelopeHeader {
    pub magic: [u8; 8],
    pub envelope_version: u16,
    pub profile: String,
    pub kdf: KdfParameters,
    pub salt: [u8; 32],
    pub nonce: [u8; 12],
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EncryptedEnvelope {
    pub header: EnvelopeHeader,
    pub ciphertext: Vec<u8>,
}

pub fn seal(
    plaintext: &[u8],
    password: &str,
    canonical_context: &[u8],
    kdf: KdfParameters,
) -> Result<EncryptedEnvelope, CryptoError> {
    if plaintext.len() > MAX_ENVELOPE_BYTES || password.is_empty() || canonical_context.is_empty() {
        return Err(CryptoError::InvalidInput);
    }
    kdf.validate()?;
    let mut salt = [0u8; 32];
    let mut nonce = [0u8; 12];
    rand::rngs::OsRng
        .try_fill_bytes(&mut salt)
        .map_err(|_| CryptoError::RandomnessUnavailable)?;
    rand::rngs::OsRng
        .try_fill_bytes(&mut nonce)
        .map_err(|_| CryptoError::RandomnessUnavailable)?;
    let key = derive_key(password, &salt, kdf)?;
    let header = EnvelopeHeader {
        magic: ENVELOPE_MAGIC,
        envelope_version: ENVELOPE_VERSION,
        profile: PROFILE_NAME.into(),
        kdf,
        salt,
        nonce,
    };
    let aad = envelope_aad(&header, canonical_context)?;
    let cipher = ChaCha20Poly1305::new_from_slice(key.expose_for_crypto())
        .map_err(|_| CryptoError::EncryptionFailed)?;
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad: &aad,
            },
        )
        .map_err(|_| CryptoError::EncryptionFailed)?;
    Ok(EncryptedEnvelope { header, ciphertext })
}

pub fn open(
    envelope: &EncryptedEnvelope,
    password: &str,
    canonical_context: &[u8],
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    if password.is_empty()
        || canonical_context.is_empty()
        || envelope.ciphertext.len() > MAX_ENVELOPE_BYTES
    {
        return Err(CryptoError::InvalidInput);
    }
    validate_header(&envelope.header)?;
    let key = derive_key(password, &envelope.header.salt, envelope.header.kdf)?;
    let aad = envelope_aad(&envelope.header, canonical_context)?;
    let cipher = ChaCha20Poly1305::new_from_slice(key.expose_for_crypto())
        .map_err(|_| CryptoError::DecryptionFailed)?;
    let plaintext = cipher
        .decrypt(
            Nonce::from_slice(&envelope.header.nonce),
            Payload {
                msg: &envelope.ciphertext,
                aad: &aad,
            },
        )
        .map_err(|_| CryptoError::AuthenticationFailed)?;
    if plaintext.len() > MAX_ENVELOPE_BYTES {
        return Err(CryptoError::EnvelopeTooLarge);
    }
    Ok(Zeroizing::new(plaintext))
}

pub fn encode(envelope: &EncryptedEnvelope) -> Result<Vec<u8>, CryptoError> {
    let encoded = serde_json::to_vec(envelope).map_err(|_| CryptoError::CanonicalEncoding)?;
    if encoded.len() > MAX_ENVELOPE_BYTES {
        return Err(CryptoError::EnvelopeTooLarge);
    }
    Ok(encoded)
}

pub fn decode(encoded: &[u8]) -> Result<EncryptedEnvelope, CryptoError> {
    if encoded.is_empty() || encoded.len() > MAX_ENVELOPE_BYTES {
        return Err(CryptoError::EnvelopeTooLarge);
    }
    let envelope: EncryptedEnvelope =
        serde_json::from_slice(encoded).map_err(|_| CryptoError::CanonicalEncoding)?;
    validate_header(&envelope.header)?;
    Ok(envelope)
}

fn validate_header(header: &EnvelopeHeader) -> Result<(), CryptoError> {
    if header.magic != ENVELOPE_MAGIC
        || header.envelope_version != ENVELOPE_VERSION
        || header.profile != PROFILE_NAME
    {
        return Err(CryptoError::UnsupportedVersion);
    }
    header.kdf.validate()
}

fn derive_key(
    password: &str,
    salt: &[u8; 32],
    parameters: KdfParameters,
) -> Result<SecretBytes, CryptoError> {
    parameters.validate()?;
    let params = Params::new(
        parameters.memory_kib,
        parameters.time_cost,
        parameters.parallelism,
        Some(32),
    )
    .map_err(|_| CryptoError::KdfParametersOutOfBounds)?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut password_material = Zeroizing::new([0u8; 32]);
    argon
        .hash_password_into(password.as_bytes(), salt, &mut *password_material)
        .map_err(|_| CryptoError::KdfFailed)?;
    let expansion = Hkdf::<Sha256>::new(Some(salt), &password_material[..]);
    let mut key = Zeroizing::new([0u8; 32]);
    expansion
        .expand(b"DOM-WALLET-V3-STATE-ENCRYPTION-V1", &mut *key)
        .map_err(|_| CryptoError::KdfFailed)?;
    SecretBytes::from_bytes(key.to_vec())
}

fn envelope_aad(header: &EnvelopeHeader, context: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let mut digest = Sha256::new();
    digest.update(header.magic);
    digest.update(header.envelope_version.to_le_bytes());
    digest.update(header.profile.as_bytes());
    digest.update(header.salt);
    digest.update(context);
    Ok(digest.finalize().to_vec())
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum CryptoError {
    #[error("invalid secret length")]
    InvalidSecretLength,
    #[error("secure randomness is unavailable")]
    RandomnessUnavailable,
    #[error("invalid cryptographic input")]
    InvalidInput,
    #[error("KDF parameters are out of bounds")]
    KdfParametersOutOfBounds,
    #[error("key derivation failed")]
    KdfFailed,
    #[error("unsupported envelope or profile version")]
    UnsupportedVersion,
    #[error("canonical envelope encoding failed")]
    CanonicalEncoding,
    #[error("envelope exceeds bounded size")]
    EnvelopeTooLarge,
    #[error("encryption failed")]
    EncryptionFailed,
    #[error("decryption failed")]
    DecryptionFailed,
    #[error("envelope authentication failed")]
    AuthenticationFailed,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn envelope_rejects_wrong_password_and_context() {
        let envelope = seal(b"state", "correct", b"wallet:one", KdfParameters::TEST).unwrap();
        assert_eq!(
            open(&envelope, "wrong", b"wallet:one"),
            Err(CryptoError::AuthenticationFailed)
        );
        assert_eq!(
            open(&envelope, "correct", b"wallet:two"),
            Err(CryptoError::AuthenticationFailed)
        );
    }

    #[test]
    fn envelope_rejects_excessive_parameters_and_unknown_version() {
        let bad = KdfParameters {
            memory_kib: MAX_KDF_MEMORY_KIB + 1,
            ..KdfParameters::TEST
        };
        assert_eq!(
            seal(b"state", "password", b"context", bad),
            Err(CryptoError::KdfParametersOutOfBounds)
        );
        let mut envelope = seal(b"state", "password", b"context", KdfParameters::TEST).unwrap();
        envelope.header.envelope_version += 1;
        assert_eq!(
            open(&envelope, "password", b"context"),
            Err(CryptoError::UnsupportedVersion)
        );
    }

    #[test]
    fn secret_debug_is_redacted() {
        let secret = SecretBytes::from_bytes(vec![1, 2, 3]).unwrap();
        assert_eq!(format!("{secret:?}"), "SecretBytes([REDACTED])");
    }
}
