#![allow(missing_docs)]
//! secp256k1 key types with strict validation.
//!
//! RFC-0001: All scalar and point values MUST be validated before use.
//! Compressed SEC1 encoding is the only accepted format for public keys.

use dom_core::DomError;
use secp256k1::SECP256K1;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// A validated secp256k1 scalar.
///
/// Scalars are in the range [1, n-1] where n is the curve order.
/// Zero scalars are rejected as they produce degenerate keys.
/// Stored as 32 canonical little-endian bytes per RFC-0001.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Scalar([u8; 32]);

impl Scalar {
    /// Parse a scalar from 32 little-endian bytes.
    ///
    /// Returns error if:
    /// - the scalar is zero
    /// - the scalar >= curve order n
    pub fn from_le_bytes(bytes: [u8; 32]) -> Result<Self, DomError> {
        // Convert from LE to the secp256k1 library's expected format (BE)
        let mut be = bytes;
        be.reverse();
        // Attempt to parse as a secp256k1 secret key — this validates range
        secp256k1::SecretKey::from_slice(&be)
            .map_err(|e| DomError::Invalid(format!("invalid scalar: {e}")))?;
        Ok(Self(bytes))
    }

    /// Parse a scalar from 32 big-endian bytes (for interop with secp256k1 crate).
    pub fn from_be_bytes(bytes: [u8; 32]) -> Result<Self, DomError> {
        secp256k1::SecretKey::from_slice(&bytes)
            .map_err(|e| DomError::Invalid(format!("invalid scalar: {e}")))?;
        let mut le = bytes;
        le.reverse();
        Ok(Self(le))
    }

    /// Return the scalar as little-endian bytes.
    pub fn as_le_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Return the scalar as big-endian bytes (for secp256k1 crate).
    pub fn to_be_bytes(&self) -> [u8; 32] {
        let mut be = self.0;
        be.reverse();
        be
    }

    /// Convert to a secp256k1 SecretKey.
    #[allow(dead_code)]
    pub(crate) fn to_secret_key(&self) -> secp256k1::SecretKey {
        secp256k1::SecretKey::from_slice(&self.to_be_bytes())
            .expect("Scalar is already validated")
    }
}

impl ConstantTimeEq for Scalar {
    fn ct_eq(&self, other: &Self) -> subtle::Choice {
        self.0.ct_eq(&other.0)
    }
}

impl PartialEq for Scalar {
    fn eq(&self, other: &Self) -> bool {
        bool::from(self.ct_eq(other))
    }
}

impl Eq for Scalar {}

impl std::fmt::Debug for Scalar {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Scalar([REDACTED])")
    }
}

// ── SecretKey ─────────────────────────────────────────────────────────────────

/// A validated secp256k1 secret key.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SecretKey([u8; 32]);

impl SecretKey {
    /// Parse from 32 big-endian bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, DomError> {
        if bytes.len() != 32 {
            return Err(DomError::Malformed(format!("secret key must be 32 bytes, got {}", bytes.len())));
        }
        secp256k1::SecretKey::from_slice(bytes)
            .map_err(|e| DomError::Invalid(format!("invalid secret key: {e}")))?;
        let mut arr = [0u8; 32];
        arr.copy_from_slice(bytes);
        Ok(Self(arr))
    }

    /// Derive the corresponding public key.
    pub fn public_key(&self) -> PublicKey {
        let sk = secp256k1::SecretKey::from_slice(&self.0).expect("already validated");
        let pk = secp256k1::PublicKey::from_secret_key(SECP256K1, &sk);
        PublicKey(pk)
    }

    /// Return raw 32 big-endian bytes (secret key material — handle with care).
    pub fn to_be_bytes_raw(&self) -> [u8; 32] {
        self.0
    }
}

impl std::fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SecretKey([REDACTED])")
    }
}

// ── PublicKey ─────────────────────────────────────────────────────────────────

/// A validated secp256k1 public key in compressed SEC1 encoding.
///
/// Compressed SEC1: 33 bytes, first byte is 0x02 or 0x03.
/// Uncompressed keys (65 bytes, 0x04 prefix) are REJECTED.
/// The point at infinity is REJECTED.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct PublicKey(secp256k1::PublicKey);

impl PublicKey {
    /// Parse from 33-byte compressed SEC1 encoding.
    ///
    /// Returns error if:
    /// - not 33 bytes
    /// - first byte is not 0x02 or 0x03
    /// - not a valid curve point
    /// - point is at infinity
    pub fn from_compressed_bytes(bytes: &[u8]) -> Result<Self, DomError> {
        if bytes.len() != 33 {
            return Err(DomError::Malformed(format!(
                "compressed public key must be 33 bytes, got {}",
                bytes.len()
            )));
        }
        if bytes[0] != 0x02 && bytes[0] != 0x03 {
            return Err(DomError::Malformed(format!(
                "compressed public key prefix must be 0x02 or 0x03, got 0x{:02x}",
                bytes[0]
            )));
        }
        secp256k1::PublicKey::from_slice(bytes)
            .map(Self)
            .map_err(|e| DomError::Invalid(format!("invalid public key point: {e}")))
    }

    /// Serialize to 33-byte compressed SEC1 encoding.
    pub fn to_compressed_bytes(&self) -> [u8; 33] {
        self.0.serialize()
    }

    /// Return reference to inner secp256k1 public key.
    #[allow(dead_code)]
    pub(crate) fn inner(&self) -> &secp256k1::PublicKey {
        &self.0
    }
}

impl std::fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "PublicKey({})", hex::encode(self.to_compressed_bytes()))
    }
}

impl std::fmt::Display for PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(self.to_compressed_bytes()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_secret_key() -> SecretKey {
        let bytes = [1u8; 32]; // valid non-zero scalar
        SecretKey::from_bytes(&bytes).unwrap()
    }

    #[test]
    fn secret_key_derives_public_key() {
        let sk = test_secret_key();
        let pk = sk.public_key();
        let compressed = pk.to_compressed_bytes();
        assert!(compressed[0] == 0x02 || compressed[0] == 0x03);
        assert_eq!(compressed.len(), 33);
    }

    #[test]
    fn public_key_roundtrip() {
        let sk = test_secret_key();
        let pk = sk.public_key();
        let bytes = pk.to_compressed_bytes();
        let pk2 = PublicKey::from_compressed_bytes(&bytes).unwrap();
        assert_eq!(pk, pk2);
    }

    #[test]
    fn uncompressed_key_rejected() {
        let sk = test_secret_key();
        let pk = sk.public_key();
        let mut uncompressed = [0u8; 65];
        uncompressed[0] = 0x04;
        // Fill with valid-looking data
        uncompressed[1..33].copy_from_slice(&pk.to_compressed_bytes()[1..]);
        assert!(PublicKey::from_compressed_bytes(&uncompressed).is_err());
    }

    #[test]
    fn wrong_prefix_rejected() {
        let sk = test_secret_key();
        let pk = sk.public_key();
        let mut bytes = pk.to_compressed_bytes();
        bytes[0] = 0x04; // wrong prefix
        assert!(PublicKey::from_compressed_bytes(&bytes).is_err());
    }

    #[test]
    fn wrong_length_rejected() {
        assert!(PublicKey::from_compressed_bytes(&[0x02u8; 32]).is_err());
        assert!(PublicKey::from_compressed_bytes(&[0x02u8; 34]).is_err());
        assert!(PublicKey::from_compressed_bytes(&[]).is_err());
    }

    #[test]
    fn zero_scalar_rejected() {
        assert!(SecretKey::from_bytes(&[0u8; 32]).is_err());
    }

    #[test]
    fn secret_key_debug_is_redacted() {
        let sk = test_secret_key();
        let dbg = format!("{:?}", sk);
        assert!(dbg.contains("REDACTED"));
        assert!(!dbg.contains("01010101"));
    }
}
