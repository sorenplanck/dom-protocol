//! Opaque Monero scalar/share types for the DOM XMR adapter.

#![forbid(unsafe_code)]

use core::fmt;
use curve25519_dalek::{
    constants::ED25519_BASEPOINT_POINT, edwards::CompressedEdwardsY, scalar::Scalar,
};
use zeroize::Zeroizing;

/// XMR scalar errors.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum XmrCryptoError {
    /// Scalar is zero.
    #[error("XMR scalar is zero")]
    ZeroScalar,
    /// Bytes are not a canonical ed25519 scalar.
    #[error("XMR scalar is non-canonical")]
    NonCanonicalScalar,
    /// Compressed point is invalid or not prime-order.
    #[error("XMR point is invalid")]
    InvalidPoint,
}

fn canonical_nonzero(bytes: [u8; 32]) -> Result<Scalar, XmrCryptoError> {
    let scalar = Option::<Scalar>::from(Scalar::from_canonical_bytes(bytes))
        .ok_or(XmrCryptoError::NonCanonicalScalar)?;
    if scalar == Scalar::ZERO {
        return Err(XmrCryptoError::ZeroScalar);
    }
    Ok(scalar)
}

/// One private XMR spend-key share. Zeroized and never serializable.
pub struct XmrSpendShare(Zeroizing<[u8; 32]>);

impl fmt::Debug for XmrSpendShare {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("XmrSpendShare(<redacted>)")
    }
}

impl XmrSpendShare {
    /// Imports canonical little-endian scalar bytes.
    pub fn from_canonical_bytes(bytes: [u8; 32]) -> Result<Self, XmrCryptoError> {
        canonical_nonzero(bytes)?;
        Ok(Self(Zeroizing::new(bytes)))
    }

    /// Runs one operation with the scalar encoding without returning ownership.
    pub fn expose<R>(&self, operation: impl FnOnce(&[u8; 32]) -> R) -> R {
        operation(&self.0)
    }

    /// Public point for this share.
    pub fn public_share(&self) -> Result<[u8; 32], XmrCryptoError> {
        let scalar = canonical_nonzero(*self.0)?;
        Ok((ED25519_BASEPOINT_POINT * scalar).compress().to_bytes())
    }

    /// Adds two private shares and returns the combined spend key.
    pub fn combine(&self, other: &Self) -> Result<XmrSpendKey, XmrCryptoError> {
        let sum = canonical_nonzero(*self.0)? + canonical_nonzero(*other.0)?;
        if sum == Scalar::ZERO {
            return Err(XmrCryptoError::ZeroScalar);
        }
        Ok(XmrSpendKey(Zeroizing::new(sum.to_bytes())))
    }
}

/// Combined private XMR spend key. Zeroized and closure-only.
pub struct XmrSpendKey(Zeroizing<[u8; 32]>);

impl fmt::Debug for XmrSpendKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("XmrSpendKey(<redacted>)")
    }
}

impl XmrSpendKey {
    /// Runs one operation with canonical scalar bytes.
    pub fn expose<R>(&self, operation: impl FnOnce(&[u8; 32]) -> R) -> R {
        operation(&self.0)
    }

    /// Alias emphasizing closure-scoped signing access.
    pub fn with_scalar<R>(&self, operation: impl FnOnce(&[u8; 32]) -> R) -> R {
        self.expose(operation)
    }

    /// Combined public spend key.
    pub fn public_key(&self) -> Result<[u8; 32], XmrCryptoError> {
        let scalar = canonical_nonzero(*self.0)?;
        Ok((ED25519_BASEPOINT_POINT * scalar).compress().to_bytes())
    }
}

/// Private XMR view key. Zeroized and never serializable.
pub struct XmrPrivateViewKey(Zeroizing<[u8; 32]>);

impl fmt::Debug for XmrPrivateViewKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("XmrPrivateViewKey(<redacted>)")
    }
}

impl XmrPrivateViewKey {
    /// Imports canonical non-zero scalar bytes.
    pub fn from_canonical_bytes(bytes: [u8; 32]) -> Result<Self, XmrCryptoError> {
        canonical_nonzero(bytes)?;
        Ok(Self(Zeroizing::new(bytes)))
    }

    /// Closure-only access.
    pub fn expose<R>(&self, operation: impl FnOnce(&[u8; 32]) -> R) -> R {
        operation(&self.0)
    }
}

/// Adds two public spend shares after strict point validation.
pub fn combine_public_shares(left: [u8; 32], right: [u8; 32]) -> Result<[u8; 32], XmrCryptoError> {
    let left = CompressedEdwardsY(left)
        .decompress()
        .filter(|point| point.is_torsion_free())
        .ok_or(XmrCryptoError::InvalidPoint)?;
    let right = CompressedEdwardsY(right)
        .decompress()
        .filter(|point| point.is_torsion_free())
        .ok_or(XmrCryptoError::InvalidPoint)?;
    let combined = left + right;
    if combined == curve25519_dalek::EdwardsPoint::default() {
        return Err(XmrCryptoError::InvalidPoint);
    }
    Ok(combined.compress().to_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn private_material_is_redacted() -> Result<(), XmrCryptoError> {
        let share = XmrSpendShare::from_canonical_bytes(Scalar::ONE.to_bytes())?;
        assert!(format!("{share:?}").contains("redacted"));
        Ok(())
    }

    #[test]
    fn private_and_public_addition_agree() -> Result<(), XmrCryptoError> {
        let left = XmrSpendShare::from_canonical_bytes(Scalar::from(7_u64).to_bytes())?;
        let right = XmrSpendShare::from_canonical_bytes(Scalar::from(11_u64).to_bytes())?;
        assert_eq!(
            left.combine(&right)?.public_key()?,
            combine_public_shares(left.public_share()?, right.public_share()?)?,
        );
        Ok(())
    }
}
