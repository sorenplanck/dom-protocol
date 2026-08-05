//! Opaque signing-share ownership for DOM Scriptless Contracts.

use crate::{AdaptorError, Result};
use dom_crypto::{scalar_bytes_are_canonical, secret_scalar_public_key, PublicKey};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// Canonical signing share with no raw-byte export.
///
/// The type deliberately implements no clone, copy, debug, display, equality,
/// ordering, or generic serialization. Its bytes are zeroized on drop.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SigningShareV1 {
    bytes: [u8; 32],
    #[zeroize(skip)]
    public_key: PublicKey,
}

impl SigningShareV1 {
    /// Parse a canonical nonzero big-endian signing share.
    pub fn from_be_bytes(bytes: [u8; 32]) -> Result<Self> {
        let bytes = Zeroizing::new(bytes);
        if !scalar_bytes_are_canonical(&bytes, false) {
            return Err(AdaptorError::InvalidContext(
                "signing share must be a canonical nonzero scalar",
            ));
        }
        let public_key = secret_scalar_public_key(&bytes)?;
        Ok(Self {
            bytes: *bytes,
            public_key,
        })
    }

    /// Return the corresponding canonical public key.
    pub const fn public_key(&self) -> &PublicKey {
        &self.public_key
    }

    #[cfg(test)]
    pub(crate) fn zeroizing_bytes(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(self.bytes)
    }

    pub(crate) const fn as_be_bytes(&self) -> &[u8; 32] {
        &self.bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constructor_rejects_every_fallible_scalar_boundary() {
        const GROUP_ORDER: [u8; 32] = [
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xfe, 0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c,
            0xd0, 0x36, 0x41, 0x41,
        ];
        assert!(SigningShareV1::from_be_bytes([0u8; 32]).is_err());
        assert!(SigningShareV1::from_be_bytes([0xff; 32]).is_err());
        assert!(SigningShareV1::from_be_bytes(GROUP_ORDER).is_err());
    }
}
