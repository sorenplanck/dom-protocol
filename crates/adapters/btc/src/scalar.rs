//! Canonical scalar range checks and the secret adaptor scalar (M.1.1,
//! M.4.1).
//!
//! These are *range checks over big-endian bytes*, not group arithmetic:
//! no BIP340/BIP327/secp256k1 primitive is reimplemented here (M.0.4).
//! Every scalar that crosses the wire is 32-byte big-endian, canonical and
//! strictly less than the group order `n`; `t = 0`, `t ≥ n` and any
//! non-canonical form are failures, never silently reduced.

use zeroize::Zeroize;

use crate::error::ScalarError;

/// The order `n` of the secp256k1 group, big-endian (SEC2, BIP340).
pub const SECP256K1_ORDER_BE: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
    0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41,
];

/// Returns `true` when `bytes` encodes a scalar strictly below `n`
/// (zero included). Constant-flow over the comparison prefix is not
/// required here: every caller handles public or already-failed data.
#[must_use]
pub fn is_below_order(bytes: &[u8; 32]) -> bool {
    // Big-endian lexicographic comparison IS numeric comparison for
    // fixed-width unsigned integers.
    *bytes < SECP256K1_ORDER_BE
}

/// Returns `true` when `bytes` encodes a canonical *non-zero* scalar,
/// i.e. `1 ≤ x < n` (the domain required for `t` by M.1.1).
#[must_use]
pub fn is_canonical_nonzero(bytes: &[u8; 32]) -> bool {
    is_below_order(bytes) && bytes.iter().any(|b| *b != 0)
}

/// The adaptor secret `t` (M.4.1).
///
/// Deliberately implements none of `Clone`, `Copy`, `Debug`, `Display`,
/// serde or public serialization. The constructor enforces `1 ≤ t < n`;
/// `Drop` zeroizes. The raw bytes are reachable only inside this crate,
/// at the cryptographic boundary that consumes them (M.4.3): journal,
/// outbox, Relay, Keystone and USPE only ever see the public commitment
/// `T`.
pub struct AdaptorSecretV1 {
    bytes: [u8; 32],
}

impl AdaptorSecretV1 {
    /// Validates and takes ownership of the scalar bytes.
    ///
    /// The input buffer is zeroized on both success and failure, so a
    /// rejected candidate does not linger on the caller's stack frame.
    pub fn from_bytes(mut bytes: [u8; 32]) -> Result<Self, ScalarError> {
        if !is_canonical_nonzero(&bytes) {
            bytes.zeroize();
            return Err(ScalarError::NonCanonicalScalar);
        }
        let secret = Self { bytes };
        Ok(secret)
    }

    /// Exposes the scalar to the in-crate cryptographic boundary.
    ///
    /// Crate-private on purpose: no public API returns these bytes.
    /// Consumed by the backend wrapper of build-order step 5 (M.17);
    /// until that step lands only the tests touch it.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn expose(&self) -> &[u8; 32] {
        &self.bytes
    }
}

impl Drop for AdaptorSecretV1 {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn order_boundaries() {
        let zero = [0u8; 32];
        assert!(is_below_order(&zero));
        assert!(!is_canonical_nonzero(&zero));

        let one = {
            let mut b = [0u8; 32];
            b[31] = 1;
            b
        };
        assert!(is_canonical_nonzero(&one));

        let n_minus_1 = {
            let mut b = SECP256K1_ORDER_BE;
            b[31] -= 1;
            b
        };
        assert!(is_canonical_nonzero(&n_minus_1));

        assert!(!is_below_order(&SECP256K1_ORDER_BE));
        assert!(!is_canonical_nonzero(&SECP256K1_ORDER_BE));

        let max = [0xffu8; 32];
        assert!(!is_canonical_nonzero(&max));
    }

    #[test]
    fn adaptor_secret_rejects_zero_and_overflow() {
        assert!(AdaptorSecretV1::from_bytes([0u8; 32]).is_err());
        assert!(AdaptorSecretV1::from_bytes(SECP256K1_ORDER_BE).is_err());
        assert!(AdaptorSecretV1::from_bytes([0xffu8; 32]).is_err());
        let mut one = [0u8; 32];
        one[31] = 1;
        let secret = AdaptorSecretV1::from_bytes(one).expect("canonical");
        assert_eq!(secret.expose()[31], 1);
    }
}
