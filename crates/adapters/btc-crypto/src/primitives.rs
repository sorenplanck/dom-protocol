//! Point and tagged-hash primitives over the pinned backend.
//!
//! Every external point is re-validated by the C library before use
//! (M.1.1): a bad encoding, an off-curve point or the identity is
//! rejected here, not silently accepted.

use btc_secp_sys::{
    secp256k1_ec_pubkey_parse, secp256k1_ec_pubkey_serialize, secp256k1_pubkey,
    secp256k1_tagged_sha256, secp256k1_xonly_pubkey, secp256k1_xonly_pubkey_parse,
    secp256k1_xonly_pubkey_serialize, SECP256K1_EC_COMPRESSED,
};

use crate::context::SecpContext;
use crate::error::BtcCryptoError;

/// An on-curve public key parsed by the backend.
pub(crate) struct PubKey(pub(crate) secp256k1_pubkey);

/// An x-only public key parsed by the backend.
pub(crate) struct XOnlyKey(pub(crate) secp256k1_xonly_pubkey);

impl SecpContext {
    /// Parses a 33-byte compressed point, rejecting non-canonical or
    /// off-curve encodings.
    pub(crate) fn parse_pubkey(&self, bytes: &[u8; 33]) -> Result<PubKey, BtcCryptoError> {
        let mut pk = secp256k1_pubkey { data: [0; 64] };
        // SAFETY: ctx valid; `bytes` is exactly 33 readable bytes; `pk`
        // is a valid out-param.
        let ok = unsafe { secp256k1_ec_pubkey_parse(self.as_ptr(), &mut pk, bytes.as_ptr(), 33) };
        if ok != 1 {
            return Err(BtcCryptoError::InvalidPoint);
        }
        Ok(PubKey(pk))
    }

    /// Serializes a public key to 33-byte compressed form.
    pub(crate) fn serialize_pubkey(&self, pk: &PubKey) -> [u8; 33] {
        let mut out = [0u8; 33];
        let mut len = 33usize;
        // SAFETY: ctx and pk valid; `out` holds 33 bytes; len is in/out.
        let ok = unsafe {
            secp256k1_ec_pubkey_serialize(
                self.as_ptr(),
                out.as_mut_ptr(),
                &mut len,
                &pk.0,
                SECP256K1_EC_COMPRESSED,
            )
        };
        assert_eq!(ok, 1, "serializing a valid pubkey cannot fail");
        assert_eq!(len, 33);
        out
    }

    /// Parses a 32-byte x-only key.
    pub(crate) fn parse_xonly(&self, bytes: &[u8; 32]) -> Result<XOnlyKey, BtcCryptoError> {
        let mut xk = secp256k1_xonly_pubkey { data: [0; 64] };
        // SAFETY: ctx valid; 32 readable bytes; valid out-param.
        let ok = unsafe { secp256k1_xonly_pubkey_parse(self.as_ptr(), &mut xk, bytes.as_ptr()) };
        if ok != 1 {
            return Err(BtcCryptoError::InvalidXOnlyKey);
        }
        Ok(XOnlyKey(xk))
    }

    /// Serializes an x-only key to 32 bytes.
    pub(crate) fn serialize_xonly(&self, xk: &XOnlyKey) -> [u8; 32] {
        let mut out = [0u8; 32];
        // SAFETY: ctx and xk valid; `out` holds 32 bytes.
        let ok =
            unsafe { secp256k1_xonly_pubkey_serialize(self.as_ptr(), out.as_mut_ptr(), &xk.0) };
        assert_eq!(ok, 1, "serializing a valid x-only key cannot fail");
        out
    }

    /// BIP340 tagged SHA-256: `SHA256(SHA256(tag) || SHA256(tag) || msg)`.
    /// Computed by the pinned library, never reimplemented (M.0.4).
    #[must_use]
    pub fn tagged_sha256(&self, tag: &[u8], msg: &[u8]) -> [u8; 32] {
        let mut out = [0u8; 32];
        // SAFETY: ctx valid; tag/msg are readable for their lengths; out
        // holds 32 bytes.
        let ok = unsafe {
            secp256k1_tagged_sha256(
                self.as_ptr(),
                out.as_mut_ptr(),
                tag.as_ptr(),
                tag.len(),
                msg.as_ptr(),
                msg.len(),
            )
        };
        assert_eq!(ok, 1, "tagged_sha256 cannot fail for valid buffers");
        out
    }
}
