//! BIP327 key aggregation and the Taproot x-only tweak (M.1.3, M.2.2).

use btc_secp_sys::{
    secp256k1_musig_keyagg_cache, secp256k1_musig_pubkey_agg,
    secp256k1_musig_pubkey_xonly_tweak_add, secp256k1_pubkey, secp256k1_xonly_pubkey,
    secp256k1_xonly_pubkey_from_pubkey,
};

use crate::context::SecpContext;
use crate::error::BtcCryptoError;
use crate::primitives::{PubKey, XOnlyKey};

/// Parity of a point's y coordinate.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Parity {
    /// Even y.
    Even,
    /// Odd y.
    Odd,
}

impl Parity {
    fn from_c(value: core::ffi::c_int) -> Result<Self, BtcCryptoError> {
        match value {
            0 => Ok(Self::Even),
            1 => Ok(Self::Odd),
            _ => Err(BtcCryptoError::NonceParityOutOfDomain),
        }
    }
}

/// The MuSig2 key-aggregation context: the opaque backend cache plus the
/// public facts derived from it. The cache is NOT wire format (M.1.3
/// rule 8) — only these derived public bytes are ever persisted.
pub struct KeyAggContext {
    cache: secp256k1_musig_keyagg_cache,
    /// x-only aggregate key before the TapTweak (the Taproot internal
    /// key `x(P)`).
    pub internal_xonly: [u8; 32],
    /// Parity of the full aggregate key `P` (`internal_flip`).
    pub internal_parity: Parity,
}

/// The Taproot output key after applying the TapTweak (M.2.2).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct TaprootTweak {
    /// x-only Taproot output key `x(Q)`.
    pub output_xonly: [u8; 32],
    /// Parity of `Q` (`output_flip`) — enters the control block.
    pub output_parity: Parity,
}

impl SecpContext {
    /// BIP327 key aggregation over an ORDERED list of compressed keys.
    /// The order is the caller's law (M.1.3 rule 2); the backend never
    /// reorders here.
    pub fn key_agg(&self, ordered_keys: &[[u8; 33]]) -> Result<KeyAggContext, BtcCryptoError> {
        let parsed: Vec<PubKey> = ordered_keys
            .iter()
            .map(|k| self.parse_pubkey(k))
            .collect::<Result<_, _>>()?;
        let ptrs: Vec<*const secp256k1_pubkey> = parsed.iter().map(|p| &p.0 as *const _).collect();

        let mut cache = secp256k1_musig_keyagg_cache { data: [0; 197] };
        let mut agg_xonly = secp256k1_xonly_pubkey { data: [0; 64] };
        // SAFETY: ctx valid; `ptrs` holds `parsed.len()` valid pointers
        // that outlive the call; out-params valid; scratch may be null.
        let ok = unsafe {
            secp256k1_musig_pubkey_agg(
                self.as_ptr(),
                core::ptr::null_mut(),
                &mut agg_xonly,
                &mut cache,
                ptrs.as_ptr(),
                ptrs.len(),
            )
        };
        if ok != 1 {
            return Err(BtcCryptoError::KeyAggregationFailed);
        }
        let internal_xonly = self.serialize_xonly(&XOnlyKey(agg_xonly));
        let internal_parity = self.full_agg_parity(&cache)?;
        Ok(KeyAggContext {
            cache,
            internal_xonly,
            internal_parity,
        })
    }

    /// Parity of the full aggregate key derived from the cache.
    fn full_agg_parity(
        &self,
        cache: &secp256k1_musig_keyagg_cache,
    ) -> Result<Parity, BtcCryptoError> {
        let mut full = secp256k1_pubkey { data: [0; 64] };
        // SAFETY: ctx and cache valid; valid out-param.
        let ok =
            unsafe { btc_secp_sys::secp256k1_musig_pubkey_get(self.as_ptr(), &mut full, cache) };
        if ok != 1 {
            return Err(BtcCryptoError::KeyAggregationFailed);
        }
        let mut xonly = secp256k1_xonly_pubkey { data: [0; 64] };
        let mut parity: core::ffi::c_int = -1;
        // SAFETY: ctx and `full` valid; valid out-params.
        let ok = unsafe {
            secp256k1_xonly_pubkey_from_pubkey(self.as_ptr(), &mut xonly, &mut parity, &full)
        };
        if ok != 1 {
            return Err(BtcCryptoError::KeyAggregationFailed);
        }
        Parity::from_c(parity)
    }

    /// Applies the Taproot tweak `h` to the aggregate inside the cache.
    ///
    /// The backend returns 0 when `h ≥ n` or `Q = ∞`; we fail closed and
    /// NEVER reduce (M.2.2 step 7, M.21). On success the cache now holds
    /// the tweaked key, and signing under it produces a signature valid
    /// for `x(Q)`.
    pub fn apply_tap_tweak(
        &self,
        ctx: &mut KeyAggContext,
        taptweak: &[u8; 32],
    ) -> Result<TaprootTweak, BtcCryptoError> {
        let mut output_full = secp256k1_pubkey { data: [0; 64] };
        // SAFETY: ctx.cache is a valid cache from `key_agg`; tweak is 32
        // bytes; out-param valid. The call mutates the cache in place.
        let ok = unsafe {
            secp256k1_musig_pubkey_xonly_tweak_add(
                self.as_ptr(),
                &mut output_full,
                &mut ctx.cache,
                taptweak.as_ptr(),
            )
        };
        if ok != 1 {
            return Err(BtcCryptoError::TapTweakRejected);
        }
        let mut output_xonly = secp256k1_xonly_pubkey { data: [0; 64] };
        let mut parity: core::ffi::c_int = -1;
        // SAFETY: ctx and `output_full` valid; valid out-params.
        let ok = unsafe {
            secp256k1_xonly_pubkey_from_pubkey(
                self.as_ptr(),
                &mut output_xonly,
                &mut parity,
                &output_full,
            )
        };
        if ok != 1 {
            return Err(BtcCryptoError::TapTweakRejected);
        }
        Ok(TaprootTweak {
            output_xonly: self.serialize_xonly(&XOnlyKey(output_xonly)),
            output_parity: Parity::from_c(parity)?,
        })
    }
}

impl KeyAggContext {
    /// The opaque cache, for the signing layer (crate-internal only).
    pub(crate) fn cache(&self) -> &secp256k1_musig_keyagg_cache {
        &self.cache
    }
}
