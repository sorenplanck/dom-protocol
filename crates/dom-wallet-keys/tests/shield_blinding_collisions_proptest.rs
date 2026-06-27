//! dom-shield FAMILY 3b — public blinding helpers must reject bit-31 aliasing.
//!
//! Threat model: if a public wallet blinding helper silently folds high-bit
//! account/index values back into the `u31` BIP-32 domain, two distinct logical
//! inputs can derive the same blinding. That is a funds-safety hazard because
//! it reuses the same scalar across different outputs.
//!
//! After FIX-043, both public helpers reject any account/index/height outside
//! the `0..=0x7fff_ffff` domain instead of masking.

use dom_wallet_keys::{coinbase_blinding, spend_output_blinding, ExtendedPrivKey};
use proptest::prelude::*;

const MASK: u32 = 0x7fff_ffff;
const HIGH_BIT: u32 = 0x8000_0000;

fn root(seed: &[u8; 32]) -> ExtendedPrivKey {
    ExtendedPrivKey::from_seed(seed).expect("32-byte seed is always in-range")
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(48))]

    #[test]
    fn spend_account_high_bit_is_rejected(
        seed in any::<[u8; 32]>(),
        x in HIGH_BIT..=u32::MAX,
        idx in 0u32..=MASK,
    ) {
        let r = root(&seed);
        prop_assert!(
            spend_output_blinding(&r, x, idx).is_err(),
            "high-bit account {x:#x} must be rejected, not folded into the u31 domain"
        );
    }

    #[test]
    fn spend_index_high_bit_is_rejected(
        seed in any::<[u8; 32]>(),
        acct in 0u32..=MASK,
        y in HIGH_BIT..=u32::MAX,
    ) {
        let r = root(&seed);
        prop_assert!(
            spend_output_blinding(&r, acct, y).is_err(),
            "high-bit index {y:#x} must be rejected, not folded into the u31 domain"
        );
    }

    #[test]
    fn coinbase_high_bit_height_rejected_not_masked(
        seed in any::<[u8; 32]>(),
        low in 0u64..0x8000_0000u64,
    ) {
        let r = root(&seed);
        let high = low | (HIGH_BIT as u64);
        prop_assert!(
            coinbase_blinding(&r, high).is_err(),
            "coinbase_blinding(height={high:#x}) must reject high-bit heights"
        );
        if low <= MASK as u64 {
            prop_assert!(coinbase_blinding(&r, low).is_ok());
        }
    }
}

#[cfg(test)]
mod boundary_pins {
    use super::*;

    #[test]
    fn coinbase_u31_frontier_is_a_hard_gate() {
        let r = root(&[0x5eu8; 32]);
        assert!(coinbase_blinding(&r, 0x7fff_ffff).is_ok());
        assert!(coinbase_blinding(&r, 0x8000_0000).is_err());
        assert!(coinbase_blinding(&r, u64::MAX).is_err());
    }

    #[test]
    fn spend_account_high_bit_no_longer_aliases_zero() {
        let r = root(&[0x5eu8; 32]);
        let zero = spend_output_blinding(&r, 0, 7).unwrap();
        assert!(spend_output_blinding(&r, 0x8000_0000, 7).is_err());
        assert_eq!(zero.as_ref().len(), 32);
    }

    #[test]
    fn spend_index_high_bit_is_rejected() {
        let r = root(&[0x5eu8; 32]);
        assert!(spend_output_blinding(&r, 7, 0x8000_0000).is_err());
    }
}
