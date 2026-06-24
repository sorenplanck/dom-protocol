//! dom-shield FAMILY 3b — blinding/mask collision proptests (#25-27).
//!
//! Threat model (Lens A: malleability / aliasing): a wallet blinding helper
//! that *masks* an out-of-range index instead of *rejecting* it maps two
//! distinct logical inputs onto the SAME derived blinding factor. Reusing a
//! blinding across two distinct outputs is a funds-safety hazard (commitment
//! reuse / key reuse).
//!
//! The boundary under test is bit 31 (the BIP-32 hardened-index frontier,
//! `0x8000_0000`). The two public blinding helpers treat it differently:
//!
//!   - `spend_output_blinding` masks `account` and `index` with `& 0x7fff_ffff`
//!     (seed.rs:217-218) — high-bit inputs are SILENTLY FOLDED, not rejected.
//!     => collision EXISTS (RED finding, mask aliasing).
//!
//!   - `coinbase_blinding` gates `height` through `u32::try_from(..).filter(|v|
//!     *v <= 0x7fff_ffff)` (seed.rs:191-198) — high-bit heights are REJECTED
//!     with `SeedError::Internal`. => no aliasing (GREEN dissolution).
//!
//! What this file does NOT duplicate (already covered elsewhere):
//!   - derive_blinding_path_kav.rs: FIX-001 path-doubling (m/44'/44'/...). NOT
//!     re-proven here.
//!   - derivation_proptests.rs: determinism / injectivity / hardening — all
//!     stay strictly inside 0..0x7fff_ffff and never cross the bit-31 frontier
//!     at the public blinding API, so the mask boundary is untouched there.
//!   - blinding_freeze.rs: frozen digests of in-range derivations.
//!   - negative_kav.rs / blinding_freeze.rs: no mask/alias collision assertions.
//!
//! Markers:
//!   #25 spend_output_blinding bit-31 mask collision  -> [x] RED (finding)
//!   #26 account 0x8000_0000 vs 0 concrete alias pin  -> [x] RED (finding)
//!   #27 coinbase_blinding height masking check        -> [x] GREEN (dissolution)

use dom_wallet_keys::{coinbase_blinding, spend_output_blinding, ExtendedPrivKey};
use proptest::prelude::*;

const MASK: u32 = 0x7fff_ffff;
const HIGH_BIT: u32 = 0x8000_0000;

/// Build an HD root from a 32-byte proptest seed (always in BIP-32 range).
fn root(seed: &[u8; 32]) -> ExtendedPrivKey {
    ExtendedPrivKey::from_seed(seed).expect("32-byte seed is always in-range")
}

proptest! {
    // Derivation is HMAC-SHA512 + secp256k1 tweak per level (5 levels per call,
    // two calls per case). Keep the case count modest so the suite runs in
    // seconds, not minutes.
    #![proptest_config(ProptestConfig::with_cases(48))]

    // ── #25 — spend_output_blinding: bit-31 mask collision (account) ─────────
    //
    // FINDING (RED): for any `x`, spend_output_blinding(x, idx) folds `x` to
    // `x & 0x7fff_ffff`. So `x` and `x & MASK` derive the SAME blinding whenever
    // they differ only in bit 31 (i.e. when x has the high bit set). We assert
    // the collision EXISTS — this test passes BECAUSE the masking bug is present.
    // The day the code rejects high-bit accounts instead, this assertion flips
    // and the test fails, surfacing that the behaviour changed.
    #[test]
    fn spend_account_bit31_masks_to_collision(
        seed in any::<[u8; 32]>(),
        x in any::<u32>(),
        idx in 0u32..0x7fff_ffff,
    ) {
        let r = root(&seed);
        let folded = x & MASK;

        let a = spend_output_blinding(&r, x, idx)
            .expect("spend_output_blinding masks, never rejects account");
        let b = spend_output_blinding(&r, folded, idx)
            .expect("spend_output_blinding masks, never rejects account");

        prop_assert_eq!(
            a.as_ref(), b.as_ref(),
            "MASK-ALIAS (RED): spend_output_blinding(account={:#x}) collides with \
             spend_output_blinding(account={:#x}) — bit-31 silently folded \
             (seed.rs:217 `account & 0x7fff_ffff`)",
            x, folded
        );
    }

    // ── #25b — spend_output_blinding: bit-31 mask collision (index) ──────────
    //
    // Same masking bug on the `index` argument (seed.rs:218 `index & MASK`).
    // Distinct vector: aliasing on the OTHER masked field. RED finding.
    #[test]
    fn spend_index_bit31_masks_to_collision(
        seed in any::<[u8; 32]>(),
        acct in 0u32..0x7fff_ffff,
        y in any::<u32>(),
    ) {
        let r = root(&seed);
        let folded = y & MASK;

        let a = spend_output_blinding(&r, acct, y)
            .expect("spend_output_blinding masks, never rejects index");
        let b = spend_output_blinding(&r, acct, folded)
            .expect("spend_output_blinding masks, never rejects index");

        prop_assert_eq!(
            a.as_ref(), b.as_ref(),
            "MASK-ALIAS (RED): spend_output_blinding(index={:#x}) collides with \
             spend_output_blinding(index={:#x}) — bit-31 silently folded \
             (seed.rs:218 `index & 0x7fff_ffff`)",
            y, folded
        );
    }

    // ── #26 — concrete alias pin: account 0x8000_0000 vs 0 ──────────────────
    //
    // The canonical exploit pair. account=0 is the wallet's DEFAULT account, so
    // an output erroneously (or maliciously) derived at account=0x8000_0000
    // reuses the SAME blinding as the default account at the same index. RED.
    #[test]
    fn spend_account_high_bit_aliases_zero(
        seed in any::<[u8; 32]>(),
        idx in 0u32..0x7fff_ffff,
    ) {
        let r = root(&seed);

        let zero = spend_output_blinding(&r, 0, idx)
            .expect("account 0 derives");
        let high = spend_output_blinding(&r, HIGH_BIT, idx)
            .expect("account 0x8000_0000 is masked to 0, never rejected");

        prop_assert_eq!(
            zero.as_ref(), high.as_ref(),
            "MASK-ALIAS (RED): spend_output_blinding(account=0x8000_0000, index={idx}) \
             == spend_output_blinding(account=0, index={idx}) — the high-bit account \
             aliases the DEFAULT account (seed.rs:217)",
            idx = idx
        );
    }

    // ── #27 — coinbase_blinding: height masking check (DISSOLUTION) ──────────
    //
    // DISSOLUTION (GREEN): unlike spend_output_blinding, coinbase_blinding does
    // NOT mask. It gates `height` through `u32::try_from(..).filter(|v| *v <=
    // 0x7fff_ffff)` and returns `SeedError::Internal` for anything in the high-
    // bit range. So there is no folding and no aliasing across the bit-31
    // frontier. We PROVE the rejection (not the collision) for high-bit heights,
    // and prove the in-range twin still derives — demonstrating the absence of
    // the masking misbehaviour the spend path exhibits.
    #[test]
    fn coinbase_high_bit_height_rejected_not_masked(
        seed in any::<[u8; 32]>(),
        low in 0u64..0x8000_0000u64,
    ) {
        let r = root(&seed);

        // High-bit height = low | 0x8000_0000. Were coinbase to MASK (like the
        // spend path), this would alias `low`. Instead it must be REJECTED.
        let high = low | (HIGH_BIT as u64);
        prop_assert!(
            coinbase_blinding(&r, high).is_err(),
            "DISSOLUTION BROKEN: coinbase_blinding(height={:#x}) did NOT reject — \
             if it now masks, it would alias height={:#x}",
            high, low
        );

        // The in-range twin (when distinct) must derive fine and, when low is a
        // valid u31, differ from no-op (sanity that the gate is the only block).
        if low <= MASK as u64 {
            prop_assert!(
                coinbase_blinding(&r, low).is_ok(),
                "in-range height {:#x} must derive", low
            );
        }
    }
}

#[cfg(test)]
mod boundary_pins {
    use super::*;

    /// #27 boundary pin (deterministic, non-proptest): exact u31 frontier.
    /// 0x7fff_ffff accepted; 0x8000_0000 rejected; u64::MAX rejected. Confirms
    /// coinbase uses a hard gate, not a mask. (GREEN dissolution.)
    #[test]
    fn coinbase_u31_frontier_is_a_hard_gate() {
        let r = root(&[0x5eu8; 32]);
        assert!(
            coinbase_blinding(&r, 0x7fff_ffff).is_ok(),
            "largest u31 height must be accepted"
        );
        assert!(
            coinbase_blinding(&r, 0x8000_0000).is_err(),
            "first high-bit height must be REJECTED (no mask)"
        );
        assert!(
            coinbase_blinding(&r, u64::MAX).is_err(),
            "u64::MAX height must be REJECTED"
        );
    }

    /// #26 concrete pin (deterministic): account 0x8000_0000 aliases account 0
    /// at a fixed index. Documents the exact RED collision pair without proptest
    /// noise. This PASSES because the masking bug is present.
    #[test]
    fn spend_account_high_bit_aliases_zero_pinned() {
        let r = root(&[0x5eu8; 32]);
        let zero = spend_output_blinding(&r, 0, 7).unwrap();
        let high = spend_output_blinding(&r, 0x8000_0000, 7).unwrap();
        assert_eq!(
            zero.as_ref(),
            high.as_ref(),
            "RED: spend_output_blinding(account=0x8000_0000, index=7) aliases account=0"
        );
    }
}
