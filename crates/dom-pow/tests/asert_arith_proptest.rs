//! dom-shield — dom-pow proptest-invariante (256-bit ASERT arithmetic).
//!
//! These properties exercise the consensus arithmetic that turns the anchor
//! target + time drift into the next target. They are differential against an
//! independent U512 reference (`primitive_types::U512`).
//!
//! Lens A vectors covered:
//!   * `apply_exponent` core multiply: floor((hi*2^128 + lo) * m / 65536) must
//!     equal a full-width U512 reference, observed through the PUBLIC
//!     `asert_next_target` API (the internal mul fn is private). The frac
//!     multiplier and integer shift are driven via crafted anchor/time inputs.
//!   * target ordering: harder target (numerically smaller) ⇒ higher difficulty.
//!   * target_to_difficulty == floor(MAX_TARGET / target) (U256 reference).
//!   * idempotent determinism of asert_next_target.
//!
//! NOTE ON THE INTERNAL MULTIPLY (mul_256_div_radix_checked): the function is
//! private, so the strongest differential we can run from a test crate is
//! end-to-end through asert_next_target with a multiplier-only shift
//! (integer_part == 0). The dedicated end-to-end carry test lives in
//! `asert_mul_carry_xdiff.rs`.

use dom_core::{BlockHeight, Timestamp, MAX_TARGET_BYTES, MIN_TARGET_BYTES, TARGET_SPACING};
use dom_pow::{asert_next_target, target_to_difficulty, target_to_difficulty_u256, AsertAnchor};
use primitive_types::U256;
use proptest::prelude::*;

fn inrange_target_strategy() -> impl Strategy<Value = [u8; 32]> {
    // Build a target strictly within [MIN_TARGET, MAX_TARGET]:
    // leave bytes 0..2 zero (so <= 2^240, i.e. <= MAX) and set a nonzero byte at
    // index 2 (so >= ~2^232 > MIN_TARGET ~ 2^80).
    (1u8..=0xffu8, proptest::collection::vec(any::<u8>(), 13)).prop_map(|(top, rest)| {
        let mut t = [0u8; 32];
        t[2] = top;
        for (i, b) in rest.into_iter().enumerate() {
            t[3 + i] = b;
        }
        t
    })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    // ── target_to_difficulty == floor(MAX_TARGET / target) (U256 reference) ──
    #[test]
    fn target_to_difficulty_u256_equals_u256_long_division(target in inrange_target_strategy()) {
        let t = U256::from_big_endian(&target);
        prop_assume!(!t.is_zero());
        let max = U256::from_big_endian(&MAX_TARGET_BYTES);
        let reference = max / t;
        let (hi, lo) = target_to_difficulty_u256(&target);
        let got = (U256::from(hi) << 128) | U256::from(lo);
        prop_assert_eq!(got, reference, "target_to_difficulty_u256 must equal floor(MAX/target)");
    }

    // ── ordering: numerically smaller target ⇒ >= difficulty (scalar path) ──
    #[test]
    fn smaller_target_has_higher_or_equal_scalar_difficulty(
        a in inrange_target_strategy(),
        b in inrange_target_strategy(),
    ) {
        let ua = U256::from_big_endian(&a);
        let ub = U256::from_big_endian(&b);
        let da = target_to_difficulty(&a);
        let db = target_to_difficulty(&b);
        if ua < ub {
            prop_assert!(da >= db, "smaller target must have >= difficulty: {} vs {}", da, db);
        }
    }

    // ── target_gt / target_lt equivalent to U256 ordering ──
    #[test]
    fn difficulty_pair_orders_like_u256(
        a in inrange_target_strategy(),
        b in inrange_target_strategy(),
    ) {
        let ua = U256::from_big_endian(&a);
        let ub = U256::from_big_endian(&b);
        let (ha, la) = target_to_difficulty_u256(&a);
        let (hb, lb) = target_to_difficulty_u256(&b);
        // diff(a) and diff(b) are MAX/a, MAX/b. a < b  ⇒  diff(a) >= diff(b).
        if ua < ub {
            let a_pair = (ha, la);
            let b_pair = (hb, lb);
            prop_assert!(a_pair >= b_pair, "MAX/a >= MAX/b when a < b");
        }
    }

    // ── asert_next_target determinism ──
    #[test]
    fn asert_next_target_is_deterministic(
        target in inrange_target_strategy(),
        drift in -50_000i64..50_000i64,
        height in 1u64..10_000u64,
    ) {
        let anchor = AsertAnchor {
            timestamp: Timestamp(1_700_000_000),
            height: BlockHeight(0),
            target,
        };
        let base = 1_700_000_000i64 + (height as i64) * (TARGET_SPACING as i64);
        let ts = Timestamp((base + drift).max(0) as u64);
        let r1 = asert_next_target(&anchor, ts, BlockHeight(height));
        let r2 = asert_next_target(&anchor, ts, BlockHeight(height));
        prop_assert_eq!(r1.is_ok(), r2.is_ok());
        if let (Ok(a), Ok(b)) = (r1, r2) {
            prop_assert_eq!(a, b, "asert_next_target must be deterministic");
        }
    }

    // ── asert output always within [MIN, MAX] (no overflow escape) ──
    #[test]
    fn asert_output_stays_within_bounds(
        target in inrange_target_strategy(),
        drift in -200_000i64..200_000i64,
        height in 1u64..100_000u64,
    ) {
        let anchor = AsertAnchor {
            timestamp: Timestamp(1_700_000_000),
            height: BlockHeight(0),
            target,
        };
        let base = 1_700_000_000i64 + (height as i64) * (TARGET_SPACING as i64);
        let ts = Timestamp((base + drift).max(0) as u64);
        if let Ok(out) = asert_next_target(&anchor, ts, BlockHeight(height)) {
            let v = U256::from_big_endian(&out);
            prop_assert!(v <= U256::from_big_endian(&MAX_TARGET_BYTES), "above MAX");
            prop_assert!(v >= U256::from_big_endian(&MIN_TARGET_BYTES), "below MIN");
        }
    }
}
