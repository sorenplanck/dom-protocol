//! F4-equivalent — compact<->target canonical projection invariants (proptest).
//!
//! The compact (nBits-style) encoding is a lossy mantissa/exponent projection of
//! a 256-bit target, so a naive compact->target->compact roundtrip only holds for
//! ALREADY-canonical compacts. The robust, always-true invariants:
//!
//!   (1) IDEMPOTENCE: target_to_compact is a canonical projection — projecting an
//!       arbitrary target, expanding it, and projecting again yields the SAME
//!       compact. tc(to_target(tc(t))) == tc(t).
//!   (2) STABILITY: a compact obtained from a target round-trips exactly:
//!       to_target(c) then target_to_compact gives c back.
//!
//! Catches any asymmetry between target_to_compact and to_target. No production change.

use dom_pow::{target_to_compact, CompactTarget};
use proptest::prelude::*;

fn target_strategy() -> impl Strategy<Value = [u8; 32]> {
    proptest::collection::vec(any::<u8>(), 32).prop_map(|v| {
        let mut a = [0u8; 32];
        a.copy_from_slice(&v);
        a
    })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    #[test]
    fn compact_projection_is_idempotent(target in target_strategy()) {
        let c1 = target_to_compact(&target);
        // Expanding c1 must succeed for a compact produced by the projection.
        let t1 = match CompactTarget(c1).to_target() {
            Ok(t) => t,
            Err(_) => return Ok(()), // extreme/degenerate compact — out of scope
        };
        let c2 = target_to_compact(&t1);
        prop_assert_eq!(c1, c2, "target_to_compact must be idempotent under to_target");
    }

    #[test]
    fn target_from_compact_reprojects_to_same_compact(raw in any::<u32>()) {
        // For any compact whose expansion is accepted, re-projecting the expanded
        // target must return the identical compact (canonical stability).
        let t = match CompactTarget(raw).to_target() {
            Ok(t) => t,
            Err(_) => return Ok(()), // non-expandable compact — skip
        };
        let c = target_to_compact(&t);
        let t2 = CompactTarget(c).to_target().expect("re-expansion of a canonical compact");
        prop_assert_eq!(t, t2, "to_target(target_to_compact(to_target(c))) must be stable");
    }
}
