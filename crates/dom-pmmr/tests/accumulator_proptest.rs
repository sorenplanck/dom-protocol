//! F4-equivalent — MMR accumulator structural invariants (proptest).
//!
//! dom-pmmr exposes only the building side (push/root/leaf_count); there is no
//! public prove/verify, so membership soundness is out of public reach. The
//! always-true structural invariants over ANY push sequence:
//!   (1) DETERMINISM: same payload sequence => identical root and leaf_count.
//!   (2) COUNT: leaf_count == number of pushes.
//!   (3) APPEND SENSITIVITY: the root changes on every append (no silent
//!       no-op / collision across the sequence).
//! Collapses the accumulator's determinism/counting vectors. No production change.

use dom_pmmr::Pmmr;
use proptest::prelude::*;

fn payloads_strategy() -> impl Strategy<Value = Vec<Vec<u8>>> {
    proptest::collection::vec(proptest::collection::vec(any::<u8>(), 0..40), 1..30)
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn pmmr_deterministic_same_sequence(payloads in payloads_strategy()) {
        let mut a = Pmmr::new();
        let mut b = Pmmr::new();
        for p in &payloads { a.push(p).expect("push a"); }
        for p in &payloads { b.push(p).expect("push b"); }
        prop_assert_eq!(a.leaf_count(), payloads.len() as u64);
        prop_assert_eq!(a.leaf_count(), b.leaf_count());
        let ra = *a.root().as_bytes();
        let rb = *b.root().as_bytes();
        prop_assert_eq!(ra, rb, "same payload sequence must yield the same root");
    }

    #[test]
    fn pmmr_count_and_root_change_on_append(payloads in payloads_strategy()) {
        let mut m = Pmmr::new();
        let mut prev: Option<[u8; 32]> = None;
        for (i, p) in payloads.iter().enumerate() {
            m.push(p).expect("push");
            prop_assert_eq!(m.leaf_count(), (i as u64) + 1, "leaf_count tracks pushes");
            let r = *m.root().as_bytes();
            if let Some(pr) = prev {
                prop_assert_ne!(pr, r, "root must change on every append");
            }
            prev = Some(r);
        }
    }
}
