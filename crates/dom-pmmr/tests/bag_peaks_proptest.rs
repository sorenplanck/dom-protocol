//! proptest-invariante — `bag_peaks` public-surface properties.
//!
//! `bag_peaks` is the only consensus-critical fold reachable on the
//! public surface besides `Pmmr::push/root`. Vectors covered here:
//!
//!   * non-commutativity / order-sensitivity: any reordering of >=2
//!     distinct peaks that changes the right-to-left fold input must
//!     change the output (malleability door — peak order is consensus).
//!   * determinism: same peak slice -> same hash, every time.
//!   * single-peak identity: bag of one peak == that peak (no extra hash).
//!   * empty bag is the fixed empty-domain digest, independent of inputs.
//!   * right-to-left fold equivalence: bag_peaks([p..]) == the explicit
//!     acc=last; for p in rev(rest): tagged(BAG, p||acc) recurrence.
//!
//! No production change. Uses only the public `bag_peaks` plus the
//! crypto/core tag for the reference recurrence.

use dom_core::{Hash256, TAG_PMMR_BAG};
use dom_crypto::hash::blake2b_256_tagged;
use dom_pmmr::bag_peaks;
use proptest::prelude::*;

/// Reference right-to-left fold, written independently of dom-pmmr.
fn ref_bag(peaks: &[Hash256]) -> Hash256 {
    match peaks.len() {
        0 => blake2b_256_tagged(dom_core::TAG_PMMR_EMPTY, &[]),
        1 => peaks[0],
        _ => {
            let mut acc = *peaks.last().unwrap();
            for p in peaks[..peaks.len() - 1].iter().rev() {
                let mut d = Vec::with_capacity(64);
                d.extend_from_slice(p.as_bytes());
                d.extend_from_slice(acc.as_bytes());
                acc = blake2b_256_tagged(TAG_PMMR_BAG, &d);
            }
            acc
        }
    }
}

fn hashes() -> impl Strategy<Value = Vec<Hash256>> {
    proptest::collection::vec(any::<[u8; 32]>(), 0..12)
        .prop_map(|v| v.into_iter().map(Hash256::from_bytes).collect())
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    /// bag_peaks must equal the independent right-to-left reference fold.
    #[test]
    fn bag_matches_reference_fold(peaks in hashes()) {
        prop_assert_eq!(*bag_peaks(&peaks).as_bytes(), *ref_bag(&peaks).as_bytes());
    }

    /// Determinism: identical slice -> identical output.
    #[test]
    fn bag_is_deterministic(peaks in hashes()) {
        prop_assert_eq!(*bag_peaks(&peaks).as_bytes(), *bag_peaks(&peaks).as_bytes());
    }

    /// Single-peak identity.
    #[test]
    fn single_peak_is_identity(seed in any::<[u8; 32]>()) {
        let h = Hash256::from_bytes(seed);
        prop_assert_eq!(*bag_peaks(&[h]).as_bytes(), seed);
    }

    /// Order sensitivity: for >=2 peaks that are pairwise distinct,
    /// reversing them must change the bagged root (right-to-left fold is
    /// not symmetric). We construct a strictly-distinct ascending set so
    /// the reversal is guaranteed to be a non-identity permutation.
    #[test]
    fn reversal_changes_root(len in 2usize..10) {
        let peaks: Vec<Hash256> = (0..len)
            .map(|i| {
                let mut b = [0u8; 32];
                b[0] = i as u8;
                b[31] = (i as u8).wrapping_add(1);
                Hash256::from_bytes(b)
            })
            .collect();
        let mut rev = peaks.clone();
        rev.reverse();
        prop_assert_ne!(
            *bag_peaks(&peaks).as_bytes(),
            *bag_peaks(&rev).as_bytes(),
            "reversing >=2 distinct peaks must change the bagged root"
        );
    }

    /// Empty bag is a fixed digest independent of any other inputs.
    #[test]
    fn empty_bag_is_fixed(_noise in any::<[u8; 32]>()) {
        let empty: &[Hash256] = &[];
        prop_assert_eq!(
            *bag_peaks(empty).as_bytes(),
            *blake2b_256_tagged(dom_core::TAG_PMMR_EMPTY, &[]).as_bytes()
        );
    }
}
