//! PMMR test vectors.
//!
//! RFC-0004: Required vectors for leaf counts 0, 1, 2, 3, 4, 7, 8, 15, 16.
//! Leaf `i` has payload `i.to_le_bytes()` (8 bytes).
//!
//! The hex roots below are the consensus vectors produced by the
//! Phase B Grin-postorder implementation (commit bcd59ad). They are
//! enforced by `vectors_match_pinned_hex` so an inadvertent change to
//! PMMR semantics — leaf hashing, peak ordering, bagging — would
//! immediately break this test. Any drift here means the protocol
//! forked on a layout that an external implementer relying on RFC-0004
//! would no longer reproduce.
//!
//! Update procedure (consensus-class): a deliberate change to PMMR
//! layout REQUIRES re-running `cargo test print_pmmr_vectors --
//! --nocapture`, replacing the hex below, AND documenting the
//! migration / fork implications in RFC-0004 + ROADMAP_v3.

use dom_core::Hash256;
use dom_pmmr::Pmmr;

/// A PMMR test vector.
pub struct PmmrVector {
    /// Number of leaves.
    pub leaf_count: usize,
    /// Expected root as hex (Phase B Grin-postorder).
    pub expected_root_hex: &'static str,
    /// Leaf payloads: each leaf is its index as 8 LE bytes.
    pub leaf_data_description: &'static str,
}

/// The required RFC-0004 PMMR vectors.
/// Leaf i has payload = i.to_le_bytes() (8 bytes).
pub fn required_pmmr_vectors() -> Vec<PmmrVector> {
    vec![
        PmmrVector {
            leaf_count: 0,
            expected_root_hex: "4af723a9c80c18bbb3f064a0268049dffb15a1e7c4c7fa5e8062ebbb61f532f0",
            leaf_data_description: "empty",
        },
        PmmrVector {
            leaf_count: 1,
            expected_root_hex: "d7834b348a8e70f74fe0f71c3314f21252d92569bc2d501c78ee958bfe42df1e",
            leaf_data_description: "leaf_0",
        },
        PmmrVector {
            leaf_count: 2,
            expected_root_hex: "34ed1c907c3daea3e72dec770a6b1fcfe9b5fc22975a047872f0791acd898576",
            leaf_data_description: "leaf_0..1",
        },
        PmmrVector {
            leaf_count: 3,
            expected_root_hex: "d73d551a0b06ed3e01816503029245061cf0297b12d6703407f73474cdebb2fe",
            leaf_data_description: "leaf_0..2",
        },
        PmmrVector {
            leaf_count: 4,
            expected_root_hex: "d65c11f3f96bc9b9014444698709e55a5925f97608505b6302a464994b7def58",
            leaf_data_description: "leaf_0..3",
        },
        PmmrVector {
            leaf_count: 7,
            expected_root_hex: "4bd0ca87a4b3c45086d0978fba30e44f3fbd2768ba0d909d1ff262c5d5698191",
            leaf_data_description: "leaf_0..6",
        },
        PmmrVector {
            leaf_count: 8,
            expected_root_hex: "d86f63309c5f2cebe71f230af0737aee38d7059114aeb49339cb302ea4e33282",
            leaf_data_description: "leaf_0..7",
        },
        PmmrVector {
            leaf_count: 15,
            expected_root_hex: "265c0a884d2f22a3ebd89e6e3e959571648f96cc9324248efc8012f7d6e1ddcd",
            leaf_data_description: "leaf_0..14",
        },
        PmmrVector {
            leaf_count: 16,
            expected_root_hex: "70660b13b900c86b443a72b7d5f29519de53350b7bd02484ee85bebaab414094",
            leaf_data_description: "leaf_0..15",
        },
    ]
}

/// Compute PMMR roots for all required vectors.
pub fn generate_pmmr_vectors() -> Vec<(usize, Hash256)> {
    required_pmmr_vectors()
        .iter()
        .map(|v| {
            let mut pmmr = Pmmr::new();
            for i in 0..v.leaf_count {
                pmmr.push(&(i as u64).to_le_bytes()).unwrap();
            }
            (v.leaf_count, pmmr.root())
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pmmr_vectors_are_deterministic() {
        let r1 = generate_pmmr_vectors();
        let r2 = generate_pmmr_vectors();
        for ((c1, h1), (c2, h2)) in r1.iter().zip(r2.iter()) {
            assert_eq!(c1, c2);
            assert_eq!(h1, h2, "PMMR root for {c1} leaves must be deterministic");
        }
    }

    #[test]
    fn pmmr_roots_are_all_distinct() {
        let vectors = generate_pmmr_vectors();
        let roots: Vec<&Hash256> = vectors.iter().map(|(_, r)| r).collect();
        for i in 0..roots.len() {
            for j in (i + 1)..roots.len() {
                assert_ne!(
                    roots[i], roots[j],
                    "PMMR roots must be distinct for different leaf counts"
                );
            }
        }
    }

    /// Pinned consensus contract: every required vector MUST match the
    /// hex root recorded in `required_pmmr_vectors`. A failure here is
    /// a consensus-class regression — either the PMMR layout drifted
    /// from RFC-0004 or the recorded hex was edited without a matching
    /// protocol bump.
    #[test]
    fn vectors_match_pinned_hex() {
        for vector in required_pmmr_vectors() {
            let mut pmmr = Pmmr::new();
            for i in 0..vector.leaf_count {
                pmmr.push(&(i as u64).to_le_bytes())
                    .expect("push must succeed");
            }
            let computed = pmmr.root();
            let computed_hex = computed.to_hex();
            assert_eq!(
                computed_hex, vector.expected_root_hex,
                "n={}: PMMR root drifted from RFC-0004 pinned vector",
                vector.leaf_count
            );
        }
    }

    /// Print vectors for capture (run with -- --nocapture).
    #[test]
    fn print_pmmr_vectors() {
        println!("\n=== DOM PMMR Vectors (Reference Implementation) ===");
        for (count, root) in generate_pmmr_vectors() {
            println!("  leaves={count:2}: {}", root.to_hex());
        }
    }
}
