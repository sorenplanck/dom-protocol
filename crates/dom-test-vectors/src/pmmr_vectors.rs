//! PMMR test vectors.
//!
//! RFC-0004: Required vectors for leaf counts 0,1,2,3,4,7,8,15,16.
//! These MUST be independently reproduced before testnet launch.

use dom_pmmr::Pmmr;
use dom_core::Hash256;

/// A PMMR test vector.
pub struct PmmrVector {
    /// Number of leaves.
    pub leaf_count: usize,
    /// Expected root as hex. Empty = RELEASE BLOCKER (not yet captured).
    pub expected_root_hex: &'static str,
    /// Leaf payloads: each leaf is its index as 8 LE bytes.
    pub leaf_data_description: &'static str,
}

/// The required RFC-0004 PMMR vectors.
/// Leaf i has payload = i.to_le_bytes() (8 bytes).
pub fn required_pmmr_vectors() -> Vec<PmmrVector> {
    vec![
        PmmrVector { leaf_count: 0,  expected_root_hex: "", leaf_data_description: "empty" },
        PmmrVector { leaf_count: 1,  expected_root_hex: "", leaf_data_description: "leaf_0" },
        PmmrVector { leaf_count: 2,  expected_root_hex: "", leaf_data_description: "leaf_0..1" },
        PmmrVector { leaf_count: 3,  expected_root_hex: "", leaf_data_description: "leaf_0..2" },
        PmmrVector { leaf_count: 4,  expected_root_hex: "", leaf_data_description: "leaf_0..3" },
        PmmrVector { leaf_count: 7,  expected_root_hex: "", leaf_data_description: "leaf_0..6" },
        PmmrVector { leaf_count: 8,  expected_root_hex: "", leaf_data_description: "leaf_0..7" },
        PmmrVector { leaf_count: 15, expected_root_hex: "", leaf_data_description: "leaf_0..14" },
        PmmrVector { leaf_count: 16, expected_root_hex: "", leaf_data_description: "leaf_0..15" },
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

    /// Print vectors for capture (run with -- --nocapture).
    #[test]
    fn print_pmmr_vectors() {
        println!("\n=== DOM PMMR Vectors (Reference Implementation) ===");
        for (count, root) in generate_pmmr_vectors() {
            println!("  leaves={count:2}: {}", root.to_hex());
        }
    }
}
