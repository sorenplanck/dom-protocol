//! Hash test vectors for DOM tagged Blake2b-256.
//!
//! These vectors MUST be reproduced identically by all conforming implementations.
//! If any vector fails, the implementation is non-conforming.

use dom_crypto::hash::{blake2b_256, blake2b_256_tagged};

/// A test vector for tagged hashing.
pub struct HashVector {
    /// Human-readable description.
    pub description: &'static str,
    /// Domain separation tag (empty string = untagged).
    pub tag: &'static str,
    /// Input data as hex.
    pub input_hex: &'static str,
    /// Expected output as hex (to be filled after first run).
    /// Empty string = not yet finalized (RELEASE BLOCKER).
    pub expected_hex: &'static str,
}

/// All hash vectors that must be verified.
///
/// Expected values are RELEASE BLOCKERs until the reference implementation
/// generates them and they are independently reproduced.
pub fn all_hash_vectors() -> Vec<HashVector> {
    vec![
        HashVector {
            description: "empty input, kernel-sig tag",
            tag: dom_core::TAG_KERNEL_SIG,
            input_hex: "",
            expected_hex: "", // RELEASE BLOCKER
        },
        HashVector {
            description: "empty input, PMMR empty tag",
            tag: dom_core::TAG_PMMR_EMPTY,
            input_hex: "",
            expected_hex: "", // RELEASE BLOCKER
        },
        HashVector {
            description: "empty input, PMMR bag tag",
            tag: dom_core::TAG_PMMR_BAG,
            input_hex: "",
            expected_hex: "", // RELEASE BLOCKER
        },
        HashVector {
            description: "empty input, PMMR leaf tag",
            tag: dom_core::TAG_PMMR_LEAF,
            input_hex: "",
            expected_hex: "", // RELEASE BLOCKER
        },
        HashVector {
            description: "empty input, PMMR node tag",
            tag: dom_core::TAG_PMMR_NODE,
            input_hex: "",
            expected_hex: "", // RELEASE BLOCKER
        },
        HashVector {
            description: "empty input, H2C tag",
            tag: dom_core::TAG_H2C,
            input_hex: "",
            expected_hex: "", // RELEASE BLOCKER
        },
        HashVector {
            description: "known bytes, kernel-sig tag",
            tag: dom_core::TAG_KERNEL_SIG,
            input_hex: "deadbeef",
            expected_hex: "", // RELEASE BLOCKER
        },
    ]
}

/// Generate all hash vectors and print them.
/// Run this once on the reference implementation to capture the expected values.
pub fn generate_hash_vectors() -> Vec<(String, String)> {
    let mut results = Vec::new();
    for v in all_hash_vectors() {
        let input = hex::decode(v.input_hex).unwrap_or_default();
        let hash = if v.tag.is_empty() {
            blake2b_256(&input)
        } else {
            blake2b_256_tagged(v.tag, &input)
        };
        results.push((v.description.to_string(), hash.to_hex()));
    }
    results
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify that hash generation is deterministic across runs.
    #[test]
    fn hash_vectors_are_deterministic() {
        let run1 = generate_hash_vectors();
        let run2 = generate_hash_vectors();
        assert_eq!(run1, run2, "Hash vectors must be deterministic");
    }

    /// Verify all hashes are non-zero (sanity check).
    #[test]
    fn hash_vectors_are_nonzero() {
        for (desc, hex) in generate_hash_vectors() {
            assert_eq!(
                hex.len(),
                64,
                "Hash must be 32 bytes (64 hex chars): {desc}"
            );
            assert_ne!(
                hex, "0000000000000000000000000000000000000000000000000000000000000000",
                "Hash must not be zero: {desc}"
            );
        }
    }

    /// Print vectors for documentation (run with -- --nocapture).
    #[test]
    fn print_hash_vectors() {
        println!("\n=== DOM Hash Vectors (Reference Implementation) ===");
        for (desc, hex) in generate_hash_vectors() {
            println!("{desc}:\n  {hex}");
        }
    }
}
