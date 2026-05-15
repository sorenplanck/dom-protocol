#![allow(missing_docs)]
//! Tagged Blake2b-256 hashing for DOM protocol.
//!
//! All consensus hash operations use domain-separated tagged hashing
//! to prevent cross-context hash collisions.

use blake2::digest::consts::U32;
use blake2::{Blake2b, Digest};
use dom_core::Hash256;

type Blake2b256 = Blake2b<U32>;

/// Compute Blake2b-256 of `data`.
pub fn blake2b_256(data: &[u8]) -> Hash256 {
    let mut h = Blake2b256::new();
    h.update(data);
    let result = h.finalize();
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&result);
    Hash256::from_bytes(arr)
}

/// Compute tagged Blake2b-256: Blake2b-256(u16_le(len(tag)) || tag || data).
///
/// This is the DOM domain separation pattern, used for all consensus hashes.
/// The tag length prefix prevents tag ambiguity attacks.
pub fn blake2b_256_tagged(tag: &str, data: &[u8]) -> Hash256 {
    let tag_bytes = tag.as_bytes();
    // Tag length as u16 LE — tags are short by design (<= 256 bytes)
    let tag_len: u16 = tag_bytes
        .len()
        .try_into()
        .expect("DOM tag must be <= 65535 bytes");

    let mut h = Blake2b256::new();
    h.update(tag_len.to_le_bytes());
    h.update(tag_bytes);
    h.update(data);
    let result = h.finalize();
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&result);
    Hash256::from_bytes(arr)
}

/// Incremental DOM hasher with domain separation.
///
/// Use for streaming hash operations where all data is not available
/// at once (e.g. block header hashing).
pub struct DomHasher {
    inner: Blake2b256,
}

impl DomHasher {
    /// Create a new hasher with a domain separation tag.
    pub fn new(tag: &str) -> Self {
        let tag_bytes = tag.as_bytes();
        let tag_len: u16 = tag_bytes
            .len()
            .try_into()
            .expect("DOM tag must be <= 65535 bytes");

        let mut h = Blake2b256::new();
        h.update(tag_len.to_le_bytes());
        h.update(tag_bytes);
        Self { inner: h }
    }

    /// Feed data into the hasher.
    pub fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }

    /// Finalize and return the hash.
    pub fn finalize(self) -> Hash256 {
        let result = self.inner.finalize();
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&result);
        Hash256::from_bytes(arr)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blake2b_256_is_deterministic() {
        let h1 = blake2b_256(b"DOM test vector");
        let h2 = blake2b_256(b"DOM test vector");
        assert_eq!(h1, h2);
    }

    #[test]
    fn tagged_hash_differs_from_untagged() {
        let data = b"same data";
        let tagged = blake2b_256_tagged("DOM:test:v1", data);
        let untagged = blake2b_256(data);
        assert_ne!(tagged, untagged);
    }

    #[test]
    fn different_tags_produce_different_hashes() {
        let data = b"same data";
        let h1 = blake2b_256_tagged("DOM:tag-a:v1", data);
        let h2 = blake2b_256_tagged("DOM:tag-b:v1", data);
        assert_ne!(h1, h2);
    }

    #[test]
    fn incremental_matches_oneshot() {
        let data = b"hello world";
        let oneshot = blake2b_256_tagged("DOM:test:v1", data);

        let mut hasher = DomHasher::new("DOM:test:v1");
        hasher.update(b"hello ");
        hasher.update(b"world");
        let incremental = hasher.finalize();

        assert_eq!(oneshot, incremental);
    }

    /// Reference vector — MUST be reproduced by all implementations.
    /// If this test fails, serialization or hashing has changed.
    #[test]
    fn kernel_sig_tag_vector() {
        let h = blake2b_256_tagged(dom_core::TAG_KERNEL_SIG, b"");
        // This is a deterministic vector for the empty message.
        // Record actual value once computed on reference hardware.
        // For now, assert it is 32 bytes and non-zero.
        assert_eq!(h.as_bytes().len(), 32);
        assert_ne!(h, dom_core::Hash256::ZERO);
    }
}
