//! Block storage helpers.

use dom_core::Hash256;

/// Placeholder for block store operations.
/// Full implementation via DomStore::commit_block.
pub struct BlockStore;

impl BlockStore {
    /// Compute a block hash from serialized header bytes using Blake2b-256.
    pub fn compute_block_hash(header_bytes: &[u8]) -> Hash256 {
        use blake2::{Blake2b, Digest};
        use blake2::digest::consts::U32;
        type B2b256 = Blake2b<U32>;
        let mut h = B2b256::new();
        h.update(header_bytes);
        let result = h.finalize();
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&result);
        Hash256::from_bytes(arr)
    }
}
