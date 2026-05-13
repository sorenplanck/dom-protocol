//! Chain reorganization handling.
//!
//! When a competing chain has more total_difficulty than the current best,
//! we must reorganize: disconnect blocks from the current tip back to the
//! common ancestor, then connect the new chain's blocks.

use dom_core::{DomError, Hash256};

/// Find the common ancestor between two chains.
///
/// Returns the hash of the common ancestor block, or None if chains
/// share no common ancestor (different genesis — reject immediately).
pub fn find_common_ancestor(
    _our_tip: Hash256,
    _their_tip: Hash256,
) -> Result<Option<Hash256>, DomError> {
    // Full implementation requires walking back through both chains.
    // Simplified: the genesis block is always the common ancestor for
    // chains on the same network (validated via chain_id in handshake).
    // TODO: implement full ancestor walk via block store.
    Ok(None)
}

/// Reorg limit: refuse to reorganize more than MAX_REORG_DEPTH blocks.
///
/// Per RFC-0000: MAX_REORG_DEPTH_POLICY = 1000 (policy, not consensus).
/// Deeper reorgs are rejected at the policy layer to prevent DoS.
pub fn check_reorg_depth(disconnect_count: u64) -> Result<(), DomError> {
    if disconnect_count > dom_core::MAX_REORG_DEPTH_POLICY {
        return Err(DomError::PolicyRejected(format!(
            "reorg depth {disconnect_count} exceeds MAX_REORG_DEPTH_POLICY {}",
            dom_core::MAX_REORG_DEPTH_POLICY
        )));
    }
    Ok(())
}
