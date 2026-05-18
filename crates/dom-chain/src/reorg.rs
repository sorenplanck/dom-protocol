//! Chain reorganization handling.
//!
//! When a competing chain has more total_difficulty than the current best,
//! we must reorganize: disconnect blocks from the current tip back to the
//! common ancestor, then connect the new chain's blocks.

use dom_consensus::block::BlockHeader;
use dom_core::{DomError, Hash256};
use dom_serialization::DomDeserialize;
use dom_store::DomStore;
use std::collections::HashSet;

/// Find the common ancestor between two chain tips.
///
/// Walks both chains backward via `prev_hash` simultaneously, recording all
/// visited hashes from `our_tip`. As soon as the walk from `their_tip`
/// encounters one of those hashes, that is the common ancestor.
///
/// Returns `Ok(Some(ancestor_hash))` on success, `Ok(None)` if the chains
/// share no common ancestor (different genesis — caller must reject the
/// remote chain). Returns `Err` if the store is corrupted or a header is
/// missing mid-walk.
///
/// Bounded by `MAX_REORG_DEPTH_POLICY` from each side to prevent DoS via
/// pathological remote chains. If the walk exceeds the limit without finding
/// an ancestor, returns `Ok(None)`.
pub fn find_common_ancestor(
    store: &DomStore,
    our_tip: Hash256,
    their_tip: Hash256,
) -> Result<Option<Hash256>, DomError> {
    // Same tip — trivial common ancestor.
    if our_tip == their_tip {
        return Ok(Some(our_tip));
    }

    let max_walk = dom_core::MAX_REORG_DEPTH_POLICY as usize;

    // Walk our chain backward, recording all hashes we visit.
    let mut our_chain: HashSet<Hash256> = HashSet::new();
    let mut cursor = our_tip;
    for _ in 0..=max_walk {
        our_chain.insert(cursor);
        if cursor == Hash256::ZERO {
            break;
        }
        match store.get_block_header(cursor.as_bytes())? {
            Some(bytes) => {
                let header = BlockHeader::from_bytes(&bytes)?;
                if header.prev_hash == Hash256::ZERO {
                    our_chain.insert(Hash256::ZERO);
                    break;
                }
                cursor = header.prev_hash;
            }
            None => {
                return Err(DomError::Internal(format!(
                    "missing header during ancestor walk: {cursor}"
                )));
            }
        }
    }

    // Walk their chain backward, return first hash that is in our set.
    let mut cursor = their_tip;
    for _ in 0..=max_walk {
        if our_chain.contains(&cursor) {
            return Ok(Some(cursor));
        }
        if cursor == Hash256::ZERO {
            break;
        }
        match store.get_block_header(cursor.as_bytes())? {
            Some(bytes) => {
                let header = BlockHeader::from_bytes(&bytes)?;
                cursor = header.prev_hash;
            }
            None => {
                // Their chain references a header we don't have.
                return Ok(None);
            }
        }
    }

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
