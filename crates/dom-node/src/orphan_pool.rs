//! Runtime orphan block pool.
//!
//! This is node-local, bounded, and intentionally not persisted. Consensus
//! validity still belongs to `ChainState::connect_block`; the pool only retains
//! child-before-parent block bytes long enough to re-feed them after the parent
//! arrives.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

/// Block retained because its parent was missing at first delivery.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OrphanBlock {
    pub block_hash: [u8; 32],
    pub parent_hash: [u8; 32],
    pub height: u64,
    pub block_bytes: Vec<u8>,
}

/// Insert outcome for spam/bounds accounting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OrphanInsertOutcome {
    Inserted,
    Duplicate,
    EvictedOldest,
    RejectedParentLimit,
}

/// Bounded orphan pool indexed by missing parent hash.
#[derive(Debug)]
pub struct RuntimeOrphanPool {
    max_total: usize,
    max_per_parent: usize,
    by_hash: BTreeMap<[u8; 32], OrphanBlock>,
    by_parent: BTreeMap<[u8; 32], BTreeSet<[u8; 32]>>,
    insertion_order: VecDeque<[u8; 32]>,
}

impl RuntimeOrphanPool {
    pub fn new(max_total: usize, max_per_parent: usize) -> Self {
        Self {
            max_total: max_total.max(1),
            max_per_parent: max_per_parent.max(1),
            by_hash: BTreeMap::new(),
            by_parent: BTreeMap::new(),
            insertion_order: VecDeque::new(),
        }
    }

    pub fn len(&self) -> usize {
        self.by_hash.len()
    }

    pub fn is_empty(&self) -> bool {
        self.by_hash.is_empty()
    }

    pub fn insert(&mut self, orphan: OrphanBlock) -> OrphanInsertOutcome {
        if self.by_hash.contains_key(&orphan.block_hash) {
            return OrphanInsertOutcome::Duplicate;
        }
        let parent_count = self
            .by_parent
            .get(&orphan.parent_hash)
            .map(|set| set.len())
            .unwrap_or(0);
        if parent_count >= self.max_per_parent {
            return OrphanInsertOutcome::RejectedParentLimit;
        }

        let mut outcome = OrphanInsertOutcome::Inserted;
        if self.by_hash.len() >= self.max_total {
            self.evict_oldest();
            outcome = OrphanInsertOutcome::EvictedOldest;
        }

        self.by_parent
            .entry(orphan.parent_hash)
            .or_default()
            .insert(orphan.block_hash);
        self.insertion_order.push_back(orphan.block_hash);
        self.by_hash.insert(orphan.block_hash, orphan);
        outcome
    }

    pub fn take_children(&mut self, parent_hash: &[u8; 32]) -> Vec<OrphanBlock> {
        let Some(children) = self.by_parent.remove(parent_hash) else {
            return Vec::new();
        };
        let mut out = Vec::new();
        for child_hash in children {
            if let Some(orphan) = self.by_hash.remove(&child_hash) {
                out.push(orphan);
            }
        }
        self.insertion_order
            .retain(|hash| self.by_hash.contains_key(hash));
        out.sort_unstable_by_key(|orphan| (orphan.height, orphan.block_hash));
        out
    }

    fn evict_oldest(&mut self) {
        while let Some(hash) = self.insertion_order.pop_front() {
            if let Some(orphan) = self.by_hash.remove(&hash) {
                if let Some(children) = self.by_parent.get_mut(&orphan.parent_hash) {
                    children.remove(&hash);
                    if children.is_empty() {
                        self.by_parent.remove(&orphan.parent_hash);
                    }
                }
                break;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(seed: u8) -> [u8; 32] {
        let mut x = [0u8; 32];
        x[0] = seed;
        x
    }

    fn orphan(child: u8, parent: u8, height: u64) -> OrphanBlock {
        OrphanBlock {
            block_hash: h(child),
            parent_hash: h(parent),
            height,
            block_bytes: vec![child],
        }
    }

    #[test]
    fn child_before_parent_is_retained_and_released_on_parent_arrival() {
        let mut pool = RuntimeOrphanPool::new(8, 4);
        assert_eq!(pool.insert(orphan(2, 1, 2)), OrphanInsertOutcome::Inserted);
        assert_eq!(pool.len(), 1);
        let children = pool.take_children(&h(1));
        assert_eq!(children.len(), 1);
        assert_eq!(children[0].block_hash, h(2));
        assert!(pool.is_empty());
    }

    #[test]
    fn duplicate_orphan_delivery_does_not_create_duplicate_work() {
        let mut pool = RuntimeOrphanPool::new(8, 4);
        assert_eq!(pool.insert(orphan(2, 1, 2)), OrphanInsertOutcome::Inserted);
        assert_eq!(pool.insert(orphan(2, 1, 2)), OrphanInsertOutcome::Duplicate);
        assert_eq!(pool.take_children(&h(1)).len(), 1);
    }

    #[test]
    fn orphan_spam_is_bounded_by_total_and_parent_limits() {
        let mut pool = RuntimeOrphanPool::new(2, 2);
        assert_eq!(pool.insert(orphan(2, 1, 2)), OrphanInsertOutcome::Inserted);
        assert_eq!(pool.insert(orphan(3, 1, 3)), OrphanInsertOutcome::Inserted);
        assert_eq!(
            pool.insert(orphan(4, 1, 4)),
            OrphanInsertOutcome::RejectedParentLimit
        );
        assert_eq!(
            pool.insert(orphan(5, 4, 5)),
            OrphanInsertOutcome::EvictedOldest
        );
        assert_eq!(pool.len(), 2);
    }

    #[test]
    fn children_are_reprocessed_in_deterministic_order() {
        let mut pool = RuntimeOrphanPool::new(8, 8);
        pool.insert(orphan(4, 1, 4));
        pool.insert(orphan(2, 1, 2));
        pool.insert(orphan(3, 1, 3));
        let hashes: Vec<_> = pool
            .take_children(&h(1))
            .into_iter()
            .map(|orphan| orphan.block_hash)
            .collect();
        assert_eq!(hashes, vec![h(2), h(3), h(4)]);
    }
}
