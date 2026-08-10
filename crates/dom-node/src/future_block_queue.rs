//! Future block queue for soft buffer timestamp handling.
//!
//! Blocks with timestamps slightly beyond MAX_FUTURE_BLOCK_TIME are held
//! in this queue for re-evaluation instead of immediate rejection. This
//! reduces orphan rates from transient clock drift without weakening the
//! consensus rule (MAX_FUTURE_BLOCK_TIME remains the hard limit).
//!
//! The queue is intentionally runtime-only. After restart it begins empty and
//! does not reconstruct deferred runtime state implicitly.
//!
//! Replay order for ready blocks is canonical at the drain boundary:
//! `block_height ASC`, then `block_hash ASC`.
//!
//! Section 12.2 of the DOM Protocol Design Philosophy.

use std::cmp::Reverse;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::RwLock;

/// Maximum entries in the future block queue.
///
/// This count bound complements the aggregate byte bound below.
pub const MAX_FUTURE_BLOCKS: usize = 256;

/// Maximum canonical serialized bytes retained by the future-block queue.
///
/// A protocol block may be at most 16 MiB. Sixty-four MiB therefore permits
/// four maximum-size deferred blocks, while reducing the prior 4 GiB payload
/// retention bound (`256 * 16 MiB`) to a fixed, node-local policy budget.
pub const MAX_FUTURE_BLOCK_QUEUE_BYTES: usize = 64 * 1_024 * 1_024;

/// An entry held in the future block queue.
#[derive(Debug, Clone)]
pub struct DeferredBlock {
    /// Hash of the block being deferred.
    pub block_hash: [u8; 32],
    /// Height declared by the block header.
    pub block_height: u64,
    /// Block timestamp (seconds since epoch).
    pub timestamp: u64,
    /// When this entry was queued (for expiry).
    pub queued_at: Instant,
    /// Canonical serialized block bytes for re-evaluation.
    pub block_bytes: Vec<u8>,
}

#[derive(Debug)]
struct StoredDeferredBlock {
    block: DeferredBlock,
    retained_size: usize,
}

#[derive(Debug, Default)]
struct QueueState {
    entries: HashMap<[u8; 32], StoredDeferredBlock>,
    total_retained_bytes: usize,
}

type EvictionOrderKey = (Reverse<u64>, Reverse<usize>, Reverse<[u8; 32]>, bool);

/// Result of attempting to retain a future block.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FutureBlockAdmission {
    /// The block was retained without replacing a block with the same hash.
    Queued,
    /// The block replaced an existing block with the same hash.
    Replaced,
    /// The block itself exceeds the aggregate queue byte cap.
    RejectedOversized,
    /// Admission would exceed a queue cap and the candidate has lowest priority.
    RejectedCapacity,
    /// Checked accounting could not preserve the queue invariant.
    RejectedArithmetic,
}

impl FutureBlockAdmission {
    /// Whether the block is retained by the queue after this operation.
    pub const fn is_admitted(self) -> bool {
        matches!(self, Self::Queued | Self::Replaced)
    }
}

/// Queue of blocks deferred due to soft buffer.
pub struct FutureBlockQueue {
    state: Arc<RwLock<QueueState>>,
    max_size: usize,
    max_retained_bytes: usize,
}

impl FutureBlockQueue {
    /// Create a new empty queue with default capacity.
    pub fn new() -> Self {
        Self {
            state: Arc::new(RwLock::new(QueueState::default())),
            max_size: MAX_FUTURE_BLOCKS,
            max_retained_bytes: MAX_FUTURE_BLOCK_QUEUE_BYTES,
        }
    }

    #[cfg(test)]
    fn with_limits(max_size: usize, max_retained_bytes: usize) -> Self {
        Self {
            state: Arc::new(RwLock::new(QueueState::default())),
            max_size,
            max_retained_bytes,
        }
    }

    /// Add a canonical serialized block to the deferred queue.
    ///
    /// When a cap is exceeded, the queue considers the candidate together with
    /// existing entries and evicts the least useful entries first: greatest
    /// declared height, then greatest canonical serialized length, then greatest
    /// block hash. This order is independent of `HashMap` iteration and prevents
    /// insertion timing from preserving farther-future or larger blocks.
    pub async fn admit(&self, block: DeferredBlock) -> FutureBlockAdmission {
        let retained_size = block.block_bytes.len();
        if retained_size > self.max_retained_bytes {
            return FutureBlockAdmission::RejectedOversized;
        }

        let mut state = self.state.write().await;
        let replacing = state.entries.contains_key(&block.block_hash);
        let old_size = state
            .entries
            .get(&block.block_hash)
            .map(|stored| stored.retained_size)
            .unwrap_or_default();
        let base_total = match state.total_retained_bytes.checked_sub(old_size) {
            Some(total) => total,
            None => return FutureBlockAdmission::RejectedArithmetic,
        };
        let mut projected_total = match base_total.checked_add(retained_size) {
            Some(total) => total,
            None => return FutureBlockAdmission::RejectedArithmetic,
        };
        let mut projected_count = state.entries.len();
        if !replacing {
            projected_count = match projected_count.checked_add(1) {
                Some(count) => count,
                None => return FutureBlockAdmission::RejectedArithmetic,
            };
        }

        // The candidate participates in eviction ordering before any state is
        // changed. If it is the next eviction target, admission is rejected and
        // the existing queue remains untouched.
        let mut eviction_order: Vec<EvictionOrderKey> = state
            .entries
            .iter()
            .filter(|(hash, _)| **hash != block.block_hash)
            .map(|(hash, stored)| {
                (
                    Reverse(stored.block.block_height),
                    Reverse(stored.retained_size),
                    Reverse(*hash),
                    false,
                )
            })
            .collect();
        eviction_order.push((
            Reverse(block.block_height),
            Reverse(retained_size),
            Reverse(block.block_hash),
            true,
        ));
        eviction_order.sort_unstable();

        let mut evictions = Vec::new();
        for (_, _, Reverse(hash), is_candidate) in eviction_order {
            if projected_count <= self.max_size && projected_total <= self.max_retained_bytes {
                break;
            }
            if is_candidate {
                return FutureBlockAdmission::RejectedCapacity;
            }
            let Some(stored) = state.entries.get(&hash) else {
                return FutureBlockAdmission::RejectedArithmetic;
            };
            projected_total = match projected_total.checked_sub(stored.retained_size) {
                Some(total) => total,
                None => return FutureBlockAdmission::RejectedArithmetic,
            };
            projected_count = match projected_count.checked_sub(1) {
                Some(count) => count,
                None => return FutureBlockAdmission::RejectedArithmetic,
            };
            evictions.push(hash);
        }

        if projected_count > self.max_size || projected_total > self.max_retained_bytes {
            return FutureBlockAdmission::RejectedCapacity;
        }

        if replacing {
            let Some(old) = state.entries.remove(&block.block_hash) else {
                return FutureBlockAdmission::RejectedArithmetic;
            };
            state.total_retained_bytes =
                match state.total_retained_bytes.checked_sub(old.retained_size) {
                    Some(total) => total,
                    None => return FutureBlockAdmission::RejectedArithmetic,
                };
        }
        for hash in evictions {
            let Some(evicted) = state.entries.remove(&hash) else {
                return FutureBlockAdmission::RejectedArithmetic;
            };
            state.total_retained_bytes = match state
                .total_retained_bytes
                .checked_sub(evicted.retained_size)
            {
                Some(total) => total,
                None => return FutureBlockAdmission::RejectedArithmetic,
            };
        }
        state.entries.insert(
            block.block_hash,
            StoredDeferredBlock {
                block,
                retained_size,
            },
        );
        state.total_retained_bytes = projected_total;

        if replacing {
            FutureBlockAdmission::Replaced
        } else {
            FutureBlockAdmission::Queued
        }
    }

    /// Backward-compatible boolean admission helper.
    pub async fn defer(&self, block: DeferredBlock) -> bool {
        self.admit(block).await.is_admitted()
    }

    /// Remove a specific block from the queue.
    pub async fn remove(&self, block_hash: &[u8; 32]) -> Option<DeferredBlock> {
        let mut state = self.state.write().await;
        let stored = state.entries.remove(block_hash)?;
        state.total_retained_bytes = state
            .total_retained_bytes
            .checked_sub(stored.retained_size)
            .expect("future-block queue accounting invariant");
        Some(stored.block)
    }

    /// Drain blocks whose timestamps are now within the hard limit.
    ///
    /// Ready blocks are returned in canonical replay order:
    /// `block_height ASC`, then `block_hash ASC`.
    pub async fn drain_ready(&self, now_secs: u64, hard_limit_secs: u64) -> Vec<DeferredBlock> {
        let mut state = self.state.write().await;
        let ready_cutoff = now_secs.saturating_add(hard_limit_secs);

        let mut ready_keys: Vec<(u64, [u8; 32])> = state
            .entries
            .iter()
            .filter(|(_, stored)| stored.block.timestamp <= ready_cutoff)
            .map(|(h, stored)| (stored.block.block_height, *h))
            .collect();
        ready_keys.sort_by(|(left_height, left_hash), (right_height, right_hash)| {
            left_height
                .cmp(right_height)
                .then_with(|| left_hash.as_slice().cmp(right_hash.as_slice()))
        });

        let mut ready = Vec::with_capacity(ready_keys.len());
        for (_, hash) in ready_keys {
            if let Some(stored) = state.entries.remove(&hash) {
                state.total_retained_bytes = state
                    .total_retained_bytes
                    .checked_sub(stored.retained_size)
                    .expect("future-block queue accounting invariant");
                ready.push(stored.block);
            }
        }

        ready
    }

    /// Drop entries that have been in the queue beyond expiry.
    /// Should be called periodically.
    pub async fn evict_expired(&self, max_age_secs: u64) -> usize {
        let mut state = self.state.write().await;
        let now = Instant::now();
        let expired: Vec<[u8; 32]> = state
            .entries
            .iter()
            .filter_map(|(hash, stored)| {
                (now.duration_since(stored.block.queued_at).as_secs() >= max_age_secs)
                    .then_some(*hash)
            })
            .collect();
        for hash in &expired {
            let stored = state
                .entries
                .remove(hash)
                .expect("expired future-block entry must exist");
            state.total_retained_bytes = state
                .total_retained_bytes
                .checked_sub(stored.retained_size)
                .expect("future-block queue accounting invariant");
        }
        expired.len()
    }

    /// Get current queue size.
    pub async fn size(&self) -> usize {
        self.state.read().await.entries.len()
    }

    /// Get exact canonical serialized bytes retained by queued blocks.
    pub async fn retained_bytes(&self) -> usize {
        self.state.read().await.total_retained_bytes
    }

    /// Check if a specific block is queued.
    pub async fn contains(&self, block_hash: &[u8; 32]) -> bool {
        self.state.read().await.entries.contains_key(block_hash)
    }

    /// Clear all entries.
    pub async fn clear(&self) {
        let mut state = self.state.write().await;
        state.entries.clear();
        state.total_retained_bytes = 0;
    }

    #[cfg(test)]
    async fn assert_invariants(&self) {
        let state = self.state.read().await;
        let recomputed = state.entries.values().try_fold(0usize, |total, stored| {
            assert_eq!(stored.retained_size, stored.block.block_bytes.len());
            total.checked_add(stored.retained_size)
        });
        assert_eq!(Some(state.total_retained_bytes), recomputed);
        assert!(state.entries.len() <= self.max_size);
        assert!(state.total_retained_bytes <= self.max_retained_bytes);
    }
}

impl Default for FutureBlockQueue {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dom_core::MAX_BLOCK_SERIALIZED_SIZE;

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct FutureQueueSnapshot {
        final_tip_height: u64,
        final_tip_hash: [u8; 32],
        applied_hashes: Vec<[u8; 32]>,
        pending_hashes: Vec<[u8; 32]>,
    }

    fn mock_block(hash_byte: u8, block_height: u64, timestamp: u64) -> DeferredBlock {
        mock_block_with_len(hash_byte, block_height, timestamp, 100)
    }

    fn mock_block_with_len(
        hash_byte: u8,
        block_height: u64,
        timestamp: u64,
        len: usize,
    ) -> DeferredBlock {
        DeferredBlock {
            block_hash: [hash_byte; 32],
            block_height,
            timestamp,
            queued_at: Instant::now(),
            block_bytes: vec![0u8; len],
        }
    }

    async fn pending_hashes(queue: &FutureBlockQueue) -> Vec<[u8; 32]> {
        let state = queue.state.read().await;
        let mut hashes: Vec<[u8; 32]> = state.entries.keys().copied().collect();
        hashes.sort();
        hashes
    }

    async fn capture_future_snapshot(
        queue: &FutureBlockQueue,
        applied: Vec<DeferredBlock>,
    ) -> FutureQueueSnapshot {
        let final_tip_height = applied
            .iter()
            .map(|block| block.block_height)
            .max()
            .unwrap_or_default();
        let final_tip_hash = applied
            .iter()
            .filter(|block| block.block_height == final_tip_height)
            .map(|block| block.block_hash)
            .max()
            .unwrap_or([0u8; 32]);
        FutureQueueSnapshot {
            final_tip_height,
            final_tip_hash,
            applied_hashes: applied.into_iter().map(|block| block.block_hash).collect(),
            pending_hashes: pending_hashes(queue).await,
        }
    }

    #[tokio::test]
    async fn defer_and_retrieve() {
        let queue = FutureBlockQueue::new();
        let block = mock_block(1, 10, 1000);
        assert!(queue.defer(block.clone()).await);
        assert!(queue.contains(&block.block_hash).await);
        assert_eq!(queue.size().await, 1);
    }

    #[tokio::test]
    async fn drain_ready_works() {
        let queue = FutureBlockQueue::new();
        // Block at timestamp 1500 — should be ready when now=1400, limit=120
        queue.defer(mock_block(1, 11, 1500)).await;
        // Block at timestamp 2000 — should NOT be ready yet
        queue.defer(mock_block(2, 12, 2000)).await;

        let ready = queue.drain_ready(1400, 120).await;
        assert_eq!(ready.len(), 1);
        assert_eq!(ready[0].timestamp, 1500);
        assert_eq!(ready[0].block_height, 11);
        assert_eq!(queue.size().await, 1);
    }

    #[tokio::test]
    async fn drain_ready_is_canonical_by_height_then_hash() {
        let queue = FutureBlockQueue::new();
        queue.defer(mock_block(9, 11, 1490)).await;
        queue.defer(mock_block(2, 10, 1500)).await;
        queue.defer(mock_block(4, 10, 1490)).await;

        let ready = queue.drain_ready(1400, 120).await;
        let hashes: Vec<[u8; 32]> = ready.into_iter().map(|block| block.block_hash).collect();
        assert_eq!(hashes, vec![[2u8; 32], [4u8; 32], [9u8; 32]]);
    }

    #[tokio::test]
    async fn repeated_runs_with_same_blocks_produce_same_replay_order() {
        let a = FutureBlockQueue::new();
        let b = FutureBlockQueue::new();
        let blocks = vec![
            mock_block(7, 12, 1502),
            mock_block(1, 10, 1490),
            mock_block(3, 11, 1502),
            mock_block(2, 10, 1490),
        ];

        for block in &blocks {
            assert!(a.defer(block.clone()).await);
        }
        for block in blocks.into_iter().rev() {
            assert!(b.defer(block).await);
        }

        let order_a: Vec<[u8; 32]> = a
            .drain_ready(1400, 200)
            .await
            .into_iter()
            .map(|block| block.block_hash)
            .collect();
        let order_b: Vec<[u8; 32]> = b
            .drain_ready(1400, 200)
            .await
            .into_iter()
            .map(|block| block.block_hash)
            .collect();

        assert_eq!(order_a, order_b);
        assert_eq!(order_a, vec![[1u8; 32], [2u8; 32], [3u8; 32], [7u8; 32]]);
    }

    #[tokio::test]
    async fn not_ready_blocks_remain_queued_after_canonical_drain() {
        let queue = FutureBlockQueue::new();
        let ready_low = mock_block(2, 10, 1495);
        let ready_high = mock_block(1, 11, 1490);
        let not_ready = mock_block(9, 9, 5000);

        assert!(queue.defer(ready_high.clone()).await);
        assert!(queue.defer(not_ready.clone()).await);
        assert!(queue.defer(ready_low.clone()).await);

        let ready = queue.drain_ready(1400, 120).await;
        let hashes: Vec<[u8; 32]> = ready.into_iter().map(|block| block.block_hash).collect();
        assert_eq!(hashes, vec![ready_low.block_hash, ready_high.block_hash]);
        assert!(queue.contains(&not_ready.block_hash).await);
        assert_eq!(queue.size().await, 1);
    }

    #[tokio::test]
    async fn evict_expired_works() {
        let queue = FutureBlockQueue::new();
        let mut block = mock_block(1, 10, 1000);
        // Backdate by 2s only: `Instant` cannot represent times before boot,
        // so a 1h backdate silently became "now" on freshly booted CI
        // runners (uptime < 1h) and nothing was evicted.
        block.queued_at = Instant::now()
            .checked_sub(std::time::Duration::from_secs(2))
            .expect("machine uptime exceeds 2s");
        queue.defer(block).await;

        let evicted = queue.evict_expired(1).await; // 1s max age
        assert_eq!(evicted, 1);
        assert_eq!(queue.size().await, 0);
    }

    #[tokio::test]
    async fn full_queue_rejects() {
        let queue = FutureBlockQueue::with_limits(2, 1_000);
        assert!(queue.defer(mock_block(1, 10, 1000)).await);
        assert!(queue.defer(mock_block(2, 11, 1000)).await);
        // Third should be rejected
        assert!(!queue.defer(mock_block(3, 12, 1000)).await);
    }

    #[tokio::test]
    async fn remove_works() {
        let queue = FutureBlockQueue::new();
        let block = mock_block(1, 10, 1000);
        queue.defer(block.clone()).await;

        let removed = queue.remove(&block.block_hash).await;
        assert!(removed.is_some());
        assert_eq!(queue.size().await, 0);
    }

    #[tokio::test]
    async fn duplicate_defer_replaces_without_growing_queue() {
        let queue = FutureBlockQueue::new();
        let first = mock_block(1, 10, 1000);
        let mut replacement = mock_block(1, 11, 1100);
        replacement.block_bytes = vec![0xAB; 64];

        assert!(queue.defer(first).await);
        assert!(queue.defer(replacement.clone()).await);
        assert_eq!(queue.size().await, 1);

        let removed = queue.remove(&replacement.block_hash).await.unwrap();
        assert_eq!(removed.block_height, 11);
        assert_eq!(removed.timestamp, 1100);
        assert_eq!(removed.block_bytes, vec![0xAB; 64]);
    }

    #[tokio::test]
    async fn full_queue_rejects_new_hash_but_keeps_existing_entries() {
        let queue = FutureBlockQueue::with_limits(2, 1_000);
        let first = mock_block(1, 10, 1000);
        let second = mock_block(2, 11, 1000);
        let third = mock_block(3, 12, 1000);

        assert!(queue.defer(first.clone()).await);
        assert!(queue.defer(second.clone()).await);
        assert!(!queue.defer(third).await);

        assert_eq!(queue.size().await, 2);
        assert!(queue.contains(&first.block_hash).await);
        assert!(queue.contains(&second.block_hash).await);
    }

    #[tokio::test]
    async fn duplicate_defer_replaces_even_when_queue_is_full() {
        let queue = FutureBlockQueue::with_limits(1, 1_000);
        let first = mock_block(1, 10, 1000);
        let mut replacement = mock_block(1, 11, 1100);
        replacement.block_bytes = vec![0xCD; 32];

        assert!(queue.defer(first).await);
        assert!(queue.defer(replacement.clone()).await);
        assert_eq!(queue.size().await, 1);

        let removed = queue.remove(&replacement.block_hash).await.unwrap();
        assert_eq!(removed.block_height, 11);
        assert_eq!(removed.timestamp, 1100);
        assert_eq!(removed.block_bytes, vec![0xCD; 32]);
    }

    #[tokio::test]
    async fn repeated_empty_drains_are_stable() {
        let queue = FutureBlockQueue::new();
        assert!(queue.defer(mock_block(5, 12, 5000)).await);

        let first = queue.drain_ready(1400, 120).await;
        let second = queue.drain_ready(1400, 120).await;

        assert!(first.is_empty());
        assert!(second.is_empty());
        assert_eq!(queue.size().await, 1);
    }

    #[tokio::test]
    async fn restart_drop_policy_converges_after_deterministic_redelivery() {
        let blocks = vec![
            mock_block(7, 12, 2_000),
            mock_block(1, 10, 2_000),
            mock_block(4, 11, 2_000),
            mock_block(2, 10, 2_000),
        ];

        let uninterrupted = FutureBlockQueue::new();
        for block in &blocks {
            assert!(uninterrupted.defer(block.clone()).await);
        }
        let uninterrupted_ready = uninterrupted.drain_ready(1_900, 200).await;
        let uninterrupted_snapshot =
            capture_future_snapshot(&uninterrupted, uninterrupted_ready.clone()).await;

        let before_restart = FutureBlockQueue::new();
        for block in blocks.iter().rev() {
            assert!(before_restart.defer(block.clone()).await);
        }
        assert_eq!(before_restart.size().await, blocks.len());

        // Runtime-only policy: restart creates a fresh empty queue. Pending
        // future blocks are not implicit consensus or replay state.
        let after_restart = FutureBlockQueue::new();
        assert_eq!(after_restart.size().await, 0);

        // Convergence depends on deterministic redelivery/re-request from peers:
        // even if redelivered in a different order, drain order and final
        // snapshot match the uninterrupted run.
        for index in [2usize, 0, 3, 1] {
            assert!(after_restart.defer(blocks[index].clone()).await);
        }
        let restarted_ready = after_restart.drain_ready(1_900, 200).await;
        let restarted_snapshot = capture_future_snapshot(&after_restart, restarted_ready).await;

        assert_eq!(
            uninterrupted_snapshot.applied_hashes,
            vec![[1u8; 32], [2u8; 32], [4u8; 32], [7u8; 32]]
        );
        assert_eq!(uninterrupted_snapshot, restarted_snapshot);
    }

    #[tokio::test]
    async fn local_elapsed_time_does_not_change_ready_drain_result() {
        let mut fast_clock = vec![
            mock_block(9, 12, 2_001),
            mock_block(3, 10, 2_000),
            mock_block(5, 11, 2_000),
        ];
        let mut slow_clock = fast_clock.clone();
        for (idx, block) in slow_clock.iter_mut().enumerate() {
            block.queued_at = Instant::now()
                .checked_sub(std::time::Duration::from_secs(60 + idx as u64))
                .unwrap_or_else(Instant::now);
        }

        let fast_queue = FutureBlockQueue::new();
        let slow_queue = FutureBlockQueue::new();
        for block in fast_clock.drain(..) {
            assert!(fast_queue.defer(block).await);
        }
        for block in slow_clock.drain(..).rev() {
            assert!(slow_queue.defer(block).await);
        }

        let fast_snapshot =
            capture_future_snapshot(&fast_queue, fast_queue.drain_ready(1_900, 200).await).await;
        let slow_snapshot =
            capture_future_snapshot(&slow_queue, slow_queue.drain_ready(1_900, 200).await).await;

        assert_eq!(fast_snapshot, slow_snapshot);
        assert_eq!(
            fast_snapshot.applied_hashes,
            vec![[3u8; 32], [5u8; 32], [9u8; 32]]
        );
        assert!(fast_snapshot.pending_hashes.is_empty());
    }

    #[tokio::test]
    async fn byte_accounting_tracks_insert_remove_promotion_expiry_and_clear() {
        let queue = FutureBlockQueue::with_limits(8, 1_000);
        assert_eq!(queue.size().await, 0);
        assert_eq!(queue.retained_bytes().await, 0);

        let first = mock_block_with_len(1, 10, 1_050, 120);
        let second = mock_block_with_len(2, 11, 2_000, 80);
        assert_eq!(
            queue.admit(first.clone()).await,
            FutureBlockAdmission::Queued
        );
        assert_eq!(queue.retained_bytes().await, 120);
        assert_eq!(
            queue.admit(second.clone()).await,
            FutureBlockAdmission::Queued
        );
        assert_eq!(queue.retained_bytes().await, 200);
        queue.assert_invariants().await;

        assert!(queue.remove(&second.block_hash).await.is_some());
        assert_eq!(queue.size().await, 1);
        assert_eq!(queue.retained_bytes().await, 120);
        queue.assert_invariants().await;

        let promoted = queue.drain_ready(1_000, 60).await;
        assert_eq!(promoted.len(), 1);
        assert_eq!(promoted[0].block_hash, first.block_hash);
        assert_eq!(queue.size().await, 0);
        assert_eq!(queue.retained_bytes().await, 0);

        let mut expired = mock_block_with_len(3, 12, 9_000, 75);
        expired.queued_at = Instant::now()
            .checked_sub(std::time::Duration::from_secs(2))
            .expect("machine uptime exceeds 2s");
        assert!(queue.defer(expired).await);
        assert_eq!(queue.evict_expired(1).await, 1);
        assert_eq!(queue.retained_bytes().await, 0);

        assert!(queue.defer(mock_block_with_len(4, 13, 9_000, 64)).await);
        queue.clear().await;
        assert_eq!(queue.size().await, 0);
        assert_eq!(queue.retained_bytes().await, 0);
        queue.assert_invariants().await;
    }

    #[tokio::test]
    async fn duplicate_replacement_updates_exact_byte_accounting() {
        let queue = FutureBlockQueue::with_limits(2, 1_000);
        assert_eq!(
            queue.admit(mock_block_with_len(1, 10, 1_000, 100)).await,
            FutureBlockAdmission::Queued
        );
        assert_eq!(queue.retained_bytes().await, 100);
        assert_eq!(
            queue.admit(mock_block_with_len(1, 11, 1_100, 250)).await,
            FutureBlockAdmission::Replaced
        );
        assert_eq!(queue.size().await, 1);
        assert_eq!(queue.retained_bytes().await, 250);
        queue.assert_invariants().await;
    }

    #[tokio::test]
    async fn aggregate_byte_cap_evicts_farthest_future_entry_deterministically() {
        let queue = FutureBlockQueue::with_limits(3, 250);
        let near = mock_block_with_len(1, 10, 2_000, 100);
        let far = mock_block_with_len(2, 20, 2_000, 100);
        let candidate = mock_block_with_len(3, 5, 2_000, 100);
        assert!(queue.defer(near.clone()).await);
        assert!(queue.defer(far.clone()).await);
        assert_eq!(
            queue.admit(candidate.clone()).await,
            FutureBlockAdmission::Queued
        );

        assert_eq!(queue.size().await, 2);
        assert_eq!(queue.retained_bytes().await, 200);
        assert!(queue.contains(&near.block_hash).await);
        assert!(queue.contains(&candidate.block_hash).await);
        assert!(!queue.contains(&far.block_hash).await);
        queue.assert_invariants().await;
    }

    #[tokio::test]
    async fn equal_height_eviction_uses_largest_hash_as_stable_tie_breaker() {
        let queue = FutureBlockQueue::with_limits(2, 1_000);
        let low_hash = mock_block_with_len(2, 10, 2_000, 100);
        let high_hash = mock_block_with_len(7, 10, 2_000, 100);
        let candidate = mock_block_with_len(3, 10, 2_000, 100);
        assert!(queue.defer(low_hash.clone()).await);
        assert!(queue.defer(high_hash.clone()).await);
        assert_eq!(
            queue.admit(candidate.clone()).await,
            FutureBlockAdmission::Queued
        );

        assert!(queue.contains(&low_hash.block_hash).await);
        assert!(queue.contains(&candidate.block_hash).await);
        assert!(!queue.contains(&high_hash.block_hash).await);
        assert_eq!(queue.retained_bytes().await, 200);
        queue.assert_invariants().await;
    }

    #[tokio::test]
    async fn oversized_single_entry_is_rejected_atomically_and_queue_remains_usable() {
        let queue = FutureBlockQueue::with_limits(4, 200);
        let retained = mock_block_with_len(1, 10, 2_000, 100);
        assert!(queue.defer(retained.clone()).await);

        let oversized = mock_block_with_len(2, 1, 2_000, 201);
        assert_eq!(
            queue.admit(oversized).await,
            FutureBlockAdmission::RejectedOversized
        );
        assert_eq!(queue.size().await, 1);
        assert_eq!(queue.retained_bytes().await, 100);
        assert!(queue.contains(&retained.block_hash).await);

        assert!(queue.defer(mock_block_with_len(3, 9, 2_000, 50)).await);
        assert_eq!(queue.retained_bytes().await, 150);
        queue.assert_invariants().await;
    }

    #[tokio::test]
    async fn low_priority_candidate_is_rejected_without_mutating_full_queue() {
        let queue = FutureBlockQueue::with_limits(2, 1_000);
        let first = mock_block_with_len(1, 5, 2_000, 100);
        let second = mock_block_with_len(2, 6, 2_000, 100);
        let candidate = mock_block_with_len(3, 99, 2_000, 100);
        assert!(queue.defer(first.clone()).await);
        assert!(queue.defer(second.clone()).await);
        assert_eq!(
            queue.admit(candidate).await,
            FutureBlockAdmission::RejectedCapacity
        );
        assert_eq!(queue.size().await, 2);
        assert_eq!(queue.retained_bytes().await, 200);
        assert!(queue.contains(&first.block_hash).await);
        assert!(queue.contains(&second.block_hash).await);
        queue.assert_invariants().await;
    }

    #[tokio::test]
    async fn checked_add_overflow_is_rejected_without_mutating_entries() {
        let queue = FutureBlockQueue::with_limits(2, usize::MAX);
        {
            let mut state = queue.state.write().await;
            state.total_retained_bytes = usize::MAX;
        }
        assert_eq!(
            queue.admit(mock_block_with_len(1, 1, 1_000, 1)).await,
            FutureBlockAdmission::RejectedArithmetic
        );
        assert_eq!(queue.size().await, 0);
        assert_eq!(queue.retained_bytes().await, usize::MAX);
    }

    #[tokio::test]
    async fn opaque_or_malformed_bytes_do_not_corrupt_accounting() {
        let queue = FutureBlockQueue::with_limits(2, 100);
        let opaque = DeferredBlock {
            block_hash: [9; 32],
            block_height: 10,
            timestamp: 2_000,
            queued_at: Instant::now(),
            block_bytes: vec![0xde, 0xad, 0xbe, 0xef],
        };
        assert_eq!(
            queue.admit(opaque.clone()).await,
            FutureBlockAdmission::Queued
        );
        assert_eq!(queue.retained_bytes().await, 4);
        let removed = queue
            .remove(&opaque.block_hash)
            .await
            .expect("opaque block retained");
        assert_eq!(removed.block_hash, opaque.block_hash);
        assert_eq!(removed.block_bytes, opaque.block_bytes);
        assert_eq!(queue.retained_bytes().await, 0);
        queue.assert_invariants().await;
    }

    #[tokio::test]
    async fn maximum_serialized_block_fits_the_aggregate_budget() {
        assert_eq!(MAX_FUTURE_BLOCK_QUEUE_BYTES, 4 * MAX_BLOCK_SERIALIZED_SIZE);
        let queue = FutureBlockQueue::new();
        let max_block = mock_block_with_len(1, 10, 2_000, MAX_BLOCK_SERIALIZED_SIZE);
        assert_eq!(queue.admit(max_block).await, FutureBlockAdmission::Queued);
        assert_eq!(queue.size().await, 1);
        assert_eq!(queue.retained_bytes().await, MAX_BLOCK_SERIALIZED_SIZE);
        queue.assert_invariants().await;
    }

    #[tokio::test]
    async fn deterministic_operation_sequence_preserves_byte_invariants() {
        const SEED: u64 = 0xD0F0_CAFE_2026_0001;
        const OPERATIONS: usize = 10_000;
        let queue = FutureBlockQueue::with_limits(7, 400);
        let mut random = SEED;

        for operation in 0..OPERATIONS {
            random ^= random << 7;
            random ^= random >> 9;
            random ^= random << 8;
            let hash_byte = random as u8;
            let height = (random >> 8) % 16;
            let timestamp = if random & 1 == 0 { 1_000 } else { 5_000 };
            let len = ((random >> 16) as usize % 140) + 1;

            match (random >> 32) % 6 {
                0 | 1 => {
                    let _ = queue
                        .admit(mock_block_with_len(hash_byte, height, timestamp, len))
                        .await;
                }
                2 => {
                    let _ = queue.remove(&[hash_byte; 32]).await;
                }
                3 => {
                    let _ = queue.drain_ready(1_000, 60).await;
                }
                4 => {
                    let _ = queue.evict_expired(0).await;
                }
                _ => queue.clear().await,
            }
            queue.assert_invariants().await;
            assert!(
                queue.size().await <= 7,
                "count invariant failed at operation {operation} with seed {SEED:#x}"
            );
            assert!(
                queue.retained_bytes().await <= 400,
                "byte invariant failed at operation {operation} with seed {SEED:#x}"
            );
        }
    }
}
