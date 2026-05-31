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

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::RwLock;

/// Maximum entries in the future block queue.
/// Prevents memory exhaustion from malicious peers flooding future blocks.
const MAX_QUEUE_SIZE: usize = 256;

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
    /// Serialized block bytes for re-evaluation.
    pub block_bytes: Vec<u8>,
}

/// Queue of blocks deferred due to soft buffer.
pub struct FutureBlockQueue {
    entries: Arc<RwLock<HashMap<[u8; 32], DeferredBlock>>>,
    max_size: usize,
}

impl FutureBlockQueue {
    /// Create a new empty queue with default capacity.
    pub fn new() -> Self {
        Self {
            entries: Arc::new(RwLock::new(HashMap::new())),
            max_size: MAX_QUEUE_SIZE,
        }
    }

    /// Add a block to the deferred queue.
    /// Returns false if queue is full (block should be rejected).
    pub async fn defer(&self, block: DeferredBlock) -> bool {
        let mut entries = self.entries.write().await;
        let is_existing = entries.contains_key(&block.block_hash);
        if !is_existing && entries.len() >= self.max_size {
            return false;
        }
        entries.insert(block.block_hash, block);
        true
    }

    /// Remove a specific block from the queue.
    pub async fn remove(&self, block_hash: &[u8; 32]) -> Option<DeferredBlock> {
        self.entries.write().await.remove(block_hash)
    }

    /// Drain blocks whose timestamps are now within the hard limit.
    ///
    /// Ready blocks are returned in canonical replay order:
    /// `block_height ASC`, then `block_hash ASC`.
    pub async fn drain_ready(&self, now_secs: u64, hard_limit_secs: u64) -> Vec<DeferredBlock> {
        let mut entries = self.entries.write().await;
        let ready_cutoff = now_secs.saturating_add(hard_limit_secs);

        let mut ready_keys: Vec<(u64, [u8; 32])> = entries
            .iter()
            .filter(|(_, b)| b.timestamp <= ready_cutoff)
            .map(|(h, block)| (block.block_height, *h))
            .collect();
        ready_keys.sort_by(|(left_height, left_hash), (right_height, right_hash)| {
            left_height
                .cmp(right_height)
                .then_with(|| left_hash.as_slice().cmp(right_hash.as_slice()))
        });

        let mut ready = Vec::with_capacity(ready_keys.len());
        for (_, hash) in ready_keys {
            if let Some(block) = entries.remove(&hash) {
                ready.push(block);
            }
        }

        ready
    }

    /// Drop entries that have been in the queue beyond expiry.
    /// Should be called periodically.
    pub async fn evict_expired(&self, max_age_secs: u64) -> usize {
        let mut entries = self.entries.write().await;
        let now = Instant::now();
        let before = entries.len();

        entries.retain(|_, b| now.duration_since(b.queued_at).as_secs() < max_age_secs);

        before - entries.len()
    }

    /// Get current queue size.
    pub async fn size(&self) -> usize {
        self.entries.read().await.len()
    }

    /// Check if a specific block is queued.
    pub async fn contains(&self, block_hash: &[u8; 32]) -> bool {
        self.entries.read().await.contains_key(block_hash)
    }

    /// Clear all entries.
    pub async fn clear(&self) {
        self.entries.write().await.clear();
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

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct FutureQueueSnapshot {
        final_tip_height: u64,
        final_tip_hash: [u8; 32],
        applied_hashes: Vec<[u8; 32]>,
        pending_hashes: Vec<[u8; 32]>,
    }

    fn mock_block(hash_byte: u8, block_height: u64, timestamp: u64) -> DeferredBlock {
        DeferredBlock {
            block_hash: [hash_byte; 32],
            block_height,
            timestamp,
            queued_at: Instant::now(),
            block_bytes: vec![0u8; 100],
        }
    }

    async fn pending_hashes(queue: &FutureBlockQueue) -> Vec<[u8; 32]> {
        let entries = queue.entries.read().await;
        let mut hashes: Vec<[u8; 32]> = entries.keys().copied().collect();
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
        // Pretend it was queued 1 hour ago
        block.queued_at = Instant::now()
            .checked_sub(std::time::Duration::from_secs(3600))
            .unwrap_or_else(Instant::now);
        queue.defer(block).await;

        let evicted = queue.evict_expired(60).await; // 60s max age
        assert_eq!(evicted, 1);
        assert_eq!(queue.size().await, 0);
    }

    #[tokio::test]
    async fn full_queue_rejects() {
        let queue = FutureBlockQueue {
            entries: Arc::new(RwLock::new(HashMap::new())),
            max_size: 2,
        };
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
        let queue = FutureBlockQueue {
            entries: Arc::new(RwLock::new(HashMap::new())),
            max_size: 2,
        };
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
        let queue = FutureBlockQueue {
            entries: Arc::new(RwLock::new(HashMap::new())),
            max_size: 1,
        };
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
}
