//! Transaction relay tracker (deduplication for mempool relay).
//!
//! Tracks tx hashes we have seen to avoid re-broadcasting infinite loops.
//! Operates on hash bytes only — no Transaction type dependency.

use std::collections::HashSet;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Decision for an incoming transaction hash.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RelayDecision {
    AlreadySeen,
    Accept,
    Reject(String),
}

/// Tracks seen transactions for relay deduplication.
pub struct TxRelay {
    seen_txs: Arc<RwLock<HashSet<[u8; 32]>>>,
    max_seen: usize,
}

impl TxRelay {
    pub fn new(max_seen: usize) -> Self {
        Self {
            seen_txs: Arc::new(RwLock::new(HashSet::new())),
            max_seen,
        }
    }

    pub async fn have_seen(&self, tx_hash: &[u8; 32]) -> bool {
        self.seen_txs.read().await.contains(tx_hash)
    }

    pub async fn mark_seen(&self, tx_hash: [u8; 32]) {
        let mut seen = self.seen_txs.write().await;
        if seen.len() >= self.max_seen {
            seen.clear();
        }
        seen.insert(tx_hash);
    }

    pub async fn process_incoming(&self, tx_hash: [u8; 32]) -> RelayDecision {
        if self.have_seen(&tx_hash).await {
            return RelayDecision::AlreadySeen;
        }
        self.mark_seen(tx_hash).await;
        RelayDecision::Accept
    }

    pub async fn seen_count(&self) -> usize {
        self.seen_txs.read().await.len()
    }

    pub async fn clear(&self) {
        self.seen_txs.write().await.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn seen_tracking_works() {
        let relay = TxRelay::new(1000);
        let hash = [1u8; 32];
        assert!(!relay.have_seen(&hash).await);
        relay.mark_seen(hash).await;
        assert!(relay.have_seen(&hash).await);
    }

    #[tokio::test]
    async fn duplicate_rejected() {
        let relay = TxRelay::new(1000);
        let hash = [2u8; 32];
        assert_eq!(relay.process_incoming(hash).await, RelayDecision::Accept);
        assert_eq!(
            relay.process_incoming(hash).await,
            RelayDecision::AlreadySeen
        );
    }

    #[tokio::test]
    async fn prunes_when_full() {
        let relay = TxRelay::new(5);
        for i in 0..5 {
            relay.mark_seen([i; 32]).await;
        }
        assert_eq!(relay.seen_count().await, 5);
        relay.mark_seen([99; 32]).await;
        assert!(relay.have_seen(&[99; 32]).await);
    }

    #[tokio::test]
    async fn clear_works() {
        let relay = TxRelay::new(100);
        relay.mark_seen([1u8; 32]).await;
        relay.mark_seen([2u8; 32]).await;
        assert_eq!(relay.seen_count().await, 2);
        relay.clear().await;
        assert_eq!(relay.seen_count().await, 0);
    }
}
