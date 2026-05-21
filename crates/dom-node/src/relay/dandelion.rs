//! Dandelion++ privacy layer for transaction propagation.
//!
//! Implements stem (single-peer relay) and fluff (broadcast) phases
//! to obscure transaction origin. Pure Rust, no external dependencies.

use std::collections::HashMap;
use std::time::{Duration, Instant};

/// Phase indicator for transaction propagation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PropagationPhase {
    Stem { target_peer: String },
    Fluff,
}

struct StemRoute {
    peer_id: String,
    expires_at: Instant,
}

/// Dandelion++ router decides stem vs fluff for each transaction.
pub struct DandelionRouter {
    stem_peers: HashMap<[u8; 32], StemRoute>,
    fluff_timeout: Duration,
    stem_probability: f64,
    rng_state: u64,
}

impl DandelionRouter {
    pub fn new(stem_probability: f64, fluff_timeout_secs: u64) -> Self {
        Self {
            stem_peers: HashMap::new(),
            fluff_timeout: Duration::from_secs(fluff_timeout_secs),
            stem_probability,
            rng_state: 0xDEADBEEFCAFEBABE,
        }
    }

    /// Decide if a transaction should be stemmed.
    /// Uses xorshift PRNG (no rand dependency).
    pub fn should_stem(&mut self) -> bool {
        self.rng_state ^= self.rng_state << 13;
        self.rng_state ^= self.rng_state >> 7;
        self.rng_state ^= self.rng_state << 17;
        let normalized = (self.rng_state as f64) / (u64::MAX as f64);
        normalized < self.stem_probability
    }

    /// Get stem peer for this transaction (sticky routing per tx).
    pub fn get_stem_peer(
        &mut self,
        tx_id: &[u8; 32],
        available_peers: &[String],
    ) -> Option<String> {
        if let Some(route) = self.stem_peers.get(tx_id) {
            if route.expires_at > Instant::now() {
                return Some(route.peer_id.clone());
            }
        }

        if available_peers.is_empty() {
            return None;
        }

        // Deterministic selection based on tx_id
        let idx = (tx_id[0] as usize) % available_peers.len();
        let peer = available_peers[idx].clone();

        self.stem_peers.insert(
            *tx_id,
            StemRoute {
                peer_id: peer.clone(),
                expires_at: Instant::now() + self.fluff_timeout,
            },
        );

        Some(peer)
    }

    /// Mark transaction as fluffed (broadcast everywhere).
    pub fn mark_fluff(&mut self, tx_id: &[u8; 32]) {
        self.stem_peers.remove(tx_id);
    }

    /// Clear expired stem routes.
    pub fn clear_expired(&mut self) {
        let now = Instant::now();
        self.stem_peers.retain(|_, route| route.expires_at > now);
    }

    pub fn active_stems(&self) -> usize {
        self.stem_peers.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stem_probability_works() {
        let mut router = DandelionRouter::new(0.9, 300);
        let mut stem_count = 0;
        for _ in 0..1000 {
            if router.should_stem() {
                stem_count += 1;
            }
        }
        assert!(stem_count > 700, "stem count {} below 700", stem_count);
    }

    #[test]
    fn stem_peer_sticky_selection() {
        let mut router = DandelionRouter::new(0.9, 300);
        let peers = vec!["peer1".to_string(), "peer2".to_string()];
        let tx_id = [42u8; 32];

        let peer1 = router.get_stem_peer(&tx_id, &peers);
        let peer2 = router.get_stem_peer(&tx_id, &peers);
        assert_eq!(peer1, peer2);
    }

    #[test]
    fn fluff_removes_stem_route() {
        let mut router = DandelionRouter::new(0.9, 300);
        let peers = vec!["peer1".to_string()];
        let tx_id = [1u8; 32];

        router.get_stem_peer(&tx_id, &peers);
        assert_eq!(router.active_stems(), 1);

        router.mark_fluff(&tx_id);
        assert_eq!(router.active_stems(), 0);
    }

    #[test]
    fn empty_peers_returns_none() {
        let mut router = DandelionRouter::new(0.9, 300);
        let tx_id = [1u8; 32];
        assert_eq!(router.get_stem_peer(&tx_id, &[]), None);
    }
}
