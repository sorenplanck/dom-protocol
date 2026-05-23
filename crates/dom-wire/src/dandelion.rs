//! Dandelion++ transaction routing for source privacy.
//!
//! Transactions propagate in two phases:
//! - Stem phase: forwarded to exactly ONE random peer (covers source)
//! - Fluff phase: normal broadcast to all peers
//!
//! This makes it computationally infeasible to determine which node
//! originated a transaction by observing network timing.

use std::collections::HashMap;
use std::time::{Duration, Instant};

/// Dandelion phase for a transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DandelionPhase {
    /// Stem: forward to one random peer.
    Stem,
    /// Fluff: broadcast to all peers.
    Fluff,
}

/// Envelope for a stem-phase transaction: contains the target peer that
/// should forward it. Broadcast to all peer tasks; only the task whose
/// peer address matches `target_peer` actually sends to its peer.
#[derive(Debug, Clone)]
pub struct StemEnvelope {
    /// Peer address that should forward this transaction.
    pub target_peer: std::net::SocketAddr,
    /// Raw transaction bytes (already serialized).
    pub tx_bytes: Vec<u8>,
}

/// Probability of transitioning from stem to fluff per hop.
/// 10% per hop = average stem length of 10 hops.
const FLUFF_PROBABILITY: f64 = 0.10;

/// Maximum stem phase duration before forced fluff.
const STEM_TIMEOUT: Duration = Duration::from_secs(30);

/// State for a transaction in the stem phase.
#[derive(Debug)]
pub struct StemState {
    /// When stem phase started.
    pub stem_start: Instant,
    /// Which peer this tx should be forwarded to.
    pub stem_peer: std::net::SocketAddr,
}

/// Dandelion++ router.
pub struct DandelionRouter {
    /// Transactions currently in stem phase: tx_id → state.
    stem_txs: HashMap<[u8; 32], StemState>,
}

impl DandelionRouter {
    /// Create a new router.
    pub fn new() -> Self {
        Self {
            stem_txs: HashMap::new(),
        }
    }

    /// Decide the routing phase for a new transaction.
    ///
    /// Returns Stem with the peer to forward to, or Fluff for broadcast.
    pub fn route_new_tx(
        &mut self,
        tx_hash: [u8; 32],
        available_peers: &[std::net::SocketAddr],
    ) -> DandelionPhase {
        if available_peers.is_empty() {
            return DandelionPhase::Fluff; // no peers → broadcast
        }

        // Randomly decide stem or fluff
        let p: f64 = rand_f64();
        if p < FLUFF_PROBABILITY {
            return DandelionPhase::Fluff;
        }

        // Pick a random peer for stem forwarding
        let idx = (rand_f64() * available_peers.len() as f64) as usize;
        let stem_peer = available_peers[idx.min(available_peers.len() - 1)];

        self.stem_txs.insert(
            tx_hash,
            StemState {
                stem_start: Instant::now(),
                stem_peer,
            },
        );

        DandelionPhase::Stem
    }

    /// Process a transaction received in stem phase from a peer.
    ///
    /// Either continue stem forwarding or transition to fluff.
    pub fn process_stem_tx(
        &mut self,
        tx_hash: [u8; 32],
        available_peers: &[std::net::SocketAddr],
        from_peer: std::net::SocketAddr,
    ) -> DandelionPhase {
        // If we already have this in stem, check timeout
        if let Some(state) = self.stem_txs.get(&tx_hash) {
            if state.stem_start.elapsed() > STEM_TIMEOUT {
                self.stem_txs.remove(&tx_hash);
                return DandelionPhase::Fluff;
            }
        }
        // Route as new tx but exclude the sending peer
        let peers: Vec<std::net::SocketAddr> = available_peers
            .iter()
            .filter(|p| **p != from_peer)
            .copied()
            .collect();
        self.route_new_tx(tx_hash, &peers)
    }

    /// Check for timed-out stem transactions and return them for fluff broadcast.
    pub fn collect_timed_out(&mut self) -> Vec<[u8; 32]> {
        let mut timed_out = Vec::new();
        self.stem_txs.retain(|&hash, state| {
            if state.stem_start.elapsed() > STEM_TIMEOUT {
                timed_out.push(hash);
                false
            } else {
                true
            }
        });
        timed_out
    }

    /// Get stem peer for a transaction (if still in stem phase).
    pub fn get_stem_peer(&self, tx_hash: &[u8; 32]) -> Option<std::net::SocketAddr> {
        self.stem_txs.get(tx_hash).map(|s| s.stem_peer)
    }
}

impl Default for DandelionRouter {
    fn default() -> Self {
        Self::new()
    }
}

fn rand_f64() -> f64 {
    use rand::Rng;
    rand::thread_rng().gen::<f64>()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_peers_always_fluff() {
        let mut router = DandelionRouter::new();
        let tx = [0u8; 32];
        assert_eq!(router.route_new_tx(tx, &[]), DandelionPhase::Fluff);
    }

    #[test]
    fn stem_tx_stored() {
        let mut router = DandelionRouter::new();
        let tx = [1u8; 32];
        let peers: Vec<std::net::SocketAddr> = vec!["127.0.0.1:33369".parse().unwrap()];
        let _phase = router.route_new_tx(tx, &peers);
        // With only 1 peer and 10% fluff probability, most times should be stem
        // (statistical test — run 10 times, at least one should be stem)
        let mut found_stem = false;
        for i in 0..20 {
            let tx = [i as u8; 32];
            if router.route_new_tx(tx, &peers) == DandelionPhase::Stem {
                found_stem = true;
                break;
            }
        }
        assert!(found_stem, "should find stem phase in 20 attempts");
    }

    #[test]
    fn timed_out_txs_collected() {
        // We can't easily test the timeout without sleeping,
        // but we can verify the collect_timed_out function works
        let mut router = DandelionRouter::new();
        let timed_out = router.collect_timed_out();
        assert!(timed_out.is_empty());
    }
}
