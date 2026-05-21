//! Peer Exchange (PEX) — peer address discovery and sharing.
//!
//! Implements the GetAddr/Addr protocol for peer discovery.
//! Nodes request peer addresses from connected peers and share
//! their known peers in response.
//!
//! RFC-0005 §6: Peer Discovery.
//! Philosophy Section 12: Operational Requirements.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::{SystemTime, UNIX_EPOCH};

use dom_store::PeerAddr;

/// Maximum peers to return in a single Addr response.
pub const MAX_ADDR_RESPONSE: usize = 1_000;

/// Maximum age of peer addresses to share (7 days in seconds).
pub const MAX_PEER_AGE_SECS: u64 = 7 * 24 * 3600;

/// Minimum interval between GetAddr requests to same peer (10 minutes).
pub const GETADDR_COOLDOWN_SECS: u64 = 600;

/// PEX manager — tracks known peers and handles discovery.
pub struct PexManager {
    /// Known peers by address string.
    known: HashMap<String, PeerAddr>,
    /// Timestamps of last GetAddr sent to each peer.
    last_getaddr: HashMap<String, u64>,
    /// Maximum peers to track.
    max_peers: usize,
}

impl PexManager {
    /// Create a new PEX manager.
    pub fn new(max_peers: usize) -> Self {
        Self {
            known: HashMap::new(),
            last_getaddr: HashMap::new(),
            max_peers,
        }
    }

    /// Add or update a known peer.
    pub fn add_peer(&mut self, addr: String) {
        if self.known.len() >= self.max_peers && !self.known.contains_key(&addr) {
            return;
        }
        let now = unix_now();
        self.known
            .entry(addr.clone())
            .and_modify(|p| {
                p.last_seen = now;
                p.failures = 0;
            })
            .or_insert(PeerAddr {
                addr,
                last_seen: now,
                failures: 0,
            });
    }

    /// Record a failed connection attempt.
    pub fn record_failure(&mut self, addr: &str) {
        if let Some(peer) = self.known.get_mut(addr) {
            peer.failures = peer.failures.saturating_add(1);
        }
    }

    /// Remove peers that have too many failures.
    pub fn evict_dead_peers(&mut self) {
        self.known.retain(|_, p| p.is_connectable());
    }

    /// Get peers suitable for sharing in Addr response.
    ///
    /// Returns up to MAX_ADDR_RESPONSE peers that are recent and connectable.
    pub fn peers_for_sharing(&self) -> Vec<&PeerAddr> {
        let now = unix_now();
        let mut peers: Vec<&PeerAddr> = self
            .known
            .values()
            .filter(|p| {
                p.is_connectable()
                    && now.saturating_sub(p.last_seen) < MAX_PEER_AGE_SECS
            })
            .collect();

        // Sort by most recently seen
        peers.sort_by(|a, b| b.last_seen.cmp(&a.last_seen));
        peers.truncate(MAX_ADDR_RESPONSE);
        peers
    }

    /// Get connectable peers for outbound connections.
    pub fn connectable_peers(&self) -> Vec<&PeerAddr> {
        let mut peers: Vec<&PeerAddr> =
            self.known.values().filter(|p| p.is_connectable()).collect();
        peers.sort_by(|a, b| b.last_seen.cmp(&a.last_seen));
        peers
    }

    /// Check if we should send GetAddr to this peer.
    pub fn should_getaddr(&self, peer_id: &str) -> bool {
        let now = unix_now();
        match self.last_getaddr.get(peer_id) {
            None => true,
            Some(last) => now.saturating_sub(*last) > GETADDR_COOLDOWN_SECS,
        }
    }

    /// Record that we sent GetAddr to a peer.
    pub fn record_getaddr(&mut self, peer_id: &str) {
        self.last_getaddr.insert(peer_id.to_string(), unix_now());
    }

    /// Process incoming Addr message — add peers to our known set.
    pub fn process_addr_message(&mut self, addrs: Vec<String>) -> usize {
        let mut added = 0usize;
        for addr in addrs {
            // Basic validation: must be parseable as SocketAddr
            if addr.parse::<SocketAddr>().is_ok() {
                let was_new = !self.known.contains_key(&addr);
                self.add_peer(addr);
                if was_new {
                    added += 1;
                }
            }
        }
        added
    }

    /// Total known peers count.
    pub fn known_count(&self) -> usize {
        self.known.len()
    }

    /// Seed initial peers from config.
    pub fn seed_from_config(&mut self, seed_peers: &[String]) {
        for addr in seed_peers {
            self.add_peer(addr.clone());
        }
    }
}

/// Serialize Addr payload — list of address strings.
pub fn encode_addr_payload(addrs: &[&PeerAddr]) -> Vec<u8> {
    let mut out = Vec::new();
    // Count (u16)
    let count = addrs.len().min(MAX_ADDR_RESPONSE) as u16;
    out.extend_from_slice(&count.to_le_bytes());
    for peer in addrs.iter().take(count as usize) {
        // Each addr: u8 length + bytes + u64 last_seen
        let addr_bytes = peer.addr.as_bytes();
        out.push(addr_bytes.len() as u8);
        out.extend_from_slice(addr_bytes);
        out.extend_from_slice(&peer.last_seen.to_le_bytes());
    }
    out
}

/// Deserialize Addr payload.
pub fn decode_addr_payload(data: &[u8]) -> Result<Vec<String>, dom_core::DomError> {
    if data.len() < 2 {
        return Err(dom_core::DomError::Malformed("addr payload too short".into()));
    }
    let count = u16::from_le_bytes([data[0], data[1]]) as usize;
    let count = count.min(MAX_ADDR_RESPONSE);
    let mut addrs = Vec::with_capacity(count);
    let mut pos = 2usize;

    for _ in 0..count {
        if pos >= data.len() {
            break;
        }
        let len = data[pos] as usize;
        pos += 1;
        if pos + len + 8 > data.len() {
            break;
        }
        let addr = String::from_utf8_lossy(&data[pos..pos + len]).to_string();
        pos += len + 8; // skip last_seen timestamp
        addrs.push(addr);
    }
    Ok(addrs)
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn add_and_retrieve_peer() {
        let mut pex = PexManager::new(1000);
        pex.add_peer("127.0.0.1:33370".to_string());
        assert_eq!(pex.known_count(), 1);
        let peers = pex.connectable_peers();
        assert_eq!(peers.len(), 1);
        assert_eq!(peers[0].addr, "127.0.0.1:33370");
    }

    #[test]
    fn failure_tracking() {
        let mut pex = PexManager::new(1000);
        pex.add_peer("127.0.0.1:33370".to_string());
        for _ in 0..10 {
            pex.record_failure("127.0.0.1:33370");
        }
        pex.evict_dead_peers();
        assert_eq!(pex.known_count(), 0);
    }

    #[test]
    fn getaddr_cooldown() {
        let mut pex = PexManager::new(1000);
        assert!(pex.should_getaddr("peer1"));
        pex.record_getaddr("peer1");
        assert!(!pex.should_getaddr("peer1"));
    }

    #[test]
    fn addr_encode_decode_roundtrip() {
        let peer = PeerAddr {
            addr: "127.0.0.1:33370".to_string(),
            last_seen: 1_700_000_000,
            failures: 0,
        };
        let encoded = encode_addr_payload(&[&peer]);
        let decoded = decode_addr_payload(&encoded).unwrap();
        assert_eq!(decoded.len(), 1);
        assert_eq!(decoded[0], "127.0.0.1:33370");
    }

    #[test]
    fn process_addr_filters_invalid() {
        let mut pex = PexManager::new(1000);
        let addrs = vec![
            "127.0.0.1:33370".to_string(), // valid
            "not_an_addr".to_string(),      // invalid
            "192.168.1.1:8080".to_string(), // valid
        ];
        let added = pex.process_addr_message(addrs);
        assert_eq!(added, 2);
    }

    #[test]
    fn max_peers_respected() {
        let mut pex = PexManager::new(2);
        pex.add_peer("1.1.1.1:33370".to_string());
        pex.add_peer("2.2.2.2:33370".to_string());
        pex.add_peer("3.3.3.3:33370".to_string()); // should be ignored
        assert_eq!(pex.known_count(), 2);
    }

    #[test]
    fn seed_from_config() {
        let mut pex = PexManager::new(1000);
        let seeds = vec!["seed1.dom:33369".to_string(), "seed2.dom:33369".to_string()];
        pex.seed_from_config(&seeds);
        assert_eq!(pex.known_count(), 2);
    }
}
