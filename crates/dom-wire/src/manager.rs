//! Peer connection manager — eclipse attack protection.
//!
//! Enforces:
//! - MIN_OUTBOUND = 8 connections to different /16 subnets
//! - MAX_INBOUND = 125
//! - MAX_PEERS_SAME_SLASH_16 = 2 (eclipse protection)
//! - Feeler connections for peer discovery

use crate::peer::{PeerInfo, PeerState};
use dom_core::DomError;
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;

/// Maximum peers from the same /16 subnet (eclipse protection).
const MAX_PEERS_SAME_SLASH_16: usize = 2;

/// Peer manager state.
pub struct PeerManager {
    /// Connected peers: addr_string → PeerInfo.
    pub peers: HashMap<String, PeerInfo>,
    /// Inbound sockets admitted by the listener but not yet registered.
    pending_inbound: HashSet<String>,
    /// Penalties accumulated before a peer is fully registered.
    pending_penalties: HashMap<String, u32>,
    /// Max inbound connections.
    pub max_inbound: usize,
    /// Min outbound connections.
    pub min_outbound: usize,
}

impl PeerManager {
    /// Create a new peer manager.
    pub fn new(max_inbound: usize, min_outbound: usize) -> Self {
        Self {
            peers: HashMap::new(),
            pending_inbound: HashSet::new(),
            pending_penalties: HashMap::new(),
            max_inbound,
            min_outbound,
        }
    }

    /// Count outbound connections.
    pub fn outbound_count(&self) -> usize {
        self.peers
            .values()
            .filter(|p| p.outbound && p.state != PeerState::Disconnected)
            .count()
    }

    /// Count inbound connections.
    pub fn inbound_count(&self) -> usize {
        self.peers
            .values()
            .filter(|p| !p.outbound && p.state != PeerState::Disconnected)
            .count()
    }

    /// Count inbound connections that are still in handshake / Hello exchange.
    pub fn pending_inbound_count(&self) -> usize {
        self.pending_inbound.len()
    }

    /// Check if we need more outbound connections.
    pub fn needs_outbound(&self) -> bool {
        self.outbound_count() < self.min_outbound
    }

    /// Check if we can accept another inbound connection.
    pub fn can_accept_inbound(&self, new_addr: IpAddr) -> bool {
        if self.inbound_count() + self.pending_inbound_count() >= self.max_inbound {
            return false;
        }
        // Eclipse protection: max 2 peers per /16
        let slash16 = to_slash16(new_addr);
        let connected_same_subnet = self
            .peers
            .values()
            .filter(|p| !p.outbound && to_slash16(p.addr.ip()) == slash16)
            .count();
        let pending_same_subnet = self
            .pending_inbound
            .iter()
            .filter_map(|addr| addr.parse::<std::net::SocketAddr>().ok())
            .filter(|addr| to_slash16(addr.ip()) == slash16)
            .count();
        connected_same_subnet + pending_same_subnet < MAX_PEERS_SAME_SLASH_16
    }

    /// Reserve an inbound slot before spawning handshake work.
    ///
    /// This closes the pre-registration gap where many concurrent TCP
    /// connections can all pass `can_accept_inbound` before any of them
    /// completes Noise + Hello and reaches `register_peer`.
    pub fn reserve_inbound(&mut self, addr: std::net::SocketAddr) -> Result<(), DomError> {
        let addr_str = addr.to_string();
        if self.peers.contains_key(&addr_str) || self.pending_inbound.contains(&addr_str) {
            return Err(DomError::PolicyRejected(
                "already connected or pending inbound peer".into(),
            ));
        }
        if self.pending_ban_score(&addr_str) >= crate::peer::ban_scores::BAN_THRESHOLD {
            return Err(DomError::PolicyRejected(
                "pending inbound peer is banned".into(),
            ));
        }
        if !self.can_accept_inbound(addr.ip()) {
            return Err(DomError::PolicyRejected(
                "inbound limit or subnet limit reached".into(),
            ));
        }
        self.pending_inbound.insert(addr_str);
        Ok(())
    }

    /// Release a pending inbound reservation.
    pub fn release_inbound_reservation(&mut self, addr: &std::net::SocketAddr) {
        self.pending_inbound.remove(&addr.to_string());
    }

    /// Register a new peer connection attempt.
    pub fn register_peer(&mut self, info: PeerInfo) -> Result<(), DomError> {
        let addr_str = info.addr.to_string();
        if self.peers.contains_key(&addr_str) {
            return Err(DomError::PolicyRejected(
                "already connected to this peer".into(),
            ));
        }
        let mut info = info;
        let pending_score = self.pending_penalties.get(&addr_str).copied().unwrap_or(0);
        if pending_score > 0 && info.add_ban_score(pending_score) {
            return Err(DomError::PolicyRejected(
                "pending peer penalties exceeded ban threshold".into(),
            ));
        }
        if !info.outbound {
            self.pending_inbound.remove(&addr_str);
            if !self.can_accept_inbound(info.addr.ip()) {
                return Err(DomError::PolicyRejected(
                    "inbound limit or subnet limit reached".into(),
                ));
            }
        }
        self.pending_penalties.remove(&addr_str);
        self.peers.insert(addr_str, info);
        Ok(())
    }

    /// Remove a disconnected peer.
    pub fn remove_peer(&mut self, addr: &str) {
        self.peers.remove(addr);
        self.pending_inbound.remove(addr);
    }

    /// Apply a ban-score increment to a connected peer.
    ///
    /// Returns true when the new score crosses the ban threshold and the peer
    /// transitions into the banned state.
    pub fn add_ban_score(&mut self, addr: &str, score: u32) -> bool {
        match self.peers.get_mut(addr) {
            Some(peer) => peer.add_ban_score(score),
            None => false,
        }
    }

    /// Add a penalty score for a peer that has not yet been registered.
    pub fn add_pending_ban_score(&mut self, addr: &str, score: u32) -> u32 {
        let entry = self.pending_penalties.entry(addr.to_string()).or_insert(0);
        *entry = entry.saturating_add(score);
        *entry
    }

    /// Inspect the current ban score for a peer.
    pub fn ban_score(&self, addr: &str) -> Option<u32> {
        self.peers.get(addr).map(|peer| peer.ban_score)
    }

    /// Inspect the current pre-registration penalty score for a peer.
    pub fn pending_ban_score(&self, addr: &str) -> u32 {
        self.pending_penalties.get(addr).copied().unwrap_or(0)
    }

    /// Get all connected peer addresses (for broadcasting).
    pub fn connected_peers(&self) -> Vec<String> {
        self.peers
            .iter()
            .filter(|(_, p)| p.state == PeerState::Connected)
            .map(|(addr, _)| addr.clone())
            .collect()
    }

    /// Get connected peers with higher claimed height (for IBD).
    pub fn peers_with_height_above(&self, height: u64) -> Vec<String> {
        self.peers
            .iter()
            .filter(|(_, p)| p.state == PeerState::Connected && p.best_height > height)
            .map(|(addr, _)| addr.clone())
            .collect()
    }
}

/// Extract /16 prefix from an IP for subnet diversity check.
fn to_slash16(ip: IpAddr) -> [u8; 2] {
    match ip {
        IpAddr::V4(v4) => {
            let octets = v4.octets();
            [octets[0], octets[1]]
        }
        IpAddr::V6(v6) => {
            let octets = v6.octets();
            [octets[0], octets[1]]
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::peer::PeerInfo;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    fn make_peer(ip: [u8; 4], port: u16, outbound: bool) -> PeerInfo {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::from(ip)), port);
        let mut p = PeerInfo::new(addr, outbound);
        p.state = PeerState::Connected;
        p
    }

    #[test]
    fn subnet_diversity_limit() {
        let mut mgr = PeerManager::new(125, 8);
        // Add 2 peers from same /16 (192.168.x.x)
        mgr.register_peer(make_peer([192, 168, 1, 1], 33369, false))
            .unwrap();
        mgr.register_peer(make_peer([192, 168, 2, 1], 33370, false))
            .unwrap();
        // Third from same /16 should be rejected
        let result = mgr.can_accept_inbound(IpAddr::V4(Ipv4Addr::new(192, 168, 3, 1)));
        assert!(!result, "should reject 3rd peer from same /16");
    }

    #[test]
    fn different_subnets_allowed() {
        let mut mgr = PeerManager::new(125, 8);
        mgr.register_peer(make_peer([192, 168, 1, 1], 33369, false))
            .unwrap();
        mgr.register_peer(make_peer([10, 0, 1, 1], 33370, false))
            .unwrap();
        // Different /16 — should be accepted
        assert!(mgr.can_accept_inbound(IpAddr::V4(Ipv4Addr::new(172, 16, 1, 1))));
    }

    #[test]
    fn needs_outbound_when_below_min() {
        let mgr = PeerManager::new(125, 8);
        assert!(mgr.needs_outbound());
    }

    #[test]
    fn ban_score_marks_peer_banned() {
        let mut mgr = PeerManager::new(125, 8);
        let peer = make_peer([192, 168, 1, 10], 33369, false);
        let addr = peer.addr.to_string();
        mgr.register_peer(peer).unwrap();

        assert!(!mgr.add_ban_score(&addr, 99));
        assert_eq!(mgr.ban_score(&addr), Some(99));
        assert!(mgr.add_ban_score(&addr, 1));
        assert_eq!(
            mgr.peers.get(&addr).map(|peer| peer.state),
            Some(PeerState::Banned)
        );
    }

    #[test]
    fn banned_peer_drops_out_of_connected_set() {
        let mut mgr = PeerManager::new(125, 8);
        let peer = make_peer([10, 0, 0, 2], 33369, false);
        let addr = peer.addr.to_string();
        mgr.register_peer(peer).unwrap();
        assert_eq!(mgr.connected_peers(), vec![addr.clone()]);

        assert!(mgr.add_ban_score(&addr, 100));
        assert!(mgr.connected_peers().is_empty());
    }

    #[test]
    fn pending_ban_score_applies_on_registration() {
        let mut mgr = PeerManager::new(125, 8);
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 1, 1, 1)), 33369).to_string();
        assert_eq!(mgr.add_pending_ban_score(&addr, 40), 40);
        assert_eq!(mgr.pending_ban_score(&addr), 40);

        let mut peer = PeerInfo::new(addr.parse().unwrap(), false);
        peer.state = PeerState::Connected;
        mgr.register_peer(peer).unwrap();

        assert_eq!(mgr.pending_ban_score(&addr), 0);
        assert_eq!(mgr.ban_score(&addr), Some(40));
    }

    #[test]
    fn pending_ban_threshold_blocks_registration() {
        let mut mgr = PeerManager::new(125, 8);
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 1, 1, 2)), 33369).to_string();
        assert_eq!(mgr.add_pending_ban_score(&addr, 100), 100);

        let mut peer = PeerInfo::new(addr.parse().unwrap(), false);
        peer.state = PeerState::Connected;
        assert!(mgr.register_peer(peer).is_err());
        assert!(mgr.ban_score(&addr).is_none());
        assert_eq!(mgr.pending_ban_score(&addr), 100);
    }

    #[test]
    fn pending_ban_threshold_blocks_new_reservation() {
        let mut mgr = PeerManager::new(125, 8);
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 1, 1, 3)), 33369);
        assert_eq!(mgr.add_pending_ban_score(&addr.to_string(), 100), 100);
        assert!(mgr.reserve_inbound(addr).is_err());
    }
}
