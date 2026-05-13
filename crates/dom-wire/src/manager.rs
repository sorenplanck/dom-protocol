//! Peer connection manager — eclipse attack protection.
//!
//! Enforces:
//! - MIN_OUTBOUND = 8 connections to different /16 subnets
//! - MAX_INBOUND = 125
//! - MAX_PEERS_SAME_SLASH_16 = 2 (eclipse protection)
//! - Feeler connections for peer discovery

use std::collections::HashMap;
use std::net::IpAddr;
use dom_core::DomError;
use crate::peer::{PeerInfo, PeerState};

/// Maximum peers from the same /16 subnet (eclipse protection).
const MAX_PEERS_SAME_SLASH_16: usize = 2;

/// Peer manager state.
pub struct PeerManager {
    /// Connected peers: addr_string → PeerInfo.
    pub peers: HashMap<String, PeerInfo>,
    /// Max inbound connections.
    pub max_inbound: usize,
    /// Min outbound connections.
    pub min_outbound: usize,
}

impl PeerManager {
    /// Create a new peer manager.
    pub fn new(max_inbound: usize, min_outbound: usize) -> Self {
        Self { peers: HashMap::new(), max_inbound, min_outbound }
    }

    /// Count outbound connections.
    pub fn outbound_count(&self) -> usize {
        self.peers.values().filter(|p| p.outbound && p.state != PeerState::Disconnected).count()
    }

    /// Count inbound connections.
    pub fn inbound_count(&self) -> usize {
        self.peers.values().filter(|p| !p.outbound && p.state != PeerState::Disconnected).count()
    }

    /// Check if we need more outbound connections.
    pub fn needs_outbound(&self) -> bool {
        self.outbound_count() < self.min_outbound
    }

    /// Check if we can accept another inbound connection.
    pub fn can_accept_inbound(&self, new_addr: IpAddr) -> bool {
        if self.inbound_count() >= self.max_inbound {
            return false;
        }
        // Eclipse protection: max 2 peers per /16
        let slash16 = to_slash16(new_addr);
        let same_subnet = self.peers.values()
            .filter(|p| !p.outbound && to_slash16(p.addr.ip()) == slash16)
            .count();
        same_subnet < MAX_PEERS_SAME_SLASH_16
    }

    /// Register a new peer connection attempt.
    pub fn register_peer(&mut self, info: PeerInfo) -> Result<(), DomError> {
        let addr_str = info.addr.to_string();
        if self.peers.contains_key(&addr_str) {
            return Err(DomError::PolicyRejected("already connected to this peer".into()));
        }
        if !info.outbound && !self.can_accept_inbound(info.addr.ip()) {
            return Err(DomError::PolicyRejected("inbound limit or subnet limit reached".into()));
        }
        self.peers.insert(addr_str, info);
        Ok(())
    }

    /// Remove a disconnected peer.
    pub fn remove_peer(&mut self, addr: &str) {
        self.peers.remove(addr);
    }

    /// Get all connected peer addresses (for broadcasting).
    pub fn connected_peers(&self) -> Vec<String> {
        self.peers.iter()
            .filter(|(_, p)| p.state == PeerState::Connected)
            .map(|(addr, _)| addr.clone())
            .collect()
    }

    /// Get connected peers with higher claimed height (for IBD).
    pub fn peers_with_height_above(&self, height: u64) -> Vec<String> {
        self.peers.iter()
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
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use crate::peer::PeerInfo;

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
        mgr.register_peer(make_peer([192, 168, 1, 1], 33369, false)).unwrap();
        mgr.register_peer(make_peer([192, 168, 2, 1], 33370, false)).unwrap();
        // Third from same /16 should be rejected
        let result = mgr.can_accept_inbound(IpAddr::V4(Ipv4Addr::new(192, 168, 3, 1)));
        assert!(!result, "should reject 3rd peer from same /16");
    }

    #[test]
    fn different_subnets_allowed() {
        let mut mgr = PeerManager::new(125, 8);
        mgr.register_peer(make_peer([192, 168, 1, 1], 33369, false)).unwrap();
        mgr.register_peer(make_peer([10, 0, 1, 1], 33370, false)).unwrap();
        // Different /16 — should be accepted
        assert!(mgr.can_accept_inbound(IpAddr::V4(Ipv4Addr::new(172, 16, 1, 1))));
    }

    #[test]
    fn needs_outbound_when_below_min() {
        let mgr = PeerManager::new(125, 8);
        assert!(mgr.needs_outbound());
    }
}
