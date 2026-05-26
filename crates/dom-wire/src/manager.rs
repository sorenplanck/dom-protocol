//! Peer connection manager — eclipse attack protection.
//!
//! Enforces:
//! - MIN_OUTBOUND = 8 connections to different /16 subnets
//! - MAX_INBOUND = 125
//! - MAX_PEERS_SAME_SLASH_16 = 2 (eclipse protection)
//! - Feeler connections for peer discovery

use crate::peer::{PeerInfo, PeerState};
use dom_core::DomError;
use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};

/// Maximum peers from the same /16 subnet (eclipse protection).
const MAX_PEERS_SAME_SLASH_16: usize = 2;
/// Reservations older than this are treated as dead handshakes and ignored.
const STALE_PENDING_INBOUND_SECS: u64 = crate::handshake::HANDSHAKE_TIMEOUT_SECS * 3;
/// Pre-registration penalties expire after this interval.
const PENDING_PENALTY_TTL_SECS: u64 = 15 * 60;
/// Bound memory used by hostile pre-registration address churn.
const MAX_PENDING_PENALTIES: usize = 4_096;

#[derive(Debug, Clone, Copy)]
struct PendingInbound {
    reserved_at: Instant,
}

#[derive(Debug, Clone, Copy)]
struct PendingPenalty {
    score: u32,
    last_updated: Instant,
}

/// Peer manager state.
pub struct PeerManager {
    /// Connected peers: addr_string → PeerInfo.
    pub peers: HashMap<String, PeerInfo>,
    /// Inbound sockets admitted by the listener but not yet registered.
    pending_inbound: HashMap<String, PendingInbound>,
    /// Penalties accumulated before a peer is fully registered.
    pending_penalties: HashMap<String, PendingPenalty>,
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
            pending_inbound: HashMap::new(),
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
        self.pending_inbound
            .values()
            .filter(|pending| !reservation_is_stale(**pending))
            .count()
    }

    /// Count live pre-registration penalty entries.
    pub fn pending_penalty_count(&self) -> usize {
        self.pending_penalties
            .values()
            .filter(|penalty| !penalty_is_stale(**penalty))
            .count()
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
            .filter(|(_, pending)| !reservation_is_stale(**pending))
            .filter_map(|(addr, _)| addr.parse::<std::net::SocketAddr>().ok())
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
        self.prune_stale_state();
        let addr_str = addr.to_string();
        if self.peers.contains_key(&addr_str) || self.pending_inbound.contains_key(&addr_str) {
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
        self.pending_inbound.insert(
            addr_str,
            PendingInbound {
                reserved_at: Instant::now(),
            },
        );
        Ok(())
    }

    /// Release a pending inbound reservation.
    pub fn release_inbound_reservation(&mut self, addr: &std::net::SocketAddr) {
        self.prune_stale_state();
        self.pending_inbound.remove(&addr.to_string());
    }

    /// Register a new peer connection attempt.
    pub fn register_peer(&mut self, info: PeerInfo) -> Result<(), DomError> {
        self.prune_stale_state();
        let addr_str = info.addr.to_string();
        if self.peers.contains_key(&addr_str) {
            return Err(DomError::PolicyRejected(
                "already connected to this peer".into(),
            ));
        }
        let mut info = info;
        let pending_score = self.pending_penalty_score(&addr_str);
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
        self.prune_stale_state();
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
        self.prune_stale_state();
        let now = Instant::now();
        let updated_score = {
            let entry = self
                .pending_penalties
                .entry(addr.to_string())
                .or_insert(PendingPenalty {
                    score: 0,
                    last_updated: now,
                });
            entry.score = entry.score.saturating_add(score);
            entry.last_updated = now;
            entry.score
        };
        self.enforce_pending_penalty_bound();
        updated_score
    }

    /// Inspect the current ban score for a peer.
    pub fn ban_score(&self, addr: &str) -> Option<u32> {
        self.peers.get(addr).map(|peer| peer.ban_score)
    }

    /// Inspect the current pre-registration penalty score for a peer.
    pub fn pending_ban_score(&self, addr: &str) -> u32 {
        self.pending_penalty_score(addr)
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

    fn pending_penalty_score(&self, addr: &str) -> u32 {
        self.pending_penalties
            .get(addr)
            .copied()
            .filter(|penalty| !penalty_is_stale(*penalty))
            .map(|penalty| penalty.score)
            .unwrap_or(0)
    }

    fn prune_stale_state(&mut self) {
        self.pending_inbound
            .retain(|_, pending| !reservation_is_stale(*pending));
        self.pending_penalties
            .retain(|_, penalty| !penalty_is_stale(*penalty));
        self.enforce_pending_penalty_bound();
    }

    fn enforce_pending_penalty_bound(&mut self) {
        if self.pending_penalties.len() <= MAX_PENDING_PENALTIES {
            return;
        }

        let overflow = self.pending_penalties.len() - MAX_PENDING_PENALTIES;
        let mut oldest: Vec<(String, Instant)> = self
            .pending_penalties
            .iter()
            .map(|(addr, penalty)| (addr.clone(), penalty.last_updated))
            .collect();
        oldest.sort_by(|(left_addr, left_ts), (right_addr, right_ts)| {
            left_ts
                .cmp(right_ts)
                .then_with(|| left_addr.cmp(right_addr))
        });
        for (addr, _) in oldest.into_iter().take(overflow) {
            self.pending_penalties.remove(&addr);
        }
    }
}

fn reservation_is_stale(pending: PendingInbound) -> bool {
    pending.reserved_at.elapsed() >= Duration::from_secs(STALE_PENDING_INBOUND_SECS)
}

fn penalty_is_stale(pending: PendingPenalty) -> bool {
    pending.last_updated.elapsed() >= Duration::from_secs(PENDING_PENALTY_TTL_SECS)
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

    #[test]
    fn stale_pending_reservation_stops_consuming_capacity() {
        let mut mgr = PeerManager::new(2, 8);
        let a = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 33369);
        let b = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1)), 33369);
        let c = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 0, 1)), 33369);

        mgr.reserve_inbound(a).expect("reserve a");
        mgr.reserve_inbound(b).expect("reserve b");
        mgr.pending_inbound
            .get_mut(&a.to_string())
            .unwrap()
            .reserved_at = Instant::now() - Duration::from_secs(STALE_PENDING_INBOUND_SECS + 1);

        assert_eq!(mgr.pending_inbound_count(), 1);
        mgr.reserve_inbound(c)
            .expect("stale reservation must not pin inbound capacity");
    }

    #[test]
    fn stale_pending_penalty_expires_before_new_reservation() {
        let mut mgr = PeerManager::new(125, 8);
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 1, 1, 4)), 33369);
        let key = addr.to_string();
        assert_eq!(mgr.add_pending_ban_score(&key, 100), 100);
        mgr.pending_penalties.get_mut(&key).unwrap().last_updated =
            Instant::now() - Duration::from_secs(PENDING_PENALTY_TTL_SECS + 1);

        assert_eq!(mgr.pending_ban_score(&key), 0);
        mgr.reserve_inbound(addr)
            .expect("expired pending ban must not block a later retry");
    }

    #[test]
    fn pending_penalties_are_bounded_under_address_churn() {
        let mut mgr = PeerManager::new(125, 8);
        for i in 0..(MAX_PENDING_PENALTIES + 128) {
            let addr = format!("10.0.{}.{}:33369", (i / 255) % 255, (i % 255) + 1);
            mgr.add_pending_ban_score(&addr, 20);
        }

        assert_eq!(
            mgr.pending_penalty_count(),
            MAX_PENDING_PENALTIES,
            "hostile address churn must not grow pending-penalty state without bound"
        );
        assert_eq!(
            mgr.pending_ban_score("10.0.0.1:33369"),
            0,
            "oldest churn entry should be evicted once the cap is hit"
        );
        let newest = format!(
            "10.0.{}.{}:33369",
            ((MAX_PENDING_PENALTIES + 127) / 255) % 255,
            ((MAX_PENDING_PENALTIES + 127) % 255) + 1
        );
        assert_eq!(
            mgr.pending_ban_score(&newest),
            20,
            "recent churn entries should remain tracked"
        );
    }
}
