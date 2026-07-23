//! Peer Exchange (PEX) — peer address discovery and sharing.
//!
//! Implements the GetAddr/Addr protocol for peer discovery.
//! Nodes request peer addresses from connected peers and share
//! their known peers in response.
//!
//! RFC-0005 §6: Peer Discovery.
//! Philosophy Section 12: Operational Requirements.

use std::collections::{HashMap, HashSet, VecDeque};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::{SystemTime, UNIX_EPOCH};

use dom_config::Network;
use dom_store::PeerAddr;
use dom_wire::message::AddrEntry;

/// Maximum peers to return in a single Addr response.
/// Same bound as the wire parser, so everything we share always decodes.
pub const MAX_ADDR_RESPONSE: usize = dom_wire::message::MAX_ADDRS_PER_MESSAGE;

/// Maximum age of peer addresses to share (7 days in seconds).
pub const MAX_PEER_AGE_SECS: u64 = 7 * 24 * 3600;

/// Minimum interval between GetAddr requests to same peer (10 minutes).
pub const GETADDR_COOLDOWN_SECS: u64 = 600;
/// Bound memory used by rotating GetAddr cooldown state under peer churn.
const GETADDR_TRACKING_MULTIPLIER: usize = 4;
/// Floor for the cooldown table on very small PEX pools.
const MIN_GETADDR_TRACKED: usize = 128;

/// PEX manager — tracks known peers and handles discovery.
pub struct PexManager {
    /// Known peers by address string.
    known: HashMap<String, PeerAddr>,
    /// Addresses confirmed by a successful outbound connection.  Unconfirmed
    /// addresses are candidates to dial, but are never re-advertised.
    confirmed: HashSet<String>,
    /// Timestamps of last GetAddr sent to each peer.
    last_getaddr: HashMap<String, u64>,
    /// Insertion order for GetAddr cooldown tracking.
    ///
    /// This lets us prune stale / overflow cooldown entries in O(1)-amortized
    /// time under rotating peer churn without sorting the whole table on every
    /// insert. Each queue item is `(peer_id, recorded_at)`.
    getaddr_order: VecDeque<(String, u64)>,
    /// Maximum peers to track.
    max_peers: usize,
    /// Regtest and testnet deliberately permit private/loopback addresses for
    /// local topologies. Mainnet accepts only publicly-routable addresses.
    allow_non_public_addrs: bool,
}

impl PexManager {
    /// Create a new PEX manager.
    pub fn new(max_peers: usize) -> Self {
        Self::with_policy(max_peers, false)
    }

    /// Create a PEX table using the appropriate address policy for `network`.
    pub fn for_network(max_peers: usize, network: Network) -> Self {
        Self::with_policy(max_peers, !matches!(network, Network::Mainnet))
    }

    fn with_policy(max_peers: usize, allow_non_public_addrs: bool) -> Self {
        Self {
            known: HashMap::new(),
            confirmed: HashSet::new(),
            last_getaddr: HashMap::new(),
            getaddr_order: VecDeque::new(),
            max_peers,
            allow_non_public_addrs,
        }
    }

    /// Add an unconfirmed candidate from configuration or discovery.
    ///
    /// This deliberately does not mark the address as recently seen. Only an
    /// authenticated outbound connection may do that via [`Self::mark_connected`].
    pub fn add_peer(&mut self, addr: String) -> bool {
        self.add_unconfirmed(addr, 0)
    }

    /// Learn an address advertised in an `Addr` message.
    ///
    /// A remote timestamp can age a newly learned candidate, but can never
    /// refresh an existing local observation or be placed in the future.
    pub fn process_addr_message(&mut self, entries: Vec<AddrEntry>) -> usize {
        let now = unix_now();
        entries
            .into_iter()
            .filter(|entry| self.add_unconfirmed(entry.addr.clone(), entry.last_seen.min(now)))
            .count()
    }

    /// Learn the likely listening endpoint of an authenticated inbound peer.
    ///
    /// The TCP source port is ephemeral, so the standard network P2P port is
    /// used as an unconfirmed dial candidate. It is never shared until an
    /// outbound connection succeeds.
    pub fn learn_inbound_peer(&mut self, ip: IpAddr, p2p_port: u16) -> bool {
        self.add_unconfirmed(SocketAddr::new(ip, p2p_port).to_string(), 0)
    }

    /// Record a successful outbound connection and make the endpoint shareable.
    pub fn mark_connected(&mut self, addr: &str) -> bool {
        let Ok(socket_addr) = addr.parse::<SocketAddr>() else {
            return false;
        };
        if !self.accepts(socket_addr) {
            return false;
        }
        if self.known.len() >= self.max_peers && !self.known.contains_key(addr) {
            return false;
        }

        let now = unix_now();
        self.known
            .entry(addr.to_string())
            .and_modify(|peer| {
                peer.last_seen = now;
                peer.failures = 0;
            })
            .or_insert(PeerAddr {
                addr: addr.to_string(),
                last_seen: now,
                failures: 0,
            });
        self.confirmed.insert(addr.to_string());
        true
    }

    /// Whether a candidate has been confirmed by a successful outbound dial.
    pub fn is_confirmed(&self, addr: &str) -> bool {
        self.confirmed.contains(addr)
    }

    /// Inspect the recorded timestamp for tests and diagnostics.
    pub fn last_seen(&self, addr: &str) -> Option<u64> {
        self.known.get(addr).map(|peer| peer.last_seen)
    }

    fn add_unconfirmed(&mut self, addr: String, last_seen: u64) -> bool {
        let Ok(socket_addr) = addr.parse::<SocketAddr>() else {
            return false;
        };
        if !self.accepts(socket_addr)
            || (self.known.len() >= self.max_peers && !self.known.contains_key(&addr))
        {
            return false;
        }

        match self.known.entry(addr.clone()) {
            std::collections::hash_map::Entry::Occupied(_) => false,
            std::collections::hash_map::Entry::Vacant(entry) => {
                entry.insert(PeerAddr {
                    addr,
                    last_seen,
                    failures: 0,
                });
                true
            }
        }
    }

    fn accepts(&self, addr: SocketAddr) -> bool {
        addr.port() != 0 && (self.allow_non_public_addrs || is_publicly_routable(addr.ip()))
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
        self.confirmed.retain(|addr| self.known.contains_key(addr));
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
                self.confirmed.contains(&p.addr)
                    && p.addr
                        .parse::<SocketAddr>()
                        .is_ok_and(|addr| self.accepts(addr))
                    && p.is_connectable()
                    && now.saturating_sub(p.last_seen) < MAX_PEER_AGE_SECS
            })
            .collect();

        // Sort by most recently seen
        peers.sort_by_key(|p| std::cmp::Reverse(p.last_seen));
        peers.truncate(MAX_ADDR_RESPONSE);
        peers
    }

    /// Get connectable peers for outbound connections.
    pub fn connectable_peers(&self) -> Vec<&PeerAddr> {
        let mut peers: Vec<&PeerAddr> =
            self.known.values().filter(|p| p.is_connectable()).collect();
        peers.sort_by_key(|p| std::cmp::Reverse(p.last_seen));
        peers
    }

    /// Check if we should send GetAddr to this peer.
    pub fn should_getaddr(&self, peer_id: &str) -> bool {
        self.should_getaddr_at(peer_id, unix_now())
    }

    /// Record that we sent GetAddr to a peer.
    pub fn record_getaddr(&mut self, peer_id: &str) {
        self.record_getaddr_at(peer_id, unix_now());
    }

    /// Check if we should ANSWER a GetAddr from this peer (serve-side
    /// rate-limit). Reuses the same bounded cooldown table as the send side,
    /// under a distinct key namespace, so a peer cannot make us build Addr
    /// responses more than once per GETADDR_COOLDOWN_SECS.
    pub fn should_serve_getaddr(&self, peer_id: &str) -> bool {
        self.should_serve_getaddr_at(peer_id, unix_now())
    }

    /// Record that we answered a GetAddr from this peer.
    pub fn record_getaddr_served(&mut self, peer_id: &str) {
        self.record_getaddr_served_at(peer_id, unix_now());
    }

    fn should_serve_getaddr_at(&self, peer_id: &str, now: u64) -> bool {
        self.should_getaddr_at(&Self::served_key(peer_id), now)
    }

    fn record_getaddr_served_at(&mut self, peer_id: &str, now: u64) {
        self.record_getaddr_at(&Self::served_key(peer_id), now);
    }

    /// Namespace serve-side cooldown entries away from send-side ones.
    /// Peer ids are SocketAddr strings, which never start with "served/".
    fn served_key(peer_id: &str) -> String {
        format!("served/{peer_id}")
    }

    /// Total known peers count.
    pub fn known_count(&self) -> usize {
        self.known.len()
    }

    /// Current number of peers tracked in the GetAddr cooldown table.
    pub fn tracked_getaddr_count(&self) -> usize {
        self.last_getaddr.len()
    }

    /// Seed initial peers from config.
    pub fn seed_from_config(&mut self, seed_peers: &[String]) {
        for addr in seed_peers {
            self.add_peer(addr.clone());
        }
    }

    fn should_getaddr_at(&self, peer_id: &str, now: u64) -> bool {
        match self.last_getaddr.get(peer_id) {
            None => true,
            Some(last) => now.saturating_sub(*last) > GETADDR_COOLDOWN_SECS,
        }
    }

    fn record_getaddr_at(&mut self, peer_id: &str, now: u64) {
        self.prune_getaddr_history(now);
        self.last_getaddr.insert(peer_id.to_string(), now);
        self.getaddr_order.push_back((peer_id.to_string(), now));
        self.enforce_getaddr_bound();
    }

    fn prune_getaddr_history(&mut self, now: u64) {
        while let Some((peer, recorded_at)) = self.getaddr_order.front().cloned() {
            let expired = now.saturating_sub(recorded_at) > GETADDR_COOLDOWN_SECS;
            let superseded = self.last_getaddr.get(&peer).copied() != Some(recorded_at);
            if !expired && !superseded {
                break;
            }

            self.getaddr_order.pop_front();
            if expired && self.last_getaddr.get(&peer).copied() == Some(recorded_at) {
                self.last_getaddr.remove(&peer);
            }
        }
    }

    fn enforce_getaddr_bound(&mut self) {
        let max_tracked = self.max_tracked_getaddr();
        while self.last_getaddr.len() > max_tracked {
            let Some((peer, recorded_at)) = self.getaddr_order.pop_front() else {
                break;
            };
            if self.last_getaddr.get(&peer).copied() == Some(recorded_at) {
                self.last_getaddr.remove(&peer);
            }
        }
    }

    fn max_tracked_getaddr(&self) -> usize {
        self.max_peers
            .saturating_mul(GETADDR_TRACKING_MULTIPLIER)
            .max(MIN_GETADDR_TRACKED)
    }
}

/// Whether an address is usable as a public Mainnet dial target.
///
/// The development networks intentionally bypass this policy so local private
/// topologies keep working. Mainnet excludes all special-use ranges relevant to
/// PEX poisoning, including mapped IPv4 addresses inside IPv6 notation.
fn is_publicly_routable(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => is_public_ipv4(ip),
        IpAddr::V6(ip) => is_public_ipv6(ip),
    }
}

fn is_public_ipv4(ip: Ipv4Addr) -> bool {
    let [a, b, c, _] = ip.octets();
    !ip.is_loopback()
        && !ip.is_private()
        && !ip.is_link_local()
        && !ip.is_multicast()
        && !ip.is_broadcast()
        && !ip.is_unspecified()
        && a != 0 // 0.0.0.0/8
        && !(a == 100 && (64..=127).contains(&b)) // RFC 6598 shared address space
        && !(a == 198 && (b == 18 || b == 19)) // RFC 2544 benchmarking
        && !(a == 192 && b == 0 && c == 2) // TEST-NET-1
        && !(a == 198 && b == 51 && c == 100) // TEST-NET-2
        && !(a == 203 && b == 0 && c == 113) // TEST-NET-3
        && a < 240 // reserved/future-use, including limited broadcast
}

fn is_public_ipv6(ip: Ipv6Addr) -> bool {
    if let Some(mapped) = ip.to_ipv4_mapped() {
        return is_public_ipv4(mapped);
    }
    let segments = ip.segments();
    let is_unique_local = (segments[0] & 0xfe00) == 0xfc00;
    let is_site_local = (segments[0] & 0xffc0) == 0xfec0;
    let is_documentation = segments[0] == 0x2001 && segments[1] == 0x0db8;
    let is_global_unicast = (segments[0] & 0xe000) == 0x2000;

    is_global_unicast
        && !ip.is_unspecified()
        && !ip.is_loopback()
        && !ip.is_multicast()
        && !ip.is_unicast_link_local()
        && !is_unique_local
        && !is_site_local
        && !is_documentation
}

/// Window for counting inbound Addr messages from one peer (same as the
/// GetAddr cooldown: an honest peer triggers at most one solicited Addr per
/// window, plus occasional unsolicited gossip).
pub const ADDR_FLOOD_WINDOW_SECS: u64 = GETADDR_COOLDOWN_SECS;

/// Addr messages tolerated per window per connection before each extra one
/// scores ADDRESS_FLOODING (+30): 1 solicited response + 3 unsolicited gossip.
/// At +30 each, a flooder is banned (score >= 100) on the 8th message.
pub const MAX_ADDR_MESSAGES_PER_WINDOW: u32 = 4;

/// Per-connection rate limiter for inbound Addr messages.
///
/// Fixed-window counter: cheap, no allocation, and the worst-case burst across
/// a window boundary (2x the limit) still bans a flooder within seconds.
#[derive(Debug, Default)]
pub struct AddrFloodTracker {
    window_start: u64,
    count: u32,
}

impl AddrFloodTracker {
    /// Create a tracker with an empty window.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register one inbound Addr message. Returns true if it is within the
    /// per-window budget, false if the peer is flooding.
    pub fn allow(&mut self) -> bool {
        self.allow_at(unix_now())
    }

    /// Clock-injected variant for deterministic tests.
    pub fn allow_at(&mut self, now: u64) -> bool {
        if now.saturating_sub(self.window_start) >= ADDR_FLOOD_WINDOW_SECS {
            self.window_start = now;
            self.count = 0;
        }
        self.count = self.count.saturating_add(1);
        self.count <= MAX_ADDR_MESSAGES_PER_WINDOW
    }
}

/// Serialize Addr payload — list of address strings.
/// Thin wrapper over the wire-level `AddrPayload` (single parser, no drift).
pub fn encode_addr_payload(addrs: &[&PeerAddr]) -> Vec<u8> {
    let entries: Vec<dom_wire::message::AddrEntry> = addrs
        .iter()
        .take(MAX_ADDR_RESPONSE)
        .filter(|p| p.addr.len() <= u8::MAX as usize)
        .map(|p| dom_wire::message::AddrEntry {
            addr: p.addr.clone(),
            last_seen: p.last_seen,
        })
        .collect();
    dom_wire::message::AddrPayload { entries }
        .to_bytes()
        .expect("bounded, length-filtered entries always encode")
}

/// Deserialize Addr payload.
/// Thin wrapper over the wire-level `AddrPayload` (single parser, no drift).
pub fn decode_addr_payload(data: &[u8]) -> Result<Vec<String>, dom_core::DomError> {
    let payload = dom_wire::message::AddrPayload::from_bytes(data)?;
    Ok(payload.entries.into_iter().map(|e| e.addr).collect())
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
        pex.add_peer("8.8.8.8:33370".to_string());
        assert_eq!(pex.known_count(), 1);
        let peers = pex.connectable_peers();
        assert_eq!(peers.len(), 1);
        assert_eq!(peers[0].addr, "8.8.8.8:33370");
    }

    #[test]
    fn failure_tracking() {
        let mut pex = PexManager::new(1000);
        pex.add_peer("8.8.8.8:33370".to_string());
        for _ in 0..10 {
            pex.record_failure("8.8.8.8:33370");
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
    fn serve_getaddr_cooldown_suppresses_second_within_window() {
        let mut pex = PexManager::new(1000);
        assert!(pex.should_serve_getaddr_at("1.2.3.4:5", 1_000));
        pex.record_getaddr_served_at("1.2.3.4:5", 1_000);
        // Second GetAddr from the same peer inside the window: suppressed.
        assert!(!pex.should_serve_getaddr_at("1.2.3.4:5", 1_000 + GETADDR_COOLDOWN_SECS));
        // Window elapsed: served again.
        assert!(pex.should_serve_getaddr_at("1.2.3.4:5", 1_001 + GETADDR_COOLDOWN_SECS));
    }

    #[test]
    fn serve_and_send_cooldowns_are_independent() {
        let mut pex = PexManager::new(1000);
        pex.record_getaddr_at("1.2.3.4:5", 1_000);
        // We sent GetAddr to the peer; that must not block us from ANSWERING
        // the peer's own GetAddr (and vice versa).
        assert!(pex.should_serve_getaddr_at("1.2.3.4:5", 1_000));
        pex.record_getaddr_served_at("1.2.3.4:5", 1_000);
        assert!(!pex.should_getaddr_at("1.2.3.4:5", 1_000));
        assert!(!pex.should_serve_getaddr_at("1.2.3.4:5", 1_000));
    }

    #[test]
    fn addr_flood_tracker_allows_budget_then_rejects() {
        let mut tracker = AddrFloodTracker::new();
        for i in 0..MAX_ADDR_MESSAGES_PER_WINDOW {
            assert!(tracker.allow_at(1_000), "message {i} within budget");
        }
        assert!(
            !tracker.allow_at(1_000),
            "message beyond budget must reject"
        );
        assert!(!tracker.allow_at(1_000 + ADDR_FLOOD_WINDOW_SECS - 1));
    }

    #[test]
    fn addr_flood_tracker_resets_after_window() {
        let mut tracker = AddrFloodTracker::new();
        for _ in 0..=MAX_ADDR_MESSAGES_PER_WINDOW {
            tracker.allow_at(1_000);
        }
        assert!(tracker.allow_at(1_000 + ADDR_FLOOD_WINDOW_SECS));
    }

    #[test]
    fn stale_getaddr_cooldown_entry_expires_without_sleep() {
        let mut pex = PexManager::new(1000);
        pex.record_getaddr_at("peer1", 1_000);
        assert!(!pex.should_getaddr_at("peer1", 1_000 + GETADDR_COOLDOWN_SECS));
        assert!(pex.should_getaddr_at("peer1", 1_001 + GETADDR_COOLDOWN_SECS));
    }

    #[test]
    fn stale_getaddr_entries_are_pruned_on_new_record() {
        let mut pex = PexManager::new(1000);
        pex.record_getaddr_at("peer-a", 1_000);
        pex.record_getaddr_at("peer-b", 1_000 + GETADDR_COOLDOWN_SECS + 1);
        assert_eq!(pex.tracked_getaddr_count(), 1);
        assert!(pex.should_getaddr_at("peer-a", 1_000 + GETADDR_COOLDOWN_SECS + 1));
        assert!(!pex.should_getaddr_at("peer-b", 1_000 + GETADDR_COOLDOWN_SECS + 1));
    }

    #[test]
    fn getaddr_tracking_is_bounded_under_rotating_peer_churn() {
        let mut pex = PexManager::new(1000);
        for i in 0..10_000usize {
            pex.record_getaddr_at(&format!("peer-{i}"), 1_000);
        }

        assert_eq!(pex.tracked_getaddr_count(), 4_000);
        assert!(pex.should_getaddr_at("peer-0", 1_601));
        assert!(!pex.should_getaddr_at("peer-9999", 1_000));
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
    fn addr_decode_rejects_too_short_count() {
        let err = decode_addr_payload(&[0x01]).expect_err("missing count byte must reject");
        assert!(
            format!("{err}").contains("addr payload too short"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn addr_decode_rejects_truncated_tail() {
        let peer = PeerAddr {
            addr: "127.0.0.1:33370".to_string(),
            last_seen: 1_700_000_000,
            failures: 0,
        };
        let mut encoded = encode_addr_payload(&[&peer]);
        encoded.extend_from_slice(&[0x0f, b'1', b'2', b'7']);
        encoded[0..2].copy_from_slice(&2u16.to_le_bytes());

        let err = decode_addr_payload(&encoded).expect_err("truncated tail must reject");
        assert!(
            format!("{err}").contains("addr payload truncated"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn addr_decode_rejects_trailing_bytes() {
        let peer = PeerAddr {
            addr: "127.0.0.1:33370".to_string(),
            last_seen: 1_700_000_000,
            failures: 0,
        };
        let mut encoded = encode_addr_payload(&[&peer]);
        encoded.push(0xff);

        let err = decode_addr_payload(&encoded).expect_err("trailing byte must reject");
        assert!(
            format!("{err}").contains("addr trailing bytes"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn addr_decode_rejects_oversized_count() {
        let encoded = ((MAX_ADDR_RESPONSE + 1) as u16).to_le_bytes();

        let err = decode_addr_payload(&encoded).expect_err("oversized count must reject");
        assert!(
            format!("{err}").contains("addr count exceeds limit"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn addr_decode_accepts_exact_valid() {
        let peer_a = PeerAddr {
            addr: "127.0.0.1:33370".to_string(),
            last_seen: 1_700_000_000,
            failures: 0,
        };
        let peer_b = PeerAddr {
            addr: "192.168.1.1:8080".to_string(),
            last_seen: 1_700_000_001,
            failures: 0,
        };
        let encoded = encode_addr_payload(&[&peer_a, &peer_b]);

        let decoded = decode_addr_payload(&encoded).expect("exact addr payload must decode");
        assert_eq!(
            decoded,
            vec![
                "127.0.0.1:33370".to_string(),
                "192.168.1.1:8080".to_string()
            ]
        );
    }

    #[test]
    fn mainnet_filters_non_public_ipv4_and_ipv6_addresses() {
        let mut pex = PexManager::new(1000);
        let addrs = vec![
            AddrEntry {
                addr: "8.8.8.8:33370".into(),
                last_seen: 1,
            },
            AddrEntry {
                addr: "[2606:4700:4700::1111]:33370".into(),
                last_seen: 1,
            },
            AddrEntry {
                addr: "127.0.0.1:33370".into(),
                last_seen: 1,
            },
            AddrEntry {
                addr: "10.0.0.1:33370".into(),
                last_seen: 1,
            },
            AddrEntry {
                addr: "172.16.0.1:33370".into(),
                last_seen: 1,
            },
            AddrEntry {
                addr: "192.168.1.1:33370".into(),
                last_seen: 1,
            },
            AddrEntry {
                addr: "169.254.1.1:33370".into(),
                last_seen: 1,
            },
            AddrEntry {
                addr: "198.18.1.1:33370".into(),
                last_seen: 1,
            },
            AddrEntry {
                addr: "192.0.2.1:33370".into(),
                last_seen: 1,
            },
            AddrEntry {
                addr: "198.51.100.1:33370".into(),
                last_seen: 1,
            },
            AddrEntry {
                addr: "203.0.113.1:33370".into(),
                last_seen: 1,
            },
            AddrEntry {
                addr: "224.0.0.1:33370".into(),
                last_seen: 1,
            },
            AddrEntry {
                addr: "0.1.2.3:33370".into(),
                last_seen: 1,
            },
            AddrEntry {
                addr: "8.8.4.4:0".into(),
                last_seen: 1,
            },
            AddrEntry {
                addr: "[::1]:33370".into(),
                last_seen: 1,
            },
            AddrEntry {
                addr: "[fc00::1]:33370".into(),
                last_seen: 1,
            },
            AddrEntry {
                addr: "[fe80::1]:33370".into(),
                last_seen: 1,
            },
            AddrEntry {
                addr: "[ff02::1]:33370".into(),
                last_seen: 1,
            },
            AddrEntry {
                addr: "[2001:db8::1]:33370".into(),
                last_seen: 1,
            },
            AddrEntry {
                addr: "not_an_addr".into(),
                last_seen: 1,
            },
        ];
        let added = pex.process_addr_message(addrs);
        assert_eq!(added, 2);
        assert!(pex.mark_connected("8.8.8.8:33370"));
        assert!(pex.mark_connected("[2606:4700:4700::1111]:33370"));
        assert_eq!(pex.peers_for_sharing().len(), 2);
    }

    #[test]
    fn development_networks_allow_private_addresses_but_not_zero_port() {
        let mut pex = PexManager::for_network(1000, Network::Regtest);
        let added = pex.process_addr_message(vec![
            AddrEntry {
                addr: "127.0.0.1:33370".into(),
                last_seen: 1,
            },
            AddrEntry {
                addr: "10.0.0.1:33370".into(),
                last_seen: 1,
            },
            AddrEntry {
                addr: "192.168.1.1:0".into(),
                last_seen: 1,
            },
        ]);
        assert_eq!(added, 2);
    }

    #[test]
    fn addr_reannouncement_does_not_refresh_last_seen() {
        let mut pex = PexManager::new(1000);
        let addr = "8.8.8.8:33370";
        assert_eq!(
            pex.process_addr_message(vec![AddrEntry {
                addr: addr.into(),
                last_seen: 1,
            }]),
            1
        );
        assert_eq!(pex.last_seen(addr), Some(1));

        assert_eq!(
            pex.process_addr_message(vec![AddrEntry {
                addr: addr.into(),
                last_seen: u64::MAX,
            }]),
            0
        );
        assert_eq!(pex.last_seen(addr), Some(1));

        assert!(pex.mark_connected(addr));
        let locally_confirmed = pex.last_seen(addr).expect("confirmed peer timestamp");
        assert_eq!(
            pex.process_addr_message(vec![AddrEntry {
                addr: addr.into(),
                last_seen: u64::MAX,
            }]),
            0
        );
        assert_eq!(pex.last_seen(addr), Some(locally_confirmed));
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
        let seeds = vec!["8.8.8.8:33369".to_string(), "1.1.1.1:33369".to_string()];
        pex.seed_from_config(&seeds);
        assert_eq!(pex.known_count(), 2);
    }
}
