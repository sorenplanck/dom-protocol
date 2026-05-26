//! Roadmap v2 Phase 4.2 — Eclipse-resistance adversarial coverage.
//!
//! The `PeerManager` defends against two of the three classical
//! eclipse-attack vectors at the connection-acceptance boundary:
//!
//!   1. **Subnet diversity** — `MAX_PEERS_SAME_SLASH_16 = 2`. An
//!      attacker controlling a single /16 block can never occupy
//!      more than two inbound slots.
//!   2. **Inbound cap** — `max_inbound` configurable; once full the
//!      manager refuses additional inbound connections.
//!
//! What it does NOT yet defend (tracked under RB-EVICTION-POLICY):
//!
//!   * **Slot monopolisation by first connectors** — once
//!     `max_inbound` is full, there is no eviction policy. An
//!     attacker who connects first holds the slots until they
//!     voluntarily disconnect. Bitcoin Core's "feeler + eviction"
//!     model is the documented mitigation path.
//!
//! This file pins the inbound-side defences and documents the gap.
//!
//! Outbound peers are not subject to the subnet check (the node
//! chooses outbound targets itself, so an external attacker cannot
//! steer them by IP) — that asymmetry is deliberate. See the
//! `outbound_peers_not_subject_to_subnet_cap` test.

use dom_wire::manager::PeerManager;
use dom_wire::peer::{PeerInfo, PeerState};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

fn ipv4_peer(ip: [u8; 4], port: u16, outbound: bool) -> PeerInfo {
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::from(ip)), port);
    let mut p = PeerInfo::new(addr, outbound);
    p.state = PeerState::Connected;
    p
}

fn ipv6_peer(ip: [u16; 8], port: u16, outbound: bool) -> PeerInfo {
    let addr = SocketAddr::new(IpAddr::V6(Ipv6Addr::from(ip)), port);
    let mut p = PeerInfo::new(addr, outbound);
    p.state = PeerState::Connected;
    p
}

// ── (1) Subnet flood ─────────────────────────────────────────────────────────

/// Flood from a single /16 — only the first two get in. Bound at
/// 200 connection attempts to confirm linear growth doesn't sneak
/// past the cap.
#[test]
fn ipv4_slash16_flood_caps_at_two_inbound_peers() {
    let mut mgr = PeerManager::new(125, 8);
    let mut accepted = 0usize;
    for i in 0..200u8 {
        // 203.0.113.0/24 inside the 203.0.0.0/16 subnet.
        let r = mgr.register_peer(ipv4_peer([203, 0, 113, i.wrapping_add(1)], 33369, false));
        if r.is_ok() {
            accepted += 1;
        }
    }
    assert_eq!(
        accepted, 2,
        "MAX_PEERS_SAME_SLASH_16 must cap inbound floods at 2"
    );
}

/// Same /16 reach across distinct /24 subnets MUST still cap at 2.
/// Catches a regression where the subnet check would compare /24
/// instead of /16.
#[test]
fn slash16_check_uses_first_two_octets_not_three() {
    let mut mgr = PeerManager::new(125, 8);
    mgr.register_peer(ipv4_peer([198, 51, 100, 1], 33369, false))
        .expect("first /24 ok");
    mgr.register_peer(ipv4_peer([198, 51, 200, 1], 33369, false))
        .expect("second /24 inside same /16 ok (slot 2 of 2)");
    let r = mgr.register_peer(ipv4_peer([198, 51, 7, 1], 33369, false));
    assert!(
        r.is_err(),
        "third connection from same /16 (even different /24) must be rejected"
    );
}

// ── (2) IPv6 subnet handling ─────────────────────────────────────────────────

/// IPv6 peers from the same /16 (first two octets of the
/// representation, per `to_slash16`) MUST also be capped at 2.
#[test]
fn ipv6_subnet_diversity_cap_enforced() {
    let mut mgr = PeerManager::new(125, 8);
    mgr.register_peer(ipv6_peer([0x2001, 0xdb8, 0, 0, 0, 0, 0, 1], 33369, false))
        .expect("first IPv6 ok");
    mgr.register_peer(ipv6_peer([0x2001, 0xdb8, 0, 0, 0, 0, 0, 2], 33369, false))
        .expect("second IPv6 ok");
    let r = mgr.register_peer(ipv6_peer([0x2001, 0xdb8, 0, 0, 0, 0, 0, 3], 33369, false));
    // /16 is the first two octets; 0x2001 (20:01) → [0x20, 0x01].
    // All three peers have identical [0x20, 0x01] prefix.
    assert!(r.is_err(), "third IPv6 peer from same /16 must be rejected");
}

// ── (3) Inbound cap ──────────────────────────────────────────────────────────

/// Once `max_inbound` is reached, additional inbound peers MUST be
/// rejected even from never-before-seen subnets.
#[test]
fn inbound_cap_rejects_new_subnets_when_full() {
    // max_inbound=4 so we can fill it on diverse subnets quickly.
    let mut mgr = PeerManager::new(4, 8);
    mgr.register_peer(ipv4_peer([10, 0, 0, 1], 33369, false))
        .unwrap();
    mgr.register_peer(ipv4_peer([172, 16, 0, 1], 33369, false))
        .unwrap();
    mgr.register_peer(ipv4_peer([192, 168, 0, 1], 33369, false))
        .unwrap();
    mgr.register_peer(ipv4_peer([198, 51, 100, 1], 33369, false))
        .unwrap();
    // Slot 5: distinct subnet, but cap is hit.
    let r = mgr.register_peer(ipv4_peer([203, 0, 113, 1], 33369, false));
    assert!(
        r.is_err(),
        "5th inbound must be rejected by max_inbound cap"
    );
}

// ── (4) Disconnected peers free slots ────────────────────────────────────────

/// `inbound_count` filters out disconnected peers, so removing a
/// peer frees the slot for a new one. Pins the bookkeeping so a
/// regression that leaks "ghost" slots is caught.
#[test]
fn disconnected_peer_frees_an_inbound_slot() {
    let mut mgr = PeerManager::new(2, 8);
    mgr.register_peer(ipv4_peer([10, 0, 0, 1], 33369, false))
        .unwrap();
    mgr.register_peer(ipv4_peer([172, 16, 0, 1], 33369, false))
        .unwrap();
    assert!(mgr
        .register_peer(ipv4_peer([192, 168, 0, 1], 33369, false))
        .is_err());
    // Disconnect one, then try again — slot must be available.
    mgr.remove_peer("10.0.0.1:33369");
    mgr.register_peer(ipv4_peer([192, 168, 0, 1], 33369, false))
        .expect("slot reclaimed after disconnect");
}

// ── (5) Outbound peers are not subject to subnet cap ─────────────────────────

/// Outbound peers chosen by the node (DNS-seed / hardcoded peers)
/// are intentionally NOT subject to `MAX_PEERS_SAME_SLASH_16` —
/// the node chooses its own destinations, so this is not an
/// attacker-controlled surface. The check inside `can_accept_inbound`
/// only filters `!p.outbound` peers.
#[test]
fn outbound_peers_not_subject_to_subnet_cap() {
    let mut mgr = PeerManager::new(125, 8);
    // Register 3 outbound peers from same /16 — must all succeed
    // because the subnet check is inbound-only.
    for i in 1..=3u8 {
        mgr.register_peer(ipv4_peer([203, 0, 113, i], 33369, true))
            .unwrap_or_else(|e| panic!("outbound #{i} must be accepted: {e}"));
    }
    assert_eq!(mgr.outbound_count(), 3);
    // And an inbound connection from the same /16 is still allowed
    // up to its own /16-cap on the inbound side.
    mgr.register_peer(ipv4_peer([203, 0, 113, 100], 33369, false))
        .expect("inbound slot 1 from same /16 ok");
    mgr.register_peer(ipv4_peer([203, 0, 113, 101], 33369, false))
        .expect("inbound slot 2 from same /16 ok");
    assert!(
        mgr.register_peer(ipv4_peer([203, 0, 113, 102], 33369, false))
            .is_err(),
        "inbound slot 3 from same /16 must be rejected"
    );
}

// ── (6) Duplicate registration ───────────────────────────────────────────────

/// Attempting to register the same socket twice MUST be rejected
/// regardless of inbound/outbound flag. Catches a regression where
/// a single peer connecting twice would double-count.
#[test]
fn duplicate_peer_registration_rejected() {
    let mut mgr = PeerManager::new(125, 8);
    mgr.register_peer(ipv4_peer([10, 0, 0, 1], 33369, false))
        .unwrap();
    let r = mgr.register_peer(ipv4_peer([10, 0, 0, 1], 33369, false));
    assert!(r.is_err(), "duplicate inbound rejected");
    let r = mgr.register_peer(ipv4_peer([10, 0, 0, 1], 33369, true));
    assert!(r.is_err(), "duplicate (outbound flag flip) rejected");
}

// ── (7) Pending handshakes count against inbound limits ───────────────────────

/// Inbound slots must be consumed before Noise/Hello completes. Otherwise a
/// Slowloris-style attacker can open many TCP connections that all pass the
/// pre-spawn capacity check before any peer is registered.
#[test]
fn pending_inbound_reservations_count_toward_inbound_cap() {
    let mut mgr = PeerManager::new(2, 8);
    let a = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 33369);
    let b = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1)), 33369);
    let c = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 0, 1)), 33369);

    mgr.reserve_inbound(a).expect("first pending slot");
    mgr.reserve_inbound(b).expect("second pending slot");
    assert_eq!(mgr.pending_inbound_count(), 2);
    assert!(
        mgr.reserve_inbound(c).is_err(),
        "third pending inbound must be rejected by max_inbound"
    );
}

/// Pending handshakes must also count toward the per-/16 cap. This prevents an
/// attacker from occupying all pending work with many sockets from one subnet.
#[test]
fn pending_inbound_reservations_count_toward_subnet_cap() {
    let mut mgr = PeerManager::new(125, 8);
    let a = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1)), 33369);
    let b = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 2)), 33369);
    let c = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 3)), 33369);

    mgr.reserve_inbound(a).expect("first /16 pending slot");
    mgr.reserve_inbound(b).expect("second /16 pending slot");
    assert!(
        mgr.reserve_inbound(c).is_err(),
        "third pending inbound from same /16 must be rejected"
    );
}

/// Registering a peer consumes its pending reservation exactly once. Releasing
/// after task shutdown is intentionally idempotent.
#[test]
fn registering_peer_releases_pending_reservation() {
    let mut mgr = PeerManager::new(2, 8);
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 33369);
    mgr.reserve_inbound(addr).expect("reserve");
    assert_eq!(mgr.pending_inbound_count(), 1);

    mgr.register_peer(ipv4_peer([10, 0, 0, 1], 33369, false))
        .expect("register");
    assert_eq!(mgr.pending_inbound_count(), 0);
    mgr.release_inbound_reservation(&addr);
    assert_eq!(mgr.pending_inbound_count(), 0);
}

/// Failed handshakes release their reservation so honest peers can retry later.
#[test]
fn failed_handshake_release_frees_pending_slot() {
    let mut mgr = PeerManager::new(1, 8);
    let a = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 33369);
    let b = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1)), 33369);

    mgr.reserve_inbound(a).expect("reserve");
    assert!(mgr.reserve_inbound(b).is_err());
    mgr.release_inbound_reservation(&a);
    mgr.reserve_inbound(b)
        .expect("slot must be reusable after failed handshake release");
}

/// The node cleanup path calls `remove_peer` after a connection task exits.
/// That must clear both registered peers and any pre-registration reservation.
#[test]
fn remove_peer_clears_pending_reservation_too() {
    let mut mgr = PeerManager::new(1, 8);
    let a = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 33369);
    let b = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1)), 33369);

    mgr.reserve_inbound(a).expect("reserve");
    assert!(mgr.reserve_inbound(b).is_err());
    mgr.remove_peer(&a.to_string());
    mgr.reserve_inbound(b)
        .expect("remove_peer must free a pending reservation");
}

/// A malformed-handshake storm can rotate source addresses forever. The
/// pre-registration penalty cache must stay bounded under churn so the node
/// does not trade protocol safety for unbounded RAM growth.
#[test]
fn pending_penalty_cache_stays_bounded_under_malformed_address_storm() {
    let mut mgr = PeerManager::new(125, 8);
    for i in 0..10_000usize {
        let addr = format!("198.51.{}.{}:33369", (i / 255) % 255, (i % 255) + 1);
        mgr.add_pending_ban_score(&addr, 20);
    }

    assert!(
        mgr.pending_penalty_count() <= 4_096,
        "pre-registration penalty churn must remain memory-bounded"
    );
    assert_eq!(
        mgr.pending_ban_score("198.51.0.1:33369"),
        0,
        "oldest churn entries should be evicted once the penalty cache is full"
    );
}
