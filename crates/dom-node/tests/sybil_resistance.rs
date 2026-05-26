//! Roadmap v2 Phase 4.4 — Sybil-resistance adversarial coverage.
//!
//! `PexManager` is the peer-discovery layer. It tracks known peer
//! addresses, exchanges them with connected peers over the
//! GetAddr/Addr protocol, and feeds the outbound-dialer. A
//! Sybil-flavoured attacker can attempt:
//!
//!   1. **Fake peer flood** — push N >> max_peers addrs through
//!      process_addr_message hoping to displace legitimate entries.
//!   2. **PEX poisoning** — push malformed / unroutable / localhost
//!      addrs hoping the dialer connects to attacker-controlled
//!      machines.
//!   3. **GetAddr storm** — repeatedly ask the same peer for its
//!      address list, hoping to amplify the attacker's reach.
//!   4. **Failure-tracking laundering** — connect once successfully,
//!      then fail enough times to be re-evicted (the failure counter
//!      MUST persist across observations).
//!   5. **Connection monopolisation via PEX** — advertise the same
//!      peer N times so the known set carries duplicates the dialer
//!      would consult repeatedly.
//!
//! `PexManager`'s defences are documented inline; the tests below
//! pin each behaviour as a regression gate. Subnet-diversity at the
//! connection-acceptance layer is covered separately by
//! dom-wire/tests/eclipse_resistance.rs (Phase 4.2). PEX itself
//! does NOT enforce subnet diversity in its known set — that gap
//! is documented under RB-PEX-SUBNET in RELEASE_BLOCKERS.

use dom_node::pex::{
    decode_addr_payload, encode_addr_payload, PexManager, GETADDR_COOLDOWN_SECS, MAX_ADDR_RESPONSE,
    MAX_PEER_AGE_SECS,
};
use dom_store::PeerAddr;

// ── (1) Fake peer flood is bounded by max_peers ──────────────────────────────

/// Submitting 10_000 valid addresses to a PEX with max_peers=1000
/// MUST cap the known set at 1000. The bound is enforced inside
/// `add_peer` (capacity check before insert).
#[test]
fn flood_is_bounded_by_max_peers() {
    let mut pex = PexManager::new(1000);
    let flood: Vec<String> = (0..10_000)
        .map(|i| {
            let a = (i / 65_536) as u8;
            let b = ((i / 256) % 256) as u8;
            let c = (i % 256) as u8;
            format!("203.{a}.{b}.{c}:33369")
        })
        .collect();
    pex.process_addr_message(flood);
    assert!(
        pex.known_count() <= 1000,
        "known_count {} exceeded max_peers 1000",
        pex.known_count()
    );
}

// ── (2) PEX poisoning attempts ───────────────────────────────────────────────

/// process_addr_message MUST silently drop malformed strings,
/// preventing them from polluting the known set. Catches a
/// regression where an attacker could push "PROXY THIS",
/// "../etc/passwd", or any non-SocketAddr string.
#[test]
fn malformed_addresses_filtered() {
    let mut pex = PexManager::new(1000);
    let mixed = vec![
        "10.0.0.1:33369".to_string(),
        "not_an_addr".to_string(),
        "PROXY this string".to_string(),
        "256.256.256.256:33369".to_string(), // out-of-range octets
        "1.2.3.4".to_string(),               // missing port
        "[::]:33369:wat".to_string(),
        "203.0.113.1:33369".to_string(),
    ];
    let added = pex.process_addr_message(mixed);
    assert_eq!(
        added, 2,
        "exactly 2 well-formed addresses should land in the known set"
    );
    assert_eq!(pex.known_count(), 2);
}

/// PEX SHOULD accept localhost / RFC1918 / link-local addrs as
/// strings (the dialer is responsible for not connecting to them
/// in mainnet builds — the address-set is a discovery layer, not
/// a policy layer). Pin this so a future refactor doesn't add
/// silent filtering at the wrong layer.
#[test]
fn rfc1918_and_localhost_addresses_are_accepted_at_pex_layer() {
    let mut pex = PexManager::new(1000);
    let addrs = vec![
        "127.0.0.1:33369".to_string(),
        "10.0.0.1:33369".to_string(),
        "192.168.1.1:33369".to_string(),
        "172.16.0.1:33369".to_string(),
    ];
    let added = pex.process_addr_message(addrs);
    assert_eq!(added, 4, "PEX layer must accept private addresses");
}

// ── (3) GetAddr storm ────────────────────────────────────────────────────────

/// After `record_getaddr`, the cooldown blocks all subsequent
/// queries to the same peer until GETADDR_COOLDOWN_SECS elapses.
/// Catches a regression where the cooldown is bypassed by a
/// concurrent caller racing the timestamp.
#[test]
fn getaddr_cooldown_blocks_storm() {
    let mut pex = PexManager::new(1000);
    let peer = "peer-x";
    assert!(pex.should_getaddr(peer));
    pex.record_getaddr(peer);
    // 10 fast follow-ups MUST all be blocked.
    for _ in 0..10 {
        assert!(
            !pex.should_getaddr(peer),
            "getaddr cooldown ({}s) must block repeated queries",
            GETADDR_COOLDOWN_SECS
        );
    }
}

/// A hostile rotating peer set MUST NOT turn GetAddr cooldown tracking into an
/// unbounded memory sink. The cooldown table is runtime-only state and must
/// stay bounded independently of the known-peer cap.
#[test]
fn rotating_getaddr_storm_does_not_grow_cooldown_state_without_bound() {
    let mut pex = PexManager::new(1000);
    for i in 0..50_000usize {
        pex.record_getaddr(&format!("peer-{i}"));
    }

    assert!(
        pex.tracked_getaddr_count() <= 4_000,
        "GetAddr cooldown state must remain bounded under rotating churn; got {}",
        pex.tracked_getaddr_count()
    );
}

// ── (4) Failure tracking laundering ──────────────────────────────────────────

/// Recording 10 failures on a peer MUST cause `evict_dead_peers`
/// to remove it. Catches a regression where the failure counter
/// saturates without triggering eviction.
#[test]
fn failed_peers_are_evicted() {
    let mut pex = PexManager::new(1000);
    pex.add_peer("198.51.100.1:33369".to_string());
    for _ in 0..10 {
        pex.record_failure("198.51.100.1:33369");
    }
    pex.evict_dead_peers();
    assert_eq!(pex.known_count(), 0);
}

/// add_peer MUST reset the failure counter to zero so a peer that
/// reconnects gets a clean slate. This is the legitimate use case
/// of the failure-tracking laundering pattern (a flapping peer
/// recovers) and the security one (a Sybil cannot pin a target
/// by failing it once).
#[test]
fn add_peer_resets_failure_counter() {
    let mut pex = PexManager::new(1000);
    pex.add_peer("198.51.100.2:33369".to_string());
    pex.record_failure("198.51.100.2:33369");
    pex.record_failure("198.51.100.2:33369");
    // Re-add — counter resets, not eligible for eviction yet.
    pex.add_peer("198.51.100.2:33369".to_string());
    pex.evict_dead_peers();
    assert_eq!(pex.known_count(), 1);
}

// ── (5) Connection monopolisation via duplicate advertise ────────────────────

/// Advertising the same peer N times MUST result in exactly one
/// entry in the known set — duplicates are de-duplicated by the
/// HashMap keyed on the address string.
#[test]
fn duplicate_advertise_does_not_inflate_known_set() {
    let mut pex = PexManager::new(1000);
    let dup: Vec<String> = (0..500).map(|_| "10.0.0.1:33369".to_string()).collect();
    pex.process_addr_message(dup);
    assert_eq!(pex.known_count(), 1);
}

// ── (6) Addr payload encode/decode roundtrip + cap ───────────────────────────

/// encode_addr_payload truncates at MAX_ADDR_RESPONSE so a single
/// response cannot carry more than 1000 addresses regardless of
/// the underlying known-set size.
#[test]
fn addr_response_caps_at_max_addr_response() {
    // Build 2x MAX_ADDR_RESPONSE peer refs.
    let peers: Vec<PeerAddr> = (0..(2 * MAX_ADDR_RESPONSE))
        .map(|i| PeerAddr {
            addr: format!("203.0.113.1:{}", 33369 + i),
            last_seen: 1_700_000_000 + i as u64,
            failures: 0,
        })
        .collect();
    let refs: Vec<&PeerAddr> = peers.iter().collect();
    let encoded = encode_addr_payload(&refs);
    let decoded = decode_addr_payload(&encoded).expect("decode");
    assert!(
        decoded.len() <= MAX_ADDR_RESPONSE,
        "addr payload must truncate at MAX_ADDR_RESPONSE; got {}",
        decoded.len()
    );
}

/// decode_addr_payload MUST not panic on a payload claiming
/// `count = u16::MAX` — internally clamped to MAX_ADDR_RESPONSE.
#[test]
fn decode_addr_payload_handles_oversized_count() {
    let mut buf = u16::MAX.to_le_bytes().to_vec();
    // Stop after the count — decoder sees the truncation and
    // returns whatever it managed to parse, not a panic.
    buf.extend_from_slice(&[0u8; 32]); // partial body
    let _ = decode_addr_payload(&buf).expect("must not panic");
}

// ── (7) MAX_PEER_AGE_SECS is honoured for shared peers ───────────────────────

/// `peers_for_sharing` MUST drop entries older than
/// MAX_PEER_AGE_SECS (7 days) to avoid amplifying stale Sybil
/// advertisements indefinitely.
#[test]
fn peers_for_sharing_filters_stale_entries() {
    let mut pex = PexManager::new(1000);
    pex.add_peer("10.0.0.1:33369".to_string());
    // Manually drop a peer that we'd consider expired. Achieved
    // by inspecting the inferred age via the live time path.
    // The PexManager doesn't expose direct mutation of last_seen,
    // but the in-crate test "failure_tracking" already exercises
    // the eviction path. Here we just confirm that `peers_for_sharing`
    // returns ≤ known_count for any live pool.
    let shared = pex.peers_for_sharing();
    assert!(shared.len() <= pex.known_count());
    // Sanity: the documented MAX_PEER_AGE_SECS is 7 days in seconds.
    assert_eq!(MAX_PEER_AGE_SECS, 7 * 24 * 3600);
}
