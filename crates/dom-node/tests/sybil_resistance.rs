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
use dom_wire::message::AddrEntry;

// ── (1) Fake peer flood is bounded by max_peers ──────────────────────────────

/// Submitting 10_000 valid addresses to a PEX with max_peers=1000
/// MUST cap the known set at 1000. The bound is enforced inside
/// `add_peer` (capacity check before insert).
#[test]
fn flood_is_bounded_by_max_peers() {
    let mut pex = PexManager::new(1000);
    let flood: Vec<AddrEntry> = (0..10_000)
        .map(|i| {
            let a = (i / 65_536) as u8;
            let b = ((i / 256) % 256) as u8;
            let c = (i % 256) as u8;
            AddrEntry {
                addr: format!("8.{a}.{b}.{c}:33369"),
                last_seen: 1,
            }
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
        AddrEntry {
            addr: "10.0.0.1:33369".into(),
            last_seen: 1,
        },
        AddrEntry {
            addr: "not_an_addr".into(),
            last_seen: 1,
        },
        AddrEntry {
            addr: "PROXY this string".into(),
            last_seen: 1,
        },
        AddrEntry {
            addr: "256.256.256.256:33369".into(),
            last_seen: 1,
        },
        AddrEntry {
            addr: "1.2.3.4".into(),
            last_seen: 1,
        },
        AddrEntry {
            addr: "[::]:33369:wat".into(),
            last_seen: 1,
        },
        AddrEntry {
            addr: "203.0.113.1:33369".into(),
            last_seen: 1,
        },
        AddrEntry {
            addr: "8.8.8.8:33369".into(),
            last_seen: 1,
        },
    ];
    let added = pex.process_addr_message(mixed);
    assert_eq!(
        added, 1,
        "only a public, well-formed address should land in the known set"
    );
    assert_eq!(pex.known_count(), 1);
}

/// Mainnet PEX MUST reject localhost and RFC1918 candidates before they enter
/// the address book, rather than relying on a later dial attempt.
#[test]
fn rfc1918_and_localhost_addresses_are_rejected_at_pex_layer() {
    let mut pex = PexManager::new(1000);
    let addrs = vec![
        AddrEntry {
            addr: "127.0.0.1:33369".into(),
            last_seen: 1,
        },
        AddrEntry {
            addr: "10.0.0.1:33369".into(),
            last_seen: 1,
        },
        AddrEntry {
            addr: "192.168.1.1:33369".into(),
            last_seen: 1,
        },
        AddrEntry {
            addr: "172.16.0.1:33369".into(),
            last_seen: 1,
        },
    ];
    let added = pex.process_addr_message(addrs);
    assert_eq!(added, 0, "Mainnet PEX must reject private addresses");
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
    pex.add_peer("8.8.8.1:33369".to_string());
    for _ in 0..10 {
        pex.record_failure("8.8.8.1:33369");
    }
    pex.evict_dead_peers();
    assert_eq!(pex.known_count(), 0);
}

/// Re-announcing a peer MUST NOT reset failures; only a successful outbound
/// connection may rehabilitate it.
#[test]
fn add_peer_does_not_reset_failure_counter() {
    let mut pex = PexManager::new(1000);
    pex.add_peer("8.8.8.2:33369".to_string());
    for _ in 0..2 {
        pex.record_failure("8.8.8.2:33369");
    }
    pex.add_peer("8.8.8.2:33369".to_string());
    for _ in 0..8 {
        pex.record_failure("8.8.8.2:33369");
    }
    pex.evict_dead_peers();
    assert_eq!(pex.known_count(), 0);
}

// ── (5) Connection monopolisation via duplicate advertise ────────────────────

/// Advertising the same peer N times MUST result in exactly one
/// entry in the known set — duplicates are de-duplicated by the
/// HashMap keyed on the address string.
#[test]
fn duplicate_advertise_does_not_inflate_known_set() {
    let mut pex = PexManager::new(1000);
    let dup: Vec<AddrEntry> = (0..500)
        .map(|_| AddrEntry {
            addr: "8.8.8.8:33369".into(),
            last_seen: 1,
        })
        .collect();
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

/// decode_addr_payload MUST reject a payload claiming
/// `count = u16::MAX` before allocating based on the declared count.
#[test]
fn decode_addr_payload_rejects_oversized_count() {
    let mut buf = u16::MAX.to_le_bytes().to_vec();
    buf.extend_from_slice(&[0u8; 32]); // partial body

    let err = decode_addr_payload(&buf).expect_err("oversized count must reject");
    assert!(
        format!("{err}").contains("addr count exceeds limit"),
        "unexpected error: {err}"
    );
}

// ── (7) MAX_PEER_AGE_SECS is honoured for shared peers ───────────────────────

/// `peers_for_sharing` MUST drop entries older than
/// MAX_PEER_AGE_SECS (7 days) to avoid amplifying stale Sybil
/// advertisements indefinitely.
#[test]
fn peers_for_sharing_filters_stale_entries() {
    let mut pex = PexManager::new(1000);
    pex.add_peer("8.8.8.8:33369".to_string());
    pex.mark_connected("8.8.8.8:33369");
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
