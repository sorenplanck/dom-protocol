//! dom-shield — PEX eclipse-bias coverage (PEX/relay sub-area).
//!
//! Threat: `PexManager` has NO IP-diversity / subnet bucketing in its known
//! set. `add_peer` is first-come-first-served (capacity check, then plain
//! insert), and both `connectable_peers` and `peers_for_sharing` rank purely
//! by `last_seen`. An attacker who fills the known set with addresses from a
//! single /24 subnet monopolises the outbound-dialer candidate list, which is
//! the classic eclipse precondition.
//!
//! This is a CONFIRMATION of the already-documented gap (RB-PEX-SUBNET /
//! sybil_resistance.rs note), not a new finding. The existing
//! `sybil_resistance.rs` pins the *bound* (the known set is capped) and the
//! flood/poison/storm vectors; it does NOT demonstrate the *diversity bias* of
//! the surviving set. These tests close that specific door by proving the bias
//! exists and is total when the attacker wins the fill race.
//!
//! Technique: proptest over (attacker_subnet_size, honest_count) — invariant:
//! "if attacker fills the set first, the connectable list is 100% attacker".

use dom_node::pex::PexManager;
use proptest::prelude::*;

/// A single-subnet flood that arrives BEFORE honest addrs and fills the known
/// set leaves ZERO honest peers connectable — the eclipse precondition. There
/// is no subnet cap that would reserve slots for diversity.
#[test]
fn single_subnet_flood_monopolises_connectable_set() {
    let max_peers = 64usize;
    let mut pex = PexManager::new(max_peers);

    // Attacker floods max_peers publicly-routable addresses from one /24.
    for i in 0..max_peers {
        pex.add_peer(format!("8.8.0.{}:8333", i % 256));
    }
    assert_eq!(
        pex.known_count(),
        max_peers,
        "set should be full of attacker"
    );

    // Honest peers from diverse subnets arrive AFTER the set is full.
    for i in 0..32u8 {
        pex.add_peer(format!("1.1.{}.7:8333", i));
    }

    // add_peer drops new addrs when full -> honest peers never enter the set.
    let connectable = pex.connectable_peers();
    assert_eq!(
        connectable.len(),
        max_peers,
        "set stays attacker-sized; honest addrs were dropped at the door"
    );
    let honest_present = connectable.iter().any(|p| p.addr.starts_with("1.1."));
    assert!(
        !honest_present,
        "ECLIPSE BIAS CONFIRMED: no honest (diverse-subnet) peer is connectable \
         once a single-subnet attacker fills the known set — no diversity reservation"
    );
}

proptest! {
    /// For any attacker fill that reaches capacity first, the fraction of the
    /// connectable set that belongs to the attacker subnet is 1.0 — there is no
    /// per-subnet cap that would bound it below 1.0.
    #[test]
    fn no_subnet_cap_bounds_attacker_share(
        cap in 8usize..128,
        honest in 1usize..200,
    ) {
        let mut pex = PexManager::new(cap);
        // Attacker fills first, all from one publicly-routable /24.
        for i in 0..cap {
            pex.add_peer(format!("8.9.0.{}:8333", i % 256));
        }
        // Honest addrs from many distinct subnets arrive after.
        for i in 0..honest {
            pex.add_peer(format!("1.{}.{}.{}:8333", (i / 256) % 256, (i / 256) % 256, i % 256));
        }
        let connectable = pex.connectable_peers();
        let attacker = connectable
            .iter()
            .filter(|p| p.addr.starts_with("8.9.0."))
            .count();
        // The whole connectable set is attacker-owned: no diversity reservation.
        prop_assert_eq!(attacker, connectable.len());
    }
}
