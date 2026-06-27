//! dom-shield — pre-auth ban-score port-rotation evasion KAV (node_handle/scoring sub-area).
//!
//! The node scores protocol violations via `record_peer_violation` /
//! `record_pending_peer_violation`, which key the ban score by
//! `peer_addr.to_string()` — the FULL SocketAddr, i.e. `IP:PORT`. `PeerManager`'s
//! `add_ban_score`/`add_pending_ban_score`/`ban_score` all take that string key.
//!
//! Eclipse acceptance limits ARE keyed by /16 subnet (`to_slash16`), but ban
//! SCORING is keyed by the full address. An attacker reconnecting from the same
//! IP but a NEW source port presents a different key, so accumulated ban score
//! does not follow them — port rotation resets the score. (The accept-side /16
//! limit still caps concurrent sockets per subnet, so this is a scoring-evasion
//! KAV, not a full bypass.)
//!
//! `record_*_peer_violation` and `peer_violation_score` are private to dom-node
//! (covered by in-src tests). This KAV pins the PUBLIC `PeerManager` keying
//! behaviour the node depends on, which IS the evadable surface.
//!
//! Technique: KAV on PeerManager pre-auth scoring — same IP, rotating port ⇒
//! independent score buckets, none crossing the ban threshold.

use dom_wire::peer::ban_scores;

/// Pre-registration penalties are keyed by source IP, so rotating the port no
/// longer resets the accumulated score.
#[test]
fn pending_ban_score_accumulates_across_port_rotation() {
    let mut mgr = dom_wire::manager::PeerManager::new(128, 8);

    // The per-violation pre-auth score (e.g. protocol violation).
    let score = ban_scores::PROTOCOL_VIOLATION;
    // How many violations on ONE key would be needed to ban.
    let needed = ban_scores::BAN_THRESHOLD.div_ceil(score.max(1));

    let mut rotated_last = 0u32;
    for i in 0..needed {
        let key = format!("1.2.3.4:{}", 5000 + i);
        rotated_last = mgr.add_pending_ban_score(&key, score);
    }
    assert!(
        rotated_last >= ban_scores::BAN_THRESHOLD,
        "rotating ports must still accumulate to the ban threshold on one IP (acc={rotated_last})"
    );

    // Stable-address path remains unchanged.
    let mut mgr2 = dom_wire::manager::PeerManager::new(128, 8);
    let stable = "9.9.9.9:6000";
    let mut last = 0u32;
    for _ in 0..needed {
        last = mgr2.add_pending_ban_score(stable, score);
    }
    assert!(
        last >= ban_scores::BAN_THRESHOLD,
        "a non-rotating peer accumulates to the ban threshold on a single key (acc={last})"
    );
}
