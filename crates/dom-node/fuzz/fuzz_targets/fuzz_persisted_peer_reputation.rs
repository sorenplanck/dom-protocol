#![no_main]
//! Fuzz target: dom_wire::manager::PersistedPeerReputationState::from_bytes — the
//! corrupt peer-reputation snapshot the node loads (node.rs
//! load_peer_reputation_snapshot -> from_bytes). Tampered on-disk ban-score
//! bytes must never panic the parser.
use dom_serialization::DomDeserialize;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = dom_wire::manager::PersistedPeerReputationState::from_bytes(data);
});
