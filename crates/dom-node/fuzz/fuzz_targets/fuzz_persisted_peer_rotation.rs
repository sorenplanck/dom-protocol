#![no_main]
//! Fuzz target: dom_wire::manager::PersistedPeerRotationState::from_bytes — the
//! corrupt peer-rotation snapshot the node loads (node.rs
//! load_peer_rotation_snapshot -> from_bytes -> restore_outbound_failure_state).
//! Tampered on-disk bytes must never panic the parser.
use dom_serialization::DomDeserialize;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = dom_wire::manager::PersistedPeerRotationState::from_bytes(data);
});
