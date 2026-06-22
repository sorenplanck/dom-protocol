#![no_main]
//! Fuzz target: PersistedPeerRotationState::from_bytes (persisted peer rotation).
//! Surface: u64 + count-loop over trackers (addr-utf8, u8, u64, u8). Invariant:
//! arbitrary bytes must NEVER panic.
use libfuzzer_sys::fuzz_target;
use dom_serialization::DomDeserialize;
fuzz_target!(|data: &[u8]| {
    let _ = dom_wire::manager::PersistedPeerRotationState::from_bytes(data);
});
