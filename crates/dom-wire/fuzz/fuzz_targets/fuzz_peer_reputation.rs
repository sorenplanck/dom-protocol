#![no_main]
//! Fuzz target: PersistedPeerReputationState::from_bytes (persisted reputation).
//! Surface: count-loop over (addr-utf8, u32 score). Invariant: never panic.
use libfuzzer_sys::fuzz_target;
use dom_serialization::DomDeserialize;
fuzz_target!(|data: &[u8]| {
    let _ = dom_wire::manager::PersistedPeerReputationState::from_bytes(data);
});
