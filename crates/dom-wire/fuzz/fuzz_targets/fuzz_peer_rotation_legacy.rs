#![no_main]
//! Fuzz target: PersistedPeerRotationState::from_legacy_bytes (LEGACY format).
//! Distinct layout (no cooldown field) + strict finish() trailing-byte check.
//! The most divergent of the peer-state parsers. Invariant: never panic.
use libfuzzer_sys::fuzz_target;
fuzz_target!(|data: &[u8]| {
    let _ = dom_wire::manager::PersistedPeerRotationState::from_legacy_bytes(data);
});
