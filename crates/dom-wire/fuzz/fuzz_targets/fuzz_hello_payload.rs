#![no_main]
//! Fuzz target: dom_wire::message::HelloPayload::from_bytes
//!
//! First payload received from any new peer — pre-trust attack surface.
use libfuzzer_sys::fuzz_target;
use dom_wire::message::HelloPayload;

fuzz_target!(|data: &[u8]| {
    let _ = HelloPayload::from_bytes(data);
});
