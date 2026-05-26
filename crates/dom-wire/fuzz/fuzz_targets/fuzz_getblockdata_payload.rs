#![no_main]
//! Fuzz target: dom_wire::message::GetBlockDataPayload::from_bytes
//!
//! Body fetch attack surface: arbitrary peer-supplied block hash requests.
use dom_wire::message::GetBlockDataPayload;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = GetBlockDataPayload::from_bytes(data);
});
