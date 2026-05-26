#![no_main]
//! Fuzz target: dom_wire::message::GetHeadersPayload::from_bytes
//!
//! Request-side IBD attack surface: arbitrary peer-supplied locators.
use dom_wire::message::GetHeadersPayload;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = GetHeadersPayload::from_bytes(data);
});
