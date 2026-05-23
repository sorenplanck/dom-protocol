#![no_main]
//! Fuzz target: dom_wire::message::HeadersPayload::from_bytes
//!
//! IBD attack surface: arbitrary peer-supplied headers list.
use libfuzzer_sys::fuzz_target;
use dom_wire::message::HeadersPayload;

fuzz_target!(|data: &[u8]| {
    let _ = HeadersPayload::from_bytes(data);
});
