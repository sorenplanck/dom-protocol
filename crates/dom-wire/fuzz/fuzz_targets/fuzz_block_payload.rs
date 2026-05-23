#![no_main]
//! Fuzz target: dom_wire::message::BlockPayload::from_bytes
//!
//! Block relay attack surface — every relayed block flows through here.
use libfuzzer_sys::fuzz_target;
use dom_wire::message::BlockPayload;

fuzz_target!(|data: &[u8]| {
    let _ = BlockPayload::from_bytes(data);
});
