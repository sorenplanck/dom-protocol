#![no_main]
//! Fuzz target: dom_consensus::BlockHeader::from_bytes
//!
//! Invariant: deserialization of arbitrary bytes must NEVER panic.

use libfuzzer_sys::fuzz_target;
use dom_serialization::DomDeserialize;
use dom_consensus::BlockHeader;

fuzz_target!(|data: &[u8]| {
    let _ = BlockHeader::from_bytes(data);
});
