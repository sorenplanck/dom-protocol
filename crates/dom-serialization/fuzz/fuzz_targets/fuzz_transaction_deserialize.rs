#![no_main]
//! Fuzz target: dom_consensus::Transaction::from_bytes
//!
//! Invariant: deserialization of arbitrary bytes must NEVER panic.

use libfuzzer_sys::fuzz_target;
use dom_serialization::DomDeserialize;
use dom_consensus::Transaction;

fuzz_target!(|data: &[u8]| {
    let _ = Transaction::from_bytes(data);
});
