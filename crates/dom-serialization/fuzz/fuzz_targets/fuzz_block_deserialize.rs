#![no_main]
//! Fuzz target: dom_consensus::Block::from_bytes
//!
//! Invariant: deserialization of arbitrary bytes must NEVER panic.
//! Either returns Ok(Block) or Err(DomError) — both are acceptable.

use libfuzzer_sys::fuzz_target;
use dom_serialization::DomDeserialize;
use dom_consensus::Block;

fuzz_target!(|data: &[u8]| {
    let _ = Block::from_bytes(data);
});
