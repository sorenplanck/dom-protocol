#![no_main]
//! Fuzz target: end-to-end block deserialize + validate_block.
//!
//! Strategy:
//!   1. Parse arbitrary bytes as Block (always exercises deserialization).
//!   2. If parsing succeeds, run validate_block with a deterministic context.
//!
//! Invariants:
//!   - Neither step may panic on arbitrary input.
//!   - validate_block must terminate (no infinite loops on crafted data).
//!   - Always returns Result, never aborts the process.
use libfuzzer_sys::fuzz_target;
use dom_serialization::DomDeserialize;
use dom_consensus::{validate_block, Block, ValidationContext};
use dom_core::{BlockHeight, Timestamp};

fuzz_target!(|data: &[u8]| {
    let block = match Block::from_bytes(data) {
        Ok(b) => b,
        Err(_) => return,
    };
    let ctx = ValidationContext {
        current_height: BlockHeight(1_000_000),
        chain_id: [0u8; 32],
        now: Timestamp(2_000_000_000),
    };
    let _ = validate_block(&block, &ctx);
});
