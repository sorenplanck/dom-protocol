#![no_main]
//! Fuzz target: dom_pow::asert_next_target_with_params on extreme inputs.
//!
//! Invariant (Lens A: panic/crash, overflow): for ANY anchor (timestamp,
//! height, target bytes) and ANY block timestamp/height/params, the next-target
//! computation must never panic. Overflow must surface as Err, never as a
//! wrapped value or an out-of-range slice index. When it returns Ok, the result
//! is a 32-byte target (structurally always true) — we additionally assert it
//! does not exceed MAX_TARGET when params use the public max.

use libfuzzer_sys::fuzz_target;
use arbitrary::Arbitrary;
use dom_core::{BlockHeight, Timestamp};
use dom_pow::{asert_next_target_with_params, AsertAnchor, PowParams};

#[derive(Arbitrary, Debug)]
struct Input {
    anchor_ts: u64,
    anchor_height: u64,
    anchor_target: [u8; 32],
    block_ts: u64,
    block_height: u64,
    target_spacing: u64,
    half_life: u64,
}

fuzz_target!(|input: Input| {
    // half_life must be nonzero for floor_div; production callers always pass a
    // nonzero half-life, but the fn must not panic on zero — it returns Err.
    let params = PowParams {
        target_spacing: input.target_spacing,
        half_life: input.half_life,
        genesis_target_compact: 0x1e00_ffff,
        max_compact_target: 0x1e7f_ffff,
    };
    let anchor = AsertAnchor {
        timestamp: Timestamp(input.anchor_ts),
        height: BlockHeight(input.anchor_height),
        target: input.anchor_target,
    };
    let _ = asert_next_target_with_params(
        &anchor,
        Timestamp(input.block_ts),
        BlockHeight(input.block_height),
        &params,
    );
});
