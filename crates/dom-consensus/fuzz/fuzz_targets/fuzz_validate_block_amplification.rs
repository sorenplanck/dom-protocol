#![no_main]
//! dom-shield fuzz-amplificação: resource-bounded `validate_block`.
//!
//! Vector: a peer sends a block whose body is maximally large (many txs, many
//! outputs/kernels, large range proofs) to force the validator into super-linear
//! work or unbounded allocation (DoS amplification). The deserializer already caps
//! list lengths (MAX_BLOCK_TXS, MAX_*_PER_TX, MAX_PROOF_SIZE), so this target
//! drives arbitrary bytes through Block::from_bytes + validate_block and asserts:
//!   - no panic / abort on any input (libfuzzer catches these),
//!   - validate_block TERMINATES (no infinite loop) within the run,
//!   - a bounded wall-clock per call: anything pathologically slow is a finding
//!     (amplification). We measure and abort with a clear message if a single
//!     validate_block call exceeds the budget — turning a slowdown into a crash
//!     the fuzzer records.
//!
//! The budget is generous (5s) so only genuine pathology trips it; ordinary
//! crypto-heavy valid blocks finish far under it.
use dom_consensus::{validate_block, Block, ValidationContext};
use dom_core::{BlockHeight, Timestamp};
use dom_serialization::DomDeserialize;
use libfuzzer_sys::fuzz_target;
use std::time::{Duration, Instant};

const PER_CALL_BUDGET: Duration = Duration::from_secs(5);

fuzz_target!(|data: &[u8]| {
    // Deserialize is itself capped (length-prefix gates before allocation), so a
    // parse success already implies a bounded body. Still time the validate call.
    let block = match Block::from_bytes(data) {
        Ok(b) => b,
        Err(_) => return,
    };
    let ctx = ValidationContext {
        current_height: BlockHeight(1_000_000),
        chain_id: [0u8; 32],
        now: Timestamp(2_000_000_000),
    };

    let start = Instant::now();
    let _ = validate_block(&block, &ctx);
    let elapsed = start.elapsed();

    // Amplification assert: a single bounded-size block must validate quickly.
    // A blow-up past the budget is a DoS finding — surface it as an abort so the
    // fuzzer captures the reproducer.
    assert!(
        elapsed <= PER_CALL_BUDGET,
        "validate_block exceeded {PER_CALL_BUDGET:?} on a {}-byte block ({} txs) — DoS amplification",
        data.len(),
        block.transactions.len()
    );
});
