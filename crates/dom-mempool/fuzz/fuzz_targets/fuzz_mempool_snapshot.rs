#![no_main]
//! Fuzz target: PersistedMempoolState::from_bytes (persisted mempool snapshot).
//! Surface: count-prefixed loop over N entries, each {tx_hash, received_at,
//! Transaction}. Exercises multi-entry framing + interleave that the single-tx
//! Transaction target never reaches. Invariant: deserializing arbitrary bytes
//! must NEVER panic (graceful Err on malformed/truncated/corrupt snapshot).
use libfuzzer_sys::fuzz_target;
use dom_serialization::DomDeserialize;
fuzz_target!(|data: &[u8]| {
    let _ = dom_mempool::PersistedMempoolState::from_bytes(data);
});
