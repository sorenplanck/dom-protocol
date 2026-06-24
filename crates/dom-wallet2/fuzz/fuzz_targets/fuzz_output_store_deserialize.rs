#![no_main]
//! Fuzz target: serde_json deserialize of the OutputStore.
//!
//! `OutputStore`'s `Deserialize` routes every record through `from_outputs ->
//! insert`, re-checking the duplicate-commitment primary-key invariant on load.
//! That custom path (Vec<StoredOutput> then invariant check) must never panic on
//! arbitrary bytes — including a payload with duplicate commitments, which must
//! surface as a serde error, not a crash. This is also the backup payload's
//! `outputs` parse surface.
use dom_wallet2::OutputStore;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = serde_json::from_slice::<OutputStore>(data);
});
