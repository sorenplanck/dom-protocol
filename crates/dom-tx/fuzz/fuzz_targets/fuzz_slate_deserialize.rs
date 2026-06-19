#![no_main]
//! Fuzz target: `dom_tx::slate::Slate::from_bytes`.
//!
//! The Slate is the counterparty-controlled Slatepack payload — a DEEP parser
//! that decodes framing (u16/u64 fields, u32 list counts, `Option` presence
//! flags) AND embedded cryptography: Pedersen `Commitment` and `PublicKey`
//! point decoding, length-prefixed `RangeProof` bytes (via
//! `OutputCommitmentAndProof`), and `PartialSig` scalars. Every byte arrives
//! from an untrusted peer during interactive transaction building.
//!
//! Invariant under test: decoding ARBITRARY bytes must NEVER panic, abort, or
//! fault — the only acceptable outcomes are `Ok(Slate)` or `Err(_)`. A crash
//! here is a remotely-reachable DoS on any wallet receiving a slate.

use dom_serialization::DomDeserialize;
use dom_tx::slate::Slate;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = Slate::from_bytes(data);
});
