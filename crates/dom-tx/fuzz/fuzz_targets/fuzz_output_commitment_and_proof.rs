#![no_main]
//! Fuzz target: `dom_tx::slate::OutputCommitmentAndProof::from_bytes`.
//!
//! The crypto-carrying sub-parser of a slate: a 33-byte Pedersen commitment
//! followed by a length-prefixed range proof (`RangeProof::from_bytes`). It is
//! reached inside `Slate` for the sender change output and the recipient
//! output; fuzzed directly here so libFuzzer can hammer the commitment-point
//! decode + proof-length framing without first satisfying the whole slate
//! envelope.
//!
//! Invariant: arbitrary bytes must never panic — only `Ok` or `Err`.

use dom_serialization::DomDeserialize;
use dom_tx::slate::OutputCommitmentAndProof;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = OutputCommitmentAndProof::from_bytes(data);
});
