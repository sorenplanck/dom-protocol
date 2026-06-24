#![no_main]
//! Fuzz target: `dom_slate::respond_receive` on adversarial counterparty bytes.
//!
//! In the interactive protocol, the recipient receives a fully attacker-chosen
//! Slatepack and must respond. We decode arbitrary bytes into a `Slate` (the
//! peer-controlled wire format) and, if decoding succeeds, drive
//! `respond_receive` — which runs Pedersen/PublicKey decoding, Bulletproof
//! proving, and Schnorr partial signing over peer-influenced inputs.
//!
//! Invariant: decode-then-respond on ARBITRARY bytes must NEVER panic, abort,
//! or fault. Only `Ok(_)` or `Err(_)` are acceptable. A crash is a
//! remotely-reachable DoS on any wallet that receives a slate.

use dom_serialization::DomDeserialize;
use dom_slate::respond_receive;
use dom_tx::slate::Slate;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // First 32 bytes (if present) seed the expected chain id; the rest is the
    // slate payload. This lets the fuzzer reach BOTH the chain-id-match and the
    // chain-id-mismatch branches.
    let (chain_id, payload): (&[u8], &[u8]) = if data.len() >= 32 {
        (&data[..32], &data[32..])
    } else {
        (&[][..], data)
    };
    let mut expected = [0u8; 32];
    expected[..chain_id.len().min(32)].copy_from_slice(&chain_id[..chain_id.len().min(32)]);

    if let Ok(slate) = Slate::from_bytes(payload) {
        let _ = respond_receive(slate, &expected);
    }
});
