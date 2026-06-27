#![no_main]
//! Fuzz target: `dom_slate::finalize` on adversarial counterparty bytes.
//!
//! At finalize, the sender holds its own secrets but the recipient-answered
//! Slate is fully attacker-controlled. We decode arbitrary bytes into a `Slate`
//! and drive `finalize` with attacker-influenced (but well-typed) sender
//! secrets carved from the same buffer. `finalize` runs key parsing, public-key
//! aggregation, Schnorr partial signing + aggregation, transaction assembly,
//! structure + balance validation, and signature verification — every step
//! must tolerate hostile input without panicking.
//!
//! Invariant: decode-then-finalize on ARBITRARY bytes must NEVER panic, abort,
//! or fault. Only `Ok(_)` or `Err(_)` are acceptable.

use dom_serialization::DomDeserialize;
use dom_slate::finalize;
use dom_tx::slate::Slate;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Layout: [chain_id:32][sender_excess:32][sender_nonce:32][slate bytes...].
    // Missing leading bytes default to zero so short inputs still exercise the
    // early guards.
    let mut chain_id = [0u8; 32];
    let mut sender_excess = [0u8; 32];
    let mut sender_nonce = [0u8; 32];

    let mut rest = data;
    let take = |rest: &mut &[u8], dst: &mut [u8; 32]| {
        let n = rest.len().min(32);
        dst[..n].copy_from_slice(&rest[..n]);
        *rest = &rest[n..];
    };
    take(&mut rest, &mut chain_id);
    take(&mut rest, &mut sender_excess);
    take(&mut rest, &mut sender_nonce);

    if let Ok(slate) = Slate::from_bytes(rest) {
        let _ = finalize(&slate, &sender_excess, &sender_nonce, &chain_id);
    }
});
