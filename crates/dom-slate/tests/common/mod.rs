//! Shared helpers for the dom-slate test families.
//!
//! These build a *real, balancing* interactive slate round-trip so the
//! behavioural tests (and the FIX-022 / FIX-008 reproducers) operate on the
//! same crypto the wallet drives in production, not on synthetic stand-ins.

#![allow(dead_code)]

use dom_crypto::pedersen::Commitment;
use dom_crypto::BlindingFactor;
use dom_slate::{build_send, finalize, respond_receive, SenderSlate, SlateInput};

/// A fixed but arbitrary chain id for the test network.
pub const TEST_CHAIN_ID: [u8; 32] = [7u8; 32];

/// Build a single sender input whose value and blinding the caller controls,
/// so the resulting transaction actually balances.
///
/// Returns the `SlateInput` (commitment + blinding bytes) the sender feeds to
/// `build_send`.
pub fn make_input(value: u64, blinding_byte: u8) -> SlateInput {
    let blinding = BlindingFactor::from_bytes([blinding_byte; 32]).expect("valid blinding");
    let commitment = Commitment::commit(value, &blinding);
    SlateInput {
        commitment: *commitment.as_bytes(),
        blinding: *blinding.as_bytes(),
    }
}

/// Drive a complete, balancing sender build for `amount`/`fee`/`change`.
///
/// Single input with value `amount + fee + change`. Returns the `SenderSlate`
/// (public slate + sender secrets) ready to hand to `respond_receive`.
pub fn build_balanced_send(amount: u64, fee: u64, change: u64) -> SenderSlate {
    let input_value = amount
        .checked_add(fee)
        .and_then(|v| v.checked_add(change))
        .expect("input value overflow");
    let input = make_input(input_value, 0x11);
    build_send(&[input], change, amount, fee, TEST_CHAIN_ID).expect("build_send")
}

/// Run a full, valid round-trip: build_send -> respond_receive -> finalize.
///
/// Returns the finalized `Transaction` on success; panics if any stage errors,
/// so callers can assert the happy path is genuinely reachable before tampering
/// with it.
pub fn full_roundtrip(
    amount: u64,
    fee: u64,
    change: u64,
) -> dom_consensus::transaction::Transaction {
    let sender = build_balanced_send(amount, fee, change);
    let response = respond_receive(sender.slate.clone(), &TEST_CHAIN_ID).expect("respond_receive");
    finalize(
        &response.slate,
        &sender.excess_blinding,
        &sender.nonce,
        &TEST_CHAIN_ID,
    )
    .expect("finalize")
}
