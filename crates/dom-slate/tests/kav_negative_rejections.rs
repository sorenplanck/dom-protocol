//! KAV-negativo — known-answer NEGATIVE vectors: inputs that the slate API
//! MUST reject. One assertion per rejection door declared in the source.

mod common;

use dom_core::constants::MAX_SUPPLY_NOMS;
use dom_slate::{finalize, respond_receive, SlateError};

// ── respond_receive doors ────────────────────────────────────────────────────

#[test]
fn respond_receive_rejects_wrong_chain_id() {
    let sender = common::build_balanced_send(1_000, 10, 0);
    let wrong_chain = [0xFFu8; 32];
    let Err(err) = respond_receive(sender.slate, &wrong_chain) else {
        panic!("must reject cross-chain slate");
    };
    assert!(
        matches!(err, SlateError::ChainIdMismatch),
        "expected ChainIdMismatch, got {err:?}"
    );
}

#[test]
fn respond_receive_rejects_slate_with_recipient_output_present() {
    let sender = common::build_balanced_send(1_000, 10, 0);
    // First, a legitimate response to obtain a fully-answered slate.
    let answered = respond_receive(sender.slate, &common::TEST_CHAIN_ID).expect("first respond ok");
    // Replaying respond_receive on the already-answered slate must be rejected.
    let Err(err) = respond_receive(answered.slate, &common::TEST_CHAIN_ID) else {
        panic!("must reject double-receive");
    };
    assert!(
        matches!(err, SlateError::RecipientFieldsPresent),
        "expected RecipientFieldsPresent, got {err:?}"
    );
}

#[test]
fn respond_receive_rejects_recipient_public_excess_present_only() {
    // Tamper a single recipient field to exercise the OR-chain guard.
    let sender = common::build_balanced_send(1_000, 10, 0);
    let mut slate = sender.slate;
    slate.recipient_public_excess = Some(slate.sender_public_excess.clone());
    let Err(err) = respond_receive(slate, &common::TEST_CHAIN_ID) else {
        panic!("must reject partial recipient fields");
    };
    assert!(
        matches!(err, SlateError::RecipientFieldsPresent),
        "expected RecipientFieldsPresent, got {err:?}"
    );
}

#[test]
fn respond_receive_rejects_amount_over_max_supply() {
    let sender = common::build_balanced_send(1_000, 10, 0);
    let mut slate = sender.slate;
    slate.amount = MAX_SUPPLY_NOMS + 1;
    let Err(err) = respond_receive(slate, &common::TEST_CHAIN_ID) else {
        panic!("must reject amount > MAX");
    };
    assert!(
        matches!(err, SlateError::Crypto(ref m) if m.contains("amount")),
        "expected Crypto(amount...), got {err:?}"
    );
}

#[test]
fn respond_receive_rejects_fee_over_max_supply() {
    let sender = common::build_balanced_send(1_000, 10, 0);
    let mut slate = sender.slate;
    slate.fee = MAX_SUPPLY_NOMS + 1;
    let Err(err) = respond_receive(slate, &common::TEST_CHAIN_ID) else {
        panic!("must reject fee > MAX");
    };
    assert!(
        matches!(err, SlateError::Crypto(ref m) if m.contains("fee")),
        "expected Crypto(fee...), got {err:?}"
    );
}

// ── finalize doors ───────────────────────────────────────────────────────────

#[test]
fn finalize_rejects_wrong_chain_id() {
    let sender = common::build_balanced_send(1_000, 10, 0);
    let answered =
        respond_receive(sender.slate.clone(), &common::TEST_CHAIN_ID).expect("respond ok");
    let err = finalize(
        &answered.slate,
        &sender.excess_blinding,
        &sender.nonce,
        &[0xFEu8; 32],
    )
    .expect_err("must reject cross-chain finalize");
    assert!(
        matches!(err, SlateError::ChainIdMismatch),
        "expected ChainIdMismatch, got {err:?}"
    );
}

#[test]
fn finalize_rejects_missing_recipient_output() {
    // Sender-only slate (never answered) must fail at the missing-field guard.
    let sender = common::build_balanced_send(1_000, 10, 0);
    let err = finalize(
        &sender.slate,
        &sender.excess_blinding,
        &sender.nonce,
        &common::TEST_CHAIN_ID,
    )
    .expect_err("must reject finalize of unanswered slate");
    assert!(
        matches!(err, SlateError::MissingRecipientField(_)),
        "expected MissingRecipientField, got {err:?}"
    );
}
