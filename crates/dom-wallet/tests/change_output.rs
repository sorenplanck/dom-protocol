//! Self-spend change correctness.
//!
//! Proves the wallet's change path end-to-end:
//!
//! 1. `build_spend` over UTXOs that EXCEED `amount + fee` returns a
//!    BALANCED transaction (greedy selection's surplus is returned as a
//!    change output, so `SpendBuilder::build` does not reject it as
//!    `inputs > outputs + fee`).
//! 2. On confirmation (`apply_canonical_block_with_hash` — the real
//!    chain path used by the node and the spend_e2e integration test),
//!    the change is registered as a spendable `OwnedOutput`.
//! 3. The change is GENUINELY spendable: a second `build_spend` that can
//!    only be funded by the change succeeds.
//!
//! Getting (3) wrong = permanently lost funds, so it is the central
//! assertion here.

use dom_crypto::pedersen::Commitment;
use dom_crypto::BlindingFactor;
use dom_wallet::{Network, OwnedOutput, WalletDir};
use tempfile::TempDir;

fn test_genesis() -> dom_core::Hash256 {
    dom_core::Hash256::from_bytes([0x42u8; 32])
}

fn make_output(value: u64, height: u64, is_coinbase: bool) -> OwnedOutput {
    let bf = BlindingFactor::random();
    let commitment = Commitment::commit(value, &bf);
    OwnedOutput::new(
        *commitment.as_bytes(),
        value,
        *bf.as_bytes(),
        height,
        is_coinbase,
    )
}

fn fresh_recipient(amount: u64) -> (Commitment, BlindingFactor) {
    let blinding = BlindingFactor::random();
    let commitment = Commitment::commit(amount, &blinding);
    (commitment, blinding)
}

/// End-to-end: build (with change) → confirm → change is spendable.
#[test]
fn change_is_registered_and_spendable_after_confirmation() {
    let temp = TempDir::new().unwrap();
    let dir = temp.path().join("w");
    let mut wd = WalletDir::create(&dir, "pw", Network::Mainnet, &test_genesis()).unwrap();

    // (a) A single UTXO whose value EXCEEDS amount + fee, forcing change.
    //     1000 selected for a 500 + 100 spend → 400 change.
    wd.wallet_mut().add_output(make_output(1000, 100, false));

    // (b) build_spend must return a BALANCED tx (build() Ok, not Err).
    let amount = 500u64;
    let fee = 100u64;
    let change_value = 1000 - amount - fee; // 400
    let (recipient_commitment, recipient_blinding) = fresh_recipient(amount);
    let tx = wd
        .wallet_mut()
        .build_spend(recipient_commitment, recipient_blinding, amount, fee, 1000)
        .expect("build_spend must balance via change output");

    // The tx carries two outputs: recipient + change.
    assert_eq!(
        tx.outputs.len(),
        2,
        "spend with surplus must emit a change output"
    );

    // Before confirmation the change is NOT yet spendable (mirrors the
    // chain: change only exists once the tx is canonical).
    assert!(
        wd.wallet().outputs().all(|o| o.value != change_value),
        "change must not be registered before confirmation"
    );

    // (c) Confirm via the real canonical-block path. The spend tx's input
    //     (the 1000 UTXO) is consumed by the block.
    wd.wallet_mut()
        .apply_canonical_block(std::slice::from_ref(&tx), 1001)
        .expect("apply_canonical_block");

    // (d) The change now appears as a spendable OwnedOutput.
    let change = wd
        .wallet()
        .outputs()
        .find(|o| o.value == change_value)
        .expect("change output must be registered after confirmation");
    assert_eq!(change.value, change_value);
    assert!(!change.spent, "change must be unspent");
    assert!(
        change.reserved_for_tx.is_none(),
        "change must not be reserved"
    );
    assert!(!change.is_coinbase, "change is not coinbase (no maturity)");
    assert_eq!(
        change.block_height, 1001,
        "change is attributed to the confirmation height"
    );
    // Copy the commitment out before re-borrowing the wallet mutably below.
    let change_commitment = change.commitment;

    // The original input is now spent.
    let original = wd
        .wallet()
        .outputs()
        .find(|o| o.value == 1000)
        .expect("original output still tracked");
    assert!(original.spent, "spent input must be marked spent");

    // (e) THE PROOF: a second spend that can ONLY be funded by the change.
    //     The 1000 input is spent; only the 400 change remains spendable.
    //     A 300 + 50 spend (350 ≤ 400) must succeed by selecting it.
    let amount2 = 300u64;
    let fee2 = 50u64;
    let (recipient2_commitment, recipient2_blinding) = fresh_recipient(amount2);
    let tx2 = wd
        .wallet_mut()
        .build_spend(
            recipient2_commitment,
            recipient2_blinding,
            amount2,
            fee2,
            1002,
        )
        .expect("second spend MUST be fundable by the change — else funds are lost");

    // The second spend's sole input must be the change commitment.
    assert_eq!(
        tx2.inputs.len(),
        1,
        "second spend selects exactly the change"
    );
    assert_eq!(
        *tx2.inputs[0].commitment.as_bytes(),
        change_commitment,
        "second spend must consume the change output"
    );
}

/// An EXACT spend (no surplus) must NOT emit a change output and must
/// register no PendingChange — guarding the `change_value == 0` branch.
#[test]
fn exact_spend_emits_no_change() {
    let temp = TempDir::new().unwrap();
    let dir = temp.path().join("w");
    let mut wd = WalletDir::create(&dir, "pw", Network::Mainnet, &test_genesis()).unwrap();

    // 900 selected for an exact 800 + 100 spend → 0 change.
    wd.wallet_mut().add_output(make_output(900, 100, false));
    let (recipient_commitment, recipient_blinding) = fresh_recipient(800);
    let tx = wd
        .wallet_mut()
        .build_spend(recipient_commitment, recipient_blinding, 800, 100, 1000)
        .expect("exact spend builds");

    assert_eq!(
        tx.outputs.len(),
        1,
        "exact spend must emit only the recipient output"
    );

    // Confirm; no new spendable output should appear beyond the spent input.
    wd.wallet_mut()
        .apply_canonical_block(std::slice::from_ref(&tx), 1001)
        .expect("apply_canonical_block");

    // The only tracked output is the original, now spent. No change.
    let spendable: Vec<_> = wd.wallet().outputs().filter(|o| !o.spent).collect();
    assert!(
        spendable.is_empty(),
        "exact spend must leave no spendable change behind"
    );
}
