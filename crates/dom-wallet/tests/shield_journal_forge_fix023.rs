//! dom-shield Onda 2 — FIX-023 regression for `dom_wallet::wallet`.
//!
//! Subfamily: directed-corruption (Lens B funds-safety, unauthenticated WAL).
//!
//! `reconcile_with_journal` (wallet.rs) drives spend-state and output
//! registration from the replayed journal. The journal (`journal.log`) is a
//! PLAINTEXT, UNAUTHENTICATED JSON file: no MAC, no signature, not part of the
//! encrypted `wallet.dat`. Anyone with write access to the wallet directory can
//! forge journal lines.
//!
//! This file forges journal entries by hand, reopens the wallet (which runs
//! reconcile), and asserts the forged plaintext is ignored:
//!
//!   (a) FORGED `Confirmed` over a real pending tx → reconcile marks the tx's
//!       inputs `spent` and clears reservations, with no authentication of the
//!       confirmation. The wallet now believes funds are spent purely on the
//!       say-so of an unauthenticated file.
//!
//!   (b) FORGED `Built{change}` for a tx that never existed, then a forged
//!       `Confirmed` → reconcile INJECTS A PHANTOM OUTPUT (the change) into the
//!       owned set via `register_pending_change`. The attacker controls the
//!       commitment/value/blinding, so this is attacker-chosen wallet state.
//!
//! These are regressions: a passing test means forged journal lines did not
//! rewrite spend-state or inject phantom pending transactions.

use dom_core::Hash256;
use dom_crypto::pedersen::Commitment;
use dom_crypto::BlindingFactor;
use dom_wallet::wallet_dir::WalletDir;
use dom_wallet::{Network, OwnedOutput, TxJournal};
use std::io::Write;
use tempfile::TempDir;

fn genesis() -> Hash256 {
    Hash256::from_bytes([23u8; 32])
}

fn make_output(value: u64, height: u64, blinding_byte: u8) -> OwnedOutput {
    let blinding = BlindingFactor::from_bytes([blinding_byte; 32]).unwrap();
    let commitment = Commitment::commit(value, &blinding);
    OwnedOutput::new(*commitment.as_bytes(), value, *blinding.as_bytes(), height, false)
}

fn fresh_recipient(amount: u64) -> (Commitment, BlindingFactor) {
    let b = BlindingFactor::from_bytes([0x5Au8; 32]).unwrap();
    (Commitment::commit(amount, &b), b)
}

fn append_line(journal: &TxJournal, line: &serde_json::Value) {
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(journal.path())
        .unwrap();
    writeln!(f, "{line}").unwrap();
    f.sync_all().unwrap();
}

/// (a) Forged `Confirmed` must not rewrite real spend-state.
#[test]
fn fix023_forged_confirmed_is_ignored_on_reopen() {
    let temp = TempDir::new().unwrap();
    let dir = temp.path().join("w");
    let mut wd = WalletDir::create(&dir, "pw", Network::Mainnet, &genesis()).unwrap();

    // Fund and build a genuine pending spend (so a real pending_tx + reserved
    // inputs exist on disk). Use an exact spend (no change) to keep it simple.
    wd.wallet_mut().add_output(make_output(1_000, 100, 0x11));
    wd.wallet().save().unwrap();

    let (rc, rb) = fresh_recipient(900);
    let tx = wd
        .wallet_mut()
        .build_spend(rc, rb, 900, 100, 1000)
        .expect("build exact spend");
    let tx_hash = dom_wallet::Wallet::tracking_tx_hash(&tx).unwrap();
    let input_commitment = *tx.inputs[0].commitment.as_bytes();

    // Sanity: input is reserved, not spent, before the forgery.
    let reserved_before = wd
        .wallet()
        .outputs()
        .find(|o| o.commitment == input_commitment)
        .map(|o| (o.spent, o.reserved_for_tx.is_some()))
        .unwrap();
    assert_eq!(reserved_before, (false, true), "pre-forgery: reserved, not spent");

    // ATTACKER: append a forged `Confirmed` for this pending tx. With an
    // authenticated journal, reopen must ignore it.
    let journal = wd.wallet().journal().unwrap();
    append_line(
        journal,
        &serde_json::json!({
            "timestamp": 9_999u64,
            "tx_hash": hex::encode(tx_hash),
            "event": { "type": "confirmed", "block_height": 1_000_000u64 }
        }),
    );
    drop(wd);

    let reopened = WalletDir::open(&dir, "pw").expect("reopen runs reconcile");
    let after = reopened
        .wallet()
        .outputs()
        .find(|o| o.commitment == input_commitment)
        .map(|o| (o.spent, o.reserved_for_tx));

    assert_eq!(
        after,
        Some((false, Some(tx_hash))),
        "forged Confirmed must not mark inputs spent or clear reservations"
    );
    assert!(
        reopened.wallet().has_pending_tx(&tx_hash),
        "forged Confirmed must not evict the real pending tx"
    );
}

/// (b) Forged `Built` for a never-built tx must not inject a phantom pending tx
/// or hijack reservations.
#[test]
fn fix023_forged_built_is_ignored_on_reopen() {
    let temp = TempDir::new().unwrap();
    let dir = temp.path().join("w");
    let mut wd = WalletDir::create(&dir, "pw", Network::Mainnet, &genesis()).unwrap();

    // A clean, unreserved owned output. The attacker will reference it.
    let owned = make_output(1_000, 100, 0x22);
    let owned_commitment = owned.commitment;
    wd.wallet_mut().add_output(owned);
    wd.wallet().save().unwrap();

    // Sanity: clean before forgery — not spent, not reserved.
    let before = wd
        .wallet()
        .outputs()
        .find(|o| o.commitment == owned_commitment)
        .map(|o| (o.spent, o.reserved_for_tx))
        .unwrap();
    assert_eq!(before, (false, None), "pre-forgery: clean owned output");

    // ATTACKER: forge a `Built` event for a tx that was never built, naming the
    // wallet's clean output as a reserved input. Reopen must ignore it.
    let journal = wd.wallet().journal().unwrap();
    let fake_tx_hash = [0x7Fu8; 32];
    append_line(
        journal,
        &serde_json::json!({
            "timestamp": 1u64,
            "tx_hash": hex::encode(fake_tx_hash),
            "event": {
                "type": "built",
                "inputs": [hex::encode(owned_commitment)],
                "tx_hex": null,
                "output_count": 1u32,
                "fee_noms": 0u64
            }
        }),
    );
    drop(wd);

    let reopened = WalletDir::open(&dir, "pw").expect("reopen runs reconcile");
    let after = reopened
        .wallet()
        .outputs()
        .find(|o| o.commitment == owned_commitment)
        .map(|o| (o.spent, o.reserved_for_tx))
        .unwrap();

    assert!(
        !reopened.wallet().has_pending_tx(&fake_tx_hash),
        "forged Built must not create a phantom pending tx"
    );
    assert_eq!(
        after,
        (false, None),
        "forged Built must not hijack reservations on clean owned outputs"
    );
}
