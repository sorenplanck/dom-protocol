//! dom-shield Onda 2 — FIX-023 reproducer for `dom_wallet::wallet`.
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
//! reconcile), and asserts the in-memory wallet state was rewritten by the
//! forged plaintext:
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
//! Both asserts encode the OBSERVED (insecure) reconcile behaviour so the file
//! compiles green; the security expectation each violates is documented inline.
//! These are CONFIRMATIONS of FIX-023.

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

/// (a) Forged `Confirmed` rewrites real spend-state with no authentication.
#[test]
fn fix023_forged_confirmed_marks_inputs_spent_on_reopen() {
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

    // ATTACKER: append a forged `Confirmed` for this pending tx. No key, no
    // node, no proof — just a line in the plaintext journal.
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

    // Reopen → WalletDir::open runs reconcile_with_journal.
    let reopened = WalletDir::open(&dir, "pw").expect("reopen runs reconcile");

    // The pending tx was a real one, so reconcile consumes it: input is now
    // marked SPENT and the reservation cleared — purely from the forged line.
    let after = reopened
        .wallet()
        .outputs()
        .find(|o| o.commitment == input_commitment)
        .map(|o| (o.spent, o.reserved_for_tx));

    // CONFIRMS FIX-023(a): unauthenticated journal drives spend-state.
    // SAFETY EXPECTATION (violated): a forged confirmation must NOT be able to
    // mark wallet inputs spent.
    assert_eq!(
        after,
        Some((true, None)),
        "FIX-023: forged Confirmed marked input spent + released reservation via reconcile"
    );
    assert!(
        !reopened.wallet().has_pending_tx(&tx_hash),
        "FIX-023: forged Confirmed evicted the pending tx with no authentication"
    );
}

/// (b) Forged `Built` for a never-built tx that references a CLEAN owned output
/// makes reconcile inject a phantom pending tx and HIJACK the reservation of
/// that output — a forged spend-freeze authored entirely from the plaintext
/// journal. (The encrypted pending_txs never contained this tx; the
/// Building/Submitted heal branch creates it from the journal alone.)
#[test]
fn fix023_forged_built_injects_phantom_pending_and_hijacks_reservation() {
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
    // wallet's clean output as a reserved input. Status stays `Building`.
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

    // reconcile's Building/Submitted heal branch reinstates the phantom pending
    // tx and reserves the named input — all from the unauthenticated journal.
    let after = reopened
        .wallet()
        .outputs()
        .find(|o| o.commitment == owned_commitment)
        .map(|o| (o.spent, o.reserved_for_tx))
        .unwrap();

    // CONFIRMS FIX-023(b): forged Built injects a phantom pending tx and
    // hijacks the reservation of a clean owned output. SAFETY EXPECTATION
    // (violated): an unauthenticated file must not be able to reserve/freeze
    // wallet funds for a tx the wallet never built.
    assert!(
        reopened.wallet().has_pending_tx(&fake_tx_hash),
        "FIX-023: forged Built created a phantom pending tx via reconcile"
    );
    assert_eq!(
        after,
        (false, Some(fake_tx_hash)),
        "FIX-023: forged Built hijacked the reservation of a clean owned output (spend-freeze)"
    );
}
