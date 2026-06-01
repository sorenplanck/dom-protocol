//! Tx lifecycle correctness + hash unification — adversarial coverage
//! (Phase 1.6 + 1.7).
//!
//! These tests prove three properties of the wallet built on top of
//! Phase 1.5's journal primitive:
//!
//! 1. **Lifecycle events are journalled in WAL order.** `build_spend`,
//!    `cancel_tx`, and `apply_canonical_block` each append their
//!    respective event (`Built` / `Canceled` / `Confirmed`) before
//!    mutating in-memory state.
//! 2. **Reconcile-on-open heals divergence.** Opening a `WalletDir`
//!    whose encrypted state disagrees with the journal — either a
//!    stale pending after a Confirmed/Canceled, or a lost pending
//!    after a Built that crashed before save — restores the journal-
//!    authoritative view.
//! 3. **Wallet tx hash equals the mempool hash.** The keyspace
//!    unification in Phase 1.7 means
//!    `Wallet::tracking_tx_hash(tx) == blake2b_256(tx.to_bytes())`
//!    — so a wallet pending tx and its mempool entry share one id.
//!
//! Idempotency / unknown-tx no-op tests live here too: confirming
//! the same tx twice must not error, and applying a canonical block
//! that references no wallet tx must succeed without side effects.

use dom_consensus::transaction::Transaction;
use dom_core::Hash256;
use dom_crypto::pedersen::Commitment;
use dom_crypto::BlindingFactor;
use dom_serialization::DomSerialize;
use dom_wallet::{
    JournalEntry, Network, OwnedOutput, TxJournal, TxJournalEvent, TxStatus, Wallet, WalletDir,
};
use tempfile::TempDir;

fn test_genesis() -> Hash256 {
    Hash256::from_bytes([0x42u8; 32])
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

fn build_test_spend(wallet: &mut Wallet) -> Transaction {
    let recipient_blinding = BlindingFactor::random();
    let recipient_commitment = Commitment::commit(800, &recipient_blinding);
    wallet
        .build_spend(recipient_commitment, recipient_blinding, 800, 100, 1000)
        .expect("build_spend")
}

fn replay_records(
    walletdir: &std::path::Path,
) -> std::collections::HashMap<[u8; 32], dom_wallet::TxRecord> {
    let j = TxJournal::open(walletdir).expect("open journal");
    j.replay().expect("replay")
}

// ─────────────────────────────────────────────────────────────────
// 1. build_spend writes a Built event before mutating state.
// ─────────────────────────────────────────────────────────────────

#[test]
fn build_spend_writes_built_event() {
    let temp = TempDir::new().unwrap();
    let dir = temp.path().join("w");
    let mut wd = WalletDir::create(&dir, "pw", Network::Mainnet, &test_genesis()).unwrap();
    wd.wallet_mut().add_output(make_output(900, 100, false));

    let tx = build_test_spend(wd.wallet_mut());
    let tx_hash = Wallet::tracking_tx_hash(&tx).unwrap();

    let records = replay_records(&dir);
    let rec = records.get(&tx_hash).expect("journal must contain tx");
    assert_eq!(rec.status, TxStatus::Building);
    assert_eq!(rec.fee_noms, 100);
    assert_eq!(rec.inputs.len(), 1, "Built event records one input");
}

// ─────────────────────────────────────────────────────────────────
// 2. cancel_tx writes a Canceled event before releasing reservations.
// ─────────────────────────────────────────────────────────────────

#[test]
fn cancel_tx_writes_canceled_event() {
    let temp = TempDir::new().unwrap();
    let dir = temp.path().join("w");
    let mut wd = WalletDir::create(&dir, "pw", Network::Mainnet, &test_genesis()).unwrap();
    wd.wallet_mut().add_output(make_output(900, 100, false));

    let tx = build_test_spend(wd.wallet_mut());
    let tx_hash = Wallet::tracking_tx_hash(&tx).unwrap();
    wd.wallet_mut().cancel_tx(tx_hash).unwrap();

    let records = replay_records(&dir);
    assert_eq!(records.get(&tx_hash).unwrap().status, TxStatus::Canceled);
    // Reservation released.
    let only_output = wd.wallet().outputs().next().unwrap();
    assert!(only_output.reserved_for_tx.is_none());
    assert!(!only_output.spent);
}

// ─────────────────────────────────────────────────────────────────
// 3. apply_canonical_block writes a Confirmed event.
// ─────────────────────────────────────────────────────────────────

#[test]
fn apply_canonical_block_writes_confirmed_event() {
    let temp = TempDir::new().unwrap();
    let dir = temp.path().join("w");
    let mut wd = WalletDir::create(&dir, "pw", Network::Mainnet, &test_genesis()).unwrap();
    wd.wallet_mut().add_output(make_output(900, 100, false));

    let tx = build_test_spend(wd.wallet_mut());
    let tx_hash = Wallet::tracking_tx_hash(&tx).unwrap();

    wd.wallet_mut()
        .apply_canonical_block(&[tx], 1001)
        .expect("apply_canonical_block");

    let records = replay_records(&dir);
    assert_eq!(
        records.get(&tx_hash).unwrap().status,
        TxStatus::Confirmed { block_height: 1001 }
    );
}

#[test]
fn mark_submitted_writes_submitted_event() {
    let temp = TempDir::new().unwrap();
    let dir = temp.path().join("w");
    let mut wd = WalletDir::create(&dir, "pw", Network::Mainnet, &test_genesis()).unwrap();
    wd.wallet_mut().add_output(make_output(900, 100, false));

    let tx = build_test_spend(wd.wallet_mut());
    let tx_hash = Wallet::tracking_tx_hash(&tx).unwrap();
    wd.wallet_mut().mark_submitted(tx_hash).unwrap();

    let records = replay_records(&dir);
    assert_eq!(records.get(&tx_hash).unwrap().status, TxStatus::Submitted);
}

#[test]
fn mark_failed_writes_failed_event() {
    let temp = TempDir::new().unwrap();
    let dir = temp.path().join("w");
    let mut wd = WalletDir::create(&dir, "pw", Network::Mainnet, &test_genesis()).unwrap();
    wd.wallet_mut().add_output(make_output(900, 100, false));

    let tx = build_test_spend(wd.wallet_mut());
    let tx_hash = Wallet::tracking_tx_hash(&tx).unwrap();
    wd.wallet_mut()
        .mark_failed(tx_hash, "mempool rejected")
        .unwrap();

    let records = replay_records(&dir);
    assert_eq!(
        records.get(&tx_hash).unwrap().status,
        TxStatus::Failed {
            reason: "mempool rejected".to_string()
        }
    );
}

#[test]
fn pending_tx_bytes_persist_across_reopen() {
    let temp = TempDir::new().unwrap();
    let dir = temp.path().join("w");
    let mut wd = WalletDir::create(&dir, "pw", Network::Mainnet, &test_genesis()).unwrap();
    wd.wallet_mut().add_output(make_output(900, 100, false));

    let tx = build_test_spend(wd.wallet_mut());
    let tx_hash = Wallet::tracking_tx_hash(&tx).unwrap();
    let original_bytes = tx.to_bytes().unwrap();
    drop(wd);

    let reopened = WalletDir::open(&dir, "pw").unwrap();
    let recovered = reopened
        .wallet()
        .pending_tx_bytes(&tx_hash)
        .expect("pending tx bytes must survive reopen");
    assert_eq!(recovered, original_bytes.as_slice());
}

// ─────────────────────────────────────────────────────────────────
// 4. Confirming the same tx twice is idempotent.
//
// `apply_canonical_block` is invoked once per canonical block; an
// IBD restart or a reorg-recovery replay might surface the same
// block twice. The wallet (and journal replay) must tolerate that.
// ─────────────────────────────────────────────────────────────────

#[test]
fn confirm_same_tx_twice_is_idempotent() {
    let temp = TempDir::new().unwrap();
    let dir = temp.path().join("w");
    let mut wd = WalletDir::create(&dir, "pw", Network::Mainnet, &test_genesis()).unwrap();
    wd.wallet_mut().add_output(make_output(900, 100, false));

    let tx = build_test_spend(wd.wallet_mut());
    let tx_hash = Wallet::tracking_tx_hash(&tx).unwrap();

    wd.wallet_mut()
        .apply_canonical_block(std::slice::from_ref(&tx), 1001)
        .unwrap();
    // Second call must not error even though the pending was already
    // resolved on the first.
    wd.wallet_mut().apply_canonical_block(&[tx], 1001).unwrap();

    let records = replay_records(&dir);
    // Journal replay yields the first valid terminal status; the
    // second Confirmed transition is logged-and-skipped as invalid
    // (already-terminal), so the recorded status remains Confirmed.
    assert_eq!(
        records.get(&tx_hash).unwrap().status,
        TxStatus::Confirmed { block_height: 1001 }
    );
}

// ─────────────────────────────────────────────────────────────────
// 5. Applying a canonical block with no matching wallet tx is a no-op.
// ─────────────────────────────────────────────────────────────────

#[test]
fn confirm_unknown_tx_is_a_noop() {
    let temp = TempDir::new().unwrap();
    let dir = temp.path().join("w");
    let mut wd = WalletDir::create(&dir, "pw", Network::Mainnet, &test_genesis()).unwrap();
    // Wallet has an output but no pending tx.
    wd.wallet_mut().add_output(make_output(900, 100, false));

    // Build a tx using a *second*, unrelated wallet so its inputs are
    // unknown to our wallet.
    let other_dir = temp.path().join("other");
    let mut other = WalletDir::create(&other_dir, "pw", Network::Mainnet, &test_genesis()).unwrap();
    other.wallet_mut().add_output(make_output(900, 100, false));
    let stranger_tx = build_test_spend(other.wallet_mut());

    // Apply the stranger tx to our wallet — must not error or panic.
    wd.wallet_mut()
        .apply_canonical_block(&[stranger_tx], 1001)
        .expect("unknown-tx confirmation must be a no-op");

    // No journal events for our wallet (only `other`'s journal has them).
    let our_records = replay_records(&dir);
    assert!(
        our_records.is_empty(),
        "journal must not record events for unknown txs"
    );
}

// ─────────────────────────────────────────────────────────────────
// 6. Reconcile-on-open cleans up terminal pending entries.
//
// We construct the divergence by hand: write a Confirmed event for a
// tx that the encrypted state still lists as pending. Reopen via
// WalletDir must heal that to "spent + no pending + no reservation".
// ─────────────────────────────────────────────────────────────────

#[test]
fn reconcile_on_open_cleans_up_terminal_pending() {
    let temp = TempDir::new().unwrap();
    let dir = temp.path().join("w");
    let mut wd = WalletDir::create(&dir, "pw", Network::Mainnet, &test_genesis()).unwrap();
    let output = make_output(900, 100, false);
    let input_commitment = output.commitment;
    wd.wallet_mut().add_output(output);

    let tx = build_test_spend(wd.wallet_mut());
    let tx_hash = Wallet::tracking_tx_hash(&tx).unwrap();

    // At this point the journal has a Built event and the encrypted
    // state has the pending tx. Drop without confirming.
    drop(wd);

    // Manually append a Confirmed event to the journal — simulating a
    // crash where the journal got the terminal event but the wallet
    // never saved its post-confirmation state.
    let j = TxJournal::open(&dir).unwrap();
    j.append(&JournalEntry {
        timestamp: 1234,
        tx_hash,
        event: TxJournalEvent::Confirmed { block_height: 1001 },
    })
    .unwrap();

    // Reopen — reconcile must clean up the still-pending entry.
    let reopened = WalletDir::open(&dir, "pw").unwrap();
    assert!(
        !reopened.wallet().has_pending_tx(&tx_hash),
        "terminal tx must be cleared from pending_txs on reopen"
    );
    let input = reopened
        .wallet()
        .outputs()
        .find(|o| o.commitment == input_commitment)
        .unwrap();
    assert!(
        input.spent,
        "Confirmed reconciliation must mark inputs spent"
    );
    assert!(input.reserved_for_tx.is_none(), "reservation cleared");
}

// ─────────────────────────────────────────────────────────────────
// 7. Reconcile-on-open reinstates a pending entry the encrypted
//    state lost (build_spend crashed between journal append and save).
//
// We simulate this by appending a Built event manually for a tx the
// wallet does not yet know about, then ensuring reopen reinstates it.
// ─────────────────────────────────────────────────────────────────

#[test]
fn reconcile_on_open_reinstates_lost_pending() {
    let temp = TempDir::new().unwrap();
    let dir = temp.path().join("w");
    let mut wd = WalletDir::create(&dir, "pw", Network::Mainnet, &test_genesis()).unwrap();
    let output = make_output(900, 100, false);
    let input_commitment = output.commitment;
    wd.wallet_mut().add_output(output);
    // Persist the output explicitly — `add_output` does not save.
    wd.wallet().save().unwrap();
    drop(wd);

    // Manually append a Built event referencing the wallet's only
    // input. Use a fabricated tx_hash — what matters is that the
    // input commitment matches a wallet-owned output.
    let fake_tx_hash = [0xABu8; 32];
    let tx_bytes = vec![0xAA, 0xBB, 0xCC];
    let j = TxJournal::open(&dir).unwrap();
    j.append(&JournalEntry {
        timestamp: 1,
        tx_hash: fake_tx_hash,
        event: TxJournalEvent::Built {
            inputs: vec![input_commitment],
            tx_hex: Some(hex::encode(&tx_bytes)),
            output_count: 1,
            fee_noms: 42,
            change: None,
        },
    })
    .unwrap();

    let reopened = WalletDir::open(&dir, "pw").unwrap();
    assert!(
        reopened.wallet().has_pending_tx(&fake_tx_hash),
        "Built-in-journal-but-missing-in-state pending must be reinstated"
    );
    let input = reopened
        .wallet()
        .outputs()
        .find(|o| o.commitment == input_commitment)
        .unwrap();
    assert_eq!(
        input.reserved_for_tx,
        Some(fake_tx_hash),
        "reinstated tx must re-reserve its inputs"
    );
    assert!(!input.spent);
    assert_eq!(
        reopened.wallet().pending_tx_bytes(&fake_tx_hash).unwrap(),
        tx_bytes.as_slice()
    );
}

// ─────────────────────────────────────────────────────────────────
// 7b. Reconcile-on-open SKIPS reinstating a pending whose inputs are
//    no longer in the output index. Partial reservation would leave
//    the wallet in an inconsistent state.
// ─────────────────────────────────────────────────────────────────

#[test]
fn reconcile_on_open_skips_reinstate_when_inputs_missing() {
    let temp = TempDir::new().unwrap();
    let dir = temp.path().join("w");
    let _wd = WalletDir::create(&dir, "pw", Network::Mainnet, &test_genesis()).unwrap();
    drop(_wd);

    // Journal references an input commitment the wallet has no record of.
    let fake_tx_hash = [0xCDu8; 32];
    let phantom_input = [0xEEu8; 33];
    let j = TxJournal::open(&dir).unwrap();
    j.append(&JournalEntry {
        timestamp: 1,
        tx_hash: fake_tx_hash,
        event: TxJournalEvent::Built {
            inputs: vec![phantom_input],
            tx_hex: None,
            output_count: 1,
            fee_noms: 1,
            change: None,
        },
    })
    .unwrap();

    let reopened = WalletDir::open(&dir, "pw").unwrap();
    assert!(
        !reopened.wallet().has_pending_tx(&fake_tx_hash),
        "reinstate must be skipped when inputs are absent from the output index"
    );
}

// ─────────────────────────────────────────────────────────────────
// 8. Phase 1.7 hash unification: the wallet's tracking hash equals
//    `blake2b_256(tx.to_bytes())` (un-tagged), matching the mempool's
//    `node_handle::submit_tx` keyspace.
// ─────────────────────────────────────────────────────────────────

#[test]
fn unified_tx_hash_matches_mempool_blake2b() {
    let mut wallet = Wallet::new_in_memory(Network::Testnet, &test_genesis());
    wallet.add_output(make_output(900, 100, false));

    let tx = build_test_spend(&mut wallet);
    let wallet_hash = Wallet::tracking_tx_hash(&tx).unwrap();

    let raw_bytes = tx.to_bytes().expect("tx bytes");
    let mempool_hash: [u8; 32] = *dom_crypto::blake2b_256(&raw_bytes).as_bytes();

    assert_eq!(
        wallet_hash, mempool_hash,
        "wallet tracking_tx_hash must equal the mempool blake2b_256(tx_bytes); \
         a divergence here means pending-tx lookups cross-tier will silently miss"
    );
}
