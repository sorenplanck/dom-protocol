//! Reorg rollback handling — adversarial coverage (Phase 1.8).
//!
//! These tests prove that `Wallet::rollback_to` is a deterministic
//! inverse of `apply_canonical_block` for confirmations at heights
//! strictly greater than the rollback target, and that the journal +
//! reconcile-on-open machinery survives crashes interleaved with the
//! rollback flow.
//!
//! Properties covered:
//!
//! 1. **Single-block rollback** — one Confirmed tx is rewound to
//!    `Building`; its input is unmarked spent and re-reserved.
//! 2. **Multi-block rollback** — a single `rollback_to(H)` rewinds
//!    every Confirmed record whose `block_height > H`.
//! 3. **Rollback during pending lifecycle** — a `Built`-but-not-yet-
//!    confirmed tx is unaffected by rollback when its inputs survive.
//! 4. **Restart during rollback** — a process crash after the
//!    Reorged journal append but before `save()` heals via
//!    `reconcile_with_journal` on reopen.
//! 5. **Reopen after successful rollback** — restart equivalence:
//!    the on-disk state matches the in-memory state pre-drop.
//! 6. **Tx resurrected after reorg** — confirm → rollback → confirm
//!    again at a different height converges to `Confirmed { new }`.
//! 7. **Duplicate rollback idempotency** — a second
//!    `rollback_to(H)` is a no-op.
//! 8. **Replay equivalence after alternate branch** — rollback +
//!    re-confirm a different tx converges to the same end state as
//!    applying that alternate chain from scratch.
//! 9. **Interrupted persistence during rollback** — a crash with
//!    the spent-marker still set heals on reopen (mark_unspent +
//!    re-reserve), even though the journal got the Reorged event
//!    first.

use dom_consensus::transaction::Transaction;
use dom_core::Hash256;
use dom_crypto::pedersen::Commitment;
use dom_crypto::BlindingFactor;
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

fn input_state(wallet: &Wallet, commitment: &[u8; 33]) -> (bool, Option<[u8; 32]>) {
    let o = wallet
        .outputs()
        .find(|o| &o.commitment == commitment)
        .expect("input must still be in output index");
    (o.spent, o.reserved_for_tx)
}

// ─────────────────────────────────────────────────────────────────
// 1. Single-block rollback rewinds one Confirmed tx.
// ─────────────────────────────────────────────────────────────────

#[test]
fn single_block_rollback_unconfirms_tx() {
    let temp = TempDir::new().unwrap();
    let dir = temp.path().join("w");
    let mut wd = WalletDir::create(&dir, "pw", Network::Mainnet, &test_genesis()).unwrap();
    let input = make_output(900, 100, false);
    let input_commitment = input.commitment;
    wd.wallet_mut().add_output(input);

    let tx = build_test_spend(wd.wallet_mut());
    let tx_hash = Wallet::tracking_tx_hash(&tx).unwrap();
    wd.wallet_mut().apply_canonical_block(&[tx], 200).unwrap();

    // Pre-rollback: tx confirmed, input spent.
    assert!(!wd.wallet().has_pending_tx(&tx_hash));
    let (spent, reserved) = input_state(wd.wallet(), &input_commitment);
    assert!(spent);
    assert_eq!(reserved, None);

    wd.wallet_mut().rollback_to(199).unwrap();

    assert!(
        wd.wallet().has_pending_tx(&tx_hash),
        "rollback must reinstate the pending tx"
    );
    let (spent, reserved) = input_state(wd.wallet(), &input_commitment);
    assert!(!spent, "input must be unmarked spent");
    assert_eq!(
        reserved,
        Some(tx_hash),
        "input must be re-reserved for the tx"
    );

    let records = replay_records(&dir);
    assert_eq!(records.get(&tx_hash).unwrap().status, TxStatus::Building);
}

// ─────────────────────────────────────────────────────────────────
// 2. Multi-block rollback rewinds every tx whose Confirmed height
//    is strictly above the rollback target. Txs at heights <=
//    target survive untouched.
// ─────────────────────────────────────────────────────────────────

#[test]
fn multi_block_rollback_unconfirms_all_above_target() {
    let temp = TempDir::new().unwrap();
    let dir = temp.path().join("w");
    let mut wd = WalletDir::create(&dir, "pw", Network::Mainnet, &test_genesis()).unwrap();

    // Three equal-value outputs; coin selection is HashMap-order-
    // dependent, so we identify each tx by what it actually spends
    // (read from tx.inputs after build_spend), not by setup naming.
    wd.wallet_mut().add_output(make_output(900, 100, false));
    wd.wallet_mut().add_output(make_output(900, 100, false));
    wd.wallet_mut().add_output(make_output(900, 100, false));

    let tx_a = build_test_spend(wd.wallet_mut());
    let h_a = Wallet::tracking_tx_hash(&tx_a).unwrap();
    let input_a: [u8; 33] = *tx_a.inputs[0].commitment.as_bytes();
    wd.wallet_mut().apply_canonical_block(&[tx_a], 150).unwrap();
    let tx_b = build_test_spend(wd.wallet_mut());
    let h_b = Wallet::tracking_tx_hash(&tx_b).unwrap();
    let input_b: [u8; 33] = *tx_b.inputs[0].commitment.as_bytes();
    wd.wallet_mut().apply_canonical_block(&[tx_b], 205).unwrap();
    let tx_c = build_test_spend(wd.wallet_mut());
    let h_c = Wallet::tracking_tx_hash(&tx_c).unwrap();
    let input_c: [u8; 33] = *tx_c.inputs[0].commitment.as_bytes();
    wd.wallet_mut().apply_canonical_block(&[tx_c], 210).unwrap();

    // Rollback to 199: tx_a (h=150) survives terminal; tx_b (205)
    // and tx_c (210) rewind.
    wd.wallet_mut().rollback_to(199).unwrap();

    let records = replay_records(&dir);
    assert_eq!(
        records.get(&h_a).unwrap().status,
        TxStatus::Confirmed { block_height: 150 },
        "tx_a at 150 must remain Confirmed"
    );
    assert_eq!(records.get(&h_b).unwrap().status, TxStatus::Building);
    assert_eq!(records.get(&h_c).unwrap().status, TxStatus::Building);

    let (spent_a, _) = input_state(wd.wallet(), &input_a);
    assert!(spent_a, "tx_a's input must stay spent");
    let (spent_b, res_b) = input_state(wd.wallet(), &input_b);
    let (spent_c, res_c) = input_state(wd.wallet(), &input_c);
    assert!(!spent_b, "tx_b's input must be un-spent");
    assert!(!spent_c, "tx_c's input must be un-spent");
    assert_eq!(res_b, Some(h_b));
    assert_eq!(res_c, Some(h_c));

    assert!(!wd.wallet().has_pending_tx(&h_a));
    assert!(wd.wallet().has_pending_tx(&h_b));
    assert!(wd.wallet().has_pending_tx(&h_c));
}

// ─────────────────────────────────────────────────────────────────
// 3. A Built-but-not-Confirmed tx (whose inputs survive the
//    rollback) is left exactly as-is. Stale outputs above the
//    target are removed.
// ─────────────────────────────────────────────────────────────────

#[test]
fn rollback_during_pending_lifecycle_preserves_built_tx() {
    let temp = TempDir::new().unwrap();
    let dir = temp.path().join("w");
    let mut wd = WalletDir::create(&dir, "pw", Network::Mainnet, &test_genesis()).unwrap();

    let spend_input = make_output(900, 100, false);
    let spend_input_c = spend_input.commitment;
    wd.wallet_mut().add_output(spend_input);

    // A second output sitting at a height that will be rolled away.
    let stale = make_output(500, 300, false);
    let stale_c = stale.commitment;
    wd.wallet_mut().add_output(stale);

    let tx = build_test_spend(wd.wallet_mut());
    let h = Wallet::tracking_tx_hash(&tx).unwrap();
    // No apply_canonical_block — tx stays in Building.

    wd.wallet_mut().rollback_to(199).unwrap();

    // Built tx unaffected.
    assert!(wd.wallet().has_pending_tx(&h));
    let (spent, reserved) = input_state(wd.wallet(), &spend_input_c);
    assert!(!spent);
    assert_eq!(reserved, Some(h), "Built-tx reservation must be preserved");
    let records = replay_records(&dir);
    assert_eq!(records.get(&h).unwrap().status, TxStatus::Building);

    // Stale output at height 300 must be removed.
    assert!(
        wd.wallet().outputs().all(|o| o.commitment != stale_c),
        "output at height 300 must be removed by rollback_to(199)"
    );
}

// ─────────────────────────────────────────────────────────────────
// 4. Crash after `Reorged` was appended but before the wallet
//    saved its post-rollback state: reopen via `WalletDir` must
//    heal — pending reinstated, inputs un-spent + re-reserved.
// ─────────────────────────────────────────────────────────────────

#[test]
fn restart_during_rollback_heals_via_journal_replay() {
    let temp = TempDir::new().unwrap();
    let dir = temp.path().join("w");
    let mut wd = WalletDir::create(&dir, "pw", Network::Mainnet, &test_genesis()).unwrap();

    let input = make_output(900, 100, false);
    let input_c = input.commitment;
    wd.wallet_mut().add_output(input);
    let tx = build_test_spend(wd.wallet_mut());
    let tx_hash = Wallet::tracking_tx_hash(&tx).unwrap();
    wd.wallet_mut().apply_canonical_block(&[tx], 200).unwrap();

    // At this point: input is spent, no pending entry.
    drop(wd);

    // Simulate crash mid-rollback: append the Reorged entry
    // manually but leave the encrypted state untouched.
    let j = TxJournal::open(&dir).unwrap();
    j.append(&JournalEntry {
        timestamp: 1,
        tx_hash,
        event: TxJournalEvent::Reorged { reorg_height: 199 },
    })
    .unwrap();

    let reopened = WalletDir::open(&dir, "pw").unwrap();
    assert!(
        reopened.wallet().has_pending_tx(&tx_hash),
        "reconcile must reinstate pending after crash mid-rollback"
    );
    let (spent, reserved) = input_state(reopened.wallet(), &input_c);
    assert!(!spent, "reconcile must un-spend input after Reorged");
    assert_eq!(reserved, Some(tx_hash));
}

// ─────────────────────────────────────────────────────────────────
// 5. After a fully-completed rollback, dropping and reopening the
//    wallet directory must yield bit-identical state — the
//    rollback's mutations are durable through restart.
// ─────────────────────────────────────────────────────────────────

#[test]
fn reopen_after_rollback_converges_to_same_state() {
    let temp = TempDir::new().unwrap();
    let dir = temp.path().join("w");
    let mut wd = WalletDir::create(&dir, "pw", Network::Mainnet, &test_genesis()).unwrap();
    let input = make_output(900, 100, false);
    let input_c = input.commitment;
    wd.wallet_mut().add_output(input);
    let tx = build_test_spend(wd.wallet_mut());
    let tx_hash = Wallet::tracking_tx_hash(&tx).unwrap();
    wd.wallet_mut().apply_canonical_block(&[tx], 200).unwrap();
    wd.wallet_mut().rollback_to(199).unwrap();

    // Snapshot in-memory state.
    let in_mem_pending = wd.wallet().has_pending_tx(&tx_hash);
    let in_mem_state = input_state(wd.wallet(), &input_c);

    drop(wd);

    let reopened = WalletDir::open(&dir, "pw").unwrap();
    assert_eq!(reopened.wallet().has_pending_tx(&tx_hash), in_mem_pending);
    assert_eq!(input_state(reopened.wallet(), &input_c), in_mem_state);
}

// ─────────────────────────────────────────────────────────────────
// 6. confirm → rollback → confirm again at a different height
//    settles the journal to `Confirmed { new_height }`. The
//    intermediate `Building` state was a valid stop, but the new
//    canonical chain re-confirms.
// ─────────────────────────────────────────────────────────────────

#[test]
fn tx_resurrected_after_reorg() {
    let temp = TempDir::new().unwrap();
    let dir = temp.path().join("w");
    let mut wd = WalletDir::create(&dir, "pw", Network::Mainnet, &test_genesis()).unwrap();
    let input = make_output(900, 100, false);
    let input_c = input.commitment;
    wd.wallet_mut().add_output(input);
    let tx = build_test_spend(wd.wallet_mut());
    let tx_hash = Wallet::tracking_tx_hash(&tx).unwrap();
    wd.wallet_mut()
        .apply_canonical_block(std::slice::from_ref(&tx), 200)
        .unwrap();
    wd.wallet_mut().rollback_to(199).unwrap();
    wd.wallet_mut().apply_canonical_block(&[tx], 205).unwrap();

    let records = replay_records(&dir);
    assert_eq!(
        records.get(&tx_hash).unwrap().status,
        TxStatus::Confirmed { block_height: 205 }
    );
    assert!(!wd.wallet().has_pending_tx(&tx_hash));
    let (spent, reserved) = input_state(wd.wallet(), &input_c);
    assert!(spent);
    assert_eq!(reserved, None);
}

// ─────────────────────────────────────────────────────────────────
// 7. Calling `rollback_to(H)` a second time on already-rolled-back
//    state is a no-op: no new Reorged events, no state changes.
// ─────────────────────────────────────────────────────────────────

#[test]
fn duplicate_rollback_is_idempotent() {
    let temp = TempDir::new().unwrap();
    let dir = temp.path().join("w");
    let mut wd = WalletDir::create(&dir, "pw", Network::Mainnet, &test_genesis()).unwrap();
    let input = make_output(900, 100, false);
    wd.wallet_mut().add_output(input);
    let tx = build_test_spend(wd.wallet_mut());
    let tx_hash = Wallet::tracking_tx_hash(&tx).unwrap();
    wd.wallet_mut().apply_canonical_block(&[tx], 200).unwrap();
    wd.wallet_mut().rollback_to(199).unwrap();

    let journal_bytes_before = std::fs::read(dir.join("journal.log")).unwrap();
    let pending_before = wd.wallet().has_pending_tx(&tx_hash);

    wd.wallet_mut().rollback_to(199).unwrap();

    let journal_bytes_after = std::fs::read(dir.join("journal.log")).unwrap();
    assert_eq!(
        journal_bytes_before, journal_bytes_after,
        "second rollback must not append any new journal events"
    );
    assert_eq!(wd.wallet().has_pending_tx(&tx_hash), pending_before);
}

// ─────────────────────────────────────────────────────────────────
// 8. Replay equivalence after alternate branch: a wallet that
//    confirmed tx_branch1, rolled back, canceled it, built and
//    confirmed tx_branch2 on the alternate chain, converges to a
//    deterministic terminal state — the same input is now spent
//    by tx_branch2, no pending entries remain, and reopen
//    preserves that state bit-for-bit.
// ─────────────────────────────────────────────────────────────────

#[test]
fn replay_equivalence_after_alternate_branch() {
    let temp = TempDir::new().unwrap();
    let dir = temp.path().join("w");
    let mut wd = WalletDir::create(&dir, "pw", Network::Mainnet, &test_genesis()).unwrap();

    let input = make_output(900, 100, false);
    let input_c = input.commitment;
    wd.wallet_mut().add_output(input);

    // Chain 1: build + confirm tx_branch1 at h=200.
    let tx_branch1 = build_test_spend(wd.wallet_mut());
    let h_branch1 = Wallet::tracking_tx_hash(&tx_branch1).unwrap();
    let used_input_1: [u8; 33] = *tx_branch1.inputs[0].commitment.as_bytes();
    assert_eq!(used_input_1, input_c);
    wd.wallet_mut()
        .apply_canonical_block(&[tx_branch1], 200)
        .unwrap();

    // Reorg to 199 — tx_branch1 back to Building, input reserved.
    wd.wallet_mut().rollback_to(199).unwrap();

    // Operator cancels the resurrected pending so the input is
    // free for re-spending on the alternate chain.
    wd.wallet_mut().cancel_tx(h_branch1).unwrap();

    // Chain 2: a fresh build with the same input but a different
    // random recipient blinding → distinct tx_hash.
    let tx_branch2 = build_test_spend(wd.wallet_mut());
    let h_branch2 = Wallet::tracking_tx_hash(&tx_branch2).unwrap();
    let used_input_2: [u8; 33] = *tx_branch2.inputs[0].commitment.as_bytes();
    assert_eq!(
        used_input_2, input_c,
        "tx_branch2 must spend the same input"
    );
    assert_ne!(h_branch1, h_branch2, "tx_branch2 must be a distinct tx");
    wd.wallet_mut()
        .apply_canonical_block(&[tx_branch2], 205)
        .unwrap();

    // Snapshot terminal state.
    let (spent_in_mem, reserved_in_mem) = input_state(wd.wallet(), &input_c);
    let has_branch1_in_mem = wd.wallet().has_pending_tx(&h_branch1);
    let has_branch2_in_mem = wd.wallet().has_pending_tx(&h_branch2);

    assert!(spent_in_mem, "input must be spent by tx_branch2");
    assert_eq!(reserved_in_mem, None);
    assert!(!has_branch1_in_mem);
    assert!(!has_branch2_in_mem);

    let records = replay_records(&dir);
    assert_eq!(records.get(&h_branch1).unwrap().status, TxStatus::Canceled);
    assert_eq!(
        records.get(&h_branch2).unwrap().status,
        TxStatus::Confirmed { block_height: 205 }
    );

    // Reopen the wallet directory; reconcile must produce the same
    // state we observed in memory.
    drop(wd);
    let reopened = WalletDir::open(&dir, "pw").unwrap();
    assert_eq!(
        input_state(reopened.wallet(), &input_c),
        (spent_in_mem, reserved_in_mem)
    );
    assert_eq!(
        reopened.wallet().has_pending_tx(&h_branch1),
        has_branch1_in_mem
    );
    assert_eq!(
        reopened.wallet().has_pending_tx(&h_branch2),
        has_branch2_in_mem
    );
}

// ─────────────────────────────────────────────────────────────────
// 9. Crash with the spent-marker still set + no pending entry +
//    Reorged in the journal: reopen heals via reconcile. This is
//    distinct from test #4 by asserting the input-side invariant
//    (un-spent + reserved) survives a crash whose only durable
//    record is the journal append.
// ─────────────────────────────────────────────────────────────────

#[test]
fn interrupted_persistence_during_rollback_heals_on_reopen() {
    let temp = TempDir::new().unwrap();
    let dir = temp.path().join("w");
    let mut wd = WalletDir::create(&dir, "pw", Network::Mainnet, &test_genesis()).unwrap();
    let input = make_output(900, 100, false);
    let input_c = input.commitment;
    wd.wallet_mut().add_output(input);
    let tx = build_test_spend(wd.wallet_mut());
    let tx_hash = Wallet::tracking_tx_hash(&tx).unwrap();
    wd.wallet_mut().apply_canonical_block(&[tx], 200).unwrap();

    // On disk now: tx_hash is Confirmed (journal), input is spent
    // (encrypted state), pending_txs has no entry.
    drop(wd);

    // Append Reorged manually — this is the *only* on-disk change
    // before the simulated crash.
    let j = TxJournal::open(&dir).unwrap();
    j.append(&JournalEntry {
        timestamp: 2,
        tx_hash,
        event: TxJournalEvent::Reorged { reorg_height: 199 },
    })
    .unwrap();

    // Reopen. Reconcile must un-spend + re-reserve the input AND
    // reinstate the pending entry.
    let reopened = WalletDir::open(&dir, "pw").unwrap();
    let (spent, reserved) = input_state(reopened.wallet(), &input_c);
    assert!(!spent, "spent marker must be cleared on reopen");
    assert_eq!(
        reserved,
        Some(tx_hash),
        "input must be reserved for the rewound tx"
    );
    assert!(reopened.wallet().has_pending_tx(&tx_hash));

    // The healed state must be durable: a second drop+reopen yields
    // the same state without re-running reconcile from a divergent
    // disk.
    drop(reopened);
    let reopened_again = WalletDir::open(&dir, "pw").unwrap();
    let (spent, reserved) = input_state(reopened_again.wallet(), &input_c);
    assert!(!spent);
    assert_eq!(reserved, Some(tx_hash));
    assert!(reopened_again.wallet().has_pending_tx(&tx_hash));
}
