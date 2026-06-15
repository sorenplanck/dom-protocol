//! The WDSF-001/002 acceptance scenarios, re-run with an encrypted save/load
//! cycle inserted at the critical point. This proves persistence does not break
//! INV-RET: the non-derivable blinding and the output's status survive a disk
//! round-trip, and the reconciler keeps working against the *loaded* store.
//!
//! This is the design's "restart variant" (§4.5 / V-01): the recovered state
//! lives in the on-disk store, not in volatile memory, so re-confirmation after
//! a reorg uses persisted material with no pending and no re-derivation.

use dom_wallet2::{
    load_store, reconcile, save_store, BlockRef, CanonicalView, OutputOrigin, OutputStatus,
    OutputStore, ScanBlock, StoredOutput,
};
use tempfile::TempDir;

const COINBASE_C: [u8; 33] = [0x01u8; 33];
const RECIPIENT_C: [u8; 33] = [0xC7u8; 33];
const CHANGE_C: [u8; 33] = [0xCCu8; 33];
const X_R: [u8; 32] = [0x9au8; 32]; // recipient's random, non-derivable blinding

/// Encrypt the store to a fresh file and load it back — a full restart cycle.
fn save_load_cycle(store: &OutputStore, dir: &TempDir) -> OutputStore {
    let path = dir.path().join("wallet.dat");
    save_store(store, &path, "pw").expect("save");
    load_store(&path, "pw").expect("load")
}

fn block_with_output(height: u64, hash_byte: u8, commitment: [u8; 33]) -> ScanBlock {
    ScanBlock {
        height,
        hash: [hash_byte; 32],
        output_commitments: vec![commitment],
        input_commitments: vec![],
    }
}

/// WDSF-001 with a restart: receive confirmed → reorged → **persisted** →
/// reloaded → re-mined → re-confirmed from on-disk material.
#[test]
fn reorg_remine_survives_a_persistence_restart() {
    let dir = TempDir::new().unwrap();
    let amount: u64 = 900;

    let mut store = OutputStore::new();
    store
        .insert(StoredOutput::new_unconfirmed(
            RECIPIENT_C,
            amount,
            X_R,
            OutputOrigin::ReceiveSlate,
            false,
            None,
            1000,
        ))
        .unwrap();

    // Confirm at block 2 (T1), then reorg it out (T3 -> Reorged, blinding kept).
    reconcile(
        &mut store,
        &CanonicalView::from_blocks(&[block_with_output(2, 0x02, RECIPIENT_C)]),
        1001,
    );
    reconcile(&mut store, &CanonicalView::empty(), 1002);
    assert_eq!(
        store.get(&RECIPIENT_C).unwrap().status,
        OutputStatus::Reorged
    );

    // ── Restart: persist the Reorged state and reload from disk. ──
    let mut store = save_load_cycle(&store, &dir);
    let reloaded = store
        .get(&RECIPIENT_C)
        .expect("output survives persistence");
    assert_eq!(reloaded.status, OutputStatus::Reorged);
    assert_eq!(*reloaded.blinding, X_R, "blinding recovered from disk");

    // The SAME tx is re-mined at block 2'; reconcile re-confirms (T6) using the
    // material loaded from disk — no pending, no re-derivation.
    let r = reconcile(
        &mut store,
        &CanonicalView::from_blocks(&[block_with_output(2, 0xB2, RECIPIENT_C)]),
        1003,
    );
    assert_eq!(r.confirmed, 1);
    let survivor = store.get(&RECIPIENT_C).expect("received funds survive");
    assert_eq!(survivor.status, OutputStatus::Confirmed);
    assert_eq!(survivor.value, amount);
    assert_eq!(*survivor.blinding, X_R);
}

/// WDSF-002 (receive): a confirmed receive survives a persistence cycle and a
/// subsequent Repair-style reconcile.
#[test]
fn confirmed_receive_survives_persistence_then_repair() {
    let dir = TempDir::new().unwrap();
    let amount: u64 = 900;

    let mut store = OutputStore::new();
    store
        .insert(StoredOutput::new_unconfirmed(
            RECIPIENT_C,
            amount,
            X_R,
            OutputOrigin::ReceiveSlate,
            false,
            None,
            1000,
        ))
        .unwrap();

    let block2 = ScanBlock {
        height: 2,
        hash: [2u8; 32],
        output_commitments: vec![RECIPIENT_C],
        input_commitments: vec![COINBASE_C],
    };
    reconcile(
        &mut store,
        &CanonicalView::from_blocks(std::slice::from_ref(&block2)),
        1001,
    );
    assert_eq!(
        store.get(&RECIPIENT_C).unwrap().status,
        OutputStatus::Confirmed
    );

    // Restart, then a Repair-style reconcile at an advanced tip.
    let mut store = save_load_cycle(&store, &dir);
    let empty3 = ScanBlock {
        height: 3,
        hash: [3u8; 32],
        output_commitments: vec![],
        input_commitments: vec![],
    };
    let r = reconcile(
        &mut store,
        &CanonicalView::from_blocks(&[block2, empty3]),
        1002,
    );
    assert_eq!(r.outputs_before, r.outputs_after); // INV-RET across load + reconcile
    let survivor = store.get(&RECIPIENT_C).expect("confirmed receive survives");
    assert_eq!(survivor.status, OutputStatus::Confirmed);
    assert_eq!(survivor.value, amount);
    assert_eq!(*survivor.blinding, X_R);
}

/// WDSF-002 (change): a confirmed change and the spent coinbase both survive a
/// persistence cycle and a subsequent Repair-style reconcile.
#[test]
fn confirmed_change_survives_persistence_then_repair() {
    let dir = TempDir::new().unwrap();
    let reward: u64 = 1000;
    let change_value: u64 = 400;

    let mut store = OutputStore::new();
    let mut coinbase = StoredOutput::new_unconfirmed(
        COINBASE_C,
        reward,
        [0x11u8; 32],
        OutputOrigin::Coinbase,
        true,
        None,
        1000,
    );
    coinbase
        .confirm(
            BlockRef {
                height: 1,
                hash: [1u8; 32],
            },
            1000,
        )
        .unwrap();
    store.insert(coinbase).unwrap();
    store
        .insert(StoredOutput::new_unconfirmed(
            CHANGE_C,
            change_value,
            [0xcau8; 32],
            OutputOrigin::Change,
            false,
            None,
            1001,
        ))
        .unwrap();

    let block2 = ScanBlock {
        height: 2,
        hash: [2u8; 32],
        output_commitments: vec![RECIPIENT_C, CHANGE_C],
        input_commitments: vec![COINBASE_C],
    };
    reconcile(
        &mut store,
        &CanonicalView::from_blocks(std::slice::from_ref(&block2)),
        1002,
    );
    assert_eq!(
        store.get(&CHANGE_C).unwrap().status,
        OutputStatus::Confirmed
    );
    assert_eq!(store.get(&COINBASE_C).unwrap().status, OutputStatus::Spent);

    // Restart, then a Repair-style reconcile: both records survive.
    let mut store = save_load_cycle(&store, &dir);
    assert_eq!(store.len(), 2, "both outputs survive persistence");

    let empty3 = ScanBlock {
        height: 3,
        hash: [3u8; 32],
        output_commitments: vec![],
        input_commitments: vec![],
    };
    let r = reconcile(
        &mut store,
        &CanonicalView::from_blocks(&[block2, empty3]),
        1003,
    );
    assert_eq!(r.outputs_before, r.outputs_after); // INV-RET
    let change = store.get(&CHANGE_C).expect("change survives");
    assert_eq!(change.status, OutputStatus::Confirmed);
    assert_eq!(change.value, change_value);
    assert_eq!(*change.blinding, [0xcau8; 32]);
    assert_eq!(
        store.get(&COINBASE_C).unwrap().status,
        OutputStatus::Spent,
        "spent coinbase retained across persistence"
    );
}
