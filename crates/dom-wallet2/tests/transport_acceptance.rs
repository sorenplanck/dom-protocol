//! The WDSF-001/002 acceptance scenarios driven **end-to-end through the
//! transport** ([`dom_wallet2::sync`] over an [`dom_wallet2::InMemoryChainSource`]),
//! not by calling `reconcile` directly. This proves the transport layer
//! preserves the guarantee: the same defensive scenarios that are red on v1
//! stay green when driven by `tip → scan → reconcile`.

use dom_wallet2::{
    sync, InMemoryChainSource, OutputOrigin, OutputStatus, OutputStore, ScanBlock, StoredOutput,
};

const COINBASE_C: [u8; 33] = [0x01u8; 33];
const RECIPIENT_C: [u8; 33] = [0xC7u8; 33];
const CHANGE_C: [u8; 33] = [0xCCu8; 33];
const X_R: [u8; 32] = [0x9au8; 32]; // recipient's random, non-derivable blinding

fn empty_block(height: u64) -> ScanBlock {
    ScanBlock {
        height,
        hash: [height as u8; 32],
        output_commitments: vec![],
        input_commitments: vec![],
    }
}

fn block_with_output(height: u64, hash_byte: u8, c: [u8; 33]) -> ScanBlock {
    ScanBlock {
        height,
        hash: [hash_byte; 32],
        output_commitments: vec![c],
        input_commitments: vec![],
    }
}

fn receive_store(amount: u64) -> OutputStore {
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
    store
}

/// WDSF-001 through the driver: a receive survives reorg + re-mine when the
/// canonical chain (the `InMemoryChainSource`) drops then re-adds the block.
#[test]
fn wdsf001_receive_survives_reorg_remine_via_sync() {
    let amount = 900;
    let mut store = receive_store(amount);

    // Tip at block 2 with the receive → sync confirms.
    let mut src = InMemoryChainSource::with_blocks([
        empty_block(0),
        empty_block(1),
        block_with_output(2, 0x02, RECIPIENT_C),
    ]);
    sync(&mut store, &src, 0, 1001).unwrap();
    assert_eq!(
        store.get(&RECIPIENT_C).unwrap().status,
        OutputStatus::Confirmed
    );

    // Reorg: block 2 leaves the canonical chain → sync reorgs (blinding kept).
    src.remove(2);
    sync(&mut store, &src, 0, 1002).unwrap();
    let reorged = store.get(&RECIPIENT_C).unwrap();
    assert_eq!(reorged.status, OutputStatus::Reorged);
    assert_eq!(*reorged.blinding, X_R);

    // Same tx re-mined at block 2' → sync re-confirms from store material.
    src.insert(block_with_output(2, 0xB2, RECIPIENT_C));
    sync(&mut store, &src, 0, 1003).unwrap();

    let survivor = store
        .get(&RECIPIENT_C)
        .expect("received funds survive reorg + re-mine through the driver");
    assert_eq!(survivor.status, OutputStatus::Confirmed);
    assert_eq!(survivor.value, amount);
    assert_eq!(*survivor.blinding, X_R);
}

/// WDSF-002 (receive) through the driver: a confirmed receive survives a
/// subsequent sync at an advanced (empty) tip — the repair-rescan analogue.
#[test]
fn wdsf002_confirmed_receive_survives_subsequent_sync() {
    let amount = 900;
    let mut store = receive_store(amount);

    let mut src = InMemoryChainSource::new();
    src.insert(ScanBlock {
        height: 2,
        hash: [2u8; 32],
        output_commitments: vec![RECIPIENT_C],
        input_commitments: vec![COINBASE_C],
    });
    sync(&mut store, &src, 0, 1001).unwrap();
    assert_eq!(
        store.get(&RECIPIENT_C).unwrap().status,
        OutputStatus::Confirmed
    );

    // Tip advances to an empty block 3; the receive is still in the UTXO set.
    src.insert(empty_block(3));
    let report = sync(&mut store, &src, 0, 1002).unwrap();
    assert_eq!(report.outputs_before, report.outputs_after); // INV-RET via driver

    let survivor = store
        .get(&RECIPIENT_C)
        .expect("confirmed receive survives the subsequent sync");
    assert_eq!(survivor.status, OutputStatus::Confirmed);
    assert_eq!(survivor.value, amount);
}

/// WDSF-002 (change) through the driver: a confirmed change and the spent
/// coinbase both survive a subsequent sync. Coinbase is confirmed by an earlier
/// sync, then spent by the tx block — exactly as on a live chain.
#[test]
fn wdsf002_confirmed_change_survives_subsequent_sync() {
    let reward = 1000;
    let change_value = 400;

    let mut store = OutputStore::new();
    store
        .insert(StoredOutput::new_unconfirmed(
            COINBASE_C,
            reward,
            [0x11u8; 32],
            OutputOrigin::Coinbase,
            true,
            None,
            1000,
        ))
        .unwrap();
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

    // Step 1: only block 1 (coinbase mined) → coinbase confirmed, change waits.
    let mut src = InMemoryChainSource::new();
    src.insert(block_with_output(1, 0x01, COINBASE_C));
    sync(&mut store, &src, 0, 1002).unwrap();
    assert_eq!(
        store.get(&COINBASE_C).unwrap().status,
        OutputStatus::Confirmed
    );
    assert_eq!(
        store.get(&CHANGE_C).unwrap().status,
        OutputStatus::Unconfirmed
    );

    // Step 2: block 2 mines the tx (change created, coinbase spent).
    src.insert(ScanBlock {
        height: 2,
        hash: [2u8; 32],
        output_commitments: vec![RECIPIENT_C, CHANGE_C],
        input_commitments: vec![COINBASE_C],
    });
    sync(&mut store, &src, 0, 1003).unwrap();
    assert_eq!(
        store.get(&CHANGE_C).unwrap().status,
        OutputStatus::Confirmed
    );
    assert_eq!(store.get(&COINBASE_C).unwrap().status, OutputStatus::Spent);

    // Step 3: tip advances to an empty block 3 — both records survive.
    src.insert(empty_block(3));
    let report = sync(&mut store, &src, 0, 1004).unwrap();
    assert_eq!(report.outputs_before, report.outputs_after);
    assert_eq!(store.len(), 2);

    let change = store
        .get(&CHANGE_C)
        .expect("change survives via the driver");
    assert_eq!(change.status, OutputStatus::Confirmed);
    assert_eq!(change.value, change_value);
    assert_eq!(*change.blinding, [0xcau8; 32]);
    assert_eq!(
        store.get(&COINBASE_C).unwrap().status,
        OutputStatus::Spent,
        "spent coinbase retained, not deleted"
    );
}
