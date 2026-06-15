//! WDSF-002 acceptance tests, ported to dom-wallet2 (design §4.3).
//!
//! v1 counterpart: `dom-wallet/tests/robustness_rescan_nonderivable_outputs.rs`,
//! RED by design — a `Repair` rescan replaces `self.outputs` with the
//! derivation-reconstructed set, so a confirmed receive-slate or confirmed
//! change (random blinding, no pending) is discarded on the next rescan.
//!
//! In v2 these are GREEN by construction. Rescan is reconciliation, not
//! reconstruction: [`reconcile`] walks the STORE and only reassigns status.
//! `derivable` is never consulted to decide retention (it does not appear in
//! §4.2), so a non-derivable output is never dropped. The INV-RET lemma
//! (`outputs_before == outputs_after`) is asserted on every pass.
//!
//! Operates at the store/reconcile layer; the slate/coinbase crypto that
//! produces the commitments is the transport layer, wired in later.

use dom_wallet2::{
    reconcile, DerivIndex, OutputOrigin, OutputStatus, OutputStore, ScanBlock, StoredOutput,
};

const COINBASE_C: [u8; 33] = [0x01u8; 33];
const RECIPIENT_C: [u8; 33] = [0xC7u8; 33];
const CHANGE_C: [u8; 33] = [0xCCu8; 33];

fn empty_block(height: u64) -> ScanBlock {
    ScanBlock {
        height,
        hash: [height as u8; 32],
        output_commitments: vec![],
        input_commitments: vec![],
    }
}

/// A confirmed receive-slate output must SURVIVE a subsequent Repair rescan
/// (the real trigger is the desktop background loop reconciling on every block).
#[test]
fn confirmed_slate_receive_survives_subsequent_repair_rescan() {
    let amount: u64 = 900;

    // Step 0: receive_slate (C0) — random blinding persisted, derivable=None.
    let mut store = OutputStore::new();
    store
        .insert(StoredOutput::new_unconfirmed(
            RECIPIENT_C,
            amount,
            [0x9au8; 32],
            OutputOrigin::ReceiveSlate,
            false,
            None,
            1000,
        ))
        .unwrap();

    // Step 1: block 2 includes the recipient output → 1st reconcile confirms (T1).
    let block2 = ScanBlock {
        height: 2,
        hash: [2u8; 32],
        output_commitments: vec![RECIPIENT_C],
        input_commitments: vec![COINBASE_C],
    };
    reconcile(
        &mut store,
        &dom_wallet2::CanonicalView::from_blocks(std::slice::from_ref(&block2)),
        1001,
    );
    let confirmed = store
        .get(&RECIPIENT_C)
        .expect("first reconcile confirms the slate-received output");
    assert_eq!(confirmed.status, OutputStatus::Confirmed);
    assert_eq!(confirmed.value, amount);

    // Step 2: 2nd Repair rescan with the tip advanced (empty block 3) — exactly
    // what the desktop loop fires on the next block. The output is still in the
    // canonical UTXO set (block 2), so the "keep" arm applies.
    let r = reconcile(
        &mut store,
        &dom_wallet2::CanonicalView::from_blocks(&[block2, empty_block(3)]),
        1002,
    );
    assert_eq!(
        r.unchanged, 1,
        "confirmed receive untouched by the 2nd rescan"
    );
    assert_eq!(r.outputs_before, r.outputs_after); // INV-RET

    let survivor = store
        .get(&RECIPIENT_C)
        .expect("confirmed receive survives the subsequent Repair rescan (WDSF-002 fixed)");
    assert_eq!(survivor.status, OutputStatus::Confirmed);
    assert_eq!(survivor.value, amount);
}

/// The change of a confirmed spend must survive a Repair rescan: the change
/// blinding is random and the record lives only in the store.
#[test]
fn confirmed_change_survives_repair_rescan() {
    let reward: u64 = 1000;
    let spend_amount: u64 = reward / 2; // 500
    let fee: u64 = 100;
    let change_value: u64 = reward - spend_amount - fee; // 400

    let mut store = OutputStore::new();

    // Seed: a confirmed coinbase (derivable by height) at block 1.
    let mut coinbase = StoredOutput::new_unconfirmed(
        COINBASE_C,
        reward,
        [0x11u8; 32],
        OutputOrigin::Coinbase,
        true,
        Some(DerivIndex::CoinbaseHeight(1)),
        1000,
    );
    coinbase
        .confirm(
            dom_wallet2::BlockRef {
                height: 1,
                hash: [1u8; 32],
            },
            1000,
        )
        .unwrap();
    store.insert(coinbase).unwrap();

    // create_send (C0): the change output is born Unconfirmed with a RANDOM
    // blinding (non-derivable). The coinbase is reserved as the spend input.
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

    // Block 2 mines the tx: outputs created (recipient + change), input spent
    // (the coinbase). The recipient's own output is not ours.
    let block2 = ScanBlock {
        height: 2,
        hash: [2u8; 32],
        output_commitments: vec![RECIPIENT_C, CHANGE_C],
        input_commitments: vec![COINBASE_C],
    };

    // 1st reconcile: change → Confirmed (T1); coinbase → Spent (T2, retained).
    let r = reconcile(
        &mut store,
        &dom_wallet2::CanonicalView::from_blocks(std::slice::from_ref(&block2)),
        1002,
    );
    assert_eq!(r.confirmed, 1);
    assert_eq!(r.spent, 1);
    assert_eq!(
        store.get(&CHANGE_C).unwrap().status,
        OutputStatus::Confirmed
    );
    assert_eq!(
        store.get(&COINBASE_C).unwrap().status,
        OutputStatus::Spent,
        "spent coinbase is retained, not deleted (V-03)"
    );

    // 2nd Repair rescan (advanced empty tip): both records survive.
    let r = reconcile(
        &mut store,
        &dom_wallet2::CanonicalView::from_blocks(&[block2, empty_block(3)]),
        1003,
    );
    assert_eq!(r.outputs_before, r.outputs_after); // INV-RET: cardinality stable
    assert_eq!(store.len(), 2);

    let change = store
        .get(&CHANGE_C)
        .expect("confirmed change survives the Repair rescan (WDSF-002 fixed)");
    assert_eq!(change.status, OutputStatus::Confirmed);
    assert_eq!(change.value, change_value);
    assert_eq!(*change.blinding, [0xcau8; 32]);
    // The spent coinbase is still present (Spent), never discarded.
    assert_eq!(store.get(&COINBASE_C).unwrap().status, OutputStatus::Spent);
}
