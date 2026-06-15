//! WDSF-001 acceptance test, ported to dom-wallet2 (design §4.4).
//!
//! v1 counterpart: `dom-wallet/tests/robustness_reorg_slate_receive.rs`, which
//! is RED by design — `rollback_to` removes the recipient's output and its
//! random blinding exists nowhere recoverable, so a re-mine of the same tx
//! cannot re-register the received funds.
//!
//! In v2 this is GREEN by construction: the recipient's output is a
//! `StoredOutput` born at local creation (C0) with its blinding persisted, and
//! a reorg is a *status* transition (Confirmed → Reorged, T3) that keeps the
//! blinding. When the same tx is re-mined, reconcile finds the commitment in the
//! canonical set again and applies T6 (Reorged → Confirmed) using the material
//! already in the store — no pending, no re-derivation.
//!
//! This operates at the store/reconcile layer (the slate crypto that produces
//! the commitment is the transport layer, wired in later). The reconciler's
//! contract is exactly about a commitment's presence/absence in the canonical
//! set, which is what the §4.4 proof reasons over.

use dom_wallet2::{
    reconcile, BlockRef, CanonicalView, OutputOrigin, OutputStatus, OutputStore, ScanBlock,
    StoredOutput,
};

/// Recipient's received output: random (non-derivable) blinding — the case v1
/// loses on reorg.
const C_R: [u8; 33] = [0xC7u8; 33];
const X_R: [u8; 32] = [0x9au8; 32]; // random blinding

fn block_with_output(height: u64, hash_byte: u8, commitment: [u8; 33]) -> ScanBlock {
    ScanBlock {
        height,
        hash: [hash_byte; 32],
        output_commitments: vec![commitment],
        input_commitments: vec![],
    }
}

#[test]
fn slate_receive_survives_reorg_when_tx_is_remined() {
    let amount: u64 = 900;

    // --- Step 0: receive_slate (C0). The recipient owns the output locally with
    //     its random blinding persisted, before any block. ---
    let mut store = OutputStore::new();
    store
        .insert(StoredOutput::new_unconfirmed(
            C_R,
            amount,
            X_R,
            OutputOrigin::ReceiveSlate,
            false,
            None, // derivable=None: cannot be rebuilt from the seed
            1000,
        ))
        .unwrap();

    // --- Step 1: block 2 (hash 0x02) mines the tx → reconcile confirms (T1). ---
    let r = reconcile(
        &mut store,
        &CanonicalView::from_blocks(&[block_with_output(2, 0x02, C_R)]),
        1001,
    );
    assert_eq!(r.confirmed, 1);
    let o = store.get(&C_R).expect("receive present after block 2");
    assert_eq!(o.status, OutputStatus::Confirmed);
    assert_eq!(
        o.origin_block,
        Some(BlockRef {
            height: 2,
            hash: [0x02; 32]
        })
    );

    // --- Step 2: reorg — block 2 leaves the chain (back to the common ancestor,
    //     height 1, which holds nothing of the recipient). reconcile → Reorged
    //     (T3). The output is NOT removed; the blinding is kept. ---
    let r = reconcile(&mut store, &CanonicalView::empty(), 1002);
    assert_eq!(r.reorged, 1);
    assert_eq!(r.outputs_before, r.outputs_after); // INV-RET: nothing dropped
    let o = store.get(&C_R).expect("receive RETAINED through reorg");
    assert_eq!(o.status, OutputStatus::Reorged);
    assert_eq!(*o.blinding, X_R, "blinding kept across the reorg");
    assert_eq!(o.value, amount);

    // --- Step 3: the SAME tx is re-mined in block 2' (hash 0xB2) of the winning
    //     branch → reconcile reconfirms (T6) from persisted material. ---
    let r = reconcile(
        &mut store,
        &CanonicalView::from_blocks(&[block_with_output(2, 0xB2, C_R)]),
        1003,
    );
    assert_eq!(r.confirmed, 1);

    // The whole point of WDSF-001: the received funds survive reorg + re-mine.
    let survivor = store
        .get(&C_R)
        .expect("received output survives reorg + re-mine (WDSF-001 fixed)");
    assert_eq!(survivor.status, OutputStatus::Confirmed);
    assert_eq!(survivor.value, amount);
    assert_eq!(*survivor.blinding, X_R);
    assert_eq!(
        survivor.origin_block,
        Some(BlockRef {
            height: 2,
            hash: [0xB2; 32]
        }),
        "re-confirmed at the winning branch's block"
    );
}
