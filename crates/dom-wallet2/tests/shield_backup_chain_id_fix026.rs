//! dom-shield — FIX-026 reproducer: cross-chain backup import (NO chain_id guard).
//!
//! Claim: `import_backup` must bind backup payloads to the destination wallet's
//! `chain_id`; a backup exported on one chain must not merge into another chain
//! even when the passphrase matches.
//!
//! This is a directed test: build a backup that represents a "foreign chain"
//! output set, then import it into a store conceptually belonging to another
//! chain, and assert the import is REJECTED.
//!
//! Expected by FIX-026: foreign-chain import is rejected before any output is
//! injected into the funds store.

use dom_wallet2::{export_backup, import_backup, OutputOrigin, OutputStore, StoredOutput};

const FOREIGN_CHAIN_ID: [u8; 32] = [0xF0; 32];
const OUR_CHAIN_ID: [u8; 32] = [0x0A; 32];

fn foreign_output() -> StoredOutput {
    // A confirmed output that exists ONLY on the foreign chain — its commitment
    // is meaningless / non-canonical on our chain.
    StoredOutput::new_unconfirmed(
        [0xF0u8; 33],
        1_000_000,
        [0xF1u8; 32],
        OutputOrigin::ReceiveSlate,
        false,
        None,
        1,
    )
}

#[test]
fn fix026_foreign_chain_backup_is_rejected_on_import() {
    let dir = tempfile::TempDir::new().unwrap();
    let path = dir.path().join("foreign.dombak");

    // Backup produced for a FOREIGN chain (right passphrase, wrong chain).
    let mut foreign_src = OutputStore::new();
    foreign_src.insert(foreign_output()).unwrap();
    export_backup(
        &foreign_src,
        &path,
        "shared-passphrase",
        FOREIGN_CHAIN_ID,
        1,
    )
    .unwrap();

    // Our wallet/store belongs to a DIFFERENT chain.
    let mut our_store = OutputStore::new();
    let result = import_backup(&mut our_store, &path, "shared-passphrase", OUR_CHAIN_ID);

    assert!(
        result.is_err(),
        "import_backup accepted a foreign-chain backup; {} foreign output(s) were injected",
        our_store.len()
    );
    assert!(
        our_store.is_empty(),
        "{} foreign output(s) leaked into the funds store",
        our_store.len()
    );
}

#[test]
fn fix026_backup_payload_is_chain_bound() {
    let dir = tempfile::TempDir::new().unwrap();
    let path = dir.path().join("our.dombak");
    let mut src = OutputStore::new();
    src.insert(foreign_output()).unwrap();
    export_backup(&src, &path, "pw", OUR_CHAIN_ID, 1).unwrap();

    let mut matching_store = OutputStore::new();
    let matching = import_backup(&mut matching_store, &path, "pw", OUR_CHAIN_ID);
    assert!(matching.is_ok(), "same-chain backup must import");
    assert_eq!(matching_store.len(), 1);

    let mut foreign_store = OutputStore::new();
    let foreign = import_backup(&mut foreign_store, &path, "pw", FOREIGN_CHAIN_ID);
    assert!(
        foreign.is_err(),
        "same backup bytes must reject wrong chain_id"
    );
    assert!(foreign_store.is_empty());
}
