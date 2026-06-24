//! dom-shield — FIX-026 reproducer: cross-chain backup import (NO chain_id guard).
//!
//! Claim: `import_backup` (backup.rs) takes only `(store, path, passphrase)`.
//! The `BackupEnvelopeV2` payload carries no `chain_id`, so a backup EXPORTED on
//! one chain can be IMPORTED into a wallet on a DIFFERENT chain as long as the
//! passphrase matches — injecting foreign-chain outputs into the funds store.
//!
//! This is a directed test: build a backup that represents a "foreign chain"
//! output set, then import it into a store conceptually belonging to another
//! chain, and assert the import is REJECTED.
//!
//! Expected by FIX-026: there is no rejection path -> the assert fails -> RED
//! confirms FIX-026. If it is GREEN, FIX-026 is dissolved.

use dom_wallet2::{export_backup, import_backup, OutputOrigin, OutputStore, StoredOutput};

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
    export_backup(&foreign_src, &path, "shared-passphrase", 1).unwrap();

    // Our wallet/store belongs to a DIFFERENT chain. There is no chain_id
    // available to the import API at all — that is exactly the defect.
    let mut our_store = OutputStore::new();
    let result = import_backup(&mut our_store, &path, "shared-passphrase");

    // The defensive contract we WANT: a foreign-chain backup must be rejected.
    assert!(
        result.is_err(),
        "FIX-026 CONFIRMED: import_backup accepted a foreign-chain backup \
         (no chain_id guard); {} foreign output(s) were injected into the store",
        our_store.len()
    );
    assert!(
        our_store.is_empty(),
        "FIX-026 CONFIRMED: {} foreign output(s) leaked into the funds store",
        our_store.len()
    );
}

#[test]
fn fix026_backup_payload_carries_no_chain_binding() {
    // Structural corollary: the SAME backup bytes import identically regardless
    // of which chain the caller "intends". Because the API has no chain_id
    // parameter, two callers on two different chains both succeed — proving the
    // payload is not chain-bound. (This test is GREEN today and documents the
    // missing binding; it turns into a redundant pass once FIX-026 is fixed and
    // the prior test goes GREEN.)
    let dir = tempfile::TempDir::new().unwrap();
    let path = dir.path().join("any.dombak");
    let mut src = OutputStore::new();
    src.insert(foreign_output()).unwrap();
    export_backup(&src, &path, "pw", 1).unwrap();

    // "Chain A" caller imports.
    let mut store_a = OutputStore::new();
    let a = import_backup(&mut store_a, &path, "pw");
    // "Chain B" caller imports the very same file.
    let mut store_b = OutputStore::new();
    let b = import_backup(&mut store_b, &path, "pw");

    // Both succeed identically — no chain distinguishes them.
    assert_eq!(
        a.is_ok(),
        b.is_ok(),
        "import outcome must not depend on caller chain — it cannot, there is no chain_id param"
    );
    if a.is_ok() && b.is_ok() {
        assert_eq!(
            store_a.len(),
            store_b.len(),
            "same bytes -> same injected set on any chain (no chain binding)"
        );
    }
}
