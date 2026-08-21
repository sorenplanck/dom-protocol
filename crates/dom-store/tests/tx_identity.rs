//! Tests for the admission-time transaction-identity map (Option A of the
//! tx-identity defects, NOT RATIFIED).
//!
//! The properties asserted here are the ones the ratification text promises:
//! the entry itself never changes and is never removed by a reorg; every
//! reorg-dependent answer flows through the kernel index; retention prunes by
//! admission age and nothing else.

mod common;

use common::open_test_store;
use dom_store::db::TX_IDENTITY_RETENTION_BLOCKS;
use tempfile::TempDir;

fn h32(x: u8) -> [u8; 32] {
    [x; 32]
}
fn e33(x: u8) -> [u8; 33] {
    [x; 33]
}

#[test]
fn identity_roundtrips_and_reports_admission_height() {
    let dir = TempDir::new().expect("tempdir");
    let store = open_test_store(dir.path());
    store
        .put_tx_identity(&h32(0x11), &e33(0x22), 500)
        .expect("put");
    let (excess, admitted) = store
        .get_tx_identity(&h32(0x11))
        .expect("get")
        .expect("present");
    assert_eq!(excess, e33(0x22));
    assert_eq!(admitted, 500);
    assert!(store.get_tx_identity(&h32(0x99)).expect("get").is_none());
}

#[test]
fn a_reorg_that_removes_the_kernel_leaves_the_identity_entry_alone() {
    // The operative text: "The tx_hash → kernel_excess entry is NOT removed:
    // it remains a true statement about the transaction. Confirmation is
    // never asserted from that entry alone." The identity map must therefore
    // survive apply_reorg untouched, while the kernel index — the only
    // source of confirmation — loses and regains the excess.
    let dir = TempDir::new().expect("tempdir");
    let store = open_test_store(dir.path());
    let excess = e33(0x33);
    store.put_tx_identity(&h32(0x44), &excess, 10).expect("put");

    // Disconnect: the kernel leaves the canonical index.
    store
        .apply_reorg(&h32(0xAA), &[], &[], &[(excess, None)])
        .expect("reorg out");
    assert!(store.get_kernel_block(&excess).expect("get").is_none());
    assert!(
        store.get_tx_identity(&h32(0x44)).expect("get").is_some(),
        "the identity entry must survive the reorg"
    );

    // Re-mined into a different block: resolution follows the kernel index
    // to the new block, with no write to the identity map.
    store
        .apply_reorg(&h32(0xBB), &[], &[], &[(excess, Some(h32(0xB1)))])
        .expect("reorg in");
    assert_eq!(
        store.get_kernel_block(&excess).expect("get"),
        Some(h32(0xB1))
    );
}

#[test]
fn retention_prunes_by_admission_age_only() {
    let dir = TempDir::new().expect("tempdir");
    let store = open_test_store(dir.path());
    // Admitted at height 10 — expires once the chain passes
    // 10 + RETENTION; a fresh entry at the same tip must survive.
    store
        .put_tx_identity(&h32(0x01), &e33(0x01), 10)
        .expect("put old");
    let tip = 11 + TX_IDENTITY_RETENTION_BLOCKS;
    store
        .put_tx_identity(&h32(0x02), &e33(0x02), tip)
        .expect("put new");
    assert!(
        store.get_tx_identity(&h32(0x01)).expect("get").is_none(),
        "the aged entry must be pruned by the sweep"
    );
    assert!(store.get_tx_identity(&h32(0x02)).expect("get").is_some());
}

#[test]
fn an_old_store_opens_with_the_new_database() {
    // Compatibility: the ninth named database is created on open when
    // missing, and reopening preserves entries.
    let dir = TempDir::new().expect("tempdir");
    {
        let store = open_test_store(dir.path());
        store
            .put_tx_identity(&h32(0x55), &e33(0x66), 7)
            .expect("put");
    }
    let store = open_test_store(dir.path());
    let (excess, admitted) = store
        .get_tx_identity(&h32(0x55))
        .expect("get")
        .expect("survives reopen");
    assert_eq!(excess, e33(0x66));
    assert_eq!(admitted, 7);
}
