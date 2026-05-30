//! Roadmap v2 Phase 3.1 — Storage Crash Consistency invariants.
//!
//! These tests do not actually SIGKILL the process — that lives in a
//! separate harness (see TODO in Phase 3.1 follow-up). What they
//! enforce here is the *consistency contract* the LMDB layer is
//! supposed to uphold, namely:
//!
//! 1. `commit_block` is atomic. After it returns `Ok`, every persisted
//!    relation derived from that block (header, body, height -> hash,
//!    tip, utxos created, kernels indexed) is visible on the next
//!    read txn.
//! 2. After dropping and re-opening the environment, the same
//!    relations are still consistent — no header-without-body,
//!    no tip pointing at an unknown block, no dangling height -> hash
//!    mappings.
//! 3. Re-committing the same block hash is rejected by the
//!    `NO_OVERWRITE` write flag (DOM-LMDB-001). A consensus bypass
//!    that allowed this to fire silently would be a security bug;
//!    the store must surface it as an explicit error.
//!
//! Together these properties guarantee that an interrupted /
//! restarted node will never observe a partially-persisted block on
//! the next start, even before the upcoming SIGKILL harness.

mod common;

use common::open_test_store;
use dom_store::utxo::UtxoEntry;
use tempfile::TempDir;

/// Synthetic block components for commit_block — opaque bytes are fine
/// because dom-store does not parse them; that's dom-consensus's job.
struct Synthetic {
    hash: [u8; 32],
    height: u64,
    header: Vec<u8>,
    body: Vec<u8>,
    commitment: [u8; 33],
    excess: [u8; 33],
}

fn dummy_block(hash_seed: u8, height: u64) -> Synthetic {
    let mut hash = [0u8; 32];
    hash[0] = hash_seed;
    let mut commitment = [0u8; 33];
    commitment[0] = 0x02;
    commitment[1] = hash_seed;
    let mut excess = [0u8; 33];
    excess[0] = 0x03;
    excess[1] = hash_seed;
    Synthetic {
        hash,
        height,
        header: vec![0xAA; 64],
        body: vec![0xBB; 32],
        commitment,
        excess,
    }
}

fn entry_for(height: u64) -> Vec<u8> {
    let e = UtxoEntry {
        block_height: height,
        is_coinbase: true,
        proof: vec![0xCC; 16],
    };
    e.to_bytes()
}

#[test]
fn commit_block_persists_all_five_relations() {
    let dir = TempDir::new().expect("tempdir");
    let store = open_test_store(dir.path());
    let b = dummy_block(0x11, 1);

    store
        .commit_block(
            &b.hash,
            b.height,
            &b.header,
            &b.body,
            &[(b.commitment, entry_for(b.height))],
            &[],
            &[(b.excess, b.hash)],
        )
        .expect("commit_block");

    // Five reads — each must observe its persisted record.
    assert_eq!(store.get_block_header(&b.hash).unwrap().unwrap(), b.header);
    assert_eq!(store.get_block_body(&b.hash).unwrap().unwrap(), b.body);
    assert_eq!(store.get_hash_at_height(b.height).unwrap().unwrap(), b.hash);
    assert_eq!(store.get_chain_tip().unwrap().unwrap(), b.hash);
    assert!(store.get_utxo(&b.commitment).unwrap().is_some());
}

#[test]
fn reopen_observes_identical_committed_state() {
    let dir = TempDir::new().expect("tempdir");
    let b = dummy_block(0x22, 1);

    {
        let store = open_test_store(dir.path());
        store
            .commit_block(
                &b.hash,
                b.height,
                &b.header,
                &b.body,
                &[(b.commitment, entry_for(b.height))],
                &[],
                &[(b.excess, b.hash)],
            )
            .expect("commit_block");
    }
    // env dropped here — LMDB file holds the persisted state.

    let store = open_test_store(dir.path());
    assert_eq!(store.get_block_header(&b.hash).unwrap().unwrap(), b.header);
    assert_eq!(store.get_block_body(&b.hash).unwrap().unwrap(), b.body);
    assert_eq!(store.get_hash_at_height(b.height).unwrap().unwrap(), b.hash);
    assert_eq!(store.get_chain_tip().unwrap().unwrap(), b.hash);
    let utxo = store
        .get_utxo(&b.commitment)
        .unwrap()
        .expect("utxo present");
    assert_eq!(utxo.block_height, b.height);
    assert!(utxo.is_coinbase);
}

#[test]
fn committing_same_hash_twice_is_rejected() {
    let dir = TempDir::new().expect("tempdir");
    let store = open_test_store(dir.path());
    let b = dummy_block(0x33, 1);

    store
        .commit_block(
            &b.hash,
            b.height,
            &b.header,
            &b.body,
            &[(b.commitment, entry_for(b.height))],
            &[],
            &[(b.excess, b.hash)],
        )
        .expect("first commit");

    // Second commit with the same hash must surface NO_OVERWRITE as an
    // explicit error (DOM-LMDB-001). Using a fresh kernel excess so the
    // failure is attributable to the block-hash collision rather than
    // the kernel-index collision.
    let mut excess_b = [0u8; 33];
    excess_b[0] = 0x03;
    excess_b[1] = 0x99;
    let err = store
        .commit_block(
            &b.hash,
            b.height,
            &b.header,
            &b.body,
            &[],
            &[],
            &[(excess_b, b.hash)],
        )
        .expect_err("duplicate hash must error");
    let msg = format!("{err}");
    assert!(
        msg.contains("block header already exists"),
        "expected explicit dedup-bypass error, got: {msg}"
    );
}

#[test]
fn no_orphan_header_without_body_after_commit() {
    // The LMDB transaction is atomic per RFC-0007 step 14. We exercise
    // both writes via the public API: if either failed without the
    // other rolling back, the assertion below would catch it.
    let dir = TempDir::new().expect("tempdir");
    let store = open_test_store(dir.path());
    for seed in 0..8u8 {
        let b = dummy_block(seed, seed as u64 + 1);
        store
            .commit_block(
                &b.hash,
                b.height,
                &b.header,
                &b.body,
                &[(b.commitment, entry_for(b.height))],
                &[],
                &[(b.excess, b.hash)],
            )
            .expect("commit");
    }

    // Every block hash that has a header must also have a body.
    for seed in 0..8u8 {
        let mut hash = [0u8; 32];
        hash[0] = seed;
        let header_present = store.get_block_header(&hash).unwrap().is_some();
        let body_present = store.get_block_body(&hash).unwrap().is_some();
        assert_eq!(
            header_present, body_present,
            "header/body presence diverged at seed {seed}"
        );
    }
}

#[test]
fn store_known_block_does_not_mutate_canonical_state() {
    let dir = TempDir::new().expect("tempdir");
    let store = open_test_store(dir.path());
    let canonical = dummy_block(0x44, 1);
    let side = dummy_block(0x55, 1);

    store
        .commit_block(
            &canonical.hash,
            canonical.height,
            &canonical.header,
            &canonical.body,
            &[(canonical.commitment, entry_for(canonical.height))],
            &[],
            &[(canonical.excess, canonical.hash)],
        )
        .expect("canonical commit");

    store
        .store_known_block(&side.hash, &side.header, &side.body)
        .expect("known side block");

    assert_eq!(
        store.get_chain_tip().unwrap().unwrap(),
        canonical.hash,
        "known side block must not rewrite chain_tip",
    );
    assert_eq!(
        store.get_hash_at_height(canonical.height).unwrap().unwrap(),
        canonical.hash,
        "known side block must not rewrite canonical height index",
    );
    assert_eq!(
        store.get_block_header(&side.hash).unwrap().unwrap(),
        side.header,
        "known side block header should be retained by hash",
    );
    assert_eq!(
        store.get_block_body(&side.hash).unwrap().unwrap(),
        side.body,
        "known side block body should be retained by hash",
    );
    assert!(
        store.get_utxo(&side.commitment).unwrap().is_none(),
        "known side block must not mutate canonical UTXO set",
    );
}
