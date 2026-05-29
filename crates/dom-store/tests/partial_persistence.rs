//! Roadmap v2 Phase 3.2 — Partial persistence detection.
//!
//! The SIGKILL harness in `crash_consistency_sigkill.rs` showed the
//! atomicity contract of `commit_block` holds against process kill:
//! header and body are always coupled. That leaves a separate question:
//!
//!   *If something else* — a future refactor that splits commit_block
//!   across two transactions, an external corruption tool, a manual
//!   recovery operation — *did* leave the store in a partial state,
//!   what is the observable contract?
//!
//! This file pins that contract by fabricating each kind of partial
//! state directly via the LMDB write API (bypassing `commit_block` so
//! we are not constrained by its NO_OVERWRITE check) and then
//! re-opening the store to verify that:
//!
//! - DomStore::open succeeds. The store does not refuse to open just
//!   because the on-disk state is partially populated; refusing here
//!   would deny callers the ability to inspect and repair.
//! - The read API surfaces the partial state honestly: `Some` for the
//!   side that was written, `None` for the side that was not. No
//!   silent reconstruction, no panics.
//! - Pointer relations (`chain_tip → block`, `height → hash`,
//!   `kernel → block_hash`) keep pointing at the dangling hash, again
//!   reporting `None` to callers when the target is dereferenced.
//!
//! These guarantees are what the chain-init layer (above DomStore)
//! relies on to detect a partial state and take corrective action
//! (currently: log + abort; ROADMAP v2 phase 6 adds rebuild-from-genesis).
//!
//! What is *not* tested here:
//! - `commit_block` does not produce these partial states on its own.
//!   That property is covered by the SIGKILL harness.
//! - The chain-init layer's recovery policy is owned by `dom-chain`.

use dom_store::utxo::UtxoEntry;
use dom_store::{
    DomStore, DB_BLOCKS, DB_BLOCK_BODIES, DB_BLOCK_HEIGHT, DB_CHAIN_TIP, DB_KERNEL_INDEX,
};
use lmdb::{Transaction, WriteFlags};
use tempfile::TempDir;

fn put_raw(store: &DomStore, db_name: &str, key: &[u8], value: &[u8]) {
    let db = match db_name {
        DB_BLOCKS => store.db_blocks,
        DB_BLOCK_BODIES => store.db_block_bodies,
        DB_BLOCK_HEIGHT => store.db_height,
        DB_CHAIN_TIP => store.db_tip,
        DB_KERNEL_INDEX => store.db_kernels,
        _ => panic!("put_raw: unknown db name {db_name}"),
    };
    let mut txn = store.env.begin_rw_txn().expect("rw txn");
    txn.put(db, &key, &value, WriteFlags::empty())
        .expect("put_raw");
    txn.commit().expect("commit");
}

fn make_hash(seed: u8) -> [u8; 32] {
    let mut h = [0u8; 32];
    h[0] = seed;
    h
}

#[test]
fn orphan_header_without_body_is_observable_after_reopen() {
    let dir = TempDir::new().expect("tempdir");
    {
        let store = DomStore::open(dir.path()).expect("open");
        // Header written, body never written — simulates a future buggy
        // commit_block that split its writes across transactions, or a
        // manual recovery that restored a header backup but lost bodies.
        let hash = make_hash(0x11);
        put_raw(&store, DB_BLOCKS, &hash, &[0xAAu8; 64]);
    }
    // env dropped — re-open from disk.
    let store = DomStore::open(dir.path()).expect("reopen");
    let hash = make_hash(0x11);
    assert!(
        store.get_block_header(&hash).expect("get header").is_some(),
        "header that was written must still be observable after reopen",
    );
    assert!(
        store.get_block_body(&hash).expect("get body").is_none(),
        "body that was never written must surface as None — store must not fabricate",
    );
}

#[test]
fn orphan_body_without_header_is_observable_after_reopen() {
    let dir = TempDir::new().expect("tempdir");
    {
        let store = DomStore::open(dir.path()).expect("open");
        let hash = make_hash(0x22);
        put_raw(&store, DB_BLOCK_BODIES, &hash, &[0xBBu8; 32]);
    }
    let store = DomStore::open(dir.path()).expect("reopen");
    let hash = make_hash(0x22);
    assert!(
        store.get_block_header(&hash).expect("get header").is_none(),
        "header that was never written must surface as None",
    );
    assert!(
        store.get_block_body(&hash).expect("get body").is_some(),
        "body that was written must still be observable",
    );
}

#[test]
fn dangling_height_pointer_to_unknown_hash_is_observable() {
    let dir = TempDir::new().expect("tempdir");
    {
        let store = DomStore::open(dir.path()).expect("open");
        let height_key = 7u64.to_le_bytes();
        let dangling_hash = make_hash(0x33);
        put_raw(&store, DB_BLOCK_HEIGHT, &height_key, &dangling_hash);
        // intentionally do NOT write the block at this hash
    }
    let store = DomStore::open(dir.path()).expect("reopen");
    let mapped = store.get_hash_at_height(7).expect("get_hash_at_height");
    assert!(
        mapped.is_some(),
        "the height pointer survived reopen — must still report Some",
    );
    let hash = mapped.unwrap();
    assert!(
        store.get_block_header(&hash).expect("get header").is_none(),
        "dereferenced dangling height pointer must report a missing block honestly",
    );
}

#[test]
fn dangling_chain_tip_pointer_is_observable() {
    let dir = TempDir::new().expect("tempdir");
    {
        let store = DomStore::open(dir.path()).expect("open");
        let tip_hash = make_hash(0x44);
        put_raw(&store, DB_CHAIN_TIP, b"tip", &tip_hash);
    }
    let store = DomStore::open(dir.path()).expect("reopen");
    let tip = store.get_chain_tip().expect("get_chain_tip");
    assert_eq!(
        tip,
        Some(make_hash(0x44)),
        "tip pointer must be returned verbatim — the store does not silently null it out",
    );
    assert!(
        store
            .get_block_header(&tip.unwrap())
            .expect("get header")
            .is_none(),
        "tip target must report missing — chain-init layer's job to detect and react",
    );
}

#[test]
fn dangling_kernel_index_entry_is_observable_via_block_lookup() {
    let dir = TempDir::new().expect("tempdir");
    {
        let store = DomStore::open(dir.path()).expect("open");
        let mut excess = [0u8; 33];
        excess[0] = 0x03;
        excess[1] = 0x55;
        let block_hash = make_hash(0x55);
        put_raw(&store, DB_KERNEL_INDEX, &excess, &block_hash);
    }
    let store = DomStore::open(dir.path()).expect("reopen");
    // The kernel index keeps pointing at the (missing) block.
    assert!(
        store
            .get_block_header(&make_hash(0x55))
            .expect("get header")
            .is_none(),
        "kernel index points at a block whose header is missing — surfaced honestly",
    );
}

#[test]
fn store_does_not_panic_when_reopened_with_arbitrary_partial_state() {
    // Combination of every partial state at once. The point is solely
    // to assert that reopen + read methods survive — no panic, no
    // unwrap explosion, no silent reconstruction. Diagnostic-style
    // catch-all so a future regression in any read path is caught
    // without having to enumerate cases.
    let dir = TempDir::new().expect("tempdir");
    {
        let store = DomStore::open(dir.path()).expect("open");

        put_raw(&store, DB_BLOCKS, &make_hash(0x60), &[0u8; 32]);
        put_raw(&store, DB_BLOCK_BODIES, &make_hash(0x61), &[0u8; 16]);
        put_raw(
            &store,
            DB_BLOCK_HEIGHT,
            &42u64.to_le_bytes(),
            &make_hash(0x62),
        );
        put_raw(&store, DB_CHAIN_TIP, b"tip", &make_hash(0x63));
        let mut excess = [0u8; 33];
        excess[0] = 0x03;
        put_raw(&store, DB_KERNEL_INDEX, &excess, &make_hash(0x64));
    }
    let store = DomStore::open(dir.path()).expect("reopen");

    // Every read method must complete without panic and return its
    // documented Option/Result type, regardless of the on-disk mess.
    let _ = store.get_block_header(&make_hash(0x60)).unwrap();
    let _ = store.get_block_body(&make_hash(0x60)).unwrap();
    let _ = store.get_block_header(&make_hash(0x61)).unwrap();
    let _ = store.get_block_body(&make_hash(0x61)).unwrap();
    let _ = store.get_hash_at_height(42).unwrap();
    let _ = store.get_chain_tip().unwrap();
    let _ = store.get_utxo(&[0u8; 33]).unwrap();
}

#[test]
fn commit_block_on_clean_store_still_works_after_unrelated_partial_state() {
    // Partial state at one hash must not contaminate a subsequent
    // commit_block at a different hash. This pins the property that
    // the partial-state region of the store is *inert* — it does not
    // poison the path for callers who supply fresh, complete inputs.
    let dir = TempDir::new().expect("tempdir");
    {
        let store = DomStore::open(dir.path()).expect("open");
        put_raw(&store, DB_BLOCKS, &make_hash(0x70), &[0xCCu8; 16]);
    }
    let store = DomStore::open(dir.path()).expect("reopen");

    let clean_hash = make_hash(0x71);
    let mut commitment = [0u8; 33];
    commitment[0] = 0x02;
    commitment[1] = 0x71;
    let mut excess = [0u8; 33];
    excess[0] = 0x03;
    excess[1] = 0x71;
    store
        .commit_block(
            &clean_hash,
            1,
            &[0xAAu8; 64],
            &[0xBBu8; 32],
            &[(
                commitment,
                UtxoEntry {
                    block_height: 1,
                    is_coinbase: true,
                    proof: vec![0xCC; 16],
                }
                .to_bytes(),
            )],
            &[],
            &[(excess, clean_hash)],
        )
        .expect("commit_block on clean hash must succeed despite unrelated partial state");

    assert!(store
        .get_block_header(&clean_hash)
        .expect("get header")
        .is_some(),);
    assert!(store
        .get_block_body(&clean_hash)
        .expect("get body")
        .is_some(),);
}
