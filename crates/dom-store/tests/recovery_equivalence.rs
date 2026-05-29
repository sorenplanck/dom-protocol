//! Roadmap v2 Phase 6.1 — Recovery bit-for-bit equivalence.
//!
//! These tests are the empirical proof that DOM storage is
//! deterministically equivalent across:
//!
//!   (a) **two independent data directories** receiving the
//!       same `commit_block` sequence in the same order;
//!   (b) **drop-and-reopen** of a single data directory
//!       (the "wipe nothing, just restart" recovery shape);
//!   (c) **N successive reopens** with no commits in between
//!       (idempotent reload).
//!
//! The harness intentionally bypasses RandomX PoW validation by
//! exercising `DomStore::commit_block` directly with synthetic
//! header/body bytes. This is sound for the deterministic
//! equivalence property — the store doesn't parse blocks, so the
//! bit-equivalence we pin here is the storage layer's invariant.
//! The chain-state-level equivalence with full PoW validation is
//! the heavier `replay_determinism` integration test (RB-PMMR-001
//! deferred to dedicated mining host).
//!
//! Method: an LMDB-cursor snapshot helper walks every named
//! database and captures every (key, value) pair into a sorted
//! BTreeMap. Two snapshots are byte-identical iff every database
//! contains the same set of entries with byte-identical values.

use dom_store::utxo::UtxoEntry;
use dom_store::{
    DomStore, DB_BLOCKS, DB_BLOCK_BODIES, DB_BLOCK_HEIGHT, DB_CHAIN_TIP, DB_KERNEL_INDEX, DB_UTXOS,
};
use lmdb::{Cursor, Database, Transaction};
use std::collections::BTreeMap;
use tempfile::TempDir;

/// Full snapshot of a `DomStore` — every (db_name, key, value) tuple
/// across every named database. BTreeMap ordering makes equality
/// stable and the failure message readable.
type DbSnapshot = BTreeMap<&'static str, BTreeMap<Vec<u8>, Vec<u8>>>;

fn snapshot(store: &DomStore) -> DbSnapshot {
    fn dump(store: &DomStore, db: Database) -> BTreeMap<Vec<u8>, Vec<u8>> {
        let txn = store.env.begin_ro_txn().expect("ro txn");
        let mut cursor = txn.open_ro_cursor(db).expect("open cursor");
        let mut out = BTreeMap::new();
        for (k, v) in cursor.iter() {
            out.insert(k.to_vec(), v.to_vec());
        }
        out
    }
    let mut snap = BTreeMap::new();
    snap.insert(DB_BLOCKS, dump(store, store.db_blocks));
    snap.insert(DB_BLOCK_BODIES, dump(store, store.db_block_bodies));
    snap.insert(DB_BLOCK_HEIGHT, dump(store, store.db_height));
    snap.insert(DB_CHAIN_TIP, dump(store, store.db_tip));
    snap.insert(DB_UTXOS, dump(store, store.db_utxos));
    snap.insert(DB_KERNEL_INDEX, dump(store, store.db_kernels));
    snap
}

/// Synthetic block fixture — deterministic in `(seed, height)`.
/// The fields are opaque bytes; the store doesn't parse them, so
/// determinism here is purely a function of the inputs.
struct Synthetic {
    hash: [u8; 32],
    height: u64,
    header: Vec<u8>,
    body: Vec<u8>,
    commit: [u8; 33],
    excess: [u8; 33],
}

fn synth(seed: u8, height: u64) -> Synthetic {
    let mut hash = [0u8; 32];
    hash[0] = seed;
    hash[1] = (height & 0xff) as u8;
    hash[2] = ((height >> 8) & 0xff) as u8;
    let mut commit = [0u8; 33];
    commit[0] = 0x02;
    commit[1] = seed;
    commit[2] = (height & 0xff) as u8;
    let mut excess = [0u8; 33];
    excess[0] = 0x03;
    excess[1] = seed;
    excess[2] = (height & 0xff) as u8;
    let mut header = vec![0xAA; 96];
    header[0..32].copy_from_slice(&hash);
    let mut body = vec![0xBB; 64];
    body[0] = seed;
    body[1..9].copy_from_slice(&height.to_le_bytes());
    Synthetic {
        hash,
        height,
        header,
        body,
        commit,
        excess,
    }
}

fn utxo_entry(height: u64) -> Vec<u8> {
    UtxoEntry {
        block_height: height,
        is_coinbase: true,
        proof: vec![0xCC; 16],
    }
    .to_bytes()
}

/// Apply the same fixed sequence of N synthetic commits to a
/// fresh `DomStore` at `path`. Returns the populated store so the
/// caller can snapshot before drop.
fn apply_sequence(path: &std::path::Path, n: u64) -> DomStore {
    let store = DomStore::open(path).expect("open");
    for h in 1..=n {
        let b = synth(0x42, h);
        store
            .commit_block(
                &b.hash,
                b.height,
                &b.header,
                &b.body,
                &[(b.commit, utxo_entry(b.height))],
                &[],
                &[(b.excess, b.hash)],
            )
            .unwrap_or_else(|e| panic!("commit h={h} failed: {e}"));
    }
    store
}

fn snapshots_equal(a: &DbSnapshot, b: &DbSnapshot) -> Result<(), String> {
    if a.keys().collect::<Vec<_>>() != b.keys().collect::<Vec<_>>() {
        return Err(format!(
            "database set differs: a={:?} b={:?}",
            a.keys().collect::<Vec<_>>(),
            b.keys().collect::<Vec<_>>()
        ));
    }
    for (db, a_db) in a {
        let b_db = b.get(db).expect("db present");
        if a_db != b_db {
            // Find the first differing key for a readable message.
            let mut a_iter = a_db.iter();
            let mut b_iter = b_db.iter();
            loop {
                match (a_iter.next(), b_iter.next()) {
                    (Some((ka, va)), Some((kb, vb))) => {
                        if ka != kb {
                            return Err(format!(
                                "db {db}: key mismatch — a={} b={}",
                                hex::encode(ka),
                                hex::encode(kb)
                            ));
                        }
                        if va != vb {
                            return Err(format!(
                                "db {db}: value mismatch at key {} — a={} b={}",
                                hex::encode(ka),
                                hex::encode(va),
                                hex::encode(vb)
                            ));
                        }
                    }
                    (None, None) => break,
                    (a_entry, b_entry) => {
                        return Err(format!(
                            "db {db}: length mismatch — a={:?} b={:?}",
                            a_entry, b_entry
                        ));
                    }
                }
            }
        }
    }
    Ok(())
}

// ── (1) Cross-instance deterministic equivalence ─────────────────────────────

/// Two completely independent `DomStore` instances receiving the
/// same `commit_block` sequence MUST end with byte-identical
/// state across every named database. This is the foundational
/// determinism invariant DOM consensus relies on.
#[test]
fn two_independent_stores_with_same_sequence_produce_identical_state() {
    let dir_a = TempDir::new().expect("dir A");
    let dir_b = TempDir::new().expect("dir B");

    let store_a = apply_sequence(dir_a.path(), 25);
    let store_b = apply_sequence(dir_b.path(), 25);

    let snap_a = snapshot(&store_a);
    let snap_b = snapshot(&store_b);

    snapshots_equal(&snap_a, &snap_b).unwrap_or_else(|e| {
        panic!("two-store equivalence failed: {e}");
    });
}

// ── (2) Drop-and-reopen equivalence ──────────────────────────────────────────

/// A store dropped and reopened against the same `data_dir` MUST
/// snapshot byte-identical to the pre-drop state. This is the
/// recovery invariant a clean shutdown / restart depends on.
#[test]
fn drop_and_reopen_observes_identical_state() {
    let dir = TempDir::new().expect("dir");
    let path = dir.path().to_path_buf();

    let pre_snapshot = {
        let store = apply_sequence(&path, 15);
        snapshot(&store)
    }; // env dropped here

    let store_reopened = DomStore::open(&path).expect("reopen");
    let post_snapshot = snapshot(&store_reopened);

    snapshots_equal(&pre_snapshot, &post_snapshot).unwrap_or_else(|e| {
        panic!("reopen equivalence failed: {e}");
    });
}

// ── (3) Idempotent reload — N successive reopens ─────────────────────────────

/// 8 successive opens of the same on-disk state MUST each
/// produce byte-identical snapshots. Catches a regression where
/// open/close races could mutate the file (e.g. via spurious
/// meta-page rewrites).
#[test]
fn n_successive_reopens_yield_identical_snapshots() {
    let dir = TempDir::new().expect("dir");
    let path = dir.path().to_path_buf();
    {
        let _ = apply_sequence(&path, 10);
    }

    let baseline = {
        let store = DomStore::open(&path).expect("first reopen");
        snapshot(&store)
    };
    for round in 0..8 {
        let store = DomStore::open(&path).expect("round reopen");
        let snap = snapshot(&store);
        snapshots_equal(&baseline, &snap).unwrap_or_else(|e| {
            panic!("reopen round {round} diverged: {e}");
        });
    }
}

// ── (4) Cross-instance equivalence under longer sequence ─────────────────────

/// Same as (1) with a longer sequence (100 blocks) and richer
/// per-block state (multiple UTXOs spent and created per block).
/// Designed to surface any state-machine bookkeeping bug that
/// only manifests at scale.
#[test]
fn cross_instance_equivalence_holds_for_long_sequence() {
    fn apply_long(path: &std::path::Path, n: u64) -> DomStore {
        let store = DomStore::open(path).expect("open");
        for h in 1..=n {
            let b = synth(0xA5, h);
            // Create 2 new UTXOs every block.
            let mut c2 = b.commit;
            c2[3] = 0xFF;
            // Spend the previous block's primary commitment from h ≥ 2.
            let spent: Vec<[u8; 33]> = if h > 1 {
                let prev = synth(0xA5, h - 1);
                vec![prev.commit]
            } else {
                vec![]
            };
            store
                .commit_block(
                    &b.hash,
                    b.height,
                    &b.header,
                    &b.body,
                    &[(b.commit, utxo_entry(b.height)), (c2, utxo_entry(b.height))],
                    &spent,
                    &[(b.excess, b.hash)],
                )
                .unwrap_or_else(|e| panic!("long-seq commit h={h}: {e}"));
        }
        store
    }

    let dir_a = TempDir::new().expect("dir A");
    let dir_b = TempDir::new().expect("dir B");
    let store_a = apply_long(dir_a.path(), 100);
    let store_b = apply_long(dir_b.path(), 100);
    snapshots_equal(&snapshot(&store_a), &snapshot(&store_b)).unwrap_or_else(|e| {
        panic!("long-sequence cross-instance divergence: {e}");
    });
}

// ── (5) Empty-store equivalence baseline ─────────────────────────────────────

/// Two freshly-opened stores with zero commits MUST snapshot
/// identically (both empty across every DB). Sanity baseline so
/// the equivalence harness doesn't trivially pass on a no-op
/// state.
#[test]
fn two_empty_stores_snapshot_identically() {
    let dir_a = TempDir::new().expect("a");
    let dir_b = TempDir::new().expect("b");
    let store_a = DomStore::open(dir_a.path()).expect("a");
    let store_b = DomStore::open(dir_b.path()).expect("b");
    snapshots_equal(&snapshot(&store_a), &snapshot(&store_b)).unwrap_or_else(|e| {
        panic!("empty-store equivalence failed: {e}");
    });
}

// ── (6) Negative control — diverging input yields diverging state ────────────

/// Sanity: if we apply different sequences to two stores, the
/// snapshots MUST diverge. Catches a regression where `snapshots_equal`
/// would erroneously claim equivalence regardless of input.
#[test]
fn diverging_sequences_yield_diverging_snapshots() {
    let dir_a = TempDir::new().expect("a");
    let dir_b = TempDir::new().expect("b");
    let _ = apply_sequence(dir_a.path(), 5);
    let _ = apply_sequence(dir_b.path(), 7); // different length
    let store_a = DomStore::open(dir_a.path()).expect("a reopen");
    let store_b = DomStore::open(dir_b.path()).expect("b reopen");
    let result = snapshots_equal(&snapshot(&store_a), &snapshot(&store_b));
    assert!(
        result.is_err(),
        "snapshots_equal must detect 5-block vs 7-block divergence; got Ok()"
    );
}
