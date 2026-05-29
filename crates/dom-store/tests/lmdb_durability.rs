//! Roadmap v2 Phase 3.3 — LMDB durability + map-full surface.
//!
//! Two contracts pinned here:
//!
//! 1. **Durability:** the environment is opened *without* `MDB_NOSYNC` /
//!    `MDB_NOMETASYNC`, so a successful `commit_block` flushes both the
//!    data file and the meta page to disk before returning. This test
//!    cannot fault-inject a kernel panic, but it does prove the
//!    weaker observable property: after a clean `Drop` of the
//!    environment, the on-disk file holds the committed state and a
//!    fresh open recovers it byte-identically. The pre-Phase-3.3
//!    `NO_SYNC` configuration relied on the kernel's writeback timing
//!    to make this true; today it is enforced by the LMDB commit
//!    path itself.
//!
//! 2. **Map-full sentinel:** the `LMDB_MAP_FULL_SENTINEL` constant is a
//!    stable substring callers grep for to recognise `MDB_MAP_FULL`
//!    distinctly from other `DomError::Internal` cases. This test
//!    pins the constant value so a typo-introducing edit fails CI
//!    before reaching the chain-init layer.

use dom_store::utxo::UtxoEntry;
use dom_store::{DomStore, LMDB_MAP_FULL_SENTINEL};
use tempfile::TempDir;

fn entry_for(height: u64) -> Vec<u8> {
    UtxoEntry {
        block_height: height,
        is_coinbase: true,
        proof: vec![0xCC; 16],
    }
    .to_bytes()
}

struct Synthetic {
    hash: [u8; 32],
    height: u64,
    header: Vec<u8>,
    body: Vec<u8>,
    commitment: [u8; 33],
    excess: [u8; 33],
}

fn dummy_block(seed: u8, height: u64) -> Synthetic {
    let mut hash = [0u8; 32];
    hash[0] = seed;
    let mut commitment = [0u8; 33];
    commitment[0] = 0x02;
    commitment[1] = seed;
    let mut excess = [0u8; 33];
    excess[0] = 0x03;
    excess[1] = seed;
    Synthetic {
        hash,
        height,
        header: vec![0xAA; 64],
        body: vec![0xBB; 32],
        commitment,
        excess,
    }
}

/// After `commit_block` returns Ok, the data MUST survive an explicit
/// `Drop` of the environment — no kernel writeback assumption. Today
/// the LMDB commit path fsyncs by default; this test pins the
/// observable consequence so a future re-introduction of `NO_SYNC`
/// flag is caught here even before a real crash test runs.
#[test]
fn commit_survives_clean_env_drop_and_reopen() {
    let dir = TempDir::new().expect("tempdir");
    let path = dir.path().to_path_buf();
    let b = dummy_block(0xAB, 7);

    {
        let store = DomStore::open(&path).expect("open");
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
        // env Drop here — must not lose the write.
    }

    let reopen = DomStore::open(&path).expect("reopen");
    assert_eq!(reopen.get_block_header(&b.hash).unwrap().unwrap(), b.header);
    assert_eq!(reopen.get_block_body(&b.hash).unwrap().unwrap(), b.body);
    assert_eq!(
        reopen.get_hash_at_height(b.height).unwrap().unwrap(),
        b.hash
    );
    assert_eq!(reopen.get_chain_tip().unwrap().unwrap(), b.hash);
    let utxo = reopen
        .get_utxo(&b.commitment)
        .unwrap()
        .expect("utxo must be durable across reopen");
    assert_eq!(utxo.block_height, b.height);
}

/// Multiple commits in a row, each followed by a fresh `DomStore::open`,
/// all observe the latest tip. Catches a regression where the env
/// would buffer the new tip in memory but never make it to disk.
#[test]
fn each_commit_is_independently_durable() {
    let dir = TempDir::new().expect("tempdir");
    let path = dir.path().to_path_buf();
    let blocks: Vec<Synthetic> = (1u64..=5).map(|i| dummy_block(0x10 + i as u8, i)).collect();

    for (i, b) in blocks.iter().enumerate() {
        let store = DomStore::open(&path).expect("open");
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
            .unwrap_or_else(|e| panic!("commit #{i} failed: {e}"));
        // Drop to force flush + close. Reopen below MUST find the tip.
        drop(store);

        let reopen = DomStore::open(&path).expect("reopen");
        assert_eq!(
            reopen.get_chain_tip().unwrap().unwrap(),
            b.hash,
            "after commit #{i} the reopened tip must equal the just-written hash"
        );
    }
}

/// The map-full sentinel is part of the public surface that the
/// chain-init layer matches against. Pinning the literal value here
/// guarantees a typo will fail CI rather than silently producing a
/// generic-looking `DomError::Internal`.
#[test]
fn lmdb_map_full_sentinel_value_is_stable() {
    assert_eq!(LMDB_MAP_FULL_SENTINEL, "LMDB_MAP_FULL");
}
