//! Roadmap v2 Phase 6.2 — ChainState corruption detection at reopen.
//!
//! `ChainState::open` is the chain-init layer that sits between the
//! raw `DomStore` (which honestly reports partial state — see
//! dom-store/tests/partial_persistence.rs) and the rest of the node.
//! It is where corruption MUST be detected and the node MUST refuse
//! to continue mining or relaying. Continuing on a corrupted state
//! would either fork the local view (height_index pointing at one
//! block while tip points at another) or accept blocks that build on
//! a hash whose body is missing.
//!
//! The contract pinned here:
//!
//!  • Tip set, header missing → open MUST fail with CHAIN_CORRUPT_SENTINEL.
//!  • Tip set, header present, body missing → open MUST fail.
//!  • Tip set, header present, body present, but `height_index[h]`
//!    points to a different hash → open MUST fail.
//!  • Tip set, header present, body present, but `height_index[h]`
//!    has no entry at all → open MUST fail.
//!  • No tip set → open succeeds (fresh / genesis-ready chain).
//!  • Healthy committed block via `commit_block` → open succeeds.
//!
//! Each failure case is fabricated by writing directly through the
//! LMDB write API on the publicly-exposed `DomStore` databases,
//! mirroring the corruption fixtures used in
//! `dom-store/tests/partial_persistence.rs`.

use dom_chain::{ChainState, CHAIN_CORRUPT_SENTINEL};
use dom_consensus::block::{BlockHeader, ProofOfWork};
use dom_core::{BlockHeight, Hash256, Timestamp, PROTOCOL_VERSION};
use dom_pow::CompactTarget;
use dom_serialization::DomSerialize;
use dom_store::utxo::UtxoEntry;
use dom_store::{DomStore, DB_BLOCKS, DB_BLOCK_BODIES, DB_BLOCK_HEIGHT, DB_CHAIN_TIP};
use lmdb::{Transaction, WriteFlags};
use primitive_types::U256;
use tempfile::TempDir;

const REGTEST_GENESIS: [u8; 32] = dom_core::GENESIS_HASH_REGTEST;

fn put_raw(store: &DomStore, db_name: &str, key: &[u8], value: &[u8]) {
    let db = match db_name {
        DB_BLOCKS => store.db_blocks,
        DB_BLOCK_BODIES => store.db_block_bodies,
        DB_BLOCK_HEIGHT => store.db_height,
        DB_CHAIN_TIP => store.db_tip,
        _ => panic!("put_raw: unknown db name {db_name}"),
    };
    let mut txn = store.env.begin_rw_txn().expect("rw txn");
    txn.put(db, &key, &value, WriteFlags::empty())
        .expect("put_raw");
    txn.commit().expect("commit");
}

fn synthetic_header(height: u64) -> Vec<u8> {
    BlockHeader {
        version: PROTOCOL_VERSION,
        height: BlockHeight(height),
        prev_hash: Hash256::ZERO,
        timestamp: Timestamp(1_704_067_200 + height),
        output_root: Hash256::ZERO,
        kernel_root: Hash256::ZERO,
        rangeproof_root: Hash256::ZERO,
        total_kernel_offset: [0u8; 32],
        target: CompactTarget(0x1f00_ffff),
        total_difficulty: U256::one(),
        pow: ProofOfWork {
            nonce: 0,
            randomx_hash: Hash256::ZERO,
        },
    }
    .to_bytes()
    .expect("serialize header")
}

fn make_hash(seed: u8) -> [u8; 32] {
    let mut h = [0u8; 32];
    h[0] = seed;
    h
}

fn open_chain(dir: &std::path::Path) -> Result<ChainState, dom_core::DomError> {
    let store = DomStore::open(dir).expect("store open");
    ChainState::open(
        store,
        Hash256::from_bytes(REGTEST_GENESIS),
        dom_core::NETWORK_MAGIC_REGTEST,
    )
}

fn err_msg<T>(r: Result<T, dom_core::DomError>) -> String {
    match r {
        Err(e) => format!("{e}"),
        Ok(_) => panic!("expected error, got Ok"),
    }
}

/// Sanity: an empty store opens as a genesis-ready chain. This is the
/// healthy baseline — corruption-detection logic must not produce
/// false positives.
#[test]
fn empty_store_opens_as_genesis_ready_chain() {
    let dir = TempDir::new().expect("tempdir");
    let chain = open_chain(dir.path()).expect("empty store must open cleanly");
    assert_eq!(chain.tip_hash, Hash256::ZERO);
    assert_eq!(chain.tip_height, BlockHeight::GENESIS);
}

/// Sanity: a healthy commit_block followed by reopen must succeed.
/// Catches a false-positive regression where the corruption checks
/// reject perfectly valid chainstate.
#[test]
fn healthy_committed_block_opens_cleanly() {
    let dir = TempDir::new().expect("tempdir");
    let hash = make_hash(0xAA);
    let header_bytes = synthetic_header(1);
    {
        let store = DomStore::open(dir.path()).expect("open");
        store
            .commit_block(
                &hash,
                1,
                &header_bytes,
                b"body",
                &[(
                    [0x02u8; 33],
                    UtxoEntry {
                        block_height: 1,
                        is_coinbase: true,
                        proof: vec![0u8; 8],
                    }
                    .to_bytes(),
                )],
                &[],
                &[([0x03u8; 33], hash)],
            )
            .expect("commit");
    }
    let chain = open_chain(dir.path()).expect("healthy state must open cleanly");
    assert_eq!(chain.tip_hash, Hash256::from_bytes(hash));
    assert_eq!(chain.tip_height, BlockHeight(1));
}

/// chain_tip set, but the header DB has nothing at that hash. open
/// MUST fail with the corrupt sentinel.
#[test]
fn tip_with_missing_header_rejected() {
    let dir = TempDir::new().expect("tempdir");
    {
        let store = DomStore::open(dir.path()).expect("open");
        let dangling = make_hash(0xBB);
        put_raw(&store, DB_CHAIN_TIP, b"tip", &dangling);
    }
    let msg = err_msg(open_chain(dir.path()));
    assert!(
        msg.contains(CHAIN_CORRUPT_SENTINEL),
        "missing-header corruption must surface the {CHAIN_CORRUPT_SENTINEL} sentinel; got: {msg}"
    );
}

/// chain_tip set, header DB has the header, but body is missing.
/// commit_block writes header + body in one txn; a header-without-body
/// state is corruption that must block reopen.
#[test]
fn tip_with_missing_body_rejected() {
    let dir = TempDir::new().expect("tempdir");
    {
        let store = DomStore::open(dir.path()).expect("open");
        let hash = make_hash(0xCC);
        put_raw(&store, DB_BLOCKS, &hash, &synthetic_header(1));
        // height_index entry agrees with the header
        let height_key = 1u64.to_le_bytes();
        put_raw(&store, DB_BLOCK_HEIGHT, &height_key, &hash);
        put_raw(&store, DB_CHAIN_TIP, b"tip", &hash);
        // body intentionally omitted
    }
    let msg = err_msg(open_chain(dir.path()));
    assert!(
        msg.contains(CHAIN_CORRUPT_SENTINEL) && msg.contains("no body"),
        "missing-body corruption must surface the sentinel + 'no body'; got: {msg}"
    );
}

/// chain_tip set, header present, body present, but the height index
/// points at a different hash at the header's height. This is the
/// most dangerous corruption — continuing to mine from here would
/// fork the local view from itself.
#[test]
fn tip_with_diverging_height_index_rejected() {
    let dir = TempDir::new().expect("tempdir");
    {
        let store = DomStore::open(dir.path()).expect("open");
        let hash = make_hash(0xDD);
        let other = make_hash(0xEE);
        put_raw(&store, DB_BLOCKS, &hash, &synthetic_header(1));
        put_raw(&store, DB_BLOCK_BODIES, &hash, b"body");
        let height_key = 1u64.to_le_bytes();
        put_raw(&store, DB_BLOCK_HEIGHT, &height_key, &other); // diverges
        put_raw(&store, DB_CHAIN_TIP, b"tip", &hash);
    }
    let msg = err_msg(open_chain(dir.path()));
    assert!(
        msg.contains(CHAIN_CORRUPT_SENTINEL) && msg.contains("height_index"),
        "diverging-height-index corruption must surface the sentinel + 'height_index'; got: {msg}"
    );
}

/// chain_tip set, header present, body present, but the height index
/// has no entry at all at the header's height.
#[test]
fn tip_with_no_height_index_entry_rejected() {
    let dir = TempDir::new().expect("tempdir");
    {
        let store = DomStore::open(dir.path()).expect("open");
        let hash = make_hash(0xFF);
        put_raw(&store, DB_BLOCKS, &hash, &synthetic_header(1));
        put_raw(&store, DB_BLOCK_BODIES, &hash, b"body");
        put_raw(&store, DB_CHAIN_TIP, b"tip", &hash);
        // height_index intentionally empty
    }
    let msg = err_msg(open_chain(dir.path()));
    assert!(
        msg.contains(CHAIN_CORRUPT_SENTINEL) && msg.contains("no height_index entry"),
        "missing-height-index corruption must surface sentinel + 'no height_index entry'; got: {msg}"
    );
}
