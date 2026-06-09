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

mod common;

use blake2::digest::consts::U32;
use blake2::{Blake2b, Digest};
use common::{open_test_chain, open_test_store};
use dom_chain::{ChainState, CHAIN_CORRUPT_SENTINEL};
use dom_consensus::block::{BlockHeader, ProofOfWork};
use dom_consensus::{Block, CoinbaseKernel, CoinbaseTransaction, TransactionOutput};
use dom_core::{BlockHeight, Hash256, Timestamp, KERNEL_FEAT_COINBASE, PROTOCOL_VERSION};
use dom_crypto::pedersen::{BlindingFactor, Commitment};
use dom_pow::CompactTarget;
use dom_serialization::DomSerialize;
use dom_store::utxo::UtxoEntry;
use dom_store::{
    DomStore, DB_BLOCKS, DB_BLOCK_BODIES, DB_BLOCK_HEIGHT, DB_CHAIN_TIP, DB_METADATA, DB_UTXOS,
    METADATA_UTXO_SET_DIGEST_KEY,
};
use lmdb::{Cursor, Database, Transaction, WriteFlags};
use primitive_types::U256;
use std::collections::BTreeMap;
use tempfile::TempDir;

const REGTEST_GENESIS: [u8; 32] = dom_core::GENESIS_HASH_REGTEST;

fn put_raw(store: &DomStore, db_name: &str, key: &[u8], value: &[u8]) {
    let db = match db_name {
        DB_BLOCKS => store.db_blocks,
        DB_BLOCK_BODIES => store.db_block_bodies,
        DB_BLOCK_HEIGHT => store.db_height,
        DB_CHAIN_TIP => store.db_tip,
        DB_UTXOS => store.db_utxos,
        DB_METADATA => store.db_metadata,
        _ => panic!("put_raw: unknown db name {db_name}"),
    };
    let mut txn = store.env.begin_rw_txn().expect("rw txn");
    txn.put(db, &key, &value, WriteFlags::empty())
        .expect("put_raw");
    txn.commit().expect("commit");
}

fn delete_raw(store: &DomStore, db_name: &str, key: &[u8]) {
    let db = match db_name {
        DB_BLOCKS => store.db_blocks,
        DB_BLOCK_BODIES => store.db_block_bodies,
        DB_BLOCK_HEIGHT => store.db_height,
        DB_CHAIN_TIP => store.db_tip,
        DB_UTXOS => store.db_utxos,
        DB_METADATA => store.db_metadata,
        _ => panic!("delete_raw: unknown db name {db_name}"),
    };
    let mut txn = store.env.begin_rw_txn().expect("rw txn");
    match txn.del(db, &key, None) {
        Ok(()) | Err(lmdb::Error::NotFound) => {}
        Err(e) => panic!("delete_raw failed: {e}"),
    }
    txn.commit().expect("commit");
}

fn dump_db(store: &DomStore, db: Database) -> BTreeMap<Vec<u8>, Vec<u8>> {
    let txn = store.env.begin_ro_txn().expect("ro txn");
    let mut cursor = txn.open_ro_cursor(db).expect("open cursor");
    let mut out = BTreeMap::new();
    for (k, v) in cursor.iter() {
        out.insert(k.to_vec(), v.to_vec());
    }
    out
}

fn dump_utxo_db(store: &DomStore) -> BTreeMap<Vec<u8>, Vec<u8>> {
    dump_db(store, store.db_utxos)
}

fn utxo_digest(entries: &BTreeMap<Vec<u8>, Vec<u8>>) -> [u8; 32] {
    type B2b256 = Blake2b<U32>;
    let mut hasher = B2b256::new();
    hasher.update(b"TEST_CANONICAL_UTXO_DIGEST_V1");
    for (commitment, entry) in entries {
        hasher.update((commitment.len() as u64).to_le_bytes());
        hasher.update(commitment);
        hasher.update((entry.len() as u64).to_le_bytes());
        hasher.update(entry);
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&hasher.finalize());
    out
}

fn g_point() -> Commitment {
    let g = [
        0x02u8, 0x79, 0xBE, 0x66, 0x7E, 0xF9, 0xDC, 0xBB, 0xAC, 0x55, 0xA0, 0x62, 0x95, 0xCE, 0x87,
        0x0B, 0x07, 0x02, 0x9B, 0xFC, 0xDB, 0x2D, 0xCE, 0x28, 0xD9, 0x59, 0xF2, 0x81, 0x5B, 0x16,
        0xF8, 0x17, 0x98,
    ];
    Commitment::from_compressed_bytes(&g).unwrap()
}

fn h_point() -> Commitment {
    let h = [
        0x02u8, 0xc6, 0x04, 0x7f, 0x94, 0x41, 0xed, 0x7d, 0x6d, 0x30, 0x45, 0x40, 0x6e, 0x95, 0xc0,
        0x7c, 0xd8, 0x5c, 0x77, 0x8e, 0x4b, 0x8c, 0xef, 0x3c, 0xa7, 0xab, 0xac, 0x09, 0xb9, 0x5c,
        0x70, 0x9e, 0xe5,
    ];
    Commitment::from_compressed_bytes(&h).unwrap()
}

fn deterministic_commitment(seed: u8, value: u64) -> Commitment {
    let mut blind = [0u8; 32];
    blind[31] = seed.max(1);
    Commitment::commit(
        value,
        &BlindingFactor::from_bytes(blind).expect("deterministic blinding"),
    )
}

fn synthetic_header_struct(height: u64, nonce: u64) -> BlockHeader {
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
            nonce,
            randomx_hash: Hash256::ZERO,
        },
    }
}

fn synthetic_header(height: u64) -> Vec<u8> {
    synthetic_header_struct(height, 0)
        .to_bytes()
        .expect("serialize header")
}

#[allow(clippy::type_complexity)]
fn synthetic_block_bytes(
    height: u64,
    nonce: u64,
    output: Commitment,
    kernel_excess: Commitment,
) -> (Vec<u8>, Vec<u8>, [u8; 32], [u8; 33], [u8; 33]) {
    let header = synthetic_header_struct(height, nonce);
    let header_bytes = header.to_bytes().expect("serialize header");
    let block_hash = *dom_crypto::hash::blake2b_256(&header_bytes).as_bytes();
    let output_bytes = *output.as_bytes();
    let excess_bytes = *kernel_excess.as_bytes();
    let block = Block {
        header,
        coinbase: CoinbaseTransaction {
            output: TransactionOutput {
                commitment: output,
                proof: vec![0xAA; 8],
            },
            kernel: CoinbaseKernel {
                features: KERNEL_FEAT_COINBASE,
                explicit_value: 1,
                excess: kernel_excess,
                excess_signature: [0u8; 65],
            },
            offset: [0u8; 32],
        },
        transactions: Vec::new(),
    };
    (
        header_bytes,
        block.to_bytes().expect("serialize block"),
        block_hash,
        output_bytes,
        excess_bytes,
    )
}

#[allow(clippy::type_complexity)]
fn synthetic_genesis_block_bytes() -> (Vec<u8>, Vec<u8>, [u8; 32], [u8; 33], [u8; 33]) {
    synthetic_block_bytes(
        0,
        0xA0,
        deterministic_commitment(0xE0, 50),
        deterministic_commitment(0xE1, 0),
    )
}

fn commit_synthetic_genesis(store: &DomStore) {
    let (header, body, hash, output, excess) = synthetic_genesis_block_bytes();
    store
        .commit_block(
            &hash,
            0,
            &header,
            &body,
            &[(
                output,
                UtxoEntry {
                    block_height: 0,
                    is_coinbase: true,
                    proof: vec![0xAA; 8],
                }
                .to_bytes(),
            )],
            &[],
            &[(excess, hash)],
        )
        .expect("commit synthetic genesis");
}

fn make_hash(seed: u8) -> [u8; 32] {
    let mut h = [0u8; 32];
    h[0] = seed;
    h
}

fn open_chain(dir: &std::path::Path) -> Result<ChainState, dom_core::DomError> {
    open_test_chain(
        dir,
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
    let (header_bytes, body_bytes, hash, output, excess) =
        synthetic_block_bytes(1, 0xAA, g_point(), h_point());
    {
        let store = open_test_store(dir.path());
        commit_synthetic_genesis(&store);
        store
            .commit_block(
                &hash,
                1,
                &header_bytes,
                &body_bytes,
                &[(
                    output,
                    UtxoEntry {
                        block_height: 1,
                        is_coinbase: true,
                        proof: vec![0u8; 8],
                    }
                    .to_bytes(),
                )],
                &[],
                &[(excess, hash)],
            )
            .expect("commit");
    }
    let chain = open_chain(dir.path()).expect("healthy state must open cleanly");
    assert_eq!(chain.tip_hash, Hash256::from_bytes(hash));
    assert_eq!(chain.tip_height, BlockHeight(1));
}

#[test]
fn corrupt_utxo_entry_is_rebuilt_from_canonical_history_on_reopen() {
    let dir = TempDir::new().expect("tempdir");
    let (header_bytes, body_bytes, hash, output, excess) =
        synthetic_block_bytes(1, 0xAB, g_point(), h_point());
    {
        let store = open_test_store(dir.path());
        commit_synthetic_genesis(&store);
        let canonical_entry = UtxoEntry {
            block_height: 1,
            is_coinbase: true,
            proof: vec![0u8; 8],
        };
        store
            .commit_block(
                &hash,
                1,
                &header_bytes,
                &body_bytes,
                &[(output, canonical_entry.to_bytes())],
                &[],
                &[(excess, hash)],
            )
            .expect("commit");
        put_raw(&store, DB_UTXOS, &output, &[0x99, 0x88, 0x77]);
        delete_raw(&store, DB_METADATA, METADATA_UTXO_SET_DIGEST_KEY);
    }

    let reopened = open_chain(dir.path()).expect("reopen must rebuild corrupt utxo entry");
    let repaired = reopened
        .store
        .get_utxo(&output)
        .expect("lookup")
        .expect("utxo present");
    assert_eq!(repaired.block_height, 1);
    assert!(repaired.is_coinbase);
    assert_eq!(repaired.proof, vec![0xAA; 8]);
    assert!(
        reopened
            .store
            .get_metadata(METADATA_UTXO_SET_DIGEST_KEY)
            .expect("digest lookup")
            .is_some(),
        "reopen must persist the canonical utxo digest"
    );
}

#[test]
fn missing_utxo_entry_is_rebuilt_from_canonical_history_on_reopen() {
    let dir = TempDir::new().expect("tempdir");
    let (header_bytes, body_bytes, hash, output, excess) =
        synthetic_block_bytes(1, 0xAC, g_point(), h_point());
    {
        let store = open_test_store(dir.path());
        commit_synthetic_genesis(&store);
        store
            .commit_block(
                &hash,
                1,
                &header_bytes,
                &body_bytes,
                &[(
                    output,
                    UtxoEntry {
                        block_height: 1,
                        is_coinbase: true,
                        proof: vec![1u8; 8],
                    }
                    .to_bytes(),
                )],
                &[],
                &[(excess, hash)],
            )
            .expect("commit");
        delete_raw(&store, DB_UTXOS, &output);
        delete_raw(&store, DB_METADATA, METADATA_UTXO_SET_DIGEST_KEY);
    }

    let reopened = open_chain(dir.path()).expect("reopen must restore missing utxo entry");
    let repaired = reopened
        .store
        .get_utxo(&output)
        .expect("lookup")
        .expect("utxo present");
    assert_eq!(repaired.block_height, 1);
    assert!(repaired.is_coinbase);
    assert_eq!(repaired.proof, vec![0xAA; 8]);
}

#[test]
fn extra_utxo_entry_is_removed_by_canonical_rebuild_on_reopen() {
    let dir = TempDir::new().expect("tempdir");
    let (header_bytes, body_bytes, hash, output, excess) =
        synthetic_block_bytes(1, 0xAD, g_point(), h_point());
    let mut extra_commitment = [0u8; 33];
    extra_commitment[0] = 0x02;
    extra_commitment[32] = 0xFE;
    {
        let store = open_test_store(dir.path());
        commit_synthetic_genesis(&store);
        store
            .commit_block(
                &hash,
                1,
                &header_bytes,
                &body_bytes,
                &[(
                    output,
                    UtxoEntry {
                        block_height: 1,
                        is_coinbase: true,
                        proof: vec![2u8; 8],
                    }
                    .to_bytes(),
                )],
                &[],
                &[(excess, hash)],
            )
            .expect("commit");
        put_raw(
            &store,
            DB_UTXOS,
            &extra_commitment,
            &UtxoEntry {
                block_height: 99,
                is_coinbase: false,
                proof: vec![9u8; 8],
            }
            .to_bytes(),
        );
        delete_raw(&store, DB_METADATA, METADATA_UTXO_SET_DIGEST_KEY);
    }

    let reopened = open_chain(dir.path()).expect("reopen must remove extra utxo entry");
    assert!(
        reopened.store.get_utxo(&output).unwrap().is_some(),
        "canonical utxo must remain"
    );
    assert!(
        reopened
            .store
            .get_utxo(&extra_commitment)
            .unwrap()
            .is_none(),
        "non-canonical extra utxo must be removed"
    );
}

#[test]
fn reopen_rebuilds_exact_canonical_utxo_after_missing_entry_corruption() {
    let dir = TempDir::new().expect("tempdir");
    let (header_bytes, body_bytes, hash, output, excess) =
        synthetic_block_bytes(1, 0xB1, g_point(), h_point());
    {
        let store = open_test_store(dir.path());
        commit_synthetic_genesis(&store);
        store
            .commit_block(
                &hash,
                1,
                &header_bytes,
                &body_bytes,
                &[(
                    output,
                    UtxoEntry {
                        block_height: 1,
                        is_coinbase: true,
                        proof: vec![6u8; 8],
                    }
                    .to_bytes(),
                )],
                &[],
                &[(excess, hash)],
            )
            .expect("commit");
    }
    let canonical_digest = {
        let normalized = open_chain(dir.path()).expect("normalize canonical utxo");
        utxo_digest(&dump_utxo_db(&normalized.store))
    };
    {
        let store = open_test_store(dir.path());
        delete_raw(&store, DB_UTXOS, &output);
        delete_raw(&store, DB_METADATA, METADATA_UTXO_SET_DIGEST_KEY);
    }

    let reopened = open_chain(dir.path()).expect("reopen must rebuild missing utxo");
    assert_eq!(
        utxo_digest(&dump_utxo_db(&reopened.store)),
        canonical_digest
    );
}

#[test]
fn reopen_rebuilds_exact_canonical_utxo_after_fake_entry_corruption() {
    let dir = TempDir::new().expect("tempdir");
    let (header_bytes, body_bytes, hash, output, excess) =
        synthetic_block_bytes(1, 0xB2, g_point(), h_point());
    let mut fake_commitment = [0u8; 33];
    fake_commitment[0] = 0x02;
    fake_commitment[32] = 0xFD;
    {
        let store = open_test_store(dir.path());
        commit_synthetic_genesis(&store);
        store
            .commit_block(
                &hash,
                1,
                &header_bytes,
                &body_bytes,
                &[(
                    output,
                    UtxoEntry {
                        block_height: 1,
                        is_coinbase: true,
                        proof: vec![7u8; 8],
                    }
                    .to_bytes(),
                )],
                &[],
                &[(excess, hash)],
            )
            .expect("commit");
    }
    let canonical_digest = {
        let normalized = open_chain(dir.path()).expect("normalize canonical utxo");
        utxo_digest(&dump_utxo_db(&normalized.store))
    };
    {
        let store = open_test_store(dir.path());
        put_raw(
            &store,
            DB_UTXOS,
            &fake_commitment,
            &UtxoEntry {
                block_height: 77,
                is_coinbase: false,
                proof: vec![0xFE; 8],
            }
            .to_bytes(),
        );
        delete_raw(&store, DB_METADATA, METADATA_UTXO_SET_DIGEST_KEY);
    }

    let reopened = open_chain(dir.path()).expect("reopen must drop fake utxo");
    assert_eq!(
        utxo_digest(&dump_utxo_db(&reopened.store)),
        canonical_digest
    );
}

#[test]
fn reopen_rebuilds_exact_canonical_utxo_after_altered_persisted_utxo() {
    let dir = TempDir::new().expect("tempdir");
    let (header_bytes, body_bytes, hash, output, excess) =
        synthetic_block_bytes(1, 0xB3, g_point(), h_point());
    {
        let store = open_test_store(dir.path());
        commit_synthetic_genesis(&store);
        store
            .commit_block(
                &hash,
                1,
                &header_bytes,
                &body_bytes,
                &[(
                    output,
                    UtxoEntry {
                        block_height: 1,
                        is_coinbase: true,
                        proof: vec![8u8; 8],
                    }
                    .to_bytes(),
                )],
                &[],
                &[(excess, hash)],
            )
            .expect("commit");
    }
    let canonical_digest = {
        let normalized = open_chain(dir.path()).expect("normalize canonical utxo");
        utxo_digest(&dump_utxo_db(&normalized.store))
    };
    {
        let store = open_test_store(dir.path());
        put_raw(
            &store,
            DB_UTXOS,
            &output,
            &UtxoEntry {
                block_height: 999,
                is_coinbase: false,
                proof: vec![0xAB; 8],
            }
            .to_bytes(),
        );
        delete_raw(&store, DB_METADATA, METADATA_UTXO_SET_DIGEST_KEY);
    }

    let reopened = open_chain(dir.path()).expect("reopen must repair altered utxo entry");
    assert_eq!(
        utxo_digest(&dump_utxo_db(&reopened.store)),
        canonical_digest
    );
}

#[test]
fn reopen_rebuilds_exact_canonical_utxo_after_digest_metadata_corruption() {
    let dir = TempDir::new().expect("tempdir");
    let (header_bytes, body_bytes, hash, output, excess) =
        synthetic_block_bytes(1, 0xB4, g_point(), h_point());
    {
        let store = open_test_store(dir.path());
        commit_synthetic_genesis(&store);
        store
            .commit_block(
                &hash,
                1,
                &header_bytes,
                &body_bytes,
                &[(
                    output,
                    UtxoEntry {
                        block_height: 1,
                        is_coinbase: true,
                        proof: vec![9u8; 8],
                    }
                    .to_bytes(),
                )],
                &[],
                &[(excess, hash)],
            )
            .expect("commit");
    }
    let canonical_digest = {
        let normalized = open_chain(dir.path()).expect("normalize canonical utxo");
        utxo_digest(&dump_utxo_db(&normalized.store))
    };
    {
        let store = open_test_store(dir.path());
        put_raw(
            &store,
            DB_METADATA,
            METADATA_UTXO_SET_DIGEST_KEY,
            &[0x13; 32],
        );
    }

    let reopened = open_chain(dir.path()).expect("reopen must repair digest metadata");
    assert_eq!(
        utxo_digest(&dump_utxo_db(&reopened.store)),
        canonical_digest
    );
}

#[test]
fn canonical_utxo_set_is_equivalent_before_and_after_restart() {
    let dir = TempDir::new().expect("tempdir");
    let (header_1, body_1, hash_1, output_1, excess_1) =
        synthetic_block_bytes(1, 0xAE, g_point(), h_point());
    let (header_2, body_2, hash_2, output_2, excess_2) =
        synthetic_block_bytes(2, 0xAF, h_point(), g_point());
    {
        let store = open_test_store(dir.path());
        commit_synthetic_genesis(&store);
        store
            .commit_block(
                &hash_1,
                1,
                &header_1,
                &body_1,
                &[(
                    output_1,
                    UtxoEntry {
                        block_height: 1,
                        is_coinbase: true,
                        proof: vec![3u8; 8],
                    }
                    .to_bytes(),
                )],
                &[],
                &[(excess_1, hash_1)],
            )
            .expect("commit block 1");
        store
            .commit_block(
                &hash_2,
                2,
                &header_2,
                &body_2,
                &[(
                    output_2,
                    UtxoEntry {
                        block_height: 2,
                        is_coinbase: true,
                        proof: vec![4u8; 8],
                    }
                    .to_bytes(),
                )],
                &[],
                &[(excess_2, hash_2)],
            )
            .expect("commit block 2");
    }

    let first = open_chain(dir.path()).expect("first reopen");
    let before = dump_utxo_db(&first.store);
    assert!(
        first
            .store
            .get_metadata(METADATA_UTXO_SET_DIGEST_KEY)
            .expect("digest lookup")
            .is_some(),
        "verified reopen must persist the utxo digest"
    );
    drop(first);

    let second = open_chain(dir.path()).expect("second reopen");
    let after = dump_utxo_db(&second.store);
    assert_eq!(
        before, after,
        "healthy canonical utxo set must be identical across restart"
    );
}

#[test]
fn interrupted_reopen_does_not_leave_partial_repair_state() {
    let dir = TempDir::new().expect("tempdir");
    let (header_bytes, body_bytes, hash, output, excess) =
        synthetic_block_bytes(1, 0xB0, g_point(), h_point());
    let utxo_before_failed_open = {
        let store = open_test_store(dir.path());
        commit_synthetic_genesis(&store);
        store
            .commit_block(
                &hash,
                1,
                &header_bytes,
                &body_bytes,
                &[(
                    output,
                    UtxoEntry {
                        block_height: 1,
                        is_coinbase: true,
                        proof: vec![5u8; 8],
                    }
                    .to_bytes(),
                )],
                &[],
                &[(excess, hash)],
            )
            .expect("commit");
        put_raw(&store, DB_UTXOS, &output, &[0x01, 0x02, 0x03]);
        put_raw(&store, DB_BLOCK_BODIES, &hash, &[0xDE, 0xAD, 0xBE, 0xEF]);
        delete_raw(&store, DB_METADATA, METADATA_UTXO_SET_DIGEST_KEY);
        dump_utxo_db(&store)
    };

    let msg = err_msg(open_chain(dir.path()));
    assert!(
        msg.contains(CHAIN_CORRUPT_SENTINEL)
            && (msg.contains("UTXO rebuild") || msg.contains("kernel-index rebuild")),
        "failed canonical reopen repair must fail closed; got: {msg}"
    );

    let reopened_store = open_test_store(dir.path());
    assert_eq!(
        utxo_before_failed_open,
        dump_utxo_db(&reopened_store),
        "failed repair must not partially mutate the persisted utxo database"
    );
    assert!(
        reopened_store
            .get_metadata(METADATA_UTXO_SET_DIGEST_KEY)
            .expect("digest lookup")
            .is_none(),
        "failed repair must not persist a new utxo digest"
    );
}

/// A side-chain block retained by hash must not become canonical after restart.
/// This pins the replay/restart invariant without invoking the RandomX mining
/// path: only `commit_block` may mutate canonical pointers; `store_known_block`
/// may retain immutable block data by hash.
#[test]
fn known_side_block_does_not_resurrect_as_tip_on_restart() {
    let dir = TempDir::new().expect("tempdir");
    let (canonical_header, canonical_body, canonical, canonical_output, canonical_excess) =
        synthetic_block_bytes(1, 0xA1, g_point(), g_point());
    let (side_header, side_body, side, _, _) = synthetic_block_bytes(1, 0xA2, h_point(), h_point());
    {
        let store = open_test_store(dir.path());
        commit_synthetic_genesis(&store);
        store
            .commit_block(
                &canonical,
                1,
                &canonical_header,
                &canonical_body,
                &[(
                    canonical_output,
                    UtxoEntry {
                        block_height: 1,
                        is_coinbase: true,
                        proof: vec![0u8; 8],
                    }
                    .to_bytes(),
                )],
                &[],
                &[(canonical_excess, canonical)],
            )
            .expect("canonical commit");
        store
            .store_known_block(&side, &side_header, &side_body)
            .expect("known side block");
    }

    let chain = open_chain(dir.path()).expect("side-known state must open cleanly");
    assert_eq!(chain.tip_hash, Hash256::from_bytes(canonical));
    assert_eq!(chain.tip_height, BlockHeight(1));
    assert_eq!(chain.store.get_chain_tip().unwrap().unwrap(), canonical);
    assert_eq!(
        chain.store.get_hash_at_height(1).unwrap().unwrap(),
        canonical
    );
    assert_eq!(
        chain.store.get_block_body(&side).unwrap().unwrap(),
        side_body,
        "side block body remains available by hash for duplicate suppression"
    );
}

/// Alternating canonical and side-chain arrivals must be restart-equivalent:
/// canonical height pointers remain the canonical sequence, while side-chain
/// bodies remain addressable only by hash.
#[test]
fn alternating_canonical_and_side_arrivals_reopen_to_canonical_chain() {
    let dir = TempDir::new().expect("tempdir");
    let (canonical_1_header, canonical_1_body, canonical_1, canonical_1_output, canonical_1_excess) =
        synthetic_block_bytes(1, 0xB1, g_point(), g_point());
    let (side_1_header, side_1_body, side_1, _, _) =
        synthetic_block_bytes(1, 0xB2, h_point(), h_point());
    let (canonical_2_header, canonical_2_body, canonical_2, canonical_2_output, canonical_2_excess) =
        synthetic_block_bytes(2, 0xB3, h_point(), h_point());
    let (side_2_header, side_2_body, side_2, _, _) =
        synthetic_block_bytes(2, 0xB4, g_point(), g_point());
    {
        let store = open_test_store(dir.path());
        commit_synthetic_genesis(&store);
        store
            .commit_block(
                &canonical_1,
                1,
                &canonical_1_header,
                &canonical_1_body,
                &[(
                    canonical_1_output,
                    UtxoEntry {
                        block_height: 1,
                        is_coinbase: true,
                        proof: vec![0u8; 8],
                    }
                    .to_bytes(),
                )],
                &[],
                &[(canonical_1_excess, canonical_1)],
            )
            .expect("canonical 1");
        store
            .store_known_block(&side_1, &side_1_header, &side_1_body)
            .expect("side 1");
        store
            .commit_block(
                &canonical_2,
                2,
                &canonical_2_header,
                &canonical_2_body,
                &[(
                    canonical_2_output,
                    UtxoEntry {
                        block_height: 2,
                        is_coinbase: true,
                        proof: vec![1u8; 8],
                    }
                    .to_bytes(),
                )],
                &[],
                &[(canonical_2_excess, canonical_2)],
            )
            .expect("canonical 2");
        store
            .store_known_block(&side_2, &side_2_header, &side_2_body)
            .expect("side 2");
    }

    let chain = open_chain(dir.path()).expect("alternating state must open cleanly");
    assert_eq!(chain.tip_hash, Hash256::from_bytes(canonical_2));
    assert_eq!(chain.tip_height, BlockHeight(2));
    assert_eq!(
        chain.store.get_hash_at_height(1).unwrap().unwrap(),
        canonical_1
    );
    assert_eq!(
        chain.store.get_hash_at_height(2).unwrap().unwrap(),
        canonical_2
    );
    assert_eq!(
        chain.store.get_block_body(&side_1).unwrap().unwrap(),
        side_1_body
    );
    assert_eq!(
        chain.store.get_block_body(&side_2).unwrap().unwrap(),
        side_2_body
    );
}

/// Replaying the same side-chain block must hit duplicate suppression and leave
/// canonical state unchanged.
#[test]
fn duplicate_known_side_block_rejected_without_mutating_canonical_state() {
    let dir = TempDir::new().expect("tempdir");
    let (canonical_header, canonical_body, canonical, canonical_output, canonical_excess) =
        synthetic_block_bytes(1, 0xC1, g_point(), g_point());
    let (side_header, side_body, side, _, _) = synthetic_block_bytes(1, 0xC2, h_point(), h_point());
    {
        let store = open_test_store(dir.path());
        commit_synthetic_genesis(&store);
        store
            .commit_block(
                &canonical,
                1,
                &canonical_header,
                &canonical_body,
                &[(
                    canonical_output,
                    UtxoEntry {
                        block_height: 1,
                        is_coinbase: true,
                        proof: vec![0u8; 8],
                    }
                    .to_bytes(),
                )],
                &[],
                &[(canonical_excess, canonical)],
            )
            .expect("canonical commit");
        store
            .store_known_block(&side, &side_header, &side_body)
            .expect("first side write");
        let err = store
            .store_known_block(&side, &side_header, &side_body)
            .expect_err("duplicate side hash must be rejected");
        assert!(
            format!("{err}").contains("block header already exists"),
            "unexpected duplicate error: {err}"
        );
        assert_eq!(store.get_chain_tip().unwrap().unwrap(), canonical);
        assert_eq!(store.get_hash_at_height(1).unwrap().unwrap(), canonical);
    }

    let chain = open_chain(dir.path()).expect("duplicate side state must open cleanly");
    assert_eq!(chain.tip_hash, Hash256::from_bytes(canonical));
    assert_eq!(chain.tip_height, BlockHeight(1));
}

/// Old stores may have canonical block bodies but an empty kernel index because
/// early `connect_block` passed no kernel excesses into `commit_block`. Reopen
/// must deterministically rebuild missing canonical kernel entries so future
/// validation is equivalent to fresh replay.
#[test]
fn reopen_rebuilds_missing_kernel_index_for_canonical_blocks() {
    let dir = TempDir::new().expect("tempdir");
    let (header, body, hash, output, excess) = synthetic_block_bytes(1, 0xC3, g_point(), h_point());
    {
        let store = open_test_store(dir.path());
        commit_synthetic_genesis(&store);
        store
            .commit_block(
                &hash,
                1,
                &header,
                &body,
                &[(
                    output,
                    UtxoEntry {
                        block_height: 1,
                        is_coinbase: true,
                        proof: vec![0u8; 8],
                    }
                    .to_bytes(),
                )],
                &[],
                &[],
            )
            .expect("legacy canonical commit without kernel index");
        assert!(
            store.get_kernel_block(&excess).unwrap().is_none(),
            "fixture must start with missing kernel index"
        );
    }

    let chain = open_chain(dir.path()).expect("reindexable state must open cleanly");
    assert_eq!(chain.tip_hash, Hash256::from_bytes(hash));
    assert_eq!(chain.store.get_kernel_block(&excess).unwrap(), Some(hash));
}

/// Reindexing old canonical history must not silently accept duplicate kernel
/// excesses. A duplicate across two canonical blocks is exactly the replay
/// primitive the index exists to catch.
#[test]
fn reopen_rejects_duplicate_kernel_excess_in_legacy_canonical_history() {
    let dir = TempDir::new().expect("tempdir");
    let duplicated_kernel = g_point();
    let (header_1, body_1, hash_1, output_1, _) =
        synthetic_block_bytes(1, 0xC4, g_point(), duplicated_kernel.clone());
    let (header_2, body_2, hash_2, output_2, _) =
        synthetic_block_bytes(2, 0xC5, h_point(), duplicated_kernel);
    {
        let store = open_test_store(dir.path());
        commit_synthetic_genesis(&store);
        store
            .commit_block(
                &hash_1,
                1,
                &header_1,
                &body_1,
                &[(
                    output_1,
                    UtxoEntry {
                        block_height: 1,
                        is_coinbase: true,
                        proof: vec![0u8; 8],
                    }
                    .to_bytes(),
                )],
                &[],
                &[],
            )
            .expect("legacy block 1");
        store
            .commit_block(
                &hash_2,
                2,
                &header_2,
                &body_2,
                &[(
                    output_2,
                    UtxoEntry {
                        block_height: 2,
                        is_coinbase: true,
                        proof: vec![1u8; 8],
                    }
                    .to_bytes(),
                )],
                &[],
                &[],
            )
            .expect("legacy block 2");
    }

    let msg = err_msg(open_chain(dir.path()));
    assert!(
        msg.contains("KERNEL REPLAY DETECTED"),
        "duplicate canonical kernel must fail reopen; got: {msg}"
    );
}

/// A delayed side branch may be retained for future reorg work, but until the
/// reorg engine explicitly promotes it, restart must still load the canonical
/// direct-extension chain.
#[test]
fn delayed_side_branch_candidate_stays_noncanonical_after_restart() {
    let dir = TempDir::new().expect("tempdir");
    let (canonical_1_header, canonical_1_body, canonical_1, canonical_1_output, canonical_1_excess) =
        synthetic_block_bytes(1, 0xD1, g_point(), g_point());
    let (canonical_2_header, canonical_2_body, canonical_2, canonical_2_output, canonical_2_excess) =
        synthetic_block_bytes(2, 0xD2, h_point(), h_point());
    let (side_1_header, side_1_body, side_1, _, _) =
        synthetic_block_bytes(1, 0xD3, h_point(), h_point());
    let (side_2_header, side_2_body, side_2, _, _) =
        synthetic_block_bytes(2, 0xD4, g_point(), g_point());
    {
        let store = open_test_store(dir.path());
        commit_synthetic_genesis(&store);
        store
            .commit_block(
                &canonical_1,
                1,
                &canonical_1_header,
                &canonical_1_body,
                &[(
                    canonical_1_output,
                    UtxoEntry {
                        block_height: 1,
                        is_coinbase: true,
                        proof: vec![0u8; 8],
                    }
                    .to_bytes(),
                )],
                &[],
                &[(canonical_1_excess, canonical_1)],
            )
            .expect("canonical 1");
        store
            .store_known_block(&side_1, &side_1_header, &side_1_body)
            .expect("side 1");
        store
            .store_known_block(&side_2, &side_2_header, &side_2_body)
            .expect("side 2");
        store
            .commit_block(
                &canonical_2,
                2,
                &canonical_2_header,
                &canonical_2_body,
                &[(
                    canonical_2_output,
                    UtxoEntry {
                        block_height: 2,
                        is_coinbase: true,
                        proof: vec![1u8; 8],
                    }
                    .to_bytes(),
                )],
                &[],
                &[(canonical_2_excess, canonical_2)],
            )
            .expect("canonical 2");
    }

    let chain = open_chain(dir.path()).expect("delayed side branch state must open cleanly");
    assert_eq!(chain.tip_hash, Hash256::from_bytes(canonical_2));
    assert_eq!(chain.tip_height, BlockHeight(2));
    assert_eq!(
        chain.store.get_hash_at_height(1).unwrap().unwrap(),
        canonical_1
    );
    assert_eq!(
        chain.store.get_hash_at_height(2).unwrap().unwrap(),
        canonical_2
    );
    assert_eq!(
        chain.store.get_block_body(&side_1).unwrap().unwrap(),
        side_1_body
    );
    assert_eq!(
        chain.store.get_block_body(&side_2).unwrap().unwrap(),
        side_2_body
    );
}

/// chain_tip set, but the header DB has nothing at that hash. open
/// MUST fail with the corrupt sentinel.
#[test]
fn tip_with_missing_header_rejected() {
    let dir = TempDir::new().expect("tempdir");
    {
        let store = open_test_store(dir.path());
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
        let store = open_test_store(dir.path());
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
        let store = open_test_store(dir.path());
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
        let store = open_test_store(dir.path());
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
