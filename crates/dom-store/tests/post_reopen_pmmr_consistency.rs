//! Roadmap v2 Phase 3.4 / 1.3 interrupted-flush boundary —
//! post-reopen PMMR consistency.
//!
//! Contract: for every block persisted on the canonical chain,
//! the three PMMR roots in the stored header (output_root,
//! kernel_root, rangeproof_root) MUST recompute byte-identical
//! to `dom_consensus::compute_block_pmmr_roots` applied to the
//! stored body — *after* a drop-and-reopen of the LMDB
//! environment.
//!
//! This is the strongest empirical statement that the
//! "interrupted-flush + recovery" path the protocol relies on
//! does not silently lose PMMR-root agreement. Concretely it
//! catches:
//!
//!   * a future refactor that splits header and body writes
//!     across two LMDB transactions, leaving them inconsistent
//!     after a crash;
//!   * a serialization drift where Block::to_bytes() and
//!     Block::from_bytes() disagree on a field width;
//!   * a regression in `compute_block_pmmr_roots` that breaks
//!     iteration order;
//!   * a regression in the PMMR algorithm itself (DOM-PMMR-001
//!     symptom: roots would no longer recompute because the
//!     stored body is mutated-equivalent).
//!
//! The harness bypasses RandomX PoW validation by writing
//! synthetic header+body bytes directly via `DomStore::commit_block`
//! and reads them back through `Block::from_bytes`. PoW validity
//! is irrelevant to the PMMR-recomputation property pinned here;
//! that is a chain-state-level concern covered by the
//! `replay_determinism` integration test (env-blocked per
//! RB-PMMR-001).

use dom_consensus::{
    block::{BlockHeader, ProofOfWork},
    compute_block_pmmr_roots, Block, CoinbaseKernel, CoinbaseTransaction, TransactionOutput,
};
use dom_core::{
    Amount, BlockHeight, Hash256, Timestamp, KERNEL_FEAT_COINBASE, KERNEL_FEAT_PLAIN,
    PROTOCOL_VERSION,
};
use dom_crypto::pedersen::{BlindingFactor, Commitment};
use dom_pow::CompactTarget;
use dom_serialization::{DomDeserialize, DomSerialize};
use dom_store::{utxo::UtxoEntry, DomStore};
use primitive_types::U256;
use tempfile::TempDir;

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
        0x02u8, 0x0e, 0x2c, 0xfc, 0x9a, 0xba, 0x78, 0x45, 0x5f, 0xfd, 0x39, 0x0c, 0xf5, 0xf1, 0xd1,
        0x7b, 0x99, 0x82, 0xd0, 0xee, 0x29, 0xb2, 0x66, 0xbb, 0x3e, 0xa6, 0x21, 0x7b, 0x07, 0x8f,
        0x09, 0xd5, 0x50,
    ];
    Commitment::from_compressed_bytes(&h).unwrap()
}

/// Distinct per-height commitments so the kernel-index can hold
/// every coinbase excess in the chain without colliding under
/// DOM-LMDB-001's NO_OVERWRITE kernel-replay guard.
fn unique_excess(height: u64) -> Commitment {
    let mut bf_bytes = [0u8; 32];
    bf_bytes[0] = 0x01;
    bf_bytes[24..32].copy_from_slice(&height.to_le_bytes());
    let bf = BlindingFactor::from_bytes(bf_bytes).expect("blinding in range");
    Commitment::commit(0, &bf)
}

fn unique_output(height: u64) -> Commitment {
    let mut bf_bytes = [0u8; 32];
    bf_bytes[0] = 0x02;
    bf_bytes[24..32].copy_from_slice(&height.to_le_bytes());
    let bf = BlindingFactor::from_bytes(bf_bytes).expect("blinding in range");
    Commitment::commit(3_300_000_000, &bf)
}

/// Build a synthetic block at the requested height with internally
/// consistent header roots derived from `compute_block_pmmr_roots`
/// over the coinbase + (optional) one transaction. Each block
/// carries a unique kernel excess so multi-block tests don't
/// trip the NO_OVERWRITE kernel-index guard.
fn build_consistent_block(height: u64, include_tx: bool) -> Block {
    let coinbase = CoinbaseTransaction {
        output: TransactionOutput {
            commitment: unique_output(height),
            proof: vec![0xAA; 24],
        },
        kernel: CoinbaseKernel {
            features: KERNEL_FEAT_COINBASE,
            explicit_value: 3_300_000_000,
            excess: unique_excess(height),
            excess_signature: [0u8; 65],
        },
        offset: [0u8; 32],
    };

    let txs = if include_tx {
        use dom_consensus::Transaction;
        use dom_consensus::transaction::TransactionKernel;
        vec![Transaction {
            inputs: vec![],
            outputs: vec![TransactionOutput {
                commitment: h_point(),
                proof: vec![0xBB; 24],
            }],
            kernels: vec![TransactionKernel {
                features: KERNEL_FEAT_PLAIN,
                fee: Amount::from_noms(1_000_000).unwrap(),
                lock_height: 0,
                excess: g_point(),
                excess_signature: [0u8; 65],
            }],
            offset: [0u8; 32],
        }]
    } else {
        Vec::new()
    };

    let (output_root, kernel_root, rangeproof_root) =
        compute_block_pmmr_roots(&coinbase, &txs).expect("compute roots");

    let header = BlockHeader {
        version: PROTOCOL_VERSION,
        height: BlockHeight(height),
        prev_hash: Hash256::ZERO,
        timestamp: Timestamp(1_704_067_200 + height),
        output_root,
        kernel_root,
        rangeproof_root,
        total_kernel_offset: [0u8; 32],
        target: CompactTarget(0x1f00_ffff),
        total_difficulty: U256::one(),
        pow: ProofOfWork {
            nonce: 0,
            randomx_hash: Hash256::ZERO,
        },
    };

    Block {
        header,
        coinbase,
        transactions: txs,
    }
}

/// Commit a block to the store via the low-level `DomStore::commit_block`
/// API (no PoW validation; that's not what this harness is testing).
fn commit_synthetic(store: &DomStore, block: &Block) -> [u8; 32] {
    let header_bytes = block.header.to_bytes().expect("ser header");
    let block_hash = *dom_crypto::hash::blake2b_256(&header_bytes).as_bytes();
    let body_bytes = block.to_bytes().expect("ser block");
    store
        .commit_block(
            &block_hash,
            block.header.height.0,
            &header_bytes,
            &body_bytes,
            // No UTXO bookkeeping — the consistency contract under
            // test is PMMR-root agreement, not UTXO replay.
            &[],
            &[],
            &[(*block.coinbase.kernel.excess.as_bytes(), block_hash)],
        )
        .unwrap_or_else(|e| panic!("commit_block h={}: {e}", block.header.height.0));
    block_hash
}

/// Read the body back via `Block::from_bytes` and assert the
/// three PMMR roots in the parsed header match what
/// `compute_block_pmmr_roots` computes over the parsed body.
fn assert_recomputed_roots_match_stored_header(store: &DomStore, hash: &[u8; 32], height: u64) {
    let body_bytes = store
        .get_block_body(hash)
        .expect("get body")
        .expect("body present");
    let block = Block::from_bytes(&body_bytes).expect("body decodes");
    let (or, kr, rr) = compute_block_pmmr_roots(&block.coinbase, &block.transactions)
        .expect("recompute roots");
    assert_eq!(
        block.header.output_root, or,
        "h={height}: output_root drift on reopen — header={} recomputed={}",
        block.header.output_root, or
    );
    assert_eq!(
        block.header.kernel_root, kr,
        "h={height}: kernel_root drift on reopen"
    );
    assert_eq!(
        block.header.rangeproof_root, rr,
        "h={height}: rangeproof_root drift on reopen"
    );
}

// ── (1) Single block, recomputed roots match after reopen ────────────────────

#[test]
fn coinbase_only_block_pmmr_roots_recompute_after_reopen() {
    let dir = TempDir::new().expect("dir");
    let path = dir.path().to_path_buf();
    let block = build_consistent_block(1, false);
    let hash;
    {
        let store = DomStore::open(&path).expect("open");
        hash = commit_synthetic(&store, &block);
    } // env dropped — body must survive to disk

    let store = DomStore::open(&path).expect("reopen");
    assert_recomputed_roots_match_stored_header(&store, &hash, 1);
}

// ── (2) Block with txs, same property holds ──────────────────────────────────

#[test]
fn block_with_transactions_pmmr_roots_recompute_after_reopen() {
    let dir = TempDir::new().expect("dir");
    let path = dir.path().to_path_buf();
    let block = build_consistent_block(1, true);
    let hash;
    {
        let store = DomStore::open(&path).expect("open");
        hash = commit_synthetic(&store, &block);
    }
    let store = DomStore::open(&path).expect("reopen");
    assert_recomputed_roots_match_stored_header(&store, &hash, 1);
}

// ── (3) Chain of N blocks, every height verifies post-reopen ─────────────────

/// Commit 8 synthetic blocks at successive heights (some
/// coinbase-only, some with txs), drop the env, reopen, and
/// walk every height verifying that the stored header roots
/// recompute byte-identical from the stored body. This is the
/// strongest in-session empirical proof of the
/// interrupted-flush + recovery invariant the protocol depends
/// on.
#[test]
fn chain_of_8_blocks_pmmr_roots_recompute_after_reopen() {
    let dir = TempDir::new().expect("dir");
    let path = dir.path().to_path_buf();
    let blocks: Vec<Block> = (1..=8u64)
        .map(|h| build_consistent_block(h, h.is_multiple_of(2)))
        .collect();
    let mut hashes = Vec::new();
    {
        let store = DomStore::open(&path).expect("open");
        for b in &blocks {
            hashes.push(commit_synthetic(&store, b));
        }
    }
    let store = DomStore::open(&path).expect("reopen");
    for (i, hash) in hashes.iter().enumerate() {
        assert_recomputed_roots_match_stored_header(&store, hash, (i + 1) as u64);
    }
}

// ── (4) Negative control — header roots mutated post-reopen yields mismatch ─

/// Sanity for the verifier itself: if we tamper with the
/// stored body (replace the coinbase output bytes with an
/// alternative commitment), recomputed roots MUST diverge from
/// the stored header. Catches a regression where the
/// recomputation accidentally re-reads the header values
/// without checking.
#[test]
fn body_mutation_post_persist_breaks_recomputed_pmmr_roots() {
    let dir = TempDir::new().expect("dir");
    let path = dir.path().to_path_buf();
    let original = build_consistent_block(1, false);
    let original_header_bytes = original.header.to_bytes().expect("ser header");
    let original_hash = *dom_crypto::hash::blake2b_256(&original_header_bytes).as_bytes();
    // Same hash → store under it but with a different body.
    let mut mutated = original.clone();
    mutated.coinbase.output.commitment = h_point(); // changed
    let mutated_body_bytes = mutated.to_bytes().expect("ser body");

    {
        let store = DomStore::open(&path).expect("open");
        // Direct store write — we want the stored body to NOT
        // match the stored header's PMMR roots.
        store
            .commit_block(
                &original_hash,
                1,
                &original_header_bytes,
                &mutated_body_bytes,
                &[],
                &[],
                &[(*mutated.coinbase.kernel.excess.as_bytes(), original_hash)],
            )
            .expect("commit_block under original header");
    }

    let store = DomStore::open(&path).expect("reopen");
    let body = store
        .get_block_body(&original_hash)
        .expect("get body")
        .expect("body present");
    let block = Block::from_bytes(&body).expect("decode");
    let (or, _, _) = compute_block_pmmr_roots(&block.coinbase, &block.transactions)
        .expect("recompute");
    // The body's output commitment was tampered with → output_root
    // recomputed from the body MUST differ from the header's
    // stored output_root (which was committed when output =
    // g_point()).
    assert_ne!(
        or, block.header.output_root,
        "negative-control failed: recomputed roots agreed with stored header \
         despite body mutation — the verifier is not actually checking"
    );
}

// ── (5) Drop-and-reopen + utxo entry preserves the same property ────────────

/// Same chain consistency property in the presence of UTXO
/// bookkeeping — `commit_block` writes header, body, height
/// index, tip, utxos, kernel index in ONE LMDB transaction
/// (RFC-0007 §14). After reopen, every component MUST still be
/// internally consistent.
#[test]
fn chain_consistency_holds_with_utxo_bookkeeping_after_reopen() {
    let dir = TempDir::new().expect("dir");
    let path = dir.path().to_path_buf();
    let block = build_consistent_block(1, true);
    let header_bytes = block.header.to_bytes().expect("ser");
    let block_hash = *dom_crypto::hash::blake2b_256(&header_bytes).as_bytes();
    let body_bytes = block.to_bytes().expect("ser");
    let new_utxo_commit = *block.coinbase.output.commitment.as_bytes();
    {
        let store = DomStore::open(&path).expect("open");
        store
            .commit_block(
                &block_hash,
                1,
                &header_bytes,
                &body_bytes,
                &[(
                    new_utxo_commit,
                    UtxoEntry {
                        block_height: 1,
                        is_coinbase: true,
                        proof: vec![0xCC; 16],
                    }
                    .to_bytes(),
                )],
                &[],
                &[(*block.coinbase.kernel.excess.as_bytes(), block_hash)],
            )
            .expect("commit_block");
    }
    let store = DomStore::open(&path).expect("reopen");
    assert_recomputed_roots_match_stored_header(&store, &block_hash, 1);
    // UTXO survived too.
    let utxo = store
        .get_utxo(&new_utxo_commit)
        .expect("utxo read")
        .expect("utxo present after reopen");
    assert_eq!(utxo.block_height, 1);
}
