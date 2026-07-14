//! dom-shield A2-001 — cross-branch reorg with a SHARED transaction.
//!
//! Proves the A2-001 closure: a reorg succeeds when the SAME transaction
//! (byte-identical kernel excess) appears in both the disconnected canonical
//! branch and the reconnected heavier branch.
//!
//! Structure mirrors `v1_reorg_a_to_b_removes_a_state_applies_b_keeps_uniqueness`
//! in `shield_reorg_cross_branch_directed.rs`, and reuses the same consensus-
//! valid block/coinbase/spend builders (copied verbatim; test helpers are
//! per-file in this crate, only `open_test_store`/`open_test_chain` come from
//! `common.rs`). The KEY difference: instead of two distinct spends with
//! different kernel seeds, ONE `shared_spend` is built and the SAME object is
//! cloned into a block on canonical branch A AND a block on heavier branch B,
//! so the kernel excess is byte-identical on both branches.
//!
//! Layout:
//!   genesis(h0) -> shared(h1, coinbase) --+-- A2(h2, [shared_spend]) -> A3(h3)
//!                                           \
//!                                            +-- B2(h2) -> B3(h3, [shared_spend])
//!                                                            -> B4(h4, heavier)
//!
//! Both A2 and B3 spend the shared(h1) coinbase via the SAME `shared_spend`, so
//! its kernel excess is indexed at A2 pre-reorg and must MIGRATE to B3 when the
//! chain reorgs A->B.
//!
//! The test asserts the consensus contract: the reorg to the heavier branch B
//! must succeed, the tip must advance to B4, and the shared transaction state
//! must migrate to its canonical owner.
//!
//! REAL mechanism (verified at runtime AND against the source — the failure is
//! NOT where A2-001 was first hypothesised; corrected below):
//!
//!   PRIMARY (what actually fires): the reorg builds a UTXO overlay and converts
//!   it via `build_utxo_updates` (crates/dom-chain/src/chain_state.rs, ~line
//!   1680) — this runs in the CHAIN layer, UPSTREAM of the store's `apply_reorg`.
//!   The shared_spend OUTPUT exists on canonical A at height 2 and the reorg
//!   wants it on B at height 3: a `Some(current) -> Some(desired)` change with a
//!   different `UtxoEntry.block_height`. `build_utxo_updates` only handles inserts
//!   (`None -> Some`) and deletes (`Some -> None`); an in-place MIGRATION
//!   (`Some -> Some` with different bytes) is rejected with
//!   `DomError::Internal("reorg utxo mismatch for existing commitment <c>:
//!   current_height=2 desired_height=3")`. The whole reorg is rolled back
//!   atomically, leaving the node stuck on the LIGHTER chain.
//!
//!   Why UTXO and not kernel: `shared_spend` carries BOTH an output and a kernel.
//!   The output collides on `block_height` first, so the UTXO arm fails-closed
//!   before any kernel handling is reached.
//!
//!   SECONDARY / MASKED in the old failure mode: the chain-layer
//!   `build_kernel_updates` was permissive, but the store-layer `apply_reorg`
//!   kernel arm used to reject migrating the shared excess to a new block hash.
//!
//! The current contract is to let the reorg re-home commitments and excesses
//! that are shared across the disconnected and reconnected branches.

mod common;

use blake2::digest::consts::U32;
use blake2::{Blake2b, Digest};
use common::{open_test_chain, open_test_store};
use dom_chain::ChainState;
use dom_consensus::block::{BlockHeader, ProofOfWork};
use dom_consensus::{
    compute_block_pmmr_roots, derive_chain_id, Block, CoinbaseKernel, CoinbaseTransaction,
    Transaction, TransactionInput, TransactionKernel, TransactionOutput,
};
use dom_core::{
    Amount, BlockHeight, Hash256, Timestamp, KERNEL_FEAT_COINBASE, KERNEL_FEAT_PLAIN,
    PROTOCOL_VERSION, TAG_KERNEL_MSG, TAG_KERNEL_MSG_COINBASE,
};
use dom_crypto::hash::blake2b_256_tagged;
use dom_crypto::keys::SecretKey;
use dom_crypto::pedersen::{BlindingFactor, Commitment};
use dom_crypto::schnorr_sign;
use dom_pow::CompactTarget;
use dom_serialization::DomSerialize;
use dom_store::utxo::UtxoEntry;
use dom_store::DomStore;
use primitive_types::U256;
use std::collections::BTreeMap;

type UtxoBytes = ([u8; 33], Vec<u8>);
type SpentCommitment = [u8; 33];

// ---------------------------------------------------------------------------
// Helpers (verbatim from reorg_equivalence.rs / shield_reorg_cross_branch_
// directed.rs — real consensus-valid bodies).
// ---------------------------------------------------------------------------

fn block_hash(header: &BlockHeader) -> Hash256 {
    let bytes = header.to_bytes().expect("header serialise");
    type B2b256 = Blake2b<U32>;
    let mut h = B2b256::new();
    h.update(&bytes);
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&h.finalize());
    Hash256::from_bytes(arr)
}

fn blinding(seed: u8) -> BlindingFactor {
    let mut bytes = [0u8; 32];
    bytes[31] = seed.max(1);
    BlindingFactor::from_bytes(bytes).expect("deterministic blinding")
}

fn test_chain_id() -> [u8; 32] {
    *derive_chain_id(
        dom_core::NETWORK_MAGIC_REGTEST,
        &Hash256::from_bytes(dom_core::GENESIS_HASH_REGTEST),
    )
    .as_bytes()
}

fn kernel_message(fee: u64, lock_height: u64) -> [u8; 32] {
    let mut data = Vec::with_capacity(1 + 8 + 8);
    data.push(KERNEL_FEAT_PLAIN);
    data.extend_from_slice(&fee.to_le_bytes());
    data.extend_from_slice(&lock_height.to_le_bytes());
    *blake2b_256_tagged(TAG_KERNEL_MSG, &data).as_bytes()
}

fn valid_coinbase(height: BlockHeight, total_fees: u64, seed: u8) -> CoinbaseTransaction {
    let explicit_value = dom_core::block_reward(height).noms() + total_fees;
    let blinding = blinding(seed);
    let commitment = Commitment::commit(explicit_value, &blinding);
    let (proof, _) = dom_crypto::bp2_prove(explicit_value, &blinding).expect("coinbase proof");
    let excess = Commitment::commit(0, &blinding);
    let secret = SecretKey::from_bytes(blinding.as_bytes()).expect("coinbase secret");
    let msg = {
        let mut data = Vec::with_capacity(1 + 8);
        data.push(KERNEL_FEAT_COINBASE);
        data.extend_from_slice(&explicit_value.to_le_bytes());
        blake2b_256_tagged(TAG_KERNEL_MSG_COINBASE, &data)
    };
    let sig = schnorr_sign(&secret, msg.as_bytes(), &test_chain_id()).expect("coinbase sig");

    CoinbaseTransaction {
        output: TransactionOutput { commitment, proof },
        kernel: CoinbaseKernel {
            features: KERNEL_FEAT_COINBASE,
            explicit_value,
            excess,
            excess_signature: sig.to_bytes(),
        },
        offset: [0u8; 32],
    }
}

fn valid_spend_tx(
    input_value: u64,
    input_blinding: BlindingFactor,
    output_value: u64,
    kernel_seed: u8,
) -> Transaction {
    let fee = input_value
        .checked_sub(output_value)
        .expect("spend output must not exceed input");
    let kernel_blinding = blinding(kernel_seed);
    let output_blinding = input_blinding
        .add(&kernel_blinding)
        .expect("output blinding add");
    let input_commitment = Commitment::commit(input_value, &input_blinding);
    let output_commitment = Commitment::commit(output_value, &output_blinding);
    let (proof, _) = dom_crypto::bp2_prove(output_value, &output_blinding).expect("tx proof");
    let excess = Commitment::commit(0, &kernel_blinding);
    let secret = SecretKey::from_bytes(kernel_blinding.as_bytes()).expect("kernel secret");
    let sig = schnorr_sign(&secret, &kernel_message(fee, 0), &test_chain_id()).expect("kernel sig");

    Transaction {
        inputs: vec![TransactionInput {
            commitment: input_commitment,
        }],
        outputs: vec![TransactionOutput {
            commitment: output_commitment,
            proof,
        }],
        kernels: vec![TransactionKernel {
            features: KERNEL_FEAT_PLAIN,
            fee: Amount::from_noms(fee).expect("fee"),
            lock_height: 0,
            excess,
            excess_signature: sig.to_bytes(),
        }],
        offset: [0u8; 32],
    }
}

fn signed_coinbase(height: BlockHeight, seed: u8) -> CoinbaseTransaction {
    let reward = dom_core::block_reward(height).noms();
    let blinding = blinding(seed);
    let commitment = Commitment::commit(reward, &blinding);
    let (proof, _) = dom_crypto::bp2_prove(reward, &blinding).expect("coinbase proof");
    let excess = Commitment::commit(0, &blinding);
    let secret = SecretKey::from_bytes(blinding.as_bytes()).expect("coinbase secret");
    let chain_id = derive_chain_id(
        dom_core::NETWORK_MAGIC_REGTEST,
        &Hash256::from_bytes(dom_core::GENESIS_HASH_REGTEST),
    );
    let msg = {
        let mut data = Vec::with_capacity(1 + 8);
        data.push(KERNEL_FEAT_COINBASE);
        data.extend_from_slice(&reward.to_le_bytes());
        blake2b_256_tagged(TAG_KERNEL_MSG_COINBASE, &data)
    };
    let sig = schnorr_sign(&secret, msg.as_bytes(), chain_id.as_bytes()).expect("coinbase sig");
    CoinbaseTransaction {
        output: TransactionOutput { commitment, proof },
        kernel: CoinbaseKernel {
            features: KERNEL_FEAT_COINBASE,
            explicit_value: reward,
            excess,
            excess_signature: sig.to_bytes(),
        },
        offset: [0u8; 32],
    }
}

fn synthetic_block(
    prev_hash: Hash256,
    height: u64,
    total_difficulty: u64,
    nonce_seed: u64,
    coinbase_seed: u8,
    transactions: Vec<Transaction>,
) -> Block {
    let total_fees = transactions.iter().map(|tx| tx.total_fee().unwrap()).sum();
    let coinbase = valid_coinbase(BlockHeight(height), total_fees, coinbase_seed);
    let (output_root, kernel_root, rangeproof_root) =
        compute_block_pmmr_roots(&coinbase, &transactions).expect("pmmr roots");

    Block {
        header: BlockHeader {
            version: PROTOCOL_VERSION,
            height: BlockHeight(height),
            prev_hash,
            timestamp: Timestamp(1_700_100_000 + height),
            output_root,
            kernel_root,
            rangeproof_root,
            total_kernel_offset: [0u8; 32],
            target: CompactTarget(0),
            total_difficulty: U256::from(total_difficulty),
            pow: ProofOfWork {
                nonce: nonce_seed,
                randomx_hash: Hash256::ZERO,
            },
        },
        coinbase,
        transactions,
    }
}

fn valid_coinbase_only_block(
    prev_hash: Hash256,
    height: u64,
    total_difficulty: u64,
    nonce_seed: u64,
    coinbase_seed: u8,
) -> Block {
    let coinbase = signed_coinbase(BlockHeight(height), coinbase_seed);
    let (output_root, kernel_root, rangeproof_root) =
        compute_block_pmmr_roots(&coinbase, &[]).expect("pmmr roots");
    Block {
        header: BlockHeader {
            version: PROTOCOL_VERSION,
            height: BlockHeight(height),
            prev_hash,
            timestamp: Timestamp(1_700_200_000 + height),
            output_root,
            kernel_root,
            rangeproof_root,
            total_kernel_offset: [0u8; 32],
            target: CompactTarget(0),
            total_difficulty: U256::from(total_difficulty),
            pow: ProofOfWork {
                nonce: nonce_seed,
                randomx_hash: Hash256::ZERO,
            },
        },
        coinbase,
        transactions: vec![],
    }
}

fn block_state_changes(block: &Block) -> (Vec<UtxoBytes>, Vec<SpentCommitment>) {
    let mut new_utxos = vec![(
        *block.coinbase.output.commitment.as_bytes(),
        UtxoEntry {
            block_height: block.header.height.0,
            is_coinbase: true,
            proof: block.coinbase.output.proof.clone(),
        }
        .to_bytes(),
    )];
    let mut spent_utxos = Vec::new();
    for tx in &block.transactions {
        for input in &tx.inputs {
            spent_utxos.push(*input.commitment.as_bytes());
        }
        for output in &tx.outputs {
            new_utxos.push((
                *output.commitment.as_bytes(),
                UtxoEntry {
                    block_height: block.header.height.0,
                    is_coinbase: false,
                    proof: output.proof.clone(),
                }
                .to_bytes(),
            ));
        }
    }
    (new_utxos, spent_utxos)
}

fn kernel_excesses(block: &Block, hash: Hash256) -> Vec<([u8; 33], [u8; 32])> {
    let mut out = vec![(*block.coinbase.kernel.excess.as_bytes(), *hash.as_bytes())];
    for tx in &block.transactions {
        for kernel in &tx.kernels {
            out.push((*kernel.excess.as_bytes(), *hash.as_bytes()));
        }
    }
    out
}

fn commit_genesis(store: &DomStore) -> Block {
    let block = valid_coinbase_only_block(Hash256::ZERO, 0, 1, 0xA0, 0xE0);
    commit_canonical_block(store, &block);
    block
}

fn commit_canonical_block(store: &DomStore, block: &Block) -> Hash256 {
    let header_bytes = block.header.to_bytes().expect("header serialise");
    let hash = block_hash(&block.header);
    let body_bytes = block.to_bytes().expect("block serialise");
    let (new_utxos, spent_utxos) = block_state_changes(block);
    let kernels = kernel_excesses(block, hash);
    store
        .commit_block(
            hash.as_bytes(),
            block.header.height.0,
            &header_bytes,
            &body_bytes,
            &new_utxos,
            &spent_utxos,
            &kernels,
        )
        .expect("commit canonical block");
    hash
}

fn store_side_block(store: &DomStore, block: &Block) -> Hash256 {
    let header_bytes = block.header.to_bytes().expect("header serialise");
    let hash = block_hash(&block.header);
    let body_bytes = block.to_bytes().expect("block serialise");
    store
        .store_known_block(hash.as_bytes(), &header_bytes, &body_bytes)
        .expect("store side block");
    hash
}

fn open_chain(dir: &std::path::Path) -> ChainState {
    open_test_chain(
        dir,
        Hash256::from_bytes(dom_core::GENESIS_HASH_REGTEST),
        dom_core::NETWORK_MAGIC_REGTEST,
    )
    .expect("chain open")
}

fn utxo_digest(chain: &ChainState) -> [u8; 32] {
    type B2b256 = Blake2b<U32>;
    let mut h = B2b256::new();
    for (k, v) in chain.store.read_all_utxos_raw().expect("read utxos") {
        h.update((k.len() as u64).to_le_bytes());
        h.update(&k);
        h.update((v.len() as u64).to_le_bytes());
        h.update(&v);
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&h.finalize());
    out
}

fn kernel_digest(chain: &ChainState) -> [u8; 32] {
    type B2b256 = Blake2b<U32>;
    let mut h = B2b256::new();
    for (k, v) in chain
        .store
        .read_all_kernel_index_raw()
        .expect("read kernels")
    {
        h.update((k.len() as u64).to_le_bytes());
        h.update(&k);
        h.update((v.len() as u64).to_le_bytes());
        h.update(&v);
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&h.finalize());
    out
}

fn assert_raw_maps_eq(
    actual: &BTreeMap<Vec<u8>, Vec<u8>>,
    expected: &BTreeMap<Vec<u8>, Vec<u8>>,
    label: &str,
) {
    assert_eq!(
        actual.len(),
        expected.len(),
        "{label} entry count mismatch: actual={} expected={}",
        actual.len(),
        expected.len()
    );
    for (key, expected_value) in expected {
        let actual_value = actual
            .get(key)
            .unwrap_or_else(|| panic!("{label} missing key {}", hex::encode(key)));
        assert_eq!(
            actual_value,
            expected_value,
            "{label} value mismatch for key {}: actual_len={} expected_len={}",
            hex::encode(key),
            actual_value.len(),
            expected_value.len()
        );
    }
}

// ===========================================================================
// A2-001 — reorg A->B with a SHARED tx (same kernel excess on both branches).
// ===========================================================================
//
// The single `shared_spend` is included in canonical A2 AND heavier B3, both
// spending the shared(h1) coinbase. Its kernel excess is indexed at A2
// pre-reorg and must migrate to B3 when the chain reorgs to the heavier B.
//
// CORRECT CONTRACT (asserted): the reorg SUCCEEDS, the tip advances to B4, and
// the shared kernel excess migrates A2 -> B3.
#[test]
fn a2_001_reorg_a_to_b_with_shared_tx_same_kernel_excess_must_succeed() {
    let dir = tempfile::TempDir::new().expect("tempdir");
    let store = open_test_store(dir.path());
    commit_genesis(&store);

    // Shared block h1 (coinbase seed 10).
    let shared = synthetic_block(Hash256::ZERO, 1, 1, 1, 10, vec![]);
    let shared_hash = commit_canonical_block(&store, &shared);
    let shared_cb_value = dom_core::block_reward(BlockHeight(1)).noms();
    let shared_cb_blinding = blinding(10);

    // THE SHARED TRANSACTION: built ONCE, cloned verbatim into a block on each
    // branch, so the kernel excess is byte-identical on A2 and B3.
    let shared_spend = valid_spend_tx(shared_cb_value, shared_cb_blinding, shared_cb_value - 1, 21);
    let shared_kernel = *shared_spend.kernels[0].excess.as_bytes();

    // --- Branch A (canonical): A2 includes shared_spend, then A3. ---
    let a2 = synthetic_block(shared_hash, 2, 2, 2, 11, vec![shared_spend.clone()]);
    let a2_hash = commit_canonical_block(&store, &a2);
    let a3 = synthetic_block(a2_hash, 3, 3, 3, 12, vec![]);
    let a3_hash = commit_canonical_block(&store, &a3);

    // --- Branch B (heavier side chain): B2 -> B3 (SAME shared_spend) -> B4. ---
    let b2 = synthetic_block(shared_hash, 2, 2, 20, 30, vec![]);
    let b2_hash = store_side_block(&store, &b2);
    let b3 = synthetic_block(b2_hash, 3, 3, 21, 33, vec![shared_spend.clone()]);
    let b3_hash = store_side_block(&store, &b3);
    let b4 = synthetic_block(b3_hash, 4, 4, 22, 34, vec![]);
    let b4_hash = store_side_block(&store, &b4);

    let mut chain = open_chain(dir.path());
    assert_eq!(chain.tip_hash, a3_hash, "A must be canonical pre-reorg");

    // Pre-reorg: the shared tx kernel excess is indexed at A2.
    assert_eq!(
        chain
            .store
            .get_kernel_block(&shared_kernel)
            .unwrap()
            .expect("shared kernel indexed pre-reorg"),
        *a2_hash.as_bytes(),
        "shared tx kernel must be indexed at A2 before the reorg"
    );

    // Reorg A->B must succeed. The shared kernel excess must migrate from A2 to B3.
    chain
        .promote_heavier_known_tip(b4_hash, Timestamp(2_000_000_000))
        .expect("reorg A->B with shared tx must succeed");
    assert_eq!(chain.tip_hash, b4_hash, "tip must advance to the heavier B");
    assert_eq!(chain.tip_height, BlockHeight(4));

    // After a correct reorg, the shared excess is indexed at B3 (migrated).
    assert_eq!(
        chain
            .store
            .get_kernel_block(&shared_kernel)
            .unwrap()
            .expect("shared kernel indexed post-reorg"),
        *b3_hash.as_bytes(),
        "shared tx kernel must migrate from A2 to B3 after the reorg"
    );
}

#[test]
fn shared_transaction_reorg_is_restart_and_direct_construction_equivalent() {
    let dir = tempfile::TempDir::new().expect("tempdir");
    let store = open_test_store(dir.path());
    let genesis = commit_genesis(&store);

    let shared = synthetic_block(Hash256::ZERO, 1, 1, 1, 40, vec![]);
    let shared_hash = commit_canonical_block(&store, &shared);
    let shared_cb_value = dom_core::block_reward(BlockHeight(1)).noms();
    let shared_cb_blinding = blinding(40);

    let prefix_spend = valid_spend_tx(shared_cb_value, shared_cb_blinding, shared_cb_value - 1, 41);
    let prefix_spend_blinding = blinding(40)
        .add(&blinding(41))
        .expect("prefix output blinding");
    let prefix_spend_output = *prefix_spend.outputs[0].commitment.as_bytes();
    let prefix_spend_kernel = *prefix_spend.kernels[0].excess.as_bytes();
    let prefix = synthetic_block(shared_hash, 2, 2, 2, 42, vec![prefix_spend.clone()]);
    let prefix_hash = commit_canonical_block(&store, &prefix);

    let shared_after_fork = valid_spend_tx(
        shared_cb_value - 1,
        prefix_spend_blinding,
        shared_cb_value - 2,
        43,
    );
    let shared_after_fork_output = *shared_after_fork.outputs[0].commitment.as_bytes();
    let shared_after_fork_kernel = *shared_after_fork.kernels[0].excess.as_bytes();

    let a3 = synthetic_block(prefix_hash, 3, 3, 3, 44, vec![shared_after_fork.clone()]);
    let a3_hash = commit_canonical_block(&store, &a3);
    let a4 = synthetic_block(a3_hash, 4, 4, 4, 45, vec![]);
    let a4_hash = commit_canonical_block(&store, &a4);

    let b3 = synthetic_block(prefix_hash, 3, 3, 30, 46, vec![]);
    let b3_hash = store_side_block(&store, &b3);
    let b4 = synthetic_block(b3_hash, 4, 4, 31, 47, vec![shared_after_fork.clone()]);
    let b4_hash = store_side_block(&store, &b4);
    let b5 = synthetic_block(b4_hash, 5, 5, 32, 48, vec![]);
    let b5_hash = store_side_block(&store, &b5);
    let a5 = synthetic_block(a4_hash, 5, 6, 50, 49, vec![]);
    let a5_hash = store_side_block(&store, &a5);
    drop(store);

    let mut chain = open_chain(dir.path());
    assert_eq!(chain.tip_hash, a4_hash);
    assert_eq!(
        chain.store.get_kernel_block(&prefix_spend_kernel).unwrap(),
        Some(*prefix_hash.as_bytes()),
        "common-prefix transaction kernel must be owned by the prefix block"
    );
    assert_eq!(
        chain
            .store
            .get_kernel_block(&shared_after_fork_kernel)
            .unwrap(),
        Some(*a3_hash.as_bytes()),
        "post-divergence shared transaction starts on branch A"
    );

    chain
        .promote_heavier_known_tip(b5_hash, Timestamp(2_000_000_000))
        .expect("A->B shared transaction reorg");
    assert_eq!(chain.tip_hash, b5_hash);
    assert_eq!(
        chain.store.get_kernel_block(&prefix_spend_kernel).unwrap(),
        Some(*prefix_hash.as_bytes()),
        "common-prefix transaction kernel must not be re-owned by the reorg"
    );
    assert!(
        chain
            .store
            .get_utxo(&prefix_spend_output)
            .unwrap()
            .is_none(),
        "common-prefix output is spent by the canonical branch after reorg"
    );
    assert_eq!(
        chain
            .store
            .get_kernel_block(&shared_after_fork_kernel)
            .unwrap(),
        Some(*b4_hash.as_bytes()),
        "post-divergence shared transaction kernel must migrate to branch B"
    );
    let b_shared_output = chain
        .store
        .get_utxo(&shared_after_fork_output)
        .unwrap()
        .expect("shared transaction output present on B");
    assert_eq!(b_shared_output.block_height, 4);
    assert!(!b_shared_output.is_coinbase);

    drop(chain);
    let reopened_b = open_chain(dir.path());
    assert_eq!(reopened_b.tip_hash, b5_hash);
    let reorg_b_utxos: BTreeMap<Vec<u8>, Vec<u8>> = reopened_b.store.read_all_utxos_raw().unwrap();
    let reorg_b_kernels: BTreeMap<Vec<u8>, Vec<u8>> =
        reopened_b.store.read_all_kernel_index_raw().unwrap();
    let reorg_b_utxo_digest = utxo_digest(&reopened_b);
    let reorg_b_kernel_digest = kernel_digest(&reopened_b);
    drop(reopened_b);

    let direct_dir = tempfile::TempDir::new().expect("direct tempdir");
    let direct_store = open_test_store(direct_dir.path());
    commit_canonical_block(&direct_store, &genesis);
    commit_canonical_block(&direct_store, &shared);
    commit_canonical_block(&direct_store, &prefix);
    commit_canonical_block(&direct_store, &b3);
    commit_canonical_block(&direct_store, &b4);
    commit_canonical_block(&direct_store, &b5);
    drop(direct_store);
    let direct_b = open_chain(direct_dir.path());
    assert_eq!(direct_b.tip_hash, b5_hash);
    assert_raw_maps_eq(
        &direct_b.store.read_all_utxos_raw().unwrap(),
        &reorg_b_utxos,
        "A->B reorg UTXO set vs direct B construction",
    );
    assert_raw_maps_eq(
        &direct_b.store.read_all_kernel_index_raw().unwrap(),
        &reorg_b_kernels,
        "A->B reorg kernel index vs direct B construction",
    );
    assert_eq!(utxo_digest(&direct_b), reorg_b_utxo_digest);
    assert_eq!(kernel_digest(&direct_b), reorg_b_kernel_digest);
    drop(direct_b);

    let mut chain = open_chain(dir.path());
    chain
        .promote_heavier_known_tip(a5_hash, Timestamp(2_000_000_000))
        .expect("B->A shared transaction reorg");
    assert_eq!(chain.tip_hash, a5_hash);
    assert_eq!(
        chain.store.get_kernel_block(&prefix_spend_kernel).unwrap(),
        Some(*prefix_hash.as_bytes()),
        "common-prefix transaction remains owned by the prefix block after B->A"
    );
    assert_eq!(
        chain
            .store
            .get_kernel_block(&shared_after_fork_kernel)
            .unwrap(),
        Some(*a3_hash.as_bytes()),
        "post-divergence shared transaction kernel must migrate back to branch A"
    );
    let a_shared_output = chain
        .store
        .get_utxo(&shared_after_fork_output)
        .unwrap()
        .expect("shared transaction output present on A");
    assert_eq!(a_shared_output.block_height, 3);
    assert!(!a_shared_output.is_coinbase);
    assert!(
        chain
            .store
            .get_kernel_block(b4.coinbase.kernel.excess.as_bytes())
            .unwrap()
            .is_none(),
        "B-only kernel must be removed after reorg back to A"
    );
    drop(chain);

    let reopened_a = open_chain(dir.path());
    assert_eq!(reopened_a.tip_hash, a5_hash);
    assert_eq!(
        reopened_a
            .store
            .get_kernel_block(&shared_after_fork_kernel)
            .unwrap(),
        Some(*a3_hash.as_bytes())
    );
    assert_eq!(
        reopened_a
            .store
            .get_utxo(&shared_after_fork_output)
            .unwrap()
            .expect("shared output survives B->A restart")
            .block_height,
        3
    );
}
