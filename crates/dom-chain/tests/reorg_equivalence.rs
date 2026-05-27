//! Roadmap v2 Phase 1.2 — Reorg equivalence framework.
//!
//! The integration-level reorg test (`dom-integration-tests/tests/reorg.rs`)
//! is ENV-BLOCKED on WSL2: it spins real RandomX miners on the Regtest
//! target, which the host can't sustain inside the test deadline. This
//! file fills the gap by exercising the reorg primitives that *don't*
//! need mining: the chain-DAG walks. They run in milliseconds and can
//! ship in CI without any host-specific assumptions.
//!
//! What is covered here:
//! 1. `find_common_ancestor` on synthetic header DAGs. The function is
//!    pure graph traversal over `prev_hash` links; given a populated
//!    `DomStore` it does not touch PoW, signatures, or the UTXO set.
//!    The synthetic chains here therefore use placeholder PoW / target
//!    / commitment fields, but real header layout and real hashing
//!    (Blake2b-256 of the serialised header) so the on-disk hash chain
//!    is identical to what a live node would produce.
//! 2. `check_reorg_depth` boundary behaviour against
//!    `MAX_REORG_DEPTH_POLICY`.
//!
use blake2::digest::consts::U32;
use blake2::{Blake2b, Digest};
use dom_chain::reorg::{check_reorg_depth, find_common_ancestor};
use dom_chain::ChainState;
use dom_consensus::block::{BlockHeader, ProofOfWork};
use dom_consensus::{
    Block, CoinbaseKernel, CoinbaseTransaction, Transaction, TransactionInput, TransactionKernel,
    TransactionOutput,
};
use dom_core::{Amount, BlockHeight, Hash256, Timestamp, KERNEL_FEAT_COINBASE, KERNEL_FEAT_PLAIN};
use dom_crypto::pedersen::{BlindingFactor, Commitment};
use dom_pow::CompactTarget;
use dom_serialization::DomSerialize;
use dom_store::utxo::UtxoEntry;
use dom_store::DomStore;
use primitive_types::U256;
use tempfile::TempDir;

type UtxoBytes = ([u8; 33], Vec<u8>);
type SpentCommitment = [u8; 33];

/// Build a synthetic header with a controllable `prev_hash` and `height`.
/// Other fields are zeroed because the helpers exercised here do not
/// read them.
fn synthetic_header(prev_hash: Hash256, height: u64, nonce_seed: u64) -> BlockHeader {
    BlockHeader {
        version: 1,
        height: BlockHeight(height),
        prev_hash,
        timestamp: Timestamp(1_700_000_000 + height),
        output_root: Hash256::ZERO,
        kernel_root: Hash256::ZERO,
        rangeproof_root: Hash256::ZERO,
        total_kernel_offset: [0u8; 32],
        target: CompactTarget(0),
        total_difficulty: U256::from(height),
        // Vary `nonce` so two forks at the same height hash differently.
        pow: ProofOfWork {
            nonce: nonce_seed,
            randomx_hash: Hash256::ZERO,
        },
    }
}

/// Same hashing scheme as `chain_state::compute_block_hash`: Blake2b-256
/// of the serialised header bytes. Kept private there, re-implemented
/// here because tests are the public contract.
fn block_hash(header: &BlockHeader) -> Hash256 {
    let bytes = header.to_bytes().expect("header serialise");
    type B2b256 = Blake2b<U32>;
    let mut h = B2b256::new();
    h.update(&bytes);
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&h.finalize());
    Hash256::from_bytes(arr)
}

/// Push a synthetic block by writing only its header + body. The
/// store's `commit_block` requires a full block body and a UTXO / kernel
/// changeset, none of which are relevant to the chain-DAG walk — using
/// it here would force this test to fabricate consensus-valid bodies.
/// Instead we put directly into the same LMDB databases via the higher
/// `BlockStore` trait surface that `DomStore` already exposes.
fn put_header(store: &DomStore, header: &BlockHeader) -> Hash256 {
    let hash = block_hash(header);
    let header_bytes = header.to_bytes().expect("header serialise");
    // The body can be any bytes — find_common_ancestor never reads it,
    // and the NO_OVERWRITE check is keyed on the hash.
    let body_bytes = vec![0u8; 8];
    store
        .commit_block(
            hash.as_bytes(),
            header.height.0,
            &header_bytes,
            &body_bytes,
            &[],
            &[],
            &[],
        )
        .expect("commit_block (synthetic)");
    hash
}

/// Build a linear chain of `len` headers starting from `start_prev` and
/// `start_height`. Returns every hash, in order.
fn build_chain(
    store: &DomStore,
    start_prev: Hash256,
    start_height: u64,
    len: u64,
    nonce_offset: u64,
) -> Vec<Hash256> {
    let mut hashes = Vec::with_capacity(len as usize);
    let mut prev = start_prev;
    for i in 0..len {
        let header = synthetic_header(prev, start_height + i, nonce_offset + i);
        prev = put_header(store, &header);
        hashes.push(prev);
    }
    hashes
}

fn blinding(seed: u8) -> BlindingFactor {
    let mut bytes = [0u8; 32];
    bytes[31] = seed.max(1);
    BlindingFactor::from_bytes(bytes).expect("deterministic blinding")
}

fn commitment(seed: u8, value: u64) -> Commitment {
    Commitment::commit(value, &blinding(seed))
}

fn tx_output(seed: u8, value: u64) -> TransactionOutput {
    TransactionOutput {
        commitment: commitment(seed, value),
        proof: vec![seed; 8],
    }
}

fn tx_kernel(seed: u8) -> TransactionKernel {
    TransactionKernel {
        features: KERNEL_FEAT_PLAIN,
        fee: Amount::ZERO,
        lock_height: 0,
        excess: commitment(seed, 0),
        excess_signature: [seed; 65],
    }
}

fn spend_tx(input: Commitment, output_seed: u8, kernel_seed: u8) -> Transaction {
    Transaction {
        inputs: vec![TransactionInput { commitment: input }],
        outputs: vec![tx_output(output_seed, u64::from(output_seed) + 1)],
        kernels: vec![tx_kernel(kernel_seed)],
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
    Block {
        header: BlockHeader {
            version: 1,
            height: BlockHeight(height),
            prev_hash,
            timestamp: Timestamp(1_700_100_000 + height),
            output_root: Hash256::ZERO,
            kernel_root: Hash256::ZERO,
            rangeproof_root: Hash256::ZERO,
            total_kernel_offset: [0u8; 32],
            target: CompactTarget(0),
            total_difficulty: U256::from(total_difficulty),
            pow: ProofOfWork {
                nonce: nonce_seed,
                randomx_hash: Hash256::ZERO,
            },
        },
        coinbase: CoinbaseTransaction {
            output: tx_output(coinbase_seed, 1_000 + height),
            kernel: CoinbaseKernel {
                features: KERNEL_FEAT_COINBASE,
                explicit_value: 1,
                excess: commitment(coinbase_seed.wrapping_add(100), 0),
                excess_signature: [coinbase_seed; 65],
            },
            offset: [0u8; 32],
        },
        transactions,
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
    let store = DomStore::open(dir).expect("store open");
    ChainState::open(
        store,
        Hash256::from_bytes(dom_core::GENESIS_HASH_REGTEST),
        dom_core::NETWORK_MAGIC_REGTEST,
    )
    .expect("chain open")
}

#[test]
fn find_common_ancestor_same_tip_is_self() {
    let dir = TempDir::new().expect("tempdir");
    let store = DomStore::open(dir.path()).expect("open");
    let chain = build_chain(&store, Hash256::ZERO, 1, 5, 0);
    let tip = *chain.last().unwrap();

    let ancestor = find_common_ancestor(&store, tip, tip).expect("walk");
    assert_eq!(ancestor, Some(tip));
}

#[test]
fn find_common_ancestor_linear_chain_to_genesis() {
    let dir = TempDir::new().expect("tempdir");
    let store = DomStore::open(dir.path()).expect("open");
    // One single chain, two cursors at different depths along it.
    let chain = build_chain(&store, Hash256::ZERO, 1, 10, 0);
    let near = chain[3];
    let far = chain[9];

    let ancestor = find_common_ancestor(&store, far, near).expect("walk");
    assert_eq!(
        ancestor,
        Some(near),
        "the lower cursor must itself be the common ancestor",
    );
}

#[test]
fn find_common_ancestor_two_forks_at_known_depth() {
    let dir = TempDir::new().expect("tempdir");
    let store = DomStore::open(dir.path()).expect("open");

    // Shared prefix: genesis → A1 → A2 → A3.
    let prefix = build_chain(&store, Hash256::ZERO, 1, 3, 0);
    let fork_point = *prefix.last().unwrap();

    // Branch A continues for 4 more blocks.
    let branch_a = build_chain(&store, fork_point, 4, 4, 1_000);
    // Branch B continues for 5 more blocks with different nonces so the
    // hashes diverge from branch A immediately.
    let branch_b = build_chain(&store, fork_point, 4, 5, 2_000);

    let tip_a = *branch_a.last().unwrap();
    let tip_b = *branch_b.last().unwrap();

    let ancestor = find_common_ancestor(&store, tip_a, tip_b).expect("walk");
    assert_eq!(
        ancestor,
        Some(fork_point),
        "the last shared block before the fork must be the common ancestor",
    );
}

#[test]
fn find_common_ancestor_separate_genesis_chains_share_zero() {
    let dir = TempDir::new().expect("tempdir");
    let store = DomStore::open(dir.path()).expect("open");

    // Two chains, each rooted at its own real genesis block whose
    // prev_hash terminates at Hash256::ZERO. The walks therefore both
    // insert Hash256::ZERO into the ancestor set, so the function
    // returns Some(ZERO). Semantically that means "no real shared
    // history" — callers must treat ZERO as the empty-state sentinel,
    // not a usable block, but the function's contract is exactly that.
    let chain1 = build_chain(&store, Hash256::ZERO, 1, 5, 0);
    let chain2 = build_chain(&store, Hash256::ZERO, 1, 5, 10_000);

    let ancestor = find_common_ancestor(&store, *chain1.last().unwrap(), *chain2.last().unwrap())
        .expect("walk");
    assert_eq!(
        ancestor,
        Some(Hash256::ZERO),
        "two chains terminating at ZERO must share ZERO as the walk ancestor",
    );
}

#[test]
fn find_common_ancestor_returns_none_when_their_chain_unknown() {
    let dir = TempDir::new().expect("tempdir");
    let store = DomStore::open(dir.path()).expect("open");

    // Our chain is fully populated.
    let ours = build_chain(&store, Hash256::ZERO, 1, 5, 0);
    let our_tip = *ours.last().unwrap();

    // Pick a hash the store has never seen. The walk for "their" tip
    // immediately fails to find the header and the function reports
    // Ok(None) per its documented behaviour for partially-known remote
    // chains.
    let mut unknown = [0u8; 32];
    unknown[0] = 0xDE;
    unknown[1] = 0xAD;
    let their_tip = Hash256::from_bytes(unknown);

    let ancestor = find_common_ancestor(&store, our_tip, their_tip).expect("walk");
    assert!(
        ancestor.is_none(),
        "unknown remote tip must report no ancestor (signals: ask for headers first)",
    );
}

#[test]
fn find_common_ancestor_unbalanced_depths() {
    let dir = TempDir::new().expect("tempdir");
    let store = DomStore::open(dir.path()).expect("open");

    // Shared prefix is tiny (1 block), branches are very different lengths.
    let prefix = build_chain(&store, Hash256::ZERO, 1, 1, 0);
    let fork = *prefix.last().unwrap();
    let short = build_chain(&store, fork, 2, 2, 100);
    let long = build_chain(&store, fork, 2, 50, 5_000);

    let ancestor =
        find_common_ancestor(&store, *short.last().unwrap(), *long.last().unwrap()).expect("walk");
    assert_eq!(ancestor, Some(fork));
}

#[test]
fn check_reorg_depth_boundary() {
    // Exactly at the policy limit must be accepted; one over must be rejected.
    check_reorg_depth(dom_core::MAX_REORG_DEPTH_POLICY).expect("at-limit must be accepted");
    check_reorg_depth(dom_core::MAX_REORG_DEPTH_POLICY + 1)
        .expect_err("over-limit must be rejected");
    check_reorg_depth(0).expect("zero (no disconnect) is always accepted");
}

#[test]
fn promote_heavier_known_tip_rewrites_canonical_state_and_survives_restart() {
    let dir = TempDir::new().expect("tempdir");
    let store = DomStore::open(dir.path()).expect("open");

    let shared = synthetic_block(Hash256::ZERO, 1, 1, 1, 10, vec![]);
    let shared_hash = commit_canonical_block(&store, &shared);

    let shared_coinbase_commitment = shared.coinbase.output.commitment.clone();
    let old_spend = spend_tx(shared_coinbase_commitment.clone(), 20, 21);
    let old_2 = synthetic_block(shared_hash, 2, 2, 2, 11, vec![old_spend.clone()]);
    let old_2_hash = commit_canonical_block(&store, &old_2);
    let old_3 = synthetic_block(old_2_hash, 3, 3, 3, 12, vec![]);
    let old_3_hash = commit_canonical_block(&store, &old_3);

    let alt_2 = synthetic_block(shared_hash, 2, 2, 20, 30, vec![]);
    let alt_2_hash = store_side_block(&store, &alt_2);
    let alt_spend = spend_tx(shared_coinbase_commitment, 31, 32);
    let alt_3 = synthetic_block(alt_2_hash, 3, 3, 21, 33, vec![alt_spend.clone()]);
    let alt_3_hash = store_side_block(&store, &alt_3);
    let alt_4 = synthetic_block(alt_3_hash, 4, 4, 22, 34, vec![]);
    let alt_4_hash = store_side_block(&store, &alt_4);

    let mut chain = open_chain(dir.path());
    assert_eq!(chain.tip_hash, old_3_hash);

    let reorg = chain
        .promote_heavier_known_tip(alt_4_hash)
        .expect("reorg promotion");

    assert_eq!(reorg.disconnected_txs.len(), 1);
    assert_eq!(reorg.connected_txs.len(), 1);
    assert_eq!(
        *reorg.disconnected_txs[0].outputs[0].commitment.as_bytes(),
        *old_spend.outputs[0].commitment.as_bytes()
    );
    assert_eq!(
        *reorg.connected_txs[0].outputs[0].commitment.as_bytes(),
        *alt_spend.outputs[0].commitment.as_bytes()
    );

    assert_eq!(chain.tip_hash, alt_4_hash);
    assert_eq!(chain.tip_height, BlockHeight(4));
    assert_eq!(
        chain.store.get_hash_at_height(2).unwrap().unwrap(),
        *alt_2_hash.as_bytes()
    );
    assert_eq!(
        chain.store.get_hash_at_height(3).unwrap().unwrap(),
        *alt_3_hash.as_bytes()
    );
    assert_eq!(
        chain.store.get_hash_at_height(4).unwrap().unwrap(),
        *alt_4_hash.as_bytes()
    );

    let shared_coinbase = *shared.coinbase.output.commitment.as_bytes();
    let old_spend_out = *old_spend.outputs[0].commitment.as_bytes();
    let old_2_coinbase = *old_2.coinbase.output.commitment.as_bytes();
    let old_3_coinbase = *old_3.coinbase.output.commitment.as_bytes();
    let alt_spend_out = *alt_spend.outputs[0].commitment.as_bytes();
    let alt_2_coinbase = *alt_2.coinbase.output.commitment.as_bytes();
    let alt_3_coinbase = *alt_3.coinbase.output.commitment.as_bytes();
    let alt_4_coinbase = *alt_4.coinbase.output.commitment.as_bytes();

    assert!(
        chain.store.get_utxo(&shared_coinbase).unwrap().is_none(),
        "shared coinbase is spent on the promoted branch"
    );
    assert!(
        chain.store.get_utxo(&old_spend_out).unwrap().is_none(),
        "old branch spend output must be removed"
    );
    assert!(chain.store.get_utxo(&old_2_coinbase).unwrap().is_none());
    assert!(chain.store.get_utxo(&old_3_coinbase).unwrap().is_none());

    let alt_spend_entry = chain
        .store
        .get_utxo(&alt_spend_out)
        .unwrap()
        .expect("alt spend output present");
    assert_eq!(alt_spend_entry.block_height, 3);
    assert!(!alt_spend_entry.is_coinbase);
    assert!(chain.store.get_utxo(&alt_2_coinbase).unwrap().is_some());
    assert!(chain.store.get_utxo(&alt_3_coinbase).unwrap().is_some());
    assert!(chain.store.get_utxo(&alt_4_coinbase).unwrap().is_some());

    let old_kernel = *old_2.coinbase.kernel.excess.as_bytes();
    let new_kernel = *alt_4.coinbase.kernel.excess.as_bytes();
    assert!(chain.store.get_kernel_block(&old_kernel).unwrap().is_none());
    assert_eq!(
        chain.store.get_kernel_block(&new_kernel).unwrap().unwrap(),
        *alt_4_hash.as_bytes()
    );

    drop(chain);
    let reopened = open_chain(dir.path());
    assert_eq!(reopened.tip_hash, alt_4_hash);
    assert_eq!(reopened.tip_height, BlockHeight(4));
    assert_eq!(
        reopened.store.get_hash_at_height(4).unwrap().unwrap(),
        *alt_4_hash.as_bytes()
    );
    assert!(reopened.store.get_utxo(&alt_spend_out).unwrap().is_some());
    assert!(reopened.store.get_utxo(&old_spend_out).unwrap().is_none());
}
