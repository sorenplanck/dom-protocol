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
use dom_chain::{
    ChainState, MAX_RETAINED_SIDE_BRANCH_LENGTH, MAX_RETAINED_SIDE_BRANCH_REORG_DEPTH,
    MAX_RETAINED_SIDE_BRANCH_TIPS,
};
use dom_consensus::block::{BlockHeader, ProofOfWork};
use dom_consensus::{
    compute_block_pmmr_roots, derive_chain_id, Block, CoinbaseKernel, CoinbaseTransaction,
    Transaction, TransactionInput, TransactionKernel, TransactionOutput,
};
use dom_core::{
    Amount, BlockHeight, Hash256, Timestamp, KERNEL_FEAT_COINBASE, KERNEL_FEAT_PLAIN,
    PROTOCOL_VERSION, TAG_KERNEL_MSG, TAG_KERNEL_MSG_COINBASE,
};
use dom_crypto::bulletproof;
use dom_crypto::hash::blake2b_256_tagged;
use dom_crypto::keys::SecretKey;
use dom_crypto::pedersen::{BlindingFactor, Commitment};
use dom_crypto::schnorr_sign;
use dom_pow::CompactTarget;
use dom_serialization::DomSerialize;
use dom_store::utxo::UtxoEntry;
use dom_store::DomStore;
use primitive_types::U256;
use std::collections::BTreeSet;
use tempfile::TempDir;

type UtxoBytes = ([u8; 33], Vec<u8>);
type SpentCommitment = [u8; 33];

/// Build a synthetic header with a controllable `prev_hash` and `height`.
/// Other fields are zeroed because the helpers exercised here do not
/// read them.
fn synthetic_header(prev_hash: Hash256, height: u64, nonce_seed: u64) -> BlockHeader {
    BlockHeader {
        version: PROTOCOL_VERSION,
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
    let (proof, _) = bulletproof::prove(explicit_value, &blinding).expect("coinbase proof");
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
        output: TransactionOutput {
            commitment,
            proof: proof.bytes,
        },
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
    let (proof, _) = bulletproof::prove(output_value, &output_blinding).expect("tx proof");
    let excess = Commitment::commit(0, &kernel_blinding);
    let secret = SecretKey::from_bytes(kernel_blinding.as_bytes()).expect("kernel secret");
    let sig = schnorr_sign(&secret, &kernel_message(fee, 0), &test_chain_id()).expect("kernel sig");

    Transaction {
        inputs: vec![TransactionInput {
            commitment: input_commitment,
        }],
        outputs: vec![TransactionOutput {
            commitment: output_commitment,
            proof: proof.bytes,
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
    let (proof, _) = bulletproof::prove(reward, &blinding).expect("coinbase proof");
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
        output: TransactionOutput {
            commitment,
            proof: proof.bytes,
        },
        kernel: CoinbaseKernel {
            features: KERNEL_FEAT_COINBASE,
            explicit_value: reward,
            excess,
            excess_signature: sig.to_bytes(),
        },
        offset: [0u8; 32],
    }
}

fn valid_reorg_block(
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

fn retained_noncanonical_hashes(chain: &ChainState) -> BTreeSet<[u8; 32]> {
    let canonical: BTreeSet<[u8; 32]> = (0..=chain.tip_height.0)
        .filter_map(|height| chain.store.get_hash_at_height(height).unwrap())
        .collect();
    chain
        .store
        .read_all_block_headers_raw()
        .expect("read all headers")
        .into_keys()
        .filter(|hash| !canonical.contains(hash))
        .collect()
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
fn promote_heavier_known_tip_emits_block_level_reorg_metadata() {
    let dir = TempDir::new().expect("tempdir");
    let store = DomStore::open(dir.path()).expect("open");

    let shared = valid_coinbase_only_block(Hash256::ZERO, 1, 1, 1, 10);
    let shared_hash = commit_canonical_block(&store, &shared);
    let old_2 = valid_coinbase_only_block(shared_hash, 2, 2, 2, 11);
    let old_2_hash = commit_canonical_block(&store, &old_2);
    let old_3 = valid_coinbase_only_block(old_2_hash, 3, 3, 3, 12);
    let old_3_hash = commit_canonical_block(&store, &old_3);

    let alt_2 = valid_coinbase_only_block(shared_hash, 2, 2, 20, 30);
    let alt_2_hash = store_side_block(&store, &alt_2);
    let alt_3 = valid_coinbase_only_block(alt_2_hash, 3, 3, 21, 33);
    let alt_3_hash = store_side_block(&store, &alt_3);
    let alt_4 = valid_coinbase_only_block(alt_3_hash, 4, 4, 22, 34);
    let alt_4_hash = store_side_block(&store, &alt_4);

    let mut chain = open_chain(dir.path());
    let reorg = chain
        .promote_heavier_known_tip(alt_4_hash)
        .expect("reorg promotion");

    assert_eq!(reorg.common_ancestor_height, 1);
    assert!(reorg.disconnected_txs.is_empty());
    assert!(reorg.connected_txs.is_empty());
    assert_eq!(
        reorg
            .disconnected_blocks
            .iter()
            .map(|b| (b.block_height, b.block_hash, b.transactions.len()))
            .collect::<Vec<_>>(),
        vec![
            (3, *old_3_hash.as_bytes(), 0),
            (2, *old_2_hash.as_bytes(), 0)
        ]
    );
    assert_eq!(
        reorg
            .connected_blocks
            .iter()
            .map(|b| (b.block_height, b.block_hash, b.transactions.len()))
            .collect::<Vec<_>>(),
        vec![
            (2, *alt_2_hash.as_bytes(), 0),
            (3, *alt_3_hash.as_bytes(), 0),
            (4, *alt_4_hash.as_bytes(), 0)
        ]
    );
}

#[test]
fn promote_heavier_known_tip_rewrites_canonical_state_and_survives_restart() {
    let dir = TempDir::new().expect("tempdir");
    let store = DomStore::open(dir.path()).expect("open");

    let shared = valid_reorg_block(Hash256::ZERO, 1, 1, 1, 10, vec![]);
    let shared_hash = commit_canonical_block(&store, &shared);

    let shared_coinbase_value = dom_core::block_reward(BlockHeight(1)).noms();
    let shared_coinbase_blinding = blinding(10);
    let old_spend = valid_spend_tx(
        shared_coinbase_value,
        shared_coinbase_blinding.clone(),
        shared_coinbase_value - 1,
        21,
    );
    let old_2 = valid_reorg_block(shared_hash, 2, 2, 2, 11, vec![old_spend.clone()]);
    let old_2_hash = commit_canonical_block(&store, &old_2);
    let old_3 = valid_reorg_block(old_2_hash, 3, 3, 3, 12, vec![]);
    let old_3_hash = commit_canonical_block(&store, &old_3);

    let alt_2 = valid_reorg_block(shared_hash, 2, 2, 20, 30, vec![]);
    let alt_2_hash = store_side_block(&store, &alt_2);
    let alt_spend = valid_spend_tx(
        shared_coinbase_value,
        shared_coinbase_blinding,
        shared_coinbase_value - 2,
        32,
    );
    let alt_3 = valid_reorg_block(alt_2_hash, 3, 3, 21, 33, vec![alt_spend.clone()]);
    let alt_3_hash = store_side_block(&store, &alt_3);
    let alt_4 = valid_reorg_block(alt_3_hash, 4, 4, 22, 34, vec![]);
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

#[test]
fn side_chain_retention_prunes_to_deterministic_tip_bound_and_survives_restart() {
    let dir = TempDir::new().expect("tempdir");
    let store = DomStore::open(dir.path()).expect("open");

    let canonical_1 = valid_coinbase_only_block(Hash256::ZERO, 1, 100, 1, 60);
    let canonical_1_hash = commit_canonical_block(&store, &canonical_1);
    let canonical_2 = valid_coinbase_only_block(canonical_1_hash, 2, 200, 2, 61);
    commit_canonical_block(&store, &canonical_2);

    let mut all_side_tips = Vec::new();
    for i in 0..(MAX_RETAINED_SIDE_BRANCH_TIPS + 2) {
        let block = valid_coinbase_only_block(
            canonical_1_hash,
            2,
            10 + i as u64,
            100 + i as u64,
            70 + i as u8,
        );
        let hash = store_side_block(&store, &block);
        all_side_tips.push(hash);
    }

    let expected_retained: BTreeSet<[u8; 32]> = all_side_tips
        .iter()
        .rev()
        .take(MAX_RETAINED_SIDE_BRANCH_TIPS)
        .map(|hash| *hash.as_bytes())
        .collect();

    let reopened = open_chain(dir.path());
    let retained = retained_noncanonical_hashes(&reopened);
    assert_eq!(retained.len(), MAX_RETAINED_SIDE_BRANCH_TIPS);
    assert_eq!(retained, expected_retained);
    assert_eq!(
        reopened.tip_height,
        BlockHeight(2),
        "side retention must not rewrite canonical tip on reopen"
    );

    drop(reopened);
    let reopened_again = open_chain(dir.path());
    assert_eq!(
        retained_noncanonical_hashes(&reopened_again),
        expected_retained
    );
}

#[test]
fn retained_reorg_candidate_is_not_pruned_before_promotion() {
    let dir = TempDir::new().expect("tempdir");
    let store = DomStore::open(dir.path()).expect("open");

    let shared = valid_coinbase_only_block(Hash256::ZERO, 1, 100, 1, 80);
    let shared_hash = commit_canonical_block(&store, &shared);
    let canonical_2 = valid_coinbase_only_block(shared_hash, 2, 200, 2, 81);
    let canonical_2_hash = commit_canonical_block(&store, &canonical_2);
    let canonical_3 = valid_coinbase_only_block(canonical_2_hash, 3, 300, 3, 82);
    commit_canonical_block(&store, &canonical_3);

    let candidate_2 = valid_coinbase_only_block(shared_hash, 2, 190, 20, 90);
    let candidate_2_hash = store_side_block(&store, &candidate_2);
    let candidate_3 = valid_coinbase_only_block(candidate_2_hash, 3, 280, 21, 91);
    let candidate_3_hash = store_side_block(&store, &candidate_3);
    let candidate_4 = valid_coinbase_only_block(candidate_3_hash, 4, 310, 22, 92);
    let candidate_4_hash = store_side_block(&store, &candidate_4);

    for i in 0..(MAX_RETAINED_SIDE_BRANCH_TIPS - 1) {
        let spam =
            valid_coinbase_only_block(shared_hash, 2, 50 + i as u64, 40 + i as u64, 100 + i as u8);
        store_side_block(&store, &spam);
    }
    let pruned = valid_coinbase_only_block(shared_hash, 2, 1, 99, 120);
    let pruned_hash = store_side_block(&store, &pruned);

    let mut chain = open_chain(dir.path());
    let retained = retained_noncanonical_hashes(&chain);
    assert!(retained.contains(candidate_4_hash.as_bytes()));
    assert!(retained.contains(candidate_3_hash.as_bytes()));
    assert!(retained.contains(candidate_2_hash.as_bytes()));
    assert!(
        !retained.contains(pruned_hash.as_bytes()),
        "lowest-ranked side tip must be pruned deterministically"
    );
    assert!(
        chain.tip_height.0 <= MAX_RETAINED_SIDE_BRANCH_REORG_DEPTH,
        "fixture must stay within configured reorg retention depth"
    );
    assert!(
        3 <= MAX_RETAINED_SIDE_BRANCH_LENGTH,
        "fixture branch length must stay within configured branch limit"
    );

    chain
        .promote_heavier_known_tip(candidate_4_hash)
        .expect("retained heavier branch must remain promotable");
    assert_eq!(chain.tip_hash, candidate_4_hash);
    assert_eq!(chain.tip_height, BlockHeight(4));
}
