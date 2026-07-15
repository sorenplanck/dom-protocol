//! Production-path regression test for duplicate kernel excesses inside one block.
//!
//! The test drives `ChainState::connect_block`, including contextual header
//! validation, PoW, full block validation, and the canonical persistence gate.

mod common;

use common::open_test_chain;
use dom_chain::{ChainState, ConnectResult};
use dom_consensus::block::{BlockHeader, ProofOfWork};
use dom_consensus::{
    compute_block_pmmr_roots, derive_chain_id, Block, CoinbaseKernel, CoinbaseTransaction,
    Transaction, TransactionInput, TransactionKernel, TransactionOutput,
};
use dom_core::{
    Amount, BlockHeight, DomError, Hash256, Timestamp, KERNEL_FEAT_COINBASE, KERNEL_FEAT_PLAIN,
    NETWORK_MAGIC_REGTEST, PROTOCOL_VERSION, TAG_KERNEL_MSG, TAG_KERNEL_MSG_COINBASE,
};
use dom_crypto::{
    hash::blake2b_256_tagged,
    keys::SecretKey,
    pedersen::{BlindingFactor, Commitment},
    schnorr_sign,
};
use dom_pow::{
    compute_expected_target, fast_pow_hash, genesis_anchor, hash_meets_target, target_to_compact,
    target_to_difficulty, CompactTarget,
};
use dom_serialization::{DomDeserialize, DomSerialize};
use primitive_types::U256;
use tempfile::TempDir;

fn scalar(seed: u8) -> BlindingFactor {
    let mut bytes = [0u8; 32];
    bytes[31] = seed.max(1);
    BlindingFactor::from_bytes(bytes).expect("deterministic scalar")
}

fn chain_id() -> [u8; 32] {
    *derive_chain_id(NETWORK_MAGIC_REGTEST, &Hash256::ZERO).as_bytes()
}

fn open_chain(path: &std::path::Path) -> ChainState {
    // This fixture creates a spendable synthetic genesis for block validation;
    // production startup always configures the frozen Regtest genesis identity.
    open_test_chain(path, Hash256::ZERO, NETWORK_MAGIC_REGTEST).expect("chain open")
}

fn safe_now() -> Timestamp {
    Timestamp(2_000_000_000)
}

fn block_hash(block: &Block) -> Hash256 {
    Hash256::from_bytes(
        *dom_crypto::hash::blake2b_256(&block.header.to_bytes().expect("header bytes")).as_bytes(),
    )
}

fn kernel_message(fee: u64, lock_height: u64) -> [u8; 32] {
    let mut data = Vec::with_capacity(1 + 8 + 8);
    data.push(KERNEL_FEAT_PLAIN);
    data.extend_from_slice(&fee.to_le_bytes());
    data.extend_from_slice(&lock_height.to_le_bytes());
    *blake2b_256_tagged(TAG_KERNEL_MSG, &data).as_bytes()
}

fn build_coinbase(
    height: BlockHeight,
    claimed_fees: u64,
    seed: u8,
    chain_id: &[u8; 32],
) -> CoinbaseTransaction {
    let reward = dom_core::block_reward(height).noms();
    let explicit_value = reward + claimed_fees;
    let blinding = scalar(seed);
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
    let sig = schnorr_sign(&secret, msg.as_bytes(), chain_id).expect("coinbase sig");

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

#[allow(clippy::too_many_arguments)]
fn mine_fast_header(
    seed_hash: [u8; 32],
    prev_hash: Hash256,
    height: BlockHeight,
    timestamp: Timestamp,
    output_root: Hash256,
    kernel_root: Hash256,
    rangeproof_root: Hash256,
    total_kernel_offset: [u8; 32],
    total_difficulty: U256,
) -> BlockHeader {
    let target = compute_expected_target(NETWORK_MAGIC_REGTEST, timestamp, height).expect("target");
    let mut nonce = 0u64;
    loop {
        let mut header = BlockHeader {
            version: PROTOCOL_VERSION,
            height,
            prev_hash,
            timestamp,
            output_root,
            kernel_root,
            rangeproof_root,
            total_kernel_offset,
            target: CompactTarget(target_to_compact(&target)),
            total_difficulty,
            pow: ProofOfWork {
                nonce,
                randomx_hash: Hash256::ZERO,
            },
        };
        let hash = fast_pow_hash(&seed_hash, &header.pow_preimage());
        if hash_meets_target(&hash, &target) {
            header.pow.randomx_hash = Hash256::from_bytes(hash);
            return header;
        }
        nonce = nonce.wrapping_add(1);
    }
}

#[allow(clippy::too_many_arguments)]
fn build_block(
    seed_hash: [u8; 32],
    prev_hash: Hash256,
    height: BlockHeight,
    parent_total_difficulty: U256,
    coinbase_seed: u8,
    transactions: Vec<Transaction>,
    chain_id: &[u8; 32],
) -> Block {
    let total_fees = transactions
        .iter()
        .map(|tx| tx.total_fee().expect("fee"))
        .sum();
    let coinbase = build_coinbase(height, total_fees, coinbase_seed, chain_id);
    let (output_root, kernel_root, rangeproof_root) =
        compute_block_pmmr_roots(&coinbase, &transactions).expect("roots");
    let timestamp = genesis_anchor(NETWORK_MAGIC_REGTEST)
        .expect("anchor")
        .timestamp
        .checked_add_secs(height.0 * dom_core::TARGET_SPACING)
        .expect("timestamp");
    let target = compute_expected_target(NETWORK_MAGIC_REGTEST, timestamp, height).expect("target");
    let canonical_target = CompactTarget(target_to_compact(&target))
        .to_target()
        .expect("compact target round-trip");
    let total_difficulty =
        parent_total_difficulty + U256::from(target_to_difficulty(&canonical_target));
    let header = mine_fast_header(
        seed_hash,
        prev_hash,
        height,
        timestamp,
        output_root,
        kernel_root,
        rangeproof_root,
        [0u8; 32],
        total_difficulty,
    );
    Block {
        header,
        coinbase,
        transactions,
    }
}

fn spend_coinbase_tx(
    input_height: BlockHeight,
    input_blinding: BlindingFactor,
    kernel_seed: u8,
    chain_id: &[u8; 32],
) -> Transaction {
    let input_value = dom_core::block_reward(input_height).noms();
    let fee = dom_core::MIN_RELAY_FEE_RATE * 100;
    let output_value = input_value.checked_sub(fee).expect("fee below reward");
    let kernel_blinding = scalar(kernel_seed);
    let output_blinding = input_blinding
        .add(&kernel_blinding)
        .expect("output blinding");
    let input_commitment = Commitment::commit(input_value, &input_blinding);
    let output_commitment = Commitment::commit(output_value, &output_blinding);
    let (proof, _) = dom_crypto::bp2_prove(output_value, &output_blinding).expect("tx proof");
    let excess = Commitment::commit(0, &kernel_blinding);
    let secret = SecretKey::from_bytes(kernel_blinding.as_bytes()).expect("kernel secret");
    let sig = schnorr_sign(&secret, &kernel_message(fee, 0), chain_id).expect("kernel signature");

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

fn build_base_chain(chain: &mut ChainState, chain_id: &[u8; 32]) -> (Block, Block) {
    let genesis = build_block(
        [0u8; 32],
        Hash256::ZERO,
        BlockHeight::GENESIS,
        U256::zero(),
        10,
        vec![],
        chain_id,
    );
    assert_eq!(
        chain
            .connect_block(&genesis, safe_now())
            .expect("genesis connect"),
        ConnectResult::BestChain
    );

    let height_1 = build_block(
        *block_hash(&genesis).as_bytes(),
        block_hash(&genesis),
        BlockHeight(1),
        genesis.header.total_difficulty,
        11,
        vec![],
        chain_id,
    );
    assert_eq!(
        chain
            .connect_block(&height_1, safe_now())
            .expect("height 1 connect"),
        ConnectResult::BestChain
    );
    (genesis, height_1)
}

fn unique_kernel_block(genesis: &Block, height_1: &Block, chain_id: &[u8; 32]) -> Block {
    build_block(
        *block_hash(genesis).as_bytes(),
        block_hash(height_1),
        BlockHeight(2),
        height_1.header.total_difficulty,
        12,
        vec![
            spend_coinbase_tx(BlockHeight::GENESIS, scalar(10), 80, chain_id),
            spend_coinbase_tx(BlockHeight(1), scalar(11), 81, chain_id),
        ],
        chain_id,
    )
}

fn duplicate_kernel_block(genesis: &Block, height_1: &Block, chain_id: &[u8; 32]) -> Block {
    build_block(
        *block_hash(genesis).as_bytes(),
        block_hash(height_1),
        BlockHeight(2),
        height_1.header.total_difficulty,
        12,
        vec![
            spend_coinbase_tx(BlockHeight::GENESIS, scalar(10), 90, chain_id),
            spend_coinbase_tx(BlockHeight(1), scalar(11), 90, chain_id),
        ],
        chain_id,
    )
}

fn assert_not_persisted(chain: &ChainState, block: &Block) {
    let hash = block_hash(block);
    assert!(
        chain
            .store
            .get_block_header(hash.as_bytes())
            .expect("header lookup")
            .is_none(),
        "rejected block header must not be persisted"
    );
    assert!(
        chain
            .store
            .get_block_body(hash.as_bytes())
            .expect("body lookup")
            .is_none(),
        "rejected block body must not be persisted"
    );
    for tx in &block.transactions {
        for kernel in &tx.kernels {
            assert!(
                chain
                    .store
                    .get_kernel_block(kernel.excess.as_bytes())
                    .expect("kernel lookup")
                    .is_none(),
                "rejected block kernel must not be indexed"
            );
        }
    }
}

fn assert_duplicate_rejected_before_persistence(chain: &mut ChainState, block: &Block) -> DomError {
    let err = chain
        .connect_block(block, safe_now())
        .expect_err("duplicate kernel excess inside one block must be rejected");
    assert_not_persisted(chain, block);
    err
}

#[test]
fn duplicate_kernel_excess_inside_one_production_block_is_rejected() {
    std::env::set_var("DOM_REGTEST_FAST_MINING", "1");
    let chain_id = chain_id();

    let accepted_dir = TempDir::new().expect("tempdir");
    let mut accepted_chain = open_chain(&accepted_dir.path().join("accepted"));
    let (accepted_genesis, accepted_height_1) = build_base_chain(&mut accepted_chain, &chain_id);
    let unique = unique_kernel_block(&accepted_genesis, &accepted_height_1, &chain_id);
    assert_eq!(
        accepted_chain
            .connect_block(&unique, safe_now())
            .expect("unique kernels must be accepted"),
        ConnectResult::BestChain
    );

    let rejected_dir = TempDir::new().expect("tempdir");
    let rejected_store = rejected_dir.path().join("rejected");
    let mut rejected_chain = open_chain(&rejected_store);
    let (genesis, height_1) = build_base_chain(&mut rejected_chain, &chain_id);
    let duplicate = duplicate_kernel_block(&genesis, &height_1, &chain_id);

    assert_eq!(
        duplicate.transactions[0].kernels[0].excess, duplicate.transactions[1].kernels[0].excess,
        "fixture must duplicate kernel excess"
    );
    assert_eq!(
        duplicate.transactions[0].kernels[0].excess_signature,
        duplicate.transactions[1].kernels[0].excess_signature,
        "fixture must duplicate kernel signature"
    );
    assert_ne!(
        duplicate.transactions[0].outputs[0].commitment,
        duplicate.transactions[1].outputs[0].commitment,
        "fixture must isolate kernel duplication from output duplication"
    );

    let forward_err = assert_duplicate_rejected_before_persistence(&mut rejected_chain, &duplicate);
    let forward_msg = forward_err.to_string().to_ascii_lowercase();
    assert!(
        forward_msg.contains("kernel"),
        "duplicate kernel rejection should identify kernel cause, got: {forward_err}"
    );

    let mut reordered = duplicate.clone();
    reordered.transactions.reverse();
    assert_duplicate_rejected_before_persistence(&mut rejected_chain, &reordered);

    let decoded = Block::from_bytes(&duplicate.to_bytes().expect("block bytes"))
        .expect("duplicate block must round-trip");
    assert_duplicate_rejected_before_persistence(&mut rejected_chain, &decoded);

    drop(rejected_chain);
    let mut reopened = open_chain(&rejected_store);
    assert_duplicate_rejected_before_persistence(&mut reopened, &duplicate);
}
