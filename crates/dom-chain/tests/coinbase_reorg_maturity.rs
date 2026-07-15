//! Production-path coinbase maturity coverage for direct connection and reorg.

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
    hash::{blake2b_256, blake2b_256_tagged},
    keys::SecretKey,
    pedersen::{BlindingFactor, Commitment},
    schnorr_sign,
};
use dom_pow::{
    compute_expected_target, fast_pow_hash, genesis_anchor, hash_meets_target, target_to_compact,
    target_to_difficulty, CompactTarget,
};
use dom_serialization::DomSerialize;
use dom_store::utxo::{UtxoEntry, UtxoSet};
use primitive_types::U256;
use tempfile::TempDir;

const TEST_MATURITY: u64 = 2;

fn scalar(seed: u8) -> BlindingFactor {
    let mut bytes = [0u8; 32];
    bytes[31] = seed.max(1);
    BlindingFactor::from_bytes(bytes).expect("deterministic scalar")
}

fn chain_id() -> [u8; 32] {
    *derive_chain_id(NETWORK_MAGIC_REGTEST, &Hash256::ZERO).as_bytes()
}

fn open_chain(path: &std::path::Path) -> ChainState {
    // These fixtures construct a spendable synthetic height-zero block to
    // exercise maturity. The unpinned test identity is confined to this target;
    // production startup supplies the frozen Regtest genesis hash.
    let mut chain =
        open_test_chain(path, Hash256::ZERO, NETWORK_MAGIC_REGTEST).expect("chain open");
    chain.coinbase_maturity = TEST_MATURITY;
    chain
}

fn safe_now() -> Timestamp {
    Timestamp(2_000_000_000)
}

fn block_hash(block: &Block) -> Hash256 {
    Hash256::from_bytes(*blake2b_256(&block.header.to_bytes().expect("header bytes")).as_bytes())
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
            total_kernel_offset: [0u8; 32],
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
    input_seed: u8,
    kernel_seed: u8,
    chain_id: &[u8; 32],
) -> Transaction {
    let input_value = dom_core::block_reward(input_height).noms();
    let fee = dom_core::MIN_RELAY_FEE_RATE * 100;
    let output_value = input_value.checked_sub(fee).expect("fee below reward");
    let input_blinding = scalar(input_seed);
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

fn connect_tip(
    chain: &mut ChainState,
    pow_seed: [u8; 32],
    prev: &Block,
    height: u64,
    coinbase_seed: u8,
    transactions: Vec<Transaction>,
    chain_id: &[u8; 32],
) -> Block {
    let block = build_block(
        pow_seed,
        block_hash(prev),
        BlockHeight(height),
        prev.header.total_difficulty,
        coinbase_seed,
        transactions,
        chain_id,
    );
    assert_eq!(
        chain
            .connect_block(&block, safe_now())
            .expect("connect canonical block"),
        ConnectResult::BestChain
    );
    block
}

fn store_known_block(chain: &ChainState, block: &Block) -> Hash256 {
    let hash = block_hash(block);
    chain
        .store
        .store_known_block(
            hash.as_bytes(),
            &block.header.to_bytes().expect("header bytes"),
            &block.to_bytes().expect("block bytes"),
        )
        .expect("store known block");
    hash
}

fn assert_immature_error(err: &DomError) {
    assert!(
        matches!(err, DomError::Invalid(_)),
        "immature reorg/direct spend must be Invalid, got {err:?}"
    );
    assert!(
        err.to_string().contains("immature coinbase"),
        "error must identify immature coinbase, got {err}"
    );
}

fn assert_temporary_immature_error(err: &DomError) {
    assert!(
        matches!(err, DomError::TemporarilyInvalid(_)),
        "UTXO maturity failure must be TemporarilyInvalid, got {err:?}"
    );
    assert!(
        err.to_string().contains("immature") || err.to_string().contains("not mature"),
        "error must identify immature coinbase, got {err}"
    );
}

fn coinbase_entry(block_height: u64) -> UtxoEntry {
    UtxoEntry {
        block_height,
        is_coinbase: true,
        proof: vec![],
    }
}

fn assert_store_maturity_boundary(height: u64, expect_ok: bool) {
    let entry = coinbase_entry(1);

    let store_result =
        UtxoSet::validate_input_with_maturity(&entry, BlockHeight(height), TEST_MATURITY);

    if expect_ok {
        store_result.expect("store UTXO maturity should accept this boundary");
    } else {
        assert_temporary_immature_error(
            &store_result.expect_err("store UTXO maturity must reject immature coinbase"),
        );
    }
}

fn assert_ibd_header_then_body_boundary(height: u64, kernel_seed: u8, expect_body_ok: bool) {
    let dir = TempDir::new().expect("tempdir");
    let store_dir = dir.path().join(format!("ibd-body-height-{height}"));
    let chain_id = chain_id();
    let mut chain = open_chain(&store_dir);

    let genesis = build_block(
        [0u8; 32],
        Hash256::ZERO,
        BlockHeight::GENESIS,
        U256::zero(),
        100,
        vec![],
        &chain_id,
    );
    assert_eq!(
        chain.connect_block(&genesis, safe_now()).expect("genesis"),
        ConnectResult::BestChain
    );
    let genesis_seed = *block_hash(&genesis).as_bytes();
    let mut parent = connect_tip(
        &mut chain,
        genesis_seed,
        &genesis,
        1,
        101,
        vec![],
        &chain_id,
    );
    for filler_height in 2..height {
        parent = connect_tip(
            &mut chain,
            genesis_seed,
            &parent,
            filler_height,
            (101 + filler_height) as u8,
            vec![],
            &chain_id,
        );
    }

    let spend = spend_coinbase_tx(BlockHeight(1), 101, kernel_seed, &chain_id);
    let candidate = build_block(
        genesis_seed,
        block_hash(&parent),
        BlockHeight(height),
        parent.header.total_difficulty,
        (120 + height) as u8,
        vec![spend],
        &chain_id,
    );
    let header_bytes = candidate.header.to_bytes().expect("header bytes");
    let missing = chain
        .validate_ibd_headers_batch(&[header_bytes], safe_now())
        .expect("IBD header-only batch should validate header consensus before body import");
    assert_eq!(missing, vec![*block_hash(&candidate).as_bytes()]);

    let body_result = chain.connect_block(&candidate, safe_now());
    if expect_body_ok {
        assert_eq!(
            body_result.expect("IBD body import should accept mature coinbase spend"),
            ConnectResult::BestChain
        );
    } else {
        assert_immature_error(
            &body_result.expect_err("IBD body import must reject immature coinbase spend"),
        );
        assert_eq!(chain.tip_hash, block_hash(&parent));
    }
}

#[test]
fn admission_matrix_enforces_coinbase_maturity_boundaries() {
    std::env::set_var("DOM_REGTEST_FAST_MINING", "1");

    assert_store_maturity_boundary(2, false);
    assert_store_maturity_boundary(3, true);
    assert_store_maturity_boundary(4, true);

    assert_ibd_header_then_body_boundary(2, 24, false);
    assert_ibd_header_then_body_boundary(3, 25, true);
    assert_ibd_header_then_body_boundary(4, 26, true);
}

#[test]
fn direct_connection_enforces_coinbase_maturity_boundaries() {
    std::env::set_var("DOM_REGTEST_FAST_MINING", "1");
    let dir = TempDir::new().expect("tempdir");
    let store_dir = dir.path().join("direct-minus-one");
    let chain_id = chain_id();
    let mut chain = open_chain(&store_dir);

    let genesis = build_block(
        [0u8; 32],
        Hash256::ZERO,
        BlockHeight::GENESIS,
        U256::zero(),
        10,
        vec![],
        &chain_id,
    );
    assert_eq!(
        chain.connect_block(&genesis, safe_now()).expect("genesis"),
        ConnectResult::BestChain
    );
    let genesis_seed = *block_hash(&genesis).as_bytes();
    let funding = connect_tip(&mut chain, genesis_seed, &genesis, 1, 11, vec![], &chain_id);
    let immature_spend = spend_coinbase_tx(BlockHeight(1), 11, 30, &chain_id);
    let immature_block = build_block(
        genesis_seed,
        block_hash(&funding),
        BlockHeight(2),
        funding.header.total_difficulty,
        12,
        vec![immature_spend],
        &chain_id,
    );
    let immature_hash = block_hash(&immature_block);
    let err = chain
        .connect_block(&immature_block, safe_now())
        .expect_err("height 2 is one block before maturity for height-1 coinbase");
    assert_immature_error(&err);
    assert_eq!(chain.tip_hash, block_hash(&funding));
    assert!(
        chain
            .store
            .get_block_body(immature_hash.as_bytes())
            .expect("read rejected block body")
            .is_none(),
        "rejected direct block must not be partially persisted"
    );

    let filler = connect_tip(&mut chain, genesis_seed, &funding, 2, 13, vec![], &chain_id);
    let exact_spend = spend_coinbase_tx(BlockHeight(1), 11, 31, &chain_id);
    let exact = connect_tip(
        &mut chain,
        genesis_seed,
        &filler,
        3,
        14,
        vec![exact_spend],
        &chain_id,
    );
    assert_eq!(chain.tip_hash, block_hash(&exact));

    let after_dir = TempDir::new().expect("tempdir");
    let mut after_chain = open_chain(&after_dir.path().join("direct-plus-one"));
    let genesis = build_block(
        [0u8; 32],
        Hash256::ZERO,
        BlockHeight::GENESIS,
        U256::zero(),
        40,
        vec![],
        &chain_id,
    );
    after_chain
        .connect_block(&genesis, safe_now())
        .expect("genesis");
    let genesis_seed = *block_hash(&genesis).as_bytes();
    let funding = connect_tip(
        &mut after_chain,
        genesis_seed,
        &genesis,
        1,
        41,
        vec![],
        &chain_id,
    );
    let h2 = connect_tip(
        &mut after_chain,
        genesis_seed,
        &funding,
        2,
        42,
        vec![],
        &chain_id,
    );
    let h3 = connect_tip(
        &mut after_chain,
        genesis_seed,
        &h2,
        3,
        43,
        vec![],
        &chain_id,
    );
    let after_spend = spend_coinbase_tx(BlockHeight(1), 41, 44, &chain_id);
    let after = connect_tip(
        &mut after_chain,
        genesis_seed,
        &h3,
        4,
        45,
        vec![after_spend],
        &chain_id,
    );
    assert_eq!(after_chain.tip_hash, block_hash(&after));
}

#[test]
fn reorg_rejects_immature_coinbase_spend_without_partial_state() {
    std::env::set_var("DOM_REGTEST_FAST_MINING", "1");
    let dir = TempDir::new().expect("tempdir");
    let store_dir = dir.path().join("reorg-immature");
    let chain_id = chain_id();
    let mut chain = open_chain(&store_dir);

    let genesis = build_block(
        [0u8; 32],
        Hash256::ZERO,
        BlockHeight::GENESIS,
        U256::zero(),
        60,
        vec![],
        &chain_id,
    );
    chain.connect_block(&genesis, safe_now()).expect("genesis");
    let genesis_seed = *block_hash(&genesis).as_bytes();
    let common = connect_tip(&mut chain, genesis_seed, &genesis, 1, 61, vec![], &chain_id);
    let a2 = connect_tip(&mut chain, genesis_seed, &common, 2, 62, vec![], &chain_id);
    let mature_spend = spend_coinbase_tx(BlockHeight(1), 61, 63, &chain_id);
    let a3 = connect_tip(
        &mut chain,
        genesis_seed,
        &a2,
        3,
        64,
        vec![mature_spend.clone()],
        &chain_id,
    );
    connect_tip(&mut chain, genesis_seed, &a3, 4, 65, vec![], &chain_id);
    let original_tip = chain.tip_hash;
    let mature_output = *mature_spend.outputs[0].commitment.as_bytes();

    let immature_spend = spend_coinbase_tx(BlockHeight(1), 61, 70, &chain_id);
    let immature_output = *immature_spend.outputs[0].commitment.as_bytes();
    let b2 = build_block(
        genesis_seed,
        block_hash(&common),
        BlockHeight(2),
        common.header.total_difficulty,
        71,
        vec![immature_spend],
        &chain_id,
    );
    let b2_result = chain
        .connect_block(&b2, safe_now())
        .expect("immature side block is retained before branch-context validation");
    assert!(matches!(b2_result, ConnectResult::SideChain));
    let b3 = build_block(
        genesis_seed,
        block_hash(&b2),
        BlockHeight(3),
        b2.header.total_difficulty,
        72,
        vec![],
        &chain_id,
    );
    store_known_block(&chain, &b3);
    let b4 = build_block(
        genesis_seed,
        block_hash(&b3),
        BlockHeight(4),
        b3.header.total_difficulty,
        73,
        vec![],
        &chain_id,
    );
    store_known_block(&chain, &b4);
    let b5 = build_block(
        genesis_seed,
        block_hash(&b4),
        BlockHeight(5),
        b4.header.total_difficulty,
        74,
        vec![],
        &chain_id,
    );
    let b5_hash = store_known_block(&chain, &b5);

    let err = chain
        .promote_heavier_known_tip(b5_hash, safe_now())
        .expect_err("promotion must reject the side branch's immature spend");
    assert_immature_error(&err);
    assert_eq!(
        chain.tip_hash, original_tip,
        "failed reorg must leave the original canonical tip unchanged"
    );
    assert!(
        chain
            .store
            .get_utxo(&mature_output)
            .expect("read mature output")
            .is_some(),
        "failed reorg must not roll back the previously mature canonical spend"
    );
    assert!(
        chain
            .store
            .get_utxo(&immature_output)
            .expect("read rejected side output")
            .is_none(),
        "failed reorg must not apply the immature side-branch transaction output"
    );
    assert!(
        chain
            .store
            .get_hash_at_height(5)
            .expect("read height 5")
            .is_none(),
        "failed reorg must not install the side branch as canonical"
    );

    drop(chain);
    let reopened = open_chain(&store_dir);
    assert_eq!(reopened.tip_hash, original_tip);
    assert!(reopened.store.get_utxo(&mature_output).unwrap().is_some());
    assert!(reopened.store.get_utxo(&immature_output).unwrap().is_none());
}

#[test]
fn reorg_accepts_exact_and_after_maturity_coinbase_spends_across_restart() {
    std::env::set_var("DOM_REGTEST_FAST_MINING", "1");
    let dir = TempDir::new().expect("tempdir");
    let store_dir = dir.path().join("reorg-mature");
    let chain_id = chain_id();
    let mut chain = open_chain(&store_dir);

    let genesis = build_block(
        [0u8; 32],
        Hash256::ZERO,
        BlockHeight::GENESIS,
        U256::zero(),
        90,
        vec![],
        &chain_id,
    );
    chain.connect_block(&genesis, safe_now()).expect("genesis");
    let genesis_seed = *block_hash(&genesis).as_bytes();
    let common = connect_tip(&mut chain, genesis_seed, &genesis, 1, 91, vec![], &chain_id);
    let a2 = connect_tip(&mut chain, genesis_seed, &common, 2, 92, vec![], &chain_id);
    connect_tip(&mut chain, genesis_seed, &a2, 3, 93, vec![], &chain_id);

    let b2 = build_block(
        genesis_seed,
        block_hash(&common),
        BlockHeight(2),
        common.header.total_difficulty,
        94,
        vec![],
        &chain_id,
    );
    assert!(matches!(
        chain.connect_block(&b2, safe_now()).expect("side b2"),
        ConnectResult::SideChain
    ));
    let exact_spend = spend_coinbase_tx(BlockHeight(1), 91, 95, &chain_id);
    let exact_output = *exact_spend.outputs[0].commitment.as_bytes();
    let b3 = build_block(
        genesis_seed,
        block_hash(&b2),
        BlockHeight(3),
        b2.header.total_difficulty,
        96,
        vec![exact_spend],
        &chain_id,
    );
    store_known_block(&chain, &b3);
    let after_spend = spend_coinbase_tx(BlockHeight(2), 94, 97, &chain_id);
    let after_output = *after_spend.outputs[0].commitment.as_bytes();
    let b4 = build_block(
        genesis_seed,
        block_hash(&b3),
        BlockHeight(4),
        b3.header.total_difficulty,
        98,
        vec![after_spend],
        &chain_id,
    );
    let b4_hash = store_known_block(&chain, &b4);

    let reorg = chain
        .promote_heavier_known_tip(b4_hash, safe_now())
        .expect("exact and after-maturity reorg should promote");
    assert_eq!(chain.tip_hash, b4_hash);
    assert_eq!(reorg.connected_blocks.len(), 3);
    assert!(chain.store.get_utxo(&exact_output).unwrap().is_some());
    assert!(chain.store.get_utxo(&after_output).unwrap().is_some());

    drop(chain);
    let reopened = open_chain(&store_dir);
    assert_eq!(reopened.tip_hash, b4_hash);
    assert!(reopened.store.get_utxo(&exact_output).unwrap().is_some());
    assert!(reopened.store.get_utxo(&after_output).unwrap().is_some());
}
