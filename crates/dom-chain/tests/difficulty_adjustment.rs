mod common;

use blake2::digest::consts::U32;
use blake2::{Blake2b, Digest};
use common::open_test_store;
use dom_chain::ChainState;
use dom_consensus::block::{BlockHeader, ProofOfWork};
use dom_consensus::{Block, CoinbaseKernel, CoinbaseTransaction, TransactionOutput};
use dom_core::{
    BlockHeight, Hash256, Timestamp, GENESIS_HASH_MAINNET, GENESIS_HASH_REGTEST,
    GENESIS_HASH_TESTNET, GENESIS_TARGET_COMPACT, KERNEL_FEAT_COINBASE, NETWORK_MAGIC_MAINNET,
    NETWORK_MAGIC_REGTEST, NETWORK_MAGIC_TESTNET,
};
use dom_crypto::pedersen::{BlindingFactor, Commitment};
use dom_pow::{
    compute_expected_target, fast_pow_hash, hash_meets_target, pow_params_for_network,
    randomx_seed_height, target_to_difficulty, CompactTarget, REGTEST_TARGET_COMPACT,
};
use dom_serialization::{DomDeserialize, DomSerialize};
use primitive_types::U256;
use tempfile::TempDir;

fn block_hash(header: &BlockHeader) -> Hash256 {
    let bytes = header.to_bytes().expect("header serialize");
    type B2b256 = Blake2b<U32>;
    let mut h = B2b256::new();
    h.update(&bytes);
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&h.finalize());
    Hash256::from_bytes(arr)
}

fn commitment(seed: u8, value: u64) -> Commitment {
    let mut blind = [0u8; 32];
    blind[31] = seed.max(1);
    Commitment::commit(
        value,
        &BlindingFactor::from_bytes(blind).expect("deterministic blinding"),
    )
}

fn synthetic_block(
    prev_hash: Hash256,
    height: u64,
    timestamp: u64,
    target: CompactTarget,
    total_difficulty: u64,
    nonce_seed: u64,
) -> Block {
    let coinbase_commitment = commitment((height as u8).wrapping_add(1), height + 1);
    Block {
        header: BlockHeader {
            version: dom_core::PROTOCOL_VERSION,
            height: BlockHeight(height),
            prev_hash,
            timestamp: Timestamp(timestamp),
            output_root: Hash256::ZERO,
            kernel_root: Hash256::ZERO,
            rangeproof_root: Hash256::ZERO,
            total_kernel_offset: [0u8; 32],
            target,
            total_difficulty: U256::from(total_difficulty),
            pow: ProofOfWork {
                nonce: nonce_seed,
                randomx_hash: Hash256::ZERO,
            },
        },
        coinbase: CoinbaseTransaction {
            output: TransactionOutput {
                commitment: coinbase_commitment,
                proof: vec![height as u8; 8],
            },
            kernel: CoinbaseKernel {
                features: KERNEL_FEAT_COINBASE,
                explicit_value: 1,
                excess: commitment((height as u8).wrapping_add(100), 0),
                excess_signature: [height as u8; 65],
            },
            offset: [0u8; 32],
        },
        transactions: Vec::new(),
    }
}

fn populate_history(
    dir: &TempDir,
    genesis_hash: [u8; 32],
    network_magic: u32,
    spacing_secs: u64,
    count: u64,
) -> ChainState {
    let store = open_test_store(dir.path());
    let target = CompactTarget(GENESIS_TARGET_COMPACT);
    let mut prev_hash = Hash256::ZERO;
    let mut total_difficulty = 0u64;
    let genesis_ts = dom_core::GENESIS_TIMESTAMP_PLACEHOLDER;

    for height in 0..count {
        let timestamp = genesis_ts + spacing_secs.saturating_mul(height);
        total_difficulty = total_difficulty.saturating_add(1);
        let block = synthetic_block(
            prev_hash,
            height,
            timestamp,
            target,
            total_difficulty,
            height + 1,
        );
        let header_bytes = block.header.to_bytes().expect("header serialize");
        let body_bytes = block.to_bytes().expect("block serialize");
        let hash = block_hash(&block.header);
        store
            .commit_block(
                hash.as_bytes(),
                height,
                &header_bytes,
                &body_bytes,
                &[],
                &[],
                &[],
            )
            .expect("commit synthetic block");
        prev_hash = hash;
    }

    ChainState::open(store, Hash256::from_bytes(genesis_hash), network_magic).expect("chain open")
}

fn populate_history_with_timestamps(
    dir: &TempDir,
    genesis_hash: [u8; 32],
    network_magic: u32,
    timestamps: &[u64],
) -> ChainState {
    let store = open_test_store(dir.path());
    let target = CompactTarget(REGTEST_TARGET_COMPACT);
    let target_bytes = target.to_target().expect("target bytes");
    let block_diff = target_to_difficulty(&target_bytes);
    let mut prev_hash = Hash256::ZERO;
    let mut total_difficulty = U256::zero();

    for (height, timestamp) in timestamps.iter().copied().enumerate() {
        total_difficulty = total_difficulty.saturating_add(U256::from(block_diff));
        let block = synthetic_block(
            prev_hash,
            height as u64,
            timestamp,
            target,
            total_difficulty.low_u64(),
            height as u64 + 1,
        );
        let header_bytes = block.header.to_bytes().expect("header serialize");
        let body_bytes = block.to_bytes().expect("block serialize");
        let hash = block_hash(&block.header);
        store
            .commit_block(
                hash.as_bytes(),
                height as u64,
                &header_bytes,
                &body_bytes,
                &[],
                &[],
                &[],
            )
            .expect("commit synthetic block");
        prev_hash = hash;
    }

    ChainState::open(store, Hash256::from_bytes(genesis_hash), network_magic).expect("chain open")
}

fn finish_pow_for_header(chain: &ChainState, mut header: BlockHeader) -> BlockHeader {
    let seed_height = randomx_seed_height(header.height.0);
    let seed_hash = chain
        .store
        .get_hash_at_height(seed_height)
        .expect("seed height lookup")
        .unwrap_or([0u8; 32]);
    let target = header.target.to_target().expect("target bytes");
    let mut nonce = 0u64;
    loop {
        header.pow.nonce = nonce;
        header.pow.randomx_hash = Hash256::ZERO;
        let hash = fast_pow_hash(&seed_hash, &header.pow_preimage());
        if hash_meets_target(&hash, &target) {
            header.pow.randomx_hash = Hash256::from_bytes(hash);
            return header;
        }
        nonce = nonce.wrapping_add(1);
    }
}

fn expected_child_total_difficulty(parent: &BlockHeader, target: CompactTarget) -> U256 {
    let block_diff = target_to_difficulty(&target.to_target().expect("target bytes"));
    parent
        .total_difficulty
        .saturating_add(U256::from(block_diff))
}

#[test]
fn identical_chain_history_yields_identical_next_target() {
    let dir_a = TempDir::new().unwrap();
    let dir_b = TempDir::new().unwrap();
    let chain_a = populate_history(
        &dir_a,
        GENESIS_HASH_TESTNET,
        NETWORK_MAGIC_TESTNET,
        dom_core::TARGET_BLOCK_TIME_SECS / 2,
        12,
    );
    let chain_b = populate_history(
        &dir_b,
        GENESIS_HASH_TESTNET,
        NETWORK_MAGIC_TESTNET,
        dom_core::TARGET_BLOCK_TIME_SECS / 2,
        12,
    );

    let next_a = chain_a.next_block_target().expect("next target A");
    let next_b = chain_b.next_block_target().expect("next target B");
    assert_eq!(next_a, next_b);
}

#[test]
fn regtest_keeps_dev_target_while_testnet_retargets() {
    let reg_dir = TempDir::new().unwrap();
    let test_dir = TempDir::new().unwrap();
    let reg_chain = populate_history(&reg_dir, GENESIS_HASH_REGTEST, NETWORK_MAGIC_REGTEST, 1, 4);
    let test_chain = populate_history(&test_dir, GENESIS_HASH_TESTNET, NETWORK_MAGIC_TESTNET, 1, 4);

    let reg_next = reg_chain.next_block_target().expect("regtest target");
    let test_next = test_chain.next_block_target().expect("testnet target");
    let regtest_target = CompactTarget(REGTEST_TARGET_COMPACT)
        .to_target()
        .expect("regtest compact target");
    assert_eq!(
        reg_next.next_target, regtest_target,
        "regtest keeps its fixed compact-stable easy target"
    );
    assert_ne!(
        test_next.next_target, regtest_target,
        "testnet must not use the regtest fixed target"
    );
}

#[test]
fn public_next_block_target_matches_canonical_asert_helper() {
    let dir = TempDir::new().unwrap();
    let chain = populate_history(&dir, GENESIS_HASH_TESTNET, NETWORK_MAGIC_TESTNET, 60, 8);
    let tip_bytes = chain
        .store
        .get_block_header(chain.tip_hash.as_bytes())
        .expect("tip lookup")
        .expect("tip header");
    let tip = BlockHeader::from_bytes(&tip_bytes).expect("tip decode");
    let params = pow_params_for_network(NETWORK_MAGIC_TESTNET);
    let child_height = tip.height.checked_next().expect("next height");
    let child_timestamp = tip
        .timestamp
        .checked_add_secs(params.target_spacing)
        .expect("next timestamp");

    let preview = chain.next_block_target().expect("next block target");
    let canonical = compute_expected_target(NETWORK_MAGIC_TESTNET, child_timestamp, child_height)
        .expect("canonical target");

    assert_eq!(preview.next_target, canonical);
}

#[test]
fn public_networks_do_not_share_regtest_target() {
    let regtest_target = compute_expected_target(
        NETWORK_MAGIC_REGTEST,
        Timestamp(dom_core::GENESIS_TIMESTAMP_TESTNET + dom_core::TARGET_SPACING),
        BlockHeight(1),
    )
    .expect("regtest target");
    let mainnet_target = compute_expected_target(
        NETWORK_MAGIC_MAINNET,
        Timestamp(dom_core::GENESIS_TIMESTAMP_PLACEHOLDER + dom_core::TARGET_SPACING),
        BlockHeight(1),
    )
    .expect("mainnet target");
    let testnet_target = compute_expected_target(
        NETWORK_MAGIC_TESTNET,
        Timestamp(dom_core::GENESIS_TIMESTAMP_TESTNET + dom_core::TARGET_SPACING),
        BlockHeight(1),
    )
    .expect("testnet target");

    assert_ne!(mainnet_target, regtest_target);
    assert_ne!(testnet_target, regtest_target);
}

#[test]
fn window_retarget_still_unreachable_from_mainnet_testnet() {
    for (genesis_hash, network_magic) in [
        (GENESIS_HASH_MAINNET, NETWORK_MAGIC_MAINNET),
        (GENESIS_HASH_TESTNET, NETWORK_MAGIC_TESTNET),
    ] {
        let dir = TempDir::new().unwrap();
        let chain = populate_history(&dir, genesis_hash, network_magic, 1, 4);
        let tip_bytes = chain
            .store
            .get_block_header(chain.tip_hash.as_bytes())
            .expect("tip lookup")
            .expect("tip header");
        let tip = BlockHeader::from_bytes(&tip_bytes).expect("tip decode");
        let params = pow_params_for_network(network_magic);
        let child_height = tip.height.checked_next().expect("next height");
        let child_timestamp = tip
            .timestamp
            .checked_add_secs(params.target_spacing)
            .expect("next timestamp");

        let preview = chain.next_block_target().expect("next block target");
        let canonical = compute_expected_target(network_magic, child_timestamp, child_height)
            .expect("canonical ASERT target");

        assert_eq!(
            preview.next_target, canonical,
            "public next target must come from compute_expected_target"
        );
    }
}

#[test]
fn first_public_block_after_genesis_uses_asert_anchor_target() {
    for (network_magic, anchor_ts) in [
        (
            NETWORK_MAGIC_MAINNET,
            dom_core::GENESIS_TIMESTAMP_PLACEHOLDER,
        ),
        (NETWORK_MAGIC_TESTNET, dom_core::GENESIS_TIMESTAMP_TESTNET),
    ] {
        let params = pow_params_for_network(network_magic);
        let timestamp = Timestamp(anchor_ts + params.target_spacing);
        let first_target =
            compute_expected_target(network_magic, timestamp, BlockHeight(1)).expect("target");
        let anchor_target = params.genesis_target().expect("anchor target");
        let canonical_anchor = CompactTarget(dom_pow::target_to_compact(&anchor_target))
            .to_target()
            .expect("canonical anchor target");

        assert_eq!(first_target, canonical_anchor);
    }
}

#[test]
fn public_validator_rejects_wrong_asert_target() {
    let dir = TempDir::new().unwrap();
    let chain = populate_history(&dir, GENESIS_HASH_TESTNET, NETWORK_MAGIC_TESTNET, 60, 1);
    let parent = chain
        .store
        .get_block_header(chain.tip_hash.as_bytes())
        .expect("parent lookup")
        .expect("parent header");
    let parent = BlockHeader::from_bytes(&parent).expect("parent decode");
    let child_height = parent.height.checked_next().expect("next height");
    let params = pow_params_for_network(NETWORK_MAGIC_TESTNET);
    let child_timestamp = parent
        .timestamp
        .checked_add_secs(params.target_spacing)
        .expect("next timestamp");
    let expected = compute_expected_target(NETWORK_MAGIC_TESTNET, child_timestamp, child_height)
        .expect("expected target");
    let wrong_target = CompactTarget(GENESIS_TARGET_COMPACT)
        .to_target()
        .expect("wrong target");
    assert_ne!(wrong_target, expected);

    let header = BlockHeader {
        version: dom_core::PROTOCOL_VERSION,
        height: child_height,
        prev_hash: chain.tip_hash,
        timestamp: child_timestamp,
        output_root: Hash256::ZERO,
        kernel_root: Hash256::ZERO,
        rangeproof_root: Hash256::ZERO,
        total_kernel_offset: [0u8; 32],
        target: CompactTarget(GENESIS_TARGET_COMPACT),
        total_difficulty: expected_child_total_difficulty(
            &parent,
            CompactTarget(GENESIS_TARGET_COMPACT),
        ),
        pow: ProofOfWork {
            nonce: 0,
            randomx_hash: Hash256::ZERO,
        },
    };
    let header = finish_pow_for_header(&chain, header);

    let err = chain
        .validate_header_only(&header, Timestamp(child_timestamp.0 + 1))
        .expect_err("wrong ASERT target must be rejected");
    assert!(
        err.to_string().contains("target mismatch"),
        "unexpected error: {err}"
    );
}

#[test]
fn validate_header_only_rejects_non_increasing_parent_timestamp() {
    let dir = TempDir::new().unwrap();
    let chain = populate_history(&dir, GENESIS_HASH_REGTEST, NETWORK_MAGIC_REGTEST, 1, 1);
    let parent_bytes = chain
        .store
        .get_block_header(chain.tip_hash.as_bytes())
        .expect("parent lookup")
        .expect("parent header");
    let parent = BlockHeader::from_bytes(&parent_bytes).expect("parent decode");
    let child_height = parent.height.checked_next().expect("next height");
    let target = CompactTarget(REGTEST_TARGET_COMPACT);
    let header = BlockHeader {
        version: dom_core::PROTOCOL_VERSION,
        height: child_height,
        prev_hash: chain.tip_hash,
        timestamp: parent.timestamp,
        output_root: Hash256::ZERO,
        kernel_root: Hash256::ZERO,
        rangeproof_root: Hash256::ZERO,
        total_kernel_offset: [0u8; 32],
        target,
        total_difficulty: expected_child_total_difficulty(&parent, target),
        pow: ProofOfWork {
            nonce: 0,
            randomx_hash: Hash256::ZERO,
        },
    };

    let err = chain
        .validate_header_only(&header, Timestamp(parent.timestamp.0 + 1))
        .expect_err("non-increasing timestamp must be rejected");
    assert!(
        err.to_string()
            .contains("not greater than parent timestamp"),
        "unexpected error: {err}"
    );
}

#[test]
fn validate_header_only_rejects_median_time_past_violation() {
    let dir = TempDir::new().unwrap();
    let base = dom_core::GENESIS_TIMESTAMP_TESTNET;
    let mut timestamps = vec![base + 1_000; 11];
    timestamps.push(base + 100);
    let chain = populate_history_with_timestamps(
        &dir,
        GENESIS_HASH_REGTEST,
        NETWORK_MAGIC_REGTEST,
        &timestamps,
    );
    let parent_bytes = chain
        .store
        .get_block_header(chain.tip_hash.as_bytes())
        .expect("parent lookup")
        .expect("parent header");
    let parent = BlockHeader::from_bytes(&parent_bytes).expect("parent decode");
    let child_height = parent.height.checked_next().expect("next height");
    let child_timestamp = Timestamp(parent.timestamp.0 + 1);
    let target = CompactTarget(REGTEST_TARGET_COMPACT);
    let header = BlockHeader {
        version: dom_core::PROTOCOL_VERSION,
        height: child_height,
        prev_hash: chain.tip_hash,
        timestamp: child_timestamp,
        output_root: Hash256::ZERO,
        kernel_root: Hash256::ZERO,
        rangeproof_root: Hash256::ZERO,
        total_kernel_offset: [0u8; 32],
        target,
        total_difficulty: expected_child_total_difficulty(&parent, target),
        pow: ProofOfWork {
            nonce: 0,
            randomx_hash: Hash256::ZERO,
        },
    };

    let err = chain
        .validate_header_only(&header, Timestamp(child_timestamp.0 + 1))
        .expect_err("MTP violation must be rejected");
    assert!(
        err.to_string().contains("median-time-past"),
        "unexpected error: {err}"
    );
}

#[test]
fn validate_header_only_rejects_total_difficulty_mismatch() {
    let dir = TempDir::new().unwrap();
    let chain = populate_history(&dir, GENESIS_HASH_REGTEST, NETWORK_MAGIC_REGTEST, 1, 1);
    let parent_bytes = chain
        .store
        .get_block_header(chain.tip_hash.as_bytes())
        .expect("parent lookup")
        .expect("parent header");
    let parent = BlockHeader::from_bytes(&parent_bytes).expect("parent decode");
    let child_height = parent.height.checked_next().expect("next height");
    let child_timestamp = parent
        .timestamp
        .checked_add_secs(1)
        .expect("next timestamp");
    let target = CompactTarget(REGTEST_TARGET_COMPACT);
    let header = BlockHeader {
        version: dom_core::PROTOCOL_VERSION,
        height: child_height,
        prev_hash: chain.tip_hash,
        timestamp: child_timestamp,
        output_root: Hash256::ZERO,
        kernel_root: Hash256::ZERO,
        rangeproof_root: Hash256::ZERO,
        total_kernel_offset: [0u8; 32],
        target,
        total_difficulty: parent.total_difficulty,
        pow: ProofOfWork {
            nonce: 0,
            randomx_hash: Hash256::ZERO,
        },
    };
    let header = finish_pow_for_header(&chain, header);

    let err = chain
        .validate_header_only(&header, Timestamp(child_timestamp.0 + 1))
        .expect_err("total difficulty mismatch must be rejected");
    assert!(
        err.to_string().contains("total_difficulty mismatch"),
        "unexpected error: {err}"
    );
}
