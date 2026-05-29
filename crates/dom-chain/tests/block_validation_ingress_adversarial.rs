//! Adversarial ingress tests for block-level consensus completeness.
//!
//! These tests pin the invariant that a block with syntactically valid header
//! data and self-consistent PMMR roots is still rejected if its aggregate
//! economic balance is invalid. The same malformed bytes must not slip through
//! direct extension, IBD-style body import, or known-tip promotion.

use dom_chain::ChainState;
use dom_consensus::block::{BlockHeader, ProofOfWork};
use dom_consensus::{
    compute_block_pmmr_roots, derive_chain_id, Block, CoinbaseKernel, CoinbaseTransaction,
    TransactionOutput,
};
use dom_core::{
    BlockHeight, Hash256, Timestamp, KERNEL_FEAT_COINBASE, NETWORK_MAGIC_REGTEST, PROTOCOL_VERSION,
    TAG_KERNEL_MSG_COINBASE,
};
use dom_crypto::{
    bulletproof,
    hash::blake2b_256_tagged,
    keys::SecretKey,
    pedersen::{BlindingFactor, Commitment},
    schnorr_sign,
};
use dom_pow::{
    compute_expected_target, fast_pow_hash, genesis_anchor, hash_meets_target, target_to_compact,
    target_to_difficulty, CompactTarget,
};
use dom_serialization::DomSerialize;
use dom_store::DomStore;
use primitive_types::U256;
use tempfile::TempDir;

fn scalar(seed: u8) -> BlindingFactor {
    let mut bytes = [0u8; 32];
    bytes[31] = seed.max(1);
    BlindingFactor::from_bytes(bytes).expect("deterministic scalar")
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
    let (proof, _) = bulletproof::prove(explicit_value, &blinding).expect("coinbase proof");
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

fn build_coinbase_only_block(
    seed_hash: [u8; 32],
    prev_hash: Hash256,
    height: BlockHeight,
    parent_total_difficulty: U256,
    total_kernel_offset: [u8; 32],
    coinbase_seed: u8,
    chain_id: &[u8; 32],
) -> Block {
    let coinbase = build_coinbase(height, 0, coinbase_seed, chain_id);
    let (output_root, kernel_root, rangeproof_root) =
        compute_block_pmmr_roots(&coinbase, &[]).expect("roots");
    let timestamp = genesis_anchor(NETWORK_MAGIC_REGTEST)
        .expect("anchor")
        .timestamp
        .checked_add_secs(height.0 * dom_core::TARGET_SPACING)
        .expect("timestamp");
    let target = compute_expected_target(NETWORK_MAGIC_REGTEST, timestamp, height).expect("target");
    // The header stores the *compact-encoded* target, and consensus derives the
    // block's difficulty from that compact-rounded value (see ChainState::connect_block).
    // Compute total_difficulty from the same round-tripped target so the fixture's
    // total_difficulty matches what consensus expects.
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
        total_kernel_offset,
        total_difficulty,
    );
    Block {
        header,
        coinbase,
        transactions: vec![],
    }
}

fn block_hash(block: &Block) -> Hash256 {
    Hash256::from_bytes(
        *dom_crypto::hash::blake2b_256(&block.header.to_bytes().unwrap()).as_bytes(),
    )
}

fn open_chain(dir: &std::path::Path) -> ChainState {
    let store = DomStore::open(dir).expect("store open");
    ChainState::open(
        store,
        Hash256::from_bytes(dom_core::GENESIS_HASH_REGTEST),
        NETWORK_MAGIC_REGTEST,
    )
    .expect("chain open")
}

fn safe_now() -> Timestamp {
    Timestamp(2_000_000_000)
}

#[test]
fn invariant_direct_chain_extension_rejects_header_and_pmmr_valid_but_economically_unbalanced_block(
) {
    std::env::set_var("DOM_REGTEST_FAST_MINING", "1");
    let dir = TempDir::new().expect("tempdir");
    let chain_id = *derive_chain_id(
        NETWORK_MAGIC_REGTEST,
        &Hash256::from_bytes(dom_core::GENESIS_HASH_REGTEST),
    )
    .as_bytes();
    let mut chain = open_chain(dir.path());

    let genesis = build_coinbase_only_block(
        [0u8; 32],
        Hash256::ZERO,
        BlockHeight::GENESIS,
        U256::zero(),
        [0u8; 32],
        10,
        &chain_id,
    );
    chain.connect_block(&genesis, safe_now()).expect("genesis");

    let mut invalid_offset = [0u8; 32];
    invalid_offset[31] = 1;
    let invalid = build_coinbase_only_block(
        *block_hash(&genesis).as_bytes(),
        block_hash(&genesis),
        BlockHeight(1),
        genesis.header.total_difficulty,
        invalid_offset,
        11,
        &chain_id,
    );

    let err = chain
        .connect_block(&invalid, safe_now())
        .expect_err("direct extension must reject invalid aggregate balance");
    let msg = err.to_string();
    assert!(
        msg.contains("aggregate") || msg.contains("balance"),
        "expected economic-balance rejection, got: {msg}"
    );
}

#[test]
fn invariant_reorg_candidate_promotion_revalidates_economic_balance_before_state_rewrite() {
    std::env::set_var("DOM_REGTEST_FAST_MINING", "1");
    let dir = TempDir::new().expect("tempdir");
    let chain_id = *derive_chain_id(
        NETWORK_MAGIC_REGTEST,
        &Hash256::from_bytes(dom_core::GENESIS_HASH_REGTEST),
    )
    .as_bytes();
    let mut chain = open_chain(dir.path());

    let genesis = build_coinbase_only_block(
        [0u8; 32],
        Hash256::ZERO,
        BlockHeight::GENESIS,
        U256::zero(),
        [0u8; 32],
        20,
        &chain_id,
    );
    chain.connect_block(&genesis, safe_now()).expect("genesis");

    let canonical = build_coinbase_only_block(
        *block_hash(&genesis).as_bytes(),
        block_hash(&genesis),
        BlockHeight(1),
        genesis.header.total_difficulty,
        [0u8; 32],
        21,
        &chain_id,
    );
    chain
        .connect_block(&canonical, safe_now())
        .expect("canonical tip");

    let side_1 = build_coinbase_only_block(
        *block_hash(&genesis).as_bytes(),
        block_hash(&genesis),
        BlockHeight(1),
        genesis.header.total_difficulty,
        [0u8; 32],
        22,
        &chain_id,
    );
    let side_1_result = chain
        .connect_block(&side_1, safe_now())
        .expect("side block");
    assert!(
        matches!(side_1_result, dom_chain::ConnectResult::SideChain),
        "first side block must stay non-canonical until heavier work arrives"
    );

    let mut invalid_offset = [0u8; 32];
    invalid_offset[31] = 1;
    let invalid_side_2 = build_coinbase_only_block(
        *block_hash(&genesis).as_bytes(),
        block_hash(&side_1),
        BlockHeight(2),
        side_1.header.total_difficulty,
        invalid_offset,
        23,
        &chain_id,
    );
    let invalid_side_2_hash = block_hash(&invalid_side_2);
    chain
        .store
        .store_known_block(
            invalid_side_2_hash.as_bytes(),
            &invalid_side_2.header.to_bytes().expect("header bytes"),
            &invalid_side_2.to_bytes().expect("block bytes"),
        )
        .expect("store invalid side block");

    let err = chain
        .promote_heavier_known_tip(invalid_side_2_hash)
        .expect_err("reorg promotion must reject invalid aggregate balance");
    let msg = err.to_string();
    assert!(
        msg.contains("aggregate") || msg.contains("balance") || msg.contains("validation"),
        "expected validation rejection during reorg promotion, got: {msg}"
    );
}
