//! Adversarial ingress tests for block-level consensus completeness.
//!
//! These tests pin the invariant that a block with syntactically valid header
//! data and self-consistent PMMR roots is still rejected if its aggregate
//! economic balance is invalid. The same malformed bytes must not slip through
//! direct extension, IBD-style body import, or known-tip promotion.

mod common;

use common::open_test_chain;
use dom_chain::ChainState;
use dom_consensus::block::{BlockHeader, ProofOfWork};
use dom_consensus::{
    compute_block_pmmr_roots, derive_chain_id, Block, CoinbaseKernel, CoinbaseTransaction,
    Transaction, TransactionInput, TransactionKernel, TransactionOutput,
};
use dom_core::{
    Amount, BlockHeight, Hash256, Timestamp, KERNEL_FEAT_COINBASE, KERNEL_FEAT_PLAIN,
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
use dom_serialization::DomSerialize;
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
        output: TransactionOutput {
            commitment,
            proof: proof,
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

fn kernel_message(fee: u64, lock_height: u64) -> [u8; 32] {
    let mut data = Vec::with_capacity(1 + 8 + 8);
    data.push(KERNEL_FEAT_PLAIN);
    data.extend_from_slice(&fee.to_le_bytes());
    data.extend_from_slice(&lock_height.to_le_bytes());
    *blake2b_256_tagged(TAG_KERNEL_MSG, &data).as_bytes()
}

fn valid_spend_tx(
    input_value: u64,
    input_blinding: BlindingFactor,
    output_value: u64,
    kernel_seed: u8,
    chain_id: &[u8; 32],
) -> Transaction {
    let fee = input_value
        .checked_sub(output_value)
        .expect("output must not exceed input");
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
            proof: proof,
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

#[allow(clippy::too_many_arguments)]
fn build_block_with_transactions(
    seed_hash: [u8; 32],
    prev_hash: Hash256,
    height: BlockHeight,
    parent_total_difficulty: U256,
    total_kernel_offset: [u8; 32],
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
        total_kernel_offset,
        total_difficulty,
    );
    Block {
        header,
        coinbase,
        transactions,
    }
}

fn block_hash(block: &Block) -> Hash256 {
    Hash256::from_bytes(
        *dom_crypto::hash::blake2b_256(&block.header.to_bytes().unwrap()).as_bytes(),
    )
}

fn open_chain(dir: &std::path::Path) -> ChainState {
    open_test_chain(
        dir,
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
    // Keep the TempDir alive for the test, but open LMDB in a child directory.
    // Windows CI does not tolerate reserving the full 16 GiB production map
    // for these tiny adversarial fixtures, so the test uses a small map size
    // only for fixture storage. Consensus behavior is unchanged.
    let store_dir = dir.path().join("chain");
    let chain_id = *derive_chain_id(
        NETWORK_MAGIC_REGTEST,
        &Hash256::from_bytes(dom_core::GENESIS_HASH_REGTEST),
    )
    .as_bytes();
    let mut chain = open_chain(&store_dir);

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
    // Use a child store directory and the small test-only LMDB map size for
    // Windows CI fixture isolation; production map sizing remains unchanged.
    let store_dir = dir.path().join("chain");
    let chain_id = *derive_chain_id(
        NETWORK_MAGIC_REGTEST,
        &Hash256::from_bytes(dom_core::GENESIS_HASH_REGTEST),
    )
    .as_bytes();
    let mut chain = open_chain(&store_dir);

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

#[test]
fn side_chain_with_branch_invalid_input_is_quarantined_then_rejected_on_promotion() {
    std::env::set_var("DOM_REGTEST_FAST_MINING", "1");
    let dir = TempDir::new().expect("tempdir");
    let store_dir = dir.path().join("chain");
    let chain_id = *derive_chain_id(
        NETWORK_MAGIC_REGTEST,
        &Hash256::from_bytes(dom_core::GENESIS_HASH_REGTEST),
    )
    .as_bytes();
    let mut chain = open_chain(&store_dir);

    let genesis = build_coinbase_only_block(
        [0u8; 32],
        Hash256::ZERO,
        BlockHeight::GENESIS,
        U256::zero(),
        [0u8; 32],
        30,
        &chain_id,
    );
    chain.connect_block(&genesis, safe_now()).expect("genesis");

    let canonical_1 = build_coinbase_only_block(
        *block_hash(&genesis).as_bytes(),
        block_hash(&genesis),
        BlockHeight(1),
        genesis.header.total_difficulty,
        [0u8; 32],
        31,
        &chain_id,
    );
    chain
        .connect_block(&canonical_1, safe_now())
        .expect("canonical 1");

    let canonical_2 = build_coinbase_only_block(
        *block_hash(&genesis).as_bytes(),
        block_hash(&canonical_1),
        BlockHeight(2),
        canonical_1.header.total_difficulty,
        [0u8; 32],
        32,
        &chain_id,
    );
    chain
        .connect_block(&canonical_2, safe_now())
        .expect("canonical 2");

    let side_1 = build_coinbase_only_block(
        *block_hash(&genesis).as_bytes(),
        block_hash(&genesis),
        BlockHeight(1),
        genesis.header.total_difficulty,
        [0u8; 32],
        33,
        &chain_id,
    );
    let side_1_result = chain.connect_block(&side_1, safe_now()).expect("side 1");
    assert!(
        matches!(side_1_result, dom_chain::ConnectResult::SideChain),
        "side_1 should be retained, not promoted"
    );

    let canonical_1_coinbase_value = dom_core::block_reward(BlockHeight(1)).noms();
    let invalid_against_side_branch = valid_spend_tx(
        canonical_1_coinbase_value,
        scalar(31),
        canonical_1_coinbase_value - dom_core::MIN_RELAY_FEE_RATE * 100,
        40,
        &chain_id,
    );
    let side_2_invalid = build_block_with_transactions(
        *block_hash(&genesis).as_bytes(),
        block_hash(&side_1),
        BlockHeight(2),
        side_1.header.total_difficulty,
        [0u8; 32],
        34,
        vec![invalid_against_side_branch],
        &chain_id,
    );
    let side_2_invalid_hash = block_hash(&side_2_invalid);
    let side_2_result = chain
        .connect_block(&side_2_invalid, safe_now())
        .expect("invalid-context side block is quarantined");
    assert!(
        matches!(side_2_result, dom_chain::ConnectResult::SideChain),
        "side_2 should be retained before branch-context input validation"
    );
    assert!(
        chain
            .store
            .get_block_body(side_2_invalid_hash.as_bytes())
            .expect("read retained side body")
            .is_some(),
        "side-chain block should be persisted in quarantine"
    );

    let side_3_heavier = build_coinbase_only_block(
        *block_hash(&genesis).as_bytes(),
        block_hash(&side_2_invalid),
        BlockHeight(3),
        side_2_invalid.header.total_difficulty,
        [0u8; 32],
        35,
        &chain_id,
    );
    let side_3_heavier_hash = block_hash(&side_3_heavier);
    chain
        .store
        .store_known_block(
            side_3_heavier_hash.as_bytes(),
            &side_3_heavier.header.to_bytes().expect("header bytes"),
            &side_3_heavier.to_bytes().expect("block bytes"),
        )
        .expect("store heavier side tip");

    let err = chain
        .promote_heavier_known_tip(side_3_heavier_hash)
        .expect_err("promotion must reject branch-invalid input");
    let msg = err.to_string();
    assert!(
        msg.contains("missing input") || msg.contains("reorg connect"),
        "expected branch-context input rejection, got: {msg}"
    );
    assert_eq!(
        chain.tip_hash,
        block_hash(&canonical_2),
        "failed promotion must leave canonical tip unchanged"
    );
}

// ── R-06: direct connect path kernel/output uniqueness ────────────────────────
//
// Before R-06, a duplicate kernel/output on the direct connect path was caught
// only by dom-store's NO_OVERWRITE guard and surfaced as DomError::Internal,
// which does NOT increase ban score (dom-core error.rs). The reorg path already
// returned Invalid. These tests pin that the direct path now also returns
// Invalid (ban-scored), mirroring the reorg path, so a replaying peer is
// penalized. Each isolates ONE branch so the matching message is asserted.

#[test]
fn direct_connect_rejects_replayed_kernel_with_invalid() {
    std::env::set_var("DOM_REGTEST_FAST_MINING", "1");
    let dir = TempDir::new().expect("tempdir");
    let store_dir = dir.path().join("chain");
    let chain_id = *derive_chain_id(
        NETWORK_MAGIC_REGTEST,
        &Hash256::from_bytes(dom_core::GENESIS_HASH_REGTEST),
    )
    .as_bytes();
    let mut chain = open_chain(&store_dir);

    let genesis = build_coinbase_only_block(
        [0u8; 32],
        Hash256::ZERO,
        BlockHeight::GENESIS,
        U256::zero(),
        [0u8; 32],
        40,
        &chain_id,
    );
    chain.connect_block(&genesis, safe_now()).expect("genesis");

    // Fully valid height-1 direct extension. Its coinbase uses a DIFFERENT
    // blinding seed than genesis, so the coinbase OUTPUT commitment does not
    // collide with any persisted UTXO — only the kernel excess is made to
    // collide, isolating the kernel-uniqueness branch.
    let replay = build_coinbase_only_block(
        *block_hash(&genesis).as_bytes(),
        block_hash(&genesis),
        BlockHeight(1),
        genesis.header.total_difficulty,
        [0u8; 32],
        41,
        &chain_id,
    );

    // Seed the kernel index with the replay block's coinbase excess (as if a
    // prior block already used it), WITHOUT persisting its output, so only the
    // kernel branch can fire.
    let replayed_excess = *replay.coinbase.kernel.excess.as_bytes();
    chain
        .store
        .ensure_kernel_indices(&[(replayed_excess, *block_hash(&genesis).as_bytes())])
        .expect("seed kernel index with prior excess");

    let err = chain
        .connect_block(&replay, safe_now())
        .expect_err("direct connect must reject a replayed kernel excess");
    assert!(
        matches!(err, dom_core::DomError::Invalid(_)),
        "kernel replay on the direct path must be Invalid, got: {err:?}"
    );
    assert!(
        err.increases_ban_score(),
        "kernel replay must raise ban score (got non-ban-scored: {err:?})"
    );
    assert!(
        err.to_string()
            .contains("direct connect kernel replay detected"),
        "unexpected error message: {err}"
    );
}

#[test]
fn direct_connect_rejects_duplicate_output_commitment() {
    std::env::set_var("DOM_REGTEST_FAST_MINING", "1");
    let dir = TempDir::new().expect("tempdir");
    let store_dir = dir.path().join("chain");
    let chain_id = *derive_chain_id(
        NETWORK_MAGIC_REGTEST,
        &Hash256::from_bytes(dom_core::GENESIS_HASH_REGTEST),
    )
    .as_bytes();
    let mut chain = open_chain(&store_dir);

    let genesis = build_coinbase_only_block(
        [0u8; 32],
        Hash256::ZERO,
        BlockHeight::GENESIS,
        U256::zero(),
        [0u8; 32],
        50,
        &chain_id,
    );
    chain.connect_block(&genesis, safe_now()).expect("genesis");

    // Height-1 direct extension whose coinbase REUSES genesis's blinding seed,
    // so its coinbase output commitment equals genesis's already-persisted UTXO
    // (reward is constant before the first halving, so the value matches too).
    // The output branch is checked first, mirroring the reorg path.
    let dup = build_coinbase_only_block(
        *block_hash(&genesis).as_bytes(),
        block_hash(&genesis),
        BlockHeight(1),
        genesis.header.total_difficulty,
        [0u8; 32],
        50,
        &chain_id,
    );
    assert_eq!(
        dup.coinbase.output.commitment.as_bytes(),
        genesis.coinbase.output.commitment.as_bytes(),
        "fixture must reuse the genesis coinbase output commitment"
    );

    let err = chain
        .connect_block(&dup, safe_now())
        .expect_err("direct connect must reject a duplicate output commitment");
    assert!(
        matches!(err, dom_core::DomError::Invalid(_)),
        "duplicate output on the direct path must be Invalid, got: {err:?}"
    );
    assert!(
        err.increases_ban_score(),
        "duplicate output must raise ban score (got non-ban-scored: {err:?})"
    );
    assert!(
        err.to_string()
            .contains("direct connect duplicate output commitment"),
        "unexpected error message: {err}"
    );
}
