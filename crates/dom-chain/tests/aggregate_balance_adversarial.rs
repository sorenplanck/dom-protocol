//! Integration-level aggregate block-balance adversarial tests.
//!
//! `connect_block()` in `chain_state.rs` (line 257) delegates all consensus
//! validation to `dom_consensus::validate_block()` — the single gate for every
//! block acceptance path (live relay, IBD, chain extension, reorg promotion,
//! local mining). These tests call `validate_block()` directly with
//! cryptographically valid coinbase-only blocks to prove that the aggregate
//! balance equation is enforced and cannot be bypassed.
//!
//! Why coinbase-only blocks: they let us isolate aggregate balance enforcement
//! with minimal crypto setup. An empty transaction list means per-tx validation
//! trivially passes, so any rejection comes purely from the aggregate balance
//! or coinbase explicit_value checks — which is exactly what we want to pin.

use dom_consensus::{
    block::{BlockHeader, ProofOfWork},
    compute_block_pmmr_roots, validate_block, Block, CoinbaseKernel, CoinbaseTransaction,
    TransactionOutput, ValidationContext,
};
use dom_core::{
    BlockHeight, Hash256, Timestamp, KERNEL_FEAT_COINBASE, PROTOCOL_VERSION,
    TAG_KERNEL_MSG_COINBASE,
};
use dom_crypto::{
    hash::blake2b_256_tagged,
    keys::SecretKey,
    pedersen::{BlindingFactor, Commitment},
    schnorr_sign,
};
use dom_pow::CompactTarget;
use primitive_types::U256;

fn scalar(seed: u8) -> BlindingFactor {
    let mut bytes = [0u8; 32];
    bytes[31] = seed.max(1);
    BlindingFactor::from_bytes(bytes).expect("deterministic scalar")
}

/// Build a cryptographically valid coinbase for height 1 with the given chain_id.
/// The coinbase claims exactly block_reward + claimed_fees in explicit_value.
fn build_coinbase(claimed_fees: u64, chain_id: &[u8; 32]) -> CoinbaseTransaction {
    let reward = dom_core::block_reward(BlockHeight(1)).noms();
    let explicit_value = reward + claimed_fees;
    let blinding = scalar(50);
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

fn make_header(coinbase: &CoinbaseTransaction, total_kernel_offset: [u8; 32]) -> BlockHeader {
    let (output_root, kernel_root, rangeproof_root) =
        compute_block_pmmr_roots(coinbase, &[]).expect("pmmr roots");
    BlockHeader {
        version: PROTOCOL_VERSION,
        height: BlockHeight(1),
        prev_hash: Hash256::from_bytes([0x77; 32]),
        timestamp: Timestamp(1_704_067_260),
        output_root,
        kernel_root,
        rangeproof_root,
        total_kernel_offset,
        target: CompactTarget(0x1f00_ffff),
        total_difficulty: U256::from(2u64),
        pow: ProofOfWork {
            nonce: 1,
            randomx_hash: Hash256::ZERO,
        },
    }
}

/// A coinbase-only block with total_kernel_offset = zero must pass aggregate
/// balance. For an empty block: LHS = coinbase_output, RHS = coinbase_excess +
/// reward·H. Both equal reward·H + r·G when the coinbase is correctly built.
#[test]
fn coinbase_only_block_with_zero_offset_passes_aggregate_balance() {
    let chain_id = [0x11u8; 32];
    let coinbase = build_coinbase(0, &chain_id);
    let block = Block {
        header: make_header(&coinbase, [0u8; 32]),
        coinbase,
        transactions: vec![],
    };
    validate_block(
        &block,
        &ValidationContext {
            current_height: BlockHeight(1),
            chain_id,
            now: Timestamp(u64::MAX),
        },
    )
    .expect("coinbase-only block with zero offset must satisfy aggregate balance");
}

/// Tampering total_kernel_offset in the block header breaks the aggregate
/// balance equation for an otherwise valid coinbase-only block.
///
/// For an empty transaction list the correct offset is always [0u8; 32].
/// Any non-zero value shifts the RHS by offset·G, making LHS ≠ RHS.
///
/// This is the same check that `connect_block()` enforces on every acceptance
/// path via its call to `validate_block()` at chain_state.rs:257.
#[test]
fn tampered_kernel_offset_breaks_aggregate_balance_on_coinbase_only_block() {
    let chain_id = [0x11u8; 32];
    let coinbase = build_coinbase(0, &chain_id);

    let mut bad_offset = [0u8; 32];
    bad_offset[31] = 1; // shift RHS by G — LHS ≠ RHS

    let block = Block {
        header: make_header(&coinbase, bad_offset),
        coinbase,
        transactions: vec![],
    };
    let err = validate_block(
        &block,
        &ValidationContext {
            current_height: BlockHeight(1),
            chain_id,
            now: Timestamp(u64::MAX),
        },
    )
    .expect_err("non-zero offset on coinbase-only block must fail aggregate balance");
    assert!(
        err.to_string().contains("aggregate") || err.to_string().contains("balance"),
        "expected aggregate balance rejection, got: {err}"
    );
}

/// A block where the coinbase claims more fees than zero (the actual tx fee
/// sum for an empty transaction list) is rejected via the coinbase
/// explicit_value check — a distinct defence-in-depth layer that fires before
/// the aggregate balance equation is evaluated.
#[test]
fn coinbase_fee_overstatement_on_empty_block_is_rejected() {
    let chain_id = [0x11u8; 32];
    let coinbase = build_coinbase(100, &chain_id); // claims 100 noms in fees; actual = 0
    let block = Block {
        header: make_header(&coinbase, [0u8; 32]),
        coinbase,
        transactions: vec![],
    };
    let err = validate_block(
        &block,
        &ValidationContext {
            current_height: BlockHeight(1),
            chain_id,
            now: Timestamp(u64::MAX),
        },
    )
    .expect_err("coinbase with overstated fees must be rejected");
    let msg = err.to_string();
    assert!(
        msg.contains("explicit_value") || msg.contains("coinbase") || msg.contains("fee"),
        "expected coinbase/explicit_value rejection, got: {msg}"
    );
}
