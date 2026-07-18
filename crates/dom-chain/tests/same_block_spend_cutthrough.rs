//! Same-block-spend / cut-through path-alignment tests (TASK 29).
//!
//! Policy B (RFC-0012 §4, RFC-0010 §3.3): a published block must never spend an
//! output created earlier in the same block. The canonical (post-cut-through)
//! form of a block contains no commitment that appears as both a block input and
//! a block output; any such block is rejected unconditionally, before
//! cryptographic/economic checks.
//!
//! These tests pin the alignment guarantee at two levels:
//!   * the *live* direct-extension path (`connect_block`) rejects a same-block
//!     spend end-to-end (real PoW, real ingress);
//!   * the shared consensus gate `dom_consensus::validate_block` — through which
//!     the live, IBD body-import, replay, and reorg paths all funnel — rejects
//!     the identical block with the identical cut-through reason under both a
//!     live-style and an IBD-style validation context, so the paths cannot
//!     disagree.

mod common;

use common::open_test_chain;
use dom_chain::ChainState;
use dom_consensus::block::{BlockHeader, ProofOfWork};
use dom_consensus::{
    compute_block_pmmr_roots, derive_chain_id, validate_block, Block, CoinbaseKernel,
    CoinbaseTransaction, Transaction, TransactionInput, TransactionKernel, TransactionOutput,
    ValidationContext,
};
use dom_core::{
    Amount, BlockHeight, Hash256, Timestamp, KERNEL_FEAT_COINBASE, KERNEL_FEAT_PLAIN,
    MIN_RELAY_FEE_RATE, NETWORK_MAGIC_REGTEST, PROTOCOL_VERSION, TAG_KERNEL_MSG_COINBASE,
};
use dom_crypto::{
    hash::blake2b_256_tagged,
    keys::SecretKey,
    pedersen::{BlindingFactor, Commitment},
    schnorr_sign,
};
use dom_pow::{
    expected_target_for_network, fast_pow_hash, genesis_anchor, hash_meets_target,
    target_to_compact, target_to_difficulty, CompactTarget,
};
use dom_serialization::DomSerialize;
use primitive_types::U256;
use tempfile::TempDir;

fn scalar(seed: u8) -> BlindingFactor {
    let mut bytes = [0u8; 32];
    bytes[31] = seed.max(1);
    BlindingFactor::from_bytes(bytes).expect("deterministic scalar")
}

fn commitment(seed: u8, value: u64) -> Commitment {
    Commitment::commit(value, &scalar(seed))
}

fn block_timestamp(height: BlockHeight) -> Timestamp {
    genesis_anchor(NETWORK_MAGIC_REGTEST)
        .expect("anchor")
        .timestamp
        .checked_add_secs(height.0 * dom_core::TARGET_SPACING)
        .expect("timestamp")
}

/// One fixed, compact-exact target reused for genesis and the first post-genesis
/// block. The regtest DAA keeps the target constant immediately after genesis
/// (next == previous), so reusing genesis's canonical target lets a height-1
/// block satisfy `validate_expected_target`.
fn fixed_target() -> [u8; 32] {
    let raw = expected_target_for_network(
        NETWORK_MAGIC_REGTEST,
        block_timestamp(BlockHeight(0)),
        BlockHeight(0),
    )
    .expect("target");
    CompactTarget(target_to_compact(&raw))
        .to_target()
        .expect("target roundtrip")
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
    target: [u8; 32],
    seed_hash: [u8; 32],
    prev_hash: Hash256,
    height: BlockHeight,
    timestamp: Timestamp,
    output_root: Hash256,
    kernel_root: Hash256,
    rangeproof_root: Hash256,
    total_difficulty: U256,
) -> BlockHeader {
    let compact = target_to_compact(&target);
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
            target: CompactTarget(compact),
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

/// Build a regtest-mineable block at `height` carrying `transactions`, using the
/// fixed canonical target. `seed_hash` is the RandomX seed the chain validates
/// against — the genesis hash for early heights, `[0u8; 32]` for genesis.
fn build_block_with_txs(
    seed_hash: [u8; 32],
    prev_hash: Hash256,
    height: BlockHeight,
    parent_total_difficulty: U256,
    coinbase_seed: u8,
    chain_id: &[u8; 32],
    transactions: Vec<Transaction>,
) -> Block {
    let target = fixed_target();
    let coinbase = build_coinbase(height, 0, coinbase_seed, chain_id);
    let (output_root, kernel_root, rangeproof_root) =
        compute_block_pmmr_roots(height, &coinbase, &transactions).expect("roots");
    let total_difficulty = parent_total_difficulty + U256::from(target_to_difficulty(&target));
    let header = mine_fast_header(
        target,
        seed_hash,
        prev_hash,
        height,
        block_timestamp(height),
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

/// A regular plain transaction with the given inputs and a single output. The
/// crypto is not meaningful: the cut-through gate rejects same-block spends
/// before any signature/range-proof/balance validation runs, so these never
/// reach it.
fn plain_tx(inputs: Vec<Commitment>, output: Commitment, seed: u8) -> Transaction {
    Transaction {
        inputs: inputs
            .into_iter()
            .map(|commitment| TransactionInput { commitment })
            .collect(),
        outputs: vec![TransactionOutput {
            commitment: output,
            proof: vec![seed; 8],
        }],
        kernels: vec![TransactionKernel {
            features: KERNEL_FEAT_PLAIN,
            fee: Amount::from_noms(MIN_RELAY_FEE_RATE * 100).expect("fee"),
            lock_height: 0,
            excess: commitment(seed.wrapping_add(100), 0),
            excess_signature: [seed; 65],
        }],
        offset: [0u8; 32],
    }
}

/// A block at `height` whose body spends, within the same block, an output it
/// also creates (tx A creates X; tx B spends X) — the forbidden same-block-spend
/// / non-cut-through form.
fn same_block_spend_block(
    seed_hash: [u8; 32],
    prev_hash: Hash256,
    height: BlockHeight,
    parent_total_difficulty: U256,
    coinbase_seed: u8,
    chain_id: &[u8; 32],
) -> Block {
    let x = commitment(coinbase_seed.wrapping_add(1), 10);
    let y = commitment(coinbase_seed.wrapping_add(2), 9);
    let tx_a = plain_tx(vec![], x.clone(), coinbase_seed.wrapping_add(3));
    let tx_b = plain_tx(vec![x], y, coinbase_seed.wrapping_add(4));
    build_block_with_txs(
        seed_hash,
        prev_hash,
        height,
        parent_total_difficulty,
        coinbase_seed,
        chain_id,
        vec![tx_a, tx_b],
    )
}

fn block_hash(block: &Block) -> Hash256 {
    Hash256::from_bytes(
        *dom_crypto::hash::blake2b_256(&block.header.to_bytes().unwrap()).as_bytes(),
    )
}

fn open_chain(dir: &std::path::Path) -> ChainState {
    // These direct-ingress fixtures construct their own block-zero record.
    // Use the unpinned test identity so the canonical Regtest genesis check
    // remains enforced for production configurations without rejecting it.
    open_test_chain(dir, Hash256::ZERO, NETWORK_MAGIC_REGTEST).expect("chain open")
}

fn safe_now() -> Timestamp {
    Timestamp(2_000_000_000)
}

fn chain_id() -> [u8; 32] {
    *derive_chain_id(NETWORK_MAGIC_REGTEST, &Hash256::ZERO).as_bytes()
}

fn is_cut_through_rejection(msg: &str) -> bool {
    msg.contains("cut-through") || msg.contains("cut through")
}

/// Live path: direct chain extension rejects a same-block spend with the
/// cut-through reason, never consulting an intra-block output overlay.
#[test]
fn direct_extension_rejects_same_block_spend() {
    std::env::set_var("DOM_REGTEST_FAST_MINING", "1");
    let dir = TempDir::new().expect("tempdir");
    let chain_id = chain_id();
    let mut chain = open_chain(dir.path());

    let genesis = build_block_with_txs(
        [0u8; 32],
        Hash256::ZERO,
        BlockHeight::GENESIS,
        U256::zero(),
        10,
        &chain_id,
        vec![],
    );
    chain.connect_block(&genesis, safe_now()).expect("genesis");

    // randomx_seed_height(1) == 0 → seed is the genesis block hash.
    let violating = same_block_spend_block(
        *block_hash(&genesis).as_bytes(),
        block_hash(&genesis),
        BlockHeight(1),
        genesis.header.total_difficulty,
        11,
        &chain_id,
    );
    let err = chain
        .connect_block(&violating, safe_now())
        .expect_err("direct extension must reject a same-block spend");
    assert!(
        is_cut_through_rejection(&err.to_string()),
        "expected cut-through rejection on the live path, got: {err}"
    );
}

/// Live path specificity: a clean (cut-through-respecting) height-1 block is
/// accepted, proving the rejection above is specific to the same-block spend.
#[test]
fn direct_extension_accepts_clean_block() {
    std::env::set_var("DOM_REGTEST_FAST_MINING", "1");
    let dir = TempDir::new().expect("tempdir");
    let chain_id = chain_id();
    let mut chain = open_chain(dir.path());

    let genesis = build_block_with_txs(
        [0u8; 32],
        Hash256::ZERO,
        BlockHeight::GENESIS,
        U256::zero(),
        30,
        &chain_id,
        vec![],
    );
    chain
        .connect_block(&genesis, safe_now())
        .expect("clean genesis must be accepted");

    let clean = build_block_with_txs(
        *block_hash(&genesis).as_bytes(),
        block_hash(&genesis),
        BlockHeight(1),
        genesis.header.total_difficulty,
        31,
        &chain_id,
        vec![],
    );
    let result = chain
        .connect_block(&clean, safe_now())
        .expect("clean height-1 block must be accepted");
    assert!(matches!(result, dom_chain::ConnectResult::BestChain));
}

/// Shared-gate alignment: the same-block-spend block is rejected by
/// `dom_consensus::validate_block` — the single gate the live, IBD body-import,
/// replay, and reorg paths all delegate to — with the identical cut-through
/// reason under both a live-style and an IBD-style validation context. The paths
/// therefore cannot disagree. A clean block passes the same gate under both
/// contexts, confirming the rejection is specific to the same-block spend.
#[test]
fn shared_validate_block_gate_rejects_same_block_spend_under_live_and_ibd_contexts() {
    std::env::set_var("DOM_REGTEST_FAST_MINING", "1");
    let chain_id = chain_id();

    let violating = same_block_spend_block(
        [0u8; 32],
        Hash256::ZERO,
        BlockHeight::GENESIS,
        U256::zero(),
        40,
        &chain_id,
    );

    // Live-style context (wall-clock now) and IBD-style context (historical/no
    // future-time pressure). The cut-through gate is context-independent, so both
    // must reject identically.
    let live_ctx = ValidationContext {
        current_height: BlockHeight::GENESIS,
        chain_id,
        now: safe_now(),
    };
    let ibd_ctx = ValidationContext {
        current_height: BlockHeight::GENESIS,
        chain_id,
        now: Timestamp(u64::MAX),
    };

    let live_err = validate_block(&violating, &live_ctx)
        .expect_err("live-context validation must reject the same-block spend");
    let ibd_err = validate_block(&violating, &ibd_ctx)
        .expect_err("ibd-context validation must reject the same-block spend");
    assert!(
        is_cut_through_rejection(&live_err.to_string()),
        "live context: expected cut-through rejection, got: {live_err}"
    );
    assert_eq!(
        live_err.to_string(),
        ibd_err.to_string(),
        "live and IBD validation must reject with the identical reason — they cannot disagree"
    );

    // Specificity: a clean coinbase-only block passes the same gate under both
    // contexts.
    let clean = build_block_with_txs(
        [0u8; 32],
        Hash256::ZERO,
        BlockHeight::GENESIS,
        U256::zero(),
        41,
        &chain_id,
        vec![],
    );
    validate_block(&clean, &live_ctx).expect("clean block passes the live-context gate");
    validate_block(&clean, &ibd_ctx).expect("clean block passes the ibd-context gate");
}
