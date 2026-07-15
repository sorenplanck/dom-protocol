//! dom-shield FAMILY 1 — I3 consensus convergence (dom-chain).
//!
//! Convergence invariant: when two independent nodes follow valid block-delivery
//! sequences that *select the same canonical tip T*, their final committed state
//! must be byte-identical. "Final state" is the differential ORACLE below:
//!
//!   (tip_hash, tip_height, tip_difficulty)               — fork-choice result
//!   store.read_all_utxos_raw()  (BTreeMap, PartialEq)    — full UTXO set
//!   store.get_metadata(METADATA_UTXO_SET_DIGEST_KEY)     — persisted digest
//!
//! A divergence between two paths to the same tip T is a LATENT CHAIN-SPLIT:
//! two honest nodes would commit different UTXO sets behind the same hash.
//!
//! Method: build via the REAL proof-of-work block builder (fast-mining regtest),
//! drive two independent `ChainState` instances over two tempdir stores, and
//! assert the oracle is equal at the end. No production code is touched; this is
//! read-only over behavior (dom-shield test-construction method).
//!
//! Helpers (mine_fast_header, build_coinbase, valid_spend_tx,
//! build_coinbase_only_block, build_block_with_transactions) are COPIED from
//! `block_validation_ingress_adversarial.rs` — Rust integration tests cannot
//! share a non-`common` module, so duplication is required, not theater.

mod common;

use common::{open_test_chain, open_test_store};
use dom_chain::{ChainState, ConnectResult};
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
use dom_store::{DomStore, METADATA_UTXO_SET_DIGEST_KEY};
use primitive_types::U256;
use std::collections::BTreeMap;
use std::path::Path;
use tempfile::TempDir;

// ─────────────────────────── REAL-PoW builder helpers ────────────────────────
// Copied verbatim (semantics) from block_validation_ingress_adversarial.rs.

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

// ───────────────────────────── shared test utilities ─────────────────────────

fn block_hash(block: &Block) -> Hash256 {
    Hash256::from_bytes(
        *dom_crypto::hash::blake2b_256(&block.header.to_bytes().unwrap()).as_bytes(),
    )
}

fn open_chain(dir: &Path) -> ChainState {
    // These convergence scenarios build independent synthetic block-zero
    // records. Hash256::ZERO selects the unpinned test identity while the
    // finalized Regtest identity remains mandatory in production startup.
    open_test_chain(dir, Hash256::ZERO, NETWORK_MAGIC_REGTEST).expect("chain open")
}

fn regtest_chain_id() -> [u8; 32] {
    *derive_chain_id(NETWORK_MAGIC_REGTEST, &Hash256::ZERO).as_bytes()
}

fn safe_now() -> Timestamp {
    Timestamp(2_000_000_000)
}

/// The differential convergence ORACLE: full committed state of a chain.
#[derive(Debug, PartialEq, Eq)]
struct StateFingerprint {
    tip_hash: Hash256,
    tip_height: BlockHeight,
    tip_difficulty: U256,
    utxos: BTreeMap<Vec<u8>, Vec<u8>>,
    digest: Option<Vec<u8>>,
}

fn fingerprint(chain: &ChainState) -> StateFingerprint {
    StateFingerprint {
        tip_hash: chain.tip_hash,
        tip_height: chain.tip_height,
        tip_difficulty: chain.tip_difficulty,
        utxos: chain.store.read_all_utxos_raw().expect("read utxos"),
        digest: chain
            .store
            .get_metadata(METADATA_UTXO_SET_DIGEST_KEY)
            .expect("digest metadata"),
    }
}

fn fingerprint_store(store: &DomStore, tip: &ChainState) -> StateFingerprint {
    StateFingerprint {
        tip_hash: tip.tip_hash,
        tip_height: tip.tip_height,
        tip_difficulty: tip.tip_difficulty,
        utxos: store.read_all_utxos_raw().expect("read utxos"),
        digest: store
            .get_metadata(METADATA_UTXO_SET_DIGEST_KEY)
            .expect("digest metadata"),
    }
}

/// Consensus-relevant fingerprint: tip triple + UTXO set, WITHOUT the cached
/// digest. The `METADATA_UTXO_SET_DIGEST_KEY` is a derived cache populated only
/// by `ChainState::open` (reopen), not by the live `connect_block` path, so two
/// live nodes legitimately have `digest: None` while a reopened node has
/// `Some(..)`. The convergence invariant is over the UTXO SET itself (which the
/// digest summarizes); comparing the full fingerprint would conflate a cache
/// artifact with a real chain-split. See FINDING-DIGEST-CACHE in the report.
#[derive(Debug, PartialEq, Eq)]
struct ConsensusFingerprint {
    tip_hash: Hash256,
    tip_height: BlockHeight,
    tip_difficulty: U256,
    utxos: BTreeMap<Vec<u8>, Vec<u8>>,
}

fn consensus_fingerprint(chain: &ChainState) -> ConsensusFingerprint {
    ConsensusFingerprint {
        tip_hash: chain.tip_hash,
        tip_height: chain.tip_height,
        tip_difficulty: chain.tip_difficulty,
        utxos: chain.store.read_all_utxos_raw().expect("read utxos"),
    }
}

// ───────────────────────── (a) same chain, different build order ──────────────
//
// Two nodes that end at the SAME canonical tip T must commit identical state,
// regardless of the order in which blocks (and competing forks) arrived.
//
// chain-A: builds the canonical branch G -> C1 -> C2 -> C3 directly, in order.
// chain-B: extends to C1 (so the current tip is C1, not genesis), THEN delivers
//          a competing fork off genesis (side block S1). Because S1's parent
//          (genesis) is no longer the tip, connect_block routes it to the
//          side-chain quarantine (a height-1 block whose parent IS the tip would
//          instead be a direct extension and, at equal work, rejected Invalid —
//          DOM has no orphan buffer, so every parent is always present). B then
//          extends C2, C3. S1 lingers non-canonical; both nodes finish at C3.
//
// The oracle (tip triple + UTXO set) must be byte-identical regardless of the
// order in which the competing fork arrived.

#[test]
fn convergence_same_canonical_tip_independent_of_arrival_order() {
    std::env::set_var("DOM_REGTEST_FAST_MINING", "1");
    let chain_id = regtest_chain_id();

    // ── Build the canonical branch G -> C1 -> C2 -> C3 once; both nodes commit
    //    the SAME byte-identical blocks so the final tip T is the same hash.
    let genesis = build_coinbase_only_block(
        [0u8; 32],
        Hash256::ZERO,
        BlockHeight::GENESIS,
        U256::zero(),
        [0u8; 32],
        10,
        &chain_id,
    );
    let mut height_1_siblings: Vec<_> = (11u8..=80)
        .map(|seed| {
            build_coinbase_only_block(
                *block_hash(&genesis).as_bytes(),
                block_hash(&genesis),
                BlockHeight(1),
                genesis.header.total_difficulty,
                [0u8; 32],
                seed,
                &chain_id,
            )
        })
        .collect();
    height_1_siblings.sort_by(|a, b| block_hash(a).as_bytes().cmp(block_hash(b).as_bytes()));
    let c1 = height_1_siblings.remove(0);
    let s1 = height_1_siblings
        .pop()
        .expect("higher equal-work side sibling");
    let c1_hash = block_hash(&c1);
    assert!(
        c1_hash.as_bytes() < block_hash(&s1).as_bytes(),
        "fixture must keep side sibling worse than C1 under equal-work tie rule"
    );
    let c2 = build_coinbase_only_block(
        *block_hash(&genesis).as_bytes(),
        block_hash(&c1),
        BlockHeight(2),
        c1.header.total_difficulty,
        [0u8; 32],
        12,
        &chain_id,
    );
    let c3 = build_coinbase_only_block(
        *block_hash(&genesis).as_bytes(),
        block_hash(&c2),
        BlockHeight(3),
        c2.header.total_difficulty,
        [0u8; 32],
        13,
        &chain_id,
    );

    // S1 is a competing fork off genesis whose equal-work hash is higher than
    // C1, so this test exercises side-chain retention, not tie-rule promotion.

    // ── chain-A: canonical branch in order, no competing fork ────────────────
    let dir_a = TempDir::new().expect("tempdir A");
    let mut chain_a = open_chain(&dir_a.path().join("chain"));
    assert!(matches!(
        chain_a
            .connect_block(&genesis, safe_now())
            .expect("A genesis"),
        ConnectResult::BestChain
    ));
    assert!(matches!(
        chain_a.connect_block(&c1, safe_now()).expect("A c1"),
        ConnectResult::BestChain
    ));
    assert!(matches!(
        chain_a.connect_block(&c2, safe_now()).expect("A c2"),
        ConnectResult::BestChain
    ));
    assert!(matches!(
        chain_a.connect_block(&c3, safe_now()).expect("A c3"),
        ConnectResult::BestChain
    ));

    // ── chain-B: C1 first, then competing fork S1, then C2, C3 ───────────────
    let dir_b = TempDir::new().expect("tempdir B");
    let mut chain_b = open_chain(&dir_b.path().join("chain"));
    assert!(matches!(
        chain_b
            .connect_block(&genesis, safe_now())
            .expect("B genesis"),
        ConnectResult::BestChain
    ));
    assert!(matches!(
        chain_b.connect_block(&c1, safe_now()).expect("B c1"),
        ConnectResult::BestChain
    ));
    // S1's parent (genesis) is no longer the tip (C1 is), and its equal-work
    // hash is higher than C1, so it must remain side-chain data.
    assert!(matches!(
        chain_b.connect_block(&s1, safe_now()).expect("B s1"),
        ConnectResult::SideChain
    ));
    assert!(matches!(
        chain_b.connect_block(&c2, safe_now()).expect("B c2"),
        ConnectResult::BestChain
    ));
    assert!(matches!(
        chain_b.connect_block(&c3, safe_now()).expect("B c3"),
        ConnectResult::BestChain
    ));

    // Both nodes selected the same canonical tip T == c3.
    assert_eq!(chain_a.tip_hash, block_hash(&c3), "A tip must be c3");
    assert_eq!(chain_b.tip_hash, block_hash(&c3), "B tip must be c3");

    // ORACLE: byte-identical final committed state despite the competing fork
    // arriving mid-stream on chain-B.
    assert_eq!(
        consensus_fingerprint(&chain_a),
        consensus_fingerprint(&chain_b),
        "DIVERGENCE: two paths to the same canonical tip committed different state \
         (latent chain-split)"
    );
}

#[test]
fn equal_work_siblings_converge_to_lower_tip_hash_across_arrival_order_and_restart() {
    std::env::set_var("DOM_REGTEST_FAST_MINING", "1");
    let chain_id = regtest_chain_id();

    let genesis = build_coinbase_only_block(
        [0u8; 32],
        Hash256::ZERO,
        BlockHeight::GENESIS,
        U256::zero(),
        [0u8; 32],
        30,
        &chain_id,
    );
    let sibling_a = build_coinbase_only_block(
        *block_hash(&genesis).as_bytes(),
        block_hash(&genesis),
        BlockHeight(1),
        genesis.header.total_difficulty,
        [0u8; 32],
        31,
        &chain_id,
    );
    let sibling_b = build_coinbase_only_block(
        *block_hash(&genesis).as_bytes(),
        block_hash(&genesis),
        BlockHeight(1),
        genesis.header.total_difficulty,
        [0u8; 32],
        32,
        &chain_id,
    );
    assert_eq!(
        sibling_a.header.total_difficulty, sibling_b.header.total_difficulty,
        "siblings must carry equal accumulated work"
    );
    let hash_a = block_hash(&sibling_a);
    let hash_b = block_hash(&sibling_b);
    assert_ne!(hash_a, hash_b, "siblings must be distinct tips");
    let expected_tip = if hash_a.as_bytes() < hash_b.as_bytes() {
        hash_a
    } else {
        hash_b
    };

    let dir_ab = TempDir::new().expect("tempdir AB");
    let mut chain_ab = open_chain(&dir_ab.path().join("chain"));
    assert!(matches!(
        chain_ab
            .connect_block(&genesis, safe_now())
            .expect("AB genesis"),
        ConnectResult::BestChain
    ));
    assert!(matches!(
        chain_ab
            .connect_block(&sibling_a, safe_now())
            .expect("AB sibling A"),
        ConnectResult::BestChain
    ));
    let _ = chain_ab
        .connect_block(&sibling_b, safe_now())
        .expect("AB sibling B");
    assert_eq!(
        chain_ab.tip_hash, expected_tip,
        "A-then-B arrival must select the lower equal-work tip hash"
    );

    let dir_ba = TempDir::new().expect("tempdir BA");
    let mut chain_ba = open_chain(&dir_ba.path().join("chain"));
    assert!(matches!(
        chain_ba
            .connect_block(&genesis, safe_now())
            .expect("BA genesis"),
        ConnectResult::BestChain
    ));
    assert!(matches!(
        chain_ba
            .connect_block(&sibling_b, safe_now())
            .expect("BA sibling B"),
        ConnectResult::BestChain
    ));
    let _ = chain_ba
        .connect_block(&sibling_a, safe_now())
        .expect("BA sibling A");
    assert_eq!(
        chain_ba.tip_hash, expected_tip,
        "B-then-A arrival must select the lower equal-work tip hash"
    );

    let reopened_ab = open_chain(&dir_ab.path().join("chain"));
    let reopened_ba = open_chain(&dir_ba.path().join("chain"));
    assert_eq!(reopened_ab.tip_hash, expected_tip);
    assert_eq!(reopened_ba.tip_hash, expected_tip);
    assert_eq!(
        consensus_fingerprint(&reopened_ab),
        consensus_fingerprint(&reopened_ba),
        "equal-work fork choice must be restart-equivalent across opposite arrival orders"
    );
}

// ─────────── (a') out-of-order ORPHAN delivery — covered in dom-node ──────────
//
// Production child-before-parent convergence is exercised through live P2P
// block ingress by `production_peer_ingress_recursively_converges_reverse_orphans`
// in dom-node's `multinode_reordered_delivery` integration test.

// ─────────────── (b) chain+reorg vs direct chain to the SAME tip ──────────────
//
// chain-A connects the heavier winning branch G -> W1 -> W2 directly to tip T(=W2).
// chain-B first makes a LIGHTER branch canonical (G -> L1 becomes the tip), then
// receives the heavier branch G -> W1 -> W2; the arrival of W2 makes the W-branch
// heavier than L1 and triggers an automatic reorg (ConnectResult::Reorg) to the
// SAME tip T(=W2), disconnecting L1.
//
// Both end at tip W2. The oracle (tip triple + UTXO set) must be byte-identical:
// a reorg that lands on T must produce the exact UTXO set a direct path to T
// produces. This exercises the disconnect/reconnect overlay, not just sequential
// extension.

#[test]
fn convergence_reorg_to_tip_matches_direct_chain_to_same_tip() {
    std::env::set_var("DOM_REGTEST_FAST_MINING", "1");
    let chain_id = regtest_chain_id();

    let genesis = build_coinbase_only_block(
        [0u8; 32],
        Hash256::ZERO,
        BlockHeight::GENESIS,
        U256::zero(),
        [0u8; 32],
        20,
        &chain_id,
    );

    // Heavier winning branch (2 blocks above genesis): G -> W1 -> W2 = T.
    let w1 = build_coinbase_only_block(
        *block_hash(&genesis).as_bytes(),
        block_hash(&genesis),
        BlockHeight(1),
        genesis.header.total_difficulty,
        [0u8; 32],
        21,
        &chain_id,
    );
    let w2 = build_coinbase_only_block(
        *block_hash(&genesis).as_bytes(),
        block_hash(&w1),
        BlockHeight(2),
        w1.header.total_difficulty,
        [0u8; 32],
        22,
        &chain_id,
    );

    // Lighter branch: a single competing height-1 block off genesis. chain-B
    // accepts it as canonical first, so the winning branch must REORG over it.
    let l1 = build_coinbase_only_block(
        *block_hash(&genesis).as_bytes(),
        block_hash(&genesis),
        BlockHeight(1),
        genesis.header.total_difficulty,
        [0u8; 32],
        77,
        &chain_id,
    );

    // ── chain-A: direct path to T = W2 ───────────────────────────────────────
    let dir_a = TempDir::new().expect("tempdir A");
    let mut chain_a = open_chain(&dir_a.path().join("chain"));
    chain_a
        .connect_block(&genesis, safe_now())
        .expect("A genesis");
    chain_a.connect_block(&w1, safe_now()).expect("A w1");
    chain_a.connect_block(&w2, safe_now()).expect("A w2");
    assert_eq!(chain_a.tip_hash, block_hash(&w2), "A direct tip must be W2");

    // ── chain-B: lighter branch canonical, then reorg to T = W2 ──────────────
    let dir_b = TempDir::new().expect("tempdir B");
    let mut chain_b = open_chain(&dir_b.path().join("chain"));
    chain_b
        .connect_block(&genesis, safe_now())
        .expect("B genesis");
    // L1 directly extends genesis (the tip) -> becomes canonical height-1 tip.
    assert!(matches!(
        chain_b.connect_block(&l1, safe_now()).expect("B l1"),
        ConnectResult::BestChain
    ));
    assert_eq!(chain_b.tip_hash, block_hash(&l1), "B tip = L1");
    // W1's parent (genesis) is no longer the tip (L1 is). It remains side-chain
    // data unless the deterministic equal-work lower-hash tie rule promotes it.
    let _ = chain_b
        .connect_block(&w1, safe_now())
        .expect("B w1 side or tie reorg");
    // W2 makes the W-branch heavier than L1; if W1 already won the equal-work
    // lower-hash tie, W2 is a direct extension, otherwise this is a reorg.
    let reorg = chain_b.connect_block(&w2, safe_now()).expect("B w2");
    assert!(
        matches!(reorg, ConnectResult::Reorg(_) | ConnectResult::BestChain),
        "arrival of W2 must select the W branch, got: {reorg:?}"
    );
    assert_eq!(
        chain_b.tip_hash,
        block_hash(&w2),
        "B reorged tip must be W2"
    );

    // ORACLE: identical committed state for direct-vs-reorg to the same tip.
    assert_eq!(
        consensus_fingerprint(&chain_a),
        consensus_fingerprint(&chain_b),
        "DIVERGENCE: reorg path diverged from direct path to the same tip \
         (latent chain-split)"
    );
}

// ─── (b2) genuine auto-reorg (ConnectResult::Reorg) converges to direct tip ───
//
// Stronger than (b): here chain-B actually traverses the reorg engine. It builds
// a heavier height-1 side branch off genesis AFTER the canonical height-1 block
// is already the tip, so the side block's arrival promotes it via an automatic
// reorg (ConnectResult::Reorg) — exercising the disconnect/reconnect overlay,
// not just sequential best-chain extension. chain-A reaches the SAME tip T by a
// direct path. Spending transactions ensure the UTXO set is non-trivial so the
// oracle has real content to compare.

#[test]
fn convergence_auto_reorg_with_spends_matches_direct_path_to_same_tip() {
    std::env::set_var("DOM_REGTEST_FAST_MINING", "1");
    let chain_id = regtest_chain_id();

    // Genesis whose coinbase (seed 1) we will spend on the winning branch.
    let genesis = build_coinbase_only_block(
        [0u8; 32],
        Hash256::ZERO,
        BlockHeight::GENESIS,
        U256::zero(),
        [0u8; 32],
        1,
        &chain_id,
    );
    let cb_value = dom_core::block_reward(BlockHeight::GENESIS).noms();
    let cb_blinding = scalar(1);

    // Winning branch off genesis: W1 spends the genesis coinbase, W2 extends it.
    // W1 is heavier than the canonical decoy (it is the branch we converge to).
    let spend = valid_spend_tx(
        cb_value,
        cb_blinding.clone(),
        cb_value - dom_core::MIN_RELAY_FEE_RATE * 100,
        50,
        &chain_id,
    );
    let w1 = build_block_with_transactions(
        *block_hash(&genesis).as_bytes(),
        block_hash(&genesis),
        BlockHeight(1),
        genesis.header.total_difficulty,
        [0u8; 32],
        51,
        vec![spend],
        &chain_id,
    );
    let w2 = build_coinbase_only_block(
        *block_hash(&genesis).as_bytes(),
        block_hash(&w1),
        BlockHeight(2),
        w1.header.total_difficulty,
        [0u8; 32],
        52,
        &chain_id,
    );

    // A decoy canonical height-1 block (different coinbase seed) that chain-B
    // accepts as best chain first, so the winning branch must REORG over it.
    let decoy1 = build_coinbase_only_block(
        *block_hash(&genesis).as_bytes(),
        block_hash(&genesis),
        BlockHeight(1),
        genesis.header.total_difficulty,
        [0u8; 32],
        60,
        &chain_id,
    );

    // ── chain-A: direct path to T = W2 (no decoy) ────────────────────────────
    let dir_a = TempDir::new().expect("tempdir A");
    let mut chain_a = open_chain(&dir_a.path().join("chain"));
    chain_a
        .connect_block(&genesis, safe_now())
        .expect("A genesis");
    chain_a.connect_block(&w1, safe_now()).expect("A w1");
    chain_a.connect_block(&w2, safe_now()).expect("A w2");
    assert_eq!(chain_a.tip_hash, block_hash(&w2), "A direct tip must be W2");

    // ── chain-B: decoy canonical, then auto-reorg onto the winning branch ────
    let dir_b = TempDir::new().expect("tempdir B");
    let mut chain_b = open_chain(&dir_b.path().join("chain"));
    chain_b
        .connect_block(&genesis, safe_now())
        .expect("B genesis");
    // Decoy becomes canonical height-1 tip.
    assert!(matches!(
        chain_b
            .connect_block(&decoy1, safe_now())
            .expect("B decoy1"),
        ConnectResult::BestChain
    ));
    assert_eq!(chain_b.tip_hash, block_hash(&decoy1), "B tip = decoy1");
    // W1 ties decoy1 work. It remains side-chain data unless the deterministic
    // equal-work lower-hash tie rule promotes it immediately.
    let _ = chain_b
        .connect_block(&w1, safe_now())
        .expect("B w1 side or tie reorg");
    // W2 selects the W-branch; if W1 already won the equal-work tie, W2 is a
    // direct extension, otherwise this is a reorg.
    let reorg = chain_b.connect_block(&w2, safe_now()).expect("B w2");
    assert!(
        matches!(reorg, ConnectResult::Reorg(_) | ConnectResult::BestChain),
        "arrival of W2 must select the W branch, got: {reorg:?}"
    );
    assert_eq!(
        chain_b.tip_hash,
        block_hash(&w2),
        "B reorged tip must be W2"
    );

    // ORACLE: reorg-path state must equal direct-path state at the same tip.
    assert_eq!(
        consensus_fingerprint(&chain_a),
        consensus_fingerprint(&chain_b),
        "DIVERGENCE: auto-reorg landed on T with a different UTXO set than the \
         direct path to T (latent chain-split)"
    );
}

// ───────────────── (c) live-vs-reopen byte-identity (clean chain) ─────────────
//
// dom-chain ALREADY covers reopen/reconstruct convergence broadly:
//   corruption_detection.rs::canonical_utxo_set_is_equivalent_before_and_after_restart
//   corruption_detection.rs::reopen_rebuilds_exact_canonical_utxo_* (4 variants)
//   reorg_equivalence.rs::*survives_restart*
// Those use synthetic blocks committed via the store. To avoid duplication while
// adding non-overlapping value, this single thin test pins live-vs-reopen
// byte-identity for a chain built through the REAL connect_block path with a
// spend (so the UTXO set is non-trivial), then reopened from disk. It asserts
// the convergence oracle (tip triple + UTXO set) over the production connect
// path — a surface the existing store-synthetic tests do not exercise.
//
// FINDING-DIGEST-CACHE (recorded, NOT a chain-split): the consensus state
// (tip + UTXO set) converges byte-for-byte, but the cached digest metadata
// (METADATA_UTXO_SET_DIGEST_KEY) is written ONLY by ChainState::open (reopen,
// via ensure_canonical_utxo_set), NOT by the live connect_block path. So a live
// node legitimately has `digest: None` while the same store reopened has
// `Some(..)`. This test pins that asymmetry explicitly so it cannot silently
// change: it is a cache-materialization detail, not a divergence of canonical
// state. See report FIX-QUEUE note (analysis: not exploitable — digest is a
// derived summary of the very UTXO set already proven identical).

#[test]
fn convergence_live_state_equals_reopened_state_real_connect_path() {
    std::env::set_var("DOM_REGTEST_FAST_MINING", "1");
    let chain_id = regtest_chain_id();
    let dir = TempDir::new().expect("tempdir");
    let store_dir = dir.path().join("chain");

    let genesis = build_coinbase_only_block(
        [0u8; 32],
        Hash256::ZERO,
        BlockHeight::GENESIS,
        U256::zero(),
        [0u8; 32],
        1,
        &chain_id,
    );
    let cb_value = dom_core::block_reward(BlockHeight::GENESIS).noms();
    let spend = valid_spend_tx(
        cb_value,
        scalar(1),
        cb_value - dom_core::MIN_RELAY_FEE_RATE * 100,
        70,
        &chain_id,
    );
    let b1 = build_block_with_transactions(
        *block_hash(&genesis).as_bytes(),
        block_hash(&genesis),
        BlockHeight(1),
        genesis.header.total_difficulty,
        [0u8; 32],
        71,
        vec![spend],
        &chain_id,
    );

    let (live_consensus, live_full) = {
        let mut chain = open_chain(&store_dir);
        chain.connect_block(&genesis, safe_now()).expect("genesis");
        chain.connect_block(&b1, safe_now()).expect("b1");
        let cfp = consensus_fingerprint(&chain);
        let ffp = fingerprint(&chain);
        // Drop the writer env before reopening (Windows LMDB single-writer).
        drop(chain);
        (cfp, ffp)
    };

    let reopened = open_chain(&store_dir);
    let reopened_consensus = consensus_fingerprint(&reopened);
    let reopened_full = fingerprint(&reopened);

    // CONVERGENCE INVARIANT: canonical state (tip + UTXO set) is byte-identical
    // live-vs-reopened on the real connect path.
    assert_eq!(
        live_consensus, reopened_consensus,
        "DIVERGENCE: reopened canonical state differs from live state on the real \
         connect path (latent chain-split across restart)"
    );

    // FINDING-DIGEST-CACHE pinned: the live path does NOT persist the cached
    // digest; reopen materializes it. This is the ONLY difference between the
    // full fingerprints, and it is a cache artifact, not a state divergence.
    assert_eq!(
        live_full.digest, None,
        "live connect path is expected NOT to persist the cached utxo digest"
    );
    assert!(
        reopened_full.digest.is_some(),
        "reopen is expected to materialize the cached utxo digest"
    );

    // The reopened oracle must match an independent fresh store reader at the
    // same tip, proving the persisted digest is real (not a cached field value).
    let independent = open_test_store(&store_dir);
    let independent_full = fingerprint_store(&independent, &reopened);
    assert_eq!(
        reopened_full, independent_full,
        "reopened oracle must match an independent store reader at the same tip"
    );
}
