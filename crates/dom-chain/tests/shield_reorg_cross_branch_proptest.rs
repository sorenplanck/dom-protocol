//! dom-shield FAMILY 2b — cross-branch reorg adversarial suite.
//!
//! This file covers reorg attack vectors that the existing dom-chain reorg
//! tests do NOT cover, and is deliberately scoped to avoid duplicating them:
//!
//!   * `reorg_equivalence.rs` — pure DAG walks (`find_common_ancestor`),
//!     `check_reorg_depth` boundary on the *pure function*, side-branch
//!     retention/pruning, and a single equivalence promotion.
//!   * `block_validation_ingress_adversarial.rs` (I2) — *within-branch*
//!     double-spend on the auto-reorg path (`connect_block`), and direct-
//!     connect replay/duplicate rejection.
//!   * `fork_choice_negative.rs` — strict-`>` fork-choice (equal-work sibling
//!     does not reorg).
//!
//! What is NEW here, by vector:
//!
//!   V1  CROSS-BRANCH double-spend: a UTXO created only on the *losing*
//!       (canonical) branch is referenced as an input by the *winning* side
//!       branch. After the reorg disconnects the losing branch, that output
//!       no longer exists, so the winning branch's spend MUST be rejected and
//!       the canonical tip MUST be left untouched. This is distinct from I2's
//!       within-branch double-spend (same input spent twice inside ONE branch).
//!
//!   V1b POSITIVE CONTROL: a UTXO from the *shared prefix*, spent on the
//!       losing branch, is legitimately re-spendable on the winning branch
//!       after the reorg resurrects it. Proves V1's rejection is specific, not
//!       a blanket "any spend on a promoted branch fails".
//!
//!   V2  reorg-depth cap (integrated path): drive a real reorg through the
//!       public `promote_heavier_known_tip` whose *disconnect* depth crosses
//!       MAX_REORG_DEPTH_POLICY, and leave the tip untouched on rejection. This
//!       is the END-TO-END path, not the pure-function boundary already pinned
//!       by `reorg_equivalence.rs::check_reorg_depth_boundary`. EVIDENCE: an
//!       over-cap reorg is refused EARLIER than `check_reorg_depth` — by the
//!       bounded `find_common_ancestor` walk (see V2-FIX019).
//!
//!   V2-FIX019 PROBE/DISSOLUTION: `promote_heavier_known_tip` calls
//!       `collect_branch_blocks` (an UNBOUNDED `while tip != ancestor` walk that
//!       materialises every block body into a Vec) for the disconnect branch
//!       BEFORE the depth cap is consulted (chain_state.rs:1076 collect, :1077
//!       check) — which on paper reads like an unbounded-allocation-before-cap
//!       bug. Execution DISSOLVES it: for an over-cap disconnect the prior
//!       `find_common_ancestor` (bounded to MAX_REORG_DEPTH_POLICY steps per
//!       side, reorg.rs) returns None first, so the unbounded collect is never
//!       reached and the load is bounded by the cap. VERDICT: NOT RED
//!       (confirmed-mitigated). See the test note for the full argument.
//!
//!   V3  CONVERGENCE proptest: two independent stores fed the SAME set of
//!       blocks in DIFFERENT (valid) orderings must reach an IDENTICAL final
//!       state — same canonical tip hash AND same UTXO-set digest. A reorg is
//!       path-independent; the heaviest tip and the UTXO set it implies must
//!       not depend on arrival order.
//!
//! Driving model. Like `reorg_equivalence.rs`, reorgs are driven through the
//! real public reorg API (`promote_heavier_known_tip`) after staging blocks
//! into the store. Canonical blocks go in via `commit_block` (a pure store
//! write — it performs NO consensus validation), side blocks via
//! `store_known_block`. The promotion path itself runs the real
//! `validate_block` over every CONNECT block, so any branch that must be
//! *promoted* (V1, V1b, V3) is built with real bulletproofs + signatures.
//! Branches that exist only to be *counted/walked* (V2 disconnect depth) use
//! cheap dummy proofs, because `collect_branch_blocks` + `check_reorg_depth`
//! run before any proof is ever inspected — confirmed by reading
//! chain_state.rs:1076-1093 and dom-store/src/db.rs::commit_block.

use blake2::digest::consts::U32;
use blake2::{Blake2b, Digest};
use dom_chain::ChainState;
use dom_consensus::block::{BlockHeader, ProofOfWork};
use dom_consensus::{
    compute_block_pmmr_roots, derive_chain_id, Block, CoinbaseKernel, CoinbaseTransaction,
    Transaction, TransactionInput, TransactionKernel, TransactionOutput,
};
use dom_core::{
    Amount, BlockHeight, DomError, Hash256, Timestamp, KERNEL_FEAT_COINBASE, KERNEL_FEAT_PLAIN,
    PROTOCOL_VERSION, TAG_KERNEL_MSG, TAG_KERNEL_MSG_COINBASE,
};
use dom_crypto::hash::blake2b_256_tagged;
use dom_crypto::keys::SecretKey;
use dom_crypto::pedersen::{BlindingFactor, Commitment};
use dom_crypto::schnorr_sign;
use dom_pow::CompactTarget;
use dom_serialization::DomSerialize;
use dom_store::utxo::UtxoEntry;
use dom_store::DomStore;
use primitive_types::U256;
use tempfile::TempDir;

mod common;
use common::{open_test_chain, open_test_store};

type UtxoBytes = ([u8; 33], Vec<u8>);
type SpentCommitment = [u8; 33];

// ----------------------------------------------------------------------------
// Builders. Re-implemented locally because Rust integration tests are separate
// crates and cannot share helpers; this mirrors the convention already used by
// reorg_equivalence.rs ("tests are the public contract").
// ----------------------------------------------------------------------------

fn block_hash(header: &BlockHeader) -> Hash256 {
    let bytes = header.to_bytes().expect("header serialise");
    type B2b256 = Blake2b<U32>;
    let mut h = B2b256::new();
    h.update(&bytes);
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&h.finalize());
    Hash256::from_bytes(arr)
}

fn blinding(seed: u8) -> BlindingFactor {
    let mut bytes = [0u8; 32];
    bytes[31] = seed.max(1);
    BlindingFactor::from_bytes(bytes).expect("deterministic blinding")
}

/// Wider blinding space than the single-byte `blinding`, so the V2 disconnect
/// branch can mint >1000 distinct commitments without collisions. Byte[29] is
/// pinned to a non-zero constant so this space can never collide with the
/// single-byte `blinding(seed)` space (which only ever touches byte[31]), in
/// particular the genesis coinbase blinding.
fn blinding_u16(seed: u16) -> BlindingFactor {
    let mut bytes = [0u8; 32];
    bytes[29] = 0xCC;
    bytes[30] = (seed >> 8) as u8;
    bytes[31] = (seed & 0xff) as u8;
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

/// Consensus-valid signed coinbase with a real range proof (slow; used only on
/// branches that get promoted and therefore run `validate_block`). The coinbase
/// claims `block_reward(height) + total_fees`, matching the consensus rule.
fn signed_coinbase_with_fees(
    height: BlockHeight,
    total_fees: u64,
    seed: u8,
) -> CoinbaseTransaction {
    let explicit_value = dom_core::block_reward(height).noms() + total_fees;
    let blinding = blinding(seed);
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
    let sig = schnorr_sign(&secret, msg.as_bytes(), &test_chain_id()).expect("coinbase sig");
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

fn signed_coinbase(height: BlockHeight, seed: u8) -> CoinbaseTransaction {
    signed_coinbase_with_fees(height, 0, seed)
}

/// Cheap coinbase with a DUMMY (non-valid) range proof. Used only for branches
/// that are walked/counted by `collect_branch_blocks` + `check_reorg_depth` and
/// never reach `validate_block`. `commit_block` performs no proof validation;
/// the only store constraint is a unique output commitment per block.
fn dummy_coinbase(height: BlockHeight, blinding: &BlindingFactor) -> CoinbaseTransaction {
    let reward = dom_core::block_reward(height).noms();
    let commitment = Commitment::commit(reward, blinding);
    let excess = Commitment::commit(0, blinding);
    CoinbaseTransaction {
        output: TransactionOutput {
            commitment,
            // A short, fixed, non-range-proof byte string. Serialises fine and
            // is never verified on this path.
            proof: vec![0xAB; 8],
        },
        kernel: CoinbaseKernel {
            features: KERNEL_FEAT_COINBASE,
            explicit_value: reward,
            excess,
            // Length-correct dummy signature (65 bytes); never verified here.
            excess_signature: [0u8; 65],
        },
        offset: [0u8; 32],
    }
}

/// Consensus-valid 1-in/1-out spend transaction (real proof + signature).
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
    let (proof, _) = dom_crypto::bp2_prove(output_value, &output_blinding).expect("tx proof");
    let excess = Commitment::commit(0, &kernel_blinding);
    let secret = SecretKey::from_bytes(kernel_blinding.as_bytes()).expect("kernel secret");
    let sig = schnorr_sign(&secret, &kernel_message(fee, 0), &test_chain_id()).expect("kernel sig");

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

fn assemble_block(
    prev_hash: Hash256,
    height: u64,
    total_difficulty: u64,
    nonce_seed: u64,
    coinbase: CoinbaseTransaction,
    transactions: Vec<Transaction>,
) -> Block {
    let (output_root, kernel_root, rangeproof_root) =
        compute_block_pmmr_roots(&coinbase, &transactions).expect("pmmr roots");
    Block {
        header: BlockHeader {
            version: PROTOCOL_VERSION,
            height: BlockHeight(height),
            prev_hash,
            timestamp: Timestamp(1_700_300_000 + height),
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
    assemble_block(
        prev_hash,
        height,
        total_difficulty,
        nonce_seed,
        signed_coinbase(BlockHeight(height), coinbase_seed),
        vec![],
    )
}

fn valid_block_with_txs(
    prev_hash: Hash256,
    height: u64,
    total_difficulty: u64,
    nonce_seed: u64,
    coinbase_seed: u8,
    transactions: Vec<Transaction>,
) -> Block {
    let total_fees = transactions
        .iter()
        .map(|tx| tx.total_fee().expect("fee"))
        .sum();
    assemble_block(
        prev_hash,
        height,
        total_difficulty,
        nonce_seed,
        signed_coinbase_with_fees(BlockHeight(height), total_fees, coinbase_seed),
        transactions,
    )
}

fn dummy_coinbase_only_block(
    prev_hash: Hash256,
    height: u64,
    total_difficulty: u64,
    nonce_seed: u64,
    blinding: &BlindingFactor,
) -> Block {
    assemble_block(
        prev_hash,
        height,
        total_difficulty,
        nonce_seed,
        dummy_coinbase(BlockHeight(height), blinding),
        vec![],
    )
}

// ----------------------------------------------------------------------------
// Store staging.
// ----------------------------------------------------------------------------

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

/// Build a genesis block. NOTE: `bp2_prove` is non-deterministic (random
/// nonces, see dom-crypto bulletproof_bp.rs::prove_raw), so two builds of the
/// "same" logical block have DIFFERENT proof bytes. Tests that compare UTXO
/// state across runs must build the block ONCE and replay its bytes (see V3).
fn build_genesis() -> Block {
    valid_coinbase_only_block(Hash256::ZERO, 0, 1, 0xA0, 0xE0)
}

fn commit_genesis(store: &DomStore) {
    commit_canonical_block(store, &build_genesis());
}

fn commit_canonical_block(store: &DomStore, block: &Block) -> Hash256 {
    let hash = block_hash(&block.header);
    let (new_utxos, spent_utxos) = block_state_changes(block);
    store
        .commit_block(
            hash.as_bytes(),
            block.header.height.0,
            &block.header.to_bytes().expect("header serialise"),
            &block.to_bytes().expect("block serialise"),
            &new_utxos,
            &spent_utxos,
            &kernel_excesses(block, hash),
        )
        .expect("commit canonical block");
    hash
}

fn store_side_block(store: &DomStore, block: &Block) -> Hash256 {
    let hash = block_hash(&block.header);
    store
        .store_known_block(
            hash.as_bytes(),
            &block.header.to_bytes().expect("header serialise"),
            &block.to_bytes().expect("block serialise"),
        )
        .expect("store side block");
    hash
}

fn open_chain(dir: &std::path::Path) -> ChainState {
    open_test_chain(
        dir,
        Hash256::from_bytes(dom_core::GENESIS_HASH_REGTEST),
        dom_core::NETWORK_MAGIC_REGTEST,
    )
    .expect("chain open")
}

/// Deterministic digest over the entire persisted UTXO set (commitment + entry
/// bytes), used as the convergence equality witness in V3.
fn utxo_digest(chain: &ChainState) -> [u8; 32] {
    let utxos = chain.store.read_all_utxos_raw().expect("read all utxos");
    type B2b256 = Blake2b<U32>;
    let mut h = B2b256::new();
    // BTreeMap iterates in key order → deterministic regardless of insert order.
    for (k, v) in &utxos {
        h.update((k.len() as u64).to_le_bytes());
        h.update(k);
        h.update((v.len() as u64).to_le_bytes());
        h.update(v);
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&h.finalize());
    out
}

// ============================================================================
// V1 — CROSS-BRANCH double-spend rejection.
// ============================================================================
//
// Topology (heights):
//
//   genesis(0) → shared(1) ─┬─ A2 (canonical, spends shared coinbase → Oa)
//                           │
//                           └─ B2 (side) → B3 (side, spends Oa) → heavier tip
//
// `Oa` is produced ONLY on branch A. Branch B never created it. When B is
// promoted, A is disconnected first (apply_disconnect removes Oa from the
// overlay), so B3's input lookup for Oa hits None → REJECTED. The canonical
// tip must remain A2.
#[test]
fn cross_branch_spend_of_disconnected_only_output_is_rejected() {
    let dir = TempDir::new().expect("tempdir");
    let store = open_test_store(dir.path());
    commit_genesis(&store);

    // Shared prefix: one block whose coinbase is the spendable UTXO `U`.
    let shared = valid_coinbase_only_block(Hash256::ZERO, 1, 1, 1, 10);
    let shared_hash = commit_canonical_block(&store, &shared);
    let u_value = dom_core::block_reward(BlockHeight(1)).noms();
    let u_blinding = blinding(10);

    // Canonical branch A: A2 spends U → produces output Oa.
    let a_spend = valid_spend_tx(u_value, u_blinding.clone(), u_value - 100, 41);
    let oa_commitment = *a_spend.outputs[0].commitment.as_bytes();
    // Reconstruct Oa's blinding so B3 can attempt to spend it.
    let oa_blinding = u_blinding.add(&blinding(41)).expect("oa blinding");
    let oa_value = u_value - 100;
    let a2 = valid_block_with_txs(shared_hash, 2, 2, 2, 11, vec![a_spend]);
    commit_canonical_block(&store, &a2);

    // Side branch B: B2 (coinbase only), B3 spends Oa — an output that exists
    // ONLY on the canonical branch A. Make B heavier (total_difficulty 3>2).
    let b2 = valid_coinbase_only_block(shared_hash, 2, 2, 20, 30);
    let b2_hash = store_side_block(&store, &b2);
    let b3_spend = valid_spend_tx(oa_value, oa_blinding, oa_value - 100, 42);
    let b3 = valid_block_with_txs(b2_hash, 3, 3, 21, 31, vec![b3_spend]);
    let b3_hash = store_side_block(&store, &b3);

    let mut chain = open_chain(dir.path());
    let canonical_tip = chain.tip_hash;
    assert_eq!(canonical_tip, block_hash(&a2.header), "A2 is canonical tip");

    let err = chain
        .promote_heavier_known_tip(b3_hash)
        .expect_err("promoting a branch that spends a disconnected-only output must fail");
    let msg = err.to_string();
    assert!(
        msg.contains("missing input commitment") && msg.contains(&hex::encode(oa_commitment)),
        "expected cross-branch missing-input rejection naming Oa, got: {msg}"
    );

    // Fail-closed: the rejected reorg must leave canonical state untouched.
    assert_eq!(
        chain.tip_hash, canonical_tip,
        "rejected cross-branch reorg must not move the tip"
    );
    assert_eq!(chain.tip_height, BlockHeight(2));
    assert!(
        chain.store.get_utxo(&oa_commitment).unwrap().is_some(),
        "canonical Oa must still be present after the rejected reorg"
    );
}

// ============================================================================
// V1b — POSITIVE CONTROL: shared-prefix UTXO is re-spendable post-reorg.
// ============================================================================
//
// Same fork point, but branch B spends `U` itself (the shared coinbase),
// not an A-only output. After A is disconnected, U is resurrected, so B's
// spend is legitimate and the promotion MUST succeed. This proves V1's
// rejection is specific to disconnected-only outputs.
#[test]
fn cross_branch_respend_of_shared_prefix_utxo_succeeds() {
    let dir = TempDir::new().expect("tempdir");
    let store = open_test_store(dir.path());
    commit_genesis(&store);

    let shared = valid_coinbase_only_block(Hash256::ZERO, 1, 1, 1, 10);
    let shared_hash = commit_canonical_block(&store, &shared);
    let u_value = dom_core::block_reward(BlockHeight(1)).noms();
    let u_blinding = blinding(10);
    let u_commitment = *shared.coinbase.output.commitment.as_bytes();

    // Canonical A2 spends U → Oa.
    let a_spend = valid_spend_tx(u_value, u_blinding.clone(), u_value - 100, 41);
    let oa_commitment = *a_spend.outputs[0].commitment.as_bytes();
    let a2 = valid_block_with_txs(shared_hash, 2, 2, 2, 11, vec![a_spend]);
    commit_canonical_block(&store, &a2);

    // Side B2 coinbase, B3 spends U (the shared coinbase) with a DIFFERENT
    // kernel seed → different output Ob. B heavier.
    let b2 = valid_coinbase_only_block(shared_hash, 2, 2, 20, 30);
    let b2_hash = store_side_block(&store, &b2);
    let b3_spend = valid_spend_tx(u_value, u_blinding, u_value - 200, 50);
    let ob_commitment = *b3_spend.outputs[0].commitment.as_bytes();
    let b3 = valid_block_with_txs(b2_hash, 3, 3, 21, 31, vec![b3_spend]);
    let b3_hash = store_side_block(&store, &b3);

    let mut chain = open_chain(dir.path());
    chain
        .promote_heavier_known_tip(b3_hash)
        .expect("legitimate re-spend of resurrected shared UTXO must promote");

    assert_eq!(chain.tip_hash, b3_hash);
    assert_eq!(chain.tip_height, BlockHeight(3));
    // U is consumed on the winning branch.
    assert!(chain.store.get_utxo(&u_commitment).unwrap().is_none());
    // Oa (A-only output) is gone with the disconnected branch.
    assert!(chain.store.get_utxo(&oa_commitment).unwrap().is_none());
    // Ob (the winning branch's spend output) is present.
    assert!(chain.store.get_utxo(&ob_commitment).unwrap().is_some());
}

// ============================================================================
// V2 — reorg-depth cap on the integrated promotion path.
// ============================================================================

const POLICY: u64 = dom_core::MAX_REORG_DEPTH_POLICY; // 1000

/// Stage a canonical chain `genesis → shared(1) → c(2..=tip_height)` using
/// cheap dummy coinbases. Returns (the prebuilt heavier side block attached at
/// `shared`, expected_disconnect_depth). The side block is NOT stored here: at
/// over-cap disconnect depths `prune_retained_side_chains` (run on every
/// `open_chain`) DELETES a side tip whose disconnect depth exceeds
/// MAX_RETAINED_SIDE_BRANCH_REORG_DEPTH, so it would vanish before promotion.
/// Tests stage it directly through the open chain's store, then promote in the
/// same handle (promotion prunes only AFTER the depth check — chain_state.rs
/// :1077 check, :1175 prune).
///
/// disconnect_depth = canonical_tip_height - ancestor_height
///                  = tip_height - 1   (ancestor is `shared` at height 1)
fn stage_depth_fixture(dir: &TempDir, canonical_tip_height: u64) -> (Block, u64) {
    let store = open_test_store(dir.path());
    commit_genesis(&store);

    let shared = dummy_coinbase_only_block(Hash256::ZERO, 1, 1, 1, &blinding_u16(1));
    let shared_hash = commit_canonical_block(&store, &shared);

    let mut prev = shared_hash;
    for h in 2..=canonical_tip_height {
        // total_difficulty grows by 1 per block: canonical tip has td == h.
        let block = dummy_coinbase_only_block(prev, h, h, 1000 + h, &blinding_u16(h as u16 + 2));
        prev = commit_canonical_block(&store, &block);
    }
    drop(store);

    // Heavier 1-block side tip attached at `shared`: heavier than the entire
    // canonical chain so it is a valid reorg *target* (passes the
    // heavier-than-tip gate and the common-ancestor walk). Dummy coinbase
    // because the depth check fires before `validate_block` is reached when
    // over-limit.
    let side_td = canonical_tip_height + 10_000;
    let side = dummy_coinbase_only_block(shared_hash, 2, side_td, 9_999, &blinding_u16(0xFFFF));
    let disconnect_depth = canonical_tip_height - 1;
    (side, disconnect_depth)
}

/// Stage the side block directly into an opened chain's store (bypassing the
/// open-time retention prune that would drop an over-cap side tip), returning
/// its hash.
fn stage_side_into_open_chain(chain: &ChainState, side: &Block) -> Hash256 {
    store_side_block(&chain.store, side)
}

/// OVER-LIMIT: a disconnect depth of POLICY + 1 must be rejected by the
/// integrated promotion path, leaving the canonical tip untouched.
///
/// EVIDENCE-BASED OUTCOME (discovered by execution, see FIX-019 probe below):
/// the over-cap reorg is NOT rejected by `check_reorg_depth` (the explicit
/// depth cap at chain_state.rs:1077). It is rejected EARLIER, by
/// `find_common_ancestor` (reorg.rs), whose backward walk is itself bounded to
/// MAX_REORG_DEPTH_POLICY steps from each side. When the common ancestor lies
/// deeper than the cap, that walk returns None and `promote_heavier_known_tip`
/// fails at chain_state.rs:1057-1059 with "no common ancestor" — BEFORE the
/// unbounded `collect_branch_blocks` at :1076 is ever reached. Either way the
/// over-deep reorg is refused and the tip is preserved; we assert the actual
/// failing layer rather than the one the cap *would* have produced.
#[test]
fn reorg_depth_over_limit_is_rejected_on_promotion_path() {
    // canonical_tip_height = POLICY + 2 → disconnect_depth = POLICY + 1.
    let dir = TempDir::new().expect("tempdir");
    let (side, disconnect_depth) = stage_depth_fixture(&dir, POLICY + 2);
    assert_eq!(disconnect_depth, POLICY + 1, "fixture is one over the cap");

    let mut chain = open_chain(dir.path());
    let canonical_tip = chain.tip_hash;
    let canonical_height = chain.tip_height;
    let side_hash = stage_side_into_open_chain(&chain, &side);

    let err = chain
        .promote_heavier_known_tip(side_hash)
        .expect_err("disconnect depth over MAX_REORG_DEPTH_POLICY must be rejected");
    let msg = err.to_string();
    // The reorg is refused because the ancestor is deeper than the bounded
    // ancestor walk can reach. (It does NOT reach the explicit depth cap.)
    assert!(
        msg.contains("no common ancestor"),
        "expected over-cap reorg to be refused by the bounded ancestor walk, got: {msg}"
    );
    assert!(
        !msg.contains("exceeds MAX_REORG_DEPTH_POLICY"),
        "the explicit depth cap is unreachable for >POLICY: find_common_ancestor \
         refuses first; got: {msg}"
    );

    assert_eq!(
        chain.tip_hash, canonical_tip,
        "rejected over-deep reorg must not move the tip"
    );
    assert_eq!(chain.tip_height, canonical_height);
}

/// AT-LIMIT: disconnect depth = POLICY must pass `check_reorg_depth`. The
/// fixture's side tip carries a dummy proof, so once the depth gate passes the
/// promotion proceeds into `validate_block` and is rejected there for a
/// DIFFERENT reason (invalid range proof) — NOT for depth. We assert the
/// failure is NOT the depth-cap message, which proves the cap admitted exactly
/// POLICY. (Building a consensus-valid 1000-deep canonical chain with real
/// proofs would cost ~100s+; out of scope for a fast shield test. The cap
/// boundary is what this vector targets.)
#[test]
fn reorg_depth_at_limit_passes_depth_gate() {
    // canonical_tip_height = POLICY + 1 → disconnect_depth = POLICY (at cap).
    let dir = TempDir::new().expect("tempdir");
    let (side, disconnect_depth) = stage_depth_fixture(&dir, POLICY + 1);
    assert_eq!(disconnect_depth, POLICY, "fixture is exactly at the cap");

    let mut chain = open_chain(dir.path());
    let canonical_tip = chain.tip_hash;
    let side_hash = stage_side_into_open_chain(&chain, &side);

    let result = chain.promote_heavier_known_tip(side_hash);
    match result {
        Ok(_) => panic!("dummy-proof side tip should not validate; expected post-gate failure"),
        Err(e) => {
            let msg = e.to_string();
            assert!(
                !msg.contains("exceeds MAX_REORG_DEPTH_POLICY"),
                "at-limit depth must pass the cap; failure must be post-gate, got: {msg}"
            );
            // It must be a block-validation failure (the depth gate let it
            // through to validate_block, where the dummy proof is rejected).
            assert!(
                msg.contains("reorg candidate block validation failed"),
                "expected post-gate validation failure, got: {msg}"
            );
        }
    }
    // Either outcome, the tip must not have moved (validation failed before
    // apply_reorg).
    assert_eq!(chain.tip_hash, canonical_tip);
}

/// V2-FIX019 PROBE / DISSOLUTION — is the unbounded `collect_branch_blocks`
/// load over an over-cap disconnect branch reachable BEFORE the depth cap?
///
/// The FIX-019 concern reads, statically, like a real ordering bug:
/// chain_state.rs:1076 collects the ENTIRE disconnect branch into a Vec via
/// `collect_branch_blocks` (a `while tip != ancestor` walk with NO depth
/// bound), and ONLY THEN, at :1077, calls `check_reorg_depth(len)`. Taken in
/// isolation, that means the cap rejects AFTER an unbounded allocation.
///
/// EXECUTION DISSOLVES IT. With a real over-cap disconnect depth (POLICY + 1),
/// `promote_heavier_known_tip` never reaches :1076. It fails earlier, at
/// :1057-1059, with "heavier side chain has no common ancestor", because
/// `find_common_ancestor` (reorg.rs) walks each side for AT MOST
/// MAX_REORG_DEPTH_POLICY (+1) steps. When the true common ancestor lies deeper
/// than that bound, the walk simply does not find it and returns None. So:
///
///   * the unbounded `collect_branch_blocks` is GATED behind a bounded ancestor
///     walk — it can only run for disconnect depths the walk can reach
///     (<= POLICY), i.e. the load is bounded by MAX_REORG_DEPTH_POLICY by
///     construction;
///   * consequently `check_reorg_depth(> POLICY)` is effectively DEAD on this
///     path: a count greater than POLICY can never be produced, because the
///     ancestor for such a depth is never found.
///
/// REACHABILITY, additionally: an over-cap side tip is not even retainable.
/// `prune_retained_side_chains` (chain_state.rs:1776), run on EVERY
/// `open_chain`, DROPS any side tip whose disconnect depth exceeds
/// MAX_RETAINED_SIDE_BRANCH_REORG_DEPTH (== MAX_REORG_DEPTH_POLICY). This test
/// has to inject the side header directly into the store AFTER open to even
/// attempt the promotion; a node would never auto-select it.
///
/// VERDICT: NOT RED. The unbounded-load-before-cap reading is real on paper but
/// unreachable in execution: the bounded `find_common_ancestor` refuses the
/// over-cap reorg first, so the disconnect-branch materialisation is bounded by
/// MAX_REORG_DEPTH_POLICY. No attacker-controlled unbounded allocation exists on
/// this path. (FIX-019 is confirmed-mitigated, not a live defect.)
#[test]
fn fix019_over_cap_disconnect_is_refused_before_unbounded_collect_probe() {
    let dir = TempDir::new().expect("tempdir");
    let (side, disconnect_depth) = stage_depth_fixture(&dir, POLICY + 2);
    assert_eq!(disconnect_depth, POLICY + 1);

    let mut chain = open_chain(dir.path());
    let canonical_tip = chain.tip_hash;
    // Bounded by construction: the disconnect depth equals our own accepted
    // canonical height minus the ancestor (h=1), not an attacker-chosen number.
    assert_eq!(disconnect_depth, chain.tip_height.0 - 1);

    let side_hash = stage_side_into_open_chain(&chain, &side);

    let err = chain
        .promote_heavier_known_tip(side_hash)
        .expect_err("over-cap disconnect must be refused");
    let msg = err.to_string();

    // The refusal comes from the BOUNDED ancestor walk, BEFORE the unbounded
    // `collect_branch_blocks` at :1076 and before `check_reorg_depth` at :1077.
    // This is the execution proof that the unbounded load is gated by the cap.
    assert!(
        msg.contains("no common ancestor"),
        "over-cap reorg must be refused by find_common_ancestor's bounded walk, got: {msg}"
    );
    assert!(
        !msg.contains("exceeds MAX_REORG_DEPTH_POLICY"),
        "check_reorg_depth(>POLICY) is unreachable: the ancestor walk refuses first; got: {msg}"
    );
    // Fail-closed: tip untouched.
    assert_eq!(chain.tip_hash, canonical_tip);
}

// ============================================================================
// V3 — CONVERGENCE proptest: order-independence of reorg outcome.
// ============================================================================
//
// Build a shared prefix + two competing branches once. Feed BOTH branches'
// blocks to two fresh chains in two DIFFERENT valid orderings (canonical-first
// then promote, vs. side-first staged then promote). Both must reach the SAME
// canonical tip AND the SAME UTXO digest.
//
// To keep proptest fast under the 110ms/bulletproof cost, branch widths/depths
// are bounded small and the case count is capped.

use proptest::prelude::*;

/// One reorg scenario: a shared coinbase at height 1, a canonical branch of
/// `a_len` coinbase-only blocks, and a heavier side branch of `b_len`
/// coinbase-only blocks. Returns the two chains' final (tip, utxo_digest).
fn run_scenario_two_orderings(
    a_len: u64,
    b_len: u64,
) -> Result<((Hash256, [u8; 32]), (Hash256, [u8; 32])), DomError> {
    // Build EVERY block (incl. genesis) exactly once, then replay the SAME
    // serialized bytes into both stores. This is mandatory: `bp2_prove` uses
    // random nonces (dom-crypto bulletproof_bp.rs::prove_raw), so re-building a
    // logically-identical block yields different proof bytes and would make the
    // UTXO digest differ for a reason that has nothing to do with reorg
    // path-(in)dependence. (Verified during construction: re-calling
    // `commit_genesis` per ordering diverged ONLY in the genesis coinbase proof
    // bytes — a test artifact, not a chain bug.)
    let genesis = build_genesis();
    let shared = valid_coinbase_only_block(Hash256::ZERO, 1, 1, 1, 10);
    let shared_hash = block_hash(&shared.header);

    // Canonical branch A: heights 2..=1+a_len, td 2..=1+a_len.
    let mut a_blocks = Vec::new();
    let mut prev = shared_hash;
    for i in 0..a_len {
        let h = 2 + i;
        let blk = valid_coinbase_only_block(prev, h, h, 100 + i, 30 + i as u8);
        prev = block_hash(&blk.header);
        a_blocks.push(blk);
    }

    // Side branch B: heights 2..=1+b_len, made strictly heavier than A's tip
    // by giving every B block a higher total_difficulty.
    let a_tip_td = 1 + a_len; // td of A's tip
    let mut b_blocks = Vec::new();
    let mut prev = shared_hash;
    for i in 0..b_len {
        let h = 2 + i;
        let td = a_tip_td + 1 + i; // strictly increasing and > A's tip
        let blk = valid_coinbase_only_block(prev, h, td, 5_000 + i, 80 + i as u8);
        prev = block_hash(&blk.header);
        b_blocks.push(blk);
    }
    let b_tip_hash = block_hash(&b_blocks.last().unwrap().header);

    // --- Ordering 1: commit A as canonical, stage B as side, then promote B.
    let final_1 = {
        let dir = TempDir::new().expect("tempdir");
        let store = open_test_store(dir.path());
        commit_canonical_block(&store, &genesis);
        commit_canonical_block(&store, &shared);
        for blk in &a_blocks {
            commit_canonical_block(&store, blk);
        }
        for blk in &b_blocks {
            store_side_block(&store, blk);
        }
        drop(store);
        let mut chain = open_chain(dir.path());
        chain.promote_heavier_known_tip(b_tip_hash)?;
        (chain.tip_hash, utxo_digest(&chain))
    };

    // --- Ordering 2: commit B as canonical FIRST (it is heavier), then stage A
    // as side. A is lighter, so no reorg happens — B stays canonical. This is
    // the same heaviest-tip outcome reached by a different arrival order.
    let final_2 = {
        let dir = TempDir::new().expect("tempdir");
        let store = open_test_store(dir.path());
        commit_canonical_block(&store, &genesis);
        commit_canonical_block(&store, &shared);
        for blk in &b_blocks {
            commit_canonical_block(&store, blk);
        }
        for blk in &a_blocks {
            store_side_block(&store, blk);
        }
        drop(store);
        let chain = open_chain(dir.path());
        // B is already the canonical (heaviest) tip; nothing to promote.
        (chain.tip_hash, utxo_digest(&chain))
    };

    Ok((final_1, final_2))
}

proptest! {
    #![proptest_config(ProptestConfig {
        // Bounded: each case stages up to ~6 blocks × 2 orderings, each
        // coinbase costing one ~110ms bulletproof. Keep case count small so
        // the whole test runs in seconds.
        cases: 12,
        ..ProptestConfig::default()
    })]

    /// Two valid arrival orderings that select the SAME heaviest tip must yield
    /// identical final canonical state (tip hash + UTXO digest). Reorg is
    /// path-independent.
    #[test]
    fn reorg_converges_to_identical_state_regardless_of_arrival_order(
        a_len in 1u64..=3,
        b_len in 1u64..=3,
    ) {
        // Require B strictly heavier-or-equal length is NOT required; B's td is
        // constructed to always exceed A's tip, so B is always the heaviest.
        let ((tip1, dig1), (tip2, dig2)) =
            run_scenario_two_orderings(a_len, b_len).expect("scenario must not error");

        prop_assert_eq!(tip1, tip2, "heaviest tip must not depend on arrival order");
        prop_assert_eq!(dig1, dig2, "UTXO digest must not depend on arrival order");
    }
}
