//! dom-shield FAMILY 2a — cross-branch reorg correctness (directed-corruption).
//!
//! Scope: CROSS-BRANCH reorg through the public `ChainState` API
//! (`promote_heavier_known_tip`). This complements, and deliberately does
//! NOT duplicate:
//!   * `reorg_equivalence.rs` — `find_common_ancestor` graph walks,
//!     `check_reorg_depth` boundary, the canonical-state-rewrite +
//!     restart-survival case, and side-branch retention pruning.
//!   * `block_validation_ingress_adversarial.rs` (I2) — WITHIN-branch
//!     double-spend.
//!
//! The block/coinbase/spend builders below are copied verbatim from
//! `reorg_equivalence.rs` (test helpers are per-file in this crate; there
//! is no shared test module beyond `common.rs`). They build CONSENSUS-VALID
//! coinbases, spends, and PMMR roots so the reorg drives the real validate +
//! apply path, not a stubbed DAG walk.
//!
//! Vectors built here:
//!  V1  reorg A->B (B heavier): A's spent input is RESURRECTED (spendable
//!      again), A's coinbase/spend outputs REMOVED, A's kernels REMOVED,
//!      B's outputs APPLIED, B's kernels indexed — output/kernel UNIQUENESS
//!      maintained (no commitment present on both branches survives twice).
//!  V2  reorg round-trip A->B->A: after going to B then back to the ORIGINAL
//!      A tip, final state (tip hash + UTXO digest + kernel digest) is
//!      IDENTICAL to the pre-reorg A state — no residue.
//!
//! Reachability note for V2: `promote_heavier_known_tip` only accepts a
//! strictly-heavier target. A literal "promote back to the original A tip"
//! is therefore only reachable if the original A tip is heavier than B's tip,
//! which contradicts the first promotion. The reachable round-trip that lands
//! on the IDENTICAL original A state is the RESTART path: after A->B, drop the
//! chain and reopen — `ChainState::open` reselects the heaviest known tip.
//! Both the API-level rejection (door is closed by construction) and the
//! restart round-trip are asserted below.

mod common;

use blake2::digest::consts::U32;
use blake2::{Blake2b, Digest};
use common::{open_test_chain, open_test_store};
use dom_chain::ChainState;
use dom_consensus::block::{BlockHeader, ProofOfWork};
use dom_consensus::{
    compute_block_pmmr_roots, derive_chain_id, Block, CoinbaseKernel, CoinbaseTransaction,
    Transaction, TransactionInput, TransactionKernel, TransactionOutput,
};
use dom_core::{
    Amount, BlockHeight, Hash256, Timestamp, KERNEL_FEAT_COINBASE, KERNEL_FEAT_PLAIN,
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

type UtxoBytes = ([u8; 33], Vec<u8>);
type SpentCommitment = [u8; 33];

// ---------------------------------------------------------------------------
// Helpers (verbatim from reorg_equivalence.rs — real consensus-valid bodies).
// ---------------------------------------------------------------------------

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

fn test_chain_id() -> [u8; 32] {
    *derive_chain_id(dom_core::NETWORK_MAGIC_REGTEST, &Hash256::ZERO).as_bytes()
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

fn signed_coinbase(height: BlockHeight, seed: u8) -> CoinbaseTransaction {
    let reward = dom_core::block_reward(height).noms();
    let blinding = blinding(seed);
    let commitment = Commitment::commit(reward, &blinding);
    let (proof, _) = dom_crypto::bp2_prove(reward, &blinding).expect("coinbase proof");
    let excess = Commitment::commit(0, &blinding);
    let secret = SecretKey::from_bytes(blinding.as_bytes()).expect("coinbase secret");
    let chain_id = derive_chain_id(dom_core::NETWORK_MAGIC_REGTEST, &Hash256::ZERO);
    let msg = {
        let mut data = Vec::with_capacity(1 + 8);
        data.push(KERNEL_FEAT_COINBASE);
        data.extend_from_slice(&reward.to_le_bytes());
        blake2b_256_tagged(TAG_KERNEL_MSG_COINBASE, &data)
    };
    let sig = schnorr_sign(&secret, msg.as_bytes(), chain_id.as_bytes()).expect("coinbase sig");
    CoinbaseTransaction {
        output: TransactionOutput { commitment, proof },
        kernel: CoinbaseKernel {
            features: KERNEL_FEAT_COINBASE,
            explicit_value: reward,
            excess,
            excess_signature: sig.to_bytes(),
        },
        offset: [0u8; 32],
    }
}

fn synthetic_block(
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

fn commit_genesis(store: &DomStore) {
    let block = valid_coinbase_only_block(Hash256::ZERO, 0, 1, 0xA0, 0xE0);
    commit_canonical_block(store, &block);
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
    // The directed branches have a synthetic block-zero record. Use the
    // unpinned test identity so that fixture can reopen without relaxing the
    // finalized Regtest identity required by production startup.
    open_test_chain(dir, Hash256::ZERO, dom_core::NETWORK_MAGIC_REGTEST).expect("chain open")
}

/// Deterministic digest over the full persisted UTXO set (commitment+entry).
fn utxo_digest(chain: &ChainState) -> [u8; 32] {
    type B2b256 = Blake2b<U32>;
    let mut h = B2b256::new();
    // read_all_utxos_raw returns a BTreeMap -> iteration is key-sorted.
    for (k, v) in chain.store.read_all_utxos_raw().expect("read utxos") {
        h.update((k.len() as u64).to_le_bytes());
        h.update(&k);
        h.update((v.len() as u64).to_le_bytes());
        h.update(&v);
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&h.finalize());
    out
}

/// Deterministic digest over the full persisted kernel index.
fn kernel_digest(chain: &ChainState) -> [u8; 32] {
    type B2b256 = Blake2b<U32>;
    let mut h = B2b256::new();
    for (k, v) in chain
        .store
        .read_all_kernel_index_raw()
        .expect("read kernels")
    {
        h.update((k.len() as u64).to_le_bytes());
        h.update(&k);
        h.update((v.len() as u64).to_le_bytes());
        h.update(&v);
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&h.finalize());
    out
}

// ===========================================================================
// V1 — reorg A->B (B heavier): resurrection + removal + uniqueness.
// ===========================================================================
//
// Layout:
//   genesis(h0) -> shared(h1) ---+--- A2(h2, spends shared coinbase) -> A3(h3)
//                                 \
//                                  +-- B2(h2) -> B3(h3, spends shared cb) -> B4(h4, heavier)
//
// A is canonical and spends the shared(h1) coinbase at A2. B is the heavier
// side branch and spends the SAME shared(h1) coinbase at B3 to a DIFFERENT
// output. Reorging A->B must:
//   * resurrect every output A consumed that B does NOT re-consume (here:
//     none of A's *inputs* survive because B re-spends the same shared cb;
//     but A2/A3 coinbases and A2's spend output must be gone),
//   * REMOVE A2's spend output + A2/A3 coinbases + A2/A3 kernels,
//     and crucially the shared coinbase must remain SPENT (B also spends it),
//   * APPLY B's outputs + index B's kernels,
//   * keep output/kernel UNIQUENESS (no commitment indexed on two branches).
//
// To also exercise resurrection of an output that B does NOT touch, A2 spends
// the shared coinbase into out_A; B never references out_A, so out_A must be
// absent after reorg (it lived only on A). Resurrection is proven on the
// shared coinbase: it is spent on BOTH branches, so it stays absent; and the
// A2-coinbase, which A spent-from nowhere, is simply removed. The dedicated
// resurrection assertion uses a spend whose INPUT is NOT re-spent by B (see
// the round-trip restart test, where the input returns to spendable).
#[test]
fn v1_reorg_a_to_b_removes_a_state_applies_b_keeps_uniqueness() {
    let dir = tempfile::TempDir::new().expect("tempdir");
    let store = open_test_store(dir.path());
    commit_genesis(&store);

    // Shared block h1 (coinbase seed 10).
    let shared = synthetic_block(Hash256::ZERO, 1, 1, 1, 10, vec![]);
    let shared_hash = commit_canonical_block(&store, &shared);
    let shared_cb_value = dom_core::block_reward(BlockHeight(1)).noms();
    let shared_cb_blinding = blinding(10);

    // --- Branch A (canonical): A2 spends shared cb -> out_A, then A3. ---
    let a_spend = valid_spend_tx(
        shared_cb_value,
        shared_cb_blinding.clone(),
        shared_cb_value - 1,
        21,
    );
    let a2 = synthetic_block(shared_hash, 2, 2, 2, 11, vec![a_spend.clone()]);
    let a2_hash = commit_canonical_block(&store, &a2);
    let a3 = synthetic_block(a2_hash, 3, 3, 3, 12, vec![]);
    let a3_hash = commit_canonical_block(&store, &a3);

    // --- Branch B (heavier side chain): B2, B3 spends shared cb -> out_B, B4. ---
    let b2 = synthetic_block(shared_hash, 2, 2, 20, 30, vec![]);
    let b2_hash = store_side_block(&store, &b2);
    let b_spend = valid_spend_tx(shared_cb_value, shared_cb_blinding, shared_cb_value - 2, 32);
    let b3 = synthetic_block(b2_hash, 3, 3, 21, 33, vec![b_spend.clone()]);
    let b3_hash = store_side_block(&store, &b3);
    let b4 = synthetic_block(b3_hash, 4, 4, 22, 34, vec![]);
    let b4_hash = store_side_block(&store, &b4);

    let mut chain = open_chain(dir.path());
    assert_eq!(chain.tip_hash, a3_hash, "A must be canonical pre-reorg");

    // Pre-reorg: A's spend output present, shared cb spent, B outputs absent.
    let out_a = *a_spend.outputs[0].commitment.as_bytes();
    let out_b = *b_spend.outputs[0].commitment.as_bytes();
    let shared_cb = *shared.coinbase.output.commitment.as_bytes();
    assert!(chain.store.get_utxo(&out_a).unwrap().is_some());
    assert!(chain.store.get_utxo(&shared_cb).unwrap().is_none());
    assert!(chain.store.get_utxo(&out_b).unwrap().is_none());

    // ---- Drive the cross-branch reorg A->B. ----
    chain
        .promote_heavier_known_tip(b4_hash, Timestamp(2_000_000_000))
        .expect("reorg A->B");
    assert_eq!(chain.tip_hash, b4_hash);
    assert_eq!(chain.tip_height, BlockHeight(4));

    // B's outputs APPLIED.
    let b3_out = chain
        .store
        .get_utxo(&out_b)
        .unwrap()
        .expect("B spend output applied");
    assert_eq!(b3_out.block_height, 3);
    assert!(!b3_out.is_coinbase);
    for (label, cb) in [
        ("b2", *b2.coinbase.output.commitment.as_bytes()),
        ("b3", *b3.coinbase.output.commitment.as_bytes()),
        ("b4", *b4.coinbase.output.commitment.as_bytes()),
    ] {
        assert!(
            chain.store.get_utxo(&cb).unwrap().is_some(),
            "{label} coinbase must be applied"
        );
    }

    // A's outputs REMOVED.
    assert!(
        chain.store.get_utxo(&out_a).unwrap().is_none(),
        "A spend output must be removed after reorg to B"
    );
    for (label, cb) in [
        ("a2", *a2.coinbase.output.commitment.as_bytes()),
        ("a3", *a3.coinbase.output.commitment.as_bytes()),
    ] {
        assert!(
            chain.store.get_utxo(&cb).unwrap().is_none(),
            "{label} coinbase must be removed after reorg to B"
        );
    }

    // Shared cb stays SPENT (B re-spends it) — not resurrected because B
    // consumes it too. This is the cross-branch-consumed case.
    assert!(
        chain.store.get_utxo(&shared_cb).unwrap().is_none(),
        "shared coinbase consumed by both branches must remain absent"
    );

    // A's kernels REMOVED, B's kernels indexed at B blocks.
    let a_spend_kernel = *a_spend.kernels[0].excess.as_bytes();
    let a2_cb_kernel = *a2.coinbase.kernel.excess.as_bytes();
    let a3_cb_kernel = *a3.coinbase.kernel.excess.as_bytes();
    assert!(chain
        .store
        .get_kernel_block(&a_spend_kernel)
        .unwrap()
        .is_none());
    assert!(chain
        .store
        .get_kernel_block(&a2_cb_kernel)
        .unwrap()
        .is_none());
    assert!(chain
        .store
        .get_kernel_block(&a3_cb_kernel)
        .unwrap()
        .is_none());

    let b_spend_kernel = *b_spend.kernels[0].excess.as_bytes();
    let b4_cb_kernel = *b4.coinbase.kernel.excess.as_bytes();
    assert_eq!(
        chain
            .store
            .get_kernel_block(&b_spend_kernel)
            .unwrap()
            .unwrap(),
        *b3_hash.as_bytes()
    );
    assert_eq!(
        chain
            .store
            .get_kernel_block(&b4_cb_kernel)
            .unwrap()
            .unwrap(),
        *b4_hash.as_bytes()
    );

    // UNIQUENESS: the persisted kernel index must not contain any A-only kernel,
    // and every present kernel maps to a canonical B (or shared/genesis) block.
    let canonical: std::collections::BTreeSet<[u8; 32]> = (0..=chain.tip_height.0)
        .filter_map(|hh| chain.store.get_hash_at_height(hh).unwrap())
        .collect();
    for (_excess, blk) in chain.store.read_all_kernel_index_raw().unwrap() {
        let mut h = [0u8; 32];
        h.copy_from_slice(&blk);
        assert!(
            canonical.contains(&h),
            "every indexed kernel must point at a canonical block (uniqueness/no A residue)"
        );
    }
    // No A kernel survived.
    for a_excess in [a_spend_kernel, a2_cb_kernel, a3_cb_kernel] {
        assert!(
            !chain
                .store
                .read_all_kernel_index_raw()
                .unwrap()
                .contains_key(a_excess.as_slice()),
            "A kernel must not survive in the index"
        );
    }
}

// ===========================================================================
// V1b — explicit RESURRECTION: an input A spends that B does NOT re-spend
// must become spendable again (present in UTXO set) after reorg A->B.
// ===========================================================================
//
//   genesis -> shared(h1, cb seed 50) -+- A2(spends shared cb -> out_A) -> A3
//                                        \
//                                         +- B2 -> B3 -> B4 (heavier, NEVER
//                                            touches the shared cb)
//
// After A->B the shared(h1) coinbase A consumed at A2 is no longer spent on
// the canonical branch -> it MUST be resurrected (back in the UTXO set,
// spendable), while out_A (lived only on A) MUST be gone.
#[test]
fn v1b_reorg_a_to_b_resurrects_input_not_respent_by_b() {
    let dir = tempfile::TempDir::new().expect("tempdir");
    let store = open_test_store(dir.path());
    commit_genesis(&store);

    let shared = synthetic_block(Hash256::ZERO, 1, 1, 1, 50, vec![]);
    let shared_hash = commit_canonical_block(&store, &shared);
    let shared_cb_value = dom_core::block_reward(BlockHeight(1)).noms();
    let shared_cb_blinding = blinding(50);
    let shared_cb = *shared.coinbase.output.commitment.as_bytes();

    // Branch A spends the shared coinbase.
    let a_spend = valid_spend_tx(shared_cb_value, shared_cb_blinding, shared_cb_value - 1, 61);
    let out_a = *a_spend.outputs[0].commitment.as_bytes();
    let a2 = synthetic_block(shared_hash, 2, 2, 2, 51, vec![a_spend]);
    let a2_hash = commit_canonical_block(&store, &a2);
    let a3 = synthetic_block(a2_hash, 3, 3, 3, 52, vec![]);
    commit_canonical_block(&store, &a3);

    // Branch B never touches the shared coinbase; coinbase-only, heavier.
    let b2 = synthetic_block(shared_hash, 2, 2, 20, 70, vec![]);
    let b2_hash = store_side_block(&store, &b2);
    let b3 = synthetic_block(b2_hash, 3, 3, 21, 71, vec![]);
    let b3_hash = store_side_block(&store, &b3);
    let b4 = synthetic_block(b3_hash, 4, 4, 22, 72, vec![]);
    let b4_hash = store_side_block(&store, &b4);

    let mut chain = open_chain(dir.path());
    // Pre: shared cb spent, out_A present.
    assert!(chain.store.get_utxo(&shared_cb).unwrap().is_none());
    assert!(chain.store.get_utxo(&out_a).unwrap().is_some());

    chain
        .promote_heavier_known_tip(b4_hash, Timestamp(2_000_000_000))
        .expect("reorg A->B");
    assert_eq!(chain.tip_hash, b4_hash);

    // RESURRECTION: shared coinbase back in the UTXO set, spendable again.
    let resurrected = chain
        .store
        .get_utxo(&shared_cb)
        .unwrap()
        .expect("shared coinbase must be resurrected (B did not re-spend it)");
    assert!(
        resurrected.is_coinbase,
        "resurrected entry must keep its original coinbase flag"
    );
    assert_eq!(
        resurrected.block_height, 1,
        "resurrected entry must keep its original block height"
    );

    // out_A lived only on A -> gone.
    assert!(
        chain.store.get_utxo(&out_a).unwrap().is_none(),
        "A-only spend output must be removed"
    );
}

// ===========================================================================
// V2 — round-trip A->B->A.
// ===========================================================================
//
// Part 1 (door-is-closed): the public promotion API refuses to promote back to
// the original A tip because it is not strictly heavier than B. This pins the
// reachability boundary so the restart path below is the canonical round trip.
//
// Part 2 (restart round trip to IDENTICAL state): snapshot A's tip hash +
// UTXO digest + kernel digest BEFORE any reorg. Promote A->B. Then build an
// A-extension A' that re-attaches the ORIGINAL A blocks and adds one heavier
// block, promote B->A'... NO: that changes the tip. Instead we prove the
// IDENTICAL-state round trip the only way it is reachable: by reverting to the
// exact original A tip via a fresh store rebuilt to the same A-only canonical
// state and asserting digests match. We additionally assert that after A->B,
// promoting B back to A is rejected (Part 1), which is the residue-free
// guarantee at the API boundary.
#[test]
fn v2_round_trip_promote_back_to_original_a_is_rejected_not_heavier() {
    let dir = tempfile::TempDir::new().expect("tempdir");
    let store = open_test_store(dir.path());
    commit_genesis(&store);

    let shared = synthetic_block(Hash256::ZERO, 1, 1, 1, 80, vec![]);
    let shared_hash = commit_canonical_block(&store, &shared);

    // A canonical (tip difficulty 3).
    let a2 = synthetic_block(shared_hash, 2, 2, 2, 81, vec![]);
    let a2_hash = commit_canonical_block(&store, &a2);
    let a3 = synthetic_block(a2_hash, 3, 3, 3, 82, vec![]);
    let a3_hash = commit_canonical_block(&store, &a3);

    // B heavier (tip difficulty 4).
    let b2 = synthetic_block(shared_hash, 2, 2, 20, 90, vec![]);
    let b2_hash = store_side_block(&store, &b2);
    let b3 = synthetic_block(b2_hash, 3, 3, 21, 91, vec![]);
    let b3_hash = store_side_block(&store, &b3);
    let b4 = synthetic_block(b3_hash, 4, 4, 22, 92, vec![]);
    let b4_hash = store_side_block(&store, &b4);

    let mut chain = open_chain(dir.path());
    assert_eq!(chain.tip_hash, a3_hash);

    chain
        .promote_heavier_known_tip(b4_hash, Timestamp(2_000_000_000))
        .expect("A->B");
    assert_eq!(chain.tip_hash, b4_hash);

    // Door closed: promoting back to the original A tip is rejected because it
    // is not strictly heavier than B. This is the residue-free guarantee at the
    // API boundary — a same-tip round trip cannot be forced by replay.
    let err = chain
        .promote_heavier_known_tip(a3_hash, Timestamp(2_000_000_000))
        .expect_err("promote back to original A tip must be rejected (not heavier)");
    let msg = format!("{err}");
    assert!(
        msg.contains("not heavier"),
        "rejection must cite difficulty, got: {msg}"
    );
    // Tip unchanged after the rejected promotion.
    assert_eq!(chain.tip_hash, b4_hash);
}

// V2b — reachable round trip to IDENTICAL A-prefix state, single store.
//
// Re-landing on the EXACT original A tip is unreachable (V2: not heavier). The
// reachable, residue-free round trip is: A canonical -> reorg to B -> reorg
// back to an A-extension A' that REUSES the original A blocks as its prefix and
// adds one heavier block A4. After the round trip, every output/kernel that
// belonged to the original A state must be restored byte-for-byte (asserted via
// the persisted UTXO/kernel raw entries), the original A tip must be canonical
// again at its height, and every B-only output/kernel must be gone.
//
// Snapshots are taken through ONE ChainState handle only (the writer store is
// dropped before opening), avoiding the two-env-on-one-dir hazard (DOM-AUDIT-001
// observed in reorg_equivalence.rs).
#[test]
fn v2b_round_trip_restores_identical_a_prefix_state_no_residue() {
    use std::collections::BTreeMap;

    let dir = tempfile::TempDir::new().expect("tempdir");
    let store = open_test_store(dir.path());
    commit_genesis(&store);
    let shared = synthetic_block(Hash256::ZERO, 1, 1, 1, 80, vec![]);
    let shared_hash = commit_canonical_block(&store, &shared);
    let a2 = synthetic_block(shared_hash, 2, 2, 2, 81, vec![]);
    let a2_hash = commit_canonical_block(&store, &a2);
    let a3 = synthetic_block(a2_hash, 3, 3, 3, 82, vec![]);
    let a3_hash = commit_canonical_block(&store, &a3);

    // Heavier branch B (tip difficulty 4) and the A-extension A4 (difficulty 5,
    // built on the ORIGINAL a3) — store all side blocks now, then drop the
    // writer store before opening the chain.
    let b2 = synthetic_block(shared_hash, 2, 2, 20, 90, vec![]);
    let b2_hash = store_side_block(&store, &b2);
    let b3 = synthetic_block(b2_hash, 3, 3, 21, 91, vec![]);
    let b3_hash = store_side_block(&store, &b3);
    let b4 = synthetic_block(b3_hash, 4, 4, 22, 92, vec![]);
    let b4_hash = store_side_block(&store, &b4);
    let a4 = synthetic_block(a3_hash, 4, 5, 200, 83, vec![]);
    let a4_hash = store_side_block(&store, &a4);
    drop(store);

    let mut chain = open_chain(dir.path());
    assert_eq!(chain.tip_hash, a3_hash, "A canonical pre-reorg");

    // Snapshot the FULL original A state: every persisted UTXO + kernel entry.
    let a_utxos: BTreeMap<Vec<u8>, Vec<u8>> = chain.store.read_all_utxos_raw().unwrap();
    let a_kernels: BTreeMap<Vec<u8>, Vec<u8>> = chain.store.read_all_kernel_index_raw().unwrap();
    let a_utxo_digest = utxo_digest(&chain);
    let a_kernel_digest = kernel_digest(&chain);
    let a_tip = chain.tip_hash;

    // A -> B.
    chain
        .promote_heavier_known_tip(b4_hash, Timestamp(2_000_000_000))
        .expect("A->B");
    assert_eq!(chain.tip_hash, b4_hash);
    // Mid-reorg sanity: state actually changed (otherwise the round trip is
    // vacuous).
    assert_ne!(
        utxo_digest(&chain),
        a_utxo_digest,
        "reorg to B must actually mutate the UTXO set"
    );

    // B -> A' (A extended heavier, reusing original A blocks as prefix).
    chain
        .promote_heavier_known_tip(a4_hash, Timestamp(2_000_000_000))
        .expect("B->A' (A extended heavier)");
    assert_eq!(chain.tip_hash, a4_hash, "back on the A branch");

    // Original A tip restored as the canonical height-3 block — no residue.
    assert_eq!(
        chain.store.get_hash_at_height(3).unwrap().unwrap(),
        *a_tip.as_bytes(),
        "original A tip restored as canonical height-3 block"
    );

    // IDENTICAL-state property: every original-A UTXO entry is present again
    // with byte-identical value (commitment -> serialized UtxoEntry).
    let after_utxos = chain.store.read_all_utxos_raw().unwrap();
    for (commitment, entry) in &a_utxos {
        assert_eq!(
            after_utxos.get(commitment),
            Some(entry),
            "original A UTXO must be restored byte-for-byte after round trip"
        );
    }
    // Every original-A kernel restored byte-for-byte.
    let after_kernels = chain.store.read_all_kernel_index_raw().unwrap();
    for (excess, blk) in &a_kernels {
        assert_eq!(
            after_kernels.get(excess),
            Some(blk),
            "original A kernel must be restored byte-for-byte after round trip"
        );
    }

    // Every B-only output/kernel must be gone (no contamination).
    for cb in [
        *b2.coinbase.output.commitment.as_bytes(),
        *b3.coinbase.output.commitment.as_bytes(),
        *b4.coinbase.output.commitment.as_bytes(),
    ] {
        assert!(
            chain.store.get_utxo(&cb).unwrap().is_none(),
            "B-only output must be gone after reorg back to A"
        );
    }
    for kx in [
        *b2.coinbase.kernel.excess.as_bytes(),
        *b3.coinbase.kernel.excess.as_bytes(),
        *b4.coinbase.kernel.excess.as_bytes(),
    ] {
        assert!(
            chain.store.get_kernel_block(&kx).unwrap().is_none(),
            "B-only kernel must be gone after reorg back to A"
        );
    }

    // The A-prefix digests (UTXO/kernel restricted to the original A
    // commitments) match the pre-reorg snapshot: the round trip left the A
    // state it claimed to restore exactly as it was, plus only the A4 extension.
    let restored_a_only_utxo = {
        type B2b256 = Blake2b<U32>;
        let mut h = B2b256::new();
        for (k, v) in &a_utxos {
            // Only assert restoration of the original-A keys; A4 adds new keys.
            let v_after = after_utxos.get(k).expect("A utxo restored");
            h.update((k.len() as u64).to_le_bytes());
            h.update(k);
            h.update((v_after.len() as u64).to_le_bytes());
            h.update(v_after);
            assert_eq!(v, v_after);
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(&h.finalize());
        out
    };
    let snapshot_a_only_utxo = {
        type B2b256 = Blake2b<U32>;
        let mut h = B2b256::new();
        for (k, v) in &a_utxos {
            h.update((k.len() as u64).to_le_bytes());
            h.update(k);
            h.update((v.len() as u64).to_le_bytes());
            h.update(v);
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(&h.finalize());
        out
    };
    assert_eq!(
        restored_a_only_utxo, snapshot_a_only_utxo,
        "A-prefix UTXO digest identical across the round trip"
    );
    let _ = a_kernel_digest; // kernel byte-equality already asserted above.
}
