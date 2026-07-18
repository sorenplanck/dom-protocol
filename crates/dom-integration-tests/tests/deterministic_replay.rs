//! Phase 3 — deterministic-replay regression gate for the Bulletproof (bp2)
//! migration.
//!
//! Deterministic convergence is the single most critical property of the whole
//! migration: if a future change introduces non-determinism (HashMap iteration
//! order, a stray timestamp/RNG, a dependency that reorders proof bytes), two
//! honest nodes would compute different canonical state and the network would
//! split at launch. This test makes that failure surface on EVERY change instead
//! of being verified once by hand.
//!
//! It builds a deterministic Regtest/FastDevOnly chain WITHIN a single process,
//! using the real production construction primitives — the genesis bootstrap
//! (`spawn_node` → `create_genesis_block`), the production coinbase constructor
//! (`build_deterministic_coinbase`, a thin deterministic wrapper over the same
//! `build_coinbase_with_blinding` the genesis/normal paths use, with its real
//! bp2 range proof), the real PMMR-root computation (`compute_block_pmmr_roots`),
//! the real FastDevOnly PoW (`fast_pow_hash`), and the real validator
//! (`ChainState::connect_block`). The only thing the test controls is what makes
//! mining non-deterministic in production: the block timestamp (fixed to
//! genesis_ts + height) and the coinbase blinding/nonce (tag-derived).
//!
//! Then it:
//!   (a) builds the SAME scenario twice in the same process and asserts the two
//!       canonical dumps are byte-identical — catches RNG/time/ordering leaks;
//!   (b) asserts the dump's sha256 matches a PINNED digest — catches any future
//!       drift in genesis, coinbase proof, PMMR roots, or canonical state.
//!
//! Not `#[ignore]`d — it is a fast (FastDevOnly), deterministic CI gate.

use dom_consensus::{
    block::{BlockHeader, ProofOfWork},
    compute_block_pmmr_roots, derive_chain_id, Block,
};
use dom_core::{BlockHeight, Hash256, Timestamp};
use dom_integration_tests::helpers::*;
use dom_node::miner::build_deterministic_coinbase;
use dom_pow::{
    fast_pow_hash, randomx_seed_height, target_to_difficulty, CompactTarget, REGTEST_TARGET_COMPACT,
};
use dom_serialization::DomDeserialize;
use primitive_types::U256;
use sha2::{Digest, Sha256};
use std::time::Instant;

/// Number of deterministic blocks to build past genesis. Modest by design —
/// FastDevOnly + tag-derived coinbase means more blocks add cost without adding
/// coverage; 10 exercises multi-block linkage, cumulative UTXO/kernel state, and
/// difficulty accumulation.
const N: u64 = 10;

/// SHA-256 of the canonical dump for the finalized Regtest genesis identity.
/// A full campaign replay and its independent in-process repeat produced this
/// byte-identical dump. Any future change to genesis, the coinbase/bp2 proof,
/// PMMR roots, or canonical UTXO/kernel state changes this digest and fails CI.
// CON-009: re-pinned after non-genesis headers began binding the complete
// canonical block body into the third root. The frozen genesis is unchanged.
const PINNED_DIGEST: &str = "4565f28da0e0454ddc145f20987357a44fd133639051169494a6619131f1d249";

/// Build a deterministic Regtest chain of `N` blocks past genesis using the real
/// production construction path, then return a canonical byte dump of its state:
/// genesis + every block hash and PMMR roots, the tip (hash/height/difficulty),
/// and the sorted UTXO and kernel sets.
async fn build_and_dump_canonical_state(tag: &str, port: u16) -> Vec<u8> {
    // Wallet-less Regtest node: we construct coinbases ourselves, so no wallet is
    // needed (regtest permits wallet-less dev mining). spawn_node bootstraps the
    // deterministic genesis via the production create_genesis_block path.
    let mut config = test_config(tag, port, false);
    config.wallet_path = None;
    config.wallet_password = None;
    let node = spawn_node(config).await;

    // chain_id exactly as connect_block derives it, so our coinbase kernel
    // signatures verify against the validator.
    let chain_id = *derive_chain_id(
        dom_core::NETWORK_MAGIC_REGTEST,
        &Hash256::from_bytes(dom_core::GENESIS_HASH_REGTEST),
    )
    .as_bytes();

    // Read the genesis timestamp so block h can be stamped at genesis_ts + h
    // (strictly increasing ⇒ satisfies the timestamp-progression invariant).
    let genesis_ts = {
        let chain = node.chain.lock().await;
        let gh = chain
            .store
            .get_hash_at_height(0)
            .expect("genesis hash query")
            .expect("genesis hash present");
        let hdr_bytes = chain
            .store
            .get_block_header(&gh)
            .expect("genesis header query")
            .expect("genesis header present");
        BlockHeader::from_bytes(&hdr_bytes)
            .expect("decode genesis header")
            .timestamp
            .0
    };

    // The validator's "now" only bounds future block time; it is not stored, so
    // it does not affect the dump. Keep all blocks comfortably in the past.
    let validator_now = Timestamp(genesis_ts + N + 100);

    for height in 1..=N {
        let mut chain = node.chain.lock().await;
        let prev_hash = chain.tip_hash;
        let tip_difficulty = chain.tip_difficulty;

        // Real coinbase (deterministic blinding/nonce) + its real bp2 proof.
        let coinbase =
            build_deterministic_coinbase(BlockHeight(height), 0, &chain_id).expect("coinbase");
        // Real PMMR roots over this block's contents (coinbase only; no txs).
        let (output_root, kernel_root, rangeproof_root) =
            compute_block_pmmr_roots(BlockHeight(height), &coinbase, &[]).expect("pmmr roots");

        // Regtest fixed trivial target; difficulty derived from it exactly as
        // connect_block recomputes it (from header.target.to_target()).
        let target = CompactTarget(REGTEST_TARGET_COMPACT);
        let target_bytes = target.to_target().expect("regtest target expand");
        let block_diff = target_to_difficulty(&target_bytes);
        let total_difficulty = tip_difficulty.saturating_add(U256::from(block_diff));

        // RandomX seed exactly as ChainState::compute_randomx_seed resolves it.
        let seed = chain
            .store
            .get_hash_at_height(randomx_seed_height(height))
            .ok()
            .flatten()
            .unwrap_or([0u8; 32]);

        let mut header = BlockHeader {
            version: dom_core::PROTOCOL_VERSION,
            height: BlockHeight(height),
            prev_hash,
            timestamp: Timestamp(genesis_ts + height),
            output_root,
            kernel_root,
            rangeproof_root,
            total_kernel_offset: [0u8; 32],
            target,
            total_difficulty,
            pow: ProofOfWork {
                nonce: 0,
                randomx_hash: Hash256::ZERO,
            },
        };
        // FastDevOnly PoW: randomx_hash = fast_pow_hash(seed, preimage). The
        // function zeroes the high 16 bytes, so the hash always meets the
        // regtest target; nonce is fixed at 0.
        let pow_hash = fast_pow_hash(&seed, &header.pow_preimage());
        header.pow.randomx_hash = Hash256::from_bytes(pow_hash);

        let block = Block {
            header,
            coinbase,
            transactions: Vec::new(),
        };
        let result = chain
            .connect_block(&block, validator_now)
            .unwrap_or_else(|e| panic!("connect_block(height {height}) rejected: {e}"));
        assert_eq!(
            result,
            dom_chain::ConnectResult::BestChain,
            "deterministic block {height} must extend the best chain"
        );
    }

    // ── Canonical dump ────────────────────────────────────────────────────────
    let chain = node.chain.lock().await;
    let mut dump = Vec::new();

    // Genesis + every block: hash and the three PMMR roots in its header.
    for h in 0..=N {
        let hash = chain
            .store
            .get_hash_at_height(h)
            .expect("hash query")
            .unwrap_or_else(|| panic!("block hash at height {h} present"));
        dump.extend_from_slice(&hash);
        let hdr_bytes = chain
            .store
            .get_block_header(&hash)
            .expect("header query")
            .expect("header present");
        let hdr = BlockHeader::from_bytes(&hdr_bytes).expect("decode header");
        dump.extend_from_slice(hdr.output_root.as_bytes());
        dump.extend_from_slice(hdr.kernel_root.as_bytes());
        dump.extend_from_slice(hdr.rangeproof_root.as_bytes());
    }

    // Tip: hash, height, total difficulty (32-byte big-endian).
    dump.extend_from_slice(chain.tip_hash.as_bytes());
    dump.extend_from_slice(&chain.tip_height.0.to_le_bytes());
    let mut td = [0u8; 32];
    chain.tip_difficulty.to_big_endian(&mut td);
    dump.extend_from_slice(&td);

    // Sorted UTXO set (BTreeMap ⇒ deterministic order) and sorted kernel set.
    let append_map = |dump: &mut Vec<u8>, map: &std::collections::BTreeMap<Vec<u8>, Vec<u8>>| {
        dump.extend_from_slice(&(map.len() as u64).to_le_bytes());
        for (k, v) in map {
            dump.extend_from_slice(&(k.len() as u64).to_le_bytes());
            dump.extend_from_slice(k);
            dump.extend_from_slice(&(v.len() as u64).to_le_bytes());
            dump.extend_from_slice(v);
        }
    };
    append_map(&mut dump, &chain.store.read_all_utxos_raw().expect("utxos"));
    append_map(
        &mut dump,
        &chain.store.read_all_kernel_index_raw().expect("kernels"),
    );

    dump
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn deterministic_replay_pins_canonical_state() {
    init_tracing();
    let started = Instant::now();

    // (a) Build the SAME scenario twice in this process. Two independent builds
    //     must yield byte-identical canonical dumps — any RNG/time/ordering leak
    //     in genesis, coinbase, proof generation, root computation, or state
    //     serialization would diverge here.
    let dump_a = build_and_dump_canonical_state("det-replay-a", free_local_port()).await;
    let dump_b = build_and_dump_canonical_state("det-replay-b", free_local_port()).await;
    assert_eq!(
        dump_a, dump_b,
        "two independent in-process builds produced different canonical state — \
         a non-determinism leak (RNG / wall-clock / HashMap ordering) was introduced"
    );

    // (b) Pin the canonical state with a frozen sha256.
    let digest_hex = hex::encode(Sha256::digest(&dump_a));
    eprintln!(
        "[deterministic_replay] N={N} dump_len={} sha256={digest_hex}",
        dump_a.len()
    );
    assert_eq!(
        digest_hex, PINNED_DIGEST,
        "canonical-state digest drift: genesis / coinbase bp2 proof / PMMR roots / \
         UTXO set / kernel set changed. If this change is intentional, re-pin \
         PINNED_DIGEST to {digest_hex} and document why the canonical state moved."
    );

    eprintln!("[deterministic_replay OK] {:?}", started.elapsed());
}
