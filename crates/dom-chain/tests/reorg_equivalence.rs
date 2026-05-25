//! Roadmap v2 Phase 1.2 — Reorg equivalence framework.
//!
//! The integration-level reorg test (`dom-integration-tests/tests/reorg.rs`)
//! is ENV-BLOCKED on WSL2: it spins real RandomX miners on the Regtest
//! target, which the host can't sustain inside the test deadline. This
//! file fills the gap by exercising the reorg primitives that *don't*
//! need mining: the chain-DAG walks. They run in milliseconds and can
//! ship in CI without any host-specific assumptions.
//!
//! What is covered here:
//! 1. `find_common_ancestor` on synthetic header DAGs. The function is
//!    pure graph traversal over `prev_hash` links; given a populated
//!    `DomStore` it does not touch PoW, signatures, or the UTXO set.
//!    The synthetic chains here therefore use placeholder PoW / target
//!    / commitment fields, but real header layout and real hashing
//!    (Blake2b-256 of the serialised header) so the on-disk hash chain
//!    is identical to what a live node would produce.
//! 2. `check_reorg_depth` boundary behaviour against
//!    `MAX_REORG_DEPTH_POLICY`.
//!
//! What is NOT yet covered and why:
//! - The full reorg pipeline (disconnect blocks back to the ancestor,
//!   then connect the heavier chain forward) is not wired into
//!   `ChainState` yet — only chain-tip promotion via
//!   `ConnectResult::BestChain` is implemented. When that lands, the
//!   equivalence property documented below in
//!   `reorg_equivalence_property_placeholder` should grow into a real
//!   test: applying the heavier chain via `connect_block` must leave
//!   the UTXO set / kernel index / height index byte-identical to
//!   building the heavier chain from the fork point in isolation.
//!   That test requires either real mining (env-blocked) or a
//!   `cfg(test)`-only validation bypass — neither exists today. The
//!   placeholder pins the contract so the property is not forgotten.

use blake2::digest::consts::U32;
use blake2::{Blake2b, Digest};
use dom_chain::reorg::{check_reorg_depth, find_common_ancestor};
use dom_consensus::block::{BlockHeader, ProofOfWork};
use dom_core::{BlockHeight, Hash256, Timestamp};
use dom_pow::CompactTarget;
use dom_serialization::DomSerialize;
use dom_store::DomStore;
use primitive_types::U256;
use tempfile::TempDir;

/// Build a synthetic header with a controllable `prev_hash` and `height`.
/// Other fields are zeroed because the helpers exercised here do not
/// read them.
fn synthetic_header(prev_hash: Hash256, height: u64, nonce_seed: u64) -> BlockHeader {
    BlockHeader {
        version: 1,
        height: BlockHeight(height),
        prev_hash,
        timestamp: Timestamp(1_700_000_000 + height),
        output_root: Hash256::ZERO,
        kernel_root: Hash256::ZERO,
        rangeproof_root: Hash256::ZERO,
        total_kernel_offset: [0u8; 32],
        target: CompactTarget(0),
        total_difficulty: U256::from(height),
        // Vary `nonce` so two forks at the same height hash differently.
        pow: ProofOfWork {
            nonce: nonce_seed,
            randomx_hash: Hash256::ZERO,
        },
    }
}

/// Same hashing scheme as `chain_state::compute_block_hash`: Blake2b-256
/// of the serialised header bytes. Kept private there, re-implemented
/// here because tests are the public contract.
fn block_hash(header: &BlockHeader) -> Hash256 {
    let bytes = header.to_bytes().expect("header serialise");
    type B2b256 = Blake2b<U32>;
    let mut h = B2b256::new();
    h.update(&bytes);
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&h.finalize());
    Hash256::from_bytes(arr)
}

/// Push a synthetic block by writing only its header + body. The
/// store's `commit_block` requires a full block body and a UTXO / kernel
/// changeset, none of which are relevant to the chain-DAG walk — using
/// it here would force this test to fabricate consensus-valid bodies.
/// Instead we put directly into the same LMDB databases via the higher
/// `BlockStore` trait surface that `DomStore` already exposes.
fn put_header(store: &DomStore, header: &BlockHeader) -> Hash256 {
    let hash = block_hash(header);
    let header_bytes = header.to_bytes().expect("header serialise");
    // The body can be any bytes — find_common_ancestor never reads it,
    // and the NO_OVERWRITE check is keyed on the hash.
    let body_bytes = vec![0u8; 8];
    store
        .commit_block(
            hash.as_bytes(),
            header.height.0,
            &header_bytes,
            &body_bytes,
            &[],
            &[],
            &[],
        )
        .expect("commit_block (synthetic)");
    hash
}

/// Build a linear chain of `len` headers starting from `start_prev` and
/// `start_height`. Returns every hash, in order.
fn build_chain(
    store: &DomStore,
    start_prev: Hash256,
    start_height: u64,
    len: u64,
    nonce_offset: u64,
) -> Vec<Hash256> {
    let mut hashes = Vec::with_capacity(len as usize);
    let mut prev = start_prev;
    for i in 0..len {
        let header = synthetic_header(prev, start_height + i, nonce_offset + i);
        prev = put_header(store, &header);
        hashes.push(prev);
    }
    hashes
}

#[test]
fn find_common_ancestor_same_tip_is_self() {
    let dir = TempDir::new().expect("tempdir");
    let store = DomStore::open(dir.path()).expect("open");
    let chain = build_chain(&store, Hash256::ZERO, 1, 5, 0);
    let tip = *chain.last().unwrap();

    let ancestor = find_common_ancestor(&store, tip, tip).expect("walk");
    assert_eq!(ancestor, Some(tip));
}

#[test]
fn find_common_ancestor_linear_chain_to_genesis() {
    let dir = TempDir::new().expect("tempdir");
    let store = DomStore::open(dir.path()).expect("open");
    // One single chain, two cursors at different depths along it.
    let chain = build_chain(&store, Hash256::ZERO, 1, 10, 0);
    let near = chain[3];
    let far = chain[9];

    let ancestor = find_common_ancestor(&store, far, near).expect("walk");
    assert_eq!(
        ancestor,
        Some(near),
        "the lower cursor must itself be the common ancestor",
    );
}

#[test]
fn find_common_ancestor_two_forks_at_known_depth() {
    let dir = TempDir::new().expect("tempdir");
    let store = DomStore::open(dir.path()).expect("open");

    // Shared prefix: genesis → A1 → A2 → A3.
    let prefix = build_chain(&store, Hash256::ZERO, 1, 3, 0);
    let fork_point = *prefix.last().unwrap();

    // Branch A continues for 4 more blocks.
    let branch_a = build_chain(&store, fork_point, 4, 4, 1_000);
    // Branch B continues for 5 more blocks with different nonces so the
    // hashes diverge from branch A immediately.
    let branch_b = build_chain(&store, fork_point, 4, 5, 2_000);

    let tip_a = *branch_a.last().unwrap();
    let tip_b = *branch_b.last().unwrap();

    let ancestor = find_common_ancestor(&store, tip_a, tip_b).expect("walk");
    assert_eq!(
        ancestor,
        Some(fork_point),
        "the last shared block before the fork must be the common ancestor",
    );
}

#[test]
fn find_common_ancestor_separate_genesis_chains_share_zero() {
    let dir = TempDir::new().expect("tempdir");
    let store = DomStore::open(dir.path()).expect("open");

    // Two chains, each rooted at its own real genesis block whose
    // prev_hash terminates at Hash256::ZERO. The walks therefore both
    // insert Hash256::ZERO into the ancestor set, so the function
    // returns Some(ZERO). Semantically that means "no real shared
    // history" — callers must treat ZERO as the empty-state sentinel,
    // not a usable block, but the function's contract is exactly that.
    let chain1 = build_chain(&store, Hash256::ZERO, 1, 5, 0);
    let chain2 = build_chain(&store, Hash256::ZERO, 1, 5, 10_000);

    let ancestor = find_common_ancestor(&store, *chain1.last().unwrap(), *chain2.last().unwrap())
        .expect("walk");
    assert_eq!(
        ancestor,
        Some(Hash256::ZERO),
        "two chains terminating at ZERO must share ZERO as the walk ancestor",
    );
}

#[test]
fn find_common_ancestor_returns_none_when_their_chain_unknown() {
    let dir = TempDir::new().expect("tempdir");
    let store = DomStore::open(dir.path()).expect("open");

    // Our chain is fully populated.
    let ours = build_chain(&store, Hash256::ZERO, 1, 5, 0);
    let our_tip = *ours.last().unwrap();

    // Pick a hash the store has never seen. The walk for "their" tip
    // immediately fails to find the header and the function reports
    // Ok(None) per its documented behaviour for partially-known remote
    // chains.
    let mut unknown = [0u8; 32];
    unknown[0] = 0xDE;
    unknown[1] = 0xAD;
    let their_tip = Hash256::from_bytes(unknown);

    let ancestor = find_common_ancestor(&store, our_tip, their_tip).expect("walk");
    assert!(
        ancestor.is_none(),
        "unknown remote tip must report no ancestor (signals: ask for headers first)",
    );
}

#[test]
fn find_common_ancestor_unbalanced_depths() {
    let dir = TempDir::new().expect("tempdir");
    let store = DomStore::open(dir.path()).expect("open");

    // Shared prefix is tiny (1 block), branches are very different lengths.
    let prefix = build_chain(&store, Hash256::ZERO, 1, 1, 0);
    let fork = *prefix.last().unwrap();
    let short = build_chain(&store, fork, 2, 2, 100);
    let long = build_chain(&store, fork, 2, 50, 5_000);

    let ancestor = find_common_ancestor(&store, *short.last().unwrap(), *long.last().unwrap())
        .expect("walk");
    assert_eq!(ancestor, Some(fork));
}

#[test]
fn check_reorg_depth_boundary() {
    // Exactly at the policy limit must be accepted; one over must be rejected.
    check_reorg_depth(dom_core::MAX_REORG_DEPTH_POLICY).expect("at-limit must be accepted");
    check_reorg_depth(dom_core::MAX_REORG_DEPTH_POLICY + 1)
        .expect_err("over-limit must be rejected");
    check_reorg_depth(0).expect("zero (no disconnect) is always accepted");
}

/// Placeholder for the full reorg-equivalence property.
///
/// Property (informal): given a fork point F and two competing chains
/// A (currently best) and B (heavier total_difficulty), after applying
/// B via the chain pipeline the resulting state — UTXO set, kernel
/// index, height -> hash mapping, chain tip — must be byte-identical to
/// the state produced by building B in a fresh store from F onward.
///
/// Why this is a stub: `ChainState::connect_block` does not yet
/// disconnect superseded blocks on side-chain promotion. Until
/// `apply_reorg` (or equivalent) lands, exercising the property would
/// either (a) need real mining to produce consensus-valid heavier
/// blocks (env-blocked on WSL2), or (b) require a `cfg(test)` PoW
/// bypass that we have not introduced. The intentionally empty test
/// body keeps this file as the single point of truth: when reorg
/// completion lands, replace the body with the property check.
#[test]
fn reorg_equivalence_property_placeholder() {
    // No assertions yet — see doc comment. The test exists so the
    // property contract is registered and grep-discoverable from the
    // reorg implementation PR.
}
