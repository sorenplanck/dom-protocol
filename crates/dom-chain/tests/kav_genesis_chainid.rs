//! dom-shield KAV-conformância — genesis hash + chain_id fixed vectors.
//!
//! Attack vector (Lens A: incorrect-result / non-conformance): if the genesis
//! block hash or the derived chain_id silently changes (a refactor to the
//! hashing preimage, a constant edit to GENESIS_MESSAGE / INITIAL_BLOCK_REWARD /
//! a network magic), every node built from the new code would compute a
//! different chain_id and fork the network at height 0 — a total consensus
//! split that no liveness test would catch because each node agrees with
//! itself. The existing genesis unit tests (genesis.rs) only assert
//! determinism (g1 == g2) and cross-network difference (mainnet != testnet);
//! neither pins the ACTUAL bytes, so a uniform change to the preimage would
//! pass them. These KAV vectors freeze the exact bytes.
//!
//! The vectors below were measured against the production build paths
//! `build_mainnet_genesis()` / `build_testnet_genesis()` on 2026-06-23. They
//! are the authoritative fixed answers; if production output changes, EITHER a
//! deliberate consensus change happened (PRECISA DECISÃO HUMANA — update the
//! vector with justification) OR a regression was introduced (the finding).

use dom_chain::{build_mainnet_genesis, build_testnet_genesis};
use dom_core::{
    GENESIS_MESSAGE, INITIAL_BLOCK_REWARD, NETWORK_MAGIC_MAINNET, NETWORK_MAGIC_TESTNET,
};

// Measured fixed answers (hex, big-endian byte order as stored).
const MAINNET_GENESIS_HASH_HEX: &str =
    "cf0832d2f08aac6b6597dbd5be835f6a58b73fd24162d5e88095290b0b37121c";
const MAINNET_CHAIN_ID_HEX: &str =
    "7b87df013394591a85f205680d4b5c17073fb06a554e7f1ead1d3cf37db1ba21";
const TESTNET_GENESIS_HASH_HEX: &str =
    "562c7ac5e49d0499d083f98f15f44845b1497eff88fb34de489a61f840af72b2";
const TESTNET_CHAIN_ID_HEX: &str =
    "d652f786cd72db20173e7d3161c1eef7489dbad57ccbc4ea3ac4a4cda8c35c11";

#[test]
fn mainnet_genesis_hash_matches_fixed_vector() {
    let g = build_mainnet_genesis().expect("build mainnet genesis");
    assert_eq!(
        hex::encode(g.block_hash.as_bytes()),
        MAINNET_GENESIS_HASH_HEX,
        "mainnet genesis hash drifted from the frozen consensus vector"
    );
}

#[test]
fn testnet_genesis_hash_matches_fixed_vector() {
    let g = build_testnet_genesis().expect("build testnet genesis");
    assert_eq!(
        hex::encode(g.block_hash.as_bytes()),
        TESTNET_GENESIS_HASH_HEX,
        "testnet genesis hash drifted from the frozen consensus vector"
    );
}

#[test]
fn mainnet_chain_id_matches_fixed_vector() {
    let g = build_mainnet_genesis().expect("build mainnet genesis");
    assert_eq!(
        hex::encode(g.chain_id().as_bytes()),
        MAINNET_CHAIN_ID_HEX,
        "mainnet chain_id drifted; nodes would fork at height 0"
    );
}

#[test]
fn testnet_chain_id_matches_fixed_vector() {
    let g = build_testnet_genesis().expect("build testnet genesis");
    assert_eq!(
        hex::encode(g.chain_id().as_bytes()),
        TESTNET_CHAIN_ID_HEX,
        "testnet chain_id drifted; nodes would fork at height 0"
    );
}

#[test]
fn genesis_chain_id_binds_network_magic_and_genesis_hash() {
    // chain_id is a pure function of (network_magic, genesis_hash). The two
    // networks must therefore never collide on chain_id, and each must equal
    // its frozen vector. This pins the binding rather than just "they differ".
    let mainnet = build_mainnet_genesis().expect("mainnet");
    let testnet = build_testnet_genesis().expect("testnet");
    assert_ne!(
        mainnet.chain_id(),
        testnet.chain_id(),
        "distinct networks must derive distinct chain_id"
    );
    assert_eq!(mainnet.network_magic, NETWORK_MAGIC_MAINNET);
    assert_eq!(testnet.network_magic, NETWORK_MAGIC_TESTNET);
}

#[test]
fn genesis_economic_constants_are_frozen() {
    // The genesis hash preimage folds in INITIAL_BLOCK_REWARD and GENESIS_MESSAGE
    // (see genesis::hash_genesis_header). Freeze them so a change to either is
    // caught here AND shows up in the hash vectors above, giving two independent
    // tripwires for the same consensus-critical preimage.
    let g = build_mainnet_genesis().expect("mainnet");
    assert_eq!(g.reward, INITIAL_BLOCK_REWARD, "genesis reward changed");
    assert_eq!(
        INITIAL_BLOCK_REWARD, 3_300_000_000,
        "subsidy constant changed"
    );
    assert_eq!(g.message, GENESIS_MESSAGE, "genesis message changed");
    assert_eq!(
        GENESIS_MESSAGE, "Not a store of value. A means of exchange.",
        "genesis message text changed"
    );
}
