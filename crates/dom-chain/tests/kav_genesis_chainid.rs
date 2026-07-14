//! Canonical rooted genesis authority and identity regression tests.

use dom_chain::build_canonical_genesis;
use dom_consensus::derive_chain_id;
use dom_core::{
    configured_genesis_hash_for_network_magic, GENESIS_HASH_TESTNET, NETWORK_MAGIC_MAINNET,
    NETWORK_MAGIC_REGTEST, NETWORK_MAGIC_TESTNET,
};

fn configured_chain_id(network_magic: u32) -> [u8; 32] {
    let configured_hash = configured_genesis_hash_for_network_magic(network_magic).unwrap();
    *derive_chain_id(network_magic, &configured_hash).as_bytes()
}

#[test]
fn current_testnet_genesis_identity_is_preserved() {
    let genesis = build_canonical_genesis(
        NETWORK_MAGIC_TESTNET,
        &configured_chain_id(NETWORK_MAGIC_TESTNET),
    )
    .unwrap();
    assert_eq!(genesis.hash.as_bytes(), &GENESIS_HASH_TESTNET);
    assert_eq!(
        genesis.hash.to_hex(),
        "2ab5e6c73607e8bfbbec2d4ce3ea1419cda29ae6892e7f1c24facc465cd65821"
    );
}

#[test]
fn canonical_builder_is_deterministic_without_finalizing_other_networks() {
    for magic in [
        NETWORK_MAGIC_MAINNET,
        NETWORK_MAGIC_TESTNET,
        NETWORK_MAGIC_REGTEST,
    ] {
        let chain_id = configured_chain_id(magic);
        let first = build_canonical_genesis(magic, &chain_id).unwrap();
        let second = build_canonical_genesis(magic, &chain_id).unwrap();
        assert_eq!(first.header_bytes, second.header_bytes);
        assert_eq!(first.block_bytes, second.block_bytes);
        assert_eq!(first.hash, second.hash);
    }
}

#[test]
fn production_startup_uses_the_only_genesis_authority() {
    let chain_source = include_str!("../src/genesis.rs");
    let node_source = include_str!("../../dom-node/src/miner.rs");

    assert!(!chain_source.contains("Sha256"));
    assert!(!chain_source.contains("hash_genesis_header"));
    assert!(!chain_source.contains("build_mainnet_genesis"));
    assert!(!chain_source.contains("build_testnet_genesis"));
    assert!(node_source.contains("dom_chain::build_canonical_genesis"));
}
