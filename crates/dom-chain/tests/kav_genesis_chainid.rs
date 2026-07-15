//! Canonical rooted genesis authority and identity regression tests.

mod common;

use dom_chain::{build_canonical_genesis, canonical_header_identifier, ChainState};
use dom_consensus::{derive_chain_id, BlockHeader};
use dom_core::{
    configured_genesis_hash_for_network_magic, BlockHeight, Hash256, GENESIS_HASH_TESTNET,
    NETWORK_MAGIC_MAINNET, NETWORK_MAGIC_REGTEST, NETWORK_MAGIC_TESTNET,
};
use dom_serialization::DomDeserialize;

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
fn canonical_builder_is_deterministic_for_all_finalized_networks() {
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
fn mainnet_identifier_is_coherent_across_storage_linkage_rpc_and_chain_id_roles() {
    let configured = configured_genesis_hash_for_network_magic(NETWORK_MAGIC_MAINNET).unwrap();
    let chain_id = derive_chain_id(NETWORK_MAGIC_MAINNET, &configured);
    let canonical = build_canonical_genesis(NETWORK_MAGIC_MAINNET, chain_id.as_bytes()).unwrap();
    assert_eq!(canonical.hash, configured);
    assert_eq!(
        canonical_header_identifier(NETWORK_MAGIC_MAINNET, &canonical.header_bytes).unwrap(),
        configured
    );

    let dir = tempfile::tempdir().unwrap();
    let store = common::open_test_store(dir.path());
    store
        .commit_block(
            configured.as_bytes(),
            BlockHeight::GENESIS.0,
            &canonical.header_bytes,
            &canonical.block_bytes,
            &[],
            &[],
            &[],
        )
        .unwrap();
    let chain = ChainState::open(store, configured, NETWORK_MAGIC_MAINNET).unwrap();
    assert_eq!(chain.tip_hash, configured);
    assert_eq!(
        chain.store.get_hash_at_height(0).unwrap().unwrap(),
        *configured.as_bytes()
    );
    // RPC and explorer height lookups consume this same height index through
    // NodeHandle::get_block_hash_at_height.
    let rpc_block_zero = chain.store.get_hash_at_height(0).unwrap().unwrap();
    assert_eq!(rpc_block_zero, *configured.as_bytes());

    let genesis_header = BlockHeader::from_bytes(&canonical.header_bytes).unwrap();
    let block_one_previous_identifier = chain.tip_hash;
    assert_eq!(block_one_previous_identifier, configured);
    assert_eq!(chain.genesis_hash, configured);
    assert_eq!(genesis_header.height, BlockHeight::GENESIS);
    assert_eq!(
        derive_chain_id(NETWORK_MAGIC_MAINNET, &chain.genesis_hash),
        chain_id
    );
    assert_ne!(genesis_header.pow.randomx_hash, configured);
    assert_ne!(configured, Hash256::ZERO);
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
