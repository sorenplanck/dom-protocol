//! Mainnet genesis readiness regression tests.
//!
//! These checks deliberately validate the frozen Mainnet identity without
//! constructing or running a Mainnet node. The final campaign is local-only:
//! readiness must not require a listener, a database, DNS, NTP, or peer I/O.

use dom_core::{startup_genesis_hash_for_network_magic, Hash256, NETWORK_MAGIC_MAINNET};

#[test]
fn finalized_mainnet_genesis_passes_the_startup_readiness_gate() {
    assert_eq!(
        startup_genesis_hash_for_network_magic(NETWORK_MAGIC_MAINNET)
            .expect("finalized Mainnet genesis must be startup-ready"),
        Hash256::from_bytes(dom_core::GENESIS_HASH_MAINNET),
    );
}

#[test]
fn finalized_mainnet_genesis_matches_the_frozen_identity() {
    assert_eq!(
        Hash256::from_bytes(dom_core::GENESIS_HASH_MAINNET).to_hex(),
        "182e10af28e7ec072f462e6044f580dc9dd8c866cb78dfc293bbfaee4e9325ce"
    );
}
