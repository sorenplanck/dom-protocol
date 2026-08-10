//! DOM-SEC-004 — fail-closed mining without a wallet on a public network.
//!
//! A node that mines without a configured wallet builds a coinbase whose
//! blinding factor is discarded, making the reward permanently unspendable.
//! On testnet/mainnet that silently burns an honest operator's rewards, so
//! `mine_one_block` must refuse to mine instead.
//!
//! ## Chosen test level (and why)
//!
//! The fix lives in `mine_one_block`'s coinbase-decision branch, so this test
//! drives that exact public entry point on a real `DomNode` rather than a
//! lower-level helper.
//!
//! Testnet is the representative public network here:
//!   * Mainnet is intentionally not constructed by this local-only test. The
//!     testnet and mainnet arms of the fix are the *same* `else` branch
//!     (`network != Regtest`), so testnet covers the mainnet behaviour without
//!     activating Mainnet services.
//!   * This lives in its own integration-test binary and deliberately does NOT
//!     set `DOM_REGTEST_FAST_MINING`. Sibling unit tests in `miner.rs` set that
//!     env var process-globally and never clear it; sharing a binary with them
//!     would make `MiningMode::for_network(Testnet)` error first ("fast mining
//!     only on regtest") before the coinbase branch is reached. A dedicated
//!     binary keeps the env clean and the asserted path deterministic.

use dom_config::NodeConfig;
use dom_core::DomError;
use dom_node::node::DomNode;
use std::sync::Arc;
use tempfile::TempDir;

const TEST_LMDB_MAP_SIZE: usize = 64 << 20; // 64 MiB — these fixtures are tiny.

#[tokio::test]
async fn testnet_mining_without_wallet_fails_closed() {
    let dir = TempDir::new().expect("tempdir");
    let mut config = NodeConfig::testnet();
    config.data_dir = dir.path().to_string_lossy().into_owned();
    // No wallet configured — this is the condition that must now be refused.
    config.wallet_path = None;
    config.wallet_password = None;
    config.mine = false;

    let node = Arc::new(
        DomNode::init_with_map_size(config, TEST_LMDB_MAP_SIZE).expect("testnet node init"),
    );
    assert!(
        node.wallet.is_none(),
        "precondition: node must have no wallet"
    );

    let result = dom_node::miner::mine_one_block(node).await;

    match result {
        Err(DomError::Invalid(msg)) => {
            assert!(
                msg.contains("public network") && msg.contains("wallet"),
                "fail-closed error should explain the public-network/wallet requirement, got: {msg}"
            );
            assert!(
                msg.contains("DOM-SEC-004"),
                "error should reference DOM-SEC-004, got: {msg}"
            );
        }
        Err(other) => {
            panic!("expected DomError::Invalid fail-closed, got different error: {other:?}")
        }
        Ok(height) => panic!(
            "testnet mining without a wallet must fail closed, but it mined block {height} \
             (this is the DOM-SEC-004 burn we are preventing)"
        ),
    }
}
