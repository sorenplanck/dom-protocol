//! DOM-SEC-004 — regression guard for the regtest dev/test path.
//!
//! The fail-closed fix for public networks must NOT change regtest: mining
//! without a wallet on regtest is still allowed (the reward is unspendable,
//! which is fine for ephemeral throwaway chains). This proves the regtest arm
//! of `mine_one_block`'s coinbase decision still routes to `build_real_coinbase`
//! and mines a block, rather than hitting the new public-network error.
//!
//! Lives in its own integration-test binary so it can set
//! `DOM_REGTEST_FAST_MINING=1` (FastDevOnly hashing) without leaking that env
//! var into the testnet fail-closed test, which requires it unset.

use dom_config::NodeConfig;
use dom_node::node::DomNode;
use std::sync::Arc;
use tempfile::TempDir;

const TEST_LMDB_MAP_SIZE: usize = 64 << 20; // 64 MiB

#[tokio::test]
async fn regtest_mining_without_wallet_still_works() {
    // Regtest-only fast PoW so the test mines in milliseconds. Honored only on
    // regtest (see pow_validation_mode_for_network); isolated to this binary.
    std::env::set_var("DOM_REGTEST_FAST_MINING", "1");

    let dir = TempDir::new().expect("tempdir");
    let mut config = NodeConfig::regtest();
    config.data_dir = dir.path().to_string_lossy().into_owned();
    config.wallet_path = None;
    config.wallet_password = None;
    config.mine = false;

    let node = Arc::new(
        DomNode::init_with_map_size(config, TEST_LMDB_MAP_SIZE).expect("regtest node init"),
    );
    assert!(node.wallet.is_none(), "precondition: no wallet configured");

    // Bootstrap genesis, then mine block 1 through the real miner entry point.
    dom_node::miner::create_genesis_block(node.clone())
        .await
        .expect("regtest genesis");

    let height = dom_node::miner::mine_one_block(node)
        .await
        .expect("regtest mining without a wallet must still succeed (no regression)");

    assert_eq!(
        height, 1,
        "first mined block after genesis should be height 1"
    );
}
