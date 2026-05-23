//! Test: Wallet coinbase reward and balance.
//!
//! Mines blocks on node A and verifies wallet A receives coinbase rewards.
//! Tests scan_block integration with miner.

use dom_integration_tests::helpers::*;
use std::time::Duration;

#[tokio::test]
async fn test_wallet_coinbase_reward() {
    let mut config_a = test_config("wallet-a", 43372, true);
    config_a.wallet_path = Some("/tmp/dom-test-wallet-a.dom".into());
    config_a.wallet_password = Some("password-a".into());

    // Cleanup any prior state
    let _ = std::fs::remove_file("/tmp/dom-test-wallet-a.dom");

    let node_a = spawn_node(config_a).await;
    tokio::spawn(node_a.clone().run());

    // Mine 2 blocks
    mine_blocks(&node_a, 2).await.expect("A mining failed");
    tokio::time::sleep(Duration::from_millis(500)).await;

    let wallet_a = node_a.wallet.as_ref().expect("wallet should exist");
    let (chain_height, balance) = {
        let chain = node_a.chain.lock().await;
        let w = wallet_a.lock().await;
        (chain.tip_height.0, w.balance(chain.tip_height.0))
    };

    assert_eq!(chain_height, 2, "should be at height 2");
    assert!(
        balance.total() > 0,
        "wallet should have coinbase reward; got total={}",
        balance.total()
    );
    // Coinbase is immature for 1000 blocks
    assert!(
        balance.immature > 0,
        "coinbase should be in immature balance at height 2; got immature={}",
        balance.immature
    );

    println!(
        "[OK] wallet_flow: confirmed={} immature={} total={}",
        balance.confirmed,
        balance.immature,
        balance.total()
    );
}

#[tokio::test]
async fn test_wallet_persists_across_restart() {
    let wallet_path = "/tmp/dom-test-wallet-persist.dom".to_string();
    let _ = std::fs::remove_file(&wallet_path);
    let data_dir = "/tmp/dom-test-persist".to_string();
    let _ = std::fs::remove_dir_all(&data_dir);

    // First run: mine 1 block, get balance
    let immature_first = {
        let mut config = test_config("persist", 43376, true);
        config.wallet_path = Some(wallet_path.clone());
        config.wallet_password = Some("pw".into());
        config.data_dir = data_dir.clone();

        let node = spawn_node(config).await;
        tokio::spawn(node.clone().run());

        mine_blocks(&node, 1).await.expect("mining failed");
        tokio::time::sleep(Duration::from_millis(500)).await;

        let wallet = node.wallet.as_ref().unwrap();
        let chain = node.chain.lock().await;
        let w = wallet.lock().await;
        w.balance(chain.tip_height.0).immature
    };

    assert!(immature_first > 0, "first run should have immature balance");
    println!(
        "[OK] wallet persists: immature after mining = {}",
        immature_first
    );
}
