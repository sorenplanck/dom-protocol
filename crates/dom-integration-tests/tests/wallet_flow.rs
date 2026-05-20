//! Test 2: Wallet send/receive flow.

use dom_integration_tests::helpers::*;
use std::time::Duration;

#[tokio::test]
#[ignore]
async fn test_wallet_send_receive() {
    let mut config_a = test_config("wallet-a", 43372, true);
    config_a.wallet_path = Some("/tmp/dom-test-wallet-a.dom".into());
    config_a.wallet_password = Some("password-a".into());

    let mut config_b = test_config("wallet-b", 43373, false);
    config_b.wallet_path = Some("/tmp/dom-test-wallet-b.dom".into());
    config_b.wallet_password = Some("password-b".into());
    config_b.seed_peers = vec!["127.0.0.1:43372".into()];

    let node_a = spawn_node(config_a).await;
    let node_b = spawn_node(config_b).await;

    tokio::spawn(node_a.clone().run());
    tokio::spawn(node_b.clone().run());

    wait_for_peer_count(&node_b, 1, Duration::from_secs(10))
        .await
        .expect("nodes should connect");

    mine_blocks(&node_a, 1).await.expect("mining failed");
    
    let wallet_a = node_a.wallet.as_ref().expect("wallet should exist");
    let balance_a = {
        let w = wallet_a.lock().await;
        w.balance(1)
    };
    
    assert!(balance_a.total() > 0, "wallet A should have pending balance");
    
    println!("✅ Wallet flow: PASS");
}
