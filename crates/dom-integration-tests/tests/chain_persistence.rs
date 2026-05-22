//! Test: Chain state persists across node restart.
//!
//! Mines blocks, shuts down, restarts, verifies chain height preserved.

use dom_integration_tests::helpers::*;
use std::time::Duration;

#[tokio::test]
async fn test_chain_persists_across_restart() {
    let data_dir = "/tmp/dom-test-chain-persist".to_string();
    let _ = std::fs::remove_dir_all(&data_dir);

    let port = 43396;

    // First run
    let (height_first, hash_first) = {
        let mut config = test_config("chain-persist", port, true);
        config.data_dir = data_dir.clone();

        let node = spawn_node(config).await;
        tokio::spawn(node.clone().run());

        mine_blocks(&node, 3).await.expect("mining failed");
        tokio::time::sleep(Duration::from_millis(500)).await;

        let chain = node.chain.lock().await;
        (chain.tip_height.0, chain.tip_hash)
    };

    assert_eq!(height_first, 3);

    // Drop everything, wait
    tokio::time::sleep(Duration::from_secs(2)).await;

    // Second run: same data_dir, no mining
    let (height_second, hash_second) = {
        let mut config = test_config("chain-persist-2", port + 100, false);
        config.data_dir = data_dir.clone();

        let node = spawn_node(config).await;
        // Don't even need to run() for this — init reads from disk
        let chain = node.chain.lock().await;
        (chain.tip_height.0, chain.tip_hash)
    };

    assert_eq!(height_first, height_second, "height should persist");
    assert_eq!(hash_first, hash_second, "tip hash should persist");

    println!("[OK] chain_persists: height={} hash={}", height_second, hash_second);
}
