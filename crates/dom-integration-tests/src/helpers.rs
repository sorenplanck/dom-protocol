//! Test helpers for integration tests.

use dom_config::NodeConfig;
use dom_node::node::DomNode;
use std::sync::Arc;
use std::time::Duration;
use tokio::time::{sleep, timeout};

/// Spawn a test node with custom config.
pub async fn spawn_node(config: NodeConfig) -> Arc<DomNode> {
    Arc::new(DomNode::init(config).expect("node init failed"))
}

/// Wait for node to reach a specific height (with timeout).
pub async fn wait_for_height(
    node: &Arc<DomNode>,
    target_height: u64,
    timeout_duration: Duration,
) -> Result<(), String> {
    timeout(timeout_duration, async {
        loop {
            let chain = node.chain.lock().await;
            let current_height = chain.tip_height.0;
            drop(chain);
            
            if current_height >= target_height {
                return Ok(());
            }
            
            sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .map_err(|_| format!("timeout waiting for height {}", target_height))?
}

/// Wait for node to have at least N peers connected.
pub async fn wait_for_peer_count(
    node: &Arc<DomNode>,
    min_peers: usize,
    timeout_duration: Duration,
) -> Result<(), String> {
    timeout(timeout_duration, async {
        loop {
            let peers = node.peers.lock().await;
            let count = peers.connected_peers().len();
            drop(peers);
            
            if count >= min_peers {
                return Ok(());
            }
            
            sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .map_err(|_| format!("timeout waiting for {} peers", min_peers))?
}

/// Mine N blocks on a node (blocks until done).
pub async fn mine_blocks(node: &Arc<DomNode>, count: u64) -> Result<(), String> {
    for _ in 0..count {
        dom_node::miner::mine_one_block(node.clone())
            .await
            .map_err(|e| format!("mining failed: {:?}", e))?;
    }
    Ok(())
}

/// Create a test NodeConfig with unique data directory.
pub fn test_config(name: &str, port: u16, mine: bool) -> NodeConfig {
    let data_dir = format!("/tmp/dom-test-{}", name);
    NodeConfig {
        network: dom_config::Network::Testnet,
        data_dir,
        p2p_listen_addr: format!("127.0.0.1:{}", port),
        max_inbound: 10,
        min_outbound: 1,
        dns_seeds: vec![],
        seed_peers: vec![],
        mine,
        miner_address: None,
        wallet_path: None,
        wallet_password: None,
        log_level: "debug".into(),
    }
}
