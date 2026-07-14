use dom_explorer::{BlockSummary, ChainProvider, ExplorerServer};
use dom_wallet::{BlockHeaderInfo, NodeRpc, NodeRpcClient, NodeStatus, RpcClientError};
use std::sync::Arc;
use tracing::warn;
use url::Url;

fn default_listen_addr() -> String {
    format!("127.0.0.1:{}", dom_core::EXPLORER_PORT)
}

fn default_node_url() -> String {
    format!("http://127.0.0.1:{}", dom_core::RPC_PORT_TESTNET)
}

#[derive(Debug, Clone)]
struct NodeChainProvider {
    client: NodeRpcClient,
}

impl NodeChainProvider {
    fn new(client: NodeRpcClient) -> Self {
        Self { client }
    }

    fn status(&self) -> Option<NodeStatus> {
        match self.client.status() {
            Ok(status) => Some(status),
            Err(err) => {
                log_rpc_error("status", &err);
                None
            }
        }
    }

    fn block_summary(header: BlockHeaderInfo) -> BlockSummary {
        BlockSummary {
            height: header.height,
            hash: hex::encode(header.hash),
            prev_hash: hex::encode(header.prev_hash),
            timestamp: header.timestamp,
            output_count: header.output_count,
            kernel_count: header.kernel_count,
        }
    }
}

impl ChainProvider for NodeChainProvider {
    fn chain_height(&self) -> u64 {
        self.status().map_or(0, |status| status.chain_height)
    }

    fn chain_tip_hash(&self) -> [u8; 32] {
        let Some(status) = self.status() else {
            return [0u8; 32];
        };
        if let Some(tip_hash) = status.tip_hash {
            return tip_hash;
        }
        self.client
            .block_at_height(status.chain_height)
            .ok()
            .flatten()
            .map_or([0u8; 32], |header| header.hash)
    }

    fn network(&self) -> String {
        self.status()
            .map(|status| status.network)
            .unwrap_or_else(|| "unknown".to_string())
    }

    fn get_block_at_height(&self, height: u64) -> Option<BlockSummary> {
        match self.client.block_at_height(height) {
            Ok(Some(header)) => Some(Self::block_summary(header)),
            Ok(None) => None,
            Err(err) => {
                log_rpc_error("block_at_height", &err);
                None
            }
        }
    }

    fn get_block_by_hash(&self, hash: &[u8; 32]) -> Option<BlockSummary> {
        match self.client.block_by_hash(hash) {
            Ok(Some(header)) => Some(Self::block_summary(header)),
            Ok(None) => None,
            Err(err) => {
                log_rpc_error("block_by_hash", &err);
                None
            }
        }
    }
}

fn log_rpc_error(endpoint: &str, err: &RpcClientError) {
    warn!(endpoint, error = %err, "node RPC read failed");
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            std::env::var("RUST_LOG").unwrap_or_else(|_| "dom_explorer=info".to_string()),
        )
        .init();

    let listen_addr =
        std::env::var("DOM_EXPLORER_LISTEN_ADDR").unwrap_or_else(|_| default_listen_addr());
    let node_url = std::env::var("DOM_EXPLORER_NODE_URL").unwrap_or_else(|_| default_node_url());
    let node_url = Url::parse(&node_url)?;
    let client = NodeRpcClient::builder(node_url)
        .user_agent(format!("dom-explorer/{}", env!("CARGO_PKG_VERSION")))
        .build()?;
    let provider = Arc::new(NodeChainProvider::new(client));

    ExplorerServer::new(listen_addr, provider).start().await
}

#[cfg(test)]
mod tests {
    #[test]
    fn defaults_use_authoritative_service_ports() {
        assert_eq!(
            super::default_listen_addr(),
            format!("127.0.0.1:{}", dom_core::EXPLORER_PORT)
        );
        assert_eq!(
            super::default_node_url(),
            format!("http://127.0.0.1:{}", dom_core::RPC_PORT_TESTNET)
        );
    }
}
