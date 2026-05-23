//! DOM Protocol Block Explorer REST API.
//!
//! Exposes blockchain data via HTTP endpoints for explorer UIs.

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::Json,
    routing::get,
    Router,
};
use serde::Serialize;
use std::sync::Arc;
use tower_http::cors::CorsLayer;

/// Backend trait: explorer needs read access to chain data.
/// Implemented by `dom-node` or any other chain provider.
pub trait ChainProvider: Send + Sync + 'static {
    fn chain_height(&self) -> u64;
    fn chain_tip_hash(&self) -> [u8; 32];
    fn get_block_at_height(&self, height: u64) -> Option<BlockSummary>;
    fn get_block_by_hash(&self, hash: &[u8; 32]) -> Option<BlockSummary>;
}

#[derive(Debug, Clone, Serialize)]
pub struct BlockSummary {
    pub height: u64,
    pub hash: String,
    pub prev_hash: String,
    pub timestamp: u64,
    pub output_count: u32,
    pub kernel_count: u32,
}

#[derive(Debug, Clone, Serialize)]
pub struct ChainInfo {
    pub height: u64,
    pub tip_hash: String,
    pub network: String,
}

pub struct ExplorerServer<P: ChainProvider> {
    addr: String,
    provider: Arc<P>,
}

impl<P: ChainProvider> ExplorerServer<P> {
    pub fn new(addr: String, provider: Arc<P>) -> Self {
        Self { addr, provider }
    }

    pub async fn start(self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let app = Router::new()
            .route("/", get(root))
            .route("/api/info", get(get_info::<P>))
            .route("/api/block/height/:height", get(get_block_by_height::<P>))
            .layer(CorsLayer::permissive())
            .with_state(self.provider);

        let listener = tokio::net::TcpListener::bind(&self.addr).await?;
        tracing::info!("Block explorer listening on {}", self.addr);
        axum::serve(listener, app).await?;
        Ok(())
    }
}

async fn root() -> &'static str {
    "DOM Protocol Block Explorer API v0.1"
}

async fn get_info<P: ChainProvider>(State(provider): State<Arc<P>>) -> Json<ChainInfo> {
    let hash = provider.chain_tip_hash();
    Json(ChainInfo {
        height: provider.chain_height(),
        tip_hash: hex_encode(&hash),
        network: "Testnet".to_string(),
    })
}

async fn get_block_by_height<P: ChainProvider>(
    State(provider): State<Arc<P>>,
    Path(height): Path<u64>,
) -> Result<Json<BlockSummary>, StatusCode> {
    provider
        .get_block_at_height(height)
        .map(Json)
        .ok_or(StatusCode::NOT_FOUND)
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockProvider;
    impl ChainProvider for MockProvider {
        fn chain_height(&self) -> u64 {
            100
        }
        fn chain_tip_hash(&self) -> [u8; 32] {
            [0x42u8; 32]
        }
        fn get_block_at_height(&self, height: u64) -> Option<BlockSummary> {
            Some(BlockSummary {
                height,
                hash: "deadbeef".to_string(),
                prev_hash: "cafebabe".to_string(),
                timestamp: 1747958400,
                output_count: 1,
                kernel_count: 1,
            })
        }
        fn get_block_by_hash(&self, _: &[u8; 32]) -> Option<BlockSummary> {
            None
        }
    }

    #[test]
    fn mock_provider_works() {
        let p = MockProvider;
        assert_eq!(p.chain_height(), 100);
        assert_eq!(p.chain_tip_hash()[0], 0x42);
    }

    #[test]
    fn hex_encode_works() {
        assert_eq!(hex_encode(&[0xde, 0xad]), "dead");
    }
}
