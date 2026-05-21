//! DOM Protocol Testnet Faucet.
//!
//! Distributes small amounts of testnet DOM to requesting addresses,
//! with rate limiting per address.

use axum::{
    extract::{Json, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Router,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;
use tower_http::cors::CorsLayer;

const FAUCET_AMOUNT_NOMS: u64 = 10_000_000_000;
const RATE_LIMIT_SECS: u64 = 3600;

/// Backend trait: faucet needs to send transactions.
pub trait FaucetBackend: Send + Sync + 'static {
    fn send_to_address(&self, address: &str, amount_noms: u64) -> Result<[u8; 32], String>;
}

pub struct FaucetServer<B: FaucetBackend> {
    addr: String,
    state: Arc<FaucetState<B>>,
}

pub struct FaucetState<B: FaucetBackend> {
    last_requests: Mutex<HashMap<String, Instant>>,
    backend: Arc<B>,
}

impl<B: FaucetBackend> FaucetServer<B> {
    pub fn new(addr: String, backend: Arc<B>) -> Self {
        Self {
            addr,
            state: Arc::new(FaucetState {
                last_requests: Mutex::new(HashMap::new()),
                backend,
            }),
        }
    }

    pub async fn start(self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let app = Router::new()
            .route("/", get(root))
            .route("/api/request", post(request_coins::<B>))
            .layer(CorsLayer::permissive())
            .with_state(self.state);

        let listener = tokio::net::TcpListener::bind(&self.addr).await?;
        tracing::info!("Faucet listening on {}", self.addr);
        axum::serve(listener, app).await?;
        Ok(())
    }
}

async fn root() -> &'static str {
    "DOM Protocol Testnet Faucet v0.1"
}

#[derive(Deserialize)]
pub struct FaucetRequest {
    pub address: String,
}

#[derive(Serialize)]
pub struct FaucetResponse {
    pub success: bool,
    pub message: String,
    pub tx_hash: Option<String>,
    pub amount_noms: Option<u64>,
}

async fn request_coins<B: FaucetBackend>(
    State(state): State<Arc<FaucetState<B>>>,
    Json(req): Json<FaucetRequest>,
) -> impl IntoResponse {
    if req.address.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(FaucetResponse {
                success: false,
                message: "Address required".to_string(),
                tx_hash: None,
                amount_noms: None,
            }),
        );
    }

    let mut last_requests = state.last_requests.lock().await;
    if let Some(last_time) = last_requests.get(&req.address) {
        let elapsed = Instant::now().duration_since(*last_time);
        if elapsed < Duration::from_secs(RATE_LIMIT_SECS) {
            let remaining = Duration::from_secs(RATE_LIMIT_SECS) - elapsed;
            return (
                StatusCode::TOO_MANY_REQUESTS,
                Json(FaucetResponse {
                    success: false,
                    message: format!(
                        "Rate limited. Try again in {} minutes",
                        remaining.as_secs() / 60
                    ),
                    tx_hash: None,
                    amount_noms: None,
                }),
            );
        }
    }

    let tx_hash = match state.backend.send_to_address(&req.address, FAUCET_AMOUNT_NOMS) {
        Ok(h) => h,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(FaucetResponse {
                    success: false,
                    message: format!("Send failed: {}", e),
                    tx_hash: None,
                    amount_noms: None,
                }),
            );
        }
    };

    last_requests.insert(req.address.clone(), Instant::now());

    (
        StatusCode::OK,
        Json(FaucetResponse {
            success: true,
            message: format!("Sent {} DOM to {}", FAUCET_AMOUNT_NOMS / 1_000_000_000, req.address),
            tx_hash: Some(hex_encode(&tx_hash)),
            amount_noms: Some(FAUCET_AMOUNT_NOMS),
        }),
    )
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

    struct MockBackend;
    impl FaucetBackend for MockBackend {
        fn send_to_address(&self, _address: &str, _amount: u64) -> Result<[u8; 32], String> {
            Ok([0x42u8; 32])
        }
    }

    #[test]
    fn constants_correct() {
        assert_eq!(FAUCET_AMOUNT_NOMS, 10_000_000_000);
        assert_eq!(RATE_LIMIT_SECS, 3600);
    }

    #[test]
    fn mock_backend_works() {
        let b = MockBackend;
        let result = b.send_to_address("dom1qtest", 1000);
        assert!(result.is_ok());
        assert_eq!(result.unwrap()[0], 0x42);
    }

    #[test]
    fn hex_encode_works() {
        assert_eq!(hex_encode(&[0xca, 0xfe]), "cafe");
    }
}
