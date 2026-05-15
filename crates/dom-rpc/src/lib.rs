//! dom-rpc — HTTP RPC server for DOM Protocol nodes.
#![deny(unsafe_code)]

mod middleware;
mod token;
use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use dom_consensus::transaction::Transaction;
use dom_core::PROTOCOL_VERSION;
use dom_serialization::DomDeserialize;
use serde::{Deserialize, Serialize};
use std::{net::SocketAddr, sync::Arc};

pub trait NodeHandle: Send + Sync + 'static {
    fn chain_height(&self) -> u64;
    fn mempool_size(&self) -> usize;
    fn mempool_tx_hashes(&self) -> Vec<[u8; 32]>;
    fn get_mempool_tx(&self, hash: &[u8; 32]) -> Option<MempoolTxInfo>;
    fn submit_tx(&self, tx_bytes: Vec<u8>) -> Result<[u8; 32], RpcError>;

    /// Get list of connected peers. Returns empty vec by default (Phase 3).
    fn get_peers(&self) -> Vec<PeerInfo> {
        Vec::new()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MempoolTxInfo {
    pub tx_hash: [u8; 32],
    pub fee: u64,
    pub fee_rate: u64,
    pub weight: u32,
}

#[derive(Debug, Clone, Serialize)]
pub struct PeerInfo {
    pub addr: String,
    pub direction: String, // "inbound" | "outbound"
    pub connected_since: u64,
}

#[derive(Debug, thiserror::Error)]
pub enum RpcError {
    #[error("invalid hex: {0}")]
    InvalidHex(String),
    #[error("invalid transaction: {0}")]
    InvalidTx(String),
    #[error("rejected: {0}")]
    Rejected(String),
    #[error("internal: {0}")]
    Internal(String),
}

#[derive(Debug, Serialize)]
struct ErrorResponse {
    error: String,
}

impl IntoResponse for RpcError {
    fn into_response(self) -> Response {
        let status = match self {
            Self::InvalidHex(_) | Self::InvalidTx(_) | Self::Rejected(_) => StatusCode::BAD_REQUEST,
            Self::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
        };
        (
            status,
            Json(ErrorResponse {
                error: self.to_string(),
            }),
        )
            .into_response()
    }
}

#[derive(Debug, Serialize)]
struct HealthResponse {
    ok: bool,
}

#[derive(Debug, Serialize)]
struct StatusResponse {
    version: u32,
    chain_height: u64,
    mempool_size: usize,
    network: &'static str,
}

#[derive(Debug, Serialize)]
struct MempoolResponse {
    count: usize,
    tx_hashes: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct SubmitTxRequest {
    tx_hex: String,
}

#[derive(Debug, Serialize)]
struct SubmitTxResponse {
    accepted: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    tx_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

#[derive(Debug, Serialize)]
struct TxFoundResponse {
    found: bool,
    tx_hash: String,
    fee: u64,
    fee_rate: u64,
    weight: u32,
}

#[derive(Debug, Serialize)]
struct TxNotFoundResponse {
    found: bool,
}

use middleware::BearerToken;
use std::time::Duration;
use tower_http::{limit::RequestBodyLimitLayer, timeout::TimeoutLayer};

pub fn router(handle: Arc<dyn NodeHandle>, bearer_token: Arc<BearerToken>) -> Router {
    let body_limit = RequestBodyLimitLayer::new(1_024_000); // 1MB
    let timeout = TimeoutLayer::new(Duration::from_secs(30));

    let rate_limit_read = middleware::rate_limit_read();
    let rate_limit_submit = middleware::rate_limit_submit();

    // Public read endpoints with light rate limiting
    let public_routes = Router::new()
        .route("/status", get(status))
        .route("/mempool", get(mempool))
        .route("/tx/:tx_hash", get(get_tx))
        .layer(rate_limit_read);

    // Submit endpoint with strict rate limiting
    let submit_route = Router::new()
        .route("/tx/submit", post(submit_tx))
        .layer(rate_limit_submit);

    // Authenticated endpoints (Phase 3 placeholder)
    let auth_routes = Router::new()
        .route("/peers", get(get_peers_handler))
        .route_layer(axum::middleware::from_fn_with_state(
            bearer_token,
            middleware::require_bearer_token,
        ));

    // Combine all routes
    Router::new()
        .route("/health", get(health)) // No rate limit for load balancers
        .merge(public_routes)
        .merge(submit_route)
        .merge(auth_routes)
        .layer(axum::middleware::from_fn(middleware::cors_middleware))
        .layer(body_limit)
        .layer(timeout)
        .with_state(handle)
}

async fn get_peers_handler(State(handle): State<Arc<dyn NodeHandle>>) -> Json<Vec<PeerInfo>> {
    Json(handle.get_peers())
}

pub async fn serve(handle: Arc<dyn NodeHandle>, addr: SocketAddr) -> Result<(), RpcError> {
    // Initialize Bearer token
    let token_str = token::get_or_create_token()
        .map_err(|e| RpcError::Internal(format!("failed to init token: {e}")))?;
    let bearer_token = Arc::new(BearerToken(token_str));

    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .map_err(|e| RpcError::Internal(format!("failed to bind {addr}: {e}")))?;
    axum::serve(listener, router(handle, bearer_token))
        .await
        .map_err(|e| RpcError::Internal(format!("server error: {e}")))
}

async fn health() -> Json<HealthResponse> {
    Json(HealthResponse { ok: true })
}

async fn status(State(handle): State<Arc<dyn NodeHandle>>) -> Json<StatusResponse> {
    Json(StatusResponse {
        version: PROTOCOL_VERSION,
        chain_height: handle.chain_height(),
        mempool_size: handle.mempool_size(),
        network: "mainnet",
    })
}

async fn mempool(State(handle): State<Arc<dyn NodeHandle>>) -> Json<MempoolResponse> {
    let tx_hashes = handle
        .mempool_tx_hashes()
        .into_iter()
        .map(hex::encode)
        .collect::<Vec<_>>();
    Json(MempoolResponse {
        count: tx_hashes.len(),
        tx_hashes,
    })
}

async fn submit_tx(
    State(handle): State<Arc<dyn NodeHandle>>,
    Json(payload): Json<SubmitTxRequest>,
) -> impl IntoResponse {
    let tx_bytes = match decode_hex(&payload.tx_hex) {
        Ok(b) => b,
        Err(e) => return submit_error(e),
    };
    if let Err(e) = Transaction::from_bytes(&tx_bytes) {
        return submit_error(RpcError::InvalidTx(e.to_string()));
    }
    match handle.submit_tx(tx_bytes) {
        Ok(hash) => (
            StatusCode::OK,
            Json(SubmitTxResponse {
                accepted: true,
                tx_hash: Some(hex::encode(hash)),
                error: None,
            }),
        ),
        Err(e) => submit_error(e),
    }
}

async fn get_tx(
    State(handle): State<Arc<dyn NodeHandle>>,
    Path(tx_hash): Path<String>,
) -> Result<Response, RpcError> {
    let hash = parse_hash_hex(&tx_hash)?;
    if let Some(info) = handle.get_mempool_tx(&hash) {
        Ok((
            StatusCode::OK,
            Json(TxFoundResponse {
                found: true,
                tx_hash: hex::encode(info.tx_hash),
                fee: info.fee,
                fee_rate: info.fee_rate,
                weight: info.weight,
            }),
        )
            .into_response())
    } else {
        Ok((StatusCode::OK, Json(TxNotFoundResponse { found: false })).into_response())
    }
}

fn submit_error(err: RpcError) -> (StatusCode, Json<SubmitTxResponse>) {
    (
        StatusCode::BAD_REQUEST,
        Json(SubmitTxResponse {
            accepted: false,
            tx_hash: None,
            error: Some(err.to_string()),
        }),
    )
}

fn decode_hex(value: &str) -> Result<Vec<u8>, RpcError> {
    hex::decode(value).map_err(|e| RpcError::InvalidHex(e.to_string()))
}

fn parse_hash_hex(value: &str) -> Result<[u8; 32], RpcError> {
    decode_hex(value)?
        .try_into()
        .map_err(|_| RpcError::InvalidHex("hash must be exactly 32 bytes".to_owned()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{body::Body, http::Request};
    use http_body_util::BodyExt;
    use serde_json::Value;
    use std::{collections::HashMap, sync::Mutex};
    use tower::ServiceExt;

    #[derive(Default)]
    struct MockNode {
        height: u64,
        txs: Mutex<HashMap<[u8; 32], MempoolTxInfo>>,
    }

    impl MockNode {
        fn new(height: u64) -> Self {
            Self {
                height,
                txs: Mutex::new(HashMap::new()),
            }
        }
    }

    impl NodeHandle for MockNode {
        fn chain_height(&self) -> u64 {
            self.height
        }
        fn mempool_size(&self) -> usize {
            self.txs.lock().unwrap().len()
        }
        fn mempool_tx_hashes(&self) -> Vec<[u8; 32]> {
            self.txs.lock().unwrap().keys().copied().collect()
        }
        fn get_mempool_tx(&self, hash: &[u8; 32]) -> Option<MempoolTxInfo> {
            self.txs.lock().unwrap().get(hash).cloned()
        }
        fn submit_tx(&self, tx_bytes: Vec<u8>) -> Result<[u8; 32], RpcError> {
            if tx_bytes.is_empty() {
                return Err(RpcError::InvalidTx("empty".to_owned()));
            }
            let mut hash = [0u8; 32];
            let n = tx_bytes.len().min(32);
            hash[..n].copy_from_slice(&tx_bytes[..n]);
            self.txs.lock().unwrap().insert(
                hash,
                MempoolTxInfo {
                    tx_hash: hash,
                    fee: 0,
                    fee_rate: 0,
                    weight: 0,
                },
            );
            Ok(hash)
        }
    }

    async fn body_json(r: axum::response::Response) -> Value {
        let b = r.into_body().collect().await.unwrap().to_bytes();
        serde_json::from_slice(&b).unwrap()
    }

    fn app() -> Router {
        let token = Arc::new(middleware::BearerToken("test-token".to_string()));
        router(Arc::new(MockNode::new(42)), token)
    }

    #[tokio::test]
    async fn health_returns_ok() {
        let r = app()
            .oneshot(
                Request::builder()
                    .uri("/health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::OK);
        assert_eq!(body_json(r).await, serde_json::json!({"ok": true}));
    }

    #[tokio::test]
    async fn status_returns_protocol_version() {
        let r = app()
            .oneshot(
                Request::builder()
                    .uri("/status")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::OK);
        assert_eq!(
            body_json(r).await["version"],
            serde_json::json!(PROTOCOL_VERSION)
        );
    }

    #[tokio::test]
    async fn mempool_is_initially_empty() {
        let r = app()
            .oneshot(
                Request::builder()
                    .uri("/mempool")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::OK);
        assert_eq!(body_json(r).await["count"], serde_json::json!(0));
    }

    #[tokio::test]
    async fn submit_invalid_hex_returns_400() {
        let r = app()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/tx/submit")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"tx_hex":"not hex"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::BAD_REQUEST);
        assert_eq!(body_json(r).await["accepted"], serde_json::json!(false));
    }

    #[tokio::test]
    async fn unknown_tx_hash_returns_not_found() {
        let r = app()
            .oneshot(
                Request::builder()
                    .uri(&format!("/tx/{}", "a".repeat(64)))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::OK);
        assert_eq!(body_json(r).await, serde_json::json!({"found": false}));
    }
}
