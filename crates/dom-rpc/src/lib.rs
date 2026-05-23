//! dom-rpc — HTTP RPC server for DOM Protocol nodes.
#![deny(unsafe_code)]

mod middleware;
mod token;
use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use dom_core::PROTOCOL_VERSION;
use serde::{Deserialize, Serialize};
use std::{net::SocketAddr, sync::Arc};
use tracing::{error, info, warn};

pub trait NodeHandle: Send + Sync + 'static {
    fn chain_height(&self) -> u64;
    fn mempool_size(&self) -> usize;
    fn mempool_tx_hashes(&self) -> Vec<[u8; 32]>;
    fn get_mempool_tx(&self, hash: &[u8; 32]) -> Option<MempoolTxInfo>;
    fn submit_tx(&self, tx_bytes: Vec<u8>) -> Result<[u8; 32], RpcError>;

    /// Get block header bytes by hash. Returns None if not found.
    fn get_block_header(&self, hash: &[u8; 32]) -> Option<Vec<u8>>;

    /// Get block hash at a given height. Returns None if height unknown.
    fn get_block_hash_at_height(&self, height: u64) -> Option<[u8; 32]>;

    /// Get UTXO info by commitment (33 bytes). Returns None if spent or never created.
    fn get_utxo(&self, commitment: &[u8; 33]) -> Option<UtxoInfo>;

    /// Get list of connected peers.
    fn get_peers(&self) -> Vec<PeerInfo> {
        Vec::new()
    }
    /// Get wallet balance at current height.
    fn get_wallet_balance(&self) -> Option<WalletBalanceResponse> {
        None
    }
    /// Build and submit a spend transaction from the node wallet.
    fn wallet_spend(&self, _req: SpendRequest) -> Result<[u8; 32], RpcError> {
        Err(RpcError::Internal("wallet not available".into()))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpendRequest {
    /// Recipient commitment (hex-encoded 33 bytes).
    pub recipient_commitment: String,
    /// Recipient blinding factor (hex-encoded 32 bytes).
    pub recipient_blinding: String,
    /// Amount in noms.
    pub amount_noms: u64,
    /// Fee in noms.
    pub fee_noms: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct WalletBalanceResponse {
    pub confirmed_noms: u64,
    pub immature_noms: u64,
    pub reserved_noms: u64,
    pub confirmed_dom: f64,
    pub immature_dom: f64,
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
    pub direction: String,
    pub connected_since: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct UtxoInfo {
    pub commitment: String,
    pub block_height: u64,
    pub is_coinbase: bool,
    pub is_mature: bool,
}

#[derive(Debug, thiserror::Error)]
pub enum RpcError {
    #[error("invalid hex: {0}")]
    InvalidHex(String),
    #[error("invalid transaction: {0}")]
    InvalidTx(String),
    #[error("rejected: {0}")]
    Rejected(String),
    #[error("overloaded: {0}")]
    Overloaded(String),
    #[error("internal: {0}")]
    Internal(String),
}

impl RpcError {
    fn status_code(&self) -> StatusCode {
        match self {
            Self::InvalidHex(_) | Self::InvalidTx(_) => StatusCode::BAD_REQUEST,
            Self::Rejected(_) => StatusCode::CONFLICT,
            Self::Overloaded(_) => StatusCode::SERVICE_UNAVAILABLE,
            Self::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}

#[derive(Debug, Serialize)]
struct ErrorResponse {
    error: String,
}

impl IntoResponse for RpcError {
    fn into_response(self) -> Response {
        let status = self.status_code();
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

#[derive(Debug, Deserialize)]
struct MempoolQuery {
    #[serde(default)]
    page: usize,
    #[serde(default = "default_mempool_limit")]
    limit: usize,
}

fn default_mempool_limit() -> usize {
    100
}

const MEMPOOL_MAX_LIMIT: usize = 1_000;

#[derive(Debug, Serialize)]
struct MempoolResponse {
    count: usize,
    total: usize,
    page: usize,
    limit: usize,
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

#[derive(Debug, Serialize)]
struct BlockHeaderResponse {
    height: u64,
    hash: String,
    prev_hash: String,
    timestamp: u64,
    target: String,
}

#[derive(Debug, Serialize)]
struct BlockNotFoundResponse {
    found: bool,
}

#[derive(Debug, Serialize)]
struct UtxoFoundResponse {
    found: bool,
    commitment: String,
    block_height: u64,
    is_coinbase: bool,
    is_mature: bool,
}

#[derive(Debug, Serialize)]
struct UtxoNotFoundResponse {
    found: bool,
}

use middleware::BearerToken;
use std::time::Duration;
use tower_http::{limit::RequestBodyLimitLayer, timeout::TimeoutLayer};

pub fn router(handle: Arc<dyn NodeHandle>, bearer_token: Arc<BearerToken>) -> Router {
    let body_limit = RequestBodyLimitLayer::new(1_024_000);
    let timeout = TimeoutLayer::new(Duration::from_secs(30));

    let rate_limit_read = middleware::rate_limit_read();
    let rate_limit_submit = middleware::rate_limit_submit();

    let public_routes = Router::new()
        .route("/status", get(status))
        .route("/mempool", get(mempool))
        .route("/tx/:tx_hash", get(get_tx))
        .route("/block/:height_or_hash", get(get_block))
        .route("/utxo/:commitment", get(get_utxo))
        .route("/wallet/balance", get(wallet_balance_handler))
        .layer(rate_limit_read);

    let submit_route = Router::new()
        .route("/tx/submit", post(submit_tx))
        .route("/wallet/spend", post(wallet_spend_handler))
        .layer(rate_limit_submit);

    let auth_routes = Router::new()
        .route("/peers", get(get_peers_handler))
        .route_layer(axum::middleware::from_fn_with_state(
            bearer_token,
            middleware::require_bearer_token,
        ));

    Router::new()
        .route("/health", get(health))
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

async fn shutdown_signal() {
    tokio::signal::ctrl_c()
        .await
        .expect("failed to install CTRL+C signal handler");
    info!("Shutdown signal received, stopping RPC server");
}

pub async fn serve(handle: Arc<dyn NodeHandle>, addr: SocketAddr) -> Result<(), RpcError> {
    let token_str = token::get_or_create_token()
        .map_err(|e| RpcError::Internal(format!("failed to init token: {e}")))?;
    let bearer_token = Arc::new(BearerToken(token_str));

    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .map_err(|e| RpcError::Internal(format!("failed to bind {addr}: {e}")))?;

    info!("RPC server listening on {addr}");

    // SmartIpKeyExtractor (used by tower_governor rate limit middleware) requires
    // ConnectInfo<SocketAddr> to be present in the request extensions. Default
    // axum::serve doesn't inject it. Use into_make_service_with_connect_info to
    // wire the peer SocketAddr through. Without this, every rate-limited route
    // returns 500 "Unable To Extract Key!".
    axum::serve(
        listener,
        router(handle, bearer_token).into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await
    .map_err(|e| RpcError::Internal(format!("server error: {e}")))?;

    warn!("RPC server stopped");
    Ok(())
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

async fn mempool(
    State(handle): State<Arc<dyn NodeHandle>>,
    Query(params): Query<MempoolQuery>,
) -> impl IntoResponse {
    let limit = params.limit.clamp(1, MEMPOOL_MAX_LIMIT);
    let page = params.page;

    let all_hashes = handle.mempool_tx_hashes();
    let total = all_hashes.len();

    let tx_hashes = all_hashes
        .into_iter()
        .skip(page * limit)
        .take(limit)
        .map(hex::encode)
        .collect::<Vec<_>>();

    let count = tx_hashes.len();

    Json(MempoolResponse {
        count,
        total,
        page,
        limit,
        tx_hashes,
    })
}

async fn submit_tx(
    State(handle): State<Arc<dyn NodeHandle>>,
    Json(payload): Json<SubmitTxRequest>,
) -> impl IntoResponse {
    let tx_bytes = match decode_hex(&payload.tx_hex) {
        Ok(b) => b,
        Err(e) => {
            warn!("submit_tx: invalid hex: {e}");
            return submit_error(e);
        }
    };
    match handle.submit_tx(tx_bytes) {
        Ok(hash) => (
            StatusCode::OK,
            Json(SubmitTxResponse {
                accepted: true,
                tx_hash: Some(hex::encode(hash)),
                error: None,
            }),
        ),
        Err(e) => {
            match &e {
                RpcError::Internal(msg) => error!("submit_tx: internal error: {msg}"),
                RpcError::Overloaded(msg) => warn!("submit_tx: overloaded: {msg}"),
                RpcError::Rejected(msg) => warn!("submit_tx: rejected: {msg}"),
                _ => warn!("submit_tx: error: {e}"),
            }
            submit_error(e)
        }
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

async fn get_block(
    State(handle): State<Arc<dyn NodeHandle>>,
    Path(height_or_hash): Path<String>,
) -> Result<Response, RpcError> {
    // Determine if input is height (all digits) or hash (64 hex chars)
    let hash = if height_or_hash.chars().all(|c| c.is_ascii_digit()) {
        let height: u64 = height_or_hash
            .parse()
            .map_err(|_| RpcError::InvalidHex("invalid height".into()))?;
        match handle.get_block_hash_at_height(height) {
            Some(h) => h,
            None => {
                return Ok((
                    StatusCode::NOT_FOUND,
                    Json(BlockNotFoundResponse { found: false }),
                )
                    .into_response())
            }
        }
    } else {
        parse_hash_hex(&height_or_hash)?
    };

    match handle.get_block_header(&hash) {
        Some(header_bytes) => {
            use dom_consensus::block::BlockHeader;
            use dom_serialization::DomDeserialize;
            let header = BlockHeader::from_bytes(&header_bytes)
                .map_err(|e| RpcError::Internal(format!("corrupt header: {e}")))?;
            Ok((
                StatusCode::OK,
                Json(BlockHeaderResponse {
                    height: header.height.0,
                    hash: hex::encode(hash),
                    prev_hash: hex::encode(header.prev_hash.as_bytes()),
                    timestamp: header.timestamp.0,
                    target: hex::encode(header.target.0.to_be_bytes()),
                }),
            )
                .into_response())
        }
        None => Ok((
            StatusCode::NOT_FOUND,
            Json(BlockNotFoundResponse { found: false }),
        )
            .into_response()),
    }
}

async fn get_utxo(
    State(handle): State<Arc<dyn NodeHandle>>,
    Path(commitment_hex): Path<String>,
) -> Result<Response, RpcError> {
    let bytes = decode_hex(&commitment_hex)?;
    if bytes.len() != 33 {
        return Err(RpcError::InvalidHex(
            "commitment must be 33 bytes (66 hex chars)".into(),
        ));
    }
    let mut commitment = [0u8; 33];
    commitment.copy_from_slice(&bytes);

    match handle.get_utxo(&commitment) {
        Some(info) => Ok((
            StatusCode::OK,
            Json(UtxoFoundResponse {
                found: true,
                commitment: commitment_hex,
                block_height: info.block_height,
                is_coinbase: info.is_coinbase,
                is_mature: info.is_mature,
            }),
        )
            .into_response()),
        None => Ok((
            StatusCode::NOT_FOUND,
            Json(UtxoNotFoundResponse { found: false }),
        )
            .into_response()),
    }
}

fn submit_error(err: RpcError) -> (StatusCode, Json<SubmitTxResponse>) {
    let status = err.status_code();
    (
        status,
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

async fn wallet_balance_handler(State(handle): State<Arc<dyn NodeHandle>>) -> impl IntoResponse {
    match handle.get_wallet_balance() {
        Some(bal) => (StatusCode::OK, Json(serde_json::to_value(bal).unwrap())).into_response(),
        None => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({"error": "wallet not available"})),
        )
            .into_response(),
    }
}

async fn wallet_spend_handler(
    State(handle): State<Arc<dyn NodeHandle>>,
    Json(req): Json<SpendRequest>,
) -> impl IntoResponse {
    match handle.wallet_spend(req) {
        Ok(tx_hash) => (
            StatusCode::OK,
            Json(serde_json::json!({"tx_hash": hex::encode(tx_hash)})),
        )
            .into_response(),
        Err(e) => {
            warn!("wallet_spend error: {e}");
            e.into_response()
        }
    }
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
        fn get_block_header(&self, _: &[u8; 32]) -> Option<Vec<u8>> {
            None
        }
        fn get_block_hash_at_height(&self, _: u64) -> Option<[u8; 32]> {
            None
        }
        fn get_utxo(&self, _: &[u8; 33]) -> Option<UtxoInfo> {
            None
        }
    }

    struct RejectNode;
    impl NodeHandle for RejectNode {
        fn chain_height(&self) -> u64 {
            0
        }
        fn mempool_size(&self) -> usize {
            0
        }
        fn mempool_tx_hashes(&self) -> Vec<[u8; 32]> {
            vec![]
        }
        fn get_mempool_tx(&self, _: &[u8; 32]) -> Option<MempoolTxInfo> {
            None
        }
        fn submit_tx(&self, _: Vec<u8>) -> Result<[u8; 32], RpcError> {
            Err(RpcError::Rejected("already in mempool".to_owned()))
        }
        fn get_block_header(&self, _: &[u8; 32]) -> Option<Vec<u8>> {
            None
        }
        fn get_block_hash_at_height(&self, _: u64) -> Option<[u8; 32]> {
            None
        }
        fn get_utxo(&self, _: &[u8; 33]) -> Option<UtxoInfo> {
            None
        }
    }

    struct OverloadNode;
    impl NodeHandle for OverloadNode {
        fn chain_height(&self) -> u64 {
            0
        }
        fn mempool_size(&self) -> usize {
            0
        }
        fn mempool_tx_hashes(&self) -> Vec<[u8; 32]> {
            vec![]
        }
        fn get_mempool_tx(&self, _: &[u8; 32]) -> Option<MempoolTxInfo> {
            None
        }
        fn submit_tx(&self, _: Vec<u8>) -> Result<[u8; 32], RpcError> {
            Err(RpcError::Overloaded("mempool full".to_owned()))
        }
        fn get_block_header(&self, _: &[u8; 32]) -> Option<Vec<u8>> {
            None
        }
        fn get_block_hash_at_height(&self, _: u64) -> Option<[u8; 32]> {
            None
        }
        fn get_utxo(&self, _: &[u8; 33]) -> Option<UtxoInfo> {
            None
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

    fn app_with<N: NodeHandle>(node: N) -> Router {
        let token = Arc::new(middleware::BearerToken("test-token".to_string()));
        router(Arc::new(node), token)
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
        let body = body_json(r).await;
        assert_eq!(body["count"], serde_json::json!(0));
        assert_eq!(body["total"], serde_json::json!(0));
        assert_eq!(body["page"], serde_json::json!(0));
    }

    #[tokio::test]
    async fn mempool_pagination_page_and_limit() {
        let node = MockNode::new(0);
        for i in 1u8..=5 {
            let mut hash = [0u8; 32];
            hash[0] = i;
            node.txs.lock().unwrap().insert(
                hash,
                MempoolTxInfo {
                    tx_hash: hash,
                    fee: 0,
                    fee_rate: 0,
                    weight: 0,
                },
            );
        }
        let app = app_with(node);

        let r = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/mempool?page=0&limit=2")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let body = body_json(r).await;
        assert_eq!(body["total"], serde_json::json!(5));
        assert_eq!(body["count"], serde_json::json!(2));
        assert_eq!(body["limit"], serde_json::json!(2));
        assert_eq!(body["page"], serde_json::json!(0));

        let r = app
            .oneshot(
                Request::builder()
                    .uri("/mempool?page=2&limit=2")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let body = body_json(r).await;
        assert_eq!(body["total"], serde_json::json!(5));
        assert_eq!(body["count"], serde_json::json!(1));
    }

    #[tokio::test]
    async fn mempool_limit_capped_at_1000() {
        let r = app()
            .oneshot(
                Request::builder()
                    .uri("/mempool?limit=9999")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let body = body_json(r).await;
        assert_eq!(body["limit"], serde_json::json!(1000));
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
    async fn submit_rejected_returns_409() {
        let valid_tx_hex = hex::encode(vec![0xdeu8; 64]);
        let r = app_with(RejectNode)
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/tx/submit")
                    .header("content-type", "application/json")
                    .body(Body::from(format!(r#"{{"tx_hex":"{valid_tx_hex}"}}"#)))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::CONFLICT);
        assert_eq!(body_json(r).await["accepted"], serde_json::json!(false));
    }

    #[tokio::test]
    async fn submit_overloaded_returns_503() {
        let valid_tx_hex = hex::encode(vec![0xdeu8; 64]);
        let r = app_with(OverloadNode)
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/tx/submit")
                    .header("content-type", "application/json")
                    .body(Body::from(format!(r#"{{"tx_hex":"{valid_tx_hex}"}}"#)))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(body_json(r).await["accepted"], serde_json::json!(false));
    }

    #[tokio::test]
    async fn unknown_tx_hash_returns_not_found() {
        let r = app()
            .oneshot(
                Request::builder()
                    .uri(format!("/tx/{}", "a".repeat(64)))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::OK);
        assert_eq!(body_json(r).await, serde_json::json!({"found": false}));
    }
}
