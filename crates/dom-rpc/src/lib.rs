//! dom-rpc — HTTP RPC server for DOM Protocol nodes.
#![deny(unsafe_code)]

mod middleware;
mod token;
use axum::{
    extract::{ConnectInfo, Path, Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use dom_core::PROTOCOL_VERSION;
use serde::{Deserialize, Serialize};
use std::{future::Future, net::SocketAddr, pin::Pin, sync::Arc};
use tracing::{error, info, warn};

pub trait NodeHandle: Send + Sync + 'static {
    fn chain_height(&self) -> u64;
    fn mempool_size(&self) -> usize;
    fn mempool_tx_hashes(&self) -> Vec<[u8; 32]>;
    fn get_mempool_tx(&self, hash: &[u8; 32]) -> Option<MempoolTxInfo>;
    fn submit_tx(&self, tx_bytes: Vec<u8>) -> Result<TxAdmission, RpcError>;

    /// Lowercase name of the network this node is configured for —
    /// `"mainnet"`, `"testnet"`, or `"regtest"`. Reported verbatim by
    /// `/status`. Implementations must read the node's actual config, never
    /// a hardcoded literal.
    fn network(&self) -> &'static str;

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

    /// Per-block chain scan for the heights `from..=to` (clamped — see
    /// [`MAX_SCAN_RANGE`]), plus the current tip. Read-only projection of the
    /// canonical chain the node already has on disk; serves the v2 wallet's
    /// `ChainSource`. Default is unsupported, so adding this method does not
    /// break existing implementations.
    ///
    /// Implementations MUST NOT block on a contended chain lock: if the chain is
    /// busy (mining / connecting a block), return a retriable
    /// [`RpcError::Overloaded`] immediately. Mining always has priority.
    fn scan_chain(&self, _from: u64, _to: u64) -> Result<ChainScan, RpcError> {
        Err(RpcError::Internal("chain scan not supported".into()))
    }

    /// Request the node's existing coordinated shutdown path. The RPC handler
    /// runs this future in the background so its `202 Accepted` can reach the
    /// caller before the RPC service begins winding down.
    fn request_shutdown(&self) -> ShutdownFuture {
        Box::pin(async {})
    }
}

/// Type-erased asynchronous request to the node's shutdown coordinator.
pub type ShutdownFuture = Pin<Box<dyn Future<Output = ()> + Send + 'static>>;

/// Maximum number of heights a single [`NodeHandle::scan_chain`] / `/chain/scan`
/// call returns. Bounds how long the chain lock is held so block connection is
/// never stalled; clients page across larger ranges.
pub const MAX_SCAN_RANGE: u64 = 1000;

/// Canonical tip (height + hash) returned alongside a scan.
#[derive(Debug, Clone)]
pub struct ChainTip {
    /// Tip height.
    pub height: u64,
    /// Tip block hash.
    pub hash: [u8; 32],
}

/// One block's scan data: every output commitment created and input commitment
/// spent, plus the block hash and total fees (fees serve seed-restore).
#[derive(Debug, Clone)]
pub struct ScanBlockData {
    /// Block height.
    pub height: u64,
    /// Block hash.
    pub hash: [u8; 32],
    /// Output commitments created in this block (coinbase included).
    pub output_commitments: Vec<[u8; 33]>,
    /// Input commitments spent in this block.
    pub input_commitments: Vec<[u8; 33]>,
    /// Total transaction fees in this block (noms).
    pub fees: u64,
}

/// Result of [`NodeHandle::scan_chain`]: the tip, the actual scanned range
/// (`to` is clamped to `min(requested_to, tip, from + MAX_SCAN_RANGE - 1)`), and
/// the per-block data. Clients page by continuing from `to + 1` until `to`
/// reaches `tip.height`.
#[derive(Debug, Clone)]
pub struct ChainScan {
    /// Current canonical tip.
    pub tip: ChainTip,
    /// Lowest height scanned (echo of the request).
    pub from: u64,
    /// Highest height scanned (clamped).
    pub to: u64,
    /// Per-block scan data for `from..=to` (heights with no block are omitted).
    pub blocks: Vec<ScanBlockData>,
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

/// Outcome of admitting a transaction to the node (`submit_tx`).
///
/// The tx is in the local mempool either way; `relayed` reports whether the
/// node actually handed it to a peer. When the node has no connected peers (or
/// no live relay subscribers), `relayed` is `false`: the mempool is volatile
/// (RFC-0012 §1), so a tx accepted-but-not-relayed can be silently lost on
/// restart. The RPC surfaces this as a warning so the wallet can retransmit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TxAdmission {
    pub tx_hash: [u8; 32],
    pub relayed: bool,
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
    /// Whether the node actually relayed the tx to a peer. `false` means it was
    /// accepted into the local (volatile) mempool but no peer received it yet.
    relayed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    tx_hash: Option<String>,
    /// Non-fatal advisory (e.g. accepted but not relayed: no peers connected).
    #[serde(skip_serializing_if = "Option::is_none")]
    warning: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

/// Advisory returned when a tx is accepted locally but not relayed onward.
const WARN_ACCEPTED_NOT_RELAYED: &str =
    "no peers connected; tx will be retransmitted when the node reconnects";

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
    let rate_limit_auth_read = middleware::rate_limit_read();
    let rate_limit_submit = middleware::rate_limit_submit();
    let rate_limit_wallet_spend = middleware::rate_limit_submit();

    let public_routes = Router::new()
        .route("/status", get(status))
        .route("/mempool", get(mempool))
        .route("/tx/:tx_hash", get(get_tx))
        .route("/block/:height_or_hash", get(get_block))
        .route("/utxo/:commitment", get(get_utxo))
        .layer(rate_limit_read);

    let submit_route = Router::new()
        .route("/tx/submit", post(submit_tx))
        .layer(rate_limit_submit);

    let auth_read_routes = Router::new()
        .route("/wallet/balance", get(wallet_balance_handler))
        .route("/chain/scan", get(chain_scan_handler))
        .route("/build-info", get(build_info_handler))
        .route("/shutdown", post(shutdown_handler))
        .layer(rate_limit_auth_read);

    let auth_routes = Router::new()
        .route("/peers", get(get_peers_handler))
        .merge(auth_read_routes)
        .route(
            "/wallet/spend",
            post(wallet_spend_handler).layer(rate_limit_wallet_spend),
        )
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

async fn build_info_handler() -> Json<serde_json::Value> {
    Json(serde_json::json!({"commit": env!("DOM_RPC_BUILD_COMMIT")}))
}

/// Request a graceful node shutdown after authenticating a local caller.
///
/// The loopback check intentionally uses the TCP peer address, never a
/// forwarded header, so it remains effective even when the RPC listener is
/// configured on a non-loopback interface.
async fn shutdown_handler(
    State(handle): State<Arc<dyn NodeHandle>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
) -> StatusCode {
    if !peer.ip().is_loopback() {
        warn!(%peer, "refusing shutdown request from non-loopback peer");
        return StatusCode::FORBIDDEN;
    }

    tokio::spawn(handle.request_shutdown());
    StatusCode::ACCEPTED
}

async fn shutdown_signal() {
    tokio::signal::ctrl_c()
        .await
        .expect("failed to install CTRL+C signal handler");
    info!("Shutdown signal received, stopping RPC server");
}

/// Bind the RPC TCP listener.
///
/// Split out from `serve` so callers can fail fast on bind errors
/// (EADDRINUSE, permission, etc.) before spawning the accept loop in
/// a detached task. The caller passes the returned listener to `serve`.
pub async fn bind(addr: SocketAddr) -> Result<tokio::net::TcpListener, RpcError> {
    tokio::net::TcpListener::bind(addr)
        .await
        .map_err(|e| RpcError::Internal(format!("failed to bind {addr}: {e}")))
}

/// Run the RPC accept loop on an already-bound listener.
///
/// Use `bind(addr)` first so bind failures surface synchronously to the
/// caller; once this future is spawned, only per-request errors are
/// possible — those are logged but never propagated.
pub async fn serve(
    handle: Arc<dyn NodeHandle>,
    listener: tokio::net::TcpListener,
) -> Result<(), RpcError> {
    serve_with_token(handle, listener, None).await
}

/// Run the RPC accept loop using an explicit bearer token when supplied.
///
/// Embedded callers use this to avoid putting bearer tokens in process-global
/// environment variables. Passing `None` preserves the standalone fallback path.
pub async fn serve_with_token(
    handle: Arc<dyn NodeHandle>,
    listener: tokio::net::TcpListener,
    configured_token: Option<String>,
) -> Result<(), RpcError> {
    serve_with_token_until_shutdown(handle, listener, configured_token, shutdown_signal()).await
}

/// Run the RPC accept loop with caller-owned graceful shutdown.
///
/// Embedders with a process-wide supervisor must provide its shutdown future
/// here so the RPC service cannot consume a signal independently and appear
/// to have exited unexpectedly to that supervisor.
pub async fn serve_with_token_until_shutdown<F>(
    handle: Arc<dyn NodeHandle>,
    listener: tokio::net::TcpListener,
    configured_token: Option<String>,
    shutdown: F,
) -> Result<(), RpcError>
where
    F: Future<Output = ()> + Send + 'static,
{
    let token_str = token::get_or_create_token_with_config(configured_token.as_deref())
        .map_err(|e| RpcError::Internal(format!("failed to init token: {e}")))?;
    let bearer_token = Arc::new(BearerToken(token_str));

    let local = listener
        .local_addr()
        .map_err(|e| RpcError::Internal(format!("local_addr: {e}")))?;
    info!("RPC server listening on {local}");

    // SmartIpKeyExtractor (used by tower_governor rate limit middleware) requires
    // ConnectInfo<SocketAddr> to be present in the request extensions. Default
    // axum::serve doesn't inject it. Use into_make_service_with_connect_info to
    // wire the peer SocketAddr through. Without this, every rate-limited route
    // returns 500 "Unable To Extract Key!".
    axum::serve(
        listener,
        router(handle, bearer_token).into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown)
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
        network: handle.network(),
    })
}

async fn mempool(
    State(handle): State<Arc<dyn NodeHandle>>,
    Query(params): Query<MempoolQuery>,
) -> Response {
    let limit = params.limit.clamp(1, MEMPOOL_MAX_LIMIT);
    let page = params.page;

    // `page` is client-controlled and unbounded; `page * limit` (usize) can
    // overflow (panic under overflow-checks, silent wrap in release). Compute
    // the offset with a checked multiply and reject an overflowing page with a
    // clean 400 instead. A valid page past the end is handled by `skip` below.
    let offset = match page.checked_mul(limit) {
        Some(offset) => offset,
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "page too large".to_owned(),
                }),
            )
                .into_response()
        }
    };

    let all_hashes = handle.mempool_tx_hashes();
    let total = all_hashes.len();

    let tx_hashes = all_hashes
        .into_iter()
        .skip(offset)
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
    .into_response()
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
        Ok(admission) => {
            let warning = if admission.relayed {
                None
            } else {
                info!(
                    "submit_tx: accepted tx {} but not relayed (no peers connected)",
                    hex::encode(admission.tx_hash)
                );
                Some(WARN_ACCEPTED_NOT_RELAYED.to_owned())
            };
            (
                StatusCode::OK,
                Json(SubmitTxResponse {
                    accepted: true,
                    relayed: admission.relayed,
                    tx_hash: Some(hex::encode(admission.tx_hash)),
                    warning,
                    error: None,
                }),
            )
        }
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
            relayed: false,
            tx_hash: None,
            warning: None,
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

/// Query for `/chain/scan?from=<u64>&to=<u64>`.
#[derive(Debug, Deserialize)]
struct ScanQuery {
    from: u64,
    to: u64,
}

#[derive(Debug, Serialize)]
struct TipDto {
    height: u64,
    hash: String,
}

#[derive(Debug, Serialize)]
struct ScanBlockDto {
    height: u64,
    hash: String,
    output_commitments: Vec<String>,
    input_commitments: Vec<String>,
    fees: u64,
}

#[derive(Debug, Serialize)]
struct ChainScanResponse {
    tip: TipDto,
    from: u64,
    to: u64,
    blocks: Vec<ScanBlockDto>,
}

/// `GET /chain/scan?from&to` — per-block output/input commitments for a height
/// range (clamped to [`MAX_SCAN_RANGE`] and the tip), plus the tip. An
/// authenticated node projection. A node that does not support it answers with the trait default
/// error; a busy chain answers a retriable 503.
async fn chain_scan_handler(
    State(handle): State<Arc<dyn NodeHandle>>,
    Query(q): Query<ScanQuery>,
) -> impl IntoResponse {
    match handle.scan_chain(q.from, q.to) {
        Ok(scan) => {
            let blocks = scan
                .blocks
                .into_iter()
                .map(|b| ScanBlockDto {
                    height: b.height,
                    hash: hex::encode(b.hash),
                    output_commitments: b.output_commitments.iter().map(hex::encode).collect(),
                    input_commitments: b.input_commitments.iter().map(hex::encode).collect(),
                    fees: b.fees,
                })
                .collect();
            Json(ChainScanResponse {
                tip: TipDto {
                    height: scan.tip.height,
                    hash: hex::encode(scan.tip.hash),
                },
                from: scan.from,
                to: scan.to,
                blocks,
            })
            .into_response()
        }
        Err(e) => e.into_response(),
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
    use std::{
        collections::HashMap,
        sync::{
            atomic::{AtomicBool, Ordering},
            Arc, Mutex,
        },
        time::Duration,
    };
    use tower::ServiceExt;

    #[derive(Default)]
    struct MockNode {
        height: u64,
        txs: Mutex<HashMap<[u8; 32], MempoolTxInfo>>,
        network: &'static str,
        /// When true, submit_tx reports the tx as accepted-but-not-relayed
        /// (the no-peers case exercised by F3).
        no_peers: bool,
        /// Canned chain scan for `/chain/scan` tests; `None` → unsupported.
        scan: Option<ChainScan>,
        shutdown_requested: Arc<AtomicBool>,
    }

    impl MockNode {
        fn new(height: u64) -> Self {
            Self {
                height,
                txs: Mutex::new(HashMap::new()),
                network: "regtest",
                no_peers: false,
                scan: None,
                shutdown_requested: Arc::new(AtomicBool::new(false)),
            }
        }

        /// A node serving a canned chain scan.
        fn with_scan(height: u64, scan: ChainScan) -> Self {
            Self {
                scan: Some(scan),
                ..Self::new(height)
            }
        }

        fn with_network(height: u64, network: &'static str) -> Self {
            Self {
                network,
                ..Self::new(height)
            }
        }

        /// A node that accepts txs but has no peers to relay to.
        fn no_peers(height: u64) -> Self {
            Self {
                no_peers: true,
                ..Self::new(height)
            }
        }
    }

    impl NodeHandle for MockNode {
        fn request_shutdown(&self) -> ShutdownFuture {
            let requested = Arc::clone(&self.shutdown_requested);
            Box::pin(async move {
                requested.store(true, Ordering::SeqCst);
            })
        }

        fn chain_height(&self) -> u64 {
            self.height
        }
        fn scan_chain(&self, from: u64, to: u64) -> Result<ChainScan, RpcError> {
            match &self.scan {
                Some(s) => {
                    let mut out = s.clone();
                    out.from = from;
                    if from > to {
                        out.blocks.clear();
                        out.to = from.saturating_sub(1);
                    } else {
                        out.to = to.min(s.tip.height);
                    }
                    Ok(out)
                }
                None => Err(RpcError::Internal("chain scan not supported".into())),
            }
        }
        fn mempool_size(&self) -> usize {
            self.txs.lock().unwrap().len()
        }
        fn network(&self) -> &'static str {
            self.network
        }
        fn mempool_tx_hashes(&self) -> Vec<[u8; 32]> {
            self.txs.lock().unwrap().keys().copied().collect()
        }
        fn get_mempool_tx(&self, hash: &[u8; 32]) -> Option<MempoolTxInfo> {
            self.txs.lock().unwrap().get(hash).cloned()
        }
        fn submit_tx(&self, tx_bytes: Vec<u8>) -> Result<TxAdmission, RpcError> {
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
            Ok(TxAdmission {
                tx_hash: hash,
                relayed: !self.no_peers,
            })
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
        fn get_wallet_balance(&self) -> Option<WalletBalanceResponse> {
            Some(WalletBalanceResponse {
                confirmed_noms: 42,
                immature_noms: 0,
                reserved_noms: 0,
                confirmed_dom: 0.000_000_042,
                immature_dom: 0.0,
            })
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
        fn network(&self) -> &'static str {
            "regtest"
        }
        fn mempool_tx_hashes(&self) -> Vec<[u8; 32]> {
            vec![]
        }
        fn get_mempool_tx(&self, _: &[u8; 32]) -> Option<MempoolTxInfo> {
            None
        }
        fn submit_tx(&self, _: Vec<u8>) -> Result<TxAdmission, RpcError> {
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
        fn network(&self) -> &'static str {
            "regtest"
        }
        fn mempool_tx_hashes(&self) -> Vec<[u8; 32]> {
            vec![]
        }
        fn get_mempool_tx(&self, _: &[u8; 32]) -> Option<MempoolTxInfo> {
            None
        }
        fn submit_tx(&self, _: Vec<u8>) -> Result<TxAdmission, RpcError> {
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

    fn wallet_spend_body() -> String {
        serde_json::json!({
            "recipient_commitment": "02".repeat(33),
            "recipient_blinding": "11".repeat(32),
            "amount_noms": 1,
            "fee_noms": 1
        })
        .to_string()
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
        let body = body_json(r).await;
        assert_eq!(body["version"], serde_json::json!(PROTOCOL_VERSION));
        // app()'s MockNode is configured for regtest, so /status must report
        // it — never the old hardcoded "mainnet" (DOM-AUDIT-006).
        assert_eq!(body["network"], serde_json::json!("regtest"));
    }

    #[tokio::test]
    async fn supervisor_owned_shutdown_stops_rpc_cleanly() {
        let listener = bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
        let server = tokio::spawn(serve_with_token_until_shutdown(
            Arc::new(MockNode::new(0)),
            listener,
            Some("test-token".to_owned()),
            async move {
                let _ = shutdown_rx.await;
            },
        ));

        shutdown_tx.send(()).unwrap();
        let result = tokio::time::timeout(std::time::Duration::from_secs(2), server)
            .await
            .expect("RPC server should honor the supervisor shutdown")
            .expect("RPC server task should not panic");
        assert!(result.is_ok(), "supervisor shutdown must be a clean exit");
    }

    #[tokio::test]
    async fn status_reports_configured_network_not_mainnet() {
        // A node configured for testnet must not report itself as mainnet.
        let app = app_with(MockNode::with_network(7, "testnet"));
        let r = app
            .oneshot(
                Request::builder()
                    .uri("/status")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::OK);
        let body = body_json(r).await;
        assert_eq!(body["network"], serde_json::json!("testnet"));
        assert_ne!(body["network"], serde_json::json!("mainnet"));
    }

    #[tokio::test]
    async fn wallet_balance_requires_bearer_and_succeeds_with_it() {
        let unauthenticated = app()
            .oneshot(
                Request::builder()
                    .uri("/wallet/balance")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(unauthenticated.status(), StatusCode::UNAUTHORIZED);

        let authenticated = app()
            .oneshot(
                Request::builder()
                    .uri("/wallet/balance")
                    .header("authorization", "Bearer test-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(authenticated.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn build_info_requires_bearer_and_returns_a_commit() {
        let unauthenticated = app()
            .oneshot(
                Request::builder()
                    .uri("/build-info")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(unauthenticated.status(), StatusCode::UNAUTHORIZED);

        let authenticated = app()
            .oneshot(
                Request::builder()
                    .uri("/build-info")
                    .header("authorization", "Bearer test-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(authenticated.status(), StatusCode::OK);
        assert!(body_json(authenticated).await["commit"]
            .as_str()
            .is_some_and(|commit| !commit.is_empty()));
    }

    #[tokio::test]
    async fn shutdown_requires_bearer() {
        let r = app()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/shutdown")
                    .extension(ConnectInfo(
                        "127.0.0.1:12345".parse::<SocketAddr>().unwrap(),
                    ))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn shutdown_refuses_non_loopback_peer() {
        let node = MockNode::new(0);
        let requested = Arc::clone(&node.shutdown_requested);
        let r = app_with(node)
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/shutdown")
                    .header("authorization", "Bearer test-token")
                    .extension(ConnectInfo(
                        "192.0.2.1:12345".parse::<SocketAddr>().unwrap(),
                    ))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::FORBIDDEN);
        assert!(!requested.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn shutdown_from_loopback_returns_accepted_then_requests_shutdown() {
        let node = MockNode::new(0);
        let requested = Arc::clone(&node.shutdown_requested);
        let r = app_with(node)
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/shutdown")
                    .header("authorization", "Bearer test-token")
                    .extension(ConnectInfo(
                        "127.0.0.1:12345".parse::<SocketAddr>().unwrap(),
                    ))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::ACCEPTED);

        tokio::time::timeout(Duration::from_secs(1), async {
            while !requested.load(Ordering::SeqCst) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("shutdown request task should run after the 202 response");
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
    async fn mempool_pagination_overflow_returns_400() {
        // A client-controlled `page` of usize::MAX makes `page * limit` overflow.
        // Before the fix this panics under overflow-checks (debug); after it must
        // be a clean 400 — never a panic and never a 500.
        let r = app()
            .oneshot(
                Request::builder()
                    .uri(format!("/mempool?page={}", usize::MAX))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            body_json(r).await,
            serde_json::json!({"error": "page too large"})
        );
    }

    #[tokio::test]
    async fn mempool_normal_pagination_unchanged() {
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
        let r = app_with(node)
            .oneshot(
                Request::builder()
                    .uri("/mempool?page=1&limit=2")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::OK);
        let body = body_json(r).await;
        assert_eq!(body["total"], serde_json::json!(5));
        assert_eq!(body["count"], serde_json::json!(2));
        assert_eq!(body["page"], serde_json::json!(1));
        assert_eq!(body["limit"], serde_json::json!(2));
        assert_eq!(body["tx_hashes"].as_array().unwrap().len(), 2);
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
    async fn submit_without_bearer_remains_public() {
        let valid_tx_hex = hex::encode(vec![0xdeu8; 64]);
        let r = app()
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

        assert_eq!(r.status(), StatusCode::OK);
        let body = body_json(r).await;
        assert_eq!(body["accepted"], serde_json::json!(true));
        assert_eq!(body["relayed"], serde_json::json!(true));
        assert!(body.get("warning").is_none());
    }

    #[tokio::test]
    async fn submit_with_no_peers_returns_accepted_warning() {
        let valid_tx_hex = hex::encode(vec![0xdeu8; 64]);
        let r = app_with(MockNode::no_peers(42))
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

        assert_eq!(r.status(), StatusCode::OK);
        let body = body_json(r).await;
        assert_eq!(body["accepted"], serde_json::json!(true));
        assert_eq!(body["relayed"], serde_json::json!(false));
        assert_eq!(
            body["warning"],
            serde_json::json!(WARN_ACCEPTED_NOT_RELAYED)
        );
    }

    #[tokio::test]
    async fn wallet_spend_without_bearer_returns_401() {
        let r = app()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/wallet/spend")
                    .header("content-type", "application/json")
                    .body(Body::from(wallet_spend_body()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(r.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn wallet_spend_with_valid_bearer_reaches_handler() {
        let r = app()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/wallet/spend")
                    .header("content-type", "application/json")
                    .header("authorization", "Bearer test-token")
                    .body(Body::from(wallet_spend_body()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(r.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(
            body_json(r).await["error"],
            serde_json::json!("internal: wallet not available")
        );
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

    fn canned_scan() -> ChainScan {
        ChainScan {
            tip: ChainTip {
                height: 2,
                hash: [0xc2u8; 32],
            },
            from: 0,
            to: 2,
            blocks: vec![
                ScanBlockData {
                    height: 1,
                    hash: [0x11u8; 32],
                    output_commitments: vec![[0xa1u8; 33]],
                    input_commitments: vec![],
                    fees: 0,
                },
                ScanBlockData {
                    height: 2,
                    hash: [0x22u8; 32],
                    output_commitments: vec![[0xb2u8; 33]],
                    input_commitments: vec![[0xa1u8; 33]],
                    fees: 7,
                },
            ],
        }
    }

    #[tokio::test]
    async fn chain_scan_requires_bearer_and_succeeds_with_it() {
        let unauthenticated = app_with(MockNode::with_scan(2, canned_scan()))
            .oneshot(
                Request::builder()
                    .uri("/chain/scan?from=0&to=2")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(unauthenticated.status(), StatusCode::UNAUTHORIZED);

        let authenticated = app_with(MockNode::with_scan(2, canned_scan()))
            .oneshot(
                Request::builder()
                    .uri("/chain/scan?from=0&to=2")
                    .header("authorization", "Bearer test-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(authenticated.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn chain_scan_returns_blocks_and_tip() {
        let r = app_with(MockNode::with_scan(2, canned_scan()))
            .oneshot(
                Request::builder()
                    .uri("/chain/scan?from=0&to=2")
                    .header("authorization", "Bearer test-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::OK);
        let j = body_json(r).await;
        assert_eq!(j["tip"]["height"], serde_json::json!(2));
        assert_eq!(j["tip"]["hash"], serde_json::json!("c2".repeat(32)));
        assert_eq!(j["blocks"].as_array().unwrap().len(), 2);
        assert_eq!(j["blocks"][1]["height"], serde_json::json!(2));
        assert_eq!(j["blocks"][1]["fees"], serde_json::json!(7));
        assert_eq!(
            j["blocks"][1]["output_commitments"][0],
            serde_json::json!("b2".repeat(33))
        );
        assert_eq!(
            j["blocks"][1]["input_commitments"][0],
            serde_json::json!("a1".repeat(33))
        );
    }

    #[tokio::test]
    async fn chain_scan_unsupported_node_errors() {
        // The default node (no scan) returns the trait default error.
        let r = app()
            .oneshot(
                Request::builder()
                    .uri("/chain/scan?from=0&to=2")
                    .header("authorization", "Bearer test-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn chain_scan_empty_range_returns_only_tip() {
        let r = app_with(MockNode::with_scan(2, canned_scan()))
            .oneshot(
                Request::builder()
                    .uri("/chain/scan?from=5&to=0")
                    .header("authorization", "Bearer test-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::OK);
        let j = body_json(r).await;
        assert_eq!(j["tip"]["height"], serde_json::json!(2));
        assert_eq!(j["blocks"].as_array().unwrap().len(), 0);
    }

    // ───────────────────────────────────────────────────────────────────────
    // dom-shield TEST FAMILIES (dom-rpc) — Soren Planck
    //
    // STRUCTURAL NOTE (why these live in `#[cfg(test)]` and not in tests/*.rs):
    // `pub fn router(handle, bearer_token: Arc<BearerToken>)` takes a type from
    // the PRIVATE module `mod middleware;` (`BearerToken` is never re-exported).
    // An external integration test (`tests/*.rs`) cannot name `BearerToken`, so
    // it cannot construct the second argument and cannot call `router()`. The
    // only publicly reachable entry is `serve_with_token` over a real bound
    // socket (which, in non-test cfg, would also write ~/.dom/rpc_token and use
    // SmartIpKeyExtractor). The router HTTP surface is therefore exercised here,
    // in-crate, against the same tower `oneshot` harness the existing tests use.
    // This is a probe over UNREACHABLE-PUBLIC behavior (HARD RULE 1), not a
    // production change. No production logic is touched.
    // ───────────────────────────────────────────────────────────────────────

    // ===== KAV-negativo (auth): coverage gaps beyond the 6 existing bearer tests
    //
    // The 6 existing middleware tests (correct/wrong-same-len/short/long/missing/
    // non-Bearer-scheme) live in middleware.rs against a synthetic router. These
    // exercise the REAL production router (`router()` wiring), which is where the
    // /peers route was never tested for auth — a genuine coverage gap.

    /// AUTH-1 — /peers requires the bearer token: no header → 401 (coverage gap;
    /// /peers auth was never tested through the real router).
    #[tokio::test]
    async fn peers_without_bearer_returns_401() {
        let r = app()
            .oneshot(
                Request::builder()
                    .uri("/peers")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::UNAUTHORIZED);
    }

    /// AUTH-2 — /peers WITH the valid bearer token reaches the handler (200 +
    /// JSON array). Proves the gate lets a correct token through on the real
    /// router, not just rejects.
    #[tokio::test]
    async fn peers_with_valid_bearer_reaches_handler() {
        let r = app()
            .oneshot(
                Request::builder()
                    .uri("/peers")
                    .header("authorization", "Bearer test-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::OK);
        // default get_peers() is an empty Vec.
        assert_eq!(body_json(r).await, serde_json::json!([]));
    }

    /// AUTH-3 — wrong scheme case ("bearer " lowercase) is rejected. The
    /// production check is `header.starts_with("Bearer ")` — case-sensitive by
    /// construction; an RFC-7235 scheme is case-insensitive, so a lowercase
    /// "bearer" is rejected here. Documents the exact (strict) behavior.
    #[tokio::test]
    async fn peers_lowercase_bearer_scheme_rejected() {
        let r = app()
            .oneshot(
                Request::builder()
                    .uri("/peers")
                    .header("authorization", "bearer test-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::UNAUTHORIZED);
    }

    /// AUTH-4 — empty value after "Bearer " is rejected when the configured
    /// token is non-empty (different length → ct_eq false).
    #[tokio::test]
    async fn peers_empty_bearer_value_rejected() {
        let r = app()
            .oneshot(
                Request::builder()
                    .uri("/peers")
                    .header("authorization", "Bearer ")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::UNAUTHORIZED);
    }

    /// AUTH-5 — an EMPTY configured token must never authorize.
    ///
    /// RED (CONFIRMED BUG, NEW). With `BearerToken("")`, a request carrying
    /// `Authorization: Bearer ` (empty value after the scheme) is AUTHORIZED
    /// (200) instead of rejected (401). Mechanism in `require_bearer_token`:
    /// header `"Bearer "` passes `starts_with("Bearer ")` → `provided =
    /// &header[7..] = ""` → `"".ct_eq("")` is TRUE → `next.run`. This is an
    /// auth bypass for any deployment whose configured token is empty. Note the
    /// upstream `get_or_create_token*` paths skip empty tokens, but `router()`
    /// (a public API) accepts any `BearerToken`, and an empty token reaching the
    /// middleware authorizes. The middleware now rejects empty configured
    /// tokens and empty bearer values before the constant-time compare.
    #[tokio::test]
    async fn empty_configured_token_never_authorizes() {
        let token = Arc::new(middleware::BearerToken(String::new()));
        let app = router(Arc::new(MockNode::new(1)), token);
        let r = app
            .oneshot(
                Request::builder()
                    .uri("/peers")
                    .header("authorization", "Bearer ")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            r.status(),
            StatusCode::UNAUTHORIZED,
            "empty configured token must never authorize any request"
        );
    }

    // ===== KAV-negativo (parse): get_tx / get_block / get_utxo
    //
    // Each parses untrusted path segments. Assert a clean 4xx (or NOT_FOUND for
    // the structurally-valid-but-absent case) — never a panic, never a 500.

    /// PARSE-1 — /tx/<non-hex> → 400 InvalidHex (parse_hash_hex via decode_hex).
    #[tokio::test]
    async fn get_tx_non_hex_returns_400() {
        let r = app()
            .oneshot(
                Request::builder()
                    .uri("/tx/zzzznothex")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::BAD_REQUEST);
    }

    /// PARSE-2 — /tx/<valid hex, wrong length> → 400 ("hash must be exactly 32
    /// bytes"). 30 hex chars = 15 bytes decodes fine but try_into::<[u8;32]>
    /// fails.
    #[tokio::test]
    async fn get_tx_wrong_length_hex_returns_400() {
        let r = app()
            .oneshot(
                Request::builder()
                    .uri(format!("/tx/{}", "ab".repeat(15))) // 30 chars = 15 bytes
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::BAD_REQUEST);
    }

    /// PARSE-3 — /tx/<odd-length hex> → 400 (hex::decode rejects odd length;
    /// must surface as InvalidHex, not panic).
    #[tokio::test]
    async fn get_tx_odd_length_hex_returns_400() {
        let r = app()
            .oneshot(
                Request::builder()
                    .uri("/tx/abc") // 3 hex chars: odd
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::BAD_REQUEST);
    }

    /// PARSE-4 — /block/<huge digit string> overflows u64 parse → 400
    /// InvalidHex("invalid height"), not panic. The handler routes all-digits
    /// to `u64::parse`, which Errs on overflow.
    #[tokio::test]
    async fn get_block_height_overflow_returns_400() {
        let r = app()
            .oneshot(
                Request::builder()
                    // 30 nines: far beyond u64::MAX (~1.8e19)
                    .uri("/block/999999999999999999999999999999")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::BAD_REQUEST);
    }

    /// PARSE-5 — /block/<non-digit, non-64-hex> is treated as a hash and parsed
    /// by parse_hash_hex → 400 (wrong length), not panic.
    #[tokio::test]
    async fn get_block_garbage_hash_returns_400() {
        let r = app()
            .oneshot(
                Request::builder()
                    .uri("/block/deadbeef") // hex but only 4 bytes
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::BAD_REQUEST);
    }

    /// PARSE-6 — /utxo/<wrong byte length> → 400 ("commitment must be 33
    /// bytes"). 32-byte hex decodes but is the wrong commitment size.
    #[tokio::test]
    async fn get_utxo_wrong_length_returns_400() {
        let r = app()
            .oneshot(
                Request::builder()
                    .uri(format!("/utxo/{}", "ab".repeat(32))) // 32 bytes, need 33
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::BAD_REQUEST);
    }

    /// PARSE-7 — /utxo/<non-hex> → 400 InvalidHex (decode_hex), not panic.
    #[tokio::test]
    async fn get_utxo_non_hex_returns_400() {
        let r = app()
            .oneshot(
                Request::builder()
                    .uri("/utxo/nothexnothex")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::BAD_REQUEST);
    }

    // ===== static / info-leak: RpcError::Internal echoes internal strings
    //
    // RpcError::into_response serializes `self.to_string()` into the client
    // body. For `Internal(msg)` that is `"internal: {msg}"` — i.e. internal
    // implementation strings reach the untrusted client. This test PINS that
    // shape so the leak is documented; it is a FINDING (info-leak), not a pass.

    /// LEAK-1 — an unsupported /chain/scan returns the raw internal message
    /// ("internal: chain scan not supported") in the response body to the
    /// client. Pins the leak shape (info-leak finding: internal strings are not
    /// redacted before reaching the client).
    #[tokio::test]
    async fn internal_error_echoes_internal_string_to_client() {
        let r = app() // default MockNode → scan_chain returns Internal(...)
            .oneshot(
                Request::builder()
                    .uri("/chain/scan?from=0&to=2")
                    .header("authorization", "Bearer test-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let body = body_json(r).await;
        // FINDING: internal text reaches the client verbatim.
        assert_eq!(
            body["error"],
            serde_json::json!("internal: chain scan not supported")
        );
    }

    // ===== proptest-invariante: mempool offset (page*limit) + limit clamp
    //
    // `mempool` computes `offset = page.checked_mul(limit)` and clamps
    // `limit` to [1, MEMPOOL_MAX_LIMIT]. Invariants over arbitrary client input:
    //   (a) the endpoint NEVER panics and NEVER returns 500;
    //   (b) the response is always 200 (valid offset) or 400 (overflow);
    //   (c) when 200, reported `limit` is in [1, 1000] regardless of input.

    proptest::proptest! {
        #![proptest_config(proptest::prelude::ProptestConfig::with_cases(256))]

        #[test]
        fn mempool_page_limit_never_panics_and_clamps(page in 0usize.., limit in 0usize..) {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            rt.block_on(async move {
                let r = app()
                    .oneshot(
                        Request::builder()
                            .uri(format!("/mempool?page={page}&limit={limit}"))
                            .body(Body::empty())
                            .unwrap(),
                    )
                    .await
                    .unwrap();
                let status = r.status();
                // (a)+(b): only OK or 400 — never 500, never a panic.
                proptest::prop_assert!(
                    status == StatusCode::OK || status == StatusCode::BAD_REQUEST,
                    "unexpected status {status} for page={page} limit={limit}"
                );
                if status == StatusCode::OK {
                    let body = body_json(r).await;
                    let reported = body["limit"].as_u64().unwrap() as usize;
                    // (c): clamp invariant holds for every input.
                    proptest::prop_assert!(
                        (1..=MEMPOOL_MAX_LIMIT).contains(&reported),
                        "limit {reported} out of clamp range for input limit={limit}"
                    );
                }
                Ok(())
            })?;
        }
    }
}
