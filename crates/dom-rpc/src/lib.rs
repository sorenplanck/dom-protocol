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
use dom_core::WIRE_PROTOCOL_VERSION;
use dom_wallet_core_api::{ChainIdentity, ScanBlock};
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

    /// Get the regular transaction kernel metadata for a block. The default
    /// keeps third-party/mock handles source-compatible while node handles
    /// backed by a full block store expose the read-only projection.
    fn get_block_kernels(&self, _hash: &[u8; 32]) -> Option<Vec<KernelInfo>> {
        None
    }

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

    /// Create and durably retain a public Wallet V3 recovery Slate offer.
    fn wallet_slate_create_v1(
        &self,
        _request: WalletSlateCreateRequestV1,
    ) -> Result<WalletSlateOfferV1, RpcError> {
        Err(RpcError::Internal("wallet Slate API not available".into()))
    }

    /// Finalize and persist an exact Wallet V3 Slate response without
    /// admission or relay, leaving room for recipient third-message checking.
    fn wallet_slate_finalize_v1(
        &self,
        _request: WalletSlateFinalizeRequestV1,
    ) -> Result<WalletSlateFinalizedV1, RpcError> {
        Err(RpcError::Internal("wallet Slate API not available".into()))
    }

    /// Admit and relay only an exact transaction previously finalized and
    /// persisted by this WalletDir, after the recipient's third-message check.
    fn wallet_slate_submit_v1(
        &self,
        _request: WalletSlateSubmitRequestV1,
    ) -> Result<WalletSlateSubmittedV1, RpcError> {
        Err(RpcError::Internal("wallet Slate API not available".into()))
    }

    /// Mine an exact bounded number of real blocks on an explicitly
    /// configured regtest node whose continuous miner is disabled.
    fn regtest_mine_v1(&self, _request: RegtestMineRequestV1) -> RegtestMineFuture {
        Box::pin(async {
            Err(RpcError::Internal(
                "regtest mining API not available".into(),
            ))
        })
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

    /// Serve one authenticated, full-fidelity F7 scanner page.
    ///
    /// Implementations must validate the request's chain identity and anchor,
    /// return a contiguous canonical prefix, and never wait for a contended
    /// chain lock. The default is unsupported so existing test handles remain
    /// source compatible.
    fn scan_chain_full_v1(&self, _request: FullScanRequestV1) -> Result<ChainScanFullV1, RpcError> {
        Err(RpcError::Internal(
            "full-fidelity chain scan v1 not supported".into(),
        ))
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

/// Type-erased bounded regtest mining request owned by the node runtime.
pub type RegtestMineFuture =
    Pin<Box<dyn Future<Output = Result<RegtestMineResultV1, RpcError>> + Send + 'static>>;

/// Maximum number of heights a single [`NodeHandle::scan_chain`] / `/chain/scan`
/// call returns. Bounds how long the chain lock is held so block connection is
/// never stalled; clients page across larger ranges.
pub const MAX_SCAN_RANGE: u64 = 1000;

/// Canonical tip (height + hash) returned alongside a scan.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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

/// Version of the authenticated full-fidelity F7 scanner schema.
pub const FULL_SCAN_SCHEMA_VERSION_V1: u16 = 1;

/// Maximum block count in one full-fidelity page.
pub const MAX_FULL_SCAN_BLOCKS_V1: u64 = 64;

/// Approximate maximum encoded response size. Implementations always return at
/// least one requested block when it exists, even when that block alone is
/// larger than this soft budget.
pub const FULL_SCAN_RESPONSE_SOFT_LIMIT_BYTES_V1: usize = 8 * 1024 * 1024;

/// Canonical anchor immediately preceding a full scanner page.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FullScanAnchorV1 {
    /// Anchor height.
    pub height: u64,
    /// Canonical block identifier at `height`.
    pub block_hash: [u8; 32],
}

/// Full-fidelity scanner request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FullScanRequestV1 {
    /// Exact supported scanner schema version.
    pub schema_version: u16,
    /// Expected network magic.
    pub network_magic: u32,
    /// Expected consensus chain identifier.
    pub chain_id: [u8; 32],
    /// First canonical height to return.
    pub start_height: u64,
    /// Maximum number of blocks requested.
    pub max_blocks: u64,
    /// Canonical block at `start_height - 1`; forbidden at height zero and
    /// mandatory for every nonzero start.
    pub anchor: Option<FullScanAnchorV1>,
}

/// Restart-safe continuation returned after a nonterminal page.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FullScanContinuationV1 {
    /// Next height to request.
    pub next_height: u64,
    /// Last block returned, to be supplied as the next request's anchor.
    pub anchor: FullScanAnchorV1,
    /// Tip identifier under which this page was produced. A changed tip is not
    /// itself an error; the next anchor validation decides canonicality.
    pub snapshot_tip: ChainTip,
}

/// Authenticated full-fidelity scanner page.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainScanFullV1 {
    /// Scanner projection version.
    pub schema_version: u16,
    /// Chain identity and snapshot tip observed under the same chain lock.
    pub identity: ChainIdentity,
    /// Validated request anchor.
    pub request_anchor: Option<FullScanAnchorV1>,
    /// Contiguous canonical blocks.
    pub blocks: Vec<ScanBlock>,
    /// Continuation when the snapshot tip was not reached.
    pub continuation: Option<FullScanContinuationV1>,
}

/// Conservative encoded-size estimate for one full-fidelity block.
pub fn full_scan_block_wire_weight_v1(block: &ScanBlock) -> usize {
    const BLOCK_ENVELOPE: usize = 1024;
    const TX_ENVELOPE: usize = 768;
    const INPUT_ENVELOPE: usize = 96;
    const OUTPUT_ENVELOPE: usize = 256;
    const KERNEL_ENVELOPE: usize = 384;

    let coinbase = block
        .coinbase
        .output_proof_envelope
        .len()
        .saturating_mul(2)
        .saturating_add(KERNEL_ENVELOPE);
    block.transactions.iter().fold(
        BLOCK_ENVELOPE
            .saturating_add(block.canonical_header_bytes.len().saturating_mul(2))
            .saturating_add(coinbase),
        |total, tx| {
            let outputs = tx.outputs.iter().fold(0usize, |sum, output| {
                sum.saturating_add(OUTPUT_ENVELOPE)
                    .saturating_add(output.range_proof.len().saturating_mul(2))
                    .saturating_add(output.recovery_capsule.len().saturating_mul(2))
            });
            total
                .saturating_add(TX_ENVELOPE)
                .saturating_add(tx.canonical_bytes.len().saturating_mul(2))
                .saturating_add(tx.inputs.len().saturating_mul(INPUT_ENVELOPE))
                .saturating_add(tx.kernels.len().saturating_mul(KERNEL_ENVELOPE))
                .saturating_add(outputs)
        },
    )
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

/// Public-only request for the authenticated Wallet V3 Slate sender boundary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletSlateCreateRequestV1 {
    /// Optional canonical lowercase Wallet V3 recipient address. When absent,
    /// the official Wallet V3 automatic one-time identity framing is used.
    /// This is public material, never a recipient blinding factor.
    #[serde(default)]
    pub recipient_address: Option<String>,
    /// Recipient amount in noms.
    pub amount_noms: u64,
    /// Exact kernel fee in noms.
    pub fee_noms: u64,
    /// Inclusive canonical expiry height.
    pub expires_at_height: u64,
}

/// Exact public Wallet V3 sender offer retained by the node WalletDir.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WalletSlateOfferV1 {
    /// Canonical recovery Slate envelope bytes.
    pub canonical_slate: Vec<u8>,
    /// Public Slate identifier committed by the envelope.
    pub slate_id: [u8; 32],
    /// Public replay identifier committed by the envelope.
    pub replay_id: [u8; 32],
}

/// Exact public Wallet V3 recipient response submitted for finalization.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletSlateFinalizeRequestV1 {
    /// Hex encoding of canonical recovery Slate envelope bytes.
    pub canonical_response_hex: String,
}

/// Finalized, durably retained public transaction awaiting recipient checking.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WalletSlateFinalizedV1 {
    /// Exact canonical DOM transaction bytes retained for restart replay.
    pub canonical_transaction: Vec<u8>,
    /// Exact hash of `canonical_transaction`.
    pub transaction_hash: [u8; 32],
    /// Opaque public hash naming the durable pending sender record.
    pub pending_key: [u8; 32],
}

/// Submit authority for one exact, already-persisted Wallet V3 transaction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletSlateSubmitRequestV1 {
    /// Hex encoding of the 32-byte pending sender-record key.
    pub pending_key_hex: String,
    /// Hex encoding of the expected exact canonical transaction hash.
    pub expected_transaction_hash_hex: String,
}

/// Exact persisted Wallet V3 transaction and its node admission result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WalletSlateSubmittedV1 {
    /// Exact canonical bytes loaded from the WalletDir (never request bytes).
    pub canonical_transaction: Vec<u8>,
    /// Idempotent node admission outcome.
    pub admission: TxAdmission,
}

/// Authenticated regtest-only bounded mining request.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct RegtestMineRequestV1 {
    /// Exact number of new canonical blocks requested (1..=1000).
    pub count: u32,
}

/// Exact canonical result of a bounded regtest mining request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegtestMineResultV1 {
    /// Height of the first new block.
    pub start_height: u64,
    /// Height of the last new block.
    pub end_height: u64,
    /// Canonical hashes in ascending height order, exactly `count` entries.
    pub block_hashes: Vec<[u8; 32]>,
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
    pub kernels: Vec<KernelInfo>,
}

/// Read-only transaction-kernel fields needed to diagnose height locks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct KernelInfo {
    pub features: u8,
    pub lock_height: u64,
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
    /// Exact transaction identifier.
    pub tx_hash: [u8; 32],
    /// Whether this call handed the exact bytes to a live peer relay.
    pub relayed: bool,
    /// Idempotent lifecycle state observed by the node.
    pub state: TxAdmissionState,
}

/// Idempotent transaction-submission lifecycle state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TxAdmissionState {
    /// Newly admitted to the local mempool by this call.
    New,
    /// Exact bytes were already present in the local mempool.
    Mempool,
    /// Exact bytes were already present in a canonical block.
    Confirmed,
}

impl TxAdmissionState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::New => "new",
            Self::Mempool => "mempool",
            Self::Confirmed => "confirmed",
        }
    }

    pub const fn already_known(self) -> bool {
        !matches!(self, Self::New)
    }

    pub const fn confirmed(self) -> bool {
        matches!(self, Self::Confirmed)
    }
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
    #[error("invalid scan request: {0}")]
    InvalidScan(String),
    #[error("scanner anchor is no longer canonical: {0}")]
    ScanReorg(String),
    #[error("canonical chain gap: {0}")]
    CanonicalGap(String),
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
            Self::InvalidHex(_) | Self::InvalidTx(_) | Self::InvalidScan(_) => {
                StatusCode::BAD_REQUEST
            }
            Self::Rejected(_) | Self::ScanReorg(_) => StatusCode::CONFLICT,
            Self::Overloaded(_) => StatusCode::SERVICE_UNAVAILABLE,
            Self::CanonicalGap(_) | Self::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
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
    /// Additive detailed view; `tx_hashes` remains for existing consumers.
    transactions: Vec<TxSummaryResponse>,
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
    /// Idempotent lifecycle state for an accepted submission.
    #[serde(skip_serializing_if = "Option::is_none")]
    state: Option<&'static str>,
    /// Whether the exact bytes were known before this call.
    already_known: bool,
    /// Whether the exact bytes are already in a canonical block.
    confirmed: bool,
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
    kernels: Vec<KernelInfo>,
}

#[derive(Debug, Serialize)]
struct TxSummaryResponse {
    tx_hash: String,
    fee: u64,
    fee_rate: u64,
    weight: u32,
    kernels: Vec<KernelInfo>,
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
    kernels: Vec<KernelInfo>,
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
    let rate_limit_wallet_slate_create = middleware::rate_limit_submit();
    let rate_limit_wallet_slate_finalize = middleware::rate_limit_submit();
    let rate_limit_wallet_slate_submit = middleware::rate_limit_submit();
    let rate_limit_regtest_mine = middleware::rate_limit_submit();

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
        .route("/chain/scan/scriptless/v1", get(chain_scan_full_v1_handler))
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
        .route(
            "/wallet/slate/v1/create",
            post(wallet_slate_create_v1_handler).layer(rate_limit_wallet_slate_create),
        )
        .route(
            "/wallet/slate/v1/finalize",
            post(wallet_slate_finalize_v1_handler).layer(rate_limit_wallet_slate_finalize),
        )
        .route(
            "/wallet/slate/v1/submit",
            post(wallet_slate_submit_v1_handler).layer(rate_limit_wallet_slate_submit),
        )
        .route(
            "/regtest/mine/v1",
            post(regtest_mine_v1_handler).layer(rate_limit_regtest_mine),
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
        version: WIRE_PROTOCOL_VERSION,
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

    let page_hashes = all_hashes
        .into_iter()
        .skip(offset)
        .take(limit)
        .collect::<Vec<_>>();

    let tx_hashes = page_hashes.iter().map(hex::encode).collect::<Vec<_>>();
    let transactions = page_hashes
        .iter()
        .filter_map(|hash| handle.get_mempool_tx(hash))
        .map(|info| TxSummaryResponse {
            tx_hash: hex::encode(info.tx_hash),
            fee: info.fee,
            fee_rate: info.fee_rate,
            weight: info.weight,
            kernels: info.kernels,
        })
        .collect();

    let count = tx_hashes.len();

    Json(MempoolResponse {
        count,
        total,
        page,
        limit,
        tx_hashes,
        transactions,
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
            let warning = if admission.state == TxAdmissionState::Confirmed || admission.relayed {
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
                    state: Some(admission.state.as_str()),
                    already_known: admission.state.already_known(),
                    confirmed: admission.state.confirmed(),
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
                kernels: info.kernels,
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
                    kernels: handle.get_block_kernels(&hash).unwrap_or_default(),
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
            state: None,
            already_known: false,
            confirmed: false,
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

#[derive(Debug, Deserialize)]
struct FullScanQueryV1 {
    from: u64,
    to: u64,
    expected_network_magic: Option<u32>,
    expected_chain_id: Option<String>,
    anchor_hash: Option<String>,
}

#[derive(Debug, Serialize)]
struct FullScanIdentityDtoV1 {
    network: &'static str,
    network_magic: u32,
    chain_id: String,
    genesis_hash: String,
    protocol_version: u32,
    range_proof_serialization_version: u8,
    coinbase_maturity: u64,
    tip_height: u64,
    tip_hash: String,
}

#[derive(Debug, Serialize)]
struct FullScanAnchorDtoV1 {
    height: u64,
    block_hash: String,
}

#[derive(Debug, Serialize)]
struct FullScanInputDtoV1 {
    spent_commitment: String,
}

#[derive(Debug, Serialize)]
struct FullScanOutputDtoV1 {
    commitment: String,
    range_proof: String,
    recovery_capsule: String,
    recovery_version: u16,
    is_coinbase: bool,
    block_height: u64,
    block_hash: String,
    output_position: u32,
}

#[derive(Debug, Serialize)]
struct FullScanKernelDtoV1 {
    excess: String,
    features: u8,
    fee: u64,
    lock_height: u64,
    excess_signature: String,
}

#[derive(Debug, Serialize)]
struct FullScanTransactionDtoV1 {
    block_height: u64,
    block_hash: String,
    transaction_index: u32,
    tx_hash: String,
    canonical_bytes: String,
    inputs: Vec<FullScanInputDtoV1>,
    outputs: Vec<FullScanOutputDtoV1>,
    kernels: Vec<FullScanKernelDtoV1>,
    offset: String,
}

#[derive(Debug, Serialize)]
struct FullScanCoinbaseDtoV1 {
    output_commitment: String,
    explicit_value: u64,
    kernel_excess: String,
    kernel_features: u8,
    kernel_excess_signature: String,
    offset: String,
    output_proof_envelope: String,
}

#[derive(Debug, Serialize)]
struct FullScanBlockDtoV1 {
    height: u64,
    block_hash: String,
    previous_block_hash: String,
    canonical_header_bytes: String,
    timestamp: u64,
    canonical_marker: String,
    transactions: Vec<FullScanTransactionDtoV1>,
    coinbase: FullScanCoinbaseDtoV1,
    total_fees_noms: u64,
    protocol_version: u32,
    range_proof_serialization_version: u8,
}

#[derive(Debug, Serialize)]
struct FullScanContinuationDtoV1 {
    next_height: u64,
    anchor: FullScanAnchorDtoV1,
    snapshot_tip_height: u64,
    snapshot_tip_hash: String,
}

#[derive(Debug, Serialize)]
struct ChainScanFullResponseV1 {
    schema_version: u16,
    status: &'static str,
    canonical: bool,
    identity: FullScanIdentityDtoV1,
    requested_from: u64,
    requested_to: u64,
    served_from: u64,
    served_to: Option<u64>,
    request_anchor: Option<FullScanAnchorDtoV1>,
    blocks: Vec<FullScanBlockDtoV1>,
    continuation: Option<FullScanContinuationDtoV1>,
}

fn full_scan_anchor_dto_v1(anchor: FullScanAnchorV1) -> FullScanAnchorDtoV1 {
    FullScanAnchorDtoV1 {
        height: anchor.height,
        block_hash: hex::encode(anchor.block_hash),
    }
}

fn full_scan_input_dto_v1(input: dom_wallet_core_api::ScanInput) -> FullScanInputDtoV1 {
    FullScanInputDtoV1 {
        spent_commitment: hex::encode(input.spent_commitment),
    }
}

fn full_scan_output_dto_v1(output: dom_wallet_core_api::ScanOutput) -> FullScanOutputDtoV1 {
    FullScanOutputDtoV1 {
        commitment: hex::encode(output.commitment),
        range_proof: hex::encode(output.range_proof),
        recovery_capsule: hex::encode(output.recovery_capsule),
        recovery_version: output.recovery_version,
        is_coinbase: output.is_coinbase,
        block_height: output.block_height,
        block_hash: hex::encode(output.block_hash),
        output_position: output.output_position,
    }
}

fn full_scan_kernel_dto_v1(kernel: dom_wallet_core_api::ScanKernel) -> FullScanKernelDtoV1 {
    FullScanKernelDtoV1 {
        excess: hex::encode(kernel.excess),
        features: kernel.features,
        fee: kernel.fee,
        lock_height: kernel.lock_height,
        excess_signature: hex::encode(kernel.excess_signature),
    }
}

fn full_scan_transaction_dto_v1(
    tx: dom_wallet_core_api::ScanTransaction,
) -> FullScanTransactionDtoV1 {
    FullScanTransactionDtoV1 {
        block_height: tx.location.block_height,
        block_hash: hex::encode(tx.location.block_hash),
        transaction_index: tx.location.transaction_index,
        tx_hash: hex::encode(tx.tx_hash),
        canonical_bytes: hex::encode(tx.canonical_bytes),
        inputs: tx.inputs.into_iter().map(full_scan_input_dto_v1).collect(),
        outputs: tx
            .outputs
            .into_iter()
            .map(full_scan_output_dto_v1)
            .collect(),
        kernels: tx
            .kernels
            .into_iter()
            .map(full_scan_kernel_dto_v1)
            .collect(),
        offset: hex::encode(tx.offset),
    }
}

fn full_scan_block_dto_v1(block: ScanBlock) -> FullScanBlockDtoV1 {
    FullScanBlockDtoV1 {
        height: block.height,
        block_hash: hex::encode(block.block_hash),
        previous_block_hash: hex::encode(block.previous_block_hash),
        canonical_header_bytes: hex::encode(block.canonical_header_bytes),
        timestamp: block.timestamp,
        canonical_marker: hex::encode(block.canonical_marker),
        transactions: block
            .transactions
            .into_iter()
            .map(full_scan_transaction_dto_v1)
            .collect(),
        coinbase: FullScanCoinbaseDtoV1 {
            output_commitment: hex::encode(block.coinbase.output_commitment),
            explicit_value: block.coinbase.explicit_value,
            kernel_excess: hex::encode(block.coinbase.kernel_excess),
            kernel_features: block.coinbase.kernel_features,
            kernel_excess_signature: hex::encode(block.coinbase.kernel_excess_signature),
            offset: hex::encode(block.coinbase.offset),
            output_proof_envelope: hex::encode(block.coinbase.output_proof_envelope),
        },
        total_fees_noms: block.total_fees_noms,
        protocol_version: block.protocol_version,
        range_proof_serialization_version: block.range_proof_serialization_version,
    }
}

async fn chain_scan_full_v1_handler(
    State(handle): State<Arc<dyn NodeHandle>>,
    Query(query): Query<FullScanQueryV1>,
) -> impl IntoResponse {
    let request = (|| {
        if query.from > query.to {
            return Err(RpcError::InvalidScan("from must not exceed to".to_string()));
        }
        let requested_blocks = query
            .to
            .checked_sub(query.from)
            .and_then(|span| span.checked_add(1))
            .ok_or_else(|| RpcError::InvalidScan("scan range overflows".to_string()))?;
        if requested_blocks > MAX_FULL_SCAN_BLOCKS_V1 {
            return Err(RpcError::InvalidScan(format!(
                "requested range contains {requested_blocks} blocks; maximum is {MAX_FULL_SCAN_BLOCKS_V1}"
            )));
        }
        let chain_id = query
            .expected_chain_id
            .as_deref()
            .map(parse_hash_hex)
            .transpose()?;
        let anchor = match (query.from, query.anchor_hash.as_deref()) {
            (0, None) => None,
            (0, Some(_)) => {
                return Err(RpcError::InvalidScan(
                    "anchor_hash is forbidden when from is zero".to_string(),
                ));
            }
            (from, Some(hash)) => Some(FullScanAnchorV1 {
                height: from - 1,
                block_hash: parse_hash_hex(hash)?,
            }),
            (_, None) => {
                return Err(RpcError::InvalidScan(
                    "anchor_hash is required when from is nonzero".to_string(),
                ));
            }
        };
        Ok(FullScanRequestV1 {
            schema_version: FULL_SCAN_SCHEMA_VERSION_V1,
            network_magic: query.expected_network_magic.unwrap_or(0),
            chain_id: chain_id.unwrap_or([0u8; 32]),
            start_height: query.from,
            max_blocks: requested_blocks,
            anchor,
        })
    })();
    let request = match request {
        Ok(request) => request,
        Err(error) => return error.into_response(),
    };
    match handle.scan_chain_full_v1(request) {
        Ok(scan) => {
            let identity = FullScanIdentityDtoV1 {
                network: scan.identity.network.as_str(),
                network_magic: scan.identity.network_magic,
                chain_id: hex::encode(scan.identity.chain_id),
                genesis_hash: hex::encode(scan.identity.genesis_hash),
                protocol_version: scan.identity.protocol_version,
                range_proof_serialization_version: scan.identity.range_proof_serialization_version,
                coinbase_maturity: scan.identity.coinbase_maturity,
                tip_height: scan.identity.current_tip.height,
                tip_hash: hex::encode(scan.identity.current_tip.hash),
            };
            Json(ChainScanFullResponseV1 {
                schema_version: scan.schema_version,
                status: "ok",
                canonical: true,
                identity,
                requested_from: query.from,
                requested_to: query.to,
                served_from: query.from,
                served_to: scan.blocks.last().map(|block| block.height),
                request_anchor: scan.request_anchor.map(full_scan_anchor_dto_v1),
                blocks: scan
                    .blocks
                    .into_iter()
                    .map(full_scan_block_dto_v1)
                    .collect(),
                continuation: scan
                    .continuation
                    .map(|continuation| FullScanContinuationDtoV1 {
                        next_height: continuation.next_height,
                        anchor: full_scan_anchor_dto_v1(continuation.anchor),
                        snapshot_tip_height: continuation.snapshot_tip.height,
                        snapshot_tip_hash: hex::encode(continuation.snapshot_tip.hash),
                    }),
            })
            .into_response()
        }
        Err(error) => error.into_response(),
    }
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

async fn wallet_slate_create_v1_handler(
    State(handle): State<Arc<dyn NodeHandle>>,
    Json(request): Json<WalletSlateCreateRequestV1>,
) -> impl IntoResponse {
    match handle.wallet_slate_create_v1(request) {
        Ok(offer) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "schema_version": 1,
                "canonical_slate_hex": hex::encode(offer.canonical_slate),
                "slate_id": hex::encode(offer.slate_id),
                "replay_id": hex::encode(offer.replay_id),
            })),
        )
            .into_response(),
        Err(error) => {
            warn!("wallet Slate create error: {error}");
            error.into_response()
        }
    }
}

async fn wallet_slate_finalize_v1_handler(
    State(handle): State<Arc<dyn NodeHandle>>,
    Json(request): Json<WalletSlateFinalizeRequestV1>,
) -> impl IntoResponse {
    match handle.wallet_slate_finalize_v1(request) {
        Ok(finalized) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "schema_version": 1,
                "canonical_tx_hex": hex::encode(finalized.canonical_transaction),
                "tx_hash": hex::encode(finalized.transaction_hash),
                "pending_key": hex::encode(finalized.pending_key),
            })),
        )
            .into_response(),
        Err(error) => {
            warn!("wallet Slate finalize error: {error}");
            error.into_response()
        }
    }
}

async fn wallet_slate_submit_v1_handler(
    State(handle): State<Arc<dyn NodeHandle>>,
    Json(request): Json<WalletSlateSubmitRequestV1>,
) -> impl IntoResponse {
    match handle.wallet_slate_submit_v1(request) {
        Ok(submitted) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "schema_version": 1,
                "canonical_tx_hex": hex::encode(submitted.canonical_transaction),
                "tx_hash": hex::encode(submitted.admission.tx_hash),
                "relayed": submitted.admission.relayed,
                "state": submitted.admission.state.as_str(),
                "already_known": submitted.admission.state.already_known(),
                "confirmed": submitted.admission.state.confirmed(),
            })),
        )
            .into_response(),
        Err(error) => {
            warn!("wallet Slate submit error: {error}");
            error.into_response()
        }
    }
}

async fn regtest_mine_v1_handler(
    State(handle): State<Arc<dyn NodeHandle>>,
    Json(request): Json<RegtestMineRequestV1>,
) -> impl IntoResponse {
    match handle.regtest_mine_v1(request).await {
        Ok(result) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "schema_version": 1,
                "start_height": result.start_height,
                "end_height": result.end_height,
                "count": result.block_hashes.len(),
                "block_hashes": result.block_hashes.into_iter().map(hex::encode).collect::<Vec<_>>(),
            })),
        )
            .into_response(),
        Err(error) => {
            warn!("regtest bounded mining error: {error}");
            error.into_response()
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

    struct MockNode {
        height: u64,
        txs: Mutex<HashMap<[u8; 32], MempoolTxInfo>>,
        network: &'static str,
        /// When true, submit_tx reports the tx as accepted-but-not-relayed
        /// (the no-peers case exercised by F3).
        no_peers: bool,
        submit_state: TxAdmissionState,
        /// Canned chain scan for `/chain/scan` tests; `None` → unsupported.
        scan: Option<ChainScan>,
        /// Canned full-fidelity scan for the authenticated Scriptless route.
        full_scan: Option<ChainScanFullV1>,
        shutdown_requested: Arc<AtomicBool>,
    }

    impl MockNode {
        fn new(height: u64) -> Self {
            Self {
                height,
                txs: Mutex::new(HashMap::new()),
                network: "regtest",
                no_peers: false,
                submit_state: TxAdmissionState::New,
                scan: None,
                full_scan: None,
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

        fn with_full_scan(scan: ChainScanFullV1) -> Self {
            Self {
                height: scan.identity.current_tip.height,
                full_scan: Some(scan),
                ..Self::new(0)
            }
        }

        /// A node that accepts txs but has no peers to relay to.
        fn no_peers(height: u64) -> Self {
            Self {
                no_peers: true,
                ..Self::new(height)
            }
        }

        fn with_submit_state(state: TxAdmissionState) -> Self {
            Self {
                submit_state: state,
                no_peers: true,
                ..Self::new(0)
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
        fn scan_chain_full_v1(
            &self,
            _request: FullScanRequestV1,
        ) -> Result<ChainScanFullV1, RpcError> {
            self.full_scan.clone().ok_or_else(|| {
                RpcError::Internal("full-fidelity chain scan v1 not supported".into())
            })
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
                    kernels: Vec::new(),
                },
            );
            Ok(TxAdmission {
                tx_hash: hash,
                relayed: !self.no_peers && self.submit_state != TxAdmissionState::Confirmed,
                state: self.submit_state,
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
        fn wallet_slate_create_v1(
            &self,
            _request: WalletSlateCreateRequestV1,
        ) -> Result<WalletSlateOfferV1, RpcError> {
            Ok(WalletSlateOfferV1 {
                canonical_slate: vec![0xa1, 0xb2],
                slate_id: [0x11; 32],
                replay_id: [0x22; 32],
            })
        }
        fn wallet_slate_finalize_v1(
            &self,
            _request: WalletSlateFinalizeRequestV1,
        ) -> Result<WalletSlateFinalizedV1, RpcError> {
            Ok(WalletSlateFinalizedV1 {
                canonical_transaction: vec![0xc3, 0xd4],
                transaction_hash: [0x33; 32],
                pending_key: [0x44; 32],
            })
        }
        fn wallet_slate_submit_v1(
            &self,
            _request: WalletSlateSubmitRequestV1,
        ) -> Result<WalletSlateSubmittedV1, RpcError> {
            Ok(WalletSlateSubmittedV1 {
                canonical_transaction: vec![0xc3, 0xd4],
                admission: TxAdmission {
                    tx_hash: [0x33; 32],
                    relayed: false,
                    state: TxAdmissionState::Mempool,
                },
            })
        }
        fn regtest_mine_v1(&self, request: RegtestMineRequestV1) -> RegtestMineFuture {
            Box::pin(async move {
                if request.count == 0 || request.count > 1000 {
                    return Err(RpcError::Rejected("count out of bounds".to_string()));
                }
                Ok(RegtestMineResultV1 {
                    start_height: 43,
                    end_height: 42 + u64::from(request.count),
                    block_hashes: (0..request.count)
                        .map(|offset| {
                            let mut hash = [0u8; 32];
                            hash[..4].copy_from_slice(&(offset + 1).to_le_bytes());
                            hash
                        })
                        .collect(),
                })
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
        assert_eq!(body["version"], serde_json::json!(WIRE_PROTOCOL_VERSION));
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
        assert_eq!(body["transactions"], serde_json::json!([]));
    }

    #[tokio::test]
    async fn tx_and_mempool_expose_height_locked_kernel_fields() {
        let node = MockNode::new(0);
        let hash = [0xabu8; 32];
        node.txs.lock().unwrap().insert(
            hash,
            MempoolTxInfo {
                tx_hash: hash,
                fee: 7,
                fee_rate: 2,
                weight: 3,
                kernels: vec![KernelInfo {
                    features: dom_core::KERNEL_FEAT_HEIGHT_LOCKED,
                    lock_height: 4242,
                }],
            },
        );
        let app = app_with(node);

        let tx = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!("/tx/{}", hex::encode(hash)))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let tx_body = body_json(tx).await;
        assert_eq!(
            tx_body["kernels"],
            serde_json::json!([{"features": 2, "lock_height": 4242}])
        );

        let mempool = app
            .oneshot(
                Request::builder()
                    .uri("/mempool")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let mempool_body = body_json(mempool).await;
        assert_eq!(
            mempool_body["tx_hashes"],
            serde_json::json!([hex::encode(hash)])
        );
        assert_eq!(
            mempool_body["transactions"][0]["kernels"],
            tx_body["kernels"]
        );
    }

    #[test]
    fn block_response_serializes_kernel_fields_additively() {
        let response = BlockHeaderResponse {
            height: 1,
            hash: "11".repeat(32),
            prev_hash: "00".repeat(32),
            timestamp: 123,
            target: "1f00ffff".to_owned(),
            kernels: vec![KernelInfo {
                features: dom_core::KERNEL_FEAT_HEIGHT_LOCKED,
                lock_height: 99,
            }],
        };
        let body = serde_json::to_value(response).unwrap();
        assert_eq!(
            body["kernels"],
            serde_json::json!([{"features": 2, "lock_height": 99}])
        );
        assert_eq!(body["height"], 1);
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
                    kernels: Vec::new(),
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
                    kernels: Vec::new(),
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
        assert_eq!(body["state"], serde_json::json!("new"));
        assert_eq!(body["already_known"], serde_json::json!(false));
        assert_eq!(body["confirmed"], serde_json::json!(false));
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
        assert_eq!(body["state"], serde_json::json!("new"));
        assert_eq!(body["already_known"], serde_json::json!(false));
        assert_eq!(body["confirmed"], serde_json::json!(false));
        assert_eq!(
            body["warning"],
            serde_json::json!(WARN_ACCEPTED_NOT_RELAYED)
        );
    }

    #[tokio::test]
    async fn submit_idempotent_states_are_additive_and_confirmed_needs_no_retry() {
        let valid_tx_hex = hex::encode(vec![0xdeu8; 64]);
        for (state, expected, confirmed, warning) in [
            (TxAdmissionState::Mempool, "mempool", false, true),
            (TxAdmissionState::Confirmed, "confirmed", true, false),
        ] {
            let response = app_with(MockNode::with_submit_state(state))
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
            assert_eq!(response.status(), StatusCode::OK);
            let body = body_json(response).await;
            assert_eq!(body["accepted"], serde_json::json!(true));
            assert_eq!(body["relayed"], serde_json::json!(false));
            assert_eq!(body["state"], serde_json::json!(expected));
            assert_eq!(body["already_known"], serde_json::json!(true));
            assert_eq!(body["confirmed"], serde_json::json!(confirmed));
            assert_eq!(body.get("warning").is_some(), warning);
        }
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
    async fn wallet_slate_three_message_routes_require_bearer() {
        let requests = [
            (
                "/wallet/slate/v1/create",
                serde_json::json!({
                    "amount_noms": 1,
                    "fee_noms": 1,
                    "expires_at_height": 10
                }),
            ),
            (
                "/wallet/slate/v1/finalize",
                serde_json::json!({"canonical_response_hex": "a1b2"}),
            ),
            (
                "/wallet/slate/v1/submit",
                serde_json::json!({
                    "pending_key_hex": "44".repeat(32),
                    "expected_transaction_hash_hex": "33".repeat(32)
                }),
            ),
        ];
        for (uri, body) in requests {
            let response = app()
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri(uri)
                        .header("content-type", "application/json")
                        .body(Body::from(body.to_string()))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED, "{uri}");
        }
    }

    #[tokio::test]
    async fn wallet_slate_finalize_is_distinct_from_explicit_submit() {
        let finalize = app()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/wallet/slate/v1/finalize")
                    .header("content-type", "application/json")
                    .header("authorization", "Bearer test-token")
                    .body(Body::from(r#"{"canonical_response_hex":"a1b2"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(finalize.status(), StatusCode::OK);
        let finalize = body_json(finalize).await;
        assert_eq!(finalize["canonical_tx_hex"], serde_json::json!("c3d4"));
        assert_eq!(finalize["tx_hash"], serde_json::json!("33".repeat(32)));
        assert_eq!(finalize["pending_key"], serde_json::json!("44".repeat(32)));
        assert!(finalize.get("state").is_none());
        assert!(finalize.get("relayed").is_none());

        let submit = app()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/wallet/slate/v1/submit")
                    .header("content-type", "application/json")
                    .header("authorization", "Bearer test-token")
                    .body(Body::from(
                        serde_json::json!({
                            "pending_key_hex": "44".repeat(32),
                            "expected_transaction_hash_hex": "33".repeat(32)
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(submit.status(), StatusCode::OK);
        let submit = body_json(submit).await;
        assert_eq!(submit["canonical_tx_hex"], serde_json::json!("c3d4"));
        assert_eq!(submit["state"], serde_json::json!("mempool"));
        assert_eq!(submit["already_known"], serde_json::json!(true));
    }

    #[tokio::test]
    async fn bounded_regtest_mining_requires_bearer_and_reports_exact_count() {
        let body = serde_json::json!({"count": 3}).to_string();
        let unauthorized = app()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/regtest/mine/v1")
                    .header("content-type", "application/json")
                    .body(Body::from(body.clone()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(unauthorized.status(), StatusCode::UNAUTHORIZED);

        let authorized = app()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/regtest/mine/v1")
                    .header("content-type", "application/json")
                    .header("authorization", "Bearer test-token")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(authorized.status(), StatusCode::OK);
        let response = body_json(authorized).await;
        assert_eq!(response["start_height"], serde_json::json!(43));
        assert_eq!(response["end_height"], serde_json::json!(45));
        assert_eq!(response["count"], serde_json::json!(3));
        assert_eq!(response["block_hashes"].as_array().unwrap().len(), 3);
    }

    #[tokio::test]
    async fn bounded_regtest_mining_rejects_zero_and_excessive_counts() {
        for count in [0, 1001] {
            let response = app()
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri("/regtest/mine/v1")
                        .header("content-type", "application/json")
                        .header("authorization", "Bearer test-token")
                        .body(Body::from(serde_json::json!({"count": count}).to_string()))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::CONFLICT);
        }
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

    fn canned_full_scan_v1() -> ChainScanFullV1 {
        use dom_wallet_core_api::{
            BlockRef, CoinbaseScanMetadata, CoreNetwork, ScanInput, ScanKernel, ScanOutput,
            ScanTransaction, TransactionLocation,
        };

        let input = ScanInput {
            spent_commitment: [0xA1; 33],
        };
        let output = ScanOutput {
            commitment: [0xB2; 33],
            range_proof: vec![0xC3; 739],
            recovery_capsule: Vec::new(),
            recovery_version: 0,
            is_coinbase: false,
            block_height: 7,
            block_hash: [0xD4; 32],
            output_position: 1,
        };
        let kernel = ScanKernel {
            excess: [0xE5; 33],
            features: 0,
            fee: 42,
            lock_height: 0,
            excess_signature: [0xF6; 65],
        };
        let block = ScanBlock {
            height: 7,
            block_hash: [0xD4; 32],
            previous_block_hash: [0xD3; 32],
            canonical_header_bytes: vec![0x71; 200],
            timestamp: 1_700_000_007,
            canonical_marker: [0xD4; 32],
            outputs: vec![output.clone()],
            inputs: vec![input],
            kernels: vec![kernel.clone()],
            transactions: vec![ScanTransaction {
                location: TransactionLocation {
                    block_height: 7,
                    block_hash: [0xD4; 32],
                    transaction_index: 0,
                },
                tx_hash: [0x77; 32],
                canonical_bytes: vec![0x88; 314],
                inputs: vec![input],
                outputs: vec![output],
                kernels: vec![kernel],
                offset: [0x99; 32],
            }],
            coinbase: CoinbaseScanMetadata {
                output_commitment: [0xC0; 33],
                explicit_value: 1_000,
                kernel_excess: [0xC1; 33],
                kernel_features: 1,
                kernel_excess_signature: [0xC2; 65],
                offset: [0xC3; 32],
                output_proof_envelope: vec![0xC4; 739],
            },
            total_fees_noms: 42,
            protocol_version: 3,
            range_proof_serialization_version: 2,
        };
        ChainScanFullV1 {
            schema_version: 1,
            identity: ChainIdentity {
                network: CoreNetwork::Regtest,
                network_magic: dom_core::NETWORK_MAGIC_REGTEST,
                chain_id: [0x11; 32],
                genesis_hash: [0x22; 32],
                protocol_version: 3,
                range_proof_serialization_version: 2,
                coinbase_maturity: 1_000,
                current_tip: BlockRef {
                    height: 7,
                    hash: [0xD4; 32],
                },
            },
            request_anchor: None,
            blocks: vec![block],
            continuation: None,
        }
    }

    #[tokio::test]
    async fn scriptless_scan_v1_is_authenticated_and_full_fidelity() {
        let unauthenticated = app_with(MockNode::with_full_scan(canned_full_scan_v1()))
            .oneshot(
                Request::builder()
                    .uri("/chain/scan/scriptless/v1?from=0&to=0")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(unauthenticated.status(), StatusCode::UNAUTHORIZED);

        let response = app_with(MockNode::with_full_scan(canned_full_scan_v1()))
            .oneshot(
                Request::builder()
                    .uri("/chain/scan/scriptless/v1?from=0&to=0")
                    .header("authorization", "Bearer test-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let json = body_json(response).await;
        assert_eq!(json["schema_version"], serde_json::json!(1));
        assert_eq!(json["status"], serde_json::json!("ok"));
        assert_eq!(json["canonical"], serde_json::json!(true));
        assert_eq!(
            json["identity"]["chain_id"],
            serde_json::json!("11".repeat(32))
        );
        assert_eq!(
            json["blocks"][0]["transactions"][0]["tx_hash"],
            serde_json::json!("77".repeat(32))
        );
        assert_eq!(
            json["blocks"][0]["transactions"][0]["canonical_bytes"],
            serde_json::json!("88".repeat(314))
        );
        assert_eq!(
            json["blocks"][0]["transactions"][0]["kernels"][0]["excess_signature"],
            serde_json::json!("f6".repeat(65))
        );
    }

    #[tokio::test]
    async fn scriptless_scan_v1_requires_anchor_and_enforces_range_bound() {
        for uri in [
            "/chain/scan/scriptless/v1?from=1&to=1",
            "/chain/scan/scriptless/v1?from=0&to=64",
            "/chain/scan/scriptless/v1?from=2&to=1",
        ] {
            let response = app_with(MockNode::with_full_scan(canned_full_scan_v1()))
                .oneshot(
                    Request::builder()
                        .uri(uri)
                        .header("authorization", "Bearer test-token")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{uri}");
        }
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
