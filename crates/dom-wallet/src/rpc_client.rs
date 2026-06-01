//! Wallet ↔ node RPC client (Phase 1.9).
//!
//! Minimal blocking HTTP client against the node's REST surface
//! exposed by `dom-rpc`. The scope here is intentionally narrow — it
//! provides the *primitives* (chain tip, header lookup, tx submit,
//! mempool query, health) that higher layers will compose into sync
//! and confirmation logic in later phases.
//!
//! # Determinism and bounded runtime
//!
//! - Every request has a hard per-request timeout configured on the
//!   underlying `reqwest::blocking::Client`. The default is 10 s; an
//!   independent 3 s connect timeout fires before the request budget
//!   is consumed. No background tasks. No queueing.
//! - There is no automatic retry. A client call either succeeds with a
//!   typed value, returns a typed [`RpcClientError`], or blocks until
//!   the configured timeout — never longer.
//! - The client holds no on-disk state and no in-memory pending-request
//!   table. Dropping the client cancels nothing because every call is
//!   serialised through the caller's stack frame.
//!
//! # Replay-safe and restart-safe semantics
//!
//! The client is decoupled from [`crate::Wallet`] state. RPC failures
//! cannot corrupt the wallet's journal, output index, or pending-tx
//! table because the client never reaches into wallet internals.
//! Callers that combine a wallet mutation with an RPC call must
//! sequence them explicitly — typically: append to the journal,
//! mutate in memory, save, *then* call the RPC. A subsequent crash
//! or RPC failure leaves the wallet in a state that the existing
//! reconcile-on-open path already heals.
//!
//! Restarting the wallet process drops the client; instantiating a
//! fresh client is free and never reads any persisted RPC state.
//!
//! # Wire contract
//!
//! Endpoints, request shapes, and response shapes match the server in
//! `crates/dom-rpc/src/lib.rs`. Transactions are submitted as
//! hex-encoded canonical bytes (`Transaction::to_bytes()`), matching
//! what the node's `submit_tx` handler decodes. Hashes on the wire
//! are 64-char lowercase hex (32 bytes).

use crate::types::WalletError;
use dom_consensus::transaction::Transaction;
use dom_serialization::DomSerialize;
use reqwest::blocking::{Client, RequestBuilder, Response};
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use thiserror::Error;
use url::Url;

/// Default per-request timeout: total wall-clock budget from when the
/// request is dispatched until the response body is fully received.
pub const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

/// Default TCP connect timeout. Fires before [`DEFAULT_REQUEST_TIMEOUT`]
/// when the server is unreachable, so callers get a fast `ConnectTimeout`
/// instead of waiting out the full request budget.
pub const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(3);

/// Errors returned by [`NodeRpcClient`] methods.
///
/// Variants are organised so callers can decide on retry policy
/// without inspecting strings:
///
/// - [`ConnectTimeout`](Self::ConnectTimeout) / [`Transport`](Self::Transport):
///   the server might not have seen the request — retry is usually
///   safe but the caller decides.
/// - [`ReadTimeout`](Self::ReadTimeout): the server **may** have
///   processed the request before the client gave up; retry is
///   only safe for idempotent operations.
/// - [`NodeRejected`](Self::NodeRejected): the server received and
///   rejected the request (4xx/5xx with a structured body). The
///   operation did NOT take effect. Retrying with the same input
///   will produce the same rejection.
/// - [`UnexpectedStatus`](Self::UnexpectedStatus): a non-error HTTP
///   status that doesn't match the endpoint's documented contract.
///   Usually a node/version mismatch.
/// - [`Decode`](Self::Decode): well-formed HTTP but the body doesn't
///   parse — node and client are out of sync on the wire format.
/// - [`Unauthorized`](Self::Unauthorized): the endpoint requires a
///   bearer token and either none was supplied or it didn't match.
/// - [`Config`](Self::Config): builder-time misconfiguration.
#[derive(Debug, Error)]
pub enum RpcClientError {
    /// Could not establish a TCP connection within the configured
    /// connect timeout. The request was never sent.
    #[error("connect timeout to {url}")]
    ConnectTimeout {
        /// URL the client attempted to reach.
        url: String,
    },
    /// Connection was established but the full response was not
    /// received before the per-request timeout fired.
    #[error("read timeout on {url}")]
    ReadTimeout {
        /// URL the client was reading from.
        url: String,
    },
    /// Transport-level failure: TCP reset, TLS handshake failure, DNS
    /// resolution failure, etc. The request may or may not have
    /// reached the server.
    #[error("transport failure on {url}: {reason}")]
    Transport {
        /// URL the client was contacting.
        url: String,
        /// Underlying transport error description.
        reason: String,
    },
    /// Server returned an HTTP status outside the endpoint's
    /// documented contract. The body is preserved opaque so the
    /// caller can log it.
    #[error("unexpected HTTP {status} from {url}")]
    UnexpectedStatus {
        /// URL that produced the response.
        url: String,
        /// HTTP status code returned.
        status: u16,
        /// Response body (may be empty).
        body: String,
    },
    /// Server returned a typed rejection (the body decoded into a
    /// known error envelope). The operation did not take effect.
    #[error("node rejected request ({status}): {reason}")]
    NodeRejected {
        /// HTTP status returned (one of 400, 409, 503, 500, ...).
        status: u16,
        /// Operator-visible rejection reason from the server.
        reason: String,
    },
    /// Bearer-token-protected endpoint refused the request because
    /// the token was missing or invalid (HTTP 401 / 403).
    #[error("unauthorized request to {url}")]
    Unauthorized {
        /// URL that returned 401/403.
        url: String,
    },
    /// Response body could not be parsed as the expected JSON shape.
    /// Indicates a version mismatch between client and node.
    #[error("decode failure from {url}: {reason}")]
    Decode {
        /// URL whose response failed to decode.
        url: String,
        /// Underlying serde / hex / shape error.
        reason: String,
    },
    /// Client-side construction error (bad base URL, unsupported
    /// scheme, etc.).
    #[error("client config error: {reason}")]
    Config {
        /// Description of the misconfiguration.
        reason: String,
    },
    /// Transaction could not be serialised to wire bytes. Originates
    /// from the wallet's serialization layer, not the network.
    #[error("transaction serialization failed: {reason}")]
    TxSerialize {
        /// Underlying serialization error.
        reason: String,
    },
}

impl From<RpcClientError> for WalletError {
    fn from(err: RpcClientError) -> Self {
        WalletError::Io(format!("rpc: {err}"))
    }
}

/// Snapshot returned by [`NodeRpc::status`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeStatus {
    /// Protocol version reported by the node.
    pub version: u32,
    /// Canonical chain tip height.
    pub chain_height: u64,
    /// Current canonical chain tip hash, if exposed by the node.
    pub tip_hash: Option<[u8; 32]>,
    /// Current number of transactions in the node's mempool.
    pub mempool_size: u64,
    /// Network identifier ("mainnet", "testnet", "regtest").
    pub network: String,
}

/// Block-header snapshot returned by [`NodeRpc::block_at_height`] and
/// [`NodeRpc::block_by_hash`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockHeaderInfo {
    /// Block height.
    pub height: u64,
    /// Block hash (32 bytes).
    pub hash: [u8; 32],
    /// Parent block hash (32 bytes).
    pub prev_hash: [u8; 32],
    /// Block timestamp (seconds since epoch).
    pub timestamp: u64,
    /// Difficulty target encoded as big-endian 32 bytes.
    pub target: [u8; 32],
    /// Number of outputs in the block, if exposed by the node.
    pub output_count: Option<u32>,
    /// Number of kernels in the block, if exposed by the node.
    pub kernel_count: Option<u32>,
}

/// Outcome of a successful [`NodeRpc::submit_tx`] call.
///
/// A failed submission produces an [`RpcClientError`] instead — the
/// caller can match on [`RpcClientError::NodeRejected`] with HTTP 409
/// to recognise duplicate-in-mempool semantics if needed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxSubmitOutcome {
    /// Mempool hash assigned by the node. Equals the wallet's
    /// `compute_tx_hash` since Phase 1.7 unified the hash spaces.
    pub tx_hash: [u8; 32],
}

/// Outcome of a successful `POST /wallet/spend` call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WalletSpendOutcome {
    /// Transaction hash returned by the node after building and submitting.
    pub tx_hash: [u8; 32],
}

/// Snapshot of a transaction sitting in the node's mempool.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MempoolTxInfo {
    /// Mempool hash.
    pub tx_hash: [u8; 32],
    /// Absolute fee in noms.
    pub fee_noms: u64,
    /// Fee rate (noms per weight unit) reported by the node.
    pub fee_rate: u64,
    /// Transaction weight units.
    pub weight: u32,
}

/// Snapshot of a currently unspent output in the node's canonical UTXO set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UtxoInfo {
    /// Commitment bytes.
    pub commitment: [u8; 33],
    /// Block height that created the UTXO.
    pub block_height: u64,
    /// Whether the output is coinbase.
    pub is_coinbase: bool,
    /// Whether the node reports it as mature.
    pub is_mature: bool,
}

/// Read-side RPC surface exposed by [`NodeRpcClient`]. The trait is
/// object-safe so higher layers can substitute a mock in tests
/// without depending on `reqwest`.
pub trait NodeRpc {
    /// `GET /health`. Returns `Ok(())` on a 200 + `{ok: true}` body.
    fn health(&self) -> Result<(), RpcClientError>;

    /// `GET /status`. Returns the node's current chain tip and
    /// protocol metadata.
    fn status(&self) -> Result<NodeStatus, RpcClientError>;

    /// `GET /block/{height}`. Returns `Ok(Some(header))` if the node
    /// has a canonical block at that height, `Ok(None)` on a clean
    /// 404 / `{found: false}` body.
    fn block_at_height(&self, height: u64) -> Result<Option<BlockHeaderInfo>, RpcClientError>;

    /// `GET /block/{hash_hex}`. Same semantics as
    /// [`block_at_height`](Self::block_at_height) but keyed by hash.
    fn block_by_hash(&self, hash: &[u8; 32]) -> Result<Option<BlockHeaderInfo>, RpcClientError>;

    /// `POST /tx/submit`. Serialises `tx` to canonical bytes,
    /// hex-encodes them, and posts to the node.
    ///
    /// Idempotency contract: a node receiving the same canonical
    /// bytes twice will return HTTP 409 on the second call. Callers
    /// that need to treat duplicates as success should match on
    /// [`RpcClientError::NodeRejected`] with `status == 409`. This
    /// method does NOT auto-classify so that ambiguous rejections
    /// (e.g., real fee-too-low) remain visible.
    fn submit_tx(&self, tx: &Transaction) -> Result<TxSubmitOutcome, RpcClientError>;

    /// `GET /tx/{tx_hash}`. Returns `Ok(Some(_))` if the tx is in the
    /// mempool, `Ok(None)` if absent. Confirmation status is **not**
    /// exposed by this endpoint — that's a higher-layer concern.
    fn mempool_tx(&self, tx_hash: &[u8; 32]) -> Result<Option<MempoolTxInfo>, RpcClientError>;

    /// `GET /utxo/{commitment}`. Returns `Ok(Some(_))` if the
    /// commitment currently exists in the canonical UTXO set,
    /// `Ok(None)` if absent or already spent.
    fn utxo(&self, commitment: &[u8; 33]) -> Result<Option<UtxoInfo>, RpcClientError>;
}

/// Blocking HTTP client for the node RPC surface.
///
/// Construct via [`NodeRpcClient::builder`]. Cheap to clone (the
/// underlying `reqwest::blocking::Client` shares a connection pool).
#[derive(Debug, Clone)]
pub struct NodeRpcClient {
    base_url: Url,
    http: Client,
    bearer_token: Option<String>,
}

impl NodeRpcClient {
    /// Start configuring a new client against `base_url` (e.g.,
    /// `http://127.0.0.1:33369/`). Trailing slash is normalised.
    pub fn builder(base_url: Url) -> NodeRpcClientBuilder {
        NodeRpcClientBuilder {
            base_url,
            request_timeout: DEFAULT_REQUEST_TIMEOUT,
            connect_timeout: DEFAULT_CONNECT_TIMEOUT,
            bearer_token: None,
            user_agent: format!("dom-wallet/{}", env!("CARGO_PKG_VERSION")),
        }
    }

    /// The base URL the client was constructed with.
    pub fn base_url(&self) -> &Url {
        &self.base_url
    }

    /// `POST /wallet/spend`. This endpoint is bearer-token protected by
    /// the node and builds a wallet spend to an exact commitment/blinding.
    pub fn wallet_spend(
        &self,
        recipient_commitment: String,
        recipient_blinding: String,
        amount_noms: u64,
        fee_noms: u64,
    ) -> Result<WalletSpendOutcome, RpcClientError> {
        let url = self.url_for("wallet/spend")?;
        let url_s = url.to_string();
        let body = WireSpendRequest {
            recipient_commitment,
            recipient_blinding,
            amount_noms,
            fee_noms,
        };
        let resp = self.send(self.with_auth(self.http.post(url).json(&body)), &url_s)?;
        let status = resp.status();
        if status == StatusCode::OK {
            let parsed: WireWalletSpend = decode_body(resp, &url_s)?;
            let tx_hash = parse_hash_hex(&parsed.tx_hash, &url_s)?;
            return Ok(WalletSpendOutcome { tx_hash });
        }
        Err(classify_response_status(resp, status, &url_s))
    }

    fn url_for(&self, path: &str) -> Result<Url, RpcClientError> {
        self.base_url
            .join(path)
            .map_err(|e| RpcClientError::Config {
                reason: format!("invalid path {path:?}: {e}"),
            })
    }

    fn with_auth(&self, mut req: RequestBuilder) -> RequestBuilder {
        if let Some(token) = &self.bearer_token {
            req = req.bearer_auth(token);
        }
        req
    }

    fn send(&self, req: RequestBuilder, url_for_error: &str) -> Result<Response, RpcClientError> {
        req.send()
            .map_err(|e| classify_request_error(e, url_for_error))
    }
}

impl NodeRpc for NodeRpcClient {
    fn health(&self) -> Result<(), RpcClientError> {
        let url = self.url_for("health")?;
        let url_s = url.to_string();
        let resp = self.send(self.with_auth(self.http.get(url)), &url_s)?;
        let status = resp.status();
        if status == StatusCode::OK {
            let parsed: WireHealth = decode_body(resp, &url_s)?;
            if parsed.ok {
                Ok(())
            } else {
                Err(RpcClientError::Decode {
                    url: url_s,
                    reason: "/health returned ok=false".into(),
                })
            }
        } else {
            Err(classify_response_status(resp, status, &url_s))
        }
    }

    fn status(&self) -> Result<NodeStatus, RpcClientError> {
        let url = self.url_for("status")?;
        let url_s = url.to_string();
        let resp = self.send(self.with_auth(self.http.get(url)), &url_s)?;
        let status = resp.status();
        if status == StatusCode::OK {
            let parsed: WireStatus = decode_body(resp, &url_s)?;
            Ok(NodeStatus {
                version: parsed.version,
                chain_height: parsed.chain_height,
                tip_hash: parsed
                    .tip_hash
                    .as_deref()
                    .map(|s| parse_hash_hex(s, &url_s))
                    .transpose()?,
                mempool_size: parsed.mempool_size,
                network: parsed.network,
            })
        } else {
            Err(classify_response_status(resp, status, &url_s))
        }
    }

    fn block_at_height(&self, height: u64) -> Result<Option<BlockHeaderInfo>, RpcClientError> {
        self.fetch_block(&format!("block/{height}"))
    }

    fn block_by_hash(&self, hash: &[u8; 32]) -> Result<Option<BlockHeaderInfo>, RpcClientError> {
        self.fetch_block(&format!("block/{}", hex::encode(hash)))
    }

    fn submit_tx(&self, tx: &Transaction) -> Result<TxSubmitOutcome, RpcClientError> {
        let bytes = tx.to_bytes().map_err(|e| RpcClientError::TxSerialize {
            reason: e.to_string(),
        })?;
        let url = self.url_for("tx/submit")?;
        let url_s = url.to_string();
        let body = serde_json::json!({"tx_hex": hex::encode(&bytes)});
        let resp = self.send(self.with_auth(self.http.post(url).json(&body)), &url_s)?;
        let status = resp.status();
        let parsed: WireSubmitTx = decode_body(resp, &url_s)?;
        if status == StatusCode::OK && parsed.accepted {
            let tx_hash_hex = parsed.tx_hash.ok_or_else(|| RpcClientError::Decode {
                url: url_s.clone(),
                reason: "accepted=true but tx_hash missing".into(),
            })?;
            let tx_hash = parse_hash_hex(&tx_hash_hex, &url_s)?;
            Ok(TxSubmitOutcome { tx_hash })
        } else if status.is_client_error() || status.is_server_error() {
            if status == StatusCode::UNAUTHORIZED || status == StatusCode::FORBIDDEN {
                return Err(RpcClientError::Unauthorized { url: url_s });
            }
            let reason = parsed
                .error
                .unwrap_or_else(|| format!("node returned HTTP {status} with no error body"));
            Err(RpcClientError::NodeRejected {
                status: status.as_u16(),
                reason,
            })
        } else {
            Err(RpcClientError::UnexpectedStatus {
                url: url_s,
                status: status.as_u16(),
                body: format!(
                    "accepted={} tx_hash={:?} error={:?}",
                    parsed.accepted, parsed.tx_hash, parsed.error
                ),
            })
        }
    }

    fn mempool_tx(&self, tx_hash: &[u8; 32]) -> Result<Option<MempoolTxInfo>, RpcClientError> {
        let url = self.url_for(&format!("tx/{}", hex::encode(tx_hash)))?;
        let url_s = url.to_string();
        let resp = self.send(self.with_auth(self.http.get(url)), &url_s)?;
        let status = resp.status();
        if status == StatusCode::OK {
            // The server returns the same 200 OK for both found and
            // not-found: a `{found: true, ...}` payload or a plain
            // `{found: false}`. We deserialize loosely and branch
            // on the `found` flag.
            let parsed: WireTx = decode_body(resp, &url_s)?;
            if !parsed.found {
                return Ok(None);
            }
            let hash_hex = parsed.tx_hash.ok_or_else(|| RpcClientError::Decode {
                url: url_s.clone(),
                reason: "found=true but tx_hash missing".into(),
            })?;
            let tx_hash = parse_hash_hex(&hash_hex, &url_s)?;
            Ok(Some(MempoolTxInfo {
                tx_hash,
                fee_noms: parsed.fee.unwrap_or(0),
                fee_rate: parsed.fee_rate.unwrap_or(0),
                weight: parsed.weight.unwrap_or(0),
            }))
        } else {
            Err(classify_response_status(resp, status, &url_s))
        }
    }

    fn utxo(&self, commitment: &[u8; 33]) -> Result<Option<UtxoInfo>, RpcClientError> {
        let url = self.url_for(&format!("utxo/{}", hex::encode(commitment)))?;
        let url_s = url.to_string();
        let resp = self.send(self.with_auth(self.http.get(url)), &url_s)?;
        let status = resp.status();
        match status {
            StatusCode::OK => {
                let parsed: WireUtxo = decode_body(resp, &url_s)?;
                if !parsed.found {
                    return Ok(None);
                }
                let commitment_hex = parsed.commitment.ok_or_else(|| RpcClientError::Decode {
                    url: url_s.clone(),
                    reason: "utxo 200 missing commitment".into(),
                })?;
                let commitment = parse_commitment_hex(&commitment_hex, &url_s)?;
                Ok(Some(UtxoInfo {
                    commitment,
                    block_height: parsed.block_height.unwrap_or(0),
                    is_coinbase: parsed.is_coinbase.unwrap_or(false),
                    is_mature: parsed.is_mature.unwrap_or(false),
                }))
            }
            StatusCode::NOT_FOUND => Ok(None),
            _ => Err(classify_response_status(resp, status, &url_s)),
        }
    }
}

impl NodeRpcClient {
    fn fetch_block(&self, path: &str) -> Result<Option<BlockHeaderInfo>, RpcClientError> {
        let url = self.url_for(path)?;
        let url_s = url.to_string();
        let resp = self.send(self.with_auth(self.http.get(url)), &url_s)?;
        let status = resp.status();
        match status {
            StatusCode::OK => {
                let parsed: WireBlockHeader = decode_body(resp, &url_s)?;
                // The 200 path can still carry `{found: false}` for
                // the variant the server returns when a hash is
                // absent (it returns 404 there, but defensively we
                // accept either shape).
                if matches!(parsed.found, Some(false)) {
                    return Ok(None);
                }
                Ok(Some(BlockHeaderInfo {
                    height: parsed.height.ok_or_else(|| RpcClientError::Decode {
                        url: url_s.clone(),
                        reason: "block 200 missing height".into(),
                    })?,
                    hash: parse_hash_hex(
                        &parsed.hash.clone().ok_or_else(|| RpcClientError::Decode {
                            url: url_s.clone(),
                            reason: "block 200 missing hash".into(),
                        })?,
                        &url_s,
                    )?,
                    prev_hash: parse_hash_hex(
                        &parsed
                            .prev_hash
                            .clone()
                            .ok_or_else(|| RpcClientError::Decode {
                                url: url_s.clone(),
                                reason: "block 200 missing prev_hash".into(),
                            })?,
                        &url_s,
                    )?,
                    timestamp: parsed.timestamp.unwrap_or(0),
                    target: parse_hash_hex(
                        &parsed
                            .target
                            .clone()
                            .ok_or_else(|| RpcClientError::Decode {
                                url: url_s.clone(),
                                reason: "block 200 missing target".into(),
                            })?,
                        &url_s,
                    )?,
                    output_count: parsed.output_count,
                    kernel_count: parsed.kernel_count,
                }))
            }
            StatusCode::NOT_FOUND => Ok(None),
            _ => Err(classify_response_status(resp, status, &url_s)),
        }
    }
}

/// Builder for [`NodeRpcClient`]. Created via
/// [`NodeRpcClient::builder`].
#[derive(Debug, Clone)]
pub struct NodeRpcClientBuilder {
    base_url: Url,
    request_timeout: Duration,
    connect_timeout: Duration,
    bearer_token: Option<String>,
    user_agent: String,
}

impl NodeRpcClientBuilder {
    /// Override the per-request timeout. The default is
    /// [`DEFAULT_REQUEST_TIMEOUT`]. Must be > 0.
    pub fn request_timeout(mut self, d: Duration) -> Self {
        self.request_timeout = d;
        self
    }

    /// Override the TCP connect timeout. The default is
    /// [`DEFAULT_CONNECT_TIMEOUT`]. Must be > 0 and ≤ request_timeout.
    pub fn connect_timeout(mut self, d: Duration) -> Self {
        self.connect_timeout = d;
        self
    }

    /// Attach a bearer token for the `Authorization: Bearer <token>`
    /// header on every request. Only required by `/peers` today;
    /// other endpoints accept any token (including absent).
    pub fn bearer_token(mut self, token: impl Into<String>) -> Self {
        self.bearer_token = Some(token.into());
        self
    }

    /// Set a custom `User-Agent`. Defaults to `dom-wallet/<crate-version>`.
    pub fn user_agent(mut self, ua: impl Into<String>) -> Self {
        self.user_agent = ua.into();
        self
    }

    /// Finalise the client. Validates the URL scheme (must be `http`
    /// or `https`) and constructs the underlying HTTP client.
    pub fn build(self) -> Result<NodeRpcClient, RpcClientError> {
        if self.request_timeout.is_zero() {
            return Err(RpcClientError::Config {
                reason: "request_timeout must be > 0".into(),
            });
        }
        if self.connect_timeout.is_zero() {
            return Err(RpcClientError::Config {
                reason: "connect_timeout must be > 0".into(),
            });
        }
        if self.connect_timeout > self.request_timeout {
            return Err(RpcClientError::Config {
                reason: "connect_timeout must be <= request_timeout".into(),
            });
        }
        if !matches!(self.base_url.scheme(), "http" | "https") {
            return Err(RpcClientError::Config {
                reason: format!(
                    "base_url scheme {:?} is not supported (expected http or https)",
                    self.base_url.scheme()
                ),
            });
        }
        // Ensure the base ends with a slash so `Url::join` resolves
        // relative paths against the directory, not the parent.
        let mut base_url = self.base_url;
        if !base_url.path().ends_with('/') {
            let mut new_path = base_url.path().to_string();
            new_path.push('/');
            base_url.set_path(&new_path);
        }
        let http = Client::builder()
            .timeout(self.request_timeout)
            .connect_timeout(self.connect_timeout)
            .user_agent(self.user_agent)
            .build()
            .map_err(|e| RpcClientError::Config {
                reason: format!("reqwest build: {e}"),
            })?;
        Ok(NodeRpcClient {
            base_url,
            http,
            bearer_token: self.bearer_token,
        })
    }
}

// ── Wire DTOs ────────────────────────────────────────────────────
//
// These mirror the structs in `crates/dom-rpc/src/lib.rs`. They are
// private to this module — public surface uses the wallet-side types
// above so callers don't depend on the on-wire shape.

#[derive(Debug, Deserialize)]
struct WireHealth {
    ok: bool,
}

#[derive(Debug, Deserialize)]
struct WireStatus {
    version: u32,
    chain_height: u64,
    #[serde(default)]
    tip_hash: Option<String>,
    mempool_size: u64,
    network: String,
}

#[derive(Debug, Deserialize)]
struct WireSubmitTx {
    accepted: bool,
    #[serde(default)]
    tx_hash: Option<String>,
    #[serde(default)]
    error: Option<String>,
}

#[derive(Debug, Serialize)]
struct WireSpendRequest {
    recipient_commitment: String,
    recipient_blinding: String,
    amount_noms: u64,
    fee_noms: u64,
}

#[derive(Debug, Deserialize)]
struct WireWalletSpend {
    tx_hash: String,
}

#[derive(Debug, Deserialize)]
struct WireTx {
    found: bool,
    #[serde(default)]
    tx_hash: Option<String>,
    #[serde(default)]
    fee: Option<u64>,
    #[serde(default)]
    fee_rate: Option<u64>,
    #[serde(default)]
    weight: Option<u32>,
}

/// Combines the 200 OK header response with the 404 / explicit-not-found
/// shape behind `Option` fields. Lets `fetch_block` decode once and
/// branch on the result.
#[derive(Debug, Deserialize)]
struct WireBlockHeader {
    #[serde(default)]
    found: Option<bool>,
    #[serde(default)]
    height: Option<u64>,
    #[serde(default)]
    hash: Option<String>,
    #[serde(default)]
    prev_hash: Option<String>,
    #[serde(default)]
    timestamp: Option<u64>,
    #[serde(default)]
    target: Option<String>,
    #[serde(default)]
    output_count: Option<u32>,
    #[serde(default)]
    kernel_count: Option<u32>,
}

#[derive(Debug, Deserialize)]
struct WireUtxo {
    found: bool,
    #[serde(default)]
    commitment: Option<String>,
    #[serde(default)]
    block_height: Option<u64>,
    #[serde(default)]
    is_coinbase: Option<bool>,
    #[serde(default)]
    is_mature: Option<bool>,
}

/// Server error envelope shared across `RpcError::into_response`. The
/// submit and block paths produce their own richer shapes; this is the
/// minimal fallback shape used by `IntoResponse for RpcError`.
#[derive(Debug, Deserialize)]
struct WireErrorEnvelope {
    error: String,
}

// ── Helpers ──────────────────────────────────────────────────────

fn classify_request_error(err: reqwest::Error, url: &str) -> RpcClientError {
    // Order matters: `is_connect` is true for ConnectionRefused too, so
    // we differentiate via the timeout flag.
    if err.is_timeout() {
        if err.is_connect() {
            return RpcClientError::ConnectTimeout {
                url: url.to_string(),
            };
        }
        return RpcClientError::ReadTimeout {
            url: url.to_string(),
        };
    }
    RpcClientError::Transport {
        url: url.to_string(),
        reason: err.to_string(),
    }
}

fn classify_response_status(resp: Response, status: StatusCode, url: &str) -> RpcClientError {
    if status == StatusCode::UNAUTHORIZED || status == StatusCode::FORBIDDEN {
        return RpcClientError::Unauthorized {
            url: url.to_string(),
        };
    }
    // Try to decode the typed error envelope; fall back to opaque
    // body if it doesn't parse.
    match resp.text() {
        Ok(body) => match serde_json::from_str::<WireErrorEnvelope>(&body) {
            Ok(env) if status.is_client_error() || status.is_server_error() => {
                RpcClientError::NodeRejected {
                    status: status.as_u16(),
                    reason: env.error,
                }
            }
            _ => RpcClientError::UnexpectedStatus {
                url: url.to_string(),
                status: status.as_u16(),
                body,
            },
        },
        Err(e) => RpcClientError::Transport {
            url: url.to_string(),
            reason: format!("read body: {e}"),
        },
    }
}

fn decode_body<T: for<'de> Deserialize<'de>>(
    resp: Response,
    url: &str,
) -> Result<T, RpcClientError> {
    let bytes = resp.bytes().map_err(|e| {
        // A truncated body or connection reset mid-read surfaces here.
        // Treat it as a transport failure so callers can distinguish
        // from a real shape mismatch.
        if e.is_timeout() {
            RpcClientError::ReadTimeout {
                url: url.to_string(),
            }
        } else {
            RpcClientError::Transport {
                url: url.to_string(),
                reason: format!("read body: {e}"),
            }
        }
    })?;
    serde_json::from_slice::<T>(&bytes).map_err(|e| RpcClientError::Decode {
        url: url.to_string(),
        reason: format!("{e} (body bytes: {})", bytes.len()),
    })
}

fn parse_hash_hex(s: &str, url: &str) -> Result<[u8; 32], RpcClientError> {
    let bytes = hex::decode(s).map_err(|e| RpcClientError::Decode {
        url: url.to_string(),
        reason: format!("hash hex decode: {e}"),
    })?;
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|v: Vec<u8>| RpcClientError::Decode {
            url: url.to_string(),
            reason: format!("hash must be 32 bytes (got {})", v.len()),
        })?;
    Ok(arr)
}

fn parse_commitment_hex(s: &str, url: &str) -> Result<[u8; 33], RpcClientError> {
    let bytes = hex::decode(s).map_err(|e| RpcClientError::Decode {
        url: url.to_string(),
        reason: format!("commitment hex decode: {e}"),
    })?;
    let arr: [u8; 33] = bytes
        .try_into()
        .map_err(|v: Vec<u8>| RpcClientError::Decode {
            url: url.to_string(),
            reason: format!("commitment must be 33 bytes (got {})", v.len()),
        })?;
    Ok(arr)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builder_rejects_unsupported_scheme() {
        let url = Url::parse("ftp://node.example/").unwrap();
        let err = NodeRpcClient::builder(url).build().unwrap_err();
        match err {
            RpcClientError::Config { reason } => assert!(reason.contains("scheme")),
            other => panic!("expected Config, got {other:?}"),
        }
    }

    #[test]
    fn builder_rejects_zero_timeout() {
        let url = Url::parse("http://127.0.0.1/").unwrap();
        let err = NodeRpcClient::builder(url)
            .request_timeout(Duration::ZERO)
            .build()
            .unwrap_err();
        match err {
            RpcClientError::Config { reason } => assert!(reason.contains("request_timeout")),
            other => panic!("expected Config, got {other:?}"),
        }
    }

    #[test]
    fn builder_rejects_connect_gt_request_timeout() {
        let url = Url::parse("http://127.0.0.1/").unwrap();
        let err = NodeRpcClient::builder(url)
            .request_timeout(Duration::from_millis(100))
            .connect_timeout(Duration::from_millis(500))
            .build()
            .unwrap_err();
        match err {
            RpcClientError::Config { reason } => assert!(reason.contains("connect_timeout")),
            other => panic!("expected Config, got {other:?}"),
        }
    }

    #[test]
    fn builder_normalises_missing_trailing_slash() {
        // Without trailing slash on base path, `join("status")` would
        // resolve against the parent. The builder must ensure paths
        // join correctly.
        let url = Url::parse("http://127.0.0.1:9000/v1").unwrap();
        let client = NodeRpcClient::builder(url).build().unwrap();
        let joined = client.url_for("status").unwrap();
        assert_eq!(joined.as_str(), "http://127.0.0.1:9000/v1/status");
    }
}
