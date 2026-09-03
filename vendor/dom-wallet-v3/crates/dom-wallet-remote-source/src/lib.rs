//! Remote full-fidelity chain source for Wallet V3.
//!
//! [`RemoteNodeSource`] implements the frozen [`WalletCoreApi`] scanner surface
//! over synchronous HTTP against a remote DOM node, so `CoreChainAdapter` and
//! `SeedRestoreService` consume a remote node exactly like the embedded one:
//!
//! - `GET /chain/scan/scriptless/v1?from&to` (Bearer) serves identity, a
//!   chain-locked tip, exact canonical headers and transactions, signed kernels,
//!   range proofs, and recovery capsules. The endpoint is the frozen F7 scanner
//!   authority supplied by the pinned DOM revision.
//! - `GET /block/:height` (public) serves canonical headers for
//!   [`WalletCoreApi::canonical_hash_at_height`] and client-side
//!   [`WalletCoreApi::validate_cursor`].
//!
//! # Privacy invariant (do not weaken)
//!
//! This source downloads EVERY block of the requested range with EVERY output,
//! proof, and capsule. Selective per-output or per-commitment queries are
//! forbidden: they would reveal to the remote operator which outputs the
//! wallet cares about. Non-empty `commitment_filters` are rejected locally,
//! before any network traffic, and no endpoint keyed by a commitment is ever
//! called (`get_utxo`/`get_kernel` are deliberately unimplemented).
//!
//! # Error classes (`reports/REMOTE_SCAN_V3_SCHEMA.md` §4)
//!
//! - Retriable (the scan loop retries with backoff; NEVER terminal): HTTP 503
//!   busy → [`WalletCoreError::NodeNotReady`]; HTTP 429 / 5xx gateway /
//!   timeout / connection / DNS / TLS failures →
//!   [`WalletCoreError::TemporaryFailure`].
//! - Terminal: HTTP 401/403 (bad bearer configuration), HTTP 404 (remote node
//!   lacks `/chain/scan/scriptless/v1`), and any wire-schema violation →
//!   [`WalletCoreError::InternalFailure`]; identity drift →
//!   [`WalletCoreError::CursorChainMismatch`]; stable `canonical_gap` code →
//!   [`WalletCoreError::CanonicalGap`].
//!
//! Retry/backoff deliberately does NOT live here — the existing scan loop
//! owns retries. This source only classifies failures correctly.

#![forbid(unsafe_code)]

use dom_consensus::{BlockHeader, Transaction};
use dom_core::{fee_policy, DomError, MAX_TX_WEIGHT, MIN_RELAY_FEE_RATE};
use dom_serialization::{DomDeserialize, DomSerialize};
use dom_wallet_core_api::{
    BlockRef, BlockSelector, BlockSummary, ChainIdentity, CoinbaseScanMetadata, CoreNetwork,
    CursorValidation, FeeBreakdown, FeeEstimate, FeeEstimateRequest, FeeEstimateTarget,
    FeePolicySnapshot, FeeRate, FeeValidation, KernelQueryResult, MempoolPolicySnapshot, ScanBlock,
    ScanInput, ScanKernel, ScanOutput, ScanRequest, ScanResult, ScanStart, ScanTransaction,
    SubmissionResult, SubmitTransactionRequest, SyncStatus, TransactionIdentifier,
    TransactionLocation, TransactionShape, TransactionStatus, TransactionWeight, UtxoQueryResult,
    WalletCoreApi, WalletCoreError, WalletScanCursor,
};
use serde::Deserialize;
use std::fmt;
use std::sync::Mutex;
use std::time::Duration;
use thiserror::Error;

/// TCP connect timeout for every remote request.
pub const REMOTE_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// Total per-request timeout. The node's own server-side request timeout is
/// 30 s, so a slower answer will never arrive anyway.
pub const REMOTE_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// `/chain/scan/scriptless/v1` wire schema version this client understands. Any other
/// version on the wire is a terminal schema violation.
pub const REMOTE_FULL_SCAN_SCHEMA_VERSION: u32 = 1;

/// Server-side bound of one `/chain/scan/scriptless/v1` page. A response
/// spanning more heights than this is a schema violation.
pub const REMOTE_MAX_FULL_SCAN_RANGE: u64 = 64;

/// Configuration errors raised while constructing a [`RemoteNodeSource`].
#[derive(Debug, Error)]
pub enum RemoteSourceConfigError {
    /// The base URL failed to parse.
    #[error("invalid remote node base URL: {0}")]
    InvalidBaseUrl(String),
    /// The base URL scheme is not `http`/`https`.
    #[error("remote node base URL must use http or https")]
    UnsupportedScheme,
    /// A bearer token was supplied but is empty after trimming.
    #[error("remote node bearer token must not be empty")]
    EmptyBearerToken,
    /// The HTTP client could not be constructed.
    #[error("failed to build remote HTTP client: {0}")]
    ClientBuild(String),
}

/// Inconsistent tip regression reported by the remote node within one session.
///
/// The observed canonical tip height moved backwards relative to a tip this
/// session already saw. A canonical proof-of-work switch to a lower height is
/// theoretically possible but extremely unusual, so this is surfaced as an
/// alert ("possibly lying remote node") for the consumer to act on — it never
/// aborts a scan by itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TipRegression {
    /// Highest tip previously observed in this session.
    pub previous: BlockRef,
    /// Regressed tip reported afterwards.
    pub observed: BlockRef,
}

/// Bearer token wrapper that never leaks the secret through `Debug`.
struct BearerToken(String);

impl fmt::Debug for BearerToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("BearerToken(<redacted>)")
    }
}

#[derive(Debug, Default)]
struct SessionState {
    /// Identity pinned on the first successful response; all later responses
    /// must match it field by field (tip excluded).
    pinned_identity: Option<ChainIdentity>,
    /// Highest tip observed in this session (high-water mark, so repeated
    /// regressions keep being detected against the honest maximum).
    highest_tip: Option<BlockRef>,
    /// First-detected tip regression, kept until the session ends.
    tip_regression: Option<TipRegression>,
}

/// Remote DOM node consumed through the frozen [`WalletCoreApi`] contract.
///
/// The scan surface (`chain_identity`, `scan_range`, `scan_next`,
/// `validate_cursor`, `canonical_hash_at_height`) plus the frozen deterministic
/// fee policy and derived readiness are served remotely. Transaction
/// submission remains unavailable: broadcasting stays on the retained node.
pub struct RemoteNodeSource {
    base_url: String,
    bearer_token: Option<BearerToken>,
    client: reqwest::blocking::Client,
    session: Mutex<SessionState>,
}

impl fmt::Debug for RemoteNodeSource {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RemoteNodeSource")
            .field("base_url", &self.base_url)
            .field(
                "bearer_token",
                &self.bearer_token.as_ref().map(|_| "<redacted>"),
            )
            .finish_non_exhaustive()
    }
}

impl RemoteNodeSource {
    /// Build a remote source for `base_url` (e.g. `http://127.0.0.1:8645`).
    ///
    /// The bearer token is trimmed (the node writes `~/.dom/rpc_token` with a
    /// trailing newline). Redirects are disabled so the token can never be
    /// replayed to another host.
    pub fn new(
        base_url: &str,
        bearer_token: Option<&str>,
    ) -> Result<Self, RemoteSourceConfigError> {
        let parsed = url::Url::parse(base_url.trim())
            .map_err(|error| RemoteSourceConfigError::InvalidBaseUrl(error.to_string()))?;
        if !matches!(parsed.scheme(), "http" | "https") {
            return Err(RemoteSourceConfigError::UnsupportedScheme);
        }
        let bearer_token = match bearer_token {
            None => None,
            Some(raw) => {
                let trimmed = raw.trim();
                if trimmed.is_empty() {
                    return Err(RemoteSourceConfigError::EmptyBearerToken);
                }
                Some(BearerToken(trimmed.to_string()))
            }
        };
        let client = reqwest::blocking::Client::builder()
            .connect_timeout(REMOTE_CONNECT_TIMEOUT)
            .timeout(REMOTE_REQUEST_TIMEOUT)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|error| RemoteSourceConfigError::ClientBuild(error.to_string()))?;
        Ok(Self {
            base_url: parsed.as_str().trim_end_matches('/').to_string(),
            bearer_token,
            client,
            session: Mutex::new(SessionState::default()),
        })
    }

    /// Tip regression detected in this session, if any. `Some` means the
    /// remote node reported a canonical tip below a tip it already served —
    /// the consumer decides whether to distrust the node.
    pub fn tip_regression(&self) -> Option<TipRegression> {
        self.lock_session().tip_regression
    }

    /// Highest canonical tip observed from the remote node in this session.
    pub fn last_observed_tip(&self) -> Option<BlockRef> {
        self.lock_session().highest_tip
    }

    fn lock_session(&self) -> std::sync::MutexGuard<'_, SessionState> {
        // A poisoned lock only means another thread panicked mid-update; the
        // state itself stays structurally valid, so recover instead of
        // panicking in production.
        self.session
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn http_get(
        &self,
        path_and_query: &str,
        authenticated: bool,
    ) -> Result<HttpReply, WalletCoreError> {
        let url = format!("{}{}", self.base_url, path_and_query);
        let mut request = self.client.get(url);
        if authenticated {
            if let Some(token) = &self.bearer_token {
                request = request.bearer_auth(&token.0);
            }
        }
        let response = request.send().map_err(map_transport_error)?;
        let status = response.status().as_u16();
        let body = response.text().map_err(map_transport_error)?;
        Ok(HttpReply { status, body })
    }

    /// Fetch and fully validate one `/chain/scan/scriptless/v1` page.
    ///
    /// PRIVACY: the request carries only a height range — never an output or
    /// commitment selector — and the response carries all blocks of the range.
    fn fetch_full_scan(
        &self,
        from: u64,
        to: u64,
        expected_network_magic: Option<u32>,
        expected_chain_id: Option<[u8; 32]>,
        anchor: Option<BlockRef>,
    ) -> Result<ParsedFullScan, WalletCoreError> {
        if from > to || (from == 0) != anchor.is_none() {
            return Err(WalletCoreError::InvalidScanRequest(
                "scriptless scan requires a non-empty range and an anchor exactly when from > 0"
                    .to_string(),
            ));
        }
        let mut query = format!("/chain/scan/scriptless/v1?from={from}&to={to}");
        if let (Some(network_magic), Some(chain_id)) = (expected_network_magic, expected_chain_id) {
            query.push_str(&format!(
                "&expected_network_magic={}&expected_chain_id={}",
                network_magic,
                hex::encode(chain_id)
            ));
        } else if expected_network_magic.is_some() || expected_chain_id.is_some() {
            return Err(WalletCoreError::InvalidScanRequest(
                "scriptless scan chain expectations must be supplied together".to_string(),
            ));
        }
        if let Some(anchor) = anchor {
            if anchor.height != from - 1 {
                return Err(WalletCoreError::InvalidScanRequest(
                    "scriptless scan anchor height is not from - 1".to_string(),
                ));
            }
            query.push_str("&anchor_hash=");
            query.push_str(&hex::encode(anchor.hash));
        }
        let reply = self.http_get(&query, true)?;
        if reply.status != 200 {
            return Err(map_full_scan_status(reply.status, &reply.body));
        }
        parse_full_scan(from, to, anchor, &reply.body)
    }

    /// Pin the session identity on first sight; afterwards require every
    /// response to describe the same chain, and track the reported tip.
    fn observe_identity(&self, identity: &ChainIdentity) -> Result<(), WalletCoreError> {
        let mut session = self.lock_session();
        if let Some(pinned) = &session.pinned_identity {
            if !same_immutable_identity(pinned, identity) {
                return Err(WalletCoreError::CursorChainMismatch(
                    "remote node identity drifted within this session".to_string(),
                ));
            }
        } else {
            session.pinned_identity = Some(identity.clone());
        }
        let observed = identity.current_tip;
        match session.highest_tip {
            Some(previous) if observed.height < previous.height => {
                if session.tip_regression.is_none() {
                    session.tip_regression = Some(TipRegression { previous, observed });
                }
            }
            _ => session.highest_tip = Some(observed),
        }
        Ok(())
    }

    fn session_identity_or_probe(&self) -> Result<ChainIdentity, WalletCoreError> {
        if let Some(pinned) = self.lock_session().pinned_identity.clone() {
            return Ok(pinned);
        }
        self.chain_identity()
    }

    /// Fetch the canonical hash at `height` through the public header
    /// endpoint. `404 {"found": false}` means "no canonical block here".
    fn fetch_block_hash(&self, height: u64) -> Result<Option<[u8; 32]>, WalletCoreError> {
        let reply = self.http_get(&format!("/block/{height}"), false)?;
        match reply.status {
            200 => {
                let header: WireBlockHeader = serde_json::from_str(&reply.body)
                    .map_err(|_| schema_violation("BLOCK_HEADER_DECODE"))?;
                if header.height != height {
                    return Err(schema_violation("BLOCK_HEADER_HEIGHT"));
                }
                Ok(Some(decode_hash32(&header.hash, "BLOCK_HEADER_HASH")?))
            }
            404 => Ok(None),
            other => Err(map_block_status(other, &reply.body)),
        }
    }

    fn core_shape(shape: TransactionShape) -> fee_policy::TransactionShape {
        fee_policy::TransactionShape {
            input_count: shape.input_count,
            output_count: shape.output_count,
            kernel_count: shape.kernel_count,
        }
    }

    fn api_fee_rate(rate: fee_policy::FeeRate) -> FeeRate {
        FeeRate {
            noms_per_weight_unit: rate.noms_per_weight_unit,
        }
    }

    fn api_weight(weight: fee_policy::TransactionWeight) -> TransactionWeight {
        TransactionWeight {
            input_weight: weight.input_weight,
            output_weight: weight.output_weight,
            kernel_weight: weight.kernel_weight,
            total_weight: weight.total_weight,
        }
    }

    fn api_breakdown(network: CoreNetwork, breakdown: fee_policy::FeeBreakdown) -> FeeBreakdown {
        FeeBreakdown {
            input_count: breakdown.shape.input_count,
            output_count: breakdown.shape.output_count,
            kernel_count: breakdown.shape.kernel_count,
            input_weight: breakdown.weight.input_weight,
            output_weight: breakdown.weight.output_weight,
            kernel_weight: breakdown.weight.kernel_weight,
            total_weight: breakdown.weight.total_weight,
            minimum_fee_noms: breakdown.minimum_fee_noms,
            recommended_fee_noms: breakdown.recommended_fee_noms,
            minimum_fee_rate: Self::api_fee_rate(breakdown.minimum_fee_rate),
            recommended_fee_rate: Self::api_fee_rate(breakdown.recommended_fee_rate),
            policy_version: breakdown.policy_version,
            network,
            validity_horizon: None,
            dust_threshold_noms: breakdown.dust_threshold_noms,
        }
    }

    fn map_policy_error(error: DomError) -> WalletCoreError {
        match error {
            DomError::Invalid(message) | DomError::PolicyRejected(message) => {
                WalletCoreError::InvalidScanRequest(message)
            }
            DomError::Internal(message) => WalletCoreError::InternalFailure(message),
            other => WalletCoreError::InternalFailure(other.to_string()),
        }
    }
}

impl WalletCoreApi for RemoteNodeSource {
    fn chain_identity(&self) -> Result<ChainIdentity, WalletCoreError> {
        // Height zero needs no prior anchor and returns the identity and the
        // chain-locked snapshot tip in the same authenticated response.
        let parsed = self.fetch_full_scan(0, 0, None, None, None)?;
        self.observe_identity(&parsed.identity)?;
        Ok(parsed.identity)
    }

    fn scan_range(&self, request: ScanRequest) -> Result<ScanResult, WalletCoreError> {
        if !request.commitment_filters.is_empty() {
            // PRIVACY: a filtered remote scan would reveal wallet interest in
            // specific commitments. Rejected before any network traffic.
            return Err(WalletCoreError::InvalidScanRequest(
                "remote source is full-scan only: commitment filters are forbidden".to_string(),
            ));
        }
        if request.max_blocks == 0 {
            return Err(WalletCoreError::InvalidScanRequest(
                "max_blocks must be greater than zero".to_string(),
            ));
        }
        let (start_height, supplied_anchor) = match &request.start {
            ScanStart::Height(height) => (*height, None),
            ScanStart::Cursor(cursor) => {
                // Mirrors the embedded node: a stale anchor is CursorReorg.
                self.validate_cursor(*cursor)?;
                (
                    cursor.next_height,
                    Some(BlockRef {
                        height: cursor.anchor_height,
                        hash: cursor.anchor_hash,
                    }),
                )
            }
        };
        let stop_height = request.stop_height.unwrap_or(u64::MAX);
        if start_height > stop_height {
            let identity = self.session_identity_or_probe()?;
            if request.network != identity.network || request.chain_id != identity.chain_id {
                return Err(WalletCoreError::CursorChainMismatch(
                    "request identity does not match remote node identity".to_string(),
                ));
            }
            self.observe_identity(&identity)?;
            return Ok(ScanResult {
                tip: identity.current_tip,
                blocks: Vec::new(),
                continuation: None,
            });
        }
        // The authoritative RPC rejects pages wider than 64 blocks. Keep the
        // WalletCoreApi contract by paging large wallet requests instead of
        // forwarding an invalid range.
        let page_blocks = request.max_blocks.min(REMOTE_MAX_FULL_SCAN_RANGE);
        let span_end = start_height.saturating_add(page_blocks - 1);
        let wire_to = match request.stop_height {
            Some(stop) => span_end.min(stop),
            None => span_end,
        };
        let anchor = if start_height == 0 {
            None
        } else if let Some(anchor) = supplied_anchor {
            Some(anchor)
        } else {
            Some(BlockRef {
                height: start_height - 1,
                hash: self.fetch_block_hash(start_height - 1)?.ok_or_else(|| {
                    WalletCoreError::CanonicalGap(
                        "remote scan start has no canonical predecessor".to_string(),
                    )
                })?,
            })
        };
        let parsed = self.fetch_full_scan(
            start_height,
            wire_to,
            Some(request.network.magic()),
            Some(request.chain_id),
            anchor,
        )?;
        // Mirrors EmbeddedWalletCoreApi::validate_request_identity.
        if request.network != parsed.identity.network
            || request.chain_id != parsed.identity.chain_id
        {
            return Err(WalletCoreError::CursorChainMismatch(
                "request identity does not match remote node identity".to_string(),
            ));
        }
        self.observe_identity(&parsed.identity)?;

        let tip = parsed.identity.current_tip;
        // The server clamps the page (range cap, tip, response budget) and
        // echoes the effective `to`; continuation follows the effective page,
        // exactly like the embedded scan_range.
        let stop_height = request.stop_height.unwrap_or(tip.height).min(tip.height);
        let continuation = parsed.blocks.last().and_then(|block| {
            (block.height < stop_height).then(|| {
                WalletScanCursor::new(
                    parsed.identity.network,
                    parsed.identity.chain_id,
                    block.height.saturating_add(1),
                    BlockRef {
                        height: block.height,
                        hash: block.block_hash,
                    },
                )
            })
        });
        Ok(ScanResult {
            tip,
            blocks: parsed.blocks,
            continuation,
        })
    }

    fn validate_cursor(
        &self,
        cursor: WalletScanCursor,
    ) -> Result<CursorValidation, WalletCoreError> {
        cursor.validate_shape()?;
        let identity = self.session_identity_or_probe()?;
        if cursor.network_magic != identity.network_magic || cursor.chain_id != identity.chain_id {
            return Err(WalletCoreError::CursorChainMismatch(
                "cursor identity does not match remote node identity".to_string(),
            ));
        }
        // Client-side mirror of the embedded validate_cursor_locked, built on
        // the public header endpoint.
        match self.fetch_block_hash(cursor.anchor_height)? {
            None => Err(WalletCoreError::CursorReorg(
                "cursor anchor height is no longer canonical".to_string(),
            )),
            Some(hash) if hash != cursor.anchor_hash => Err(WalletCoreError::CursorReorg(
                "cursor anchor hash differs from canonical hash".to_string(),
            )),
            Some(_) => Ok(CursorValidation {
                valid: true,
                safe_rescan_anchor: BlockRef {
                    height: cursor.anchor_height,
                    hash: cursor.anchor_hash,
                },
            }),
        }
    }

    fn canonical_hash_at_height(&self, height: u64) -> Result<Option<[u8; 32]>, WalletCoreError> {
        self.fetch_block_hash(height)
    }

    fn get_utxo(&self, _commitment: &[u8; 33]) -> Result<Option<UtxoQueryResult>, WalletCoreError> {
        // PRIVACY: also intentionally unimplemented — a per-commitment lookup
        // against a remote operator leaks wallet interest in that output.
        Err(requires_embedded_node("utxo lookup"))
    }

    fn get_kernel(&self, _excess: &[u8; 33]) -> Result<Option<KernelQueryResult>, WalletCoreError> {
        Err(requires_embedded_node("kernel lookup"))
    }

    fn get_block_summary(
        &self,
        _selector: BlockSelector,
    ) -> Result<Option<BlockSummary>, WalletCoreError> {
        Err(requires_embedded_node("block summary"))
    }

    fn transaction_status(
        &self,
        _id: TransactionIdentifier,
    ) -> Result<TransactionStatus, WalletCoreError> {
        Err(requires_embedded_node("transaction status"))
    }

    fn submit_transaction(
        &self,
        _request: SubmitTransactionRequest,
    ) -> Result<SubmissionResult, WalletCoreError> {
        Err(requires_embedded_node("transaction submission"))
    }

    fn rebroadcast_transaction(
        &self,
        _id: TransactionIdentifier,
    ) -> Result<SubmissionResult, WalletCoreError> {
        Err(requires_embedded_node("transaction rebroadcast"))
    }

    fn query_submission(
        &self,
        _id: TransactionIdentifier,
    ) -> Result<SubmissionResult, WalletCoreError> {
        Err(requires_embedded_node("submission query"))
    }

    fn sync_status(&self) -> Result<SyncStatus, WalletCoreError> {
        // A remote node that answers already serves its canonical chain, so
        // the only states are Ready and Busy (retriable outage).
        match self.chain_identity() {
            Ok(_) => Ok(SyncStatus::Ready),
            Err(WalletCoreError::NodeNotReady(_) | WalletCoreError::TemporaryFailure(_)) => {
                Ok(SyncStatus::Busy)
            }
            Err(error) => Err(error),
        }
    }

    fn is_ready_for_wallet_operations(&self) -> Result<bool, WalletCoreError> {
        match self.chain_identity() {
            Ok(_) => Ok(true),
            Err(WalletCoreError::NodeNotReady(_) | WalletCoreError::TemporaryFailure(_)) => {
                Ok(false)
            }
            Err(error) => Err(error),
        }
    }

    fn mempool_policy_snapshot(&self) -> Result<MempoolPolicySnapshot, WalletCoreError> {
        Err(requires_embedded_node("mempool policy"))
    }

    fn fee_policy_snapshot(&self) -> Result<FeePolicySnapshot, WalletCoreError> {
        let network = self.session_identity_or_probe()?.network;
        Ok(FeePolicySnapshot {
            policy_version: fee_policy::FEE_POLICY_VERSION,
            network,
            min_relay_fee_rate: MIN_RELAY_FEE_RATE,
            min_mempool_fee_rate: MIN_RELAY_FEE_RATE,
            recommended_fee_rate: fee_policy::FeeRate::recommended()
                .map_err(Self::map_policy_error)?
                .noms_per_weight_unit,
            dust_threshold_noms: fee_policy::DUST_THRESHOLD_NOMS,
            max_tx_weight: u64::from(MAX_TX_WEIGHT),
            validity_horizon: None,
        })
    }

    fn transaction_weight(
        &self,
        shape: TransactionShape,
    ) -> Result<TransactionWeight, WalletCoreError> {
        let weight = fee_policy::transaction_weight(Self::core_shape(shape))
            .map_err(Self::map_policy_error)?;
        Ok(Self::api_weight(weight))
    }

    fn minimum_fee(&self, shape: TransactionShape) -> Result<FeeBreakdown, WalletCoreError> {
        let network = self.session_identity_or_probe()?.network;
        let breakdown =
            fee_policy::fee_breakdown(Self::core_shape(shape)).map_err(Self::map_policy_error)?;
        Ok(Self::api_breakdown(network, breakdown))
    }

    fn estimate_fee(&self, request: FeeEstimateRequest) -> Result<FeeEstimate, WalletCoreError> {
        let breakdown = self.minimum_fee(request.shape)?;
        let (selected_fee_noms, selected_fee_rate) = match request.target {
            FeeEstimateTarget::Minimum => (breakdown.minimum_fee_noms, breakdown.minimum_fee_rate),
            FeeEstimateTarget::Recommended => (
                breakdown.recommended_fee_noms,
                breakdown.recommended_fee_rate,
            ),
        };
        Ok(FeeEstimate {
            breakdown,
            selected_fee_noms,
            selected_fee_rate,
        })
    }

    fn validate_fee(&self, transaction: &Transaction) -> Result<FeeValidation, WalletCoreError> {
        let network = self.session_identity_or_probe()?.network;
        let fee = transaction.total_fee().map_err(Self::map_policy_error)?;
        let shape = transaction.fee_shape().map_err(Self::map_policy_error)?;
        let breakdown = fee_policy::fee_breakdown(shape).map_err(Self::map_policy_error)?;
        let minimum_fee_noms = breakdown.minimum_fee_noms;
        let total_weight = breakdown.weight.total_weight;
        let api_breakdown = Self::api_breakdown(network, breakdown);
        let accepted_by_policy = fee >= minimum_fee_noms;
        let shortfall_noms = if accepted_by_policy {
            0
        } else {
            minimum_fee_noms
                .checked_sub(fee)
                .ok_or_else(|| WalletCoreError::InternalFailure("fee shortfall underflow".into()))?
        };
        let actual_fee_rate =
            fee_policy::actual_fee_rate(fee, total_weight).map_err(Self::map_policy_error)?;
        Ok(FeeValidation {
            accepted_by_policy,
            actual_fee_noms: fee,
            minimum_fee_noms,
            shortfall_noms,
            actual_fee_rate: Self::api_fee_rate(actual_fee_rate),
            breakdown: api_breakdown,
        })
    }
}

struct HttpReply {
    status: u16,
    body: String,
}

/// Fully validated `/chain/scan/scriptless/v1` page mapped to frozen Core types.
#[derive(Debug)]
struct ParsedFullScan {
    identity: ChainIdentity,
    blocks: Vec<ScanBlock>,
}

/// Stable, non-retriable "this needs the embedded node" error.
///
/// `InternalFailure` maps to `CoreScanError::CoreContract` (terminal) in the
/// wallet, so composition mistakes fail fast instead of retrying forever. The
/// app composition must never wire SUBMIT/FEE services to a remote source.
fn requires_embedded_node(operation: &str) -> WalletCoreError {
    WalletCoreError::InternalFailure(format!(
        "operation requires the embedded node: remote scan source does not serve {operation}"
    ))
}

fn schema_violation(code: &str) -> WalletCoreError {
    WalletCoreError::InternalFailure(format!("remote schema violation: {code}"))
}

/// Transport-level failures (timeout, refused/reset connection, DNS, TLS) are
/// all transient from the wallet's perspective: the scan loop retries with
/// backoff. The error text never contains the bearer token.
fn map_transport_error(error: reqwest::Error) -> WalletCoreError {
    WalletCoreError::TemporaryFailure(format!("remote transport failure: {error}"))
}

/// Map a non-200 `/chain/scan/scriptless/v1` status per the pinned contract.
fn map_full_scan_status(status: u16, body: &str) -> WalletCoreError {
    match status {
        503 => WalletCoreError::NodeNotReady(format!("remote chain busy: {}", body_snippet(body))),
        429 => WalletCoreError::TemporaryFailure("remote rate limited".to_string()),
        401 | 403 => WalletCoreError::InternalFailure(
            "remote unauthorized: check the configured bearer token".to_string(),
        ),
        404 => WalletCoreError::InternalFailure(
            "remote node lacks /chain/scan/scriptless/v1: upgrade the remote node".to_string(),
        ),
        409 => WalletCoreError::CursorReorg(format!(
            "remote scriptless scan anchor is no longer canonical: {}",
            body_snippet(body)
        )),
        400 => WalletCoreError::InvalidScanRequest(format!(
            "remote rejected scan query: {}",
            body_snippet(body)
        )),
        500 if json_error_code(body).as_deref() == Some("canonical_gap") => {
            WalletCoreError::CanonicalGap(format!("remote {}", body_snippet(body)))
        }
        500..=599 => WalletCoreError::TemporaryFailure(format!(
            "remote server failure {status}: {}",
            body_snippet(body)
        )),
        other => WalletCoreError::InternalFailure(format!(
            "remote returned unexpected status {other}: {}",
            body_snippet(body)
        )),
    }
}

/// Map a non-200/404 public `/block/:height` status.
fn map_block_status(status: u16, body: &str) -> WalletCoreError {
    match status {
        503 => WalletCoreError::NodeNotReady(format!("remote chain busy: {}", body_snippet(body))),
        429 => WalletCoreError::TemporaryFailure("remote rate limited".to_string()),
        500..=599 => WalletCoreError::TemporaryFailure(format!(
            "remote server failure {status}: {}",
            body_snippet(body)
        )),
        other => WalletCoreError::InternalFailure(format!(
            "remote block endpoint returned unexpected status {other}: {}",
            body_snippet(body)
        )),
    }
}

fn body_snippet(body: &str) -> String {
    const LIMIT: usize = 200;
    let trimmed = body.trim();
    if trimmed.len() <= LIMIT {
        trimmed.to_string()
    } else {
        let mut end = LIMIT;
        while !trimmed.is_char_boundary(end) {
            end -= 1;
        }
        format!("{}…", &trimmed[..end])
    }
}

fn json_error_code(body: &str) -> Option<String> {
    let value: serde_json::Value = serde_json::from_str(body).ok()?;
    Some(value.get("code")?.as_str()?.to_string())
}

fn same_immutable_identity(expected: &ChainIdentity, actual: &ChainIdentity) -> bool {
    expected.network == actual.network
        && expected.network_magic == actual.network_magic
        && expected.chain_id == actual.chain_id
        && expected.genesis_hash == actual.genesis_hash
        && expected.protocol_version == actual.protocol_version
        && expected.range_proof_serialization_version == actual.range_proof_serialization_version
        && expected.coinbase_maturity == actual.coinbase_maturity
}

// ── Frozen F7 scriptless scanner wire schema ────────────────────────────────────

#[derive(Deserialize)]
struct WireFullScan {
    schema_version: u16,
    status: String,
    canonical: bool,
    identity: WireIdentity,
    requested_from: u64,
    requested_to: u64,
    served_from: u64,
    served_to: Option<u64>,
    request_anchor: Option<WireAnchor>,
    blocks: Vec<WireBlock>,
    continuation: Option<WireContinuation>,
}

#[derive(Deserialize)]
struct WireIdentity {
    network: String,
    network_magic: u32,
    chain_id: String,
    genesis_hash: String,
    protocol_version: u32,
    range_proof_serialization_version: u8,
    coinbase_maturity: u64,
    tip_height: u64,
    tip_hash: String,
}

#[derive(Deserialize)]
struct WireAnchor {
    height: u64,
    block_hash: String,
}

#[derive(Deserialize)]
struct WireBlock {
    height: u64,
    block_hash: String,
    previous_block_hash: String,
    canonical_header_bytes: String,
    timestamp: u64,
    canonical_marker: String,
    transactions: Vec<WireTransaction>,
    protocol_version: u32,
    range_proof_serialization_version: u8,
    total_fees_noms: u64,
    coinbase: WireCoinbase,
}

#[derive(Deserialize)]
struct WireCoinbase {
    output_commitment: String,
    explicit_value: u64,
    kernel_excess: String,
    kernel_features: u8,
    kernel_excess_signature: String,
    offset: String,
    output_proof_envelope: String,
}

#[derive(Deserialize)]
struct WireTransaction {
    block_height: u64,
    block_hash: String,
    transaction_index: u32,
    tx_hash: String,
    canonical_bytes: String,
    inputs: Vec<WireInput>,
    outputs: Vec<WireOutput>,
    kernels: Vec<WireKernel>,
    offset: String,
}

#[derive(Deserialize)]
struct WireInput {
    spent_commitment: String,
}

#[derive(Deserialize)]
struct WireOutput {
    commitment: String,
    range_proof: String,
    recovery_capsule: String,
    recovery_version: u16,
    is_coinbase: bool,
    block_height: u64,
    block_hash: String,
    output_position: u32,
}

#[derive(Deserialize)]
struct WireKernel {
    excess: String,
    features: u8,
    fee: u64,
    lock_height: u64,
    excess_signature: String,
}

#[derive(Deserialize)]
struct WireContinuation {
    next_height: u64,
    anchor: WireAnchor,
    snapshot_tip_height: u64,
    snapshot_tip_hash: String,
}

#[derive(Deserialize)]
struct WireBlockHeader {
    height: u64,
    hash: String,
}

fn decode_fixed<const N: usize>(text: &str, code: &str) -> Result<[u8; N], WalletCoreError> {
    let bytes = hex::decode(text).map_err(|_| schema_violation(code))?;
    bytes.try_into().map_err(|_| schema_violation(code))
}

fn decode_hash32(text: &str, code: &str) -> Result<[u8; 32], WalletCoreError> {
    decode_fixed(text, code)
}

fn decode_commitment33(text: &str, code: &str) -> Result<[u8; 33], WalletCoreError> {
    decode_fixed(text, code)
}

fn decode_hex_blob(text: &str, code: &str) -> Result<Vec<u8>, WalletCoreError> {
    hex::decode(text).map_err(|_| schema_violation(code))
}

fn decode_network(name: &str) -> Result<CoreNetwork, WalletCoreError> {
    match name {
        "mainnet" => Ok(CoreNetwork::Mainnet),
        "testnet" => Ok(CoreNetwork::Testnet),
        "regtest" => Ok(CoreNetwork::Regtest),
        _ => Err(schema_violation("NETWORK_NAME")),
    }
}

/// Parse and validate one page against the pinned wire contract. Any
/// violation is terminal — a page from an untrusted schema is never partially
/// consumed.
fn parse_full_scan(
    requested_from: u64,
    requested_to: u64,
    expected_anchor: Option<BlockRef>,
    body: &str,
) -> Result<ParsedFullScan, WalletCoreError> {
    let wire: WireFullScan =
        serde_json::from_str(body).map_err(|_| schema_violation("JSON_DECODE"))?;
    if u32::from(wire.schema_version) != REMOTE_FULL_SCAN_SCHEMA_VERSION
        || wire.status != "ok"
        || !wire.canonical
    {
        return Err(schema_violation("SCHEMA_VERSION"));
    }

    let network = decode_network(&wire.identity.network)?;
    let identity = ChainIdentity {
        network,
        network_magic: wire.identity.network_magic,
        chain_id: decode_hash32(&wire.identity.chain_id, "CHAIN_ID_HEX")?,
        genesis_hash: decode_hash32(&wire.identity.genesis_hash, "GENESIS_HASH_HEX")?,
        protocol_version: wire.identity.protocol_version,
        range_proof_serialization_version: wire.identity.range_proof_serialization_version,
        coinbase_maturity: wire.identity.coinbase_maturity,
        current_tip: BlockRef {
            height: wire.identity.tip_height,
            hash: decode_hash32(&wire.identity.tip_hash, "TIP_HASH_HEX")?,
        },
    };

    if wire.requested_from != requested_from
        || wire.requested_to != requested_to
        || wire.served_from != requested_from
    {
        return Err(schema_violation("REQUEST_ECHO"));
    }
    let request_anchor = wire
        .request_anchor
        .map(|anchor| {
            Ok(BlockRef {
                height: anchor.height,
                hash: decode_hash32(&anchor.block_hash, "REQUEST_ANCHOR_HASH")?,
            })
        })
        .transpose()?;
    if request_anchor != expected_anchor {
        return Err(schema_violation("REQUEST_ANCHOR"));
    }
    if wire.blocks.len() as u64 > REMOTE_MAX_FULL_SCAN_RANGE {
        return Err(schema_violation("RANGE_TOO_WIDE"));
    }
    let served_to = wire.blocks.last().map(|block| block.height);
    if wire.served_to != served_to
        || served_to
            .is_some_and(|height| height > requested_to || height > identity.current_tip.height)
    {
        return Err(schema_violation("SERVED_RANGE"));
    }

    let mut blocks = Vec::with_capacity(wire.blocks.len());
    let mut previous_hash = expected_anchor.map(|anchor| anchor.hash);
    for (index, block) in wire.blocks.into_iter().enumerate() {
        let expected_height = requested_from
            .checked_add(index as u64)
            .ok_or_else(|| schema_violation("HEIGHT_OVERFLOW"))?;
        if block.height != expected_height {
            return Err(schema_violation("NONCONSECUTIVE_HEIGHT"));
        }
        let block_hash = decode_hash32(&block.block_hash, "BLOCK_HASH_HEX")?;
        let previous_block_hash = decode_hash32(&block.previous_block_hash, "PREVIOUS_HASH_HEX")?;
        let canonical_marker = decode_hash32(&block.canonical_marker, "CANONICAL_MARKER_HEX")?;
        let canonical_header_bytes =
            decode_hex_blob(&block.canonical_header_bytes, "CANONICAL_HEADER_HEX")?;
        let header = BlockHeader::from_bytes(&canonical_header_bytes)
            .map_err(|_| schema_violation("CANONICAL_HEADER_DECODE"))?;
        if header
            .to_bytes()
            .map_err(|_| schema_violation("CANONICAL_HEADER_REENCODE"))?
            != canonical_header_bytes
            || *dom_chain::canonical_header_identifier(
                identity.network_magic,
                &canonical_header_bytes,
            )
            .map_err(|_| schema_violation("CANONICAL_HEADER_IDENTIFIER"))?
            .as_bytes()
                != block_hash
            || header.height.0 != block.height
            || *header.prev_hash.as_bytes() != previous_block_hash
            || header.timestamp.0 != block.timestamp
            || header.version != block.protocol_version
            || canonical_marker != block_hash
        {
            return Err(schema_violation("CANONICAL_HEADER"));
        }
        if let Some(expected_previous) = previous_hash {
            if previous_block_hash != expected_previous {
                return Err(schema_violation("PREVIOUS_HASH_CHAIN"));
            }
        }
        previous_hash = Some(block_hash);

        let coinbase_proof_envelope = decode_hex_blob(
            &block.coinbase.output_proof_envelope,
            "COINBASE_PROOF_ENVELOPE_HEX",
        )?;
        let (coinbase_range_proof, coinbase_recovery_capsule, coinbase_recovery_version) =
            split_proof_envelope(&coinbase_proof_envelope)?;
        let coinbase = CoinbaseScanMetadata {
            output_commitment: decode_commitment33(
                &block.coinbase.output_commitment,
                "COINBASE_COMMITMENT_HEX",
            )?,
            explicit_value: block.coinbase.explicit_value,
            kernel_excess: decode_commitment33(
                &block.coinbase.kernel_excess,
                "COINBASE_EXCESS_HEX",
            )?,
            kernel_features: block.coinbase.kernel_features,
            kernel_excess_signature: decode_fixed(
                &block.coinbase.kernel_excess_signature,
                "COINBASE_SIGNATURE_HEX",
            )?,
            offset: decode_fixed(&block.coinbase.offset, "COINBASE_OFFSET_HEX")?,
            output_proof_envelope: coinbase_proof_envelope,
        };

        let mut outputs = vec![ScanOutput {
            commitment: coinbase.output_commitment,
            range_proof: coinbase_range_proof,
            recovery_capsule: coinbase_recovery_capsule,
            recovery_version: coinbase_recovery_version,
            is_coinbase: true,
            block_height: block.height,
            block_hash,
            output_position: 0,
        }];
        let mut inputs = Vec::new();
        let mut kernels = vec![ScanKernel {
            excess: coinbase.kernel_excess,
            features: coinbase.kernel_features,
            fee: 0,
            lock_height: 0,
            excess_signature: coinbase.kernel_excess_signature,
        }];
        let mut transactions = Vec::with_capacity(block.transactions.len());
        let mut next_output_position = 1_u32;
        for (transaction_index, transaction) in block.transactions.into_iter().enumerate() {
            let transaction_first_output_position = next_output_position;
            if transaction.block_height != block.height
                || decode_hash32(&transaction.block_hash, "TX_BLOCK_HASH_HEX")? != block_hash
                || transaction.transaction_index != transaction_index as u32
            {
                return Err(schema_violation("TRANSACTION_LOCATION"));
            }
            let canonical_bytes =
                decode_hex_blob(&transaction.canonical_bytes, "TX_CANONICAL_BYTES_HEX")?;
            if canonical_bytes.is_empty() {
                return Err(schema_violation("TX_CANONICAL_BYTES"));
            }
            let tx_hash = decode_hash32(&transaction.tx_hash, "TX_HASH_HEX")?;
            let parsed_tx = Transaction::from_bytes(&canonical_bytes)
                .map_err(|_| schema_violation("TX_CANONICAL_DECODE"))?;
            if parsed_tx
                .to_bytes()
                .map_err(|_| schema_violation("TX_CANONICAL_REENCODE"))?
                != canonical_bytes
                || *dom_crypto::blake2b_256(&canonical_bytes).as_bytes() != tx_hash
            {
                return Err(schema_violation("TX_HASH_BINDING"));
            }
            let tx_inputs = transaction
                .inputs
                .into_iter()
                .map(|input| {
                    Ok(ScanInput {
                        spent_commitment: decode_commitment33(
                            &input.spent_commitment,
                            "INPUT_COMMITMENT_HEX",
                        )?,
                    })
                })
                .collect::<Result<Vec<_>, WalletCoreError>>()?;
            let mut tx_outputs = Vec::with_capacity(transaction.outputs.len());
            for output in transaction.outputs {
                if output.block_height != block.height
                    || decode_hash32(&output.block_hash, "OUTPUT_BLOCK_HASH_HEX")? != block_hash
                    || output.output_position != next_output_position
                    || output.is_coinbase
                {
                    return Err(schema_violation("OUTPUT_LOCATION"));
                }
                let parsed = parse_output(output)?;
                outputs.push(parsed.clone());
                tx_outputs.push(parsed);
                next_output_position = next_output_position
                    .checked_add(1)
                    .ok_or_else(|| schema_violation("OUTPUT_POSITION_OVERFLOW"))?;
            }
            let tx_kernels = transaction
                .kernels
                .into_iter()
                .map(parse_kernel)
                .collect::<Result<Vec<_>, WalletCoreError>>()?;
            let canonical_inputs = parsed_tx
                .inputs
                .iter()
                .map(|input| ScanInput {
                    spent_commitment: *input.commitment.as_bytes(),
                })
                .collect::<Vec<_>>();
            let canonical_outputs = parsed_tx
                .outputs
                .iter()
                .enumerate()
                .map(|(position, output)| {
                    let capsule = output
                        .recovery_capsule()
                        .map_err(|_| schema_violation("TX_OUTPUT_ENVELOPE"))?;
                    let position = u32::try_from(position)
                        .map_err(|_| schema_violation("TX_OUTPUT_POSITION"))?;
                    Ok(ScanOutput {
                        commitment: *output.commitment.as_bytes(),
                        range_proof: output
                            .range_proof_bytes()
                            .map_err(|_| schema_violation("TX_RANGE_PROOF"))?
                            .to_vec(),
                        recovery_capsule: capsule
                            .as_ref()
                            .map(|value| value.as_bytes().to_vec())
                            .unwrap_or_default(),
                        recovery_version: capsule.as_ref().map_or(0, |value| value.version()),
                        is_coinbase: false,
                        block_height: block.height,
                        block_hash,
                        output_position: transaction_first_output_position
                            .checked_add(position)
                            .ok_or_else(|| schema_violation("TX_OUTPUT_POSITION"))?,
                    })
                })
                .collect::<Result<Vec<_>, WalletCoreError>>()?;
            let canonical_kernels = parsed_tx
                .kernels
                .iter()
                .map(|kernel| ScanKernel {
                    excess: *kernel.excess.as_bytes(),
                    features: kernel.features,
                    fee: kernel.fee.noms(),
                    lock_height: kernel.lock_height,
                    excess_signature: kernel.excess_signature,
                })
                .collect::<Vec<_>>();
            if canonical_inputs != tx_inputs
                || canonical_outputs != tx_outputs
                || canonical_kernels != tx_kernels
                || parsed_tx.offset != decode_fixed(&transaction.offset, "TX_OFFSET_HEX")?
            {
                return Err(schema_violation("TX_PROJECTION_MISMATCH"));
            }
            inputs.extend(tx_inputs.iter().copied());
            kernels.extend(tx_kernels.iter().cloned());
            transactions.push(ScanTransaction {
                location: TransactionLocation {
                    block_height: block.height,
                    block_hash,
                    transaction_index: transaction_index as u32,
                },
                tx_hash,
                canonical_bytes,
                inputs: tx_inputs,
                outputs: tx_outputs,
                kernels: tx_kernels,
                offset: parsed_tx.offset,
            });
        }

        blocks.push(ScanBlock {
            height: block.height,
            block_hash,
            previous_block_hash,
            canonical_header_bytes,
            timestamp: block.timestamp,
            canonical_marker,
            outputs,
            inputs,
            kernels,
            transactions,
            coinbase,
            total_fees_noms: block.total_fees_noms,
            protocol_version: block.protocol_version,
            range_proof_serialization_version: block.range_proof_serialization_version,
        });
    }

    validate_continuation(wire.continuation, &identity, blocks.last())?;

    Ok(ParsedFullScan { identity, blocks })
}

fn parse_output(output: WireOutput) -> Result<ScanOutput, WalletCoreError> {
    let range_proof = decode_hex_blob(&output.range_proof, "RANGE_PROOF_HEX")?;
    if range_proof.len() != dom_crypto::RANGE_PROOF_SIZE {
        return Err(schema_violation("RANGE_PROOF_LENGTH"));
    }
    let recovery_capsule = decode_hex_blob(&output.recovery_capsule, "CAPSULE_HEX")?;
    if recovery_capsule.is_empty() != (output.recovery_version == 0) {
        return Err(schema_violation("CAPSULE_VERSION"));
    }
    if !recovery_capsule.is_empty()
        && dom_crypto::recovery::RecoveryCapsule::from_bytes(&recovery_capsule)
            .map_err(|_| schema_violation("CAPSULE_CANONICAL"))?
            .version()
            != output.recovery_version
    {
        return Err(schema_violation("CAPSULE_VERSION"));
    }
    Ok(ScanOutput {
        commitment: decode_commitment33(&output.commitment, "OUTPUT_COMMITMENT_HEX")?,
        range_proof,
        recovery_capsule,
        recovery_version: output.recovery_version,
        is_coinbase: output.is_coinbase,
        block_height: output.block_height,
        block_hash: decode_hash32(&output.block_hash, "OUTPUT_BLOCK_HASH_HEX")?,
        output_position: output.output_position,
    })
}

fn parse_kernel(kernel: WireKernel) -> Result<ScanKernel, WalletCoreError> {
    Ok(ScanKernel {
        excess: decode_commitment33(&kernel.excess, "KERNEL_EXCESS_HEX")?,
        features: kernel.features,
        fee: kernel.fee,
        lock_height: kernel.lock_height,
        excess_signature: decode_fixed(&kernel.excess_signature, "KERNEL_SIGNATURE_HEX")?,
    })
}

fn split_proof_envelope(envelope: &[u8]) -> Result<(Vec<u8>, Vec<u8>, u16), WalletCoreError> {
    let proof_size = dom_crypto::RANGE_PROOF_SIZE;
    match envelope.len() {
        length if length == proof_size => Ok((envelope.to_vec(), Vec::new(), 0)),
        length if length == proof_size + dom_crypto::recovery::RECOVERY_CAPSULE_SIZE => {
            let capsule =
                dom_crypto::recovery::RecoveryCapsule::from_bytes(&envelope[proof_size..])
                    .map_err(|_| schema_violation("COINBASE_CAPSULE_CANONICAL"))?;
            Ok((
                envelope[..proof_size].to_vec(),
                capsule.as_bytes().to_vec(),
                capsule.version(),
            ))
        }
        _ => Err(schema_violation("COINBASE_PROOF_ENVELOPE_LENGTH")),
    }
}

fn validate_continuation(
    continuation: Option<WireContinuation>,
    identity: &ChainIdentity,
    last: Option<&ScanBlock>,
) -> Result<(), WalletCoreError> {
    let Some(continuation) = continuation else {
        return Ok(());
    };
    let last = last.ok_or_else(|| schema_violation("CONTINUATION_WITHOUT_BLOCK"))?;
    if continuation.next_height != last.height.saturating_add(1)
        || continuation.anchor.height != last.height
        || decode_hash32(&continuation.anchor.block_hash, "CONTINUATION_ANCHOR_HASH")?
            != last.block_hash
        || continuation.snapshot_tip_height != identity.current_tip.height
        || decode_hash32(&continuation.snapshot_tip_hash, "CONTINUATION_TIP_HASH")?
            != identity.current_tip.hash
    {
        return Err(schema_violation("CONTINUATION"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, Value};
    use std::io::{Read, Write};
    use std::net::{SocketAddr, TcpListener, TcpStream};
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::thread::JoinHandle;

    const TOKEN: &str = "test-token";

    // ── Minimal local HTTP mock (std-only, same raw-socket spirit as the
    //    dom-wallet-updater test servers) ─────────────────────────────────

    struct ReceivedRequest {
        path: String,
        query: String,
        authorization: Option<String>,
    }

    #[derive(Clone)]
    struct CannedResponse {
        status: u16,
        content_type: &'static str,
        body: String,
    }

    impl CannedResponse {
        fn json(status: u16, body: Value) -> Self {
            Self {
                status,
                content_type: "application/json",
                body: body.to_string(),
            }
        }

        fn raw_json(status: u16, body: String) -> Self {
            Self {
                status,
                content_type: "application/json",
                body,
            }
        }

        fn text(status: u16, body: &str) -> Self {
            Self {
                status,
                content_type: "text/plain",
                body: body.to_string(),
            }
        }
    }

    struct MockServer {
        address: SocketAddr,
        hits: Arc<AtomicUsize>,
        shutdown: Arc<AtomicBool>,
        worker: Option<JoinHandle<()>>,
    }

    impl MockServer {
        fn start<F>(handler: F) -> Self
        where
            F: Fn(&ReceivedRequest) -> CannedResponse + Send + Sync + 'static,
        {
            let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock server");
            let address = listener.local_addr().expect("mock server address");
            let hits = Arc::new(AtomicUsize::new(0));
            let shutdown = Arc::new(AtomicBool::new(false));
            let worker_hits = Arc::clone(&hits);
            let worker_shutdown = Arc::clone(&shutdown);
            let worker = std::thread::spawn(move || {
                for stream in listener.incoming() {
                    if worker_shutdown.load(Ordering::SeqCst) {
                        break;
                    }
                    let Ok(mut stream) = stream else { continue };
                    let Some(request) = read_request(&mut stream) else {
                        continue;
                    };
                    worker_hits.fetch_add(1, Ordering::SeqCst);
                    write_response(&mut stream, &handler(&request));
                }
            });
            Self {
                address,
                hits,
                shutdown,
                worker: Some(worker),
            }
        }

        fn base_url(&self) -> String {
            format!("http://{}", self.address)
        }

        fn hits(&self) -> usize {
            self.hits.load(Ordering::SeqCst)
        }
    }

    impl Drop for MockServer {
        fn drop(&mut self) {
            self.shutdown.store(true, Ordering::SeqCst);
            let _ = TcpStream::connect(self.address);
            if let Some(worker) = self.worker.take() {
                let _ = worker.join();
            }
        }
    }

    fn read_request(stream: &mut TcpStream) -> Option<ReceivedRequest> {
        let mut buffer = Vec::new();
        let mut chunk = [0u8; 1024];
        while !buffer.windows(4).any(|window| window == b"\r\n\r\n") {
            let read = stream.read(&mut chunk).ok()?;
            if read == 0 {
                break;
            }
            buffer.extend_from_slice(&chunk[..read]);
            if buffer.len() > 64 * 1024 {
                break;
            }
        }
        let text = String::from_utf8_lossy(&buffer).into_owned();
        let mut lines = text.lines();
        let request_line = lines.next()?;
        let target = request_line.split_whitespace().nth(1)?;
        let (path, query) = match target.split_once('?') {
            Some((path, query)) => (path.to_string(), query.to_string()),
            None => (target.to_string(), String::new()),
        };
        let mut authorization = None;
        for line in lines {
            if line.is_empty() {
                break;
            }
            if let Some((name, value)) = line.split_once(':') {
                if name.eq_ignore_ascii_case("authorization") {
                    authorization = Some(value.trim().to_string());
                }
            }
        }
        Some(ReceivedRequest {
            path,
            query,
            authorization,
        })
    }

    fn write_response(stream: &mut TcpStream, response: &CannedResponse) {
        let payload = format!(
            "HTTP/1.1 {} MOCK\r\ncontent-type: {}\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
            response.status,
            response.content_type,
            response.body.len(),
            response.body
        );
        let _ = stream.write_all(payload.as_bytes());
        let _ = stream.flush();
    }

    // ── Wire fixtures ───────────────────────────────────────────────────

    mod scriptless_wire_tests {
        use super::*;
        use dom_consensus::{Block, TransactionInput, TransactionKernel, TransactionOutput};
        use std::sync::OnceLock;

        fn source_for(server: &MockServer) -> RemoteNodeSource {
            RemoteNodeSource::new(&server.base_url(), Some(TOKEN)).expect("remote source")
        }

        fn genesis() -> &'static Block {
            static GENESIS: OnceLock<Block> = OnceLock::new();
            GENESIS.get_or_init(|| {
                dom_chain::build_canonical_genesis(CoreNetwork::Regtest.magic(), &[8; 32])
                    .expect("regtest genesis")
                    .block
                    .expect("regtest canonical block")
            })
        }

        fn chain_identity(tip: BlockRef) -> ChainIdentity {
            let genesis_hash = dom_chain::canonical_header_identifier(
                CoreNetwork::Regtest.magic(),
                &genesis().header.to_bytes().expect("genesis header"),
            )
            .expect("genesis id");
            ChainIdentity {
                network: CoreNetwork::Regtest,
                network_magic: CoreNetwork::Regtest.magic(),
                chain_id: *dom_consensus::derive_chain_id(
                    CoreNetwork::Regtest.magic(),
                    &genesis_hash,
                )
                .as_bytes(),
                genesis_hash: *genesis_hash.as_bytes(),
                protocol_version: 1,
                range_proof_serialization_version: dom_crypto::RANGE_PROOF_SERIALIZATION_VERSION,
                coinbase_maturity: 1440,
                current_tip: tip,
            }
        }

        fn next_block(previous: &ScanBlock, marker: u8) -> Block {
            let mut block = genesis().clone();
            let height = previous.height + 1;
            let mut offset = [0u8; 32];
            offset[31] = marker.max(1);
            let transaction = Transaction {
                inputs: vec![TransactionInput {
                    commitment: block.coinbase.output.commitment.clone(),
                }],
                outputs: vec![TransactionOutput {
                    commitment: block.coinbase.output.commitment.clone(),
                    proof: block.coinbase.output.proof.clone(),
                }],
                kernels: vec![TransactionKernel {
                    features: dom_core::KERNEL_FEAT_PLAIN,
                    fee: dom_core::Amount::from_noms(height).expect("fee"),
                    lock_height: 0,
                    excess: block.coinbase.kernel.excess.clone(),
                    excess_signature: [marker; 65],
                }],
                offset,
            };
            block.header.version =
                dom_core::required_block_version_for_network(CoreNetwork::Regtest.magic(), height);
            block.header.height = dom_core::BlockHeight(height);
            block.header.prev_hash = dom_core::Hash256::from_bytes(previous.block_hash);
            block.header.timestamp = dom_core::Timestamp(previous.timestamp + 60);
            block.header.total_kernel_offset = offset;
            block.header.pow.nonce = u64::from(marker);
            block.transactions = vec![transaction];
            let (output_root, kernel_root, rangeproof_root) =
                dom_consensus::compute_block_pmmr_roots(
                    dom_core::BlockHeight(height),
                    &block.coinbase,
                    &block.transactions,
                )
                .expect("body roots");
            block.header.output_root = output_root;
            block.header.kernel_root = kernel_root;
            block.header.rangeproof_root = rangeproof_root;
            block
        }

        fn project_output(
            output: &TransactionOutput,
            is_coinbase: bool,
            block_height: u64,
            block_hash: [u8; 32],
            output_position: u32,
        ) -> ScanOutput {
            let capsule = output.recovery_capsule().expect("output envelope");
            ScanOutput {
                commitment: *output.commitment.as_bytes(),
                range_proof: output.range_proof_bytes().expect("range proof").to_vec(),
                recovery_capsule: capsule
                    .as_ref()
                    .map(|value| value.as_bytes().to_vec())
                    .unwrap_or_default(),
                recovery_version: capsule.as_ref().map_or(0, |value| value.version()),
                is_coinbase,
                block_height,
                block_hash,
                output_position,
            }
        }

        fn project_block(block: &Block) -> ScanBlock {
            let canonical_header_bytes = block.header.to_bytes().expect("header bytes");
            let block_hash = *dom_chain::canonical_header_identifier(
                CoreNetwork::Regtest.magic(),
                &canonical_header_bytes,
            )
            .expect("header id")
            .as_bytes();
            let coinbase_output = project_output(
                &block.coinbase.output,
                true,
                block.header.height.0,
                block_hash,
                0,
            );
            let coinbase_kernel = ScanKernel {
                excess: *block.coinbase.kernel.excess.as_bytes(),
                features: block.coinbase.kernel.features,
                fee: 0,
                lock_height: 0,
                excess_signature: block.coinbase.kernel.excess_signature,
            };
            let mut outputs = vec![coinbase_output];
            let mut inputs = Vec::new();
            let mut kernels = vec![coinbase_kernel];
            let mut transactions = Vec::new();
            let mut output_position = 1_u32;
            for (transaction_index, transaction) in block.transactions.iter().enumerate() {
                let tx_inputs = transaction
                    .inputs
                    .iter()
                    .map(|input| ScanInput {
                        spent_commitment: *input.commitment.as_bytes(),
                    })
                    .collect::<Vec<_>>();
                let tx_outputs = transaction
                    .outputs
                    .iter()
                    .map(|output| {
                        let projected = project_output(
                            output,
                            false,
                            block.header.height.0,
                            block_hash,
                            output_position,
                        );
                        output_position += 1;
                        projected
                    })
                    .collect::<Vec<_>>();
                let tx_kernels = transaction
                    .kernels
                    .iter()
                    .map(|kernel| ScanKernel {
                        excess: *kernel.excess.as_bytes(),
                        features: kernel.features,
                        fee: kernel.fee.noms(),
                        lock_height: kernel.lock_height,
                        excess_signature: kernel.excess_signature,
                    })
                    .collect::<Vec<_>>();
                let canonical_bytes = transaction.to_bytes().expect("transaction bytes");
                inputs.extend(tx_inputs.iter().copied());
                outputs.extend(tx_outputs.iter().cloned());
                kernels.extend(tx_kernels.iter().cloned());
                transactions.push(ScanTransaction {
                    location: TransactionLocation {
                        block_height: block.header.height.0,
                        block_hash,
                        transaction_index: transaction_index as u32,
                    },
                    tx_hash: *dom_crypto::blake2b_256(&canonical_bytes).as_bytes(),
                    canonical_bytes,
                    inputs: tx_inputs,
                    outputs: tx_outputs,
                    kernels: tx_kernels,
                    offset: transaction.offset,
                });
            }
            ScanBlock {
                height: block.header.height.0,
                block_hash,
                previous_block_hash: *block.header.prev_hash.as_bytes(),
                canonical_header_bytes,
                timestamp: block.header.timestamp.0,
                canonical_marker: block_hash,
                outputs,
                inputs,
                kernels,
                transactions,
                coinbase: CoinbaseScanMetadata {
                    output_commitment: *block.coinbase.output.commitment.as_bytes(),
                    explicit_value: block.coinbase.kernel.explicit_value,
                    kernel_excess: *block.coinbase.kernel.excess.as_bytes(),
                    kernel_features: block.coinbase.kernel.features,
                    kernel_excess_signature: block.coinbase.kernel.excess_signature,
                    offset: block.coinbase.offset,
                    output_proof_envelope: block.coinbase.output.proof.clone(),
                },
                total_fees_noms: block.total_fees().expect("fees"),
                protocol_version: block.header.version,
                range_proof_serialization_version: dom_crypto::RANGE_PROOF_SERIALIZATION_VERSION,
            }
        }

        fn output_json(output: &ScanOutput) -> Value {
            json!({
                "commitment": hex::encode(output.commitment),
                "range_proof": hex::encode(&output.range_proof),
                "recovery_capsule": hex::encode(&output.recovery_capsule),
                "recovery_version": output.recovery_version,
                "is_coinbase": output.is_coinbase,
                "block_height": output.block_height,
                "block_hash": hex::encode(output.block_hash),
                "output_position": output.output_position,
            })
        }

        fn kernel_json(kernel: &ScanKernel) -> Value {
            json!({
                "excess": hex::encode(kernel.excess),
                "features": kernel.features,
                "fee": kernel.fee,
                "lock_height": kernel.lock_height,
                "excess_signature": hex::encode(kernel.excess_signature),
            })
        }

        fn block_json(block: &ScanBlock) -> Value {
            json!({
                "height": block.height,
                "block_hash": hex::encode(block.block_hash),
                "previous_block_hash": hex::encode(block.previous_block_hash),
                "canonical_header_bytes": hex::encode(&block.canonical_header_bytes),
                "timestamp": block.timestamp,
                "canonical_marker": hex::encode(block.canonical_marker),
                "transactions": block.transactions.iter().map(|transaction| json!({
                    "block_height": transaction.location.block_height,
                    "block_hash": hex::encode(transaction.location.block_hash),
                    "transaction_index": transaction.location.transaction_index,
                    "tx_hash": hex::encode(transaction.tx_hash),
                    "canonical_bytes": hex::encode(&transaction.canonical_bytes),
                    "inputs": transaction.inputs.iter().map(|input| json!({
                        "spent_commitment": hex::encode(input.spent_commitment),
                    })).collect::<Vec<_>>(),
                    "outputs": transaction.outputs.iter().map(output_json).collect::<Vec<_>>(),
                    "kernels": transaction.kernels.iter().map(kernel_json).collect::<Vec<_>>(),
                    "offset": hex::encode(transaction.offset),
                })).collect::<Vec<_>>(),
                "coinbase": {
                    "output_commitment": hex::encode(block.coinbase.output_commitment),
                    "explicit_value": block.coinbase.explicit_value,
                    "kernel_excess": hex::encode(block.coinbase.kernel_excess),
                    "kernel_features": block.coinbase.kernel_features,
                    "kernel_excess_signature": hex::encode(block.coinbase.kernel_excess_signature),
                    "offset": hex::encode(block.coinbase.offset),
                    "output_proof_envelope": hex::encode(&block.coinbase.output_proof_envelope),
                },
                "total_fees_noms": block.total_fees_noms,
                "protocol_version": block.protocol_version,
                "range_proof_serialization_version": block.range_proof_serialization_version,
            })
        }

        fn response_json(
            requested_from: u64,
            requested_to: u64,
            blocks: &[ScanBlock],
            identity: &ChainIdentity,
            request_anchor: Option<BlockRef>,
        ) -> Value {
            let served_to = blocks.last().map(|block| block.height);
            let continuation = blocks.last().and_then(|last| {
                (last.height < identity.current_tip.height).then(|| {
                    json!({
                        "next_height": last.height + 1,
                        "anchor": {
                            "height": last.height,
                            "block_hash": hex::encode(last.block_hash),
                        },
                        "snapshot_tip_height": identity.current_tip.height,
                        "snapshot_tip_hash": hex::encode(identity.current_tip.hash),
                    })
                })
            });
            json!({
                "schema_version": 1,
                "status": "ok",
                "canonical": true,
                "identity": {
                    "network": "regtest",
                    "network_magic": identity.network_magic,
                    "chain_id": hex::encode(identity.chain_id),
                    "genesis_hash": hex::encode(identity.genesis_hash),
                    "protocol_version": identity.protocol_version,
                    "range_proof_serialization_version": identity.range_proof_serialization_version,
                    "coinbase_maturity": identity.coinbase_maturity,
                    "tip_height": identity.current_tip.height,
                    "tip_hash": hex::encode(identity.current_tip.hash),
                },
                "requested_from": requested_from,
                "requested_to": requested_to,
                "served_from": requested_from,
                "served_to": served_to,
                "request_anchor": request_anchor.map(|anchor| json!({
                    "height": anchor.height,
                    "block_hash": hex::encode(anchor.hash),
                })),
                "blocks": blocks.iter().map(block_json).collect::<Vec<_>>(),
                "continuation": continuation,
            })
        }

        fn request(start: ScanStart, max_blocks: u64, identity: &ChainIdentity) -> ScanRequest {
            ScanRequest {
                network: identity.network,
                chain_id: identity.chain_id,
                start,
                max_blocks,
                stop_height: None,
                commitment_filters: Vec::new(),
            }
        }

        #[test]
        fn real_scriptless_schema_roundtrips_full_canonical_projection() {
            let first = project_block(genesis());
            let second = project_block(&next_block(&first, 7));
            let blocks = vec![first.clone(), second.clone()];
            let identity = chain_identity(BlockRef {
                height: second.height,
                hash: second.block_hash,
            });
            let body = response_json(0, 1, &blocks, &identity, None);
            let expected_chain_id = identity.chain_id;
            let server = MockServer::start(move |request| {
                assert_eq!(request.path, "/chain/scan/scriptless/v1");
                assert!(request.query.contains("from=0&to=1"));
                assert!(request.query.contains(&format!(
                    "expected_chain_id={}",
                    hex::encode(expected_chain_id)
                )));
                assert_eq!(request.authorization.as_deref(), Some("Bearer test-token"));
                CannedResponse::json(200, body.clone())
            });
            let result = source_for(&server)
                .scan_range(request(ScanStart::Height(0), 2, &identity))
                .expect("scriptless scan");
            assert_eq!(result.blocks, blocks);
            assert_eq!(result.tip, identity.current_tip);
            assert!(result.continuation.is_none());
        }

        #[test]
        fn canonical_bytes_hash_and_projection_tampering_fail_closed() {
            let first = project_block(genesis());
            let second = project_block(&next_block(&first, 9));
            let identity = chain_identity(BlockRef {
                height: second.height,
                hash: second.block_hash,
            });
            let valid = response_json(0, 1, &[first, second], &identity, None);
            let mut cases = Vec::new();
            let mut header = valid.clone();
            header["blocks"][1]["canonical_header_bytes"] = json!("00");
            cases.push(header);
            let mut tx_hash = valid.clone();
            tx_hash["blocks"][1]["transactions"][0]["tx_hash"] = json!(hex::encode([1; 32]));
            cases.push(tx_hash);
            let mut signature = valid.clone();
            signature["blocks"][1]["transactions"][0]["kernels"][0]["excess_signature"] =
                json!(hex::encode([2; 65]));
            cases.push(signature);
            let mut location = valid;
            location["blocks"][1]["transactions"][0]["block_height"] = json!(99);
            cases.push(location);
            for body in cases {
                let result = parse_full_scan(0, 1, None, &body.to_string());
                assert!(
                    matches!(result, Err(WalletCoreError::InternalFailure(_))),
                    "tampered evidence must fail closed"
                );
            }
        }

        #[test]
        fn large_requests_page_at_the_authoritative_rpc_limit() {
            let first = project_block(genesis());
            let second = project_block(&next_block(&first, 12));
            let blocks = vec![first.clone(), second.clone()];
            let identity = chain_identity(BlockRef {
                height: second.height,
                hash: second.block_hash,
            });
            let body = response_json(0, 63, &blocks, &identity, None);
            let server = MockServer::start(move |request| {
                assert!(request.query.contains("from=0&to=63"));
                CannedResponse::json(200, body.clone())
            });

            let result = source_for(&server)
                .scan_range(request(ScanStart::Height(0), 1_000, &identity))
                .expect("large request is paged");
            assert_eq!(result.blocks, blocks);
            assert!(result.continuation.is_none());
        }

        #[test]
        fn stop_before_start_returns_empty_after_identity_validation() {
            let first = project_block(genesis());
            let identity = chain_identity(BlockRef {
                height: first.height,
                hash: first.block_hash,
            });
            let body = response_json(0, 0, std::slice::from_ref(&first), &identity, None);
            let server = MockServer::start(move |request| {
                assert!(request.query.contains("from=0&to=0"));
                CannedResponse::json(200, body.clone())
            });
            let mut scan = request(ScanStart::Height(2), 64, &identity);
            scan.stop_height = Some(1);

            let result = source_for(&server).scan_range(scan).expect("empty range");
            assert!(result.blocks.is_empty());
            assert!(result.continuation.is_none());
            assert_eq!(result.tip, identity.current_tip);
            assert_eq!(server.hits(), 1);
        }

        #[test]
        fn cursor_anchor_is_sent_and_reorg_conflict_is_typed() {
            let first = project_block(genesis());
            let identity = chain_identity(BlockRef {
                height: first.height,
                hash: first.block_hash,
            });
            let cursor = WalletScanCursor::new(
                identity.network,
                identity.chain_id,
                1,
                BlockRef {
                    height: 0,
                    hash: first.block_hash,
                },
            );
            let block_hash = first.block_hash;
            let identity_body = response_json(0, 0, &[first], &identity, None);
            let server = MockServer::start(move |request| match request.path.as_str() {
                "/chain/scan/scriptless/v1" if request.query.contains("from=0&to=0") => {
                    CannedResponse::json(200, identity_body.clone())
                }
                "/block/0" => {
                    CannedResponse::json(200, json!({"height": 0, "hash": hex::encode(block_hash)}))
                }
                "/chain/scan/scriptless/v1" => {
                    assert!(request
                        .query
                        .contains(&format!("anchor_hash={}", hex::encode(block_hash))));
                    CannedResponse::json(409, json!({"error": "anchor changed"}))
                }
                path => panic!("unexpected path {path}"),
            });
            let error = source_for(&server)
                .scan_range(request(ScanStart::Cursor(cursor), 1, &identity))
                .expect_err("reorg conflict");
            assert!(matches!(error, WalletCoreError::CursorReorg(_)));
        }

        #[test]
        fn remote_failures_and_privacy_boundary_remain_fail_closed() {
            assert!(matches!(
                map_full_scan_status(503, "busy"),
                WalletCoreError::NodeNotReady(_)
            ));
            assert!(matches!(
                map_full_scan_status(409, "reorg"),
                WalletCoreError::CursorReorg(_)
            ));
            assert!(matches!(
                map_full_scan_status(401, "unauthorized"),
                WalletCoreError::InternalFailure(_)
            ));
            let server = MockServer::start(|_| CannedResponse::text(500, "must not be called"));
            let source = source_for(&server);
            let identity = chain_identity(BlockRef {
                height: 0,
                hash: [0; 32],
            });
            let mut filtered = request(ScanStart::Height(0), 1, &identity);
            filtered.commitment_filters.push([3; 33]);
            assert!(matches!(
                source.scan_range(filtered),
                Err(WalletCoreError::InvalidScanRequest(_))
            ));
            assert_eq!(server.hits(), 0);
        }
    }

    mod scriptless_wire_contract_regressions {
        use super::*;
        use std::sync::OnceLock;

        fn h32(byte: u8) -> String {
            hex::encode([byte; 32])
        }

        fn canonical_chain_identity() -> ChainIdentity {
            let genesis =
                dom_chain::build_canonical_genesis(CoreNetwork::Regtest.magic(), &[8; 32])
                    .expect("regtest genesis");
            ChainIdentity {
                network: CoreNetwork::Regtest,
                network_magic: CoreNetwork::Regtest.magic(),
                chain_id: *dom_consensus::derive_chain_id(
                    CoreNetwork::Regtest.magic(),
                    &genesis.hash,
                )
                .as_bytes(),
                genesis_hash: *genesis.hash.as_bytes(),
                protocol_version: 1,
                range_proof_serialization_version: dom_crypto::RANGE_PROOF_SERIALIZATION_VERSION,
                coinbase_maturity: 1440,
                current_tip: BlockRef {
                    height: 0,
                    hash: [0; 32],
                },
            }
        }

        fn identity_json(tip_height: u64, tip_hash: [u8; 32]) -> Value {
            let identity = canonical_chain_identity();
            json!({
                "network": "regtest",
                "network_magic": identity.network_magic,
                "chain_id": hex::encode(identity.chain_id),
                "genesis_hash": hex::encode(identity.genesis_hash),
                "protocol_version": identity.protocol_version,
                "range_proof_serialization_version": identity.range_proof_serialization_version,
                "coinbase_maturity": identity.coinbase_maturity,
                "tip_height": tip_height,
                "tip_hash": hex::encode(tip_hash),
            })
        }

        fn canonical_block(height: u64, previous_hash: [u8; 32], marker: u8) -> ScanBlock {
            let mut canonical = canonical_genesis_template().clone();
            let mut offset = [0u8; 32];
            offset[31] = marker.max(1);
            let transaction = Transaction {
                inputs: vec![dom_consensus::TransactionInput {
                    commitment: canonical.coinbase.output.commitment.clone(),
                }],
                outputs: vec![canonical.coinbase.output.clone()],
                kernels: vec![dom_consensus::TransactionKernel {
                    features: dom_core::KERNEL_FEAT_PLAIN,
                    fee: dom_core::Amount::from_noms(height).expect("fee"),
                    lock_height: 0,
                    excess: canonical.coinbase.kernel.excess.clone(),
                    excess_signature: [marker.wrapping_add(60); 65],
                }],
                offset,
            };
            canonical.header.version =
                dom_core::required_block_version_for_network(CoreNetwork::Regtest.magic(), height);
            canonical.header.height = dom_core::BlockHeight(height);
            canonical.header.prev_hash = dom_core::Hash256::from_bytes(previous_hash);
            canonical.header.timestamp =
                dom_core::Timestamp(1_700_000_000 + height + u64::from(marker));
            canonical.header.total_kernel_offset = offset;
            canonical.header.pow.nonce = u64::from(marker);
            canonical.transactions = vec![transaction.clone()];
            let (output_root, kernel_root, rangeproof_root) =
                dom_consensus::compute_block_pmmr_roots(
                    dom_core::BlockHeight(height),
                    &canonical.coinbase,
                    &canonical.transactions,
                )
                .expect("roots");
            canonical.header.output_root = output_root;
            canonical.header.kernel_root = kernel_root;
            canonical.header.rangeproof_root = rangeproof_root;
            let canonical_header_bytes = canonical.header.to_bytes().expect("header");
            let hash = *dom_chain::canonical_header_identifier(
                CoreNetwork::Regtest.magic(),
                &canonical_header_bytes,
            )
            .expect("header id")
            .as_bytes();
            let coinbase_capsule = canonical
                .coinbase
                .output
                .recovery_capsule()
                .expect("coinbase envelope");
            let transaction_output_capsule = transaction.outputs[0]
                .recovery_capsule()
                .expect("transaction envelope");
            let coinbase_output = ScanOutput {
                commitment: *canonical.coinbase.output.commitment.as_bytes(),
                range_proof: canonical
                    .coinbase
                    .output
                    .range_proof_bytes()
                    .expect("proof")
                    .to_vec(),
                recovery_capsule: coinbase_capsule
                    .as_ref()
                    .map(|capsule| capsule.as_bytes().to_vec())
                    .unwrap_or_default(),
                recovery_version: coinbase_capsule
                    .as_ref()
                    .map_or(0, |capsule| capsule.version()),
                is_coinbase: true,
                block_height: height,
                block_hash: hash,
                output_position: 0,
            };
            let transaction_output = ScanOutput {
                commitment: *transaction.outputs[0].commitment.as_bytes(),
                range_proof: transaction.outputs[0]
                    .range_proof_bytes()
                    .expect("proof")
                    .to_vec(),
                recovery_capsule: transaction_output_capsule
                    .as_ref()
                    .map(|capsule| capsule.as_bytes().to_vec())
                    .unwrap_or_default(),
                recovery_version: transaction_output_capsule
                    .as_ref()
                    .map_or(0, |capsule| capsule.version()),
                is_coinbase: false,
                block_height: height,
                block_hash: hash,
                output_position: 1,
            };
            let coinbase_kernel = ScanKernel {
                excess: *canonical.coinbase.kernel.excess.as_bytes(),
                features: canonical.coinbase.kernel.features,
                fee: 0,
                lock_height: 0,
                excess_signature: canonical.coinbase.kernel.excess_signature,
            };
            let transaction_kernel = ScanKernel {
                excess: *transaction.kernels[0].excess.as_bytes(),
                features: transaction.kernels[0].features,
                fee: transaction.kernels[0].fee.noms(),
                lock_height: transaction.kernels[0].lock_height,
                excess_signature: transaction.kernels[0].excess_signature,
            };
            let transaction_bytes = transaction.to_bytes().expect("transaction");
            ScanBlock {
                height,
                block_hash: hash,
                previous_block_hash: previous_hash,
                canonical_header_bytes,
                timestamp: canonical.header.timestamp.0,
                canonical_marker: hash,
                outputs: vec![coinbase_output, transaction_output.clone()],
                inputs: vec![ScanInput {
                    spent_commitment: *transaction.inputs[0].commitment.as_bytes(),
                }],
                kernels: vec![coinbase_kernel, transaction_kernel.clone()],
                transactions: vec![ScanTransaction {
                    location: TransactionLocation {
                        block_height: height,
                        block_hash: hash,
                        transaction_index: 0,
                    },
                    tx_hash: *dom_crypto::blake2b_256(&transaction_bytes).as_bytes(),
                    canonical_bytes: transaction_bytes,
                    inputs: vec![ScanInput {
                        spent_commitment: *transaction.inputs[0].commitment.as_bytes(),
                    }],
                    outputs: vec![transaction_output],
                    kernels: vec![transaction_kernel],
                    offset,
                }],
                coinbase: CoinbaseScanMetadata {
                    output_commitment: *canonical.coinbase.output.commitment.as_bytes(),
                    explicit_value: canonical.coinbase.kernel.explicit_value,
                    kernel_excess: *canonical.coinbase.kernel.excess.as_bytes(),
                    kernel_features: canonical.coinbase.kernel.features,
                    kernel_excess_signature: canonical.coinbase.kernel.excess_signature,
                    offset: canonical.coinbase.offset,
                    output_proof_envelope: canonical.coinbase.output.proof.clone(),
                },
                total_fees_noms: canonical.total_fees().expect("fees"),
                protocol_version: canonical.header.version,
                range_proof_serialization_version: dom_crypto::RANGE_PROOF_SERIALIZATION_VERSION,
            }
        }

        fn canonical_genesis_template() -> &'static dom_consensus::Block {
            static GENESIS: OnceLock<dom_consensus::Block> = OnceLock::new();
            GENESIS.get_or_init(|| {
                dom_chain::build_canonical_genesis(CoreNetwork::Regtest.magic(), &[8; 32])
                    .expect("regtest genesis")
                    .block
                    .expect("regtest block")
            })
        }

        fn scan_output_json(output: &ScanOutput) -> Value {
            json!({
                "commitment": hex::encode(output.commitment),
                "range_proof": hex::encode(&output.range_proof),
                "recovery_capsule": hex::encode(&output.recovery_capsule),
                "recovery_version": output.recovery_version,
                "is_coinbase": output.is_coinbase,
                "block_height": output.block_height,
                "block_hash": hex::encode(output.block_hash),
                "output_position": output.output_position,
            })
        }

        fn scan_kernel_json(kernel: &ScanKernel) -> Value {
            json!({
                "excess": hex::encode(kernel.excess),
                "features": kernel.features,
                "fee": kernel.fee,
                "lock_height": kernel.lock_height,
                "excess_signature": hex::encode(kernel.excess_signature),
            })
        }

        fn block_projection_json(block: &ScanBlock) -> Value {
            json!({
                "height": block.height,
                "block_hash": hex::encode(block.block_hash),
                "previous_block_hash": hex::encode(block.previous_block_hash),
                "canonical_header_bytes": hex::encode(&block.canonical_header_bytes),
                "timestamp": block.timestamp,
                "canonical_marker": hex::encode(block.canonical_marker),
                "transactions": block.transactions.iter().map(|transaction| json!({
                    "block_height": transaction.location.block_height,
                    "block_hash": hex::encode(transaction.location.block_hash),
                    "transaction_index": transaction.location.transaction_index,
                    "tx_hash": hex::encode(transaction.tx_hash),
                    "canonical_bytes": hex::encode(&transaction.canonical_bytes),
                    "inputs": transaction.inputs.iter().map(|input| json!({
                        "spent_commitment": hex::encode(input.spent_commitment),
                    })).collect::<Vec<_>>(),
                    "outputs": transaction.outputs.iter().map(scan_output_json).collect::<Vec<_>>(),
                    "kernels": transaction.kernels.iter().map(scan_kernel_json).collect::<Vec<_>>(),
                    "offset": hex::encode(transaction.offset),
                })).collect::<Vec<_>>(),
                "coinbase": {
                    "output_commitment": hex::encode(block.coinbase.output_commitment),
                    "explicit_value": block.coinbase.explicit_value,
                    "kernel_excess": hex::encode(block.coinbase.kernel_excess),
                    "kernel_features": block.coinbase.kernel_features,
                    "kernel_excess_signature": hex::encode(block.coinbase.kernel_excess_signature),
                    "offset": hex::encode(block.coinbase.offset),
                    "output_proof_envelope": hex::encode(&block.coinbase.output_proof_envelope),
                },
                "total_fees_noms": block.total_fees_noms,
                "protocol_version": block.protocol_version,
                "range_proof_serialization_version": block.range_proof_serialization_version,
            })
        }

        fn block_json(height: u64, marker: u8, previous_hash: &str) -> ScanBlock {
            canonical_block(
                height,
                decode_hash32(previous_hash, "TEST_PREVIOUS_HASH").expect("previous hash"),
                marker,
            )
        }

        fn canonical_blocks(
            start_height: u64,
            count: u64,
            mut previous_hash: [u8; 32],
            first_marker: u8,
        ) -> Vec<ScanBlock> {
            let mut blocks = Vec::with_capacity(count as usize);
            for offset in 0..count {
                let block = canonical_block(
                    start_height + offset,
                    previous_hash,
                    first_marker.wrapping_add(offset as u8),
                );
                previous_hash = block.block_hash;
                blocks.push(block);
            }
            blocks
        }

        fn full_scan_json(
            from: u64,
            to: u64,
            tip_height: u64,
            tip_marker: u8,
            blocks: impl AsRef<[ScanBlock]>,
        ) -> Value {
            let blocks = blocks.as_ref();
            let tip_hash = blocks
                .last()
                .filter(|block| block.height == tip_height)
                .map_or([tip_marker; 32], |block| block.block_hash);
            let request_anchor = (from > 0).then(|| BlockRef {
                height: from - 1,
                hash: blocks
                    .first()
                    .map_or([from.saturating_sub(1) as u8; 32], |block| {
                        block.previous_block_hash
                    }),
            });
            let served_to = blocks.last().map(|block| block.height);
            let continuation = blocks.last().and_then(|last| {
                (last.height < tip_height).then(|| json!({
                "next_height": last.height + 1,
                "anchor": { "height": last.height, "block_hash": hex::encode(last.block_hash) },
                "snapshot_tip_height": tip_height,
                "snapshot_tip_hash": hex::encode(tip_hash),
            }))
            });
            json!({
                "schema_version": 1,
                "status": "ok",
                "canonical": true,
                "identity": identity_json(tip_height, tip_hash),
                "requested_from": from,
                "requested_to": to,
                "served_from": from,
                "served_to": served_to,
                "request_anchor": request_anchor.map(|anchor| json!({
                    "height": anchor.height,
                    "block_hash": hex::encode(anchor.hash),
                })),
                "blocks": blocks.iter().map(block_projection_json).collect::<Vec<_>>(),
                "continuation": continuation,
            })
        }

        fn identity_probe_response(tip_height: u64, tip_hash_byte: u8) -> CannedResponse {
            CannedResponse::json(
                200,
                full_scan_json(0, 0, tip_height, tip_hash_byte, Vec::new()),
            )
        }

        fn source_for(server: &MockServer) -> RemoteNodeSource {
            RemoteNodeSource::new(&server.base_url(), Some(TOKEN)).expect("remote source")
        }

        fn scan_request(start_height: u64, max_blocks: u64) -> ScanRequest {
            ScanRequest {
                network: CoreNetwork::Regtest,
                chain_id: canonical_chain_identity().chain_id,
                start: ScanStart::Height(start_height),
                max_blocks,
                stop_height: None,
                commitment_filters: Vec::new(),
            }
        }

        /// Acceptance (a): a remote scan must hand the scan loop EXACTLY what the
        /// embedded node hands it for the same chain. The loop, cursor rules and
        /// recovery all sit above this boundary, so identical projections here are
        /// what makes a remote restore reach the same balance as a local one.
        #[test]
        fn acceptance_a_remote_projection_is_identical_to_the_embedded_one() {
            let blocks = canonical_blocks(1, 3, [0x30; 32], 0x31);
            let expected = blocks.clone();
            let tip_hash = blocks.last().expect("tip").block_hash;
            let server = MockServer::start(move |request| {
                if request.path == "/block/0" {
                    CannedResponse::json(200, json!({"height": 0, "hash": h32(0x30)}))
                } else if request.path.starts_with("/chain/scan/scriptless/v1") {
                    CannedResponse::json(200, full_scan_json(1, 3, 3, 0x33, blocks.clone()))
                } else {
                    CannedResponse::json(404, json!({"error": "unexpected path"}))
                }
            });

            let result = source_for(&server)
                .scan_range(scan_request(1, 3))
                .expect("remote scan succeeds");

            assert_eq!(
                result.blocks, expected,
                "the remote projection diverged from the embedded one"
            );
            assert_eq!(result.tip.height, 3);
            assert_eq!(result.tip.hash, tip_hash);
            // Caught up with the tip: nothing left to continue from.
            assert!(result.continuation.is_none());
        }

        /// Acceptance (c): when the remote node reorganizes under a live scan, the
        /// cursor must be reported invalid — that is the signal the shared
        /// reconciliation path needs to rewind and converge on the canonical chain.
        /// Silently accepting the stale cursor would strand the wallet on a dead
        /// fork with a balance that never corrects itself.
        #[test]
        fn acceptance_c_remote_reorg_invalidates_the_cursor_instead_of_diverging() {
            // The anchor the wallet committed at height 2.
            let anchor = BlockRef {
                height: 2,
                hash: [0x32; 32],
            };
            let cursor = WalletScanCursor::new(
                CoreNetwork::Regtest,
                canonical_chain_identity().chain_id,
                3,
                anchor,
            );

            // Same height, different block: the chain reorganized under us.
            let reorged = MockServer::start(move |request| {
                if request.path.starts_with("/block/2") {
                    CannedResponse::json(200, json!({"height": 2, "hash": h32(0xF2)}))
                } else if request.path.starts_with("/chain/scan/scriptless/v1") {
                    identity_probe_response(9, 0xF9)
                } else {
                    CannedResponse::json(404, json!({"error": "unexpected path"}))
                }
            });

            let validation = source_for(&reorged).validate_cursor(cursor);
            assert!(
                matches!(&validation, Ok(check) if !check.valid) || validation.is_err(),
                "a reorged anchor must never validate: {validation:?}"
            );

            // The unchanged chain still validates, so the check is not simply
            // rejecting everything.
            let intact = MockServer::start(move |request| {
                if request.path.starts_with("/block/2") {
                    CannedResponse::json(200, json!({"height": 2, "hash": h32(0x32)}))
                } else if request.path.starts_with("/chain/scan/scriptless/v1") {
                    identity_probe_response(9, 0xF9)
                } else {
                    CannedResponse::json(404, json!({"error": "unexpected path"}))
                }
            });
            let validation = source_for(&intact)
                .validate_cursor(cursor)
                .expect("an intact anchor validates");
            assert!(validation.valid);
        }

        /// Acceptance (d): a busy remote node must never freeze the cursor. Every
        /// busy answer has to come back retriable so the scan loop backs off and
        /// tries again; classifying it as terminal is precisely the frozen-cursor
        /// regression.
        #[test]
        fn acceptance_d_busy_remote_is_retriable_and_the_scan_then_advances() {
            let attempts = Arc::new(AtomicUsize::new(0));
            let server_attempts = Arc::clone(&attempts);
            let block = block_json(1, 0x31, &h32(0x30));
            let server = MockServer::start(move |request| {
                if request.path == "/block/0" {
                    return CannedResponse::json(200, json!({"height": 0, "hash": h32(0x30)}));
                }
                if !request.path.starts_with("/chain/scan/scriptless/v1") {
                    return CannedResponse::json(404, json!({"error": "unexpected path"}));
                }
                // The first three attempts find a contended chain lock.
                if server_attempts.fetch_add(1, Ordering::SeqCst) < 3 {
                    CannedResponse::json(503, json!({"error": "overloaded: chain busy; retry"}))
                } else {
                    CannedResponse::json(200, full_scan_json(1, 1, 1, 0x31, vec![block.clone()]))
                }
            });
            let source = source_for(&server);

            for attempt in 0..3 {
                let error = source
                    .scan_range(scan_request(1, 1))
                    .expect_err("a busy chain must fail this attempt");
                assert!(
                    matches!(error, WalletCoreError::NodeNotReady(_)),
                    "attempt {attempt} must stay retriable, got {error:?}"
                );
            }

            // Once the lock frees the very same cursor advances — no reset, no
            // manual intervention, no terminal state in between.
            let result = source
                .scan_range(scan_request(1, 1))
                .expect("the scan proceeds once the remote is free");
            assert_eq!(result.blocks.len(), 1);
            assert_eq!(result.blocks[0].height, 1);
            assert_eq!(attempts.load(Ordering::SeqCst), 4);
        }

        fn scan_error_of(response: CannedResponse) -> WalletCoreError {
            let server = MockServer::start(move |_| response.clone());
            let source = source_for(&server);
            source
                .scan_range(scan_request(0, 2))
                .expect_err("scan must fail")
        }

        // ── Tests ───────────────────────────────────────────────────────────

        #[test]
        fn full_scan_page_maps_to_scan_result_and_reconstructs_output_context() {
            let blocks = canonical_blocks(1, 2, [0x50; 32], 0x51);
            let tip_hash = blocks[1].block_hash;
            let first_hash = blocks[0].block_hash;
            let body = full_scan_json(1, 2, 2, 0x52, blocks);
            let server = MockServer::start(move |request| {
                if request.path == "/block/0" {
                    return CannedResponse::json(200, json!({"height": 0, "hash": h32(0x50)}));
                }
                assert_eq!(request.path, "/chain/scan/scriptless/v1");
                assert!(request.query.contains("from=1&to=2"));
                assert_eq!(
                    request.authorization.as_deref(),
                    Some("Bearer test-token"),
                    "scan endpoint must be called with the bearer token"
                );
                CannedResponse::json(200, body.clone())
            });
            let source = source_for(&server);
            let result = source.scan_range(scan_request(1, 2)).expect("scan page");

            assert_eq!(
                result.tip,
                BlockRef {
                    height: 2,
                    hash: tip_hash
                }
            );
            assert_eq!(result.blocks.len(), 2);
            let first = &result.blocks[0];
            assert_eq!(first.height, 1);
            assert_eq!(first.block_hash, first_hash);
            assert_eq!(first.previous_block_hash, [0x50; 32]);
            assert_eq!(first.canonical_marker, first_hash);
            assert_eq!(first.outputs.len(), 2);
            let output = &first.outputs[0];
            assert_eq!(output.block_height, 1);
            assert_eq!(output.block_hash, first_hash);
            assert!(output.is_coinbase);
            assert_eq!(output.range_proof.len(), dom_crypto::RANGE_PROOF_SIZE);
            assert_eq!(output.output_position, 0);
            assert_eq!(first.inputs.len(), 1);
            assert_eq!(first.kernels.len(), 2);
            assert_eq!(first.transactions.len(), 1);
            // Page ends at the tip: no continuation.
            assert!(result.continuation.is_none());
            assert_eq!(
                source.last_observed_tip(),
                Some(BlockRef {
                    height: 2,
                    hash: tip_hash
                })
            );
            assert!(source.tip_regression().is_none());
        }

        #[test]
        fn server_clamp_is_respected_and_yields_continuation_cursor() {
            // The wallet asks for up to 1000 blocks; the server clamps the page
            // to 2 blocks (budget/tip clamp) and echoes the effective `to`.
            let blocks = canonical_blocks(1, 2, [0x50; 32], 0x51);
            let anchor_hash = blocks[1].block_hash;
            let body = full_scan_json(1, 64, 5, 0x55, blocks);
            let server = MockServer::start(move |request| {
                if request.path == "/block/0" {
                    return CannedResponse::json(200, json!({"height": 0, "hash": h32(0x50)}));
                }
                assert!(request.query.contains("from=1&to=64"));
                CannedResponse::json(200, body.clone())
            });
            let source = source_for(&server);
            let result = source.scan_range(scan_request(1, 1000)).expect("scan page");
            assert_eq!(result.blocks.len(), 2);
            let continuation = result.continuation.expect("continuation cursor");
            assert_eq!(continuation.next_height, 3);
            assert_eq!(continuation.anchor_height, 2);
            assert_eq!(continuation.anchor_hash, anchor_hash);
            assert_eq!(continuation.chain_id, canonical_chain_identity().chain_id);
            assert_eq!(continuation.network_magic, CoreNetwork::Regtest.magic());
        }

        #[test]
        fn busy_503_maps_to_retriable_node_not_ready() {
            let error = scan_error_of(CannedResponse::json(
                503,
                json!({"error": "overloaded: chain busy; retry"}),
            ));
            assert!(
                matches!(error, WalletCoreError::NodeNotReady(_)),
                "busy must stay retriable, got {error:?}"
            );
        }

        #[test]
        fn rate_limited_429_text_body_maps_to_retriable_temporary_failure() {
            // 429 arrives as plain text, not JSON (tower_governor behaviour).
            let error = scan_error_of(CannedResponse::text(429, "Too Many Requests! Wait for 1s"));
            assert!(matches!(error, WalletCoreError::TemporaryFailure(_)));
        }

        #[test]
        fn unauthorized_401_maps_to_terminal_internal_failure() {
            let error = scan_error_of(CannedResponse::text(401, ""));
            match error {
                WalletCoreError::InternalFailure(message) => {
                    assert!(message.contains("unauthorized"), "message: {message}");
                }
                other => panic!("401 must be terminal InternalFailure, got {other:?}"),
            }
        }

        #[test]
        fn missing_endpoint_404_maps_to_terminal_upgrade_error() {
            let error = scan_error_of(CannedResponse::text(404, "not found"));
            match error {
                WalletCoreError::InternalFailure(message) => {
                    assert!(
                        message.contains("/chain/scan/scriptless/v1"),
                        "message: {message}"
                    );
                }
                other => panic!("404 must be terminal InternalFailure, got {other:?}"),
            }
        }

        #[test]
        fn canonical_gap_code_maps_to_canonical_gap_and_plain_500_stays_retriable() {
            let gap = scan_error_of(CannedResponse::json(
                500,
                json!({"error": "canonical gap: missing canonical block at height 7",
                   "code": "canonical_gap"}),
            ));
            assert!(matches!(gap, WalletCoreError::CanonicalGap(_)));

            let plain = scan_error_of(CannedResponse::json(
                500,
                json!({"error": "internal: transient store hiccup"}),
            ));
            assert!(
                matches!(plain, WalletCoreError::TemporaryFailure(_)),
                "uncoded 500 must stay retriable, got {plain:?}"
            );
        }

        #[test]
        fn connection_failure_maps_to_retriable_temporary_failure() {
            // Reserved port with no listener: connection refused.
            let source =
                RemoteNodeSource::new("http://127.0.0.1:1", Some(TOKEN)).expect("remote source");
            let error = source
                .scan_range(scan_request(1, 2))
                .expect_err("connection must fail");
            assert!(matches!(error, WalletCoreError::TemporaryFailure(_)));
        }

        #[test]
        fn commitment_filters_are_rejected_locally_without_any_network_traffic() {
            let server = MockServer::start(|_| CannedResponse::text(500, "must never be reached"));
            let source = source_for(&server);
            let mut request = scan_request(1, 2);
            request.commitment_filters = vec![[0xAB; 33]];
            let error = source
                .scan_range(request)
                .expect_err("filters must be rejected");
            assert!(matches!(error, WalletCoreError::InvalidScanRequest(_)));
            assert_eq!(server.hits(), 0, "privacy: no request may leave the wallet");
        }

        #[test]
        fn schema_divergence_is_terminal_and_never_partially_consumed() {
            let valid_blocks = || canonical_blocks(1, 2, [0x50; 32], 0x51);

            let mut unknown_version = full_scan_json(1, 2, 2, 0x52, valid_blocks());
            unknown_version["schema_version"] = json!(2);

            let mut nonconsecutive = full_scan_json(1, 2, 2, 0x52, valid_blocks());
            nonconsecutive["blocks"][1]["height"] = json!(3);

            let mut missing_block =
                full_scan_json(1, 2, 2, 0x52, vec![block_json(1, 0x51, &h32(0x50))]);
            missing_block["served_to"] = json!(2);

            let mut bad_hex = full_scan_json(1, 2, 2, 0x52, valid_blocks());
            bad_hex["blocks"][0]["block_hash"] = json!("zz");

            let mut broken_chain = full_scan_json(1, 2, 2, 0x52, valid_blocks());
            broken_chain["blocks"][1]["previous_block_hash"] = json!(h32(0x99));

            let mut capsule_mismatch = full_scan_json(1, 2, 2, 0x52, valid_blocks());
            capsule_mismatch["blocks"][0]["transactions"][0]["outputs"][0]["recovery_version"] =
                json!(1);

            let mut beyond_tip = full_scan_json(1, 2, 1, 0x51, valid_blocks());
            beyond_tip["tip"]["height"] = json!(1);

            for (case, body) in [
                ("unknown schema_version", unknown_version),
                ("nonconsecutive heights", nonconsecutive),
                ("missing block in range", missing_block),
                ("invalid hex", bad_hex),
                ("broken previous-hash chain", broken_chain),
                ("capsule/version mismatch", capsule_mismatch),
                ("to beyond tip", beyond_tip),
                ("json garbage", json!("not an object")),
            ] {
                let error = scan_error_of(CannedResponse::raw_json(200, body.to_string()));
                match error {
                    WalletCoreError::InternalFailure(message) => {
                        assert!(
                            message.contains("remote schema violation"),
                            "case {case}: message {message}"
                        );
                    }
                    other => {
                        panic!("case {case}: expected terminal InternalFailure, got {other:?}")
                    }
                }
            }
        }

        #[test]
        fn tip_regression_is_recorded_for_the_consumer_without_aborting_the_scan() {
            let calls = Arc::new(AtomicUsize::new(0));
            let handler_calls = Arc::clone(&calls);
            let first = block_json(1, 0x51, &h32(0x50));
            let second = canonical_block(2, first.block_hash, 0x52);
            let first_for_server = first.clone();
            let server = MockServer::start(move |request| {
                if request.path == "/block/0" {
                    return CannedResponse::json(200, json!({"height": 0, "hash": h32(0x50)}));
                }
                if request.path == "/block/1" {
                    return CannedResponse::json(
                        200,
                        json!({"height": 1, "hash": hex::encode(first_for_server.block_hash)}),
                    );
                }
                let call = handler_calls.fetch_add(1, Ordering::SeqCst);
                if call == 0 {
                    CannedResponse::json(
                        200,
                        full_scan_json(1, 1, 10, 0x5A, vec![first_for_server.clone()]),
                    )
                } else {
                    CannedResponse::json(200, full_scan_json(2, 2, 8, 0x58, vec![second.clone()]))
                }
            });
            let source = source_for(&server);
            source.scan_range(scan_request(1, 1)).expect("first page");
            assert!(source.tip_regression().is_none());
            source.scan_range(scan_request(2, 1)).expect("second page");
            let regression = source.tip_regression().expect("regression recorded");
            assert_eq!(regression.previous.height, 10);
            assert_eq!(regression.previous.hash, [0x5A; 32]);
            assert_eq!(regression.observed.height, 8);
            assert_eq!(regression.observed.hash, [0x58; 32]);
            // High-water mark keeps the honest maximum.
            assert_eq!(source.last_observed_tip().map(|tip| tip.height), Some(10));
        }

        #[test]
        fn remote_identity_drift_within_session_is_terminal_chain_mismatch() {
            let calls = Arc::new(AtomicUsize::new(0));
            let handler_calls = Arc::clone(&calls);
            let block = block_json(1, 0x51, &h32(0x50));
            let server = MockServer::start(move |request| {
                if request.path == "/block/0" {
                    return CannedResponse::json(200, json!({"height": 0, "hash": h32(0x50)}));
                }
                let call = handler_calls.fetch_add(1, Ordering::SeqCst);
                let mut body = full_scan_json(1, 1, 5, 0x55, vec![block.clone()]);
                if call > 0 {
                    // Same network/chain_id (passes the request check) but a
                    // different genesis: a node silently swapping chains.
                    body["identity"]["genesis_hash"] = json!(h32(0x23));
                }
                CannedResponse::json(200, body)
            });
            let source = source_for(&server);
            source.scan_range(scan_request(1, 1)).expect("first page");
            let error = source
                .scan_range(scan_request(1, 1))
                .expect_err("identity drift must fail");
            assert!(matches!(error, WalletCoreError::CursorChainMismatch(_)));
        }

        #[test]
        fn chain_identity_probes_with_an_empty_page_and_pins_the_session() {
            let server = MockServer::start(|request| {
                assert_eq!(request.path, "/chain/scan/scriptless/v1");
                assert!(request.query.contains("from=0&to=0"));
                identity_probe_response(9, 0x59)
            });
            let source = source_for(&server);
            let identity = source.chain_identity().expect("identity probe");
            assert_eq!(identity.network, CoreNetwork::Regtest);
            assert_eq!(identity.network_magic, CoreNetwork::Regtest.magic());
            assert_eq!(identity.chain_id, canonical_chain_identity().chain_id);
            assert_eq!(
                identity.genesis_hash,
                canonical_chain_identity().genesis_hash
            );
            assert_eq!(identity.coinbase_maturity, 1440);
            assert_eq!(
                identity.current_tip,
                BlockRef {
                    height: 9,
                    hash: [0x59; 32]
                }
            );
            assert_eq!(source.last_observed_tip().map(|tip| tip.height), Some(9));
        }

        #[test]
        fn canonical_hash_at_height_maps_found_and_missing_headers() {
            let server = MockServer::start(|request| {
                assert!(
                    request.authorization.is_none(),
                    "/block is public; the bearer token must not be sent"
                );
                match request.path.as_str() {
                    "/block/5" => CannedResponse::json(
                        200,
                        json!({
                            "height": 5,
                            "hash": h32(0x77),
                            "prev_hash": h32(0x76),
                            "timestamp": 1_753_651_200u64,
                            "target": "00ff",
                        }),
                    ),
                    "/block/6" => CannedResponse::json(404, json!({"found": false})),
                    other => panic!("unexpected path {other}"),
                }
            });
            let source = source_for(&server);
            assert_eq!(
                source.canonical_hash_at_height(5).expect("found header"),
                Some([0x77; 32])
            );
            assert_eq!(
                source.canonical_hash_at_height(6).expect("missing header"),
                None
            );
        }

        #[test]
        fn validate_cursor_detects_reorg_through_the_public_header_endpoint() {
            let cursor = WalletScanCursor::new(
                CoreNetwork::Regtest,
                canonical_chain_identity().chain_id,
                8,
                BlockRef {
                    height: 7,
                    hash: [0x66; 32],
                },
            );

            let matching = MockServer::start(|request| match request.path.as_str() {
                "/chain/scan/scriptless/v1" => identity_probe_response(9, 0x59),
                "/block/7" => CannedResponse::json(
                    200,
                    json!({"height": 7, "hash": h32(0x66), "prev_hash": h32(0x65),
                       "timestamp": 1u64, "target": "00ff"}),
                ),
                other => panic!("unexpected path {other}"),
            });
            let source = source_for(&matching);
            let validation = source.validate_cursor(cursor).expect("valid cursor");
            assert!(validation.valid);
            assert_eq!(validation.safe_rescan_anchor.height, 7);
            assert_eq!(validation.safe_rescan_anchor.hash, [0x66; 32]);
            drop(matching);

            let reorged = MockServer::start(|request| match request.path.as_str() {
                "/chain/scan/scriptless/v1" => identity_probe_response(9, 0x59),
                "/block/7" => CannedResponse::json(
                    200,
                    json!({"height": 7, "hash": h32(0x67), "prev_hash": h32(0x65),
                       "timestamp": 1u64, "target": "00ff"}),
                ),
                other => panic!("unexpected path {other}"),
            });
            let source = source_for(&reorged);
            let error = source
                .validate_cursor(cursor)
                .expect_err("reorged anchor must fail");
            assert!(matches!(error, WalletCoreError::CursorReorg(_)));
        }

        #[test]
        fn scan_next_validates_the_anchor_and_pages_from_the_cursor() {
            let cursor = WalletScanCursor::new(
                CoreNetwork::Regtest,
                canonical_chain_identity().chain_id,
                8,
                BlockRef {
                    height: 7,
                    hash: [0x66; 32],
                },
            );
            let blocks = canonical_blocks(8, 2, [0x66; 32], 0x68);
            let blocks_for_server = blocks.clone();
            let server = MockServer::start(move |request| {
                match (request.path.as_str(), request.query.as_str()) {
                    // scan_next trait default: identity probe first.
                    ("/chain/scan/scriptless/v1", query) if query.contains("from=0&to=0") => {
                        identity_probe_response(9, 0x69)
                    }
                    ("/block/7", _) => CannedResponse::json(
                        200,
                        json!({"height": 7, "hash": h32(0x66), "prev_hash": h32(0x65),
                           "timestamp": 1u64, "target": "00ff"}),
                    ),
                    ("/chain/scan/scriptless/v1", query) if query.contains("from=8&to=9") => {
                        CannedResponse::json(
                            200,
                            full_scan_json(8, 9, 9, 0x69, blocks_for_server.clone()),
                        )
                    }
                    (path, query) => panic!("unexpected request {path}?{query}"),
                }
            });
            let source = source_for(&server);
            let result = source.scan_next(cursor, 2).expect("cursor page");
            assert_eq!(
                result
                    .blocks
                    .iter()
                    .map(|block| block.height)
                    .collect::<Vec<_>>(),
                vec![8, 9]
            );
            assert!(result.continuation.is_none(), "page reached the tip");
        }

        #[test]
        fn node_owned_operations_are_terminal_embedded_only_errors() {
            // No server needed: these must fail without any network traffic.
            let source =
                RemoteNodeSource::new("http://127.0.0.1:1", Some(TOKEN)).expect("remote source");
            let errors = [
                source.get_utxo(&[0xAB; 33]).map(|_| ()).unwrap_err(),
                source.get_kernel(&[0xAB; 33]).map(|_| ()).unwrap_err(),
                source
                    .get_block_summary(BlockSelector::Height(1))
                    .map(|_| ())
                    .unwrap_err(),
                source
                    .transaction_status(TransactionIdentifier::TxHash([0; 32]))
                    .map(|_| ())
                    .unwrap_err(),
                source
                    .rebroadcast_transaction(TransactionIdentifier::TxHash([0; 32]))
                    .map(|_| ())
                    .unwrap_err(),
                source
                    .query_submission(TransactionIdentifier::TxHash([0; 32]))
                    .map(|_| ())
                    .unwrap_err(),
                source.mempool_policy_snapshot().map(|_| ()).unwrap_err(),
            ];
            for error in errors {
                match error {
                    WalletCoreError::InternalFailure(message) => {
                        assert!(
                            message.contains("requires the embedded node"),
                            "message: {message}"
                        );
                    }
                    other => panic!("expected terminal InternalFailure, got {other:?}"),
                }
            }
        }

        #[test]
        fn frozen_fee_policy_is_available_without_submission_authority() {
            let server = MockServer::start(|request| match request.path.as_str() {
                "/chain/scan/scriptless/v1" => identity_probe_response(9, 0x59),
                other => panic!("unexpected path {other}"),
            });
            let source = source_for(&server);
            let snapshot = source.fee_policy_snapshot().expect("frozen fee policy");
            assert_eq!(snapshot.policy_version, fee_policy::FEE_POLICY_VERSION);
            assert_eq!(snapshot.network, CoreNetwork::Regtest);
            assert_eq!(snapshot.min_relay_fee_rate, MIN_RELAY_FEE_RATE);
            assert_eq!(snapshot.max_tx_weight, u64::from(MAX_TX_WEIGHT));

            let shape = TransactionShape {
                input_count: 2,
                output_count: 3,
                kernel_count: 1,
            };
            let expected = fee_policy::fee_breakdown(RemoteNodeSource::core_shape(shape))
                .expect("canonical breakdown");
            let actual = source.minimum_fee(shape).expect("remote minimum fee");
            assert_eq!(actual.total_weight, expected.weight.total_weight);
            assert_eq!(actual.minimum_fee_noms, expected.minimum_fee_noms);
            assert_eq!(actual.recommended_fee_noms, expected.recommended_fee_noms);
        }

        #[test]
        fn debug_output_redacts_the_bearer_token() {
            let source =
                RemoteNodeSource::new("http://127.0.0.1:1", Some("super-secret")).expect("source");
            let debug = format!("{source:?}");
            assert!(!debug.contains("super-secret"), "debug: {debug}");
            assert!(debug.contains("<redacted>"), "debug: {debug}");
        }

        #[test]
        fn constructor_rejects_bad_configuration() {
            assert!(matches!(
                RemoteNodeSource::new("not a url", None),
                Err(RemoteSourceConfigError::InvalidBaseUrl(_))
            ));
            assert!(matches!(
                RemoteNodeSource::new("ftp://example.com", None),
                Err(RemoteSourceConfigError::UnsupportedScheme)
            ));
            assert!(matches!(
                RemoteNodeSource::new("http://127.0.0.1:1", Some("  \n")),
                Err(RemoteSourceConfigError::EmptyBearerToken)
            ));
            // The node writes the token file with a trailing newline; trim it.
            let source = RemoteNodeSource::new("http://127.0.0.1:1/", Some("token-value\n"))
                .expect("trimmed token");
            assert_eq!(
                source.bearer_token.as_ref().map(|token| token.0.as_str()),
                Some("token-value")
            );
            assert_eq!(source.base_url, "http://127.0.0.1:1");
        }

        #[test]
        fn scan_past_the_tip_returns_an_empty_page_without_continuation() {
            let server = MockServer::start(|request| {
                if request.path == "/block/9" {
                    return CannedResponse::json(
                        200,
                        json!({"height": 9, "hash": hex::encode([9; 32])}),
                    );
                }
                assert!(request.query.contains("from=10&to=11"));
                CannedResponse::json(200, full_scan_json(10, 11, 5, 0x55, Vec::new()))
            });
            let source = source_for(&server);
            let result = source.scan_range(scan_request(10, 2)).expect("empty page");
            assert!(result.blocks.is_empty());
            assert!(result.continuation.is_none());
            assert_eq!(result.tip.height, 5);
        }
    }
}
