#![forbid(unsafe_code)]

//! Bounded ChainSource adapter boundary and deterministic test source.
//!
//! The HTTP implementation follows the pushed wallet-safe RPC contract. It
//! treats node identity and ancestry as evidence, never as configuration.

use dom_wallet_domain::{NetworkIdentity, OutputRecord, ScanBounds, ScanTarget};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, VecDeque};
use std::io::Read;
use std::time::Duration;
use thiserror::Error;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeHandshake {
    pub identity: NetworkIdentity,
    pub source_identity: String,
    pub api_compatibility_version: u16,
    pub tip_height: u64,
    pub tip_hash: [u8; 32],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ScanPage {
    pub source_identity: String,
    pub target_hash: [u8; 32],
    pub start_height: u64,
    pub end_height: u64,
    pub page_number: u32,
    pub is_last: bool,
    pub outputs: Vec<OutputRecord>,
    pub blocks: Vec<ScanBlockEvidence>,
}

/// Canonical block-context evidence. Commitments and kernel excesses are kept
/// together with their height and hash so a later reconciliation step cannot
/// accidentally use an unanchored direct lookup as chain evidence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ScanBlockEvidence {
    pub height: u64,
    pub hash: [u8; 32],
    pub output_commitments: Vec<[u8; 33]>,
    pub input_commitments: Vec<[u8; 33]>,
    pub kernel_excesses: Vec<[u8; 33]>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LiveNodeProbe {
    pub endpoint_origin: String,
    pub identity: NetworkIdentity,
    pub rpc_api_version: u16,
    pub protocol_version: u16,
    pub network_magic: [u8; 4],
    pub tip_height: u64,
    pub tip_hash: [u8; 32],
    pub max_scan_range: u64,
    pub supports_scan: bool,
    pub supports_ancestry: bool,
    pub supports_kernel_lookup: bool,
    pub supports_transaction_lookup: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KernelLookup {
    pub excess: [u8; 33],
    pub block_hash: Option<[u8; 32]>,
}

/// Public mempool evidence from the wallet-safe `/tx/{hash}` endpoint.  A
/// missing result is deliberately not a rejection or a confirmation claim.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransactionLookup {
    pub transaction_hash: [u8; 32],
    pub in_mempool: bool,
}

pub trait ChainSource {
    fn handshake(&mut self) -> Result<NodeHandshake, ChainError>;
    fn hash_at_height(&mut self, height: u64) -> Result<Option<[u8; 32]>, ChainError>;
    fn bounded_ancestry(
        &mut self,
        target: &ScanTarget,
        maximum_depth: u32,
    ) -> Result<bool, ChainError>;
    fn scan_page(&mut self, target: &ScanTarget, page_number: u32) -> Result<ScanPage, ChainError>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ConnectionState {
    Disconnected,
    Connecting,
    VerifyingIdentity,
    Connected,
    Synchronizing,
    Synced,
    Degraded { error: ChainError },
    BackingOff { delay_ms: u64 },
    WrongNetwork,
    AuthenticationFailed,
    IncompatibleProtocol,
    FatalConfigurationError,
}

#[derive(Clone, Debug)]
pub struct ReconnectController {
    retry_ceiling: u32,
    max_backoff_ms: u64,
    stable_success_threshold: u32,
    failures: u32,
    stable_successes: u32,
}

impl ReconnectController {
    pub fn new(retry_ceiling: u32, max_backoff_ms: u64, stable_success_threshold: u32) -> Self {
        Self {
            retry_ceiling,
            max_backoff_ms,
            stable_success_threshold,
            failures: 0,
            stable_successes: 0,
        }
    }

    pub fn on_failure(&mut self) -> Result<u64, ChainError> {
        self.stable_successes = 0;
        self.failures = self.failures.saturating_add(1);
        if self.failures > self.retry_ceiling {
            return Err(ChainError::RetryExhausted);
        }
        let shift = self.failures.saturating_sub(1).min(20);
        Ok((100u64.saturating_mul(1u64 << shift)).min(self.max_backoff_ms))
    }

    pub fn on_success(&mut self) {
        self.stable_successes = self.stable_successes.saturating_add(1);
        if self.stable_successes >= self.stable_success_threshold {
            self.failures = 0;
        }
    }

    pub fn failures(&self) -> u32 {
        self.failures
    }
}

pub fn acquire_target<S: ChainSource>(
    source: &mut S,
    expected: &NetworkIdentity,
    bounds: ScanBounds,
) -> Result<(NodeHandshake, ScanTarget), ChainError> {
    bounds.validate().map_err(|_| ChainError::InvalidBounds)?;
    let handshake = source.handshake()?;
    if &handshake.identity != expected {
        return Err(ChainError::IdentityMismatch);
    }
    if handshake.source_identity.is_empty() || handshake.api_compatibility_version == 0 {
        return Err(ChainError::IncompatibleProtocol);
    }
    if handshake.tip_height != bounds.end_height {
        return Err(ChainError::ChangedBounds);
    }
    let target = ScanTarget {
        target_height: handshake.tip_height,
        target_block_hash: handshake.tip_hash,
        source_identity: handshake.source_identity.clone(),
        scan_bounds: bounds,
        evidence_version: handshake.api_compatibility_version,
    };
    target.validate().map_err(|_| ChainError::InvalidTarget)?;
    Ok((handshake, target))
}

pub fn validate_target<S: ChainSource>(
    source: &mut S,
    expected: &NetworkIdentity,
    target: &ScanTarget,
    maximum_ancestry: u32,
) -> Result<(), ChainError> {
    let handshake = source.handshake()?;
    if &handshake.identity != expected {
        return Err(ChainError::IdentityMismatch);
    }
    if handshake.source_identity != target.source_identity {
        return Err(ChainError::SourceChanged);
    }
    if handshake.tip_height < target.target_height {
        return Err(ChainError::LowerTip);
    }
    let target_hash = source
        .hash_at_height(target.target_height)?
        .ok_or(ChainError::TargetHashMissing)?;
    if target_hash != target.target_block_hash {
        return Err(ChainError::TargetHashChanged);
    }
    if handshake.tip_height > target.target_height
        && !source.bounded_ancestry(target, maximum_ancestry)?
    {
        return Err(ChainError::AncestryUnavailable);
    }
    Ok(())
}

pub fn collect_provisional<S: ChainSource>(
    source: &mut S,
    target: &ScanTarget,
) -> Result<Vec<OutputRecord>, ChainError> {
    Ok(collect_provisional_pages(source, target)?
        .into_iter()
        .flat_map(|page| page.outputs)
        .collect())
}

/// Returns validated whole pages so callers can atomically apply output and
/// kernel evidence together. No page is exposed until all of its structural
/// checks succeed.
pub fn collect_provisional_pages<S: ChainSource>(
    source: &mut S,
    target: &ScanTarget,
) -> Result<Vec<ScanPage>, ChainError> {
    let mut expected_page = 0;
    let mut all = Vec::new();
    loop {
        if expected_page >= target.scan_bounds.max_pages {
            return Err(ChainError::PageLimitExceeded);
        }
        let page = source.scan_page(target, expected_page)?;
        if page.source_identity != target.source_identity
            || page.target_hash != target.target_block_hash
            || page.page_number != expected_page
        {
            return Err(ChainError::InconsistentPage);
        }
        if page.start_height < target.scan_bounds.start_height
            || page.end_height > target.scan_bounds.end_height
            || page.start_height > page.end_height
        {
            return Err(ChainError::ChangedBounds);
        }
        if page.outputs.len() > target.scan_bounds.max_records_per_page as usize {
            return Err(ChainError::PageLimitExceeded);
        }
        let is_last = page.is_last;
        all.push(page);
        if is_last {
            return Ok(all);
        }
        expected_page = expected_page
            .checked_add(1)
            .ok_or(ChainError::PageLimitExceeded)?;
    }
}

#[derive(Clone, Debug)]
pub struct MockChainSource {
    pub handshake: NodeHandshake,
    pub hashes: BTreeMap<u64, [u8; 32]>,
    pub pages: Vec<ScanPage>,
    pub ancestry_valid: bool,
    pub failures: VecDeque<ChainError>,
}

impl MockChainSource {
    pub fn new(identity: NetworkIdentity) -> Self {
        let hash = [9; 32];
        Self {
            handshake: NodeHandshake {
                identity,
                source_identity: "mock-dom-node".into(),
                api_compatibility_version: 1,
                tip_height: 0,
                tip_hash: hash,
            },
            hashes: BTreeMap::from([(0, hash)]),
            pages: vec![ScanPage {
                source_identity: "mock-dom-node".into(),
                target_hash: hash,
                start_height: 0,
                end_height: 0,
                page_number: 0,
                is_last: true,
                outputs: Vec::new(),
                blocks: Vec::new(),
            }],
            ancestry_valid: true,
            failures: VecDeque::new(),
        }
    }

    fn fail_if_queued(&mut self) -> Result<(), ChainError> {
        self.failures.pop_front().map_or(Ok(()), Err)
    }
}

impl ChainSource for MockChainSource {
    fn handshake(&mut self) -> Result<NodeHandshake, ChainError> {
        self.fail_if_queued()?;
        Ok(self.handshake.clone())
    }
    fn hash_at_height(&mut self, height: u64) -> Result<Option<[u8; 32]>, ChainError> {
        self.fail_if_queued()?;
        Ok(self.hashes.get(&height).copied())
    }
    fn bounded_ancestry(
        &mut self,
        _target: &ScanTarget,
        _maximum_depth: u32,
    ) -> Result<bool, ChainError> {
        self.fail_if_queued()?;
        Ok(self.ancestry_valid)
    }
    fn scan_page(
        &mut self,
        _target: &ScanTarget,
        page_number: u32,
    ) -> Result<ScanPage, ChainError> {
        self.fail_if_queued()?;
        self.pages
            .get(page_number as usize)
            .cloned()
            .ok_or(ChainError::MissingPage)
    }
}

#[derive(Clone, Debug)]
pub struct DomNodeAdapter {
    pub endpoint: String,
}

const MAX_HTTP_RESPONSE_BYTES: u64 = 8 * 1024 * 1024;
const MAX_NODE_PAGE_HEIGHTS: u64 = 1_000;
const MAX_ANCESTRY_STEPS: u32 = 256;

/// Strict client for the pushed DOM wallet-safe REST surface.
pub struct DomHttpChainSource {
    base_url: String,
    client: reqwest::blocking::Client,
    expected: NetworkIdentity,
    source_identity: String,
    api_version: u16,
    bearer_token: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct HealthDto {
    ok: bool,
}
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct IdentityDto {
    rpc_api_version: u16,
    protocol_version: u16,
    network: String,
    network_magic: String,
    chain_id: String,
    genesis_hash: String,
    tip_height: u64,
    tip_hash: String,
    max_scan_range: u64,
}
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AncestryDto {
    canonical: bool,
    ancestor_match: bool,
    descendant_match: bool,
    steps_checked: u64,
    bounded: bool,
    observed_ancestor_hash: String,
    observed_descendant_hash: String,
    is_finality_proof: bool,
}
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct BlockDto {
    height: u64,
    hash: String,
    prev_hash: String,
    timestamp: u64,
    target: String,
}
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ScanTipDto {
    height: u64,
    hash: String,
}
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ScanBlockDto {
    height: u64,
    hash: String,
    output_commitments: Vec<String>,
    input_commitments: Vec<String>,
    fees: u64,
    kernel_excesses: Vec<String>,
}
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ScanDto {
    tip: ScanTipDto,
    from: u64,
    to: u64,
    blocks: Vec<ScanBlockDto>,
}
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SubmitDto {
    accepted: bool,
    relayed: bool,
    tx_hash: Option<String>,
    warning: Option<String>,
    error: Option<String>,
}
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct KernelFoundDto {
    found: bool,
    excess: String,
    block_hash: String,
}
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct KernelMissingDto {
    found: bool,
}
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TxFoundDto {
    found: bool,
    tx_hash: String,
    fee: u64,
    fee_rate: u64,
    weight: u32,
}
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TxMissingDto {
    found: bool,
}

impl DomHttpChainSource {
    pub fn new(
        endpoint: &str,
        expected: NetworkIdentity,
        source_identity: String,
        api_version: u16,
        connect_timeout_ms: u64,
        request_timeout_ms: u64,
        bearer_token: Option<String>,
    ) -> Result<Self, ChainError> {
        if endpoint.len() > 2_048
            || !(endpoint.starts_with("https://") || endpoint.starts_with("http://"))
            || source_identity.is_empty()
            || api_version == 0
        {
            return Err(ChainError::InvalidConfiguration);
        }
        let client = reqwest::blocking::Client::builder()
            .connect_timeout(Duration::from_millis(connect_timeout_ms))
            .timeout(Duration::from_millis(request_timeout_ms))
            .build()
            .map_err(|_| ChainError::Transport)?;
        Ok(Self {
            base_url: endpoint.trim_end_matches('/').into(),
            client,
            expected,
            source_identity,
            api_version,
            bearer_token,
        })
    }

    fn request_json<T: for<'de> Deserialize<'de>>(&self, path: &str) -> Result<T, ChainError> {
        let url = format!("{}{}", self.base_url, path);
        let mut request = self.client.get(url);
        if let Some(token) = &self.bearer_token {
            request = request.bearer_auth(token);
        }
        let response = request.send().map_err(map_http_error)?;
        let status = response.status().as_u16();
        if status == 401 || status == 403 {
            return Err(ChainError::AuthenticationFailed);
        }
        if status == 404 {
            return Err(ChainError::CapabilityUnavailable(path.into()));
        }
        if status == 429 {
            return Err(ChainError::RateLimited);
        }
        if status == 503 {
            return Err(ChainError::Overloaded);
        }
        if !(200..300).contains(&status) {
            return Err(ChainError::HttpStatus(status));
        }
        Self::decode_response(response)
    }

    fn decode_response<T: for<'de> Deserialize<'de>>(
        response: reqwest::blocking::Response,
    ) -> Result<T, ChainError> {
        if response
            .content_length()
            .is_some_and(|len| len > MAX_HTTP_RESPONSE_BYTES)
        {
            return Err(ChainError::ResponseTooLarge);
        }
        let mut bytes = Vec::new();
        response
            .take(MAX_HTTP_RESPONSE_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| ChainError::Transport)?;
        if bytes.len() as u64 > MAX_HTTP_RESPONSE_BYTES {
            return Err(ChainError::ResponseTooLarge);
        }
        serde_json::from_slice(&bytes).map_err(|_| ChainError::MalformedResponse)
    }

    fn identity_snapshot(&self) -> Result<IdentityDto, ChainError> {
        let health: HealthDto = self.request_json("/health")?;
        if !health.ok {
            return Err(ChainError::Unhealthy);
        }
        let identity: IdentityDto = self.request_json("/chain/identity")?;
        if identity.rpc_api_version != self.api_version || identity.protocol_version != 1 {
            return Err(ChainError::IncompatibleProtocol);
        }
        if identity.max_scan_range == 0
            || identity.max_scan_range > MAX_NODE_PAGE_HEIGHTS
            || decode_lower_hex(&identity.network_magic, 4)?
                .iter()
                .all(|byte| *byte == 0)
        {
            return Err(ChainError::MalformedResponse);
        }
        let network = match self.expected.network {
            dom_wallet_domain::Network::PrivateTestnet => "regtest",
            dom_wallet_domain::Network::PublicTestnet => "testnet",
            dom_wallet_domain::Network::Mainnet => "mainnet",
        };
        if identity.network != network
            || decode_hash(&identity.chain_id)? != self.expected.chain_id
            || decode_hash(&identity.genesis_hash)? != self.expected.genesis_id
        {
            return Err(ChainError::IdentityMismatch);
        }
        if identity.tip_height == 0 && decode_hash(&identity.tip_hash)? != self.expected.genesis_id
        {
            return Err(ChainError::InconsistentNode);
        }
        Ok(identity)
    }

    /// Performs only node reads. This cannot access or mutate any wallet
    /// directory and deliberately renders the endpoint as origin only.
    pub fn live_probe(&self) -> Result<LiveNodeProbe, ChainError> {
        let identity = self.identity_snapshot()?;
        let tip = self.block(&identity.tip_height.to_string())?;
        let tip_hash = decode_hash(&identity.tip_hash)?;
        if tip.height != identity.tip_height || decode_hash(&tip.hash)? != tip_hash {
            return Err(ChainError::InconsistentNode);
        }
        let origin =
            reqwest::Url::parse(&self.base_url).map_err(|_| ChainError::InvalidConfiguration)?;
        let host = origin.host_str().ok_or(ChainError::InvalidConfiguration)?;
        let endpoint_origin = format!("{}://{}", origin.scheme(), host);
        Ok(LiveNodeProbe {
            endpoint_origin,
            identity: self.expected.clone(),
            rpc_api_version: identity.rpc_api_version,
            protocol_version: identity.protocol_version,
            network_magic: decode_lower_hex(&identity.network_magic, 4)?
                .try_into()
                .map_err(|_| ChainError::MalformedResponse)?,
            tip_height: identity.tip_height,
            tip_hash,
            max_scan_range: identity.max_scan_range,
            supports_scan: true,
            supports_ancestry: true,
            supports_kernel_lookup: true,
            supports_transaction_lookup: true,
        })
    }

    /// Verifies every non-mutating wallet-safe route needed before a wallet is
    /// opened for a live run.  It deliberately never calls `POST /tx/submit`:
    /// there is no protocol-defined read-only submit-capability endpoint and a
    /// preflight must not present any transaction bytes to a node.
    pub fn verify_wallet_safe_capabilities(&mut self) -> Result<LiveNodeProbe, ChainError> {
        let probe = self.live_probe()?;
        let target = ScanTarget {
            target_height: probe.tip_height,
            target_block_hash: probe.tip_hash,
            source_identity: self.source_identity.clone(),
            scan_bounds: ScanBounds {
                start_height: probe.tip_height,
                end_height: probe.tip_height,
                max_pages: 1,
                max_records_per_page: 100_000,
            },
            evidence_version: probe.rpc_api_version,
        };
        self.checked_scan(&target, 0)?;
        let ancestor_height = probe.tip_height.saturating_sub(MAX_ANCESTRY_STEPS as u64);
        let ancestor = self.block(&ancestor_height.to_string())?;
        if ancestor.height != ancestor_height {
            return Err(ChainError::InconsistentNode);
        }
        let ancestor_hash = decode_hash(&ancestor.hash)?;
        let ancestor_target = ScanTarget {
            target_height: ancestor_height,
            target_block_hash: ancestor_hash,
            source_identity: self.source_identity.clone(),
            scan_bounds: ScanBounds {
                start_height: ancestor_height,
                end_height: ancestor_height,
                max_pages: 1,
                max_records_per_page: 1,
            },
            evidence_version: probe.rpc_api_version,
        };
        let ancestry_bound = u32::try_from(probe.tip_height.saturating_sub(ancestor_height))
            .map_err(|_| ChainError::AncestryUnavailable)?
            .max(1);
        if !self.bounded_ancestry(&ancestor_target, ancestry_bound)? {
            return Err(ChainError::AncestryUnavailable);
        }
        let _ = self.lookup_kernel([1; 33])?;
        let _ = self.lookup_transaction([1; 32])?;
        Ok(probe)
    }

    /// Optional targeted evidence. It is intentionally not used as a scan
    /// substitute: only paginated block evidence can establish confirmation.
    pub fn lookup_kernel(&self, excess: [u8; 33]) -> Result<KernelLookup, ChainError> {
        let path = format!("/kernel/{}", hex::encode(excess));
        let url = format!("{}{}", self.base_url, path);
        let mut request = self.client.get(url);
        if let Some(token) = &self.bearer_token {
            request = request.bearer_auth(token);
        }
        let response = request.send().map_err(map_http_error)?;
        if response.status().as_u16() == 404 {
            let body: KernelMissingDto = Self::decode_response(response)?;
            if body.found {
                return Err(ChainError::MalformedResponse);
            }
            return Ok(KernelLookup {
                excess,
                block_hash: None,
            });
        }
        if !response.status().is_success() {
            return Err(ChainError::HttpStatus(response.status().as_u16()));
        }
        let body: KernelFoundDto = Self::decode_response(response)?;
        if !body.found || decode_commitment(&body.excess)? != excess {
            return Err(ChainError::MalformedResponse);
        }
        Ok(KernelLookup {
            excess,
            block_hash: Some(decode_hash(&body.block_hash)?),
        })
    }

    /// Reads only the node's authoritative volatile-mempool projection.  A
    /// false value means "not currently observed" and must never be treated
    /// as rejection: the transaction may have been mined or evicted.
    pub fn lookup_transaction(
        &self,
        transaction_hash: [u8; 32],
    ) -> Result<TransactionLookup, ChainError> {
        let path = format!("/tx/{}", hex::encode(transaction_hash));
        let url = format!("{}{}", self.base_url, path);
        let mut request = self.client.get(url);
        if let Some(token) = &self.bearer_token {
            request = request.bearer_auth(token);
        }
        let response = request.send().map_err(map_http_error)?;
        let status = response.status().as_u16();
        if status == 401 || status == 403 {
            return Err(ChainError::AuthenticationFailed);
        }
        if status == 404 {
            return Err(ChainError::CapabilityUnavailable("/tx/{hash}".into()));
        }
        if status == 429 {
            return Err(ChainError::RateLimited);
        }
        if status == 503 {
            return Err(ChainError::Overloaded);
        }
        if !(200..300).contains(&status) {
            return Err(ChainError::HttpStatus(status));
        }
        decode_transaction_lookup(
            Self::decode_response::<serde_json::Value>(response)?,
            transaction_hash,
        )
    }

    fn block(&self, id: &str) -> Result<BlockDto, ChainError> {
        let block: BlockDto = self.request_json(&format!("/block/{id}"))?;
        let _ = (&block.prev_hash, block.timestamp, &block.target);
        decode_hash(&block.hash)?;
        Ok(block)
    }

    fn checked_scan(&self, target: &ScanTarget, page: u32) -> Result<ScanPage, ChainError> {
        let start = target
            .scan_bounds
            .start_height
            .checked_add(page as u64 * MAX_NODE_PAGE_HEIGHTS)
            .ok_or(ChainError::ChangedBounds)?;
        if start > target.scan_bounds.end_height {
            return Err(ChainError::MissingPage);
        }
        let end = target
            .scan_bounds
            .end_height
            .min(start.saturating_add(MAX_NODE_PAGE_HEIGHTS - 1));
        let scan: ScanDto = self.request_json(&format!("/chain/scan?from={start}&to={end}"))?;
        if scan.from != start
            || scan.to < start
            || scan.to > end
            || scan.blocks.len() > MAX_NODE_PAGE_HEIGHTS as usize
        {
            return Err(ChainError::ChangedBounds);
        }
        let tip_hash = decode_hash(&scan.tip.hash)?;
        if scan.tip.height < target.target_height
            || (scan.tip.height == target.target_height && tip_hash != target.target_block_hash)
        {
            return Err(ChainError::TargetHashChanged);
        }
        let mut last = None;
        let mut blocks = Vec::with_capacity(scan.blocks.len());
        for item in &scan.blocks {
            if item.height < start
                || item.height > scan.to
                || last.is_some_and(|h| item.height <= h)
            {
                return Err(ChainError::InconsistentPage);
            }
            last = Some(item.height);
            let hash = decode_hash(&item.hash)?;
            if item.hash == "00".repeat(32) {
                return Err(ChainError::TargetHashMissing);
            }
            if item.output_commitments.len() + item.input_commitments.len()
                > target.scan_bounds.max_records_per_page as usize
            {
                return Err(ChainError::PageLimitExceeded);
            }
            let output_commitments = item
                .output_commitments
                .iter()
                .map(|value| decode_commitment(value))
                .collect::<Result<Vec<_>, _>>()?;
            let input_commitments = item
                .input_commitments
                .iter()
                .map(|value| decode_commitment(value))
                .collect::<Result<Vec<_>, _>>()?;
            let kernel_excesses = item
                .kernel_excesses
                .iter()
                .map(|value| decode_commitment(value))
                .collect::<Result<Vec<_>, _>>()?;
            if kernel_excesses.len() > target.scan_bounds.max_records_per_page as usize
                || has_duplicates(&kernel_excesses)
            {
                return Err(ChainError::InconsistentPage);
            }
            blocks.push(ScanBlockEvidence {
                height: item.height,
                hash,
                output_commitments,
                input_commitments,
                kernel_excesses,
            });
            let _ = item.fees;
        }
        let is_last = scan.to >= target.scan_bounds.end_height
            || scan.blocks.last().map(|b| b.height) == Some(target.scan_bounds.end_height);
        Ok(ScanPage {
            source_identity: target.source_identity.clone(),
            target_hash: target.target_block_hash,
            start_height: start,
            end_height: scan.to,
            page_number: page,
            is_last,
            outputs: Vec::new(),
            blocks,
        })
    }

    pub fn submit_finalized(&self, transaction_bytes: &[u8]) -> Result<SubmitOutcome, ChainError> {
        if transaction_bytes.is_empty()
            || transaction_bytes.len() > MAX_HTTP_RESPONSE_BYTES as usize
        {
            return Err(ChainError::InvalidTransaction);
        }
        let url = format!("{}/tx/submit", self.base_url);
        let mut request = self
            .client
            .post(url)
            .json(&serde_json::json!({"tx_hex": hex::encode(transaction_bytes)}));
        if let Some(token) = &self.bearer_token {
            request = request.bearer_auth(token);
        }
        let response = request.send().map_err(map_http_error)?;
        let status = response.status().as_u16();
        if status == 401 || status == 403 {
            return Err(ChainError::AuthenticationFailed);
        }
        if status == 404 {
            return Err(ChainError::CapabilityUnavailable("/tx/submit".into()));
        }
        if status == 429 {
            return Err(ChainError::RateLimited);
        }
        if status == 503 {
            return Err(ChainError::Overloaded);
        }
        let body: SubmitDto = Self::decode_response(response)?;
        let tx_hash = body.tx_hash.as_deref().map(decode_hash).transpose()?;
        if body.accepted && tx_hash.is_none() {
            return Err(ChainError::MalformedResponse);
        }
        Ok(SubmitOutcome {
            accepted: body.accepted,
            relayed: body.relayed,
            tx_hash,
            warning: body.warning,
            rejection: body.error,
            status,
        })
    }
}

fn decode_transaction_lookup(
    value: serde_json::Value,
    transaction_hash: [u8; 32],
) -> Result<TransactionLookup, ChainError> {
    let is_found = value
        .get("found")
        .and_then(serde_json::Value::as_bool)
        .ok_or(ChainError::MalformedResponse)?;
    if !is_found {
        let missing: TxMissingDto =
            serde_json::from_value(value).map_err(|_| ChainError::MalformedResponse)?;
        if missing.found {
            return Err(ChainError::MalformedResponse);
        }
        return Ok(TransactionLookup {
            transaction_hash,
            in_mempool: false,
        });
    }
    let found: TxFoundDto =
        serde_json::from_value(value).map_err(|_| ChainError::MalformedResponse)?;
    let found_hash = decode_hash(&found.tx_hash).map_err(|_| ChainError::MalformedResponse)?;
    if !found.found || found_hash != transaction_hash {
        return Err(ChainError::MalformedResponse);
    }
    let _ = (found.fee, found.fee_rate, found.weight);
    Ok(TransactionLookup {
        transaction_hash,
        in_mempool: true,
    })
}

impl ChainSource for DomHttpChainSource {
    fn handshake(&mut self) -> Result<NodeHandshake, ChainError> {
        let identity = self.identity_snapshot()?;
        let tip = self.block(&identity.tip_height.to_string())?;
        if tip.height != identity.tip_height
            || decode_hash(&tip.hash)? != decode_hash(&identity.tip_hash)?
        {
            return Err(ChainError::InconsistentNode);
        }
        Ok(NodeHandshake {
            identity: self.expected.clone(),
            source_identity: self.source_identity.clone(),
            api_compatibility_version: identity.rpc_api_version,
            tip_height: identity.tip_height,
            tip_hash: decode_hash(&identity.tip_hash)?,
        })
    }
    fn hash_at_height(&mut self, height: u64) -> Result<Option<[u8; 32]>, ChainError> {
        let block = self.block(&height.to_string())?;
        if block.height != height {
            return Err(ChainError::InconsistentNode);
        }
        Ok(Some(decode_hash(&block.hash)?))
    }
    fn bounded_ancestry(
        &mut self,
        target: &ScanTarget,
        maximum_depth: u32,
    ) -> Result<bool, ChainError> {
        if maximum_depth == 0 || maximum_depth > MAX_ANCESTRY_STEPS {
            return Err(ChainError::AncestryUnavailable);
        }
        let identity = self.identity_snapshot()?;
        if identity.tip_height < target.target_height {
            return Ok(false);
        }
        let steps = identity.tip_height - target.target_height;
        if steps > maximum_depth as u64 {
            return Err(ChainError::AncestryUnavailable);
        }
        let path = format!("/chain/ancestry?ancestor_height={}&ancestor_hash={}&descendant_height={}&descendant_hash={}&max_steps={}", target.target_height, hex::encode(target.target_block_hash), identity.tip_height, identity.tip_hash, maximum_depth);
        let evidence: AncestryDto = self.request_json(&path)?;
        Ok(!evidence.is_finality_proof
            && evidence.canonical
            && evidence.ancestor_match
            && evidence.descendant_match
            && evidence.bounded
            && evidence.steps_checked == steps
            && decode_hash(&evidence.observed_ancestor_hash)? == target.target_block_hash
            && decode_hash(&evidence.observed_descendant_hash)? == decode_hash(&identity.tip_hash)?)
    }
    fn scan_page(&mut self, target: &ScanTarget, page_number: u32) -> Result<ScanPage, ChainError> {
        self.checked_scan(target, page_number)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct SubmitOutcome {
    pub accepted: bool,
    pub relayed: bool,
    pub tx_hash: Option<[u8; 32]>,
    pub warning: Option<String>,
    pub rejection: Option<String>,
    pub status: u16,
}

fn decode_hash(value: &str) -> Result<[u8; 32], ChainError> {
    let bytes = decode_lower_hex(value, 32)?;
    let hash: [u8; 32] = bytes
        .try_into()
        .map_err(|_| ChainError::MalformedResponse)?;
    if hash == [0; 32] {
        return Err(ChainError::TargetHashMissing);
    }
    Ok(hash)
}
fn decode_commitment(value: &str) -> Result<[u8; 33], ChainError> {
    decode_lower_hex(value, 33)?
        .try_into()
        .map_err(|_| ChainError::MalformedResponse)
}
fn decode_lower_hex(value: &str, expected_bytes: usize) -> Result<Vec<u8>, ChainError> {
    if value.len() != expected_bytes * 2
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(ChainError::MalformedResponse);
    }
    hex::decode(value).map_err(|_| ChainError::MalformedResponse)
}
fn has_duplicates(values: &[[u8; 33]]) -> bool {
    let mut seen = std::collections::BTreeSet::new();
    values.iter().any(|value| !seen.insert(*value))
}
fn map_http_error(error: reqwest::Error) -> ChainError {
    if error.is_timeout() {
        ChainError::Timeout
    } else {
        ChainError::Transport
    }
}

impl ChainSource for DomNodeAdapter {
    fn handshake(&mut self) -> Result<NodeHandshake, ChainError> {
        Err(ChainError::CapabilityUnavailable(
            "DOM RPC response negotiation is not configured".into(),
        ))
    }
    fn hash_at_height(&mut self, _height: u64) -> Result<Option<[u8; 32]>, ChainError> {
        Err(ChainError::CapabilityUnavailable(
            "DOM RPC hash-at-height encoding is not configured".into(),
        ))
    }
    fn bounded_ancestry(
        &mut self,
        _target: &ScanTarget,
        _maximum_depth: u32,
    ) -> Result<bool, ChainError> {
        Err(ChainError::CapabilityUnavailable(
            "DOM RPC ancestry encoding is not configured".into(),
        ))
    }
    fn scan_page(
        &mut self,
        _target: &ScanTarget,
        _page_number: u32,
    ) -> Result<ScanPage, ChainError> {
        Err(ChainError::CapabilityUnavailable(
            "DOM RPC output scan encoding is not configured".into(),
        ))
    }
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum ChainError {
    #[error("node configuration is invalid")]
    InvalidConfiguration,
    #[error("node transport failure")]
    Transport,
    #[error("node request timed out")]
    Timeout,
    #[error("node authentication failed")]
    AuthenticationFailed,
    #[error("node response is malformed")]
    MalformedResponse,
    #[error("node protocol is incompatible")]
    IncompatibleProtocol,
    #[error("node capability is missing: {0}")]
    MissingNodeCapability(String),
    #[error("node returned an unavailable capability: {0}")]
    CapabilityUnavailable(String),
    #[error("node returned HTTP status {0}")]
    HttpStatus(u16),
    #[error("node response exceeds the configured limit")]
    ResponseTooLarge,
    #[error("node rate limited the request")]
    RateLimited,
    #[error("node is overloaded")]
    Overloaded,
    #[error("node health check failed")]
    Unhealthy,
    #[error("node returned internally inconsistent evidence")]
    InconsistentNode,
    #[error("transaction bytes are invalid")]
    InvalidTransaction,
    #[error("node network, chain, or genesis identity mismatches wallet")]
    IdentityMismatch,
    #[error("source identity changed")]
    SourceChanged,
    #[error("canonical tip regressed below ScanTarget")]
    LowerTip,
    #[error("ScanTarget hash is missing")]
    TargetHashMissing,
    #[error("ScanTarget hash changed")]
    TargetHashChanged,
    #[error("bounded ancestry is unavailable")]
    AncestryUnavailable,
    #[error("scan page is inconsistent")]
    InconsistentPage,
    #[error("scan page is missing")]
    MissingPage,
    #[error("scan bounds changed")]
    ChangedBounds,
    #[error("scan page limit exceeded")]
    PageLimitExceeded,
    #[error("retry budget exhausted")]
    RetryExhausted,
    #[error("invalid ScanTarget")]
    InvalidTarget,
    #[error("invalid scan bounds")]
    InvalidBounds,
}

#[cfg(test)]
mod tests {
    use super::*;
    use dom_wallet_domain::Network;

    fn identity() -> NetworkIdentity {
        NetworkIdentity {
            network: Network::PrivateTestnet,
            chain_id: [1; 32],
            genesis_id: [2; 32],
        }
    }
    fn target(source: &mut MockChainSource) -> ScanTarget {
        acquire_target(
            source,
            &identity(),
            ScanBounds {
                start_height: 0,
                end_height: 0,
                max_pages: 2,
                max_records_per_page: 10,
            },
        )
        .unwrap()
        .1
    }

    #[test]
    fn transaction_lookup_decodes_only_exact_wallet_safe_dtos() {
        let hash = [0xabu8; 32];
        let found = serde_json::from_str(&format!(
            r#"{{"found":true,"tx_hash":"{}","fee":7,"fee_rate":1,"weight":3}}"#,
            hex::encode(hash)
        ))
        .unwrap();
        assert_eq!(
            decode_transaction_lookup(found, hash).unwrap(),
            TransactionLookup {
                transaction_hash: hash,
                in_mempool: true,
            }
        );

        assert_eq!(
            decode_transaction_lookup(serde_json::json!({"found": false}), hash).unwrap(),
            TransactionLookup {
                transaction_hash: hash,
                in_mempool: false,
            }
        );
        assert!(matches!(
            decode_transaction_lookup(
                serde_json::json!({
                    "found": true,
                    "tx_hash": hex::encode(hash),
                    "fee": 7,
                    "fee_rate": 1,
                    "weight": 3,
                    "private": "must be rejected"
                }),
                hash
            ),
            Err(ChainError::MalformedResponse)
        ));
        assert!(matches!(
            decode_transaction_lookup(
                serde_json::json!({
                    "found": true,
                    "tx_hash": "00".repeat(32),
                    "fee": 7,
                    "fee_rate": 1,
                    "weight": 3
                }),
                hash
            ),
            Err(ChainError::MalformedResponse)
        ));
    }

    #[test]
    fn same_height_divergence_and_lower_tip_fail_closed() {
        let mut source = MockChainSource::new(identity());
        source.handshake.tip_height = 1;
        source.handshake.tip_hash = [8; 32];
        source.hashes.insert(1, [8; 32]);
        source.pages[0].end_height = 1;
        source.pages[0].target_hash = [8; 32];
        let target = acquire_target(
            &mut source,
            &identity(),
            ScanBounds {
                start_height: 0,
                end_height: 1,
                max_pages: 2,
                max_records_per_page: 10,
            },
        )
        .unwrap()
        .1;
        source.hashes.insert(1, [7; 32]);
        assert_eq!(
            validate_target(&mut source, &identity(), &target, 10),
            Err(ChainError::TargetHashChanged)
        );
        source.hashes.insert(1, target.target_block_hash);
        source.handshake.tip_height = 0;
        assert_eq!(
            validate_target(&mut source, &identity(), &target, 10),
            Err(ChainError::LowerTip)
        );
    }

    #[test]
    fn scan_rejects_conflicting_page_and_reconnect_needs_stable_success() {
        let mut source = MockChainSource::new(identity());
        let target = target(&mut source);
        source.pages[0].target_hash = [3; 32];
        assert_eq!(
            collect_provisional(&mut source, &target),
            Err(ChainError::InconsistentPage)
        );
        let mut reconnect = ReconnectController::new(3, 800, 2);
        assert_eq!(reconnect.on_failure().unwrap(), 100);
        reconnect.on_success();
        assert_eq!(reconnect.failures(), 1);
        reconnect.on_success();
        assert_eq!(reconnect.failures(), 0);
    }

    #[test]
    fn duplicate_kernel_excess_is_rejected_deterministically() {
        assert!(has_duplicates(&[[7; 33], [7; 33]]));
        assert!(!has_duplicates(&[[7; 33], [8; 33]]));
    }
}
