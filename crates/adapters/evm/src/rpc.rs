//! JSON-RPC boundary.
//!
//! The adapter talks to the chain exclusively through [`JsonRpc`], a two-method
//! trait. That has three consequences that matter:
//!
//! 1. the whole test suite runs offline against [`crate::mock::MockChain`],
//!    which implements the same trait deterministically;
//! 2. the real HTTP transport is optional (`rpc-http` feature) and therefore
//!    cannot be pulled into a build that does not want it;
//! 3. every RPC answer is parsed by the strict helpers in this module, which
//!    treat a missing field, a non-hex string, an over-long buffer or a
//!    non-canonical quantity as a hard failure rather than a default.
//!
//! `serde_json` is used only for the JSON-RPC envelope. It is never a
//! cryptographic wire format: everything security-relevant (binding, evidence,
//! cursor) has a hand-rolled fixed-width codec (I14).

use counterparty_api::AdapterError;
use serde_json::{json, Value};

use crate::abi::{keccak256, MAX_LOG_DATA_BYTES, MAX_LOG_TOPICS};
use crate::error::{check_cap, Result};

/// Maximum number of logs accepted from a single `eth_getLogs` page.
///
/// Checked against the JSON array length *before* anything is allocated (I14).
pub const MAX_LOGS_PER_PAGE: usize = 4096;

/// Maximum number of logs accepted inside a single transaction receipt.
///
/// Checked against the JSON array length *before* anything is allocated (I14).
///
/// A `ConditionLockV2` settlement transaction emits a handful of logs, so this
/// is a wide margin rather than a tight fit. It is also not a griefing surface:
/// the three settlement transactions (`open`, `claim`, `refund`) are sent by
/// the settlement's own parties, so no third party can pad the receipt this
/// adapter has to read.
pub const MAX_LOGS_PER_RECEIPT: usize = 1024;

/// Maximum accepted size, in bytes, of the contract bytecode returned by
/// `eth_getCode`. Real `ConditionLockV2` bytecode is a few kilobytes; the EVM
/// hard limit for deployed code is 24576 bytes (EIP-170), and this cap sits
/// just above it so a hostile endpoint cannot make the adapter allocate.
pub const MAX_CODE_BYTES: usize = 32 * 1024;

/// Maximum length of a hex quantity string, `0x` prefix included.
const MAX_QUANTITY_HEX: usize = 2 + 16;

/// A minimal, transport-agnostic JSON-RPC client.
///
/// Implementations must be side-effect free with respect to the adapter: the
/// adapter only ever issues read methods (`eth_chainId`, `eth_getCode`,
/// `eth_getBlockByNumber`, `eth_getBlockByHash`, `eth_getLogs`,
/// `eth_getTransactionReceipt`, `eth_getTransactionByHash`). It never
/// broadcasts and never signs.
pub trait JsonRpc: Send + Sync {
    /// Performs one JSON-RPC call and returns the `result` member.
    ///
    /// A transport failure, a JSON-RPC `error` object or a missing `result`
    /// must all map to [`AdapterError::AdapterUnavailable`]: the adapter treats
    /// "cannot answer" as unavailability, never as "no".
    fn call(&self, method: &str, params: Value) -> Result<Value>;
}

impl<T: JsonRpc + ?Sized> JsonRpc for &T {
    fn call(&self, method: &str, params: Value) -> Result<Value> {
        (**self).call(method, params)
    }
}

impl<T: JsonRpc + ?Sized> JsonRpc for Box<T> {
    fn call(&self, method: &str, params: Value) -> Result<Value> {
        (**self).call(method, params)
    }
}

// ---------------------------------------------------------------------------
// strict JSON helpers
// ---------------------------------------------------------------------------

/// Reads a required object member. A missing member is a failure, never a
/// default: evidence must record what was actually observed.
pub fn field<'a>(v: &'a Value, name: &str) -> Result<&'a Value> {
    v.get(name).ok_or(AdapterError::EvidenceInvalid)
}

fn as_hex_str(v: &Value) -> Result<&str> {
    let s = v.as_str().ok_or(AdapterError::EvidenceInvalid)?;
    let body = s.strip_prefix("0x").ok_or(AdapterError::EvidenceInvalid)?;
    if !body.bytes().all(|c| c.is_ascii_hexdigit()) {
        return Err(AdapterError::EvidenceInvalid);
    }
    Ok(body)
}

fn hex_nibble(c: u8) -> Result<u8> {
    match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        b'A'..=b'F' => Ok(c - b'A' + 10),
        _ => Err(AdapterError::EvidenceInvalid),
    }
}

/// Parses an Ethereum `QUANTITY` (`0x`-prefixed, big-endian) into a `u64`.
///
/// Rejects the empty body and anything wider than 64 bits. Leading zeros are
/// tolerated (some endpoints emit them) but the total length is capped first.
pub fn hex_quantity(v: &Value) -> Result<u64> {
    let s = v.as_str().ok_or(AdapterError::EvidenceInvalid)?;
    check_cap(s.len(), MAX_QUANTITY_HEX)?;
    let body = as_hex_str(v)?;
    if body.is_empty() {
        return Err(AdapterError::EvidenceInvalid);
    }
    let mut acc: u64 = 0;
    for c in body.bytes() {
        acc = acc
            .checked_mul(16)
            .ok_or(AdapterError::BoundsExceeded)?
            .checked_add(u64::from(hex_nibble(c)?))
            .ok_or(AdapterError::BoundsExceeded)?;
    }
    Ok(acc)
}

/// Parses a `0x`-prefixed byte string of arbitrary length, capped before the
/// allocation (I14).
pub fn hex_bytes(v: &Value, cap: usize) -> Result<Vec<u8>> {
    let s = v.as_str().ok_or(AdapterError::EvidenceInvalid)?;
    // Cap the *string* first: this is the check that happens before any
    // allocation proportional to attacker-controlled input.
    check_cap(s.len().saturating_sub(2) / 2, cap)?;
    let body = as_hex_str(v)?;
    if body.len() % 2 != 0 {
        return Err(AdapterError::EvidenceInvalid);
    }
    let bytes = body.as_bytes();
    let mut out = Vec::with_capacity(body.len() / 2);
    for pair in bytes.chunks_exact(2) {
        let hi = hex_nibble(pair[0])?;
        let lo = hex_nibble(pair[1])?;
        out.push((hi << 4) | lo);
    }
    Ok(out)
}

/// Parses a `0x`-prefixed 32-byte value with an exact length requirement.
pub fn hex_bytes32(v: &Value) -> Result<[u8; 32]> {
    let b = hex_bytes(v, 32)?;
    if b.len() != 32 {
        return Err(AdapterError::EvidenceInvalid);
    }
    let mut o = [0u8; 32];
    o.copy_from_slice(&b);
    Ok(o)
}

/// Parses a `0x`-prefixed 20-byte address with an exact length requirement.
pub fn hex_address(v: &Value) -> Result<[u8; 20]> {
    let b = hex_bytes(v, 20)?;
    if b.len() != 20 {
        return Err(AdapterError::EvidenceInvalid);
    }
    let mut o = [0u8; 20];
    o.copy_from_slice(&b);
    Ok(o)
}

/// Renders a `u64` as a minimal Ethereum `QUANTITY`.
pub fn quantity(v: u64) -> String {
    format!("0x{v:x}")
}

/// Renders bytes as a `0x`-prefixed lowercase hex string.
pub fn hex_of(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(2 + bytes.len() * 2);
    s.push_str("0x");
    for b in bytes {
        s.push(char::from(nibble_char(b >> 4)));
        s.push(char::from(nibble_char(b & 0x0f)));
    }
    s
}

fn nibble_char(n: u8) -> u8 {
    match n {
        0..=9 => b'0' + n,
        _ => b'a' + (n - 10),
    }
}

// ---------------------------------------------------------------------------
// typed views over RPC results
// ---------------------------------------------------------------------------

/// The subset of a block header the adapter needs.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct RpcBlockHeader {
    /// Block height.
    pub number: u64,
    /// Block hash.
    pub hash: [u8; 32],
    /// Parent block hash — the linkage a reorg breaks.
    pub parent_hash: [u8; 32],
}

impl RpcBlockHeader {
    /// Strict parse. A `null` result (unknown block / unsupported tag) is
    /// reported as `Ok(None)` so callers can distinguish "not there" from
    /// "malformed".
    pub fn parse(v: &Value) -> Result<Option<Self>> {
        if v.is_null() {
            return Ok(None);
        }
        Ok(Some(Self {
            number: hex_quantity(field(v, "number")?)?,
            hash: hex_bytes32(field(v, "hash")?)?,
            parent_hash: hex_bytes32(field(v, "parentHash")?)?,
        }))
    }
}

/// The subset of a log the adapter needs.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct RpcLog {
    /// Emitting contract.
    pub address: [u8; 20],
    /// Indexed topics, `topic0` first.
    pub topics: Vec<[u8; 32]>,
    /// Non-indexed payload.
    pub data: Vec<u8>,
    /// Height of the containing block.
    pub block_number: u64,
    /// Hash of the containing block.
    pub block_hash: [u8; 32],
    /// Hash of the containing transaction.
    pub tx_hash: [u8; 32],
    /// Position within the block.
    pub log_index: u32,
    /// Set by the endpoint when the log belongs to an orphaned block.
    pub removed: bool,
}

impl RpcLog {
    /// Strict parse. Every field is required; `removed` defaults to nothing —
    /// an absent `removed` is a malformed log, because "was this orphaned?" is
    /// exactly the question we must not guess.
    pub fn parse(v: &Value) -> Result<Self> {
        let topics_json = field(v, "topics")?
            .as_array()
            .ok_or(AdapterError::EvidenceInvalid)?;
        check_cap(topics_json.len(), MAX_LOG_TOPICS)?;
        let mut topics = Vec::with_capacity(topics_json.len());
        for t in topics_json {
            topics.push(hex_bytes32(t)?);
        }
        let log_index = hex_quantity(field(v, "logIndex")?)?;
        Ok(Self {
            address: hex_address(field(v, "address")?)?,
            topics,
            data: hex_bytes(field(v, "data")?, MAX_LOG_DATA_BYTES)?,
            block_number: hex_quantity(field(v, "blockNumber")?)?,
            block_hash: hex_bytes32(field(v, "blockHash")?)?,
            tx_hash: hex_bytes32(field(v, "transactionHash")?)?,
            log_index: u32::try_from(log_index).map_err(|_| AdapterError::BoundsExceeded)?,
            removed: field(v, "removed")?
                .as_bool()
                .ok_or(AdapterError::EvidenceInvalid)?,
        })
    }

    /// Deduplication identity: a log is uniquely located by the block it lives
    /// in, the transaction that produced it and its index.
    pub fn dedupe_key(&self) -> ([u8; 32], [u8; 32], u32) {
        (self.block_hash, self.tx_hash, self.log_index)
    }
}

/// The subset of a receipt the adapter needs.
///
/// `logs` is carried in full because a settlement is only ever accepted when
/// the log the scan saw is *also* present in the receipt the adapter fetched
/// independently: an `eth_getLogs` answer on its own proves nothing about
/// whether the transaction that supposedly produced it succeeded, or even
/// exists.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct RpcReceipt {
    /// `1` on success. Anything else means the transaction reverted.
    pub status: u64,
    /// Height of the containing block.
    pub block_number: u64,
    /// Hash of the containing block.
    pub block_hash: [u8; 32],
    /// Hash of the transaction.
    pub tx_hash: [u8; 32],
    /// Every log the transaction produced, in the order the receipt lists them.
    pub logs: Vec<RpcLog>,
}

impl RpcReceipt {
    /// Strict parse; a `null` receipt is `Ok(None)`.
    ///
    /// Pre-Byzantium receipts (no `status` field) are rejected outright: this
    /// adapter refuses to infer success from the absence of information. The
    /// `logs` member is likewise required — a receipt without it cannot answer
    /// "does this receipt contain the log I was shown?", and guessing `yes` is
    /// exactly the shortcut this module exists to prevent.
    pub fn parse(v: &Value) -> Result<Option<Self>> {
        if v.is_null() {
            return Ok(None);
        }
        let logs_json = field(v, "logs")?
            .as_array()
            .ok_or(AdapterError::EvidenceInvalid)?;
        check_cap(logs_json.len(), MAX_LOGS_PER_RECEIPT)?;
        let mut logs = Vec::with_capacity(logs_json.len());
        for l in logs_json {
            logs.push(RpcLog::parse(l)?);
        }
        Ok(Some(Self {
            status: hex_quantity(field(v, "status")?)?,
            block_number: hex_quantity(field(v, "blockNumber")?)?,
            block_hash: hex_bytes32(field(v, "blockHash")?)?,
            tx_hash: hex_bytes32(field(v, "transactionHash")?)?,
            logs,
        }))
    }

    /// The receipt's own log at `log_index`, if the receipt carries one there.
    pub fn log_at(&self, log_index: u32) -> Option<&RpcLog> {
        self.logs.iter().find(|l| l.log_index == log_index)
    }
}

/// The subset of a transaction the adapter needs.
///
/// Fetched with `eth_getTransactionByHash`, independently of the receipt, so
/// that the two can be cross-checked rather than believed one at a time.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct RpcTransaction {
    /// Transaction hash.
    pub hash: [u8; 32],
    /// Height of the containing block. `None` while the transaction is pending.
    pub block_number: Option<u64>,
    /// Hash of the containing block. `None` while the transaction is pending.
    pub block_hash: Option<[u8; 32]>,
    /// Call destination. `None` for a contract creation.
    pub to: Option<[u8; 20]>,
}

impl RpcTransaction {
    /// Strict parse; a `null` transaction is `Ok(None)`.
    ///
    /// `blockHash`, `blockNumber` and `to` are all *nullable by protocol*, so a
    /// JSON `null` is decoded as `None` and only an absent member or a
    /// malformed value is an error. A `None` in any of them is not accepted by
    /// the settlement path — see [`crate::attest`] — it simply is not a
    /// *parse* failure.
    pub fn parse(v: &Value) -> Result<Option<Self>> {
        if v.is_null() {
            return Ok(None);
        }
        let block_number = match field(v, "blockNumber")? {
            n if n.is_null() => None,
            n => Some(hex_quantity(n)?),
        };
        let block_hash = match field(v, "blockHash")? {
            h if h.is_null() => None,
            h => Some(hex_bytes32(h)?),
        };
        let to = match field(v, "to")? {
            t if t.is_null() => None,
            t => Some(hex_address(t)?),
        };
        Ok(Some(Self {
            hash: hex_bytes32(field(v, "hash")?)?,
            block_number,
            block_hash,
            to,
        }))
    }
}

/// Thin typed façade over a [`JsonRpc`].
pub struct EthClient<'r, R: JsonRpc + ?Sized> {
    rpc: &'r R,
}

impl<'r, R: JsonRpc + ?Sized> EthClient<'r, R> {
    /// Wraps a transport.
    pub fn new(rpc: &'r R) -> Self {
        Self { rpc }
    }

    /// `eth_chainId`.
    pub fn chain_id(&self) -> Result<u64> {
        let v = self.rpc.call("eth_chainId", json!([]))?;
        hex_quantity(&v)
    }

    /// `eth_getCode` at the `finalized` tag, hashed with keccak256.
    ///
    /// Reading the code at `finalized` (not `latest`) is deliberate: it means
    /// the codehash the adapter pins is the codehash of the deployment the
    /// finalized chain agrees on.
    pub fn code_hash(&self, address: &[u8; 20]) -> Result<[u8; 32]> {
        let v = self
            .rpc
            .call("eth_getCode", json!([hex_of(address), "finalized"]))?;
        let code = hex_bytes(&v, MAX_CODE_BYTES)?;
        if code.is_empty() {
            // No code at the address: there is nothing to bind to.
            return Err(AdapterError::EvidenceInvalid);
        }
        Ok(keccak256(&code))
    }

    /// `eth_getBlockByNumber(tag, false)`.
    pub fn block_by_tag(&self, tag: &str) -> Result<Option<RpcBlockHeader>> {
        let v = self.rpc.call("eth_getBlockByNumber", json!([tag, false]))?;
        RpcBlockHeader::parse(&v)
    }

    /// `eth_getBlockByNumber(height, false)`.
    pub fn block_by_number(&self, height: u64) -> Result<Option<RpcBlockHeader>> {
        let v = self
            .rpc
            .call("eth_getBlockByNumber", json!([quantity(height), false]))?;
        let h = RpcBlockHeader::parse(&v)?;
        if let Some(h) = h {
            // An endpoint that answers a height query with a different height
            // is either buggy or hostile; either way, fail closed.
            if h.number != height {
                return Err(AdapterError::EvidenceInvalid);
            }
        }
        Ok(h)
    }

    /// `eth_getBlockByHash(hash, false)`.
    ///
    /// The hash-addressed lookup, used to walk parent linkage: unlike a
    /// height-addressed one it cannot silently answer about a different chain.
    pub fn block_by_hash(&self, hash: &[u8; 32]) -> Result<Option<RpcBlockHeader>> {
        let v = self
            .rpc
            .call("eth_getBlockByHash", json!([hex_of(hash), false]))?;
        let h = RpcBlockHeader::parse(&v)?;
        if let Some(h) = h {
            // An endpoint that answers a hash query with a different hash is
            // either buggy or hostile; either way, fail closed.
            if &h.hash != hash {
                return Err(AdapterError::EvidenceInvalid);
            }
        }
        Ok(h)
    }

    /// `eth_getTransactionReceipt`, exactly as the endpoint answered it.
    ///
    /// The receipt's `transactionHash` is **not** compared against the one that
    /// was asked for. That comparison belongs to the caller, and
    /// [`crate::attest::attest_settlement_log`] makes it — reporting
    /// [`crate::error::RejectReason::ReceiptInconsistent`], which says what
    /// actually happened, rather than the flat "malformed answer" this layer
    /// would have to report. Doing it in both places left the caller's version
    /// unreachable, and an unreachable check is one no test can hold to
    /// account.
    pub fn receipt(&self, tx_hash: &[u8; 32]) -> Result<Option<RpcReceipt>> {
        let v = self
            .rpc
            .call("eth_getTransactionReceipt", json!([hex_of(tx_hash)]))?;
        RpcReceipt::parse(&v)
    }

    /// `eth_getTransactionByHash`, exactly as the endpoint answered it.
    ///
    /// As with [`Self::receipt`], identity is the caller's to check; see
    /// [`crate::error::RejectReason::TransactionInconsistent`].
    pub fn transaction(&self, tx_hash: &[u8; 32]) -> Result<Option<RpcTransaction>> {
        let v = self
            .rpc
            .call("eth_getTransactionByHash", json!([hex_of(tx_hash)]))?;
        RpcTransaction::parse(&v)
    }

    /// `eth_getLogs` over an inclusive height window, filtered by emitter and
    /// by the `topic0` alternatives given.
    ///
    /// The result array length is capped before the `Vec` is allocated.
    pub fn logs(
        &self,
        from_block: u64,
        to_block: u64,
        address: &[u8; 20],
        topic0_any_of: &[[u8; 32]],
    ) -> Result<Vec<RpcLog>> {
        if from_block > to_block {
            return Err(AdapterError::InvalidState);
        }
        let t0: Vec<Value> = topic0_any_of.iter().map(|t| json!(hex_of(t))).collect();
        let params = json!([{
            "fromBlock": quantity(from_block),
            "toBlock": quantity(to_block),
            "address": hex_of(address),
            "topics": [t0],
        }]);
        let v = self.rpc.call("eth_getLogs", params)?;
        let arr = v.as_array().ok_or(AdapterError::EvidenceInvalid)?;
        check_cap(arr.len(), MAX_LOGS_PER_PAGE)?;
        let mut out = Vec::with_capacity(arr.len());
        for l in arr {
            out.push(RpcLog::parse(l)?);
        }
        Ok(out)
    }
}

// ---------------------------------------------------------------------------
// optional real transport
// ---------------------------------------------------------------------------

#[cfg(feature = "rpc-http")]
mod http {
    use super::*;
    use core::sync::atomic::{AtomicU64, Ordering};

    /// Blocking HTTP JSON-RPC transport (feature `rpc-http`).
    ///
    /// Deliberately non-default: without this feature the crate cannot reach a
    /// network at all, which is what keeps the offline test suite honest.
    pub struct HttpJsonRpc {
        url: String,
        next_id: AtomicU64,
        timeout_secs: u64,
    }

    impl HttpJsonRpc {
        /// Builds a transport for an endpoint URL.
        ///
        /// The URL may contain an API key; it is never logged by this crate,
        /// and this type has no `Debug`.
        pub fn new(url: impl Into<String>, timeout_secs: u64) -> Self {
            Self {
                url: url.into(),
                next_id: AtomicU64::new(1),
                timeout_secs,
            }
        }
    }

    impl JsonRpc for HttpJsonRpc {
        fn call(&self, method: &str, params: Value) -> Result<Value> {
            let id = self.next_id.fetch_add(1, Ordering::Relaxed);
            let body = json!({
                "jsonrpc": "2.0",
                "id": id,
                "method": method,
                "params": params,
            });
            let agent = ureq::AgentBuilder::new()
                .timeout(core::time::Duration::from_secs(self.timeout_secs))
                .build();
            let resp = agent
                .post(&self.url)
                .set("content-type", "application/json")
                .send_json(body)
                .map_err(crate::error::unavailable)?;
            let parsed: Value = resp.into_json().map_err(crate::error::unavailable)?;
            if parsed.get("error").is_some_and(|e| !e.is_null()) {
                return Err(AdapterError::AdapterUnavailable);
            }
            match parsed.get("result") {
                Some(r) => Ok(r.clone()),
                None => Err(AdapterError::AdapterUnavailable),
            }
        }
    }
}

#[cfg(feature = "rpc-http")]
pub use http::HttpJsonRpc;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quantity_round_trips() {
        for v in [0u64, 1, 15, 16, 255, 1_000_000, u64::MAX] {
            let s = quantity(v);
            assert_eq!(hex_quantity(&json!(s)), Ok(v));
        }
    }

    #[test]
    fn quantity_rejects_garbage() {
        assert!(hex_quantity(&json!("")).is_err());
        assert!(hex_quantity(&json!("0x")).is_err());
        assert!(hex_quantity(&json!("1234")).is_err(), "missing 0x prefix");
        assert!(hex_quantity(&json!("0xzz")).is_err());
        assert!(hex_quantity(&json!(7)).is_err(), "numbers are not QUANTITY");
        assert_eq!(
            hex_quantity(&json!("0x1ffffffffffffffff")),
            Err(AdapterError::BoundsExceeded)
        );
    }

    #[test]
    fn hex_bytes_caps_before_allocating() {
        let big = format!("0x{}", "aa".repeat(64));
        assert_eq!(
            hex_bytes(&json!(big), 32),
            Err(AdapterError::BoundsExceeded)
        );
        assert!(hex_bytes(&json!(format!("0x{}", "aa".repeat(32))), 32).is_ok());
        assert!(hex_bytes(&json!("0xabc"), 32).is_err(), "odd nibble count");
    }

    #[test]
    fn hex_of_round_trips() {
        let b = [0x00u8, 0x0f, 0xf0, 0xff];
        assert_eq!(hex_of(&b), "0x000ff0ff");
        assert_eq!(hex_bytes(&json!(hex_of(&b)), 8), Ok(b.to_vec()));
        assert_eq!(hex_bytes32(&json!(hex_of(&[0x11u8; 32]))), Ok([0x11u8; 32]));
        assert_eq!(hex_address(&json!(hex_of(&[0x22u8; 20]))), Ok([0x22u8; 20]));
        assert!(hex_bytes32(&json!(hex_of(&[0x11u8; 31]))).is_err());
        assert!(hex_address(&json!(hex_of(&[0x22u8; 21]))).is_err());
    }

    #[test]
    fn header_parse_is_strict() {
        let good = json!({
            "number": "0x2a",
            "hash": hex_of(&[1u8; 32]),
            "parentHash": hex_of(&[2u8; 32]),
        });
        assert_eq!(
            RpcBlockHeader::parse(&good),
            Ok(Some(RpcBlockHeader {
                number: 42,
                hash: [1u8; 32],
                parent_hash: [2u8; 32]
            }))
        );
        assert_eq!(RpcBlockHeader::parse(&Value::Null), Ok(None));
        let missing = json!({ "number": "0x2a", "hash": hex_of(&[1u8; 32]) });
        assert_eq!(
            RpcBlockHeader::parse(&missing),
            Err(AdapterError::EvidenceInvalid)
        );
    }

    #[test]
    fn receipt_without_status_is_rejected() {
        let no_status = json!({
            "blockNumber": "0x1",
            "blockHash": hex_of(&[1u8; 32]),
            "transactionHash": hex_of(&[3u8; 32]),
            "logs": [],
        });
        assert_eq!(
            RpcReceipt::parse(&no_status),
            Err(AdapterError::EvidenceInvalid),
            "success must never be inferred from an absent field"
        );
    }

    #[test]
    fn receipt_without_logs_is_rejected() {
        // "Does this receipt contain the log I was shown?" must be answerable
        // from the receipt itself; a receipt that omits `logs` cannot answer it.
        let no_logs = json!({
            "status": "0x1",
            "blockNumber": "0x1",
            "blockHash": hex_of(&[1u8; 32]),
            "transactionHash": hex_of(&[3u8; 32]),
        });
        assert_eq!(
            RpcReceipt::parse(&no_logs),
            Err(AdapterError::EvidenceInvalid)
        );
    }

    #[test]
    fn receipt_logs_are_parsed_and_indexable() {
        let receipt = json!({
            "status": "0x1",
            "blockNumber": "0x5",
            "blockHash": hex_of(&[7u8; 32]),
            "transactionHash": hex_of(&[8u8; 32]),
            "logs": [{
                "address": hex_of(&[9u8; 20]),
                "topics": [hex_of(&[1u8; 32])],
                "data": "0x",
                "blockNumber": "0x5",
                "blockHash": hex_of(&[7u8; 32]),
                "transactionHash": hex_of(&[8u8; 32]),
                "logIndex": "0x3",
                "removed": false,
            }],
        });
        let parsed = RpcReceipt::parse(&receipt)
            .expect("valid receipt")
            .expect("present");
        assert_eq!(parsed.logs.len(), 1);
        assert!(parsed.log_at(3).is_some());
        assert!(parsed.log_at(0).is_none());
    }

    #[test]
    fn transaction_parse_is_strict_but_honours_protocol_nulls() {
        let pending = json!({
            "hash": hex_of(&[4u8; 32]),
            "blockNumber": Value::Null,
            "blockHash": Value::Null,
            "to": Value::Null,
        });
        assert_eq!(
            RpcTransaction::parse(&pending),
            Ok(Some(RpcTransaction {
                hash: [4u8; 32],
                block_number: None,
                block_hash: None,
                to: None,
            }))
        );
        assert_eq!(RpcTransaction::parse(&Value::Null), Ok(None));

        let mined = json!({
            "hash": hex_of(&[4u8; 32]),
            "blockNumber": "0x9",
            "blockHash": hex_of(&[5u8; 32]),
            "to": hex_of(&[0xC0u8; 20]),
        });
        assert_eq!(
            RpcTransaction::parse(&mined),
            Ok(Some(RpcTransaction {
                hash: [4u8; 32],
                block_number: Some(9),
                block_hash: Some([5u8; 32]),
                to: Some([0xC0u8; 20]),
            }))
        );

        let mut missing = mined;
        missing
            .as_object_mut()
            .and_then(|m| m.remove("to"))
            .expect("field present");
        assert_eq!(
            RpcTransaction::parse(&missing),
            Err(AdapterError::EvidenceInvalid),
            "an absent member is not the same as an explicit null"
        );
    }

    #[test]
    fn log_parse_requires_removed_flag_and_caps_topics() {
        let base = json!({
            "address": hex_of(&[9u8; 20]),
            "topics": [hex_of(&[1u8; 32])],
            "data": "0x",
            "blockNumber": "0x5",
            "blockHash": hex_of(&[7u8; 32]),
            "transactionHash": hex_of(&[8u8; 32]),
            "logIndex": "0x0",
            "removed": false,
        });
        let parsed = RpcLog::parse(&base).expect("valid log");
        assert_eq!(parsed.dedupe_key(), ([7u8; 32], [8u8; 32], 0));

        let mut no_removed = base.clone();
        no_removed
            .as_object_mut()
            .and_then(|m| m.remove("removed"))
            .expect("field present");
        assert_eq!(
            RpcLog::parse(&no_removed),
            Err(AdapterError::EvidenceInvalid)
        );

        let too_many = json!({
            "address": hex_of(&[9u8; 20]),
            "topics": [hex_of(&[1u8;32]), hex_of(&[1u8;32]), hex_of(&[1u8;32]),
                       hex_of(&[1u8;32]), hex_of(&[1u8;32])],
            "data": "0x",
            "blockNumber": "0x5",
            "blockHash": hex_of(&[7u8; 32]),
            "transactionHash": hex_of(&[8u8; 32]),
            "logIndex": "0x0",
            "removed": false,
        });
        assert_eq!(RpcLog::parse(&too_many), Err(AdapterError::BoundsExceeded));
    }
}
