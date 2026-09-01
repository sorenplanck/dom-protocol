//! Exact-byte monerod broadcaster with ambiguous-response reconciliation.

#![forbid(unsafe_code)]

use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};
use xmr_raw_tx_verify::verify_exact_raw_transaction;
use xmr_spend_port::{BroadcastAcceptance, ExactBroadcastPort, SpendPortError};

/// Direct loopback monerod broadcaster.
pub struct BlockingMoneroBroadcaster {
    base_url: String,
    client: Client,
}

impl core::fmt::Debug for BlockingMoneroBroadcaster {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("BlockingMoneroBroadcaster")
            .field("base_url", &self.base_url)
            .finish()
    }
}

impl BlockingMoneroBroadcaster {
    /// Creates a finite-timeout loopback client.
    pub fn new(base_url: impl Into<String>) -> Result<Self, SpendPortError> {
        let base_url = base_url.into().trim_end_matches('/').to_owned();
        if !(base_url.starts_with("http://127.0.0.1:")
            || base_url.starts_with("http://localhost:")
            || base_url.starts_with("http://[::1]:"))
        {
            return Err(SpendPortError::Rejected);
        }
        let client = Client::builder()
            .connect_timeout(core::time::Duration::from_secs(5))
            .timeout(core::time::Duration::from_secs(30))
            .build()
            .map_err(|_| SpendPortError::Retryable)?;
        Ok(Self { base_url, client })
    }

    fn transaction_is_known(&self, tx_hash: [u8; 32]) -> Result<bool, SpendPortError> {
        let response = self
            .client
            .post(format!("{}/get_transactions", self.base_url))
            .json(&GetTransactionsRequest {
                txs_hashes: vec![hex_lower(&tx_hash)],
                decode_as_json: false,
            })
            .send()
            .map_err(|_| SpendPortError::Retryable)?;
        if !response.status().is_success() {
            return Err(SpendPortError::Retryable);
        }
        let body = response
            .json::<GetTransactionsResponse>()
            .map_err(|_| SpendPortError::Retryable)?;
        if body
            .missed_tx
            .iter()
            .any(|value| value == &hex_lower(&tx_hash))
        {
            return Ok(false);
        }
        Ok(!body.txs.is_empty())
    }
}

impl ExactBroadcastPort for BlockingMoneroBroadcaster {
    fn submit_exact(
        &mut self,
        tx_hash: [u8; 32],
        raw_tx: &[u8],
    ) -> Result<BroadcastAcceptance, SpendPortError> {
        if tx_hash == [0; 32] || raw_tx.is_empty() {
            return Err(SpendPortError::Rejected);
        }
        // Re-verify the exact bytes against the expected consensus hash before
        // they reach the network. The delivery journal persists bytes and the
        // broadcaster is a separate step, so this guards against a corrupt or
        // substituted record just as the sidecar check guards the response.
        verify_exact_raw_transaction(raw_tx, tx_hash).map_err(|_| SpendPortError::Rejected)?;
        let result = self
            .client
            .post(format!("{}/send_raw_transaction", self.base_url))
            .json(&SendRawTransactionRequest {
                tx_as_hex: hex_lower(raw_tx),
                do_not_relay: false,
            })
            .send();
        let response = match result {
            Ok(value) => value,
            Err(_) => {
                return if self.transaction_is_known(tx_hash)? {
                    Ok(BroadcastAcceptance::AlreadyKnown)
                } else {
                    Err(SpendPortError::Retryable)
                };
            }
        };
        if !response.status().is_success() {
            return if self.transaction_is_known(tx_hash)? {
                Ok(BroadcastAcceptance::AlreadyKnown)
            } else if response.status().is_server_error() || response.status().as_u16() == 429 {
                Err(SpendPortError::Retryable)
            } else {
                Err(SpendPortError::Rejected)
            };
        }
        let body = response
            .json::<SendRawTransactionResponse>()
            .map_err(|_| SpendPortError::Retryable)?;
        if body.status == "OK" && !body.permanent_rejection() {
            return Ok(BroadcastAcceptance::Accepted);
        }
        if self.transaction_is_known(tx_hash)? {
            Ok(BroadcastAcceptance::AlreadyKnown)
        } else if body.busy || body.not_relayed {
            Err(SpendPortError::Retryable)
        } else {
            Err(SpendPortError::Rejected)
        }
    }
}

/// Read-only loopback monerod reader for reconciliation and observation.
///
/// Same endpoint policy as the broadcaster: loopback only, finite timeouts.
/// Every answer is a single daemon's view; quorum assembly is the caller's
/// job, never this client's.
pub struct BlockingMoneroDaemonReaderV1 {
    base_url: String,
    client: Client,
}

impl core::fmt::Debug for BlockingMoneroDaemonReaderV1 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("BlockingMoneroDaemonReaderV1")
            .field("base_url", &self.base_url)
            .finish()
    }
}

/// One daemon's answer about an exact txid.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MoneroTransactionLocationV1 {
    /// Still in the transaction pool.
    pub in_pool: bool,
    /// Inclusion height when mined.
    pub block_height: Option<u64>,
}

impl BlockingMoneroDaemonReaderV1 {
    /// Creates a finite-timeout loopback reader.
    pub fn new(base_url: impl Into<String>) -> Result<Self, SpendPortError> {
        let base_url = base_url.into().trim_end_matches('/').to_owned();
        if !(base_url.starts_with("http://127.0.0.1:")
            || base_url.starts_with("http://localhost:")
            || base_url.starts_with("http://[::1]:"))
        {
            return Err(SpendPortError::Rejected);
        }
        let client = Client::builder()
            .connect_timeout(core::time::Duration::from_secs(5))
            .timeout(core::time::Duration::from_secs(30))
            .build()
            .map_err(|_| SpendPortError::Retryable)?;
        Ok(Self { base_url, client })
    }

    /// Where the daemon sees an exact txid, `None` when unknown to it.
    pub fn transaction_location(
        &self,
        tx_hash: [u8; 32],
    ) -> Result<Option<MoneroTransactionLocationV1>, SpendPortError> {
        let wanted = hex_lower(&tx_hash);
        let response = self
            .client
            .post(format!("{}/get_transactions", self.base_url))
            .json(&GetTransactionsRequest {
                txs_hashes: vec![wanted.clone()],
                decode_as_json: false,
            })
            .send()
            .map_err(|_| SpendPortError::Retryable)?;
        if !response.status().is_success() {
            return Err(SpendPortError::Retryable);
        }
        let body = response
            .json::<GetTransactionsLocationResponse>()
            .map_err(|_| SpendPortError::Retryable)?;
        if body.missed_tx.iter().any(|value| value == &wanted) {
            return Ok(None);
        }
        let Some(entry) = body.txs.first() else {
            return Ok(None);
        };
        if entry.tx_hash != wanted {
            return Err(SpendPortError::Retryable);
        }
        Ok(Some(MoneroTransactionLocationV1 {
            in_pool: entry.in_pool,
            block_height: (!entry.in_pool).then_some(entry.block_height),
        }))
    }

    /// The daemon's current chain height.
    pub fn daemon_height(&self) -> Result<u64, SpendPortError> {
        let response = self
            .client
            .get(format!("{}/get_height", self.base_url))
            .send()
            .map_err(|_| SpendPortError::Retryable)?;
        if !response.status().is_success() {
            return Err(SpendPortError::Retryable);
        }
        let body = response
            .json::<GetHeightResponse>()
            .map_err(|_| SpendPortError::Retryable)?;
        if body.height == 0 {
            return Err(SpendPortError::Retryable);
        }
        Ok(body.height)
    }

    /// The canonical block hash at one height, from the daemon's chain view.
    pub fn block_hash_at(&self, height: u64) -> Result<[u8; 32], SpendPortError> {
        let response = self
            .client
            .post(format!("{}/json_rpc", self.base_url))
            .json(&serde_json::json!({
                "jsonrpc": "2.0",
                "id": "0",
                "method": "get_block_header_by_height",
                "params": { "height": height },
            }))
            .send()
            .map_err(|_| SpendPortError::Retryable)?;
        if !response.status().is_success() {
            return Err(SpendPortError::Retryable);
        }
        let body = response
            .json::<serde_json::Value>()
            .map_err(|_| SpendPortError::Retryable)?;
        let hash = body
            .get("result")
            .and_then(|result| result.get("block_header"))
            .and_then(|header| header.get("hash"))
            .and_then(serde_json::Value::as_str)
            .ok_or(SpendPortError::Retryable)?;
        decode_hex_32(hash).ok_or(SpendPortError::Retryable)
    }

    /// Whether the exact key image is spent in the daemon's view (chain or
    /// pool alike: either way the shared output is contested).
    pub fn key_image_spent(&self, key_image: [u8; 32]) -> Result<bool, SpendPortError> {
        let response = self
            .client
            .post(format!("{}/is_key_image_spent", self.base_url))
            .json(&IsKeyImageSpentRequest {
                key_images: vec![hex_lower(&key_image)],
            })
            .send()
            .map_err(|_| SpendPortError::Retryable)?;
        if !response.status().is_success() {
            return Err(SpendPortError::Retryable);
        }
        let body = response
            .json::<IsKeyImageSpentResponse>()
            .map_err(|_| SpendPortError::Retryable)?;
        match body.spent_status.as_slice() {
            [0] => Ok(false),
            [1] | [2] => Ok(true),
            _ => Err(SpendPortError::Retryable),
        }
    }
}

#[derive(Serialize)]
struct IsKeyImageSpentRequest {
    key_images: Vec<String>,
}

#[derive(Deserialize)]
struct IsKeyImageSpentResponse {
    #[serde(default)]
    spent_status: Vec<u8>,
}

#[derive(Deserialize)]
struct GetHeightResponse {
    #[serde(default)]
    height: u64,
}

#[derive(Deserialize)]
struct GetTransactionsLocationResponse {
    #[serde(default)]
    missed_tx: Vec<String>,
    #[serde(default)]
    txs: Vec<TransactionLocationEntry>,
}

#[derive(Deserialize)]
struct TransactionLocationEntry {
    #[serde(default)]
    tx_hash: String,
    #[serde(default)]
    in_pool: bool,
    #[serde(default)]
    block_height: u64,
}

fn decode_hex_32(value: &str) -> Option<[u8; 32]> {
    let bytes = value.as_bytes();
    if bytes.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (index, chunk) in bytes.chunks_exact(2).enumerate() {
        let high = (chunk[0] as char).to_digit(16)?;
        let low = (chunk[1] as char).to_digit(16)?;
        out[index] = u8::try_from(high * 16 + low).ok()?;
    }
    Some(out)
}

#[derive(Serialize)]
struct SendRawTransactionRequest {
    tx_as_hex: String,
    do_not_relay: bool,
}

#[derive(Deserialize)]
struct SendRawTransactionResponse {
    status: String,
    #[serde(default)]
    busy: bool,
    #[serde(default)]
    not_relayed: bool,
    #[serde(default)]
    double_spend: bool,
    #[serde(default)]
    fee_too_low: bool,
    #[serde(default)]
    invalid_input: bool,
    #[serde(default)]
    invalid_output: bool,
    #[serde(default)]
    low_mixin: bool,
    #[serde(default)]
    not_rct: bool,
    #[serde(default)]
    overspend: bool,
    #[serde(default)]
    too_big: bool,
}

impl SendRawTransactionResponse {
    fn permanent_rejection(&self) -> bool {
        self.double_spend
            || self.fee_too_low
            || self.invalid_input
            || self.invalid_output
            || self.low_mixin
            || self.not_rct
            || self.overspend
            || self.too_big
    }
}

#[derive(Serialize)]
struct GetTransactionsRequest {
    txs_hashes: Vec<String>,
    decode_as_json: bool,
}
#[derive(Deserialize)]
struct GetTransactionsResponse {
    #[serde(default)]
    missed_tx: Vec<String>,
    #[serde(default)]
    txs: Vec<serde::de::IgnoredAny>,
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bytes_that_do_not_match_the_expected_hash_never_reach_the_network() {
        // The base URL is unroutable, so any network attempt surfaces as
        // Retryable. A Rejected verdict therefore proves the bytes were refused
        // by the independent raw-transaction check before the broadcaster ever
        // opened a connection.
        let mut broadcaster =
            BlockingMoneroBroadcaster::new("http://127.0.0.1:1").expect("construct");
        assert_eq!(
            broadcaster
                .submit_exact([0x42; 32], b"not a monero transaction")
                .unwrap_err(),
            SpendPortError::Rejected
        );
    }

    #[test]
    fn zero_hash_or_empty_bytes_are_refused() {
        let mut broadcaster =
            BlockingMoneroBroadcaster::new("http://127.0.0.1:1").expect("construct");
        assert_eq!(
            broadcaster.submit_exact([0; 32], b"x").unwrap_err(),
            SpendPortError::Rejected
        );
        assert_eq!(
            broadcaster.submit_exact([1; 32], b"").unwrap_err(),
            SpendPortError::Rejected
        );
    }
}
