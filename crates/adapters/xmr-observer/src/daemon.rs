//! Minimal Monero daemon RPC client.

use reqwest::Client;
use serde::{Deserialize, Serialize};

use crate::{NodeObservation, XmrNetwork, XmrObserverError, XmrTransactionStatus};

/// RPC operations required by quorum observation.
#[allow(async_fn_in_trait)]
pub trait XmrRpc: Send + Sync {
    /// Node health and canonical tip.
    async fn observe_tip(
        &self,
        expected_network: XmrNetwork,
    ) -> Result<NodeObservation, XmrObserverError>;
    /// Transaction location.
    async fn transaction_status(
        &self,
        tx_hash: [u8; 32],
    ) -> Result<XmrTransactionStatus, XmrObserverError>;
    /// Block hash at a height.
    async fn block_hash(&self, height: u64) -> Result<[u8; 32], XmrObserverError>;
}

/// HTTP Monero daemon RPC implementation.
#[derive(Clone)]
pub struct HttpXmrRpc {
    base_url: String,
    client: Client,
}

impl core::fmt::Debug for HttpXmrRpc {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("HttpXmrRpc")
            .field("base_url", &self.base_url)
            .finish()
    }
}

impl HttpXmrRpc {
    /// Creates a finite-timeout client.
    pub fn new(base_url: impl Into<String>) -> Result<Self, XmrObserverError> {
        let client = Client::builder()
            .connect_timeout(core::time::Duration::from_secs(5))
            .timeout(core::time::Duration::from_secs(20))
            .build()
            .map_err(|_| XmrObserverError::RpcTransport)?;
        Ok(Self {
            base_url: base_url.into().trim_end_matches('/').to_owned(),
            client,
        })
    }
}

#[derive(Deserialize)]
struct GetInfoResponse {
    status: String,
    synchronized: bool,
    height: u64,
    target_height: u64,
    mainnet: bool,
    stagenet: bool,
    testnet: bool,
    top_block_hash: String,
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
    txs: Vec<TransactionInfo>,
}

#[derive(Deserialize)]
struct TransactionInfo {
    block_height: Option<u64>,
    in_pool: bool,
}

#[derive(Serialize)]
struct JsonRpcRequest<T> {
    jsonrpc: &'static str,
    id: &'static str,
    method: &'static str,
    params: T,
}

#[derive(Serialize)]
struct HeightParams {
    height: u64,
}

#[derive(Deserialize)]
struct JsonRpcResponse<T> {
    result: T,
}

#[derive(Deserialize)]
struct BlockHeaderResult {
    block_header: BlockHeader,
}

#[derive(Deserialize)]
struct BlockHeader {
    hash: String,
    height: u64,
}

impl XmrRpc for HttpXmrRpc {
    async fn observe_tip(
        &self,
        expected_network: XmrNetwork,
    ) -> Result<NodeObservation, XmrObserverError> {
        let response = self
            .client
            .get(format!("{}/get_info", self.base_url))
            .send()
            .await
            .map_err(|_| XmrObserverError::RpcTransport)?;
        if !response.status().is_success() {
            return Err(XmrObserverError::RpcTransport);
        }
        let info = response
            .json::<GetInfoResponse>()
            .await
            .map_err(|_| XmrObserverError::MalformedResponse)?;
        if info.status != "OK" {
            return Err(XmrObserverError::MalformedResponse);
        }
        let network = decode_network(info.mainnet, info.stagenet, info.testnet)?;
        if network != expected_network {
            return Err(XmrObserverError::WrongNetwork);
        }
        if !info.synchronized {
            return Err(XmrObserverError::NotSynchronized);
        }
        let tip_height = info
            .height
            .checked_sub(1)
            .ok_or(XmrObserverError::MalformedResponse)?;
        Ok(NodeObservation {
            node: self.base_url.clone(),
            network,
            synchronized: true,
            tip_height,
            target_height: info.target_height,
            top_hash: parse_hash(&info.top_block_hash)?,
        })
    }

    async fn transaction_status(
        &self,
        tx_hash: [u8; 32],
    ) -> Result<XmrTransactionStatus, XmrObserverError> {
        let encoded = hex_lower(&tx_hash);
        let response = self
            .client
            .post(format!("{}/get_transactions", self.base_url))
            .json(&GetTransactionsRequest {
                txs_hashes: vec![encoded.clone()],
                decode_as_json: false,
            })
            .send()
            .await
            .map_err(|_| XmrObserverError::RpcTransport)?;
        if !response.status().is_success() {
            return Err(XmrObserverError::RpcTransport);
        }
        let body = response
            .json::<GetTransactionsResponse>()
            .await
            .map_err(|_| XmrObserverError::MalformedResponse)?;
        if body.missed_tx.iter().any(|value| value == &encoded) {
            return Ok(XmrTransactionStatus::Unseen);
        }
        if body.txs.len() != 1 {
            return Err(XmrObserverError::MalformedResponse);
        }
        let transaction = &body.txs[0];
        if transaction.in_pool {
            if transaction.block_height.is_some() {
                return Err(XmrObserverError::MalformedResponse);
            }
            return Ok(XmrTransactionStatus::InPool);
        }
        Ok(XmrTransactionStatus::InBlock {
            block_height: transaction
                .block_height
                .ok_or(XmrObserverError::MalformedResponse)?,
        })
    }

    async fn block_hash(&self, height: u64) -> Result<[u8; 32], XmrObserverError> {
        let response = self
            .client
            .post(format!("{}/json_rpc", self.base_url))
            .json(&JsonRpcRequest {
                jsonrpc: "2.0",
                id: "0",
                method: "get_block_header_by_height",
                params: HeightParams { height },
            })
            .send()
            .await
            .map_err(|_| XmrObserverError::RpcTransport)?;
        if !response.status().is_success() {
            return Err(XmrObserverError::RpcTransport);
        }
        let body = response
            .json::<JsonRpcResponse<BlockHeaderResult>>()
            .await
            .map_err(|_| XmrObserverError::MalformedResponse)?;
        if body.result.block_header.height != height {
            return Err(XmrObserverError::MalformedResponse);
        }
        parse_hash(&body.result.block_header.hash)
    }
}

fn decode_network(
    mainnet: bool,
    stagenet: bool,
    testnet: bool,
) -> Result<XmrNetwork, XmrObserverError> {
    match (mainnet, stagenet, testnet) {
        (true, false, false) => Ok(XmrNetwork::Mainnet),
        (false, true, false) => Ok(XmrNetwork::Stagenet),
        (false, false, true) => Ok(XmrNetwork::Testnet),
        _ => Err(XmrObserverError::MalformedResponse),
    }
}

fn parse_hash(encoded: &str) -> Result<[u8; 32], XmrObserverError> {
    if encoded.len() != 64 {
        return Err(XmrObserverError::MalformedResponse);
    }
    let mut output = [0_u8; 32];
    for (index, byte) in output.iter_mut().enumerate() {
        let start = index * 2;
        *byte = u8::from_str_radix(&encoded[start..start + 2], 16)
            .map_err(|_| XmrObserverError::MalformedResponse)?;
    }
    if output == [0; 32] {
        return Err(XmrObserverError::MalformedResponse);
    }
    Ok(output)
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
