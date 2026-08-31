use crate::model::{Digest32, EvmAddressV1, EvmFeesV1};
#[cfg(feature = "rpc-http")]
use crate::model::{ZERO_ADDRESS, ZERO_DIGEST};

/// Maximum accepted JSON-RPC response before allocation continues.
pub const MAX_RPC_RESPONSE_BYTES_V1: usize = 512 * 1024;

/// Fail-closed RPC boundary error. Endpoint strings and response bodies are
/// deliberately absent.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum EvmRpcErrorV1 {
    /// Transport failed or timed out, so externalization may be ambiguous.
    #[error("EVM RPC transport unavailable")]
    Unavailable,
    /// JSON, hex or response structure was non-canonical or contradictory.
    #[error("EVM RPC returned malformed or inconsistent data")]
    InvalidResponse,
    /// The node returned an explicit JSON-RPC error.
    #[error("EVM RPC refused the request")]
    Refused,
    /// Configured endpoint violates the transport policy.
    #[error("EVM RPC endpoint policy refused configuration")]
    InvalidEndpoint,
}

/// Evidence-bound `pending` account nonce.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RpcPendingNonceV1 {
    /// Pending account nonce.
    pub nonce: u64,
    /// Commitment to the exact successful RPC response.
    pub evidence_digest: Digest32,
}

/// Evidence-bound finalized ERC-20 allowance.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RpcAllowanceV1 {
    /// Exact allowance amount.
    pub amount: [u8; 32],
    /// Finalized block height used for the call.
    pub block_number: u64,
    /// Canonical finalized block hash.
    pub block_hash: Digest32,
    /// Commitment to the call and block responses.
    pub evidence_digest: Digest32,
}

/// Canonical finalized EVM block time used to authorize a refund.
///
/// Callers never provide a bare timestamp or boolean. Production evidence is
/// constructed from a `finalized` block response corroborated by an exact
/// block-number lookup.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RpcFinalizedTimeV1 {
    /// EIP-155 chain id corroborated in the same evidence bundle.
    pub chain_id: u64,
    /// Genesis hash corroborated in the same evidence bundle.
    pub genesis_hash: Digest32,
    /// Finalized block height.
    pub block_number: u64,
    /// Canonical finalized block hash.
    pub block_hash: Digest32,
    /// Exact `block.timestamp` of that canonical block.
    pub timestamp: u64,
    /// Commitment to both RPC responses.
    pub evidence_digest: Digest32,
}

/// Exact bounded receipt log. Scalar-bearing `data` is always redacted from
/// `Debug` output.
#[derive(Clone, Eq, PartialEq)]
pub struct RpcLogV1 {
    /// Emitting contract.
    pub address: EvmAddressV1,
    /// Indexed topics, `topic0` first.
    pub topics: Vec<Digest32>,
    /// Exact non-indexed ABI payload.
    pub data: Vec<u8>,
    /// Containing block height.
    pub block_number: u64,
    /// Containing block hash.
    pub block_hash: Digest32,
    /// Containing transaction hash.
    pub transaction_hash: Digest32,
    /// Log index within the block.
    pub log_index: u32,
    /// Whether the endpoint marks the log removed.
    pub removed: bool,
}

impl core::fmt::Debug for RpcLogV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("RpcLogV1")
            .field("address", &self.address)
            .field("topics", &self.topics)
            .field("data", &"<redacted>")
            .field("block_number", &self.block_number)
            .field("block_hash", &self.block_hash)
            .field("transaction_hash", &self.transaction_hash)
            .field("log_index", &self.log_index)
            .field("removed", &self.removed)
            .finish()
    }
}

/// Exact public transaction returned by `eth_getTransactionByHash`.
#[derive(Clone, Eq, PartialEq)]
pub struct RpcTransactionV1 {
    /// Transaction hash queried.
    pub transaction_hash: Digest32,
    /// Typed transaction chain id.
    pub chain_id: u64,
    /// Sender recovered by the node.
    pub from: EvmAddressV1,
    /// Exact destination.
    pub to: EvmAddressV1,
    /// Account nonce.
    pub nonce: u64,
    /// `msg.value`.
    pub value: [u8; 32],
    /// Gas limit.
    pub gas_limit: u64,
    /// EIP-1559 fee tuple.
    pub fees: EvmFeesV1,
    /// Exact input bytes.
    pub input: Vec<u8>,
}

impl core::fmt::Debug for RpcTransactionV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("RpcTransactionV1")
            .field("transaction_hash", &self.transaction_hash)
            .field("chain_id", &self.chain_id)
            .field("from", &self.from)
            .field("to", &self.to)
            .field("nonce", &self.nonce)
            .field("value", &self.value)
            .field("gas_limit", &self.gas_limit)
            .field("fees", &self.fees)
            .field("input", &"<redacted>")
            .finish()
    }
}

/// Evidence-bound optional transaction lookup.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RpcTransactionLookupV1 {
    /// `None` is only an observation of absence, never proof of non-broadcast.
    pub transaction: Option<RpcTransactionV1>,
    /// Commitment to the exact lookup response, including `null`.
    pub evidence_digest: Digest32,
}

/// Successful receipt and its canonical/finality status.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RpcReceiptV1 {
    /// Exact transaction identity.
    pub transaction_hash: Digest32,
    /// EIP-155 chain id corroborated with this receipt.
    pub chain_id: u64,
    /// Genesis hash corroborated with this receipt.
    pub genesis_hash: Digest32,
    /// Whether EVM execution succeeded (`status == 1`).
    pub success: bool,
    /// Included block height.
    pub block_number: u64,
    /// Included canonical block hash.
    pub block_hash: Digest32,
    /// Whether the block is at or below a corroborated finalized head.
    pub finalized: bool,
    /// Commitment to receipt, canonical-block and finalized-head responses.
    pub evidence_digest: Digest32,
    /// Exact receipt logs. A successful claim/refund is final only if one
    /// canonical log proves the expected terminal event and binding.
    pub logs: Vec<RpcLogV1>,
}

/// Evidence-bound optional receipt lookup.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RpcReceiptLookupV1 {
    /// Receipt, if currently present.
    pub receipt: Option<RpcReceiptV1>,
    /// Commitment to the exact lookup response.
    pub evidence_digest: Digest32,
}

/// Minimal production RPC authority required by the durable manager.
///
/// Implementations must not treat textual provider errors as evidence of
/// non-externalization. Test doubles belong only in test graphs.
pub trait EvmRpcV1 {
    /// Returns the endpoint chain id.
    fn chain_id(&mut self) -> core::result::Result<u64, EvmRpcErrorV1>;
    /// Returns the endpoint genesis block hash.
    fn genesis_hash(&mut self) -> core::result::Result<Digest32, EvmRpcErrorV1>;
    /// Observes the account nonce using the exact `pending` tag.
    fn pending_nonce(
        &mut self,
        account: EvmAddressV1,
    ) -> core::result::Result<RpcPendingNonceV1, EvmRpcErrorV1>;
    /// Returns runtime code hash at the finalized tag.
    fn finalized_code_hash(
        &mut self,
        address: EvmAddressV1,
    ) -> core::result::Result<(Digest32, Digest32), EvmRpcErrorV1>;
    /// Reads a finalized ERC-20 allowance.
    fn finalized_allowance(
        &mut self,
        token: EvmAddressV1,
        owner: EvmAddressV1,
        spender: EvmAddressV1,
    ) -> core::result::Result<RpcAllowanceV1, EvmRpcErrorV1>;
    /// Returns a canonical, exact and finalized block timestamp.
    fn finalized_block_time(&mut self) -> core::result::Result<RpcFinalizedTimeV1, EvmRpcErrorV1>;
    /// Sends exact persisted type-2 bytes.
    fn send_raw_transaction(
        &mut self,
        raw_transaction: &[u8],
    ) -> core::result::Result<Digest32, EvmRpcErrorV1>;
    /// Looks up one exact transaction hash.
    fn transaction_by_hash(
        &mut self,
        transaction_hash: Digest32,
    ) -> core::result::Result<RpcTransactionLookupV1, EvmRpcErrorV1>;
    /// Looks up and, when possible, corroborates receipt finality.
    fn receipt(
        &mut self,
        transaction_hash: Digest32,
    ) -> core::result::Result<RpcReceiptLookupV1, EvmRpcErrorV1>;
}

#[cfg(feature = "rpc-http")]
mod http {
    use std::io::Read;
    use std::time::Duration;

    use adapter_evm::keccak256;
    use reqwest::blocking::{Client, Response};
    use serde::de::{Error as _, MapAccess, SeqAccess, Visitor};
    use serde::{Deserialize, Deserializer};
    use serde_json::{json, Map, Value};

    use super::*;

    const MAX_ENDPOINT_BYTES: usize = 2048;
    const REQUEST_TIMEOUT_SECONDS: u64 = 20;

    /// Blocking HTTP JSON-RPC implementation with bounded responses and no
    /// credential/header persistence. Debug output always redacts the endpoint.
    pub struct HttpEvmRpcV1 {
        endpoint: reqwest::Url,
        client: Client,
        next_id: u64,
    }

    impl core::fmt::Debug for HttpEvmRpcV1 {
        fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            formatter.write_str("HttpEvmRpcV1([endpoint redacted])")
        }
    }

    impl HttpEvmRpcV1 {
        /// Constructs an HTTPS endpoint without URL userinfo, query or
        /// fragment. Provider-specific path tokens remain memory-only and are
        /// always redacted. Plain HTTP is accepted only for loopback nodes.
        pub fn new(endpoint: &str) -> core::result::Result<Self, EvmRpcErrorV1> {
            if endpoint.is_empty() || endpoint.len() > MAX_ENDPOINT_BYTES {
                return Err(EvmRpcErrorV1::InvalidEndpoint);
            }
            let parsed =
                reqwest::Url::parse(endpoint).map_err(|_| EvmRpcErrorV1::InvalidEndpoint)?;
            if !parsed.username().is_empty()
                || parsed.password().is_some()
                || parsed.query().is_some()
                || parsed.fragment().is_some()
            {
                return Err(EvmRpcErrorV1::InvalidEndpoint);
            }
            let loopback = matches!(parsed.host_str(), Some("127.0.0.1" | "localhost" | "::1"));
            if parsed.scheme() != "https" && !(parsed.scheme() == "http" && loopback) {
                return Err(EvmRpcErrorV1::InvalidEndpoint);
            }
            let client = Client::builder()
                .timeout(Duration::from_secs(REQUEST_TIMEOUT_SECONDS))
                .build()
                .map_err(|_| EvmRpcErrorV1::Unavailable)?;
            Ok(Self {
                endpoint: parsed,
                client,
                next_id: 1,
            })
        }

        fn call(
            &mut self,
            method: &str,
            params: Value,
        ) -> core::result::Result<RpcValue, EvmRpcErrorV1> {
            let id = self.next_id;
            self.next_id = self
                .next_id
                .checked_add(1)
                .ok_or(EvmRpcErrorV1::InvalidResponse)?;
            let response = self
                .client
                .post(self.endpoint.clone())
                .json(&json!({"jsonrpc":"2.0","id":id,"method":method,"params":params}))
                .send()
                .map_err(|_| EvmRpcErrorV1::Unavailable)?;
            parse_response(response, id)
        }

        fn block(&mut self, tag: &str) -> core::result::Result<BlockV1, EvmRpcErrorV1> {
            let value = self.call("eth_getBlockByNumber", json!([tag, false]))?;
            let object = value
                .value
                .as_object()
                .ok_or(EvmRpcErrorV1::InvalidResponse)?;
            Ok(BlockV1 {
                number: quantity_u64(required_string(object, "number")?)?,
                hash: hash32(required_string(object, "hash")?)?,
                evidence_digest: value.evidence_digest,
            })
        }

        fn timed_block(&mut self, tag: &str) -> core::result::Result<TimedBlockV1, EvmRpcErrorV1> {
            let value = self.call("eth_getBlockByNumber", json!([tag, false]))?;
            let object = value
                .value
                .as_object()
                .ok_or(EvmRpcErrorV1::InvalidResponse)?;
            Ok(TimedBlockV1 {
                number: quantity_u64(required_string(object, "number")?)?,
                hash: hash32(required_string(object, "hash")?)?,
                timestamp: quantity_u64(required_string(object, "timestamp")?)?,
                evidence_digest: value.evidence_digest,
            })
        }
    }

    impl EvmRpcV1 for HttpEvmRpcV1 {
        fn chain_id(&mut self) -> core::result::Result<u64, EvmRpcErrorV1> {
            let response = self.call("eth_chainId", json!([]))?;
            quantity_u64(
                response
                    .value
                    .as_str()
                    .ok_or(EvmRpcErrorV1::InvalidResponse)?,
            )
        }

        fn genesis_hash(&mut self) -> core::result::Result<Digest32, EvmRpcErrorV1> {
            Ok(self.block("0x0")?.hash)
        }

        fn pending_nonce(
            &mut self,
            account: EvmAddressV1,
        ) -> core::result::Result<RpcPendingNonceV1, EvmRpcErrorV1> {
            let response = self.call(
                "eth_getTransactionCount",
                json!([hex_address(account), "pending"]),
            )?;
            Ok(RpcPendingNonceV1 {
                nonce: quantity_u64(
                    response
                        .value
                        .as_str()
                        .ok_or(EvmRpcErrorV1::InvalidResponse)?,
                )?,
                evidence_digest: response.evidence_digest,
            })
        }

        fn finalized_code_hash(
            &mut self,
            address: EvmAddressV1,
        ) -> core::result::Result<(Digest32, Digest32), EvmRpcErrorV1> {
            let finalized = self.block("finalized")?;
            let block_tag = quantity_hex(finalized.number);
            let response = self.call("eth_getCode", json!([hex_address(address), block_tag]))?;
            let code = data_bytes(
                response
                    .value
                    .as_str()
                    .ok_or(EvmRpcErrorV1::InvalidResponse)?,
                MAX_RPC_RESPONSE_BYTES_V1,
            )?;
            if code.is_empty() {
                return Err(EvmRpcErrorV1::InvalidResponse);
            }
            let exact = self.block(&quantity_hex(finalized.number))?;
            if exact.number != finalized.number || exact.hash != finalized.hash {
                return Err(EvmRpcErrorV1::InvalidResponse);
            }
            Ok((
                keccak256(&code),
                digest_evidence(&[
                    &finalized.evidence_digest,
                    &response.evidence_digest,
                    &exact.evidence_digest,
                ]),
            ))
        }

        fn finalized_allowance(
            &mut self,
            token: EvmAddressV1,
            owner: EvmAddressV1,
            spender: EvmAddressV1,
        ) -> core::result::Result<RpcAllowanceV1, EvmRpcErrorV1> {
            if token == ZERO_ADDRESS || owner == ZERO_ADDRESS || spender == ZERO_ADDRESS {
                return Err(EvmRpcErrorV1::InvalidResponse);
            }
            let mut calldata = Vec::with_capacity(68);
            calldata.extend_from_slice(&keccak256(b"allowance(address,address)")[..4]);
            calldata.extend_from_slice(&[0; 12]);
            calldata.extend_from_slice(&owner);
            calldata.extend_from_slice(&[0; 12]);
            calldata.extend_from_slice(&spender);
            let finalized = self.block("finalized")?;
            let block_tag = quantity_hex(finalized.number);
            let call = self.call(
                "eth_call",
                json!([{"to":hex_address(token),"data":hex_data(&calldata)}, block_tag]),
            )?;
            let amount_bytes = data_bytes(
                call.value.as_str().ok_or(EvmRpcErrorV1::InvalidResponse)?,
                32,
            )?;
            if amount_bytes.len() != 32 {
                return Err(EvmRpcErrorV1::InvalidResponse);
            }
            let mut amount = [0; 32];
            amount.copy_from_slice(&amount_bytes);
            let exact = self.block(&quantity_hex(finalized.number))?;
            if exact.number != finalized.number || exact.hash != finalized.hash {
                return Err(EvmRpcErrorV1::InvalidResponse);
            }
            Ok(RpcAllowanceV1 {
                amount,
                block_number: finalized.number,
                block_hash: finalized.hash,
                evidence_digest: digest_evidence(&[
                    &finalized.evidence_digest,
                    &call.evidence_digest,
                    &exact.evidence_digest,
                ]),
            })
        }

        fn finalized_block_time(
            &mut self,
        ) -> core::result::Result<RpcFinalizedTimeV1, EvmRpcErrorV1> {
            let chain = self.call("eth_chainId", json!([]))?;
            let chain_id =
                quantity_u64(chain.value.as_str().ok_or(EvmRpcErrorV1::InvalidResponse)?)?;
            let genesis = self.block("0x0")?;
            let finalized = self.timed_block("finalized")?;
            let exact = self.timed_block(&quantity_hex(finalized.number))?;
            if finalized.number != exact.number
                || finalized.hash != exact.hash
                || finalized.timestamp != exact.timestamp
            {
                return Err(EvmRpcErrorV1::InvalidResponse);
            }
            Ok(RpcFinalizedTimeV1 {
                chain_id,
                genesis_hash: genesis.hash,
                block_number: finalized.number,
                block_hash: finalized.hash,
                timestamp: finalized.timestamp,
                evidence_digest: digest_evidence(&[
                    &chain.evidence_digest,
                    &genesis.evidence_digest,
                    &finalized.evidence_digest,
                    &exact.evidence_digest,
                ]),
            })
        }

        fn send_raw_transaction(
            &mut self,
            raw_transaction: &[u8],
        ) -> core::result::Result<Digest32, EvmRpcErrorV1> {
            if raw_transaction.first() != Some(&0x02)
                || raw_transaction.len() > crate::transaction::MAX_RAW_TRANSACTION_BYTES_V1
            {
                return Err(EvmRpcErrorV1::InvalidResponse);
            }
            let response =
                self.call("eth_sendRawTransaction", json!([hex_data(raw_transaction)]))?;
            hash32(
                response
                    .value
                    .as_str()
                    .ok_or(EvmRpcErrorV1::InvalidResponse)?,
            )
        }

        fn transaction_by_hash(
            &mut self,
            transaction_hash: Digest32,
        ) -> core::result::Result<RpcTransactionLookupV1, EvmRpcErrorV1> {
            let response = self.call(
                "eth_getTransactionByHash",
                json!([hex_hash(transaction_hash)]),
            )?;
            if response.value.is_null() {
                return Ok(RpcTransactionLookupV1 {
                    transaction: None,
                    evidence_digest: response.evidence_digest,
                });
            }
            let object = response
                .value
                .as_object()
                .ok_or(EvmRpcErrorV1::InvalidResponse)?;
            if quantity_u64(required_string(object, "type")?)? != 2 {
                return Err(EvmRpcErrorV1::InvalidResponse);
            }
            let input = data_bytes(
                required_string(object, "input")?,
                adapter_evm::abi::MAX_CALLDATA_BYTES,
            )?;
            let transaction = RpcTransactionV1 {
                transaction_hash: hash32(required_string(object, "hash")?)?,
                chain_id: quantity_u64(required_string(object, "chainId")?)?,
                from: address20(required_string(object, "from")?)?,
                to: address20(required_string(object, "to")?)?,
                nonce: quantity_u64(required_string(object, "nonce")?)?,
                value: quantity_word(required_string(object, "value")?)?,
                gas_limit: quantity_u64(required_string(object, "gas")?)?,
                fees: EvmFeesV1::new(
                    quantity_u128(required_string(object, "maxFeePerGas")?)?,
                    quantity_u128(required_string(object, "maxPriorityFeePerGas")?)?,
                )
                .map_err(|_| EvmRpcErrorV1::InvalidResponse)?,
                input,
            };
            if transaction.transaction_hash != transaction_hash {
                return Err(EvmRpcErrorV1::InvalidResponse);
            }
            Ok(RpcTransactionLookupV1 {
                transaction: Some(transaction),
                evidence_digest: response.evidence_digest,
            })
        }

        fn receipt(
            &mut self,
            transaction_hash: Digest32,
        ) -> core::result::Result<RpcReceiptLookupV1, EvmRpcErrorV1> {
            let response = self.call(
                "eth_getTransactionReceipt",
                json!([hex_hash(transaction_hash)]),
            )?;
            if response.value.is_null() {
                return Ok(RpcReceiptLookupV1 {
                    receipt: None,
                    evidence_digest: response.evidence_digest,
                });
            }
            let object = response
                .value
                .as_object()
                .ok_or(EvmRpcErrorV1::InvalidResponse)?;
            let returned_hash = hash32(required_string(object, "transactionHash")?)?;
            let block_number = quantity_u64(required_string(object, "blockNumber")?)?;
            let block_hash = hash32(required_string(object, "blockHash")?)?;
            let success = match quantity_u64(required_string(object, "status")?)? {
                0 => false,
                1 => true,
                _ => return Err(EvmRpcErrorV1::InvalidResponse),
            };
            if returned_hash != transaction_hash {
                return Err(EvmRpcErrorV1::InvalidResponse);
            }
            let chain = self.call("eth_chainId", json!([]))?;
            let chain_id =
                quantity_u64(chain.value.as_str().ok_or(EvmRpcErrorV1::InvalidResponse)?)?;
            let genesis = self.block("0x0")?;
            let log_values = object
                .get("logs")
                .and_then(Value::as_array)
                .ok_or(EvmRpcErrorV1::InvalidResponse)?;
            if log_values.len() > adapter_evm::rpc::MAX_LOGS_PER_RECEIPT {
                return Err(EvmRpcErrorV1::InvalidResponse);
            }
            let mut logs = Vec::with_capacity(log_values.len());
            for value in log_values {
                let log = value.as_object().ok_or(EvmRpcErrorV1::InvalidResponse)?;
                let topic_values = log
                    .get("topics")
                    .and_then(Value::as_array)
                    .ok_or(EvmRpcErrorV1::InvalidResponse)?;
                if topic_values.len() > adapter_evm::abi::MAX_LOG_TOPICS {
                    return Err(EvmRpcErrorV1::InvalidResponse);
                }
                let mut topics = Vec::with_capacity(topic_values.len());
                for topic in topic_values {
                    topics.push(hash32(
                        topic.as_str().ok_or(EvmRpcErrorV1::InvalidResponse)?,
                    )?);
                }
                let parsed = RpcLogV1 {
                    address: address20(required_string(log, "address")?)?,
                    topics,
                    data: data_bytes(
                        required_string(log, "data")?,
                        adapter_evm::abi::MAX_LOG_DATA_BYTES,
                    )?,
                    block_number: quantity_u64(required_string(log, "blockNumber")?)?,
                    block_hash: hash32(required_string(log, "blockHash")?)?,
                    transaction_hash: hash32(required_string(log, "transactionHash")?)?,
                    log_index: u32::try_from(quantity_u64(required_string(log, "logIndex")?)?)
                        .map_err(|_| EvmRpcErrorV1::InvalidResponse)?,
                    removed: log
                        .get("removed")
                        .and_then(Value::as_bool)
                        .ok_or(EvmRpcErrorV1::InvalidResponse)?,
                };
                if parsed.block_number != block_number
                    || parsed.block_hash != block_hash
                    || parsed.transaction_hash != transaction_hash
                {
                    return Err(EvmRpcErrorV1::InvalidResponse);
                }
                logs.push(parsed);
            }
            let finalized = self.block("finalized")?;
            let exact = self.block(&quantity_hex(block_number))?;
            if exact.number != block_number || exact.hash != block_hash {
                return Err(EvmRpcErrorV1::InvalidResponse);
            }
            let is_finalized = finalized.number >= block_number;
            let evidence_digest = digest_evidence(&[
                &response.evidence_digest,
                &chain.evidence_digest,
                &genesis.evidence_digest,
                &finalized.evidence_digest,
                &exact.evidence_digest,
            ]);
            Ok(RpcReceiptLookupV1 {
                receipt: Some(RpcReceiptV1 {
                    transaction_hash,
                    chain_id,
                    genesis_hash: genesis.hash,
                    success,
                    block_number,
                    block_hash,
                    finalized: is_finalized,
                    evidence_digest,
                    logs,
                }),
                evidence_digest,
            })
        }
    }

    struct RpcValue {
        value: Value,
        evidence_digest: Digest32,
    }

    struct BlockV1 {
        number: u64,
        hash: Digest32,
        evidence_digest: Digest32,
    }

    struct TimedBlockV1 {
        number: u64,
        hash: Digest32,
        timestamp: u64,
        evidence_digest: Digest32,
    }

    fn parse_response(
        mut response: Response,
        id: u64,
    ) -> core::result::Result<RpcValue, EvmRpcErrorV1> {
        if !response.status().is_success() {
            return Err(EvmRpcErrorV1::Unavailable);
        }
        let mut bytes = Vec::new();
        response
            .by_ref()
            .take((MAX_RPC_RESPONSE_BYTES_V1 + 1) as u64)
            .read_to_end(&mut bytes)
            .map_err(|_| EvmRpcErrorV1::Unavailable)?;
        if bytes.len() > MAX_RPC_RESPONSE_BYTES_V1 {
            return Err(EvmRpcErrorV1::InvalidResponse);
        }
        let evidence_digest = keccak256(&bytes);
        let value = serde_json::from_slice::<StrictValue>(&bytes)
            .map_err(|_| EvmRpcErrorV1::InvalidResponse)?
            .0;
        let object = value.as_object().ok_or(EvmRpcErrorV1::InvalidResponse)?;
        if object.get("jsonrpc").and_then(Value::as_str) != Some("2.0")
            || object.get("id").and_then(Value::as_u64) != Some(id)
        {
            return Err(EvmRpcErrorV1::InvalidResponse);
        }
        let has_error = object.contains_key("error");
        let has_result = object.contains_key("result");
        if object.len() != 3 || has_error == has_result {
            return Err(EvmRpcErrorV1::InvalidResponse);
        }
        if has_error {
            return Err(EvmRpcErrorV1::Refused);
        }
        let result = object
            .get("result")
            .cloned()
            .ok_or(EvmRpcErrorV1::InvalidResponse)?;
        Ok(RpcValue {
            value: result,
            evidence_digest,
        })
    }

    struct StrictValue(Value);

    impl<'de> Deserialize<'de> for StrictValue {
        fn deserialize<D>(deserializer: D) -> core::result::Result<Self, D::Error>
        where
            D: Deserializer<'de>,
        {
            deserializer.deserialize_any(StrictValueVisitor)
        }
    }

    struct StrictValueVisitor;

    impl<'de> Visitor<'de> for StrictValueVisitor {
        type Value = StrictValue;

        fn expecting(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            formatter.write_str("JSON without duplicate keys or floating-point numbers")
        }

        fn visit_bool<E>(self, value: bool) -> core::result::Result<Self::Value, E> {
            Ok(StrictValue(Value::Bool(value)))
        }

        fn visit_i64<E>(self, value: i64) -> core::result::Result<Self::Value, E> {
            Ok(StrictValue(Value::Number(value.into())))
        }

        fn visit_u64<E>(self, value: u64) -> core::result::Result<Self::Value, E> {
            Ok(StrictValue(Value::Number(value.into())))
        }

        fn visit_f64<E>(self, _value: f64) -> core::result::Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            Err(E::custom("floating-point JSON is forbidden"))
        }

        fn visit_str<E>(self, value: &str) -> core::result::Result<Self::Value, E> {
            Ok(StrictValue(Value::String(value.to_owned())))
        }

        fn visit_string<E>(self, value: String) -> core::result::Result<Self::Value, E> {
            Ok(StrictValue(Value::String(value)))
        }

        fn visit_none<E>(self) -> core::result::Result<Self::Value, E> {
            Ok(StrictValue(Value::Null))
        }

        fn visit_unit<E>(self) -> core::result::Result<Self::Value, E> {
            Ok(StrictValue(Value::Null))
        }

        fn visit_seq<A>(self, mut sequence: A) -> core::result::Result<Self::Value, A::Error>
        where
            A: SeqAccess<'de>,
        {
            let mut values = Vec::new();
            while let Some(value) = sequence.next_element::<StrictValue>()? {
                values.push(value.0);
            }
            Ok(StrictValue(Value::Array(values)))
        }

        fn visit_map<A>(self, mut map: A) -> core::result::Result<Self::Value, A::Error>
        where
            A: MapAccess<'de>,
        {
            let mut values = Map::new();
            while let Some(key) = map.next_key::<String>()? {
                if values.contains_key(&key) {
                    return Err(A::Error::custom("duplicate JSON object key"));
                }
                let value = map.next_value::<StrictValue>()?;
                values.insert(key, value.0);
            }
            Ok(StrictValue(Value::Object(values)))
        }
    }

    fn required_string<'a>(
        object: &'a Map<String, Value>,
        field: &str,
    ) -> core::result::Result<&'a str, EvmRpcErrorV1> {
        object
            .get(field)
            .and_then(Value::as_str)
            .ok_or(EvmRpcErrorV1::InvalidResponse)
    }

    fn quantity_u64(value: &str) -> core::result::Result<u64, EvmRpcErrorV1> {
        let digits = quantity_digits(value)?;
        u64::from_str_radix(digits, 16).map_err(|_| EvmRpcErrorV1::InvalidResponse)
    }

    fn quantity_u128(value: &str) -> core::result::Result<u128, EvmRpcErrorV1> {
        let digits = quantity_digits(value)?;
        u128::from_str_radix(digits, 16).map_err(|_| EvmRpcErrorV1::InvalidResponse)
    }

    fn quantity_word(value: &str) -> core::result::Result<[u8; 32], EvmRpcErrorV1> {
        let digits = quantity_digits(value)?;
        let padded = if digits.len() % 2 == 0 {
            digits.to_owned()
        } else {
            let mut value = String::with_capacity(digits.len() + 1);
            value.push('0');
            value.push_str(digits);
            value
        };
        let decoded = decode_hex(&padded, 32)?;
        let mut word = [0; 32];
        word[32 - decoded.len()..].copy_from_slice(&decoded);
        Ok(word)
    }

    fn quantity_digits(value: &str) -> core::result::Result<&str, EvmRpcErrorV1> {
        let digits = value
            .strip_prefix("0x")
            .ok_or(EvmRpcErrorV1::InvalidResponse)?;
        if digits.is_empty()
            || (digits.len() > 1 && digits.starts_with('0'))
            || !digits
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(EvmRpcErrorV1::InvalidResponse);
        }
        Ok(digits)
    }

    fn hash32(value: &str) -> core::result::Result<Digest32, EvmRpcErrorV1> {
        let bytes = fixed_hex(value, 32)?;
        let mut output = [0; 32];
        output.copy_from_slice(&bytes);
        if output == ZERO_DIGEST {
            return Err(EvmRpcErrorV1::InvalidResponse);
        }
        Ok(output)
    }

    fn address20(value: &str) -> core::result::Result<EvmAddressV1, EvmRpcErrorV1> {
        let bytes = fixed_hex(value, 20)?;
        let mut output = [0; 20];
        output.copy_from_slice(&bytes);
        if output == ZERO_ADDRESS {
            return Err(EvmRpcErrorV1::InvalidResponse);
        }
        Ok(output)
    }

    fn fixed_hex(value: &str, len: usize) -> core::result::Result<Vec<u8>, EvmRpcErrorV1> {
        let digits = value
            .strip_prefix("0x")
            .ok_or(EvmRpcErrorV1::InvalidResponse)?;
        if digits.len() != len * 2 {
            return Err(EvmRpcErrorV1::InvalidResponse);
        }
        decode_hex(digits, len)
    }

    fn data_bytes(value: &str, max: usize) -> core::result::Result<Vec<u8>, EvmRpcErrorV1> {
        let digits = value
            .strip_prefix("0x")
            .ok_or(EvmRpcErrorV1::InvalidResponse)?;
        if digits.len() % 2 != 0 || digits.len() / 2 > max {
            return Err(EvmRpcErrorV1::InvalidResponse);
        }
        decode_hex(digits, max)
    }

    fn decode_hex(digits: &str, max: usize) -> core::result::Result<Vec<u8>, EvmRpcErrorV1> {
        if digits.len() % 2 != 0
            || digits.len() / 2 > max
            || !digits
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(EvmRpcErrorV1::InvalidResponse);
        }
        let mut output = Vec::with_capacity(digits.len() / 2);
        for chunk in digits.as_bytes().chunks_exact(2) {
            let hi = nibble(chunk[0])?;
            let lo = nibble(chunk[1])?;
            output.push((hi << 4) | lo);
        }
        Ok(output)
    }

    fn nibble(value: u8) -> core::result::Result<u8, EvmRpcErrorV1> {
        match value {
            b'0'..=b'9' => Ok(value - b'0'),
            b'a'..=b'f' => Ok(value - b'a' + 10),
            _ => Err(EvmRpcErrorV1::InvalidResponse),
        }
    }

    fn hex_address(value: EvmAddressV1) -> String {
        hex_data(&value)
    }

    fn hex_hash(value: Digest32) -> String {
        hex_data(&value)
    }

    fn hex_data(bytes: &[u8]) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut output = String::with_capacity(2 + bytes.len() * 2);
        output.push_str("0x");
        for byte in bytes {
            output.push(char::from(HEX[usize::from(byte >> 4)]));
            output.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
        output
    }

    fn quantity_hex(value: u64) -> String {
        format!("0x{value:x}")
    }

    fn digest_evidence(parts: &[&[u8]]) -> Digest32 {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"DOM-INTEROP/EVM-RPC-EVIDENCE/V1\0");
        for part in parts {
            bytes.extend_from_slice(part);
        }
        keccak256(&bytes)
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn strict_json_and_hex_reject_ambiguous_encodings() {
            assert!(serde_json::from_str::<StrictValue>(
                r#"{"jsonrpc":"2.0","id":1,"result":{"hash":"0x01","hash":"0x02"}}"#
            )
            .is_err());
            assert!(serde_json::from_str::<StrictValue>(
                r#"{"jsonrpc":"2.0","id":1.0,"result":null}"#
            )
            .is_err());
            assert_eq!(quantity_u64("0x0").unwrap(), 0);
            assert!(quantity_u64("0x00").is_err());
            assert!(quantity_u64("0xA").is_err());
            assert!(quantity_u64("10").is_err());
            assert!(data_bytes("0x0", 32).is_err());
            assert!(hash32(&format!("0x{}", "00".repeat(32))).is_err());
        }

        #[test]
        fn endpoint_policy_and_debug_never_expose_endpoint() {
            assert!(matches!(
                HttpEvmRpcV1::new("http://rpc.example"),
                Err(EvmRpcErrorV1::InvalidEndpoint)
            ));
            assert!(matches!(
                HttpEvmRpcV1::new("https://user:secret@rpc.example"),
                Err(EvmRpcErrorV1::InvalidEndpoint)
            ));
            assert!(matches!(
                HttpEvmRpcV1::new("https://rpc.example/?token=secret"),
                Err(EvmRpcErrorV1::InvalidEndpoint)
            ));
            let rpc = HttpEvmRpcV1::new("http://127.0.0.1:8545").unwrap();
            let debug = format!("{rpc:?}");
            assert_eq!(debug, "HttpEvmRpcV1([endpoint redacted])");
            assert!(!debug.contains("127.0.0.1"));
        }
    }
}

#[cfg(feature = "rpc-http")]
pub use http::HttpEvmRpcV1;
