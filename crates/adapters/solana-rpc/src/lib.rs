//! Bounded blocking JSON-RPC client for Solana observation and delivery.

#![forbid(unsafe_code)]

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use reqwest::blocking::Client;
use serde_json::{json, Value};
use solana_types::{
    Commitment, SolanaAccountSnapshot, SolanaBlockAnchor, SolanaCompiledInstruction, SolanaHash,
    SolanaPubkey, SolanaSignature, SolanaSignatureStatus, SolanaTransactionRecord,
};
use std::time::Duration;

pub const MAX_ACCOUNT_DATA_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_TRANSACTION_INSTRUCTIONS: usize = 256;
pub const MAX_TRANSACTION_ACCOUNTS: usize = 256;
pub const MAX_RPC_RESPONSE_BYTES: usize = 8 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RpcError {
    #[error("Solana RPC unavailable")]
    Unavailable,
    #[error("Solana RPC returned an error")]
    Remote,
    #[error("Solana RPC returned malformed or oversized data")]
    InvalidResponse,
    #[error("Solana RPC value was not found")]
    NotFound,
    #[error("signed transaction exceeds configured bound")]
    BoundsExceeded,
}

/// Minimal RPC surface consumed by the quorum and observer layers.
pub trait SolanaRpc: Send + Sync {
    fn get_slot(&self, commitment: Commitment) -> Result<u64, RpcError>;
    fn get_block_anchor(&self, slot: u64) -> Result<Option<SolanaBlockAnchor>, RpcError>;
    fn get_account(
        &self,
        key: SolanaPubkey,
        commitment: Commitment,
    ) -> Result<Option<SolanaAccountSnapshot>, RpcError>;
    fn get_signature_status(
        &self,
        signature: SolanaSignature,
    ) -> Result<Option<SolanaSignatureStatus>, RpcError>;
    fn get_transaction(
        &self,
        signature: SolanaSignature,
        commitment: Commitment,
    ) -> Result<Option<SolanaTransactionRecord>, RpcError>;
    fn get_latest_blockhash(&self) -> Result<SolanaHash, RpcError>;
    fn send_transaction(&self, raw_transaction: &[u8]) -> Result<SolanaSignature, RpcError>;
}

#[derive(Clone)]
pub struct HttpSolanaRpc {
    url: String,
    client: Client,
    max_signed_transaction_bytes: usize,
}

impl core::fmt::Debug for HttpSolanaRpc {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("HttpSolanaRpc")
            .field("url", &self.url)
            .field(
                "max_signed_transaction_bytes",
                &self.max_signed_transaction_bytes,
            )
            .finish()
    }
}

impl HttpSolanaRpc {
    pub fn new(
        url: impl Into<String>,
        max_signed_transaction_bytes: usize,
    ) -> Result<Self, RpcError> {
        if max_signed_transaction_bytes == 0 || max_signed_transaction_bytes > 16 * 1024 {
            return Err(RpcError::BoundsExceeded);
        }
        let client = Client::builder()
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(|_| RpcError::Unavailable)?;
        Ok(Self {
            url: url.into(),
            client,
            max_signed_transaction_bytes,
        })
    }

    fn call(&self, method: &str, params: Value) -> Result<Value, RpcError> {
        let response = self
            .client
            .post(&self.url)
            .json(&json!({"jsonrpc":"2.0","id":1,"method":method,"params":params}))
            .send()
            .map_err(|_| RpcError::Unavailable)?;
        if !response.status().is_success() {
            return Err(RpcError::Unavailable);
        }
        let bytes = response.bytes().map_err(|_| RpcError::Unavailable)?;
        if bytes.len() > MAX_RPC_RESPONSE_BYTES {
            return Err(RpcError::InvalidResponse);
        }
        let value: Value = serde_json::from_slice(&bytes).map_err(|_| RpcError::InvalidResponse)?;
        if value.get("error").is_some() {
            return Err(RpcError::Remote);
        }
        value
            .get("result")
            .cloned()
            .ok_or(RpcError::InvalidResponse)
    }
}

impl SolanaRpc for HttpSolanaRpc {
    fn get_slot(&self, commitment: Commitment) -> Result<u64, RpcError> {
        self.call("getSlot", json!([{"commitment": commitment.as_rpc_str()}]))?
            .as_u64()
            .ok_or(RpcError::InvalidResponse)
    }

    fn get_block_anchor(&self, slot: u64) -> Result<Option<SolanaBlockAnchor>, RpcError> {
        let result = self.call(
            "getBlock",
            json!([slot, {
                "commitment":"finalized", "transactionDetails":"none", "rewards":false,
                "maxSupportedTransactionVersion":0
            }]),
        )?;
        if result.is_null() {
            return Ok(None);
        }
        let blockhash = result
            .get("blockhash")
            .and_then(Value::as_str)
            .ok_or(RpcError::InvalidResponse)?;
        Ok(Some(SolanaBlockAnchor {
            slot,
            blockhash: SolanaHash::from_base58(blockhash).map_err(|_| RpcError::InvalidResponse)?,
        }))
    }

    fn get_account(
        &self,
        key: SolanaPubkey,
        commitment: Commitment,
    ) -> Result<Option<SolanaAccountSnapshot>, RpcError> {
        let result = self.call(
            "getAccountInfo",
            json!([
                key.to_base58(), {"commitment":commitment.as_rpc_str(),"encoding":"base64"}
            ]),
        )?;
        let context_slot = result
            .get("context")
            .and_then(|v| v.get("slot"))
            .and_then(Value::as_u64)
            .ok_or(RpcError::InvalidResponse)?;
        let Some(value) = result.get("value") else {
            return Err(RpcError::InvalidResponse);
        };
        if value.is_null() {
            return Ok(None);
        }
        let lamports = value
            .get("lamports")
            .and_then(Value::as_u64)
            .ok_or(RpcError::InvalidResponse)?;
        let owner = SolanaPubkey::from_base58(
            value
                .get("owner")
                .and_then(Value::as_str)
                .ok_or(RpcError::InvalidResponse)?,
        )
        .map_err(|_| RpcError::InvalidResponse)?;
        let executable = value
            .get("executable")
            .and_then(Value::as_bool)
            .ok_or(RpcError::InvalidResponse)?;
        let rent_epoch = value.get("rentEpoch").and_then(Value::as_u64).unwrap_or(0);
        let data_array = value
            .get("data")
            .and_then(Value::as_array)
            .ok_or(RpcError::InvalidResponse)?;
        let encoded = data_array
            .first()
            .and_then(Value::as_str)
            .ok_or(RpcError::InvalidResponse)?;
        let data = BASE64
            .decode(encoded)
            .map_err(|_| RpcError::InvalidResponse)?;
        if data.len() > MAX_ACCOUNT_DATA_BYTES {
            return Err(RpcError::InvalidResponse);
        }
        Ok(Some(SolanaAccountSnapshot {
            context_slot,
            lamports,
            owner,
            executable,
            rent_epoch,
            data,
        }))
    }

    fn get_signature_status(
        &self,
        signature: SolanaSignature,
    ) -> Result<Option<SolanaSignatureStatus>, RpcError> {
        let result = self.call(
            "getSignatureStatuses",
            json!([
                [signature.to_base58()], {"searchTransactionHistory":true}
            ]),
        )?;
        let value = result
            .get("value")
            .and_then(Value::as_array)
            .and_then(|values| values.first())
            .ok_or(RpcError::InvalidResponse)?;
        if value.is_null() {
            return Ok(None);
        }
        let slot = value
            .get("slot")
            .and_then(Value::as_u64)
            .ok_or(RpcError::InvalidResponse)?;
        let confirmation = match value.get("confirmationStatus").and_then(Value::as_str) {
            Some("processed") => Commitment::Processed,
            Some("confirmed") => Commitment::Confirmed,
            Some("finalized") => Commitment::Finalized,
            _ => return Err(RpcError::InvalidResponse),
        };
        Ok(Some(SolanaSignatureStatus {
            slot,
            confirmation,
            failed: !value.get("err").unwrap_or(&Value::Null).is_null(),
        }))
    }

    fn get_transaction(
        &self,
        signature: SolanaSignature,
        commitment: Commitment,
    ) -> Result<Option<SolanaTransactionRecord>, RpcError> {
        let result = self.call("getTransaction", json!([
            signature.to_base58(), {"commitment":commitment.as_rpc_str(),"encoding":"json","maxSupportedTransactionVersion":0}
        ]))?;
        if result.is_null() {
            return Ok(None);
        }
        let slot = result
            .get("slot")
            .and_then(Value::as_u64)
            .ok_or(RpcError::InvalidResponse)?;
        let success = result
            .get("meta")
            .and_then(|v| v.get("err"))
            .map(Value::is_null)
            .unwrap_or(false);
        let message = result
            .get("transaction")
            .and_then(|v| v.get("message"))
            .ok_or(RpcError::InvalidResponse)?;
        let recent_blockhash = SolanaHash::from_base58(
            message
                .get("recentBlockhash")
                .and_then(Value::as_str)
                .ok_or(RpcError::InvalidResponse)?,
        )
        .map_err(|_| RpcError::InvalidResponse)?;
        let keys = parse_account_keys(
            message
                .get("accountKeys")
                .and_then(Value::as_array)
                .ok_or(RpcError::InvalidResponse)?,
        )?;
        if keys.len() > MAX_TRANSACTION_ACCOUNTS {
            return Err(RpcError::InvalidResponse);
        }
        let raw_instructions = message
            .get("instructions")
            .and_then(Value::as_array)
            .ok_or(RpcError::InvalidResponse)?;
        if raw_instructions.len() > MAX_TRANSACTION_INSTRUCTIONS {
            return Err(RpcError::InvalidResponse);
        }
        let mut instructions = Vec::with_capacity(raw_instructions.len());
        for raw in raw_instructions {
            let program_index = raw
                .get("programIdIndex")
                .and_then(Value::as_u64)
                .and_then(|v| usize::try_from(v).ok())
                .ok_or(RpcError::InvalidResponse)?;
            let program_id = *keys.get(program_index).ok_or(RpcError::InvalidResponse)?;
            let account_indices = raw
                .get("accounts")
                .and_then(Value::as_array)
                .ok_or(RpcError::InvalidResponse)?;
            let mut accounts = Vec::with_capacity(account_indices.len());
            for index in account_indices {
                let index = index
                    .as_u64()
                    .and_then(|v| usize::try_from(v).ok())
                    .ok_or(RpcError::InvalidResponse)?;
                accounts.push(*keys.get(index).ok_or(RpcError::InvalidResponse)?);
            }
            let data = bs58::decode(
                raw.get("data")
                    .and_then(Value::as_str)
                    .ok_or(RpcError::InvalidResponse)?,
            )
            .into_vec()
            .map_err(|_| RpcError::InvalidResponse)?;
            instructions.push(SolanaCompiledInstruction {
                program_id,
                accounts,
                data,
            });
        }
        Ok(Some(SolanaTransactionRecord {
            slot,
            signature,
            recent_blockhash,
            success,
            instructions,
        }))
    }

    fn get_latest_blockhash(&self) -> Result<SolanaHash, RpcError> {
        let result = self.call("getLatestBlockhash", json!([{"commitment":"finalized"}]))?;
        let hash = result
            .get("value")
            .and_then(|v| v.get("blockhash"))
            .and_then(Value::as_str)
            .ok_or(RpcError::InvalidResponse)?;
        SolanaHash::from_base58(hash).map_err(|_| RpcError::InvalidResponse)
    }

    fn send_transaction(&self, raw_transaction: &[u8]) -> Result<SolanaSignature, RpcError> {
        if raw_transaction.is_empty() || raw_transaction.len() > self.max_signed_transaction_bytes {
            return Err(RpcError::BoundsExceeded);
        }
        let encoded = BASE64.encode(raw_transaction);
        let result = self.call(
            "sendTransaction",
            json!([encoded, {
                "encoding":"base64", "skipPreflight":false,
                "preflightCommitment":"confirmed", "maxRetries":5
            }]),
        )?;
        SolanaSignature::from_base58(result.as_str().ok_or(RpcError::InvalidResponse)?)
            .map_err(|_| RpcError::InvalidResponse)
    }
}

fn parse_account_keys(values: &[Value]) -> Result<Vec<SolanaPubkey>, RpcError> {
    values
        .iter()
        .map(|value| {
            let text = value
                .as_str()
                .or_else(|| value.get("pubkey").and_then(Value::as_str))
                .ok_or(RpcError::InvalidResponse)?;
            SolanaPubkey::from_base58(text).map_err(|_| RpcError::InvalidResponse)
        })
        .collect()
}
