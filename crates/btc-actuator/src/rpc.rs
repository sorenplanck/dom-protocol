//! Narrow Bitcoin Core observation and broadcast boundary.

use crate::model::BitcoinActuationScopeV1;

/// Maximum accepted JSON-RPC response size.
#[cfg(feature = "rpc-http")]
pub const MAX_BITCOIN_RPC_RESPONSE_BYTES_V1: usize = 8_500_000;

/// Named, secret-free RPC failures.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum BitcoinRpcErrorV1 {
    /// Endpoint, cookie or transport authority is unavailable.
    #[error("Bitcoin RPC transport unavailable")]
    TransportUnavailable,
    /// RPC response exceeded the production bound.
    #[error("Bitcoin RPC response exceeds bound")]
    ResponseTooLarge,
    /// RPC response was malformed or internally contradictory.
    #[error("invalid Bitcoin RPC response")]
    InvalidResponse,
    /// Bitcoin Core rejected the exact request.
    #[error("Bitcoin Core rejected request")]
    Rejected,
    /// Configured endpoint does not match authenticated deployment facts.
    #[error("Bitcoin RPC network identity mismatch")]
    IdentityMismatch,
}

/// Result of broadcasting one exact raw transaction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BitcoinRpcBroadcastV1 {
    /// Node accepted the exact transaction now.
    Accepted {
        /// Returned transaction id in internal byte order.
        txid: [u8; 32],
    },
    /// Node already retained the exact transaction.
    AlreadyKnown {
        /// Returned transaction id in internal byte order.
        txid: [u8; 32],
    },
}

/// Exact raw transaction returned by the node.
///
/// Raw bytes can contain a secret-revealing claim signature, so this value has
/// no `Clone` or `Debug` implementation.
pub struct BitcoinRpcTransactionV1 {
    pub(crate) raw_transaction: Vec<u8>,
    pub(crate) evidence_digest: [u8; 32],
}

impl BitcoinRpcTransactionV1 {
    /// Imports canonical transaction bytes plus a nonzero public observation
    /// commitment. This is the construction boundary for custom observers.
    pub fn from_consensus_bytes(
        raw_transaction: Vec<u8>,
        evidence_digest: [u8; 32],
    ) -> core::result::Result<Self, BitcoinRpcErrorV1> {
        if raw_transaction.is_empty()
            || raw_transaction.len() > 4_000_000
            || evidence_digest == [0; 32]
        {
            return Err(BitcoinRpcErrorV1::InvalidResponse);
        }
        let transaction: bitcoin::Transaction = bitcoin::consensus::deserialize(&raw_transaction)
            .map_err(|_| BitcoinRpcErrorV1::InvalidResponse)?;
        if bitcoin::consensus::serialize(&transaction) != raw_transaction
            || transaction.input.is_empty()
            || transaction.output.is_empty()
        {
            return Err(BitcoinRpcErrorV1::InvalidResponse);
        }
        Ok(Self {
            raw_transaction,
            evidence_digest,
        })
    }

    /// Public evidence commitment for the observation.
    pub const fn evidence_digest(&self) -> [u8; 32] {
        self.evidence_digest
    }

    /// Consensus byte length without exposing the bytes through formatting.
    pub fn byte_len(&self) -> usize {
        self.raw_transaction.len()
    }
}

/// Mempool/canonical-chain lookup for an expected transaction id.
pub enum BitcoinRpcLookupV1 {
    /// Node authoritatively reports no transaction under this id.
    Absent {
        /// Public query evidence commitment.
        evidence_digest: [u8; 32],
    },
    /// Exact raw bytes are present in the mempool.
    Mempool(BitcoinRpcTransactionV1),
    /// Exact raw bytes are in a canonical block.
    Confirmed {
        /// Exact transaction returned by the node.
        transaction: BitcoinRpcTransactionV1,
        /// Canonical block hash in internal byte order.
        block_hash: [u8; 32],
        /// Canonical block height authenticated independently from the
        /// transaction response.
        block_height: u64,
        /// Current positive confirmation count agreed by transaction and
        /// canonical-header responses.
        confirmations: u32,
    },
}

/// Minimal production port used by the durable actuator.
pub trait BitcoinRpcV1 {
    /// Revalidates network, genesis and Signet identity against this scope.
    fn verify_scope(
        &mut self,
        scope: &BitcoinActuationScopeV1,
    ) -> core::result::Result<(), BitcoinRpcErrorV1>;

    /// Broadcasts exactly the supplied witness-bearing bytes.
    fn broadcast_exact(
        &mut self,
        raw_transaction: &[u8],
        expected_txid: [u8; 32],
    ) -> core::result::Result<BitcoinRpcBroadcastV1, BitcoinRpcErrorV1>;

    /// Looks up one transaction across mempool and canonical chain.
    fn lookup_exact(
        &mut self,
        expected_txid: [u8; 32],
    ) -> core::result::Result<BitcoinRpcLookupV1, BitcoinRpcErrorV1>;
}

#[cfg(feature = "rpc-http")]
mod http {
    use std::fs::File;
    use std::io::Read;
    use std::os::unix::fs::MetadataExt;
    use std::path::PathBuf;
    use std::str::FromStr;

    use bitcoin::consensus::deserialize;
    use bitcoin::hashes::Hash;
    use bitcoin::{BlockHash, Transaction, Txid};
    use blake2::digest::{Update, VariableOutput};
    use blake2::Blake2bVar;
    use reqwest::blocking::{Client, Response};
    use reqwest::Url;
    use serde::de::{Error as _, MapAccess, SeqAccess, Visitor};
    use serde::{Deserialize, Deserializer};
    use serde_json::{json, Map, Value};
    use zeroize::{Zeroize, Zeroizing};

    use super::{
        BitcoinActuationScopeV1, BitcoinRpcBroadcastV1, BitcoinRpcErrorV1, BitcoinRpcLookupV1,
        BitcoinRpcTransactionV1, BitcoinRpcV1, MAX_BITCOIN_RPC_RESPONSE_BYTES_V1,
    };

    const MAX_COOKIE_BYTES: usize = 4096;
    const RPC_CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);
    const RPC_REQUEST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);
    const OBSERVATION_DOMAIN: &[u8] = b"DOM-INTEROP/BTC-ACTUATOR/RPC-EVIDENCE/V2\0";

    /// Local authenticated Bitcoin Core HTTP configuration.
    ///
    /// Only loopback endpoints are accepted. The cookie path is retained and
    /// reread under owner/mode/link checks for every call; neither field is
    /// exposed through `Debug`.
    pub struct HttpBitcoinCoreRpcConfigV1 {
        /// Node endpoint, such as `http://127.0.0.1:18443`.
        pub endpoint: String,
        /// Owner-only Bitcoin Core cookie path.
        pub cookie_path: PathBuf,
    }

    /// Blocking, bounded live Bitcoin Core RPC authority.
    pub struct HttpBitcoinCoreRpcV1 {
        endpoint: Url,
        cookie_path: PathBuf,
        client: Client,
    }

    impl core::fmt::Debug for HttpBitcoinCoreRpcV1 {
        fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            formatter.write_str("HttpBitcoinCoreRpcV1([redacted])")
        }
    }

    enum RpcCallError {
        NotFound,
        Public(BitcoinRpcErrorV1),
    }

    impl HttpBitcoinCoreRpcV1 {
        /// Connects to a loopback-only Core endpoint without making a request.
        pub fn connect(
            config: HttpBitcoinCoreRpcConfigV1,
        ) -> core::result::Result<Self, BitcoinRpcErrorV1> {
            let endpoint = Url::parse(&config.endpoint)
                .map_err(|_| BitcoinRpcErrorV1::TransportUnavailable)?;
            if !matches!(endpoint.scheme(), "http" | "https")
                || endpoint.username() != ""
                || endpoint.password().is_some()
                || endpoint.query().is_some()
                || endpoint.fragment().is_some()
                || endpoint
                    .host_str()
                    .and_then(|host| std::net::IpAddr::from_str(host).ok())
                    .map_or(true, |address| !address.is_loopback())
            {
                return Err(BitcoinRpcErrorV1::TransportUnavailable);
            }
            let client = Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .connect_timeout(RPC_CONNECT_TIMEOUT)
                .timeout(RPC_REQUEST_TIMEOUT)
                .build()
                .map_err(|_| BitcoinRpcErrorV1::TransportUnavailable)?;
            Ok(Self {
                endpoint,
                cookie_path: config.cookie_path,
                client,
            })
        }

        fn rpc(&self, method: &'static str, params: Value) -> Result<Value, RpcCallError> {
            let mut cookie = read_cookie(&self.cookie_path).map_err(RpcCallError::Public)?;
            let separator =
                cookie
                    .iter()
                    .position(|byte| *byte == b':')
                    .ok_or(RpcCallError::Public(
                        BitcoinRpcErrorV1::TransportUnavailable,
                    ))?;
            if separator == 0 || separator + 1 >= cookie.len() {
                return Err(RpcCallError::Public(
                    BitcoinRpcErrorV1::TransportUnavailable,
                ));
            }
            let username = std::str::from_utf8(&cookie[..separator])
                .map_err(|_| RpcCallError::Public(BitcoinRpcErrorV1::TransportUnavailable))?;
            let password = std::str::from_utf8(&cookie[separator + 1..])
                .map_err(|_| RpcCallError::Public(BitcoinRpcErrorV1::TransportUnavailable))?;
            let response = self
                .client
                .post(self.endpoint.clone())
                .basic_auth(username, Some(password))
                .json(&json!({"jsonrpc":"2.0","id":"dom-btc-actuator-v1","method":method,"params":params}))
                .send()
                .map_err(|_| RpcCallError::Public(BitcoinRpcErrorV1::TransportUnavailable));
            cookie.zeroize();
            let response = response?;
            let value = read_json_response(response).map_err(RpcCallError::Public)?;
            let object = value
                .as_object()
                .ok_or(RpcCallError::Public(BitcoinRpcErrorV1::InvalidResponse))?;
            if object.get("id").and_then(Value::as_str) != Some("dom-btc-actuator-v1")
                || object
                    .get("jsonrpc")
                    .is_some_and(|value| value.as_str() != Some("2.0"))
            {
                return Err(RpcCallError::Public(BitcoinRpcErrorV1::InvalidResponse));
            }
            if let Some(error) = object.get("error").filter(|value| !value.is_null()) {
                if object.get("result").is_some_and(|value| !value.is_null()) {
                    return Err(RpcCallError::Public(BitcoinRpcErrorV1::InvalidResponse));
                }
                if error.get("code").and_then(Value::as_i64) == Some(-5) {
                    return Err(RpcCallError::NotFound);
                }
                return Err(RpcCallError::Public(BitcoinRpcErrorV1::Rejected));
            }
            object
                .get("result")
                .cloned()
                .ok_or(RpcCallError::Public(BitcoinRpcErrorV1::InvalidResponse))
        }

        fn lookup(
            &self,
            expected_txid: [u8; 32],
        ) -> core::result::Result<BitcoinRpcLookupV1, BitcoinRpcErrorV1> {
            let display = display_txid(expected_txid);
            let raw_hex = match self.rpc("getrawtransaction", json!([display, false])) {
                Ok(value) => value,
                Err(RpcCallError::NotFound) => {
                    return Ok(BitcoinRpcLookupV1::Absent {
                        evidence_digest: evidence_digest(&expected_txid, b"absent")?,
                    })
                }
                Err(RpcCallError::Public(error)) => return Err(error),
            };
            let raw = decode_hex(
                raw_hex.as_str().ok_or(BitcoinRpcErrorV1::InvalidResponse)?,
                4_000_000,
            )?;
            let transaction: Transaction =
                deserialize(&raw).map_err(|_| BitcoinRpcErrorV1::InvalidResponse)?;
            if transaction.compute_txid().to_raw_hash().to_byte_array() != expected_txid {
                return Err(BitcoinRpcErrorV1::InvalidResponse);
            }
            let verbose = self
                .rpc("getrawtransaction", json!([display, true]))
                .map_err(|error| match error {
                    RpcCallError::NotFound => BitcoinRpcErrorV1::InvalidResponse,
                    RpcCallError::Public(error) => error,
                })?;
            if let Some(verbose_hex) = verbose.get("hex").and_then(Value::as_str) {
                if decode_hex(verbose_hex, 4_000_000)? != raw {
                    return Err(BitcoinRpcErrorV1::InvalidResponse);
                }
            } else {
                return Err(BitcoinRpcErrorV1::InvalidResponse);
            }
            let block_display = verbose.get("blockhash").and_then(Value::as_str);
            let confirmations = verbose.get("confirmations").and_then(Value::as_i64);
            if block_display.is_none() && matches!(confirmations, None | Some(0)) {
                return Ok(BitcoinRpcLookupV1::Mempool(BitcoinRpcTransactionV1 {
                    evidence_digest: evidence_digest(&expected_txid, &raw)?,
                    raw_transaction: raw,
                }));
            }
            let block_display = block_display.ok_or(BitcoinRpcErrorV1::InvalidResponse)?;
            let confirmations = confirmations
                .and_then(|value| u32::try_from(value).ok())
                .filter(|value| *value > 0)
                .ok_or(BitcoinRpcErrorV1::InvalidResponse)?;
            let header = self
                .rpc("getblockheader", json!([block_display, true]))
                .map_err(map_public)?;
            let height = header
                .get("height")
                .and_then(Value::as_u64)
                .ok_or(BitcoinRpcErrorV1::InvalidResponse)?;
            let canonical_hash = self
                .rpc("getblockhash", json!([height]))
                .map_err(map_public)?;
            let (block_hash, block_height) = validated_canonical_block_facts(
                block_display,
                confirmations,
                &header,
                &canonical_hash,
            )?;
            // Confirmation count is deliberately excluded. It changes as the
            // tip advances; the evidence commitment identifies the stable
            // transaction/block/height fact that was independently checked.
            Ok(BitcoinRpcLookupV1::Confirmed {
                transaction: BitcoinRpcTransactionV1 {
                    evidence_digest: confirmed_evidence_digest(
                        &expected_txid,
                        &raw,
                        block_hash,
                        block_height,
                    )?,
                    raw_transaction: raw,
                },
                block_hash,
                block_height,
                confirmations,
            })
        }
    }

    impl BitcoinRpcV1 for HttpBitcoinCoreRpcV1 {
        fn verify_scope(
            &mut self,
            scope: &BitcoinActuationScopeV1,
        ) -> core::result::Result<(), BitcoinRpcErrorV1> {
            let information = self
                .rpc("getblockchaininfo", json!([]))
                .map_err(map_public)?;
            let expected_chain = match scope.network() {
                adapter_btc::types::BitcoinNetworkV1::Regtest => "regtest",
                adapter_btc::types::BitcoinNetworkV1::PublicSignet
                | adapter_btc::types::BitcoinNetworkV1::CustomSignet => "signet",
            };
            if information.get("chain").and_then(Value::as_str) != Some(expected_chain) {
                return Err(BitcoinRpcErrorV1::IdentityMismatch);
            }
            let challenge = information
                .get("signet_challenge")
                .and_then(Value::as_str)
                .map(|value| decode_hex(value, 10_000))
                .transpose()?;
            let challenge_digest =
                crate::model::deployment_component_digest(challenge.as_deref().unwrap_or_default())
                    .map_err(|_| BitcoinRpcErrorV1::InvalidResponse)?;
            if challenge_digest != scope.signet_challenge_digest() {
                return Err(BitcoinRpcErrorV1::IdentityMismatch);
            }
            let genesis = self.rpc("getblockhash", json!([0])).map_err(map_public)?;
            let genesis =
                BlockHash::from_str(genesis.as_str().ok_or(BitcoinRpcErrorV1::InvalidResponse)?)
                    .map_err(|_| BitcoinRpcErrorV1::InvalidResponse)?
                    .to_raw_hash()
                    .to_byte_array();
            if genesis != scope.genesis_hash() {
                return Err(BitcoinRpcErrorV1::IdentityMismatch);
            }
            // A wallet-only node can report a confirmed route transaction as
            // absent after restart. Exact reconciliation therefore requires
            // a fully synchronized global transaction index.
            let indexes = self.rpc("getindexinfo", json!([])).map_err(map_public)?;
            let index = indexes
                .get("txindex")
                .ok_or(BitcoinRpcErrorV1::IdentityMismatch)?;
            let chain_height = information
                .get("blocks")
                .and_then(Value::as_u64)
                .ok_or(BitcoinRpcErrorV1::InvalidResponse)?;
            if index.get("synced").and_then(Value::as_bool) != Some(true)
                || index.get("best_block_height").and_then(Value::as_u64) != Some(chain_height)
            {
                return Err(BitcoinRpcErrorV1::IdentityMismatch);
            }
            Ok(())
        }

        fn broadcast_exact(
            &mut self,
            raw_transaction: &[u8],
            expected_txid: [u8; 32],
        ) -> core::result::Result<BitcoinRpcBroadcastV1, BitcoinRpcErrorV1> {
            let encoded = encode_hex(raw_transaction);
            match self.rpc("sendrawtransaction", json!([encoded])) {
                Ok(value) => {
                    let txid =
                        parse_txid(value.as_str().ok_or(BitcoinRpcErrorV1::InvalidResponse)?)?;
                    if txid != expected_txid {
                        return Err(BitcoinRpcErrorV1::InvalidResponse);
                    }
                    Ok(BitcoinRpcBroadcastV1::Accepted { txid })
                }
                Err(RpcCallError::NotFound) => Err(BitcoinRpcErrorV1::Rejected),
                Err(RpcCallError::Public(_)) => match self.lookup(expected_txid)? {
                    BitcoinRpcLookupV1::Mempool(transaction)
                        if transaction.raw_transaction == raw_transaction =>
                    {
                        Ok(BitcoinRpcBroadcastV1::AlreadyKnown {
                            txid: expected_txid,
                        })
                    }
                    BitcoinRpcLookupV1::Confirmed { transaction, .. }
                        if transaction.raw_transaction == raw_transaction =>
                    {
                        Ok(BitcoinRpcBroadcastV1::AlreadyKnown {
                            txid: expected_txid,
                        })
                    }
                    _ => Err(BitcoinRpcErrorV1::Rejected),
                },
            }
        }

        fn lookup_exact(
            &mut self,
            expected_txid: [u8; 32],
        ) -> core::result::Result<BitcoinRpcLookupV1, BitcoinRpcErrorV1> {
            self.lookup(expected_txid)
        }
    }

    fn map_public(error: RpcCallError) -> BitcoinRpcErrorV1 {
        match error {
            RpcCallError::NotFound => BitcoinRpcErrorV1::InvalidResponse,
            RpcCallError::Public(error) => error,
        }
    }

    fn read_cookie(path: &PathBuf) -> core::result::Result<Zeroizing<Vec<u8>>, BitcoinRpcErrorV1> {
        let metadata =
            std::fs::symlink_metadata(path).map_err(|_| BitcoinRpcErrorV1::TransportUnavailable)?;
        if !metadata.file_type().is_file()
            || metadata.file_type().is_symlink()
            || metadata.uid() != rustix::process::geteuid().as_raw()
            || metadata.mode() & 0o777 != 0o600
            || metadata.nlink() != 1
            || metadata.len() == 0
            || metadata.len() > MAX_COOKIE_BYTES as u64
        {
            return Err(BitcoinRpcErrorV1::TransportUnavailable);
        }
        let file = File::open(path).map_err(|_| BitcoinRpcErrorV1::TransportUnavailable)?;
        let reopened = file
            .metadata()
            .map_err(|_| BitcoinRpcErrorV1::TransportUnavailable)?;
        if reopened.dev() != metadata.dev() || reopened.ino() != metadata.ino() {
            return Err(BitcoinRpcErrorV1::TransportUnavailable);
        }
        let mut bytes = Zeroizing::new(Vec::new());
        file.take((MAX_COOKIE_BYTES + 1) as u64)
            .read_to_end(&mut bytes)
            .map_err(|_| BitcoinRpcErrorV1::TransportUnavailable)?;
        while matches!(bytes.last(), Some(b'\n' | b'\r')) {
            bytes.pop();
        }
        if bytes.is_empty() || bytes.len() > MAX_COOKIE_BYTES {
            return Err(BitcoinRpcErrorV1::TransportUnavailable);
        }
        Ok(bytes)
    }

    fn read_json_response(
        mut response: Response,
    ) -> core::result::Result<Value, BitcoinRpcErrorV1> {
        if !response.status().is_success() {
            return Err(BitcoinRpcErrorV1::TransportUnavailable);
        }
        let mut bytes = Vec::new();
        response
            .by_ref()
            .take((MAX_BITCOIN_RPC_RESPONSE_BYTES_V1 + 1) as u64)
            .read_to_end(&mut bytes)
            .map_err(|_| BitcoinRpcErrorV1::TransportUnavailable)?;
        if bytes.len() > MAX_BITCOIN_RPC_RESPONSE_BYTES_V1 {
            return Err(BitcoinRpcErrorV1::ResponseTooLarge);
        }
        parse_json_bytes(&bytes)
    }

    fn parse_json_bytes(bytes: &[u8]) -> core::result::Result<Value, BitcoinRpcErrorV1> {
        serde_json::from_slice::<StrictValue>(bytes)
            .map(|value| value.0)
            .map_err(|_| BitcoinRpcErrorV1::InvalidResponse)
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
            formatter.write_str("bounded JSON without duplicate object keys")
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

        fn visit_f64<E>(self, value: f64) -> core::result::Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            serde_json::Number::from_f64(value)
                .map(Value::Number)
                .map(StrictValue)
                .ok_or_else(|| E::custom("non-finite JSON number"))
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

    fn parse_txid(value: &str) -> core::result::Result<[u8; 32], BitcoinRpcErrorV1> {
        Txid::from_str(value)
            .map(|txid| txid.to_raw_hash().to_byte_array())
            .map_err(|_| BitcoinRpcErrorV1::InvalidResponse)
    }

    fn display_txid(bytes: [u8; 32]) -> String {
        Txid::from_raw_hash(bitcoin::hashes::sha256d::Hash::from_byte_array(bytes)).to_string()
    }

    fn validated_canonical_block_facts(
        requested_hash: &str,
        transaction_confirmations: u32,
        header: &Value,
        canonical_hash: &Value,
    ) -> core::result::Result<([u8; 32], u64), BitcoinRpcErrorV1> {
        let requested =
            BlockHash::from_str(requested_hash).map_err(|_| BitcoinRpcErrorV1::InvalidResponse)?;
        let returned = header
            .get("hash")
            .and_then(Value::as_str)
            .and_then(|value| BlockHash::from_str(value).ok())
            .ok_or(BitcoinRpcErrorV1::InvalidResponse)?;
        let header_confirmations = header
            .get("confirmations")
            .and_then(Value::as_i64)
            .and_then(|value| u32::try_from(value).ok())
            .filter(|value| *value > 0)
            .ok_or(BitcoinRpcErrorV1::InvalidResponse)?;
        let height = header
            .get("height")
            .and_then(Value::as_u64)
            .ok_or(BitcoinRpcErrorV1::InvalidResponse)?;
        let canonical = canonical_hash
            .as_str()
            .and_then(|value| BlockHash::from_str(value).ok())
            .ok_or(BitcoinRpcErrorV1::InvalidResponse)?;
        if returned != requested
            || canonical != requested
            || header_confirmations != transaction_confirmations
        {
            return Err(BitcoinRpcErrorV1::InvalidResponse);
        }
        Ok((requested.to_raw_hash().to_byte_array(), height))
    }

    fn confirmed_evidence_digest(
        expected_txid: &[u8; 32],
        raw: &[u8],
        block_hash: [u8; 32],
        block_height: u64,
    ) -> core::result::Result<[u8; 32], BitcoinRpcErrorV1> {
        let mut evidence = Vec::with_capacity(raw.len() + 40);
        evidence.extend_from_slice(raw);
        evidence.extend_from_slice(&block_hash);
        evidence.extend_from_slice(&block_height.to_be_bytes());
        evidence_digest(expected_txid, &evidence)
    }

    fn decode_hex(value: &str, maximum: usize) -> core::result::Result<Vec<u8>, BitcoinRpcErrorV1> {
        if value.len() % 2 != 0 || value.len() / 2 > maximum || !value.is_ascii() {
            return Err(BitcoinRpcErrorV1::InvalidResponse);
        }
        let mut output = Vec::with_capacity(value.len() / 2);
        for pair in value.as_bytes().chunks_exact(2) {
            output.push((hex_nibble(pair[0])? << 4) | hex_nibble(pair[1])?);
        }
        Ok(output)
    }

    fn hex_nibble(value: u8) -> core::result::Result<u8, BitcoinRpcErrorV1> {
        match value {
            b'0'..=b'9' => Ok(value - b'0'),
            b'a'..=b'f' => Ok(value - b'a' + 10),
            b'A'..=b'F' => Ok(value - b'A' + 10),
            _ => Err(BitcoinRpcErrorV1::InvalidResponse),
        }
    }

    fn encode_hex(bytes: &[u8]) -> String {
        const TABLE: &[u8; 16] = b"0123456789abcdef";
        let mut output = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            output.push(TABLE[usize::from(byte >> 4)] as char);
            output.push(TABLE[usize::from(byte & 0x0f)] as char);
        }
        output
    }

    fn evidence_digest(
        identity: &[u8],
        payload: &[u8],
    ) -> core::result::Result<[u8; 32], BitcoinRpcErrorV1> {
        let mut hasher = Blake2bVar::new(32).map_err(|_| BitcoinRpcErrorV1::InvalidResponse)?;
        hasher.update(OBSERVATION_DOMAIN);
        hasher.update(identity);
        hasher.update(payload);
        let mut output = [0; 32];
        hasher
            .finalize_variable(&mut output)
            .map_err(|_| BitcoinRpcErrorV1::InvalidResponse)?;
        Ok(output)
    }

    #[cfg(test)]
    mod tests {
        use serde_json::json;

        use super::{
            confirmed_evidence_digest, parse_json_bytes, validated_canonical_block_facts,
            BitcoinRpcErrorV1,
        };

        #[test]
        fn strict_json_rejects_duplicate_keys() {
            assert_eq!(
                parse_json_bytes(br#"{"result":1,"result":2}"#),
                Err(BitcoinRpcErrorV1::InvalidResponse)
            );
            assert!(parse_json_bytes(
                br#"{"result":{"verificationprogress":0.5},"error":null,"id":"dom-btc-actuator-v1"}"#
            )
            .is_ok());
        }

        #[test]
        fn canonical_header_rejects_missing_height_and_contradictions() {
            let hash = "0000000000000000000000000000000000000000000000000000000000000001";
            let other = "0000000000000000000000000000000000000000000000000000000000000002";
            assert_eq!(
                validated_canonical_block_facts(
                    hash,
                    2,
                    &json!({"hash": hash, "confirmations": 2}),
                    &json!(hash),
                ),
                Err(BitcoinRpcErrorV1::InvalidResponse)
            );
            assert_eq!(
                validated_canonical_block_facts(
                    hash,
                    2,
                    &json!({"hash": other, "height": 41, "confirmations": 2}),
                    &json!(hash),
                ),
                Err(BitcoinRpcErrorV1::InvalidResponse)
            );
            assert_eq!(
                validated_canonical_block_facts(
                    hash,
                    2,
                    &json!({"hash": hash, "height": 41, "confirmations": 1}),
                    &json!(hash),
                ),
                Err(BitcoinRpcErrorV1::InvalidResponse)
            );
            assert_eq!(
                validated_canonical_block_facts(
                    hash,
                    2,
                    &json!({"hash": hash, "height": 41, "confirmations": -1}),
                    &json!(hash),
                ),
                Err(BitcoinRpcErrorV1::InvalidResponse)
            );
            assert_eq!(
                validated_canonical_block_facts(
                    hash,
                    2,
                    &json!({"hash": hash, "height": 41, "confirmations": 2}),
                    &json!(other),
                ),
                Err(BitcoinRpcErrorV1::InvalidResponse)
            );
            assert!(validated_canonical_block_facts(
                hash,
                2,
                &json!({"hash": hash, "height": 41, "confirmations": 2}),
                &json!(hash),
            )
            .is_ok());
        }

        #[test]
        fn confirmed_evidence_commits_only_stable_block_facts() -> Result<(), BitcoinRpcErrorV1> {
            let first = confirmed_evidence_digest(&[1; 32], b"raw", [2; 32], 41)?;
            let replay = confirmed_evidence_digest(&[1; 32], b"raw", [2; 32], 41)?;
            let next_height = confirmed_evidence_digest(&[1; 32], b"raw", [2; 32], 42)?;
            assert_eq!(first, replay);
            assert_ne!(first, next_height);
            Ok(())
        }
    }
}

#[cfg(feature = "rpc-http")]
pub use http::{HttpBitcoinCoreRpcConfigV1, HttpBitcoinCoreRpcV1};
