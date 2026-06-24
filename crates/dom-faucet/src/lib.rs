//! DOM Protocol Testnet Faucet.
//!
//! Distributes small amounts of testnet DOM to payment requests, with
//! rate limiting per recipient commitment.

use axum::{
    extract::{Json, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Router,
};
use dom_core::Address;
use dom_crypto::{pedersen::Commitment, BlindingFactor};
use dom_wallet::{NodeRpcClient, RpcClientError};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;
use tower_http::cors::CorsLayer;
use url::Url;

const RATE_LIMIT_SECS: u64 = 3600;

/// Backend trait: faucet needs to send transactions.
pub trait FaucetBackend: Send + Sync + 'static {
    fn send_payment(
        &self,
        commitment_hex: &str,
        blinding_hex: &str,
        amount_noms: u64,
        fee_noms: u64,
    ) -> Result<[u8; 32], String>;
}

pub struct FaucetServer<B: FaucetBackend> {
    addr: String,
    state: Arc<FaucetState<B>>,
}

pub struct FaucetState<B: FaucetBackend> {
    last_requests: Mutex<HashMap<String, Instant>>,
    backend: Arc<B>,
    amount_noms: u64,
    fee_noms: u64,
}

impl<B: FaucetBackend> FaucetServer<B> {
    pub fn new(addr: String, backend: Arc<B>, amount_noms: u64, fee_noms: u64) -> Self {
        Self {
            addr,
            state: Arc::new(FaucetState {
                last_requests: Mutex::new(HashMap::new()),
                backend,
                amount_noms,
                fee_noms,
            }),
        }
    }

    pub async fn start(self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let app = Router::new()
            .route("/", get(root))
            .route("/api/request", post(request_coins::<B>))
            .layer(CorsLayer::permissive())
            .with_state(self.state);

        let listener = tokio::net::TcpListener::bind(&self.addr).await?;
        tracing::info!("Faucet listening on {}", self.addr);
        axum::serve(listener, app).await?;
        Ok(())
    }
}

async fn root() -> &'static str {
    "DOM Protocol Testnet Faucet v0.1 - submit a DOM-PAYMENT-REQUEST-V1"
}

#[derive(Deserialize)]
pub struct FaucetRequest {
    pub payment_request: String,
}

#[derive(Serialize)]
pub struct FaucetResponse {
    pub success: bool,
    pub message: String,
    pub tx_hash: Option<String>,
    pub amount_noms: Option<u64>,
}

async fn request_coins<B: FaucetBackend>(
    State(state): State<Arc<FaucetState<B>>>,
    Json(req): Json<FaucetRequest>,
) -> impl IntoResponse {
    let parsed = match parse_and_validate_payment_request(&req.payment_request, state.amount_noms) {
        Ok(parsed) => parsed,
        Err(e) => return faucet_error(StatusCode::BAD_REQUEST, e),
    };

    let last_requests = state.last_requests.lock().await;
    if let Some(last_time) = last_requests.get(&parsed.rate_limit_key) {
        let elapsed = Instant::now().duration_since(*last_time);
        if elapsed < Duration::from_secs(RATE_LIMIT_SECS) {
            let remaining = Duration::from_secs(RATE_LIMIT_SECS) - elapsed;
            return (
                StatusCode::TOO_MANY_REQUESTS,
                Json(FaucetResponse {
                    success: false,
                    message: format!(
                        "Rate limited. Try again in {} minutes",
                        remaining.as_secs() / 60
                    ),
                    tx_hash: None,
                    amount_noms: None,
                }),
            );
        }
    }
    drop(last_requests);

    let backend = state.backend.clone();
    let commitment_hex = parsed.commitment_hex.clone();
    let blinding_hex = parsed.blinding_hex.clone();
    let amount_noms = state.amount_noms;
    let fee_noms = state.fee_noms;
    let tx_hash = match tokio::task::spawn_blocking(move || {
        backend.send_payment(&commitment_hex, &blinding_hex, amount_noms, fee_noms)
    })
    .await
    {
        Ok(result) => match result {
            Ok(hash) => hash,
            Err(e) => {
                return faucet_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("Send failed: {e}"),
                );
            }
        },
        Err(e) => {
            return faucet_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Send task failed: {e}"),
            );
        }
    };

    let mut last_requests = state.last_requests.lock().await;
    last_requests.insert(parsed.rate_limit_key.clone(), Instant::now());

    (
        StatusCode::OK,
        Json(FaucetResponse {
            success: true,
            message: format!(
                "Sent {} DOM for payment request {}",
                amount_noms / 1_000_000_000,
                parsed.address
            ),
            tx_hash: Some(hex_encode(&tx_hash)),
            amount_noms: Some(amount_noms),
        }),
    )
}

fn faucet_error(
    status: StatusCode,
    message: impl Into<String>,
) -> (StatusCode, Json<FaucetResponse>) {
    (
        status,
        Json(FaucetResponse {
            success: false,
            message: message.into(),
            tx_hash: None,
            amount_noms: None,
        }),
    )
}

pub struct NodeBackend {
    client: NodeRpcClient,
}

impl NodeBackend {
    pub fn new(node_url: Url, bearer_token: String) -> Result<Self, RpcClientError> {
        let client = NodeRpcClient::builder(node_url)
            .bearer_token(bearer_token)
            .user_agent(format!("dom-faucet/{}", env!("CARGO_PKG_VERSION")))
            .build()?;
        Ok(Self { client })
    }
}

impl FaucetBackend for NodeBackend {
    fn send_payment(
        &self,
        commitment_hex: &str,
        blinding_hex: &str,
        amount_noms: u64,
        fee_noms: u64,
    ) -> Result<[u8; 32], String> {
        self.client
            .wallet_spend(
                commitment_hex.to_string(),
                blinding_hex.to_string(),
                amount_noms,
                fee_noms,
            )
            .map(|outcome| outcome.tx_hash)
            .map_err(|e| e.to_string())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ParsedPaymentRequest {
    amount_noms: u64,
    address: String,
    commitment_hex: String,
    blinding_hex: String,
    rate_limit_key: String,
}

fn parse_and_validate_payment_request(
    request_text: &str,
    faucet_amount_noms: u64,
) -> Result<ParsedPaymentRequest, String> {
    let mut lines = request_text
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty());
    let Some(header) = lines.next() else {
        return Err("payment request is required".to_string());
    };
    if header != "DOM-PAYMENT-REQUEST-V1" {
        return Err(format!("unsupported payment request header: {header}"));
    }

    let mut network = None;
    let mut amount_noms = None;
    let mut address = None;
    let mut commitment_hex = None;
    let mut blinding_hex = None;

    for line in lines {
        let (key, value) = line
            .split_once('=')
            .ok_or_else(|| format!("invalid payment request line: {line}"))?;
        match key {
            "network" => network = Some(parse_network_name(value)?),
            "amount_noms" => {
                amount_noms = Some(
                    value
                        .parse::<u64>()
                        .map_err(|e| format!("invalid amount_noms: {e}"))?,
                )
            }
            "address" => address = Some(value.to_string()),
            "commitment" => commitment_hex = Some(value.to_string()),
            "blinding" => blinding_hex = Some(value.to_string()),
            _ => return Err(format!("unknown payment request field: {key}")),
        }
    }

    let network = network.ok_or_else(|| "missing network".to_string())?;
    let amount_noms = amount_noms.ok_or_else(|| "missing amount_noms".to_string())?;
    if amount_noms != faucet_amount_noms {
        return Err(format!(
            "payment request amount_noms must equal faucet amount {faucet_amount_noms}"
        ));
    }
    let address = address.ok_or_else(|| "missing address".to_string())?;
    let commitment_hex = commitment_hex.ok_or_else(|| "missing commitment".to_string())?;
    let blinding_hex = blinding_hex.ok_or_else(|| "missing blinding".to_string())?;

    let commitment = parse_commitment_hex(&commitment_hex)?;
    let parsed_address = Address::decode(&address).map_err(|e| format!("address decode: {e}"))?;
    if parsed_address.payload != commitment {
        return Err("address payload does not match commitment field".to_string());
    }
    if parsed_address.is_mainnet != network.is_mainnet() {
        return Err("address network does not match request network".to_string());
    }

    let blinding = parse_blinding_hex(&blinding_hex)?;
    let recomputed = Commitment::commit(amount_noms, &blinding);
    if *recomputed.as_bytes() != commitment {
        return Err("commitment does not match amount + blinding".to_string());
    }

    Ok(ParsedPaymentRequest {
        amount_noms,
        address,
        commitment_hex,
        blinding_hex,
        rate_limit_key: hex_encode(&commitment),
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PaymentNetwork {
    Mainnet,
    Testnet,
    Regtest,
}

impl PaymentNetwork {
    fn is_mainnet(self) -> bool {
        matches!(self, PaymentNetwork::Mainnet)
    }
}

fn parse_network_name(value: &str) -> Result<PaymentNetwork, String> {
    match value {
        "mainnet" => Ok(PaymentNetwork::Mainnet),
        "testnet" => Ok(PaymentNetwork::Testnet),
        "regtest" => Ok(PaymentNetwork::Regtest),
        _ => Err(format!("unknown network: {value}")),
    }
}

fn parse_commitment_hex(value: &str) -> Result<[u8; 33], String> {
    let bytes = hex::decode(value).map_err(|e| format!("commitment hex: {e}"))?;
    bytes
        .try_into()
        .map_err(|v: Vec<u8>| format!("commitment must be 33 bytes, got {}", v.len()))
}

fn parse_blinding_hex(value: &str) -> Result<BlindingFactor, String> {
    let bytes = hex::decode(value).map_err(|e| format!("blinding hex: {e}"))?;
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|v: Vec<u8>| format!("blinding must be 32 bytes, got {}", v.len()))?;
    BlindingFactor::from_bytes(arr).map_err(|e| format!("blinding: {e}"))
}

fn hex_encode(bytes: &[u8]) -> String {
    hex::encode(bytes)
}

// ---------------------------------------------------------------------------
// dom-shield probe (default-off). Re-exports the otherwise-private untrusted
// parser so external fuzz/integration tests can reach it WITHOUT changing any
// production logic. Gated behind a feature that is never enabled in production
// builds; with the feature off this compiles to nothing.
// ---------------------------------------------------------------------------
#[cfg(feature = "shield-probe")]
#[doc(hidden)]
pub mod shield_probe {
    /// Probe over the private `parse_and_validate_payment_request`.
    ///
    /// Returns `Ok(())` if the request parses+validates, `Err(message)` otherwise.
    /// Intentionally discards the parsed value: fuzz/KAV harnesses only need the
    /// accept/reject decision and the (panic-free) behaviour.
    pub fn parse_and_validate(request_text: &str, faucet_amount_noms: u64) -> Result<(), String> {
        super::parse_and_validate_payment_request(request_text, faucet_amount_noms).map(|_| ())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dom_crypto::BlindingFactor;

    struct MockBackend;
    impl FaucetBackend for MockBackend {
        fn send_payment(
            &self,
            _commitment_hex: &str,
            _blinding_hex: &str,
            _amount: u64,
            _fee: u64,
        ) -> Result<[u8; 32], String> {
            Ok([0x42u8; 32])
        }
    }

    #[test]
    fn constants_correct() {
        assert_eq!(RATE_LIMIT_SECS, 3600);
    }

    #[test]
    fn mock_backend_works() {
        let b = MockBackend;
        let result = b.send_payment(&"02".repeat(33), &"11".repeat(32), 1000, 10);
        assert!(result.is_ok());
        assert_eq!(result.unwrap()[0], 0x42);
    }

    #[test]
    fn hex_encode_works() {
        assert_eq!(hex_encode(&[0xca, 0xfe]), "cafe");
    }

    #[test]
    fn valid_payment_request_parses() {
        let amount = 10_000;
        let blinding = BlindingFactor::from_bytes([7u8; 32]).expect("valid blinding");
        let commitment = Commitment::commit(amount, &blinding);
        let address = Address::new(*commitment.as_bytes(), false).encode();
        let request = payment_request(
            "testnet",
            amount,
            &address,
            &hex::encode(commitment.as_bytes()),
            &hex::encode(blinding.as_bytes()),
        );

        let parsed = parse_and_validate_payment_request(&request, amount).expect("valid request");

        assert_eq!(parsed.amount_noms, amount);
        assert_eq!(parsed.address, address);
        assert_eq!(parsed.commitment_hex, hex::encode(commitment.as_bytes()));
        assert_eq!(parsed.blinding_hex, hex::encode(blinding.as_bytes()));
        assert_eq!(parsed.rate_limit_key, hex::encode(commitment.as_bytes()));
    }

    #[test]
    fn payment_request_amount_must_match_faucet_amount() {
        let amount = 10_000;
        let blinding = BlindingFactor::from_bytes([8u8; 32]).expect("valid blinding");
        let commitment = Commitment::commit(amount, &blinding);
        let address = Address::new(*commitment.as_bytes(), false).encode();
        let request = payment_request(
            "testnet",
            amount,
            &address,
            &hex::encode(commitment.as_bytes()),
            &hex::encode(blinding.as_bytes()),
        );

        let err = parse_and_validate_payment_request(&request, amount + 1).unwrap_err();

        assert!(err.contains("must equal faucet amount"));
    }

    #[test]
    fn payment_request_rejects_commitment_mismatch() {
        let amount = 10_000;
        let blinding = BlindingFactor::from_bytes([9u8; 32]).expect("valid blinding");
        let commitment = Commitment::commit(amount, &blinding);
        let address = Address::new(*commitment.as_bytes(), false).encode();
        let wrong_blinding = BlindingFactor::from_bytes([10u8; 32]).expect("valid blinding");
        let request = payment_request(
            "testnet",
            amount,
            &address,
            &hex::encode(commitment.as_bytes()),
            &hex::encode(wrong_blinding.as_bytes()),
        );

        let err = parse_and_validate_payment_request(&request, amount).unwrap_err();

        assert!(err.contains("commitment does not match"));
    }

    fn payment_request(
        network: &str,
        amount: u64,
        address: &str,
        commitment_hex: &str,
        blinding_hex: &str,
    ) -> String {
        format!(
            "DOM-PAYMENT-REQUEST-V1\nnetwork={network}\namount_noms={amount}\naddress={address}\ncommitment={commitment_hex}\nblinding={blinding_hex}"
        )
    }
}
