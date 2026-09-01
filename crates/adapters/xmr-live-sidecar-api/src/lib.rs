//! Versioned authenticated DOM↔XMR sidecar wire types.

#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Active wire version.
pub const API_VERSION_V2: u16 = 2;
/// Maximum destination string bytes.
pub const MAX_DESTINATION_BYTES: usize = 256;
/// Maximum signed raw transaction bytes.
pub const MAX_RAW_TX_BYTES: usize = 512 * 1024;
/// Maximum UDS JSON frame bytes.
pub const MAX_FRAME_BYTES: usize = 1024 * 1024;

/// Secret scalar wrapper used only across the authenticated loopback boundary.
#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(transparent)]
pub struct SecretScalarBytes([u8; 32]);

impl core::fmt::Debug for SecretScalarBytes {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("SecretScalarBytes(<redacted>)")
    }
}

impl SecretScalarBytes {
    /// Wraps scalar bytes.
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
    /// Closure-only access.
    pub fn expose<R>(&self, operation: impl FnOnce(&[u8; 32]) -> R) -> R {
        operation(&self.0)
    }
}

/// Authenticated funding-verification request.
#[derive(Serialize, Deserialize)]
pub struct VerifyFundingRequestV2 {
    /// Wire version.
    pub api_version: u16,
    /// Kaystra/event idempotency nonce.
    pub request_nonce: [u8; 32],
    /// Settlement binding.
    pub settlement_id: [u8; 32],
    /// Funding transaction to scan.
    pub funding_tx_hash: [u8; 32],
    /// Exact expected amount.
    pub expected_amount_piconero: u64,
    /// Combined public spend key.
    pub expected_spend_public_key: [u8; 32],
    /// Private view scalar.
    pub view_scalar: SecretScalarBytes,
    /// HMAC tag over canonical bytes.
    pub auth_tag: [u8; 32],
}

impl core::fmt::Debug for VerifyFundingRequestV2 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("VerifyFundingRequestV2")
            .field("api_version", &self.api_version)
            .field("request_nonce", &"<public-nonce>")
            .field("settlement_id", &"<public-id>")
            .field("funding_tx_hash", &"<public-txid>")
            .field("expected_amount_piconero", &self.expected_amount_piconero)
            .field("expected_spend_public_key", &"<public-key>")
            .field("view_scalar", &"<redacted>")
            .field("auth_tag", &"<redacted>")
            .finish()
    }
}

impl Drop for VerifyFundingRequestV2 {
    fn drop(&mut self) {
        self.auth_tag.zeroize();
    }
}

impl VerifyFundingRequestV2 {
    /// Structural validation before cryptographic/network work.
    pub fn validate_public_fields(&self) -> Result<(), SidecarApiError> {
        validate_common(
            self.api_version,
            &self.request_nonce,
            &self.settlement_id,
            &self.funding_tx_hash,
            self.expected_amount_piconero,
            &self.expected_spend_public_key,
        )
    }

    /// Canonical HMAC bytes excluding `auth_tag`.
    pub fn canonical_auth_bytes(&self) -> Result<Vec<u8>, SidecarApiError> {
        self.validate_public_fields()?;
        let mut output = Vec::with_capacity(2 + 32 * 5 + 8);
        output.extend_from_slice(b"VERIFY-FUNDING\0");
        output.extend_from_slice(&self.api_version.to_be_bytes());
        output.extend_from_slice(&self.request_nonce);
        output.extend_from_slice(&self.settlement_id);
        output.extend_from_slice(&self.funding_tx_hash);
        output.extend_from_slice(&self.expected_amount_piconero.to_be_bytes());
        output.extend_from_slice(&self.expected_spend_public_key);
        self.view_scalar
            .expose(|bytes| output.extend_from_slice(bytes));
        Ok(output)
    }
}

/// Result of scanning the funding transaction with its view pair.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VerifyFundingResponseV2 {
    /// Wire version.
    pub api_version: u16,
    /// Echoed nonce.
    pub request_nonce: [u8; 32],
    /// Echoed funding transaction hash.
    pub funding_tx_hash: [u8; 32],
    /// Adapter-local event index. Single-use swap wallets use zero.
    pub event_index: u32,
    /// Exact amount found.
    pub received_amount_piconero: u64,
    /// False for additionally timelocked/unspendable output.
    pub spendable: bool,
}

impl VerifyFundingResponseV2 {
    /// Validates request/response binding.
    pub fn validate_for(&self, request: &VerifyFundingRequestV2) -> Result<(), SidecarApiError> {
        if self.api_version != API_VERSION_V2
            || self.request_nonce != request.request_nonce
            || self.funding_tx_hash != request.funding_tx_hash
            || self.received_amount_piconero != request.expected_amount_piconero
            || !self.spendable
        {
            return Err(SidecarApiError::InvalidResponse);
        }
        Ok(())
    }
}

/// Authenticated idempotent sweep-build request.
#[derive(Serialize, Deserialize)]
pub struct BuildSweepRequestV2 {
    /// Wire version.
    pub api_version: u16,
    /// Kaystra effect id and sidecar idempotency key.
    pub request_nonce: [u8; 32],
    /// Settlement id.
    pub settlement_id: [u8; 32],
    /// Funding transaction to spend.
    pub funding_tx_hash: [u8; 32],
    /// Exact piconero amount expected in the spendable output.
    pub expected_amount_piconero: u64,
    /// Destination Monero address.
    pub destination: String,
    /// Combined private spend scalar.
    pub spend_scalar: SecretScalarBytes,
    /// Public key recomputed before signing.
    pub expected_spend_public_key: [u8; 32],
    /// Private view scalar.
    pub view_scalar: SecretScalarBytes,
    /// HMAC-SHA256 tag.
    pub auth_tag: [u8; 32],
}

impl core::fmt::Debug for BuildSweepRequestV2 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("BuildSweepRequestV2")
            .field("api_version", &self.api_version)
            .field("request_nonce", &"<public-effect-id>")
            .field("settlement_id", &"<public-id>")
            .field("funding_tx_hash", &"<public-txid>")
            .field("expected_amount_piconero", &self.expected_amount_piconero)
            .field("destination", &self.destination)
            .field("spend_scalar", &"<redacted>")
            .field("expected_spend_public_key", &"<public-key>")
            .field("view_scalar", &"<redacted>")
            .field("auth_tag", &"<redacted>")
            .finish()
    }
}

impl Drop for BuildSweepRequestV2 {
    fn drop(&mut self) {
        self.auth_tag.zeroize();
    }
}

impl BuildSweepRequestV2 {
    /// Structural validation.
    pub fn validate_public_fields(&self) -> Result<(), SidecarApiError> {
        validate_common(
            self.api_version,
            &self.request_nonce,
            &self.settlement_id,
            &self.funding_tx_hash,
            self.expected_amount_piconero,
            &self.expected_spend_public_key,
        )?;
        if self.destination.is_empty() || self.destination.len() > MAX_DESTINATION_BYTES {
            return Err(SidecarApiError::InvalidRequest);
        }
        Ok(())
    }

    /// Canonical HMAC bytes excluding `auth_tag`.
    pub fn canonical_auth_bytes(&self) -> Result<Vec<u8>, SidecarApiError> {
        self.validate_public_fields()?;
        let destination = self.destination.as_bytes();
        let length =
            u16::try_from(destination.len()).map_err(|_| SidecarApiError::BoundsExceeded)?;
        let mut output = Vec::with_capacity(16 + 2 + 32 * 6 + 8 + 2 + destination.len());
        output.extend_from_slice(b"BUILD-SWEEP\0");
        output.extend_from_slice(&self.api_version.to_be_bytes());
        output.extend_from_slice(&self.request_nonce);
        output.extend_from_slice(&self.settlement_id);
        output.extend_from_slice(&self.funding_tx_hash);
        output.extend_from_slice(&self.expected_amount_piconero.to_be_bytes());
        output.extend_from_slice(&length.to_be_bytes());
        output.extend_from_slice(destination);
        self.spend_scalar
            .expose(|bytes| output.extend_from_slice(bytes));
        output.extend_from_slice(&self.expected_spend_public_key);
        self.view_scalar
            .expose(|bytes| output.extend_from_slice(bytes));
        Ok(output)
    }
}

/// Exact signed sweep response.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BuildSweepResponseV2 {
    /// Wire version.
    pub api_version: u16,
    /// Echoed request nonce.
    pub request_nonce: [u8; 32],
    /// Consensus Monero transaction hash.
    pub tx_hash: [u8; 32],
    /// Exact signed transaction bytes.
    pub raw_tx: Vec<u8>,
}

impl BuildSweepResponseV2 {
    /// Validates response binding and bounds.
    pub fn validate_for(&self, nonce: &[u8; 32]) -> Result<(), SidecarApiError> {
        if self.api_version != API_VERSION_V2 {
            return Err(SidecarApiError::VersionMismatch);
        }
        if &self.request_nonce != nonce || self.tx_hash == [0; 32] || self.raw_tx.is_empty() {
            return Err(SidecarApiError::InvalidResponse);
        }
        if self.raw_tx.len() > MAX_RAW_TX_BYTES {
            return Err(SidecarApiError::BoundsExceeded);
        }
        Ok(())
    }
}

/// Structured sidecar error body.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SidecarErrorBody {
    /// Stable code.
    pub code: String,
    /// Non-secret summary.
    pub message: String,
    /// Whether identical retry may succeed.
    pub retryable: bool,
}

/// Wire validation failures.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SidecarApiError {
    /// Unknown version.
    #[error("sidecar API version mismatch")]
    VersionMismatch,
    /// Malformed request.
    #[error("invalid sidecar request")]
    InvalidRequest,
    /// Response not bound to request.
    #[error("invalid sidecar response")]
    InvalidResponse,
    /// Length bound exceeded.
    #[error("sidecar API bound exceeded")]
    BoundsExceeded,
}

fn validate_common(
    api_version: u16,
    request_nonce: &[u8; 32],
    settlement_id: &[u8; 32],
    funding_tx_hash: &[u8; 32],
    expected_amount_piconero: u64,
    expected_spend_public_key: &[u8; 32],
) -> Result<(), SidecarApiError> {
    if api_version != API_VERSION_V2 {
        return Err(SidecarApiError::VersionMismatch);
    }
    if request_nonce == &[0; 32]
        || settlement_id == &[0; 32]
        || funding_tx_hash == &[0; 32]
        || expected_amount_piconero == 0
        || expected_spend_public_key == &[0; 32]
    {
        return Err(SidecarApiError::InvalidRequest);
    }
    Ok(())
}

/// Length-framed Unix-domain sidecar request.
#[derive(Serialize, Deserialize)]
#[serde(tag = "method", content = "request", rename_all = "kebab-case")]
pub enum SidecarRequestV2 {
    /// Verify funding output.
    VerifyFunding(VerifyFundingRequestV2),
    /// Build an exact sweep transaction.
    BuildSweep(BuildSweepRequestV2),
}

/// Length-framed Unix-domain sidecar response.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "result", content = "body", rename_all = "kebab-case")]
pub enum SidecarResponseV2 {
    /// Verified funding.
    Funding(VerifyFundingResponseV2),
    /// Exact signed sweep.
    Sweep(BuildSweepResponseV2),
    /// Structured failure.
    Error(SidecarErrorBody),
}
