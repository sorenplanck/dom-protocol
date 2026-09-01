//! Wire-compatible copy of the DOM-side API. This crate is intentionally
//! self-contained so it can be built inside the pinned Eigenwallet workspace.

use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

pub const API_VERSION_V2: u16 = 2;
pub const MAX_DESTINATION_BYTES: usize = 256;
pub const MAX_RAW_TX_BYTES: usize = 512 * 1024;
pub const MAX_HTTP_BODY_BYTES: usize = 1024 * 1024;
pub const MAX_FRAME_BYTES: usize = 1024 * 1024;

#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(transparent)]
pub struct SecretScalarBytes([u8; 32]);

impl core::fmt::Debug for SecretScalarBytes {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("SecretScalarBytes(<redacted>)")
    }
}

impl SecretScalarBytes {
    pub fn expose<R>(&self, operation: impl FnOnce(&[u8; 32]) -> R) -> R {
        operation(&self.0)
    }
}

#[derive(Serialize, Deserialize)]
pub struct VerifyFundingRequestV2 {
    pub api_version: u16,
    pub request_nonce: [u8; 32],
    pub settlement_id: [u8; 32],
    pub funding_tx_hash: [u8; 32],
    pub expected_amount_piconero: u64,
    pub expected_spend_public_key: [u8; 32],
    pub view_scalar: SecretScalarBytes,
    pub auth_tag: [u8; 32],
}

impl Drop for VerifyFundingRequestV2 {
    fn drop(&mut self) { self.auth_tag.zeroize(); }
}

impl VerifyFundingRequestV2 {
    pub fn validate_public_fields(&self) -> Result<(), WireError> {
        validate_common(
            self.api_version,
            &self.request_nonce,
            &self.settlement_id,
            &self.funding_tx_hash,
            self.expected_amount_piconero,
            &self.expected_spend_public_key,
        )
    }

    pub fn canonical_auth_bytes(&self) -> Result<Vec<u8>, WireError> {
        self.validate_public_fields()?;
        let mut output = Vec::with_capacity(16 + 2 + 32 * 5 + 8);
        output.extend_from_slice(b"VERIFY-FUNDING\0");
        output.extend_from_slice(&self.api_version.to_be_bytes());
        output.extend_from_slice(&self.request_nonce);
        output.extend_from_slice(&self.settlement_id);
        output.extend_from_slice(&self.funding_tx_hash);
        output.extend_from_slice(&self.expected_amount_piconero.to_be_bytes());
        output.extend_from_slice(&self.expected_spend_public_key);
        self.view_scalar.expose(|bytes| output.extend_from_slice(bytes));
        Ok(output)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VerifyFundingResponseV2 {
    pub api_version: u16,
    pub request_nonce: [u8; 32],
    pub funding_tx_hash: [u8; 32],
    pub event_index: u32,
    pub received_amount_piconero: u64,
    pub spendable: bool,
}

#[derive(Serialize, Deserialize)]
pub struct BuildSweepRequestV2 {
    pub api_version: u16,
    pub request_nonce: [u8; 32],
    pub settlement_id: [u8; 32],
    pub funding_tx_hash: [u8; 32],
    pub expected_amount_piconero: u64,
    pub destination: String,
    pub spend_scalar: SecretScalarBytes,
    pub expected_spend_public_key: [u8; 32],
    pub view_scalar: SecretScalarBytes,
    pub auth_tag: [u8; 32],
}

impl Drop for BuildSweepRequestV2 {
    fn drop(&mut self) { self.auth_tag.zeroize(); }
}

impl BuildSweepRequestV2 {
    pub fn validate_public_fields(&self) -> Result<(), WireError> {
        validate_common(
            self.api_version,
            &self.request_nonce,
            &self.settlement_id,
            &self.funding_tx_hash,
            self.expected_amount_piconero,
            &self.expected_spend_public_key,
        )?;
        if self.destination.is_empty() || self.destination.len() > MAX_DESTINATION_BYTES {
            return Err(WireError::InvalidRequest);
        }
        Ok(())
    }

    pub fn canonical_auth_bytes(&self) -> Result<Vec<u8>, WireError> {
        self.validate_public_fields()?;
        let destination = self.destination.as_bytes();
        let length = u16::try_from(destination.len()).map_err(|_| WireError::BoundsExceeded)?;
        let mut output = Vec::with_capacity(16 + 2 + 32 * 6 + 8 + 2 + destination.len());
        output.extend_from_slice(b"BUILD-SWEEP\0");
        output.extend_from_slice(&self.api_version.to_be_bytes());
        output.extend_from_slice(&self.request_nonce);
        output.extend_from_slice(&self.settlement_id);
        output.extend_from_slice(&self.funding_tx_hash);
        output.extend_from_slice(&self.expected_amount_piconero.to_be_bytes());
        output.extend_from_slice(&length.to_be_bytes());
        output.extend_from_slice(destination);
        self.spend_scalar.expose(|bytes| output.extend_from_slice(bytes));
        output.extend_from_slice(&self.expected_spend_public_key);
        self.view_scalar.expose(|bytes| output.extend_from_slice(bytes));
        Ok(output)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BuildSweepResponseV2 {
    pub api_version: u16,
    pub request_nonce: [u8; 32],
    pub tx_hash: [u8; 32],
    pub raw_tx: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SidecarErrorBody {
    pub code: String,
    pub message: String,
    pub retryable: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum WireError {
    #[error("version mismatch")]
    VersionMismatch,
    #[error("invalid request")]
    InvalidRequest,
    #[error("bound exceeded")]
    BoundsExceeded,
}

fn validate_common(
    version: u16,
    request_nonce: &[u8; 32],
    settlement_id: &[u8; 32],
    funding_tx_hash: &[u8; 32],
    amount: u64,
    spend_public_key: &[u8; 32],
) -> Result<(), WireError> {
    if version != API_VERSION_V2 { return Err(WireError::VersionMismatch); }
    if request_nonce == &[0; 32]
        || settlement_id == &[0; 32]
        || funding_tx_hash == &[0; 32]
        || spend_public_key == &[0; 32]
        || amount == 0
    {
        return Err(WireError::InvalidRequest);
    }
    Ok(())
}


#[derive(Serialize, Deserialize)]
#[serde(tag = "method", content = "request", rename_all = "kebab-case")]
pub enum SidecarRequestV2 {
    VerifyFunding(VerifyFundingRequestV2),
    BuildSweep(BuildSweepRequestV2),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "result", content = "body", rename_all = "kebab-case")]
pub enum SidecarResponseV2 {
    Funding(VerifyFundingResponseV2),
    Sweep(BuildSweepResponseV2),
    Error(SidecarErrorBody),
}
