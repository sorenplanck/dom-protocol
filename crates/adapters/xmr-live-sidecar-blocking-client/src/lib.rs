//! Bounded authenticated blocking client used by Kaystra's synchronous ports.

#![forbid(unsafe_code)]

use reqwest::blocking::Client;
use xmr_live_sidecar_api::{
    BuildSweepRequestV2, BuildSweepResponseV2, SidecarErrorBody, VerifyFundingRequestV2,
    VerifyFundingResponseV2,
};
use xmr_raw_tx_verify::verify_exact_raw_transaction;
use xmr_sidecar_auth::SidecarAuthKey;
use xmr_spend_port::{FundingVerifyPort, SpendPortError, SweepBuildPort};

/// Loopback-only sidecar client.
pub struct BlockingSidecarPort {
    base_url: String,
    client: Client,
    auth_key: SidecarAuthKey,
}

impl core::fmt::Debug for BlockingSidecarPort {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("BlockingSidecarPort")
            .field("base_url", &self.base_url)
            .field("auth_key", &"<redacted>")
            .finish()
    }
}

impl BlockingSidecarPort {
    /// Creates finite-timeout loopback client.
    pub fn new(
        base_url: impl Into<String>,
        auth_key: SidecarAuthKey,
    ) -> Result<Self, SpendPortError> {
        let base_url = base_url.into().trim_end_matches('/').to_owned();
        if !is_loopback_url(&base_url) {
            return Err(SpendPortError::Rejected);
        }
        let client = Client::builder()
            .connect_timeout(core::time::Duration::from_secs(5))
            .timeout(core::time::Duration::from_secs(180))
            .build()
            .map_err(|_| SpendPortError::Retryable)?;
        Ok(Self {
            base_url,
            client,
            auth_key,
        })
    }

    fn classify_error(response: reqwest::blocking::Response) -> SpendPortError {
        let status = response.status();
        let body = response.json::<SidecarErrorBody>().ok();
        if status.is_server_error()
            || status.as_u16() == 429
            || body.as_ref().map(|value| value.retryable).unwrap_or(false)
        {
            SpendPortError::Retryable
        } else {
            SpendPortError::Rejected
        }
    }
}

impl FundingVerifyPort for BlockingSidecarPort {
    fn verify_funding(
        &mut self,
        mut request: VerifyFundingRequestV2,
    ) -> Result<VerifyFundingResponseV2, SpendPortError> {
        request
            .validate_public_fields()
            .map_err(|_| SpendPortError::Rejected)?;
        self.auth_key
            .sign_funding(&mut request)
            .map_err(|_| SpendPortError::Rejected)?;
        let response = self
            .client
            .post(format!("{}/v2/verify-funding", self.base_url))
            .json(&request)
            .send()
            .map_err(|_| SpendPortError::Retryable)?;
        if !response.status().is_success() {
            return Err(Self::classify_error(response));
        }
        let output = response
            .json::<VerifyFundingResponseV2>()
            .map_err(|_| SpendPortError::Rejected)?;
        output
            .validate_for(&request)
            .map_err(|_| SpendPortError::Rejected)?;
        Ok(output)
    }
}

impl SweepBuildPort for BlockingSidecarPort {
    fn build_sweep(
        &mut self,
        mut request: BuildSweepRequestV2,
    ) -> Result<BuildSweepResponseV2, SpendPortError> {
        request
            .validate_public_fields()
            .map_err(|_| SpendPortError::Rejected)?;
        self.auth_key
            .sign_build(&mut request)
            .map_err(|_| SpendPortError::Rejected)?;
        let nonce = request.request_nonce;
        let response = self
            .client
            .post(format!("{}/v2/build-sweep", self.base_url))
            .json(&request)
            .send()
            .map_err(|_| SpendPortError::Retryable)?;
        if !response.status().is_success() {
            return Err(Self::classify_error(response));
        }
        let output = response
            .json::<BuildSweepResponseV2>()
            .map_err(|_| SpendPortError::Rejected)?;
        output
            .validate_for(&nonce)
            .map_err(|_| SpendPortError::Rejected)?;
        // Independently re-parse the sidecar's bytes and require the consensus
        // hash to equal the one it announced, before these bytes are ever
        // persisted or broadcast. Without this the DOM side would trust the
        // GPL sidecar for the content of the transaction it signs — the exact
        // boundary the process isolation exists to protect.
        verify_exact_raw_transaction(&output.raw_tx, output.tx_hash)
            .map_err(|_| SpendPortError::Rejected)?;
        Ok(output)
    }
}

fn is_loopback_url(value: &str) -> bool {
    value.starts_with("http://127.0.0.1:")
        || value.starts_with("http://localhost:")
        || value.starts_with("http://[::1]:")
}
