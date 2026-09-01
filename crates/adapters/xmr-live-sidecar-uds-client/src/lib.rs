//! Authenticated bounded blocking Unix-domain sidecar client.

#![forbid(unsafe_code)]

use std::{
    io::{Read, Write},
    path::{Path, PathBuf},
    time::Duration,
};

use xmr_live_sidecar_api::{
    BuildSweepRequestV2, BuildSweepResponseV2, SidecarRequestV2, SidecarResponseV2,
    VerifyFundingRequestV2, VerifyFundingResponseV2, MAX_FRAME_BYTES,
};
use xmr_sidecar_auth::SidecarAuthKey;
use xmr_spend_port::{FundingVerifyPort, SpendPortError, SweepBuildPort};

/// Preferred Linux sidecar transport.
pub struct BlockingUdsSidecarPort {
    socket_path: PathBuf,
    timeout: Duration,
    auth_key: SidecarAuthKey,
}

impl core::fmt::Debug for BlockingUdsSidecarPort {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("BlockingUdsSidecarPort")
            .field("socket_path", &self.socket_path)
            .field("timeout", &self.timeout)
            .field("auth_key", &"<redacted>")
            .finish()
    }
}

impl BlockingUdsSidecarPort {
    /// Constructs a finite-timeout client.
    pub fn new(
        socket_path: impl Into<PathBuf>,
        auth_key: SidecarAuthKey,
    ) -> Result<Self, SpendPortError> {
        let socket_path = socket_path.into();
        if socket_path.as_os_str().is_empty() {
            return Err(SpendPortError::Rejected);
        }
        Ok(Self {
            socket_path,
            timeout: Duration::from_secs(180),
            auth_key,
        })
    }

    /// Socket path.
    pub fn socket_path(&self) -> &Path {
        &self.socket_path
    }

    #[cfg(unix)]
    fn call(&self, request: &SidecarRequestV2) -> Result<SidecarResponseV2, SpendPortError> {
        use std::os::unix::net::UnixStream;
        let bytes = serde_json::to_vec(request).map_err(|_| SpendPortError::Rejected)?;
        if bytes.is_empty() || bytes.len() > MAX_FRAME_BYTES {
            return Err(SpendPortError::Rejected);
        }
        let mut stream =
            UnixStream::connect(&self.socket_path).map_err(|_| SpendPortError::Retryable)?;
        stream
            .set_read_timeout(Some(self.timeout))
            .map_err(|_| SpendPortError::Retryable)?;
        stream
            .set_write_timeout(Some(self.timeout))
            .map_err(|_| SpendPortError::Retryable)?;
        let length = u32::try_from(bytes.len()).map_err(|_| SpendPortError::Rejected)?;
        stream
            .write_all(&length.to_be_bytes())
            .map_err(|_| SpendPortError::Retryable)?;
        stream
            .write_all(&bytes)
            .map_err(|_| SpendPortError::Retryable)?;
        stream.flush().map_err(|_| SpendPortError::Retryable)?;
        let mut prefix = [0_u8; 4];
        stream
            .read_exact(&mut prefix)
            .map_err(|_| SpendPortError::Retryable)?;
        let response_len = u32::from_be_bytes(prefix) as usize;
        if response_len == 0 || response_len > MAX_FRAME_BYTES {
            return Err(SpendPortError::Rejected);
        }
        let mut response = vec![0_u8; response_len];
        stream
            .read_exact(&mut response)
            .map_err(|_| SpendPortError::Retryable)?;
        serde_json::from_slice(&response).map_err(|_| SpendPortError::Rejected)
    }

    #[cfg(not(unix))]
    fn call(&self, _request: &SidecarRequestV2) -> Result<SidecarResponseV2, SpendPortError> {
        Err(SpendPortError::Rejected)
    }

    fn classify_error(error: xmr_live_sidecar_api::SidecarErrorBody) -> SpendPortError {
        if error.retryable {
            SpendPortError::Retryable
        } else {
            SpendPortError::Rejected
        }
    }
}

impl FundingVerifyPort for BlockingUdsSidecarPort {
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
        match self.call(&SidecarRequestV2::VerifyFunding(request))? {
            SidecarResponseV2::Funding(response) => Ok(response),
            SidecarResponseV2::Error(error) => Err(Self::classify_error(error)),
            SidecarResponseV2::Sweep(_) => Err(SpendPortError::Rejected),
        }
    }
}

impl SweepBuildPort for BlockingUdsSidecarPort {
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
        match self.call(&SidecarRequestV2::BuildSweep(request))? {
            SidecarResponseV2::Sweep(response) => {
                response
                    .validate_for(&nonce)
                    .map_err(|_| SpendPortError::Rejected)?;
                Ok(response)
            }
            SidecarResponseV2::Error(error) => Err(Self::classify_error(error)),
            SidecarResponseV2::Funding(_) => Err(SpendPortError::Rejected),
        }
    }
}
