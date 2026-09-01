//! HMAC-SHA256 authentication for the loopback signing sidecar.

#![forbid(unsafe_code)]

use hmac::{Hmac, Mac};
use sha2::Sha256;
use xmr_live_sidecar_api::{BuildSweepRequestV2, SidecarApiError, VerifyFundingRequestV2};
use zeroize::Zeroizing;

type HmacSha256 = Hmac<Sha256>;
const AUTH_DOMAIN: &[u8] = b"DOM-INTEROP/XMR-SIDECAR-AUTH/V2\0";

/// Sidecar authentication failures.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SidecarAuthError {
    /// Request failed structural validation.
    #[error("invalid sidecar request")]
    InvalidRequest,
    /// Key or tag failed.
    #[error("sidecar authentication failed")]
    AuthenticationFailed,
}

/// Zeroized local 256-bit HMAC key.
pub struct SidecarAuthKey(Zeroizing<[u8; 32]>);

impl core::fmt::Debug for SidecarAuthKey {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("SidecarAuthKey(<redacted>)")
    }
}

impl SidecarAuthKey {
    /// Imports a non-zero key.
    pub fn new(bytes: [u8; 32]) -> Result<Self, SidecarAuthError> {
        if bytes == [0; 32] {
            return Err(SidecarAuthError::AuthenticationFailed);
        }
        Ok(Self(Zeroizing::new(bytes)))
    }

    /// Signs a sweep request in place.
    pub fn sign_build(&self, request: &mut BuildSweepRequestV2) -> Result<(), SidecarAuthError> {
        request.auth_tag = [0; 32];
        request.auth_tag = self.tag(&request.canonical_auth_bytes().map_err(map_api)?)?;
        Ok(())
    }

    /// Verifies a sweep request.
    pub fn verify_build(&self, request: &BuildSweepRequestV2) -> Result<(), SidecarAuthError> {
        self.verify_bytes(
            &request.canonical_auth_bytes().map_err(map_api)?,
            &request.auth_tag,
        )
    }

    /// Signs a funding-verification request in place.
    pub fn sign_funding(
        &self,
        request: &mut VerifyFundingRequestV2,
    ) -> Result<(), SidecarAuthError> {
        request.auth_tag = [0; 32];
        request.auth_tag = self.tag(&request.canonical_auth_bytes().map_err(map_api)?)?;
        Ok(())
    }

    /// Verifies a funding-verification request.
    pub fn verify_funding(&self, request: &VerifyFundingRequestV2) -> Result<(), SidecarAuthError> {
        self.verify_bytes(
            &request.canonical_auth_bytes().map_err(map_api)?,
            &request.auth_tag,
        )
    }

    fn tag(&self, bytes: &[u8]) -> Result<[u8; 32], SidecarAuthError> {
        let mut mac = HmacSha256::new_from_slice(&self.0[..])
            .map_err(|_| SidecarAuthError::AuthenticationFailed)?;
        mac.update(AUTH_DOMAIN);
        mac.update(bytes);
        Ok(mac.finalize().into_bytes().into())
    }

    fn verify_bytes(&self, bytes: &[u8], tag: &[u8; 32]) -> Result<(), SidecarAuthError> {
        let mut mac = HmacSha256::new_from_slice(&self.0[..])
            .map_err(|_| SidecarAuthError::AuthenticationFailed)?;
        mac.update(AUTH_DOMAIN);
        mac.update(bytes);
        mac.verify_slice(tag)
            .map_err(|_| SidecarAuthError::AuthenticationFailed)
    }
}

fn map_api(_: SidecarApiError) -> SidecarAuthError {
    SidecarAuthError::InvalidRequest
}
