//! HMAC-SHA256 authentication for the loopback signing sidecar.

#![forbid(unsafe_code)]

use hmac::{Hmac, Mac};
use sha2::Sha256;
use xmr_live_sidecar_api::{BuildSweepRequestV2, SidecarApiError, VerifyFundingRequestV2};
use zeroize::Zeroizing;

type HmacSha256 = Hmac<Sha256>;
const AUTH_DOMAIN: &[u8] = b"DOM-INTEROP/XMR-SIDECAR-AUTH/V2\0";
/// Distinct domain for the connection-opening challenge: a challenge proof
/// can never be replayed as a request tag, nor a request tag as a proof.
const CHALLENGE_DOMAIN: &[u8] = b"DOM-INTEROP/XMR-SIDECAR-CHALLENGE/V1\0";

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

    /// Computes the sidecar's proof of key possession over one challenge
    /// nonce. The sidecar side of the handshake; also what test doubles use.
    pub fn challenge_proof(&self, nonce: &[u8; 32]) -> Result<[u8; 32], SidecarAuthError> {
        if nonce == &[0; 32] {
            return Err(SidecarAuthError::InvalidRequest);
        }
        self.tag_in_domain(CHALLENGE_DOMAIN, nonce)
    }

    /// Verifies a sidecar's challenge proof before any secret is transmitted.
    pub fn verify_challenge_proof(
        &self,
        nonce: &[u8; 32],
        proof: &[u8; 32],
    ) -> Result<(), SidecarAuthError> {
        if nonce == &[0; 32] {
            return Err(SidecarAuthError::InvalidRequest);
        }
        self.verify_bytes_in_domain(CHALLENGE_DOMAIN, nonce, proof)
    }

    fn tag(&self, bytes: &[u8]) -> Result<[u8; 32], SidecarAuthError> {
        self.tag_in_domain(AUTH_DOMAIN, bytes)
    }

    fn verify_bytes(&self, bytes: &[u8], tag: &[u8; 32]) -> Result<(), SidecarAuthError> {
        self.verify_bytes_in_domain(AUTH_DOMAIN, bytes, tag)
    }

    fn tag_in_domain(&self, domain: &[u8], bytes: &[u8]) -> Result<[u8; 32], SidecarAuthError> {
        let mut mac = HmacSha256::new_from_slice(&self.0[..])
            .map_err(|_| SidecarAuthError::AuthenticationFailed)?;
        mac.update(domain);
        mac.update(bytes);
        Ok(mac.finalize().into_bytes().into())
    }

    fn verify_bytes_in_domain(
        &self,
        domain: &[u8],
        bytes: &[u8],
        tag: &[u8; 32],
    ) -> Result<(), SidecarAuthError> {
        let mut mac = HmacSha256::new_from_slice(&self.0[..])
            .map_err(|_| SidecarAuthError::AuthenticationFailed)?;
        mac.update(domain);
        mac.update(bytes);
        mac.verify_slice(tag)
            .map_err(|_| SidecarAuthError::AuthenticationFailed)
    }
}

fn map_api(_: SidecarApiError) -> SidecarAuthError {
    SidecarAuthError::InvalidRequest
}

#[cfg(test)]
mod tests {
    use xmr_live_sidecar_api::{SecretScalarBytes, VerifyFundingRequestV2, API_VERSION_V2};

    use super::*;

    const KEY: [u8; 32] = [7; 32];

    #[test]
    fn challenge_proof_round_trips_and_binds_to_the_exact_nonce() {
        let key = SidecarAuthKey::new(KEY).unwrap();
        let nonce = [1_u8; 32];
        let proof = key.challenge_proof(&nonce).unwrap();
        assert!(key.verify_challenge_proof(&nonce, &proof).is_ok());
        let mut other_nonce = nonce;
        other_nonce[0] ^= 1;
        assert_eq!(
            key.verify_challenge_proof(&other_nonce, &proof).err(),
            Some(SidecarAuthError::AuthenticationFailed)
        );
        let mut tampered = proof;
        tampered[31] ^= 1;
        assert_eq!(
            key.verify_challenge_proof(&nonce, &tampered).err(),
            Some(SidecarAuthError::AuthenticationFailed)
        );
        let wrong_key = SidecarAuthKey::new([9; 32]).unwrap();
        assert_eq!(
            wrong_key.verify_challenge_proof(&nonce, &proof).err(),
            Some(SidecarAuthError::AuthenticationFailed)
        );
        assert_eq!(
            key.challenge_proof(&[0; 32]).err(),
            Some(SidecarAuthError::InvalidRequest)
        );
    }

    #[test]
    fn challenge_domain_is_separated_from_the_request_tag_domain() {
        // A request whose canonical bytes are exactly one 32-byte nonce does
        // not exist, but the domains must differ even for equal messages:
        // tag(domain=AUTH, m) != proof(domain=CHALLENGE, m) for every m, so
        // neither artifact can ever stand in for the other.
        let key = SidecarAuthKey::new(KEY).unwrap();
        let mut request = VerifyFundingRequestV2 {
            api_version: API_VERSION_V2,
            request_nonce: [1; 32],
            settlement_id: [2; 32],
            funding_tx_hash: [3; 32],
            expected_amount_piconero: 1_000,
            expected_spend_public_key: [4; 32],
            view_scalar: SecretScalarBytes::new([5; 32]),
            auth_tag: [0; 32],
        };
        key.sign_funding(&mut request).unwrap();
        // The request tag must not verify as a challenge proof over any of
        // the request's own 32-byte fields.
        for nonce in [request.request_nonce, request.settlement_id] {
            assert!(key
                .verify_challenge_proof(&nonce, &request.auth_tag)
                .is_err());
        }
    }
}
