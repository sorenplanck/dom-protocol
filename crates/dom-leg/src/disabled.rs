//! Fail-closed boundary used when `real-dom-adaptor` is absent.
//!
//! I13/anti-theater: the names and argument order are the same as in the real
//! build, but no cryptographic operation exists here. Without the pin there
//! is no purpose registry, no transcript, and no verifier — the purpose
//! travels as an opaque byte and every operation returns
//! [`LegError::CryptoBackendDisabled`].

use crate::{LegError, PreSignatureBytes};
use counterparty_api::RevealedSecretBytes;
use zeroize::Zeroizing;

/// secp256k1 group order (big-endian). Used only for local canonicity.
pub const SECP256K1_ORDER: [u8; 32] = [
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
    0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B, 0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41,
];

/// Scalar canonicity: `0 < t < n`.
///
/// Local hygiene for the backend-less build. In the real build the authority
/// is `dom_scriptless_primitives::scalar_bytes_are_canonical` and this function does not
/// exist (I15).
pub fn scalar_is_canonical(scalar: &[u8; 32]) -> bool {
    if scalar.iter().all(|b| *b == 0) {
        return false;
    }
    for (s, n) in scalar.iter().zip(SECP256K1_ORDER.iter()) {
        match s.cmp(n) {
            core::cmp::Ordering::Less => return true,
            core::cmp::Ordering::Greater => return false,
            core::cmp::Ordering::Equal => {}
        }
    }
    false // equal to the order
}

/// Immutable bindings of a DOM leg session.
///
/// Without the pin there is no `PurposeV1`: we keep only the canonical byte,
/// which never enables anything.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct SessionBindings {
    /// Trusted DOM chain id.
    pub chain_id: [u8; 32],
    /// Hash of the canonical claim template.
    pub claim_template_hash: [u8; 32],
    /// Hash of the frozen transcript.
    pub transcript_hash: [u8; 32],
    /// Purpose byte, opaque in this build.
    pub purpose_byte: u8,
}

/// DOM leg session without a cryptographic backend.
pub struct DomLegSession {
    bindings: SessionBindings,
}

impl DomLegSession {
    /// Creates the session from bindings already validated against the context.
    pub fn new(bindings: SessionBindings) -> Self {
        Self { bindings }
    }

    /// Immutable bindings.
    pub fn bindings(&self) -> &SessionBindings {
        &self.bindings
    }

    /// Mandatory revalidation before any cryptographic operation:
    /// the pre-signature must belong to THIS session.
    pub fn check_belongs_to_session(&self, pre: &PreSignatureBytes) -> Result<(), LegError> {
        if pre.claim_template_hash() != self.bindings.claim_template_hash {
            return Err(LegError::TemplateMismatch);
        }
        if pre.transcript_hash() != self.bindings.transcript_hash {
            return Err(LegError::TranscriptMismatch);
        }
        Ok(())
    }

    /// Would adapt the pre-signature with `t`. Without the pin, fails closed.
    pub fn adapt_claim(
        &self,
        pre: &PreSignatureBytes,
        secret: &Zeroizing<[u8; 32]>,
    ) -> Result<Vec<u8>, LegError> {
        self.check_belongs_to_session(pre)?;
        if !scalar_is_canonical(secret) {
            return Err(LegError::NonCanonicalScalar);
        }
        Err(LegError::CryptoBackendDisabled)
    }

    /// Would extract `t`. Without the pin, fails closed.
    pub fn extract_secret(
        &self,
        pre: &PreSignatureBytes,
        _final_signature: &[u8],
    ) -> Result<RevealedSecretBytes, LegError> {
        self.check_belongs_to_session(pre)?;
        Err(LegError::CryptoBackendDisabled)
    }

    // ---------------------------------------------------------------------
    // The wire boundary — same names and shapes as the `round` build
    // ---------------------------------------------------------------------
    //
    // `round::DomLegSession` exposes these two over the real backend. They
    // exist here with identical signatures so a downstream crate compiles
    // against ONE API in both configurations; here they refuse, because
    // without the pin there is no verifier to reach. No default path fakes a
    // cryptographic result (I13).

    /// Would adapt a wire pre-signature with `t`. Without the pin, fails
    /// closed.
    pub fn adapt_claim_from_wire(
        &self,
        wire: &PreSignatureBytes,
        secret: &Zeroizing<[u8; 32]>,
    ) -> Result<Vec<u8>, LegError> {
        self.adapt_claim(wire, secret)
    }

    /// Would extract the revealed `t` as bytes. Without the pin, fails closed.
    pub fn extract_revealed_secret(
        &self,
        wire: &PreSignatureBytes,
        final_signature: &[u8],
    ) -> Result<RevealedSecretBytes, LegError> {
        self.extract_secret(wire, final_signature)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pre_signature_layout;

    fn bindings() -> SessionBindings {
        SessionBindings {
            chain_id: [9u8; 32],
            claim_template_hash: [1u8; 32],
            transcript_hash: [2u8; 32],
            purpose_byte: 0x02,
        }
    }

    fn pre_bytes(template: u8, transcript: u8) -> PreSignatureBytes {
        let mut buf = [0u8; pre_signature_layout::ENCODED_LEN];
        buf[pre_signature_layout::CLAIM_TEMPLATE_HASH].fill(template);
        buf[pre_signature_layout::ADAPTOR_POINT].fill(3);
        buf[pre_signature_layout::AGGREGATE_NONCE_HAT].fill(4);
        buf[pre_signature_layout::SCALAR_HAT].fill(5);
        buf[pre_signature_layout::TRANSCRIPT_HASH].fill(transcript);
        PreSignatureBytes::from_slice(&buf).unwrap()
    }

    #[test]
    fn session_binding_is_revalidated() {
        let s = DomLegSession::new(bindings());
        assert!(s.check_belongs_to_session(&pre_bytes(1, 2)).is_ok());
        assert_eq!(
            s.check_belongs_to_session(&pre_bytes(0xAA, 2)).unwrap_err(),
            LegError::TemplateMismatch
        );
        assert_eq!(
            s.check_belongs_to_session(&pre_bytes(1, 0xBB)).unwrap_err(),
            LegError::TranscriptMismatch
        );
    }

    #[test]
    fn scalar_canonicity_edges() {
        assert!(!scalar_is_canonical(&[0u8; 32]), "zero is not canonical");
        assert!(!scalar_is_canonical(&SECP256K1_ORDER), "n is not canonical");
        let mut above = SECP256K1_ORDER;
        above[31] = 0x42;
        assert!(!scalar_is_canonical(&above), "n+k is not canonical");
        let mut below = SECP256K1_ORDER;
        below[31] = 0x40;
        assert!(scalar_is_canonical(&below), "n-1 is canonical");
        assert!(scalar_is_canonical(&[1u8; 32]));
    }

    #[test]
    fn no_crypto_path_pretends_success_without_the_backend() {
        let s = DomLegSession::new(bindings());
        let pre = pre_bytes(1, 2);
        let secret = Zeroizing::new([7u8; 32]);
        assert_eq!(
            s.adapt_claim(&pre, &secret).unwrap_err(),
            LegError::CryptoBackendDisabled,
            "I13: no simulated cryptographic success"
        );
        assert_eq!(
            s.extract_secret(&pre, &[0u8; 65]).unwrap_err(),
            LegError::CryptoBackendDisabled,
            "I13: no simulated cryptographic success"
        );
    }

    #[test]
    fn session_mismatch_is_checked_before_the_backend() {
        // Order matters: a wrong template must fail as TemplateMismatch,
        // not as a disabled backend.
        let s = DomLegSession::new(bindings());
        let secret = Zeroizing::new([7u8; 32]);
        assert_eq!(
            s.adapt_claim(&pre_bytes(0xAA, 2), &secret).unwrap_err(),
            LegError::TemplateMismatch
        );
    }

    #[test]
    fn non_canonical_secret_is_rejected_before_the_backend() {
        let s = DomLegSession::new(bindings());
        let zero = Zeroizing::new([0u8; 32]);
        assert_eq!(
            s.adapt_claim(&pre_bytes(1, 2), &zero).unwrap_err(),
            LegError::NonCanonicalScalar
        );
    }
}
