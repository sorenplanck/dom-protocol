//! Canonical fixed-width G1a v1 message payloads.

use crate::error::{exact_array, AdaptorError, Result};
use dom_crypto::{PartialSig, PublicKey, schnorr_challenge};
use dom_scriptless_primitives::{scriptless_verify_bound_partial};

/// Closed and versioned purpose registry from Master Specification Appendix E.6.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum PurposeV1 {
    /// Standard refund signature.
    Refund = 0x01,
    /// Claim adaptor pre-signature.
    ClaimAdaptor = 0x02,
    /// Funding signature.
    Funding = 0x03,
    /// Sponsor codec value; strict Phase 1 execution is not yet authorized.
    Sponsor = 0x04,
}

impl PurposeV1 {
    /// Return the frozen one-byte purpose encoding.
    pub const fn to_byte(self) -> u8 {
        self as u8
    }

    /// Return whether the strict Phase 1 policy authorizes execution.
    pub const fn is_strict_v1_authorized(self) -> bool {
        !matches!(self, Self::Sponsor)
    }

    /// Enforce the currently authorized strict Phase 1 signing purposes.
    ///
    /// Sponsor is part of the canonical codec registry but has no authorized
    /// Phase 1 signing flow. Recognizing its byte must never activate it.
    pub fn require_strict_phase1(self) -> Result<Self> {
        match self {
            Self::Refund | Self::ClaimAdaptor | Self::Funding => Ok(self),
            Self::Sponsor => Err(AdaptorError::PurposeNotAuthorized(self.to_byte())),
        }
    }
}

impl TryFrom<u8> for PurposeV1 {
    type Error = AdaptorError;

    fn try_from(value: u8) -> Result<Self> {
        match value {
            0x01 => Ok(Self::Refund),
            0x02 => Ok(Self::ClaimAdaptor),
            0x03 => Ok(Self::Funding),
            0x04 => Ok(Self::Sponsor),
            other => Err(AdaptorError::UnknownPurpose(other)),
        }
    }
}

/// Canonical 35-byte nonce-commitment payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NonceCommitmentV1 {
    purpose: PurposeV1,
    participant_index: u16,
    nonce_reveal_hash: [u8; 32],
}

impl NonceCommitmentV1 {
    /// Canonical encoded length.
    pub const ENCODED_LEN: usize = 35;

    /// Construct a commitment payload from already validated fields.
    pub const fn new(
        purpose: PurposeV1,
        participant_index: u16,
        nonce_reveal_hash: [u8; 32],
    ) -> Self {
        Self {
            purpose,
            participant_index,
            nonce_reveal_hash,
        }
    }

    /// Parse an exact canonical payload and reject trailing or missing bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let bytes = exact_array::<{ Self::ENCODED_LEN }>("SigNonceCommitV1", bytes)?;
        let purpose = PurposeV1::try_from(bytes[0])?;
        let participant_index = u16::from_le_bytes([bytes[1], bytes[2]]);
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&bytes[3..]);
        Ok(Self::new(purpose, participant_index, hash))
    }

    /// Serialize the exact canonical payload.
    pub fn to_bytes(&self) -> [u8; Self::ENCODED_LEN] {
        let mut bytes = [0u8; Self::ENCODED_LEN];
        bytes[0] = self.purpose.to_byte();
        bytes[1..3].copy_from_slice(&self.participant_index.to_le_bytes());
        bytes[3..].copy_from_slice(&self.nonce_reveal_hash);
        bytes
    }

    /// Return the purpose.
    pub const fn purpose(&self) -> PurposeV1 {
        self.purpose
    }

    /// Return the participant index.
    pub const fn participant_index(&self) -> u16 {
        self.participant_index
    }

    /// Return the committed reveal digest.
    pub const fn nonce_reveal_hash(&self) -> &[u8; 32] {
        &self.nonce_reveal_hash
    }
}

/// Canonical 69-byte public nonce-reveal payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NonceRevealV1 {
    purpose: PurposeV1,
    participant_index: u16,
    first: PublicKey,
    second: PublicKey,
}

impl NonceRevealV1 {
    /// Canonical encoded length.
    pub const ENCODED_LEN: usize = 69;

    /// Construct a reveal from canonical public points.
    pub const fn new(
        purpose: PurposeV1,
        participant_index: u16,
        first: PublicKey,
        second: PublicKey,
    ) -> Self {
        Self {
            purpose,
            participant_index,
            first,
            second,
        }
    }

    /// Parse an exact canonical payload.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let bytes = exact_array::<{ Self::ENCODED_LEN }>("SigNonceRevealV1", bytes)?;
        let purpose = PurposeV1::try_from(bytes[0])?;
        let participant_index = u16::from_le_bytes([bytes[1], bytes[2]]);
        let first = PublicKey::from_compressed_bytes(&bytes[3..36])?;
        let second = PublicKey::from_compressed_bytes(&bytes[36..69])?;
        Ok(Self::new(purpose, participant_index, first, second))
    }

    /// Serialize the exact canonical payload.
    pub fn to_bytes(&self) -> [u8; Self::ENCODED_LEN] {
        let mut bytes = [0u8; Self::ENCODED_LEN];
        bytes[0] = self.purpose.to_byte();
        bytes[1..3].copy_from_slice(&self.participant_index.to_le_bytes());
        bytes[3..36].copy_from_slice(&self.first.to_compressed_bytes());
        bytes[36..69].copy_from_slice(&self.second.to_compressed_bytes());
        bytes
    }

    /// Return the purpose.
    pub const fn purpose(&self) -> PurposeV1 {
        self.purpose
    }

    /// Return the participant index.
    pub const fn participant_index(&self) -> u16 {
        self.participant_index
    }

    /// Return the first public nonce.
    pub const fn first(&self) -> &PublicKey {
        &self.first
    }

    /// Return the second public nonce.
    pub const fn second(&self) -> &PublicKey {
        &self.second
    }
}

/// Canonical 67-byte partial-signature payload.
///
/// This type intentionally implements neither `Clone` nor `Debug`; partial
/// signatures are irreversible signing material.
pub struct PartialSignatureV1 {
    purpose: PurposeV1,
    participant_index: u16,
    template_hash: [u8; 32],
    partial: PartialSig,
}

impl PartialSignatureV1 {
    /// Canonical encoded length.
    pub const ENCODED_LEN: usize = 67;

    /// Construct a canonical partial-signature payload.
    pub const fn new(
        purpose: PurposeV1,
        participant_index: u16,
        template_hash: [u8; 32],
        partial: PartialSig,
    ) -> Self {
        Self {
            purpose,
            participant_index,
            template_hash,
            partial,
        }
    }

    /// Parse an exact canonical payload.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let bytes = exact_array::<{ Self::ENCODED_LEN }>("PartialSignatureV1", bytes)?;
        let purpose = PurposeV1::try_from(bytes[0])?;
        let participant_index = u16::from_le_bytes([bytes[1], bytes[2]]);
        let mut template_hash = [0u8; 32];
        template_hash.copy_from_slice(&bytes[3..35]);
        let partial = PartialSig::from_bytes(&bytes[35..])?;
        Ok(Self::new(
            purpose,
            participant_index,
            template_hash,
            partial,
        ))
    }

    /// Serialize the exact canonical payload.
    pub fn to_bytes(&self) -> [u8; Self::ENCODED_LEN] {
        let mut bytes = [0u8; Self::ENCODED_LEN];
        bytes[0] = self.purpose.to_byte();
        bytes[1..3].copy_from_slice(&self.participant_index.to_le_bytes());
        bytes[3..35].copy_from_slice(&self.template_hash);
        bytes[35..].copy_from_slice(&self.partial.to_bytes());
        bytes
    }

    /// Return the purpose.
    pub const fn purpose(&self) -> PurposeV1 {
        self.purpose
    }

    /// Return the participant index.
    pub const fn participant_index(&self) -> u16 {
        self.participant_index
    }

    /// Return the bound template digest.
    pub const fn template_hash(&self) -> &[u8; 32] {
        &self.template_hash
    }

    /// Return the authoritative DOM partial scalar.
    pub const fn partial(&self) -> &PartialSig {
        &self.partial
    }

    /// Verify the bound partial equation with the authoritative DOM challenge.
    ///
    /// The expected purpose and template are checked before any arithmetic so
    /// a structurally valid partial cannot be replayed across purposes or
    /// templates.
    #[allow(clippy::too_many_arguments)]
    pub fn verify_bound(
        &self,
        expected_purpose: PurposeV1,
        expected_template_hash: &[u8; 32],
        bound_public_nonce: &PublicKey,
        participant_key: &PublicKey,
        aggregate_nonce_hat: &PublicKey,
        aggregate_signing_key: &PublicKey,
        chain_id: &[u8; 32],
        kernel_message: &[u8],
    ) -> Result<bool> {
        self.purpose.require_strict_phase1()?;
        expected_purpose.require_strict_phase1()?;
        if self.purpose != expected_purpose {
            return Err(AdaptorError::InvalidTranscript(
                "partial signature purpose does not match the session",
            ));
        }
        if &self.template_hash != expected_template_hash {
            return Err(AdaptorError::InvalidTranscript(
                "partial signature template does not match the session",
            ));
        }
        let challenge = schnorr_challenge(
            &aggregate_nonce_hat.to_compressed_bytes(),
            aggregate_signing_key,
            chain_id,
            kernel_message,
        );
        scriptless_verify_bound_partial(
            &self.partial,
            bound_public_nonce,
            participant_key,
            challenge.as_bytes(),
        )
        .map_err(Into::into)
    }
}
