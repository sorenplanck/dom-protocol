//! Frozen G1a v1 nonce commitment and binding transcripts.

use crate::{AdaptorError, PurposeV1, Result};
use dom_crypto::{
    blake2b_256_tagged, scriptless_bind_public_nonces, Hash256, PartialSig, PublicKey,
};

const NONCE_COMMIT_TAG_V1: &str = "DOM:scriptless-nonce-commit:v1";
const NONCE_BIND_TAG_V1: &str = "DOM:scriptless-sig-nonce-bind:v1";

/// Fixed fields shared by the v1 collective nonce-binding transcript.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BindingContextV1 {
    /// DOM chain identifier.
    pub chain_id: [u8; 32],
    /// Unique Scriptless session identifier.
    pub session_id: [u8; 32],
    /// Closed G1a purpose.
    pub purpose: PurposeV1,
    /// Digest of the immutable transaction template.
    pub template_hash: [u8; 32],
}

/// One participant's ordered public-key and two-nonce tuple.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParticipantPublicNoncesV1 {
    /// Stable participant index used to enforce canonical ordering.
    pub participant_index: u16,
    /// Participant signing public key.
    pub signing_key: PublicKey,
    /// First public nonce.
    pub first_nonce: PublicKey,
    /// Second public nonce.
    pub second_nonce: PublicKey,
}

/// Canonical nonzero binding factor produced by the frozen v1 transcript.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BindingFactorV1(PartialSig);

impl BindingFactorV1 {
    /// Return the canonical 32-byte big-endian factor.
    pub fn to_be_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    /// Compute `R1 + b*R2` through the authoritative DOM arithmetic boundary.
    pub fn bind_public_nonces(&self, first: &PublicKey, second: &PublicKey) -> Result<PublicKey> {
        scriptless_bind_public_nonces(first, second, &self.0).map_err(Into::into)
    }
}

fn validate_adaptor_grammar(purpose: PurposeV1, adaptor_point: Option<&PublicKey>) -> Result<()> {
    purpose.require_strict_phase1()?;
    match (purpose, adaptor_point) {
        (PurposeV1::ClaimAdaptor, Some(_)) | (PurposeV1::Funding | PurposeV1::Refund, None) => {
            Ok(())
        }
        (PurposeV1::ClaimAdaptor, None) => Err(AdaptorError::InvalidTranscript(
            "ClaimAdaptorV1 requires an adaptor point",
        )),
        (PurposeV1::Funding | PurposeV1::Refund, Some(_)) => Err(AdaptorError::InvalidTranscript(
            "FundingV1 and RefundV1 omit the adaptor point",
        )),
        (PurposeV1::Sponsor, _) => Err(AdaptorError::PurposeNotAuthorized(
            PurposeV1::Sponsor.to_byte(),
        )),
    }
}

/// Hash the frozen nonce-commitment preimage.
#[allow(clippy::too_many_arguments)]
pub fn nonce_commitment_hash_v1(
    chain_id: &[u8; 32],
    session_id: &[u8; 32],
    participant_id: &[u8; 32],
    purpose: PurposeV1,
    template_hash: &[u8; 32],
    first_nonce: &PublicKey,
    second_nonce: &PublicKey,
    adaptor_point: Option<&PublicKey>,
) -> Result<Hash256> {
    validate_adaptor_grammar(purpose, adaptor_point)?;
    let mut body = Vec::with_capacity(32 + 32 + 32 + 1 + 32 + 33 + 33 + 33);
    body.extend_from_slice(chain_id);
    body.extend_from_slice(session_id);
    body.extend_from_slice(participant_id);
    body.push(purpose.to_byte());
    body.extend_from_slice(template_hash);
    body.extend_from_slice(&first_nonce.to_compressed_bytes());
    body.extend_from_slice(&second_nonce.to_compressed_bytes());
    if let Some(point) = adaptor_point {
        body.extend_from_slice(&point.to_compressed_bytes());
    }
    Ok(blake2b_256_tagged(NONCE_COMMIT_TAG_V1, &body))
}

/// Derive the frozen collective nonce-binding factor.
///
/// Participants must be supplied in strictly increasing participant-index
/// order. The tagged digest is interpreted directly as a big-endian scalar;
/// zero or values at least the group order are rejected without reduction or
/// retry.
pub fn binding_factor_v1(
    context: &BindingContextV1,
    participants: &[ParticipantPublicNoncesV1],
    adaptor_point: Option<&PublicKey>,
) -> Result<BindingFactorV1> {
    validate_adaptor_grammar(context.purpose, adaptor_point)?;
    if participants.is_empty() {
        return Err(AdaptorError::InvalidTranscript(
            "binding participant list must not be empty",
        ));
    }
    if participants
        .windows(2)
        .any(|pair| pair[0].participant_index >= pair[1].participant_index)
    {
        return Err(AdaptorError::InvalidTranscript(
            "participants must have unique strictly increasing indexes",
        ));
    }
    if participants.windows(2).any(|pair| {
        pair[0].signing_key.to_compressed_bytes() >= pair[1].signing_key.to_compressed_bytes()
    }) {
        return Err(AdaptorError::InvalidTranscript(
            "participant signing keys must follow the canonical signing roster",
        ));
    }
    for (position, participant) in participants.iter().enumerate() {
        for other in &participants[position + 1..] {
            if participant.signing_key == other.signing_key {
                return Err(AdaptorError::InvalidTranscript(
                    "participant signing keys must be unique",
                ));
            }
            if participant.first_nonce == other.first_nonce
                || participant.first_nonce == other.second_nonce
                || participant.second_nonce == other.first_nonce
                || participant.second_nonce == other.second_nonce
            {
                return Err(AdaptorError::InvalidTranscript(
                    "public nonces must be unique across participants",
                ));
            }
        }
    }
    let count = u32::try_from(participants.len())
        .map_err(|_| AdaptorError::InvalidTranscript("participant count exceeds u32"))?;
    let public_key_bytes =
        participants
            .len()
            .checked_mul(33)
            .ok_or(AdaptorError::InvalidTranscript(
                "participant list size overflow",
            ))?;
    let nonce_bytes = participants
        .len()
        .checked_mul(66)
        .ok_or(AdaptorError::InvalidTranscript("nonce list size overflow"))?;
    let capacity = 97usize
        .checked_add(4)
        .and_then(|value| value.checked_add(public_key_bytes))
        .and_then(|value| value.checked_add(4))
        .and_then(|value| value.checked_add(nonce_bytes))
        .and_then(|value| value.checked_add(adaptor_point.map_or(0, |_| 33)))
        .ok_or(AdaptorError::InvalidTranscript(
            "binding transcript size overflow",
        ))?;

    let mut body = Vec::with_capacity(capacity);
    body.extend_from_slice(&context.chain_id);
    body.extend_from_slice(&context.session_id);
    body.push(context.purpose.to_byte());
    body.extend_from_slice(&context.template_hash);
    body.extend_from_slice(&count.to_le_bytes());
    for participant in participants {
        body.extend_from_slice(&participant.signing_key.to_compressed_bytes());
    }
    body.extend_from_slice(&count.to_le_bytes());
    for participant in participants {
        body.extend_from_slice(&participant.first_nonce.to_compressed_bytes());
        body.extend_from_slice(&participant.second_nonce.to_compressed_bytes());
    }
    if let Some(point) = adaptor_point {
        body.extend_from_slice(&point.to_compressed_bytes());
    }

    let digest = blake2b_256_tagged(NONCE_BIND_TAG_V1, &body);
    let factor = PartialSig::from_bytes(digest.as_bytes()).map_err(AdaptorError::from)?;
    Ok(BindingFactorV1(factor))
}
