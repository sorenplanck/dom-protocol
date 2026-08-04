//! Ratified closed registries and canonical SessionContextV1 encoding.

use crate::{AdaptorError, PurposeV1, Result};
use dom_crypto::{PublicKey, ScriptlessSecretScalar};

/// Ratified V1 direction registry, stable by protocol role.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum DirectionV1 {
    /// Party that created the session identifier and sent the first message.
    Initiator = 0x01,
    /// Party that accepted the first message and sent the first response.
    Responder = 0x02,
}

impl DirectionV1 {
    /// Return the exact one-byte encoding.
    pub const fn to_byte(self) -> u8 {
        self as u8
    }
}

impl TryFrom<u8> for DirectionV1 {
    type Error = AdaptorError;

    fn try_from(value: u8) -> Result<Self> {
        match value {
            0x01 => Ok(Self::Initiator),
            0x02 => Ok(Self::Responder),
            other => Err(AdaptorError::UnknownDirection(other)),
        }
    }
}

/// Ratified signing-only V1 phase subregistry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum SigningPhaseV1 {
    /// Nonce-commitment phase.
    SigNonceCommit = 0x0100,
    /// Nonce-reveal phase.
    SigNonceReveal = 0x0101,
    /// Collective nonce-binding phase.
    SigBinding = 0x0102,
    /// Participant partial-signature phase.
    SigPartial = 0x0103,
    /// Adaptor-secret application phase.
    SigAdapt = 0x0104,
    /// Adaptor-secret extraction phase.
    SigExtract = 0x0105,
}

impl SigningPhaseV1 {
    /// Return the exact little-endian two-byte encoding.
    pub const fn to_le_bytes(self) -> [u8; 2] {
        (self as u16).to_le_bytes()
    }
}

impl TryFrom<u16> for SigningPhaseV1 {
    type Error = AdaptorError;

    fn try_from(value: u16) -> Result<Self> {
        match value {
            0x0100 => Ok(Self::SigNonceCommit),
            0x0101 => Ok(Self::SigNonceReveal),
            0x0102 => Ok(Self::SigBinding),
            0x0103 => Ok(Self::SigPartial),
            0x0104 => Ok(Self::SigAdapt),
            0x0105 => Ok(Self::SigExtract),
            other => Err(AdaptorError::UnknownSigningPhase(other)),
        }
    }
}

/// Validated immutable inputs used to construct a `SessionContextV1`.
pub struct SessionContextInputsV1 {
    /// Trusted local DOM chain identifier.
    pub chain_id: [u8; 32],
    /// Nonzero session identifier.
    pub session_id: [u8; 32],
    /// Closed strict Phase 1 purpose.
    pub purpose: PurposeV1,
    /// Stable protocol-role direction.
    pub direction: DirectionV1,
    /// Signing subphase.
    pub signing_phase: SigningPhaseV1,
    /// Complete immutable template commitment.
    pub template_hash: [u8; 32],
    /// Exact DOM kernel message digest.
    pub message_digest: [u8; 32],
    /// Accepted session transcript hash.
    pub transcript_hash: [u8; 32],
    /// Retry counter, valid only before public export.
    pub retry_counter: u64,
    /// Canonical compressed keys in strictly ascending byte order.
    pub participant_public_keys: Vec<PublicKey>,
    /// Local participant position in the canonical roster.
    pub participant_index: u16,
    /// Claim adaptor point, absent for all other V1 purposes.
    pub adaptor_point: Option<PublicKey>,
}

/// Canonical, validated, immutable SessionContextV1.
#[derive(Clone)]
pub struct SessionContextV1 {
    chain_id: [u8; 32],
    session_id: [u8; 32],
    purpose: PurposeV1,
    direction: DirectionV1,
    signing_phase: SigningPhaseV1,
    template_hash: [u8; 32],
    message_digest: [u8; 32],
    transcript_hash: [u8; 32],
    retry_counter: u64,
    participant_public_keys: Vec<PublicKey>,
    participant_index: u16,
    adaptor_point: Option<PublicKey>,
}

impl SessionContextV1 {
    /// Exact context version encoded by this type.
    pub const VERSION: u16 = 1;
    /// Minimum participant count.
    pub const MIN_PARTICIPANTS: usize = 2;
    /// Maximum participant count.
    pub const MAX_PARTICIPANTS: usize = 16;

    /// Validate all ratified invariants and construct an immutable context.
    pub fn new(
        inputs: SessionContextInputsV1,
        signing_share: &ScriptlessSecretScalar,
    ) -> Result<Self> {
        if inputs.chain_id == [0u8; 32] {
            return Err(AdaptorError::InvalidContext("chain ID must be nonzero"));
        }
        if inputs.session_id == [0u8; 32] {
            return Err(AdaptorError::InvalidContext("session ID must be nonzero"));
        }
        inputs.purpose.require_strict_phase1()?;
        let count = inputs.participant_public_keys.len();
        if !(Self::MIN_PARTICIPANTS..=Self::MAX_PARTICIPANTS).contains(&count) {
            return Err(AdaptorError::InvalidContext(
                "participant count must be in the inclusive range 2 through 16",
            ));
        }
        for (index, key) in inputs.participant_public_keys.iter().enumerate() {
            let encoded = key.to_compressed_bytes();
            let reparsed = PublicKey::from_compressed_bytes(&encoded)?;
            if reparsed.to_compressed_bytes() != encoded {
                return Err(AdaptorError::InvalidContext(
                    "participant key does not re-encode byte-exactly",
                ));
            }
            if inputs.participant_public_keys[index + 1..]
                .iter()
                .any(|candidate| candidate == key)
            {
                return Err(AdaptorError::DuplicateParticipant);
            }
        }
        if inputs
            .participant_public_keys
            .windows(2)
            .any(|pair| pair[0].to_compressed_bytes() > pair[1].to_compressed_bytes())
        {
            return Err(AdaptorError::ParticipantOrder);
        }
        let participant_index = usize::from(inputs.participant_index);
        if participant_index >= count {
            return Err(AdaptorError::InvalidContext(
                "participant index is outside the roster",
            ));
        }
        let local_key = signing_share.public_key();
        let matches = inputs
            .participant_public_keys
            .iter()
            .filter(|candidate| **candidate == local_key)
            .count();
        if matches != 1 || inputs.participant_public_keys[participant_index] != local_key {
            return Err(AdaptorError::InvalidContext(
                "signing share must match exactly one roster key at participant_index",
            ));
        }
        match (inputs.purpose, inputs.adaptor_point.as_ref()) {
            (PurposeV1::ClaimAdaptor, Some(point)) => {
                let encoded = point.to_compressed_bytes();
                if PublicKey::from_compressed_bytes(&encoded)?.to_compressed_bytes() != encoded {
                    return Err(AdaptorError::InvalidContext(
                        "adaptor point does not re-encode byte-exactly",
                    ));
                }
            }
            (PurposeV1::ClaimAdaptor, None) => {
                return Err(AdaptorError::InvalidContext(
                    "ClaimAdaptor requires an adaptor point",
                ));
            }
            (PurposeV1::Refund | PurposeV1::Funding, None) => {}
            (PurposeV1::Refund | PurposeV1::Funding, Some(_)) => {
                return Err(AdaptorError::InvalidContext(
                    "Refund and Funding reject an adaptor point",
                ));
            }
            (PurposeV1::Sponsor, _) => {
                return Err(AdaptorError::PurposeNotAuthorized(
                    PurposeV1::Sponsor.to_byte(),
                ));
            }
        }

        Ok(Self {
            chain_id: inputs.chain_id,
            session_id: inputs.session_id,
            purpose: inputs.purpose,
            direction: inputs.direction,
            signing_phase: inputs.signing_phase,
            template_hash: inputs.template_hash,
            message_digest: inputs.message_digest,
            transcript_hash: inputs.transcript_hash,
            retry_counter: inputs.retry_counter,
            participant_public_keys: inputs.participant_public_keys,
            participant_index: inputs.participant_index,
            adaptor_point: inputs.adaptor_point,
        })
    }

    /// Parse exact canonical bytes and re-run every semantic validation.
    pub fn from_bytes(
        bytes: &[u8],
        trusted_chain_id: &[u8; 32],
        signing_share: &ScriptlessSecretScalar,
    ) -> Result<Self> {
        if bytes.len() < 179 {
            return Err(AdaptorError::InvalidLength {
                object: "SessionContextV1",
                expected: 179,
                actual: bytes.len(),
            });
        }
        let version = u16::from_le_bytes([bytes[0], bytes[1]]);
        if version != Self::VERSION {
            return Err(AdaptorError::InvalidContext(
                "context version must be exactly V1",
            ));
        }
        let chain_id: [u8; 32] = bytes[2..34]
            .try_into()
            .expect("fixed offsets provide 32 bytes");
        if &chain_id != trusted_chain_id {
            return Err(AdaptorError::InvalidContext(
                "context chain ID differs from the trusted local chain",
            ));
        }
        let count = usize::from(u16::from_le_bytes([bytes[174], bytes[175]]));
        if !(Self::MIN_PARTICIPANTS..=Self::MAX_PARTICIPANTS).contains(&count) {
            return Err(AdaptorError::InvalidContext(
                "participant count must be in the inclusive range 2 through 16",
            ));
        }
        let roster_end = 176usize
            .checked_add(count.checked_mul(33).ok_or(AdaptorError::InvalidContext(
                "participant byte count overflow",
            ))?)
            .ok_or(AdaptorError::InvalidContext("context length overflow"))?;
        let presence_offset = roster_end
            .checked_add(2)
            .ok_or(AdaptorError::InvalidContext("context length overflow"))?;
        if bytes.len() <= presence_offset {
            return Err(AdaptorError::InvalidContext("truncated participant roster"));
        }
        let adaptor_present = match bytes[presence_offset] {
            0x00 => false,
            0x01 => true,
            _ => {
                return Err(AdaptorError::InvalidContext(
                    "adaptor presence must be 0x00 or 0x01",
                ));
            }
        };
        let expected_len = presence_offset + 1 + usize::from(adaptor_present) * 33;
        if bytes.len() != expected_len {
            return Err(AdaptorError::InvalidLength {
                object: "SessionContextV1",
                expected: expected_len,
                actual: bytes.len(),
            });
        }
        let mut roster = Vec::with_capacity(count);
        for chunk in bytes[176..roster_end].chunks_exact(33) {
            roster.push(PublicKey::from_compressed_bytes(chunk)?);
        }
        let adaptor_point = if adaptor_present {
            Some(PublicKey::from_compressed_bytes(
                &bytes[presence_offset + 1..],
            )?)
        } else {
            None
        };
        Self::new(
            SessionContextInputsV1 {
                chain_id,
                session_id: bytes[34..66]
                    .try_into()
                    .expect("fixed offsets provide 32 bytes"),
                purpose: PurposeV1::try_from(bytes[66])?,
                direction: DirectionV1::try_from(bytes[67])?,
                signing_phase: SigningPhaseV1::try_from(u16::from_le_bytes([
                    bytes[68], bytes[69],
                ]))?,
                template_hash: bytes[70..102]
                    .try_into()
                    .expect("fixed offsets provide 32 bytes"),
                message_digest: bytes[102..134]
                    .try_into()
                    .expect("fixed offsets provide 32 bytes"),
                transcript_hash: bytes[134..166]
                    .try_into()
                    .expect("fixed offsets provide 32 bytes"),
                retry_counter: u64::from_le_bytes(
                    bytes[166..174]
                        .try_into()
                        .expect("fixed offsets provide 8 bytes"),
                ),
                participant_public_keys: roster,
                participant_index: u16::from_le_bytes(
                    bytes[roster_end..roster_end + 2]
                        .try_into()
                        .expect("fixed offsets provide 2 bytes"),
                ),
                adaptor_point,
            },
            signing_share,
        )
    }

    /// Encode the exact canonical byte layout ratified by NAR-001.
    pub fn to_bytes(&self) -> Vec<u8> {
        self.encode_with_retry_counter(self.retry_counter)
    }

    pub(crate) fn encode_with_retry_counter(&self, retry_counter: u64) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(
            179 + self.participant_public_keys.len() * 33
                + usize::from(self.adaptor_point.is_some()) * 33,
        );
        bytes.extend_from_slice(&Self::VERSION.to_le_bytes());
        bytes.extend_from_slice(&self.chain_id);
        bytes.extend_from_slice(&self.session_id);
        bytes.push(self.purpose.to_byte());
        bytes.push(self.direction.to_byte());
        bytes.extend_from_slice(&self.signing_phase.to_le_bytes());
        bytes.extend_from_slice(&self.template_hash);
        bytes.extend_from_slice(&self.message_digest);
        bytes.extend_from_slice(&self.transcript_hash);
        bytes.extend_from_slice(&retry_counter.to_le_bytes());
        bytes.extend_from_slice(&(self.participant_public_keys.len() as u16).to_le_bytes());
        for key in &self.participant_public_keys {
            bytes.extend_from_slice(&key.to_compressed_bytes());
        }
        bytes.extend_from_slice(&self.participant_index.to_le_bytes());
        match &self.adaptor_point {
            None => bytes.push(0x00),
            Some(point) => {
                bytes.push(0x01);
                bytes.extend_from_slice(&point.to_compressed_bytes());
            }
        }
        bytes
    }

    /// Return the trusted chain identifier.
    pub const fn chain_id(&self) -> &[u8; 32] {
        &self.chain_id
    }
    /// Return the session identifier.
    pub const fn session_id(&self) -> &[u8; 32] {
        &self.session_id
    }
    /// Return the strict signing purpose.
    pub const fn purpose(&self) -> PurposeV1 {
        self.purpose
    }
    /// Return the stable protocol direction.
    pub const fn direction(&self) -> DirectionV1 {
        self.direction
    }
    /// Return the signing subphase.
    pub const fn signing_phase(&self) -> SigningPhaseV1 {
        self.signing_phase
    }
    /// Return the complete template commitment.
    pub const fn template_hash(&self) -> &[u8; 32] {
        &self.template_hash
    }
    /// Return the exact DOM kernel message digest.
    pub const fn message_digest(&self) -> &[u8; 32] {
        &self.message_digest
    }
    /// Return the transcript hash.
    pub const fn transcript_hash(&self) -> &[u8; 32] {
        &self.transcript_hash
    }
    /// Return the retry counter.
    pub const fn retry_counter(&self) -> u64 {
        self.retry_counter
    }
    /// Return the immutable canonical participant roster.
    pub fn participant_public_keys(&self) -> &[PublicKey] {
        &self.participant_public_keys
    }
    /// Return the local participant index.
    pub const fn participant_index(&self) -> u16 {
        self.participant_index
    }
    /// Return the optional adaptor point.
    pub const fn adaptor_point(&self) -> Option<&PublicKey> {
        self.adaptor_point.as_ref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn secret(byte: u8) -> ScriptlessSecretScalar {
        ScriptlessSecretScalar::from_be_bytes([byte; 32]).expect("fixture scalar is canonical")
    }

    fn point(hex_value: &str) -> PublicKey {
        PublicKey::from_compressed_bytes(&hex::decode(hex_value).expect("hex"))
            .expect("canonical point")
    }

    fn base_inputs() -> SessionContextInputsV1 {
        SessionContextInputsV1 {
            chain_id: [0xaa; 32],
            session_id: [0x01; 32],
            purpose: PurposeV1::Refund,
            direction: DirectionV1::Initiator,
            signing_phase: SigningPhaseV1::SigNonceCommit,
            template_hash: [0xcc; 32],
            message_digest: [0xdd; 32],
            transcript_hash: [0xee; 32],
            retry_counter: 0,
            participant_public_keys: vec![
                point("02989c0b76cb563971fdc9bef31ec06c3560f3249d6ee9e5d83c57625596e05f6f"),
                point("02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9"),
            ],
            participant_index: 0,
            adaptor_point: None,
        }
    }

    #[test]
    fn ratified_registries_are_closed() {
        assert_eq!(DirectionV1::Initiator.to_byte(), 0x01);
        assert_eq!(DirectionV1::Responder.to_byte(), 0x02);
        for value in 0u8..=u8::MAX {
            assert_eq!(
                DirectionV1::try_from(value).is_ok(),
                (1..=2).contains(&value)
            );
        }
        let phases: [(SigningPhaseV1, u16); 6] = [
            (SigningPhaseV1::SigNonceCommit, 0x0100),
            (SigningPhaseV1::SigNonceReveal, 0x0101),
            (SigningPhaseV1::SigBinding, 0x0102),
            (SigningPhaseV1::SigPartial, 0x0103),
            (SigningPhaseV1::SigAdapt, 0x0104),
            (SigningPhaseV1::SigExtract, 0x0105),
        ];
        for (phase, value) in phases {
            assert_eq!(phase.to_le_bytes(), value.to_le_bytes());
            assert_eq!(SigningPhaseV1::try_from(value).expect("registered"), phase);
        }
        for value in 0u16..=u16::MAX {
            assert_eq!(
                SigningPhaseV1::try_from(value).is_ok(),
                (0x0100..=0x0105).contains(&value),
                "signing phase 0x{value:04x}"
            );
        }
    }

    #[test]
    fn signed_b1_context_encodes_and_parses_byte_exactly() {
        let signing_share = secret(0x07);
        let context = SessionContextV1::new(base_inputs(), &signing_share).expect("B1 context");
        let encoded = context.to_bytes();
        assert_eq!(encoded.len(), 245);
        assert_eq!(&encoded[0..2], &[0x01, 0x00]);
        assert_eq!(&encoded[66..70], &[0x01, 0x01, 0x00, 0x01]);
        assert_eq!(&encoded[166..176], &[0, 0, 0, 0, 0, 0, 0, 0, 2, 0]);
        assert_eq!(encoded[244], 0x00);
        let parsed = SessionContextV1::from_bytes(&encoded, &[0xaa; 32], &signing_share)
            .expect("canonical roundtrip");
        assert_eq!(parsed.to_bytes(), encoded);
    }

    #[test]
    fn context_rejects_duplicate_order_key_and_adaptor_mutations() {
        let signing_share = secret(0x07);
        let mut duplicate = base_inputs();
        duplicate.participant_public_keys[1] = duplicate.participant_public_keys[0].clone();
        assert_eq!(
            SessionContextV1::new(duplicate, &signing_share)
                .err()
                .expect("duplicate"),
            AdaptorError::DuplicateParticipant
        );

        let mut order = base_inputs();
        order.participant_public_keys.reverse();
        order.participant_index = 1;
        assert_eq!(
            SessionContextV1::new(order, &signing_share)
                .err()
                .expect("order"),
            AdaptorError::ParticipantOrder
        );

        let mut wrong_index = base_inputs();
        wrong_index.participant_index = 1;
        assert!(SessionContextV1::new(wrong_index, &signing_share).is_err());

        let mut unexpected = base_inputs();
        unexpected.adaptor_point = Some(point(
            "022f8bde4d1a07209355b4a7250a5c5128e88b84bddc619ab7cba8d569b240efe4",
        ));
        assert!(SessionContextV1::new(unexpected, &signing_share).is_err());

        let mut claim = base_inputs();
        claim.purpose = PurposeV1::ClaimAdaptor;
        assert!(SessionContextV1::new(claim, &signing_share).is_err());
    }

    #[test]
    fn decoder_rejects_every_truncation_and_unknown_discriminants() {
        let signing_share = secret(0x07);
        let encoded = SessionContextV1::new(base_inputs(), &signing_share)
            .expect("context")
            .to_bytes();
        for length in 0..encoded.len() {
            assert!(
                SessionContextV1::from_bytes(&encoded[..length], &[0xaa; 32], &signing_share)
                    .is_err(),
                "truncation {length}"
            );
        }
        for (offset, value) in [(0, 2), (66, 0), (67, 3), (68, 6), (69, 0)] {
            let mut mutated = encoded.clone();
            mutated[offset] = value;
            assert!(SessionContextV1::from_bytes(&mutated, &[0xaa; 32], &signing_share).is_err());
        }
    }
}
