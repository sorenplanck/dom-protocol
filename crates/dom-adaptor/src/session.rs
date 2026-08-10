//! NAR-002 authoritative chain, participant, session, and template adapters.

use crate::{AdaptorError, DirectionV1, Result};
use dom_core::Hash256;
use dom_crypto::{blake2b_256_tagged, PublicKey};
use rand_core::{OsRng, RngCore};
use zeroize::Zeroizing;

const PARTICIPANT_TAG_V1: &str = crate::DomainTag::Participant.as_str();
const SESSION_ID_TAG_V1: &str = crate::DomainTag::SessionId.as_str();
const TEMPLATE_TAG_V1: &str = crate::DomainTag::Template.as_str();
const TRANSCRIPT_INIT_TAG_V1: &str = crate::DomainTag::TranscriptInit.as_str();
const SESSION_MESSAGE_TAG_V1: &str = crate::DomainTag::Message.as_str();
const TRANSCRIPT_UPDATE_TAG_V1: &str = crate::DomainTag::Transcript.as_str();

/// Chain identifier obtained only from the authoritative DOM chain adapter.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct TrustedChainIdV1([u8; 32]);

impl TrustedChainIdV1 {
    /// Derive the trusted chain identifier from authenticated local chain data.
    pub fn from_authenticated_genesis(network_magic: u32, genesis_hash: &Hash256) -> Self {
        Self(*dom_consensus::derive_chain_id(network_magic, genesis_hash).as_bytes())
    }

    /// Return the canonical chain identifier bytes.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    #[cfg(test)]
    /// Construct a synthetic chain identifier for crate-local tests.
    /// This API is absent from every downstream and release feature resolution.
    pub const fn from_signed_fixture(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

/// Closed Scriptless contract-kind registry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum ContractKindV1 {
    /// Witness-or-timeout contract assigned by NAR-002.
    WitnessOrTimeout = 0x0001,
}

impl ContractKindV1 {
    /// Return the exact little-endian registry bytes.
    pub const fn to_le_bytes(self) -> [u8; 2] {
        (self as u16).to_le_bytes()
    }
}

impl TryFrom<u16> for ContractKindV1 {
    type Error = AdaptorError;

    fn try_from(value: u16) -> Result<Self> {
        match value {
            0x0001 => Ok(Self::WitnessOrTimeout),
            _ => Err(AdaptorError::InvalidContext(
                "unknown Scriptless contract kind",
            )),
        }
    }
}

/// Canonical participant identity and signing-key mapping.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParticipantIdentityV1 {
    participant_id: [u8; 32],
    identity_public_key: PublicKey,
    signing_public_key: PublicKey,
    direction: DirectionV1,
}

impl ParticipantIdentityV1 {
    /// Construct a participant entry and derive its identifier canonically.
    pub fn new(
        chain_id: &TrustedChainIdV1,
        identity_public_key: PublicKey,
        signing_public_key: PublicKey,
        direction: DirectionV1,
    ) -> Result<Self> {
        let mut body = [0u8; 65];
        body[..32].copy_from_slice(chain_id.as_bytes());
        body[32..].copy_from_slice(&identity_public_key.to_compressed_bytes());
        let participant_id = *blake2b_256_tagged(PARTICIPANT_TAG_V1, &body).as_bytes();
        if participant_id == [0u8; 32] {
            return Err(AdaptorError::InvalidContext(
                "derived participant ID must be nonzero",
            ));
        }
        Ok(Self {
            participant_id,
            identity_public_key,
            signing_public_key,
            direction,
        })
    }

    /// Return the participant identifier.
    pub const fn participant_id(&self) -> &[u8; 32] {
        &self.participant_id
    }
    /// Return the canonical identity public key.
    pub const fn identity_public_key(&self) -> &PublicKey {
        &self.identity_public_key
    }
    /// Return the canonical signing public key.
    pub const fn signing_public_key(&self) -> &PublicKey {
        &self.signing_public_key
    }
    /// Return the role-stable direction.
    pub const fn direction(&self) -> DirectionV1 {
        self.direction
    }
}

/// Validated protocol roster sorted strictly by participant identifier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParticipantRosterV1(Vec<ParticipantIdentityV1>);

impl ParticipantRosterV1 {
    /// Validate count, ordering, and one-to-one identity/signing mappings.
    pub fn new(entries: Vec<ParticipantIdentityV1>) -> Result<Self> {
        if !(2..=16).contains(&entries.len()) {
            return Err(AdaptorError::InvalidContext(
                "participant count must be in the inclusive range 2 through 16",
            ));
        }
        if entries
            .windows(2)
            .any(|pair| pair[0].participant_id >= pair[1].participant_id)
        {
            return Err(AdaptorError::ParticipantOrder);
        }
        for (index, entry) in entries.iter().enumerate() {
            if entries[index + 1..].iter().any(|other| {
                other.identity_public_key == entry.identity_public_key
                    || other.signing_public_key == entry.signing_public_key
            }) {
                return Err(AdaptorError::DuplicateParticipant);
            }
        }
        Ok(Self(entries))
    }

    /// Return the immutable protocol roster.
    pub fn entries(&self) -> &[ParticipantIdentityV1] {
        &self.0
    }

    /// Resolve the G1a signing index for a protocol participant.
    pub fn signing_index(&self, participant_id: &[u8; 32]) -> Result<u16> {
        let signing_key = self
            .0
            .iter()
            .find(|entry| entry.participant_id() == participant_id)
            .ok_or(AdaptorError::InvalidContext(
                "participant is not in protocol roster",
            ))?
            .signing_public_key();
        let mut signing_keys: Vec<[u8; 33]> = self
            .0
            .iter()
            .map(|entry| entry.signing_public_key.to_compressed_bytes())
            .collect();
        signing_keys.sort_unstable();
        signing_keys
            .iter()
            .position(|candidate| candidate == &signing_key.to_compressed_bytes())
            .and_then(|index| u16::try_from(index).ok())
            .ok_or(AdaptorError::InvalidContext(
                "signing index is not representable",
            ))
    }
}

/// Storage-owned permanent session-ID uniqueness boundary.
///
/// Implementations must durably reject every identifier used previously for
/// the lifetime of the local participant identity. An in-memory registry is
/// not a production implementation of this contract.
pub trait SessionIdRegistryV1 {
    /// Durably register a never-before-used identifier before it is returned.
    fn register_unique_session_id(&mut self, session_id: &[u8; 32]) -> Result<bool>;
}

/// Generate and durably register a fresh nonzero session identifier with the
/// NAR-002 framing.
pub fn generate_session_id_v1<R: SessionIdRegistryV1>(
    chain_id: &TrustedChainIdV1,
    initiator_participant_id: &[u8; 32],
    contract_kind: ContractKindV1,
    registry: &mut R,
) -> Result<[u8; 32]> {
    if initiator_participant_id == &[0u8; 32] {
        return Err(AdaptorError::InvalidContext(
            "initiator participant ID must be nonzero",
        ));
    }
    loop {
        let mut initiator_nonce = Zeroizing::new([0u8; 32]);
        OsRng
            .try_fill_bytes(initiator_nonce.as_mut())
            .map_err(|_| AdaptorError::RandomnessFailure)?;
        if initiator_nonce.iter().all(|byte| *byte == 0) {
            continue;
        }
        let session_id = session_id_from_nonce_v1(
            chain_id,
            initiator_participant_id,
            contract_kind,
            &initiator_nonce,
        );
        if session_id == [0u8; 32] {
            continue;
        }
        if registry.register_unique_session_id(&session_id)? {
            return Ok(session_id);
        }
    }
}

fn session_id_from_nonce_v1(
    chain_id: &TrustedChainIdV1,
    initiator_participant_id: &[u8; 32],
    contract_kind: ContractKindV1,
    initiator_nonce: &[u8; 32],
) -> [u8; 32] {
    let mut body = [0u8; 100];
    body[..2].copy_from_slice(&1u16.to_le_bytes());
    body[2..34].copy_from_slice(chain_id.as_bytes());
    body[34..66].copy_from_slice(initiator_nonce);
    body[66..98].copy_from_slice(initiator_participant_id);
    body[98..].copy_from_slice(&contract_kind.to_le_bytes());
    *blake2b_256_tagged(SESSION_ID_TAG_V1, &body).as_bytes()
}

/// Project a DOM transaction through the authoritative NAR-002 template adapter.
pub fn canonical_template_v1(tx: &dom_consensus::Transaction) -> Result<(Vec<u8>, [u8; 32])> {
    let bytes = dom_consensus::scriptless_transaction_template_bytes_v1(tx)?;
    let hash = *blake2b_256_tagged(TEMPLATE_TAG_V1, &bytes).as_bytes();
    Ok((bytes, hash))
}

/// Compute the initial protocol transcript over the participant-ID roster.
pub fn initial_transcript_hash_v1(
    chain_id: &TrustedChainIdV1,
    session_id: &[u8; 32],
    contract_kind: ContractKindV1,
    roster: &ParticipantRosterV1,
) -> [u8; 32] {
    let mut body = Vec::with_capacity(68 + roster.entries().len() * 99);
    body.extend_from_slice(chain_id.as_bytes());
    body.extend_from_slice(session_id);
    body.extend_from_slice(&contract_kind.to_le_bytes());
    body.extend_from_slice(&(roster.entries().len() as u16).to_le_bytes());
    for participant in roster.entries() {
        body.extend_from_slice(participant.participant_id());
        body.extend_from_slice(&participant.identity_public_key().to_compressed_bytes());
        body.extend_from_slice(&participant.signing_public_key().to_compressed_bytes());
        body.push(participant.direction().to_byte());
    }
    *blake2b_256_tagged(TRANSCRIPT_INIT_TAG_V1, &body).as_bytes()
}

/// Hash exact canonical unsigned DSC1 message bytes.
pub fn session_message_digest_v1(unsigned_message_bytes: &[u8]) -> [u8; 32] {
    *blake2b_256_tagged(SESSION_MESSAGE_TAG_V1, unsigned_message_bytes).as_bytes()
}

/// Advance the accepted transcript with an exact message digest and registry fields.
pub fn advance_transcript_hash_v1(
    previous: &[u8; 32],
    session_message_digest: &[u8; 32],
    direction: DirectionV1,
    accepted_phase: crate::SigningPhaseV1,
) -> [u8; 32] {
    let mut body = [0u8; 67];
    body[..32].copy_from_slice(previous);
    body[32..64].copy_from_slice(session_message_digest);
    body[64] = direction.to_byte();
    body[65..].copy_from_slice(&accepted_phase.to_le_bytes());
    *blake2b_256_tagged(TRANSCRIPT_UPDATE_TAG_V1, &body).as_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SigningShareV1;

    fn point(value: u8) -> PublicKey {
        let mut bytes = [0u8; 32];
        bytes[31] = value;
        SigningShareV1::from_be_bytes(bytes)
            .expect("fixture scalar")
            .public_key()
            .clone()
    }

    #[test]
    fn participant_mapping_and_transcript_are_ordered_and_domain_separated() {
        let chain = TrustedChainIdV1::from_signed_fixture([7; 32]);
        let mut entries = vec![
            ParticipantIdentityV1::new(&chain, point(2), point(4), DirectionV1::Responder)
                .expect("participant"),
            ParticipantIdentityV1::new(&chain, point(1), point(3), DirectionV1::Initiator)
                .expect("participant"),
        ];
        entries.sort_by_key(|entry| *entry.participant_id());
        let roster = ParticipantRosterV1::new(entries).expect("roster");
        let first =
            initial_transcript_hash_v1(&chain, &[8; 32], ContractKindV1::WitnessOrTimeout, &roster);
        let digest = session_message_digest_v1(b"canonical unsigned DSC1 bytes");
        let initiator = advance_transcript_hash_v1(
            &first,
            &digest,
            DirectionV1::Initiator,
            crate::SigningPhaseV1::SigNonceCommit,
        );
        assert_ne!(
            initiator,
            advance_transcript_hash_v1(
                &first,
                &digest,
                DirectionV1::Responder,
                crate::SigningPhaseV1::SigNonceCommit,
            )
        );
        let mut exact_body = [0u8; 67];
        exact_body[..32].copy_from_slice(&first);
        exact_body[32..64].copy_from_slice(&digest);
        exact_body[64] = DirectionV1::Initiator.to_byte();
        exact_body[65..].copy_from_slice(&crate::SigningPhaseV1::SigNonceCommit.to_le_bytes());
        assert_eq!(
            initiator,
            *blake2b_256_tagged("DOM:scriptless-transcript:v1", &exact_body).as_bytes(),
            "NAR-002 section 8.2 tag and body must remain byte-exact",
        );
    }

    #[test]
    fn session_generation_requires_durable_uniqueness_registration() {
        struct Registry(usize);
        impl SessionIdRegistryV1 for Registry {
            fn register_unique_session_id(&mut self, _session_id: &[u8; 32]) -> Result<bool> {
                if self.0 == 0 {
                    Ok(true)
                } else {
                    self.0 -= 1;
                    Ok(false)
                }
            }
        }

        let chain = TrustedChainIdV1::from_signed_fixture([7; 32]);
        assert!(generate_session_id_v1(
            &chain,
            &[8; 32],
            ContractKindV1::WitnessOrTimeout,
            &mut Registry(0),
        )
        .is_ok());
        assert!(generate_session_id_v1(
            &chain,
            &[8; 32],
            ContractKindV1::WitnessOrTimeout,
            &mut Registry(1),
        )
        .is_ok());
        assert!(generate_session_id_v1(
            &chain,
            &[0; 32],
            ContractKindV1::WitnessOrTimeout,
            &mut Registry(0),
        )
        .is_err());
    }
}
