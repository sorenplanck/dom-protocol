//! Complete reservation authority binding for the two-party Phase 1 profile.

use crate::{
    AdaptorError, ContractKindV1, CounterpartyBucket, ParticipantId, ParticipantRosterV1,
    PurposeV1, ReservationRequestLookupV1, Result, SessionContextV1, SessionId, SigningPhaseV1,
    SigningShareV1, TemplateHash, VaultKeyId,
};
use dom_crypto::blake2b_256_tagged;
use rand_core::{OsRng, RngCore};
use std::error::Error;

const CONTEXT_BINDING_MAGIC: &[u8; 8] = b"DOMNVCT1";
const CONTEXT_BINDING_TAG_V1: &str = "DOM:contracts-vault-reservation-context:v1";
const BUDGET_KEY_TAG_V1: &str = crate::DomainTag::VaultBudgetKey.as_str();
const COUNTERPARTY_TAG_V1: &str = crate::DomainTag::VaultCounterparty.as_str();
const CONTEXT_BINDING_FIXED_PREFIX_LEN: usize = 16;
const PROTOCOL_ROSTER_ENTRY_LEN: usize = 101;
const PROTOCOL_ROSTER_LEN: usize = 2 * PROTOCOL_ROSTER_ENTRY_LEN;
const CONTEXT_BINDING_TRAILER_LEN: usize = 2 + PROTOCOL_ROSTER_LEN + 2 + 32;

/// Complete canonical reservation context and protocol-roster binding.
///
/// The type is constructed only by the safe signer from a validated context,
/// roster, local signing share, and trusted protocol position.
pub struct ReservationContextBindingV1 {
    bytes: Vec<u8>,
    digest: [u8; 32],
    local_participant_id: [u8; 32],
    remote_participant_id: [u8; 32],
}

impl ReservationContextBindingV1 {
    pub(crate) fn new(
        context: &SessionContextV1,
        roster: &ParticipantRosterV1,
        local_protocol_roster_index: u16,
        signing_share: &SigningShareV1,
    ) -> Result<Self> {
        if context.signing_phase() != SigningPhaseV1::SigNonceCommit
            || context.retry_counter() != 0
            || roster.entries().len() != 2
            || local_protocol_roster_index > 1
            || context.participant_public_keys().len() != 2
        {
            return Err(AdaptorError::InvalidContext(
                "reservation binding requires the two-party derivation-base context",
            ));
        }
        context.purpose().require_strict_phase1()?;

        let local_position = usize::from(local_protocol_roster_index);
        let local = &roster.entries()[local_position];
        let remote = &roster.entries()[1 - local_position];
        let local_g1a_index = roster.signing_index(local.participant_id())?;
        if local.direction() != context.direction()
            || local_g1a_index != context.participant_index()
            || local.signing_public_key() != signing_share.public_key()
            || local.signing_public_key()
                != &context.participant_public_keys()[usize::from(context.participant_index())]
        {
            return Err(AdaptorError::InvalidContext(
                "local protocol roster mapping does not match the signing context",
            ));
        }
        for entry in roster.entries() {
            let signing_index = roster.signing_index(entry.participant_id())?;
            if signing_index > 1
                || entry.signing_public_key()
                    != &context.participant_public_keys()[usize::from(signing_index)]
            {
                return Err(AdaptorError::InvalidContext(
                    "protocol and signing rosters are not a one-to-one mapping",
                ));
            }
        }

        let context_bytes = context.to_bytes();
        if !matches!(context_bytes.len(), 245 | 278) {
            return Err(AdaptorError::InvalidContext(
                "reservation context length is outside the two-party profile",
            ));
        }
        let total_len = CONTEXT_BINDING_FIXED_PREFIX_LEN
            .checked_add(context_bytes.len())
            .and_then(|length| length.checked_add(CONTEXT_BINDING_TRAILER_LEN))
            .ok_or(AdaptorError::InvalidContext(
                "reservation context-binding length overflow",
            ))?;
        let mut bytes = Vec::with_capacity(total_len);
        bytes.extend_from_slice(CONTEXT_BINDING_MAGIC);
        bytes.extend_from_slice(&1u16.to_le_bytes());
        bytes.extend_from_slice(&ContractKindV1::WitnessOrTimeout.to_le_bytes());
        bytes.extend_from_slice(
            &u32::try_from(context_bytes.len())
                .map_err(|_| AdaptorError::InvalidContext("context length overflow"))?
                .to_le_bytes(),
        );
        bytes.extend_from_slice(&context_bytes);
        bytes.extend_from_slice(&2u16.to_le_bytes());
        for entry in roster.entries() {
            bytes.extend_from_slice(entry.participant_id());
            bytes.extend_from_slice(&entry.identity_public_key().to_compressed_bytes());
            bytes.extend_from_slice(&entry.signing_public_key().to_compressed_bytes());
            bytes.push(entry.direction().to_byte());
            bytes.extend_from_slice(&roster.signing_index(entry.participant_id())?.to_le_bytes());
        }
        bytes.extend_from_slice(&local_protocol_roster_index.to_le_bytes());
        let digest = *blake2b_256_tagged(CONTEXT_BINDING_TAG_V1, &bytes).as_bytes();
        if digest == [0; 32] {
            return Err(AdaptorError::InvalidTranscript(
                "zero reservation context-binding digest",
            ));
        }
        bytes.extend_from_slice(&digest);
        debug_assert_eq!(bytes.len(), total_len);
        Ok(Self {
            bytes,
            digest,
            local_participant_id: *local.participant_id(),
            remote_participant_id: *remote.participant_id(),
        })
    }

    /// Return the complete canonical binding bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Return the digest stored at the end of the canonical binding.
    pub const fn digest(&self) -> &[u8; 32] {
        &self.digest
    }

    /// Return the exact local protocol participant identifier.
    pub const fn local_participant_id(&self) -> &[u8; 32] {
        &self.local_participant_id
    }

    /// Return the exact remote protocol participant identifier.
    pub const fn remote_participant_id(&self) -> &[u8; 32] {
        &self.remote_participant_id
    }
}

struct ReservationRequestFieldsV1 {
    key_id: VaultKeyId,
    session_id: SessionId,
    counterparty: CounterpartyBucket,
    purpose: PurposeV1,
    participant_id: ParticipantId,
    template_hash: TemplateHash,
    request_lookup: ReservationRequestLookupV1,
    context_binding: ReservationContextBindingV1,
}

fn derive_request_fields(
    context: &SessionContextV1,
    signing_share: &SigningShareV1,
    request_lookup: ReservationRequestLookupV1,
    context_binding: ReservationContextBindingV1,
) -> Result<ReservationRequestFieldsV1> {
    if context.chain_id() == &[0; 32]
        || context_binding.local_participant_id() == &[0; 32]
        || context_binding.remote_participant_id() == &[0; 32]
    {
        return Err(AdaptorError::InvalidContext(
            "reservation request contains an empty trusted binding",
        ));
    }
    let mut budget_key_preimage = [0u8; 65];
    budget_key_preimage[..32].copy_from_slice(context.chain_id());
    budget_key_preimage[32..].copy_from_slice(&signing_share.public_key().to_compressed_bytes());
    let key_id = VaultKeyId::from_bytes(
        *blake2b_256_tagged(BUDGET_KEY_TAG_V1, &budget_key_preimage).as_bytes(),
    )
    .map_err(|_| AdaptorError::InvalidContext("derived budget key ID is zero"))?;

    let mut counterparty_preimage = [0u8; 64];
    counterparty_preimage[..32].copy_from_slice(context.chain_id());
    counterparty_preimage[32..].copy_from_slice(context_binding.remote_participant_id());
    let counterparty = CounterpartyBucket::from_bytes(
        *blake2b_256_tagged(COUNTERPARTY_TAG_V1, &counterparty_preimage).as_bytes(),
    )
    .map_err(|_| AdaptorError::InvalidContext("derived counterparty bucket is zero"))?;

    Ok(ReservationRequestFieldsV1 {
        key_id,
        session_id: SessionId::from_bytes(*context.session_id())
            .map_err(|_| AdaptorError::InvalidContext("session ID is zero"))?,
        counterparty,
        purpose: context.purpose(),
        participant_id: ParticipantId::from_bytes(*context_binding.local_participant_id())
            .map_err(|_| AdaptorError::InvalidContext("participant ID is zero"))?,
        template_hash: TemplateHash::from_bytes(*context.template_hash())
            .map_err(|_| AdaptorError::InvalidContext("template hash is zero"))?,
        request_lookup,
        context_binding,
    })
}

/// Opaque one-shot request for fresh reservation creation.
pub struct FreshReservationRequestV1(ReservationRequestFieldsV1);

impl FreshReservationRequestV1 {
    /// Return the trusted signing-key budget owner.
    pub const fn key_id(&self) -> &VaultKeyId {
        &self.0.key_id
    }
    /// Return the lifetime-unique session identifier.
    pub const fn session_id(&self) -> &SessionId {
        &self.0.session_id
    }
    /// Return the trusted counterparty budget bucket.
    pub const fn counterparty(&self) -> &CounterpartyBucket {
        &self.0.counterparty
    }
    /// Return the strict Phase 1 purpose.
    pub const fn purpose(&self) -> PurposeV1 {
        self.0.purpose
    }
    /// Return the local participant identifier.
    pub const fn participant_id(&self) -> &ParticipantId {
        &self.0.participant_id
    }
    /// Return the canonical template hash.
    pub const fn template_hash(&self) -> &TemplateHash {
        &self.0.template_hash
    }
    /// Return the internally generated public retry lookup identifier.
    pub const fn request_lookup(&self) -> &ReservationRequestLookupV1 {
        &self.0.request_lookup
    }
    /// Return the complete validated canonical context binding.
    pub const fn context_binding(&self) -> &ReservationContextBindingV1 {
        &self.0.context_binding
    }
}

/// Private pre-claim state retaining the request and its non-authoritative lookup.
pub struct PreparedFreshReservationV1 {
    request: FreshReservationRequestV1,
}

impl PreparedFreshReservationV1 {
    pub(crate) fn new(
        context: &SessionContextV1,
        signing_share: &SigningShareV1,
        context_binding: ReservationContextBindingV1,
    ) -> Result<Self> {
        let request_lookup = loop {
            let mut bytes = [0u8; 32];
            OsRng
                .try_fill_bytes(&mut bytes)
                .map_err(|_| AdaptorError::RandomnessFailure)?;
            if bytes != [0; 32] {
                break ReservationRequestLookupV1::from_bytes(bytes)
                    .map_err(|_| AdaptorError::RandomnessFailure)?;
            }
        };
        Ok(Self {
            request: FreshReservationRequestV1(derive_request_fields(
                context,
                signing_share,
                request_lookup,
                context_binding,
            )?),
        })
    }

    /// Return the public lookup that trusted session storage must retain first.
    pub const fn request_lookup(&self) -> &ReservationRequestLookupV1 {
        self.request.request_lookup()
    }

    /// Return the exact context-binding digest that must be retained with the lookup.
    pub const fn context_binding_digest(&self) -> &[u8; 32] {
        self.request.context_binding().digest()
    }

    /// Return the lifetime-unique session retained with the lookup custody record.
    pub const fn session_id(&self) -> &SessionId {
        self.request.session_id()
    }

    pub(crate) fn into_request(
        self,
        custody: impl DurableReservationLookupV1,
    ) -> Result<FreshReservationRequestV1> {
        if custody.request_lookup() != self.request.request_lookup()
            || custody.context_binding_digest() != self.request.context_binding().digest()
            || custody.session_id() != self.request.session_id()
        {
            return Err(AdaptorError::AuthorizationMismatch);
        }
        Ok(self.request)
    }
}

/// Opaque one-shot evidence that trusted session storage retained the lookup.
pub trait DurableReservationLookupV1 {
    /// Return the exact retained lookup.
    fn request_lookup(&self) -> &ReservationRequestLookupV1;
    /// Return the exact retained context-binding digest.
    fn context_binding_digest(&self) -> &[u8; 32];
    /// Return the lifetime-unique session identifier.
    fn session_id(&self) -> &SessionId;
}

/// Trusted session-store custody boundary invoked before vault admission.
pub trait ReservationLookupCustodyV1: Sized {
    /// Redacted durable-storage failure.
    type Error: Error + Send + Sync + 'static;
    /// Opaque one-shot result of durable commit and reread.
    type DurableLookup: DurableReservationLookupV1;

    /// Persist and reread the exact lookup and binding before Store admission.
    fn persist_prepared_lookup(
        &mut self,
        prepared: &PreparedFreshReservationV1,
    ) -> core::result::Result<Self::DurableLookup, Self::Error>;

    /// Irreversibly abandon a custody record that resolved to no vault occurrence.
    fn abandon_before_vault_claim(
        &mut self,
        lookup: &ReservationRequestLookupV1,
        session_id: &SessionId,
        context_binding_digest: &[u8; 32],
    ) -> core::result::Result<(), Self::Error>;
}

/// Opaque restart-only request for the exact retained reservation lookup.
///
/// Only the vault-backed signer can construct this value, after recomputing
/// the canonical reservation-context binding from an authenticated signing
/// session and the local signing share. Downstream callers cannot provide a
/// raw digest or trial candidate lookup to the recovery custody boundary.
pub struct ReservationLookupRecoveryRequestV1 {
    session_id: SessionId,
    context_binding_digest: [u8; 32],
}

impl ReservationLookupRecoveryRequestV1 {
    pub(crate) fn new(session_id: SessionId, context_binding_digest: [u8; 32]) -> Result<Self> {
        if context_binding_digest == [0; 32] {
            return Err(AdaptorError::InvalidTranscript(
                "zero restart reservation context-binding digest",
            ));
        }
        Ok(Self {
            session_id,
            context_binding_digest,
        })
    }

    /// Return the authenticated lifetime-unique session identifier.
    pub const fn session_id(&self) -> &SessionId {
        &self.session_id
    }

    /// Return the signer-derived canonical reservation-context digest.
    pub const fn context_binding_digest(&self) -> &[u8; 32] {
        &self.context_binding_digest
    }
}

/// Additive production custody boundary for restart-only lookup recovery.
///
/// This trait is intentionally separate from [`ReservationLookupCustodyV1`]
/// so existing fresh-claim custody implementations do not gain restart
/// authority accidentally. Implementations must resolve exactly one retained
/// lookup or fail closed; they must never create a lookup or select among
/// caller-provided candidates.
pub trait ReservationLookupRecoveryCustodyV1: ReservationLookupCustodyV1 {
    /// Load the one exact lookup bound to the opaque signer request.
    fn load_custodied_lookup(
        &mut self,
        request: &ReservationLookupRecoveryRequestV1,
    ) -> core::result::Result<ReservationRequestLookupV1, Self::Error>;
}

/// Opaque one-shot request for exact reservation retry or restart lookup.
pub struct ReservationResumeRequestV1(ReservationRequestFieldsV1);

impl ReservationResumeRequestV1 {
    pub(crate) fn from_trusted_state(
        context: &SessionContextV1,
        signing_share: &SigningShareV1,
        request_lookup: ReservationRequestLookupV1,
        context_binding: ReservationContextBindingV1,
    ) -> Result<Self> {
        Ok(Self(derive_request_fields(
            context,
            signing_share,
            request_lookup,
            context_binding,
        )?))
    }

    /// Return the public retry lookup identifier.
    pub const fn request_lookup(&self) -> &ReservationRequestLookupV1 {
        &self.0.request_lookup
    }
    /// Return the trusted signing-key budget owner.
    pub const fn key_id(&self) -> &VaultKeyId {
        &self.0.key_id
    }
    /// Return the lifetime-unique session identifier.
    pub const fn session_id(&self) -> &SessionId {
        &self.0.session_id
    }
    /// Return the trusted counterparty budget bucket.
    pub const fn counterparty(&self) -> &CounterpartyBucket {
        &self.0.counterparty
    }
    /// Return the strict Phase 1 purpose.
    pub const fn purpose(&self) -> PurposeV1 {
        self.0.purpose
    }
    /// Return the local participant identifier.
    pub const fn participant_id(&self) -> &ParticipantId {
        &self.0.participant_id
    }
    /// Return the canonical template hash.
    pub const fn template_hash(&self) -> &TemplateHash {
        &self.0.template_hash
    }
    /// Return the complete validated canonical context binding.
    pub const fn context_binding(&self) -> &ReservationContextBindingV1 {
        &self.0.context_binding
    }
}

/// Fuzz-only harness for the four closed reservation and computation requests.
///
/// NAR-DC-P1-004 §20 requires persistent fuzz coverage of the closed request
/// types. They are deliberately non-constructible outside this crate — the same
/// section requires proof that an application caller cannot build a fresh,
/// resume, derivation, or later-stage request — so no downstream target can
/// reach them and the harness has to live here, next to their constructors.
///
/// This symbol is selected only by cargo-fuzz's `cfg(fuzzing)` build and is
/// absent from production feature resolution.
#[cfg(fuzzing)]
pub fn fuzz_closed_request_types_v1(data: &[u8]) {
    use crate::{
        DirectionV1, NonceDerivationRequestV1, ParticipantIdentityV1, SessionContextInputsV1,
        TrustedChainIdV1,
    };
    use dom_core::Hash256;

    fn field(data: &[u8], start: usize, fallback: u8) -> [u8; 32] {
        let mut value = [fallback; 32];
        if let Some(bytes) = data.get(start..start.saturating_add(32)) {
            if bytes.len() == 32 {
                value.copy_from_slice(bytes);
            }
        }
        // Keep the field nonzero: every identifier here rejects zero, and a
        // stream of zero fields would only ever exercise that one branch.
        value[0] |= 1;
        value
    }

    let selector = data.first().copied().unwrap_or_default();
    let chain_bytes = field(data, 1, 0x21);
    let session_bytes = field(data, 33, 0x22);
    let template_bytes = field(data, 65, 0x23);
    let message_bytes = field(data, 97, 0x24);
    let transcript_bytes = field(data, 129, 0x25);
    let binding_digest = field(data, 161, 0x26);

    let network_magic = u32::from_le_bytes([
        chain_bytes[0],
        chain_bytes[1],
        chain_bytes[2],
        chain_bytes[3],
    ]);
    let chain = TrustedChainIdV1::from_authenticated_genesis(
        network_magic,
        &Hash256::from_bytes(session_bytes),
    );
    let chain_bytes = *chain.as_bytes();
    let (Ok(local_share), Ok(remote_share)) = (
        SigningShareV1::from_be_bytes(field(data, 193, 0x27)),
        SigningShareV1::from_be_bytes(field(data, 225, 0x28)),
    ) else {
        return;
    };
    if local_share.public_key() == remote_share.public_key() {
        return;
    }

    let local_direction = if selector & 1 == 0 {
        DirectionV1::Initiator
    } else {
        DirectionV1::Responder
    };
    let remote_direction = if selector & 1 == 0 {
        DirectionV1::Responder
    } else {
        DirectionV1::Initiator
    };

    let (Ok(local_entry), Ok(remote_entry)) = (
        ParticipantIdentityV1::new(
            &chain,
            local_share.public_key().clone(),
            local_share.public_key().clone(),
            local_direction,
        ),
        ParticipantIdentityV1::new(
            &chain,
            remote_share.public_key().clone(),
            remote_share.public_key().clone(),
            remote_direction,
        ),
    ) else {
        return;
    };
    let local_participant_id = *local_entry.participant_id();

    let mut entries = vec![local_entry, remote_entry];
    entries.sort_by_key(|entry| *entry.participant_id());
    let Ok(roster) = ParticipantRosterV1::new(entries) else {
        return;
    };

    // The binding requires the local roster position, the G1A signing index and
    // the context key order to agree. Derive them instead of guessing, so valid
    // cases reach the deep constructors rather than dying at the first check.
    let Some(local_protocol_index) = roster
        .entries()
        .iter()
        .position(|entry| entry.participant_id() == &local_participant_id)
        .and_then(|index| u16::try_from(index).ok())
    else {
        return;
    };
    let Ok(signing_index) = roster.signing_index(&local_participant_id) else {
        return;
    };
    let mut participant_public_keys = vec![
        local_share.public_key().clone(),
        remote_share.public_key().clone(),
    ];
    if usize::from(signing_index) == 1 {
        participant_public_keys.swap(0, 1);
    }

    let inputs = SessionContextInputsV1 {
        chain_id: chain_bytes,
        session_id: session_bytes,
        purpose: if selector & 2 == 0 {
            PurposeV1::Refund
        } else {
            PurposeV1::ClaimAdaptor
        },
        direction: local_direction,
        signing_phase: SigningPhaseV1::SigNonceCommit,
        template_hash: template_bytes,
        message_digest: message_bytes,
        transcript_hash: transcript_bytes,
        retry_counter: 0,
        participant_public_keys,
        participant_index: signing_index,
        adaptor_point: None,
    };
    let Ok(context) = SessionContextV1::new(inputs, &local_share) else {
        return;
    };

    // The binding is deliberately not `Clone`: it is a one-shot authority.
    // Build a fresh one for each consumer rather than reusing a copy.
    let build_binding =
        || ReservationContextBindingV1::new(&context, &roster, local_protocol_index, &local_share);
    let Ok(reference_binding) = build_binding() else {
        return;
    };
    let reference_digest = *reference_binding.digest();
    drop(reference_binding);

    // Fresh: the constructor draws its own lookup, so the caller cannot choose
    // it. Exercising it proves the OS-randomness path stays reachable.
    if let Ok(binding) = build_binding() {
        let _fresh = PreparedFreshReservationV1::new(&context, &local_share, binding);
    }

    // Resume: the lookup is caller-supplied and must bind to the same context.
    if let (Ok(resume_lookup), Ok(binding)) = (
        ReservationRequestLookupV1::from_bytes(field(data, 257, 0x29)),
        build_binding(),
    ) {
        let _resume = ReservationResumeRequestV1::from_trusted_state(
            &context,
            &local_share,
            resume_lookup,
            binding,
        );
    }

    // Derivation: a caller-shaped digest must not be able to stand in for the
    // binding digest the Store authenticated.
    let derivation_digest = if selector & 4 == 0 {
        reference_digest
    } else {
        binding_digest
    };
    let _derivation = NonceDerivationRequestV1::new(derivation_digest, context.clone());

    // Later stage: the same constructor must reject a context whose phase was
    // advanced without the round evidence that authorizes the advance.
    if let Ok(advanced) =
        context.with_stage_and_transcript(SigningPhaseV1::SigNonceReveal, transcript_bytes)
    {
        let _rejected_stage = NonceDerivationRequestV1::new(derivation_digest, advanced);
    }
}
