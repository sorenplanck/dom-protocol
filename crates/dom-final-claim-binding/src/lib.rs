//! Canonical bilateral role binding for a DOM final claim.
//!
//! These values freeze facts that settlement terms deliberately do not infer:
//! who originally owns the adaptor secret, who broadcasts the DOM claim, who
//! receives the bilateral `FinalClaim` message, and which admitted claim is the
//! source of the reveal.  Every wire format is closed, versioned, and rejects
//! unknown tags, non-zero reserved bytes, and trailing bytes.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

use dom_adaptor::{
    audit_retained_participant_id_v1, DirectionV1, ParticipantIdentityV1, ParticipantRosterV1,
    TrustedChainIdV1,
};
use dom_crypto::{blake2b_256_tagged, pedersen::Commitment, PublicKey};
use kaystra_core::types::{ChainId, Digest32, SessionId, SettlementId};

// Re-exported, not merely imported: this crate names `SettlementTermsV1` and
// `ParticipantId` in its own public typed-input API, and several accessors
// return `ParticipantId`. Without these re-exports every
// caller is forced into a direct dependency edge on `kaystra-core` just to name
// a type this crate already demands, which is a defect of this crate's surface
// rather than of the caller's manifest.
pub use kaystra_core::{terms::SettlementTermsV1, types::ParticipantId};

/// Domain of [`FinalClaimSecretSourceScopeV1::digest`].
pub const FINAL_CLAIM_SECRET_SOURCE_SCOPE_DOMAIN: &str = "DOM:final-claim-secret-source-scope:v1";
/// Domain of [`ComposedFinalClaimRolePlanV1::digest`].
pub const COMPOSED_FINAL_CLAIM_ROLE_PLAN_DOMAIN: &str =
    "DOM:route-composer/final-claim-role-plan:v1";
/// Domain of the complete DOM participant roster committed by a role binding.
pub const FINAL_CLAIM_ROLE_ROSTER_DOMAIN: &str = "DOM:final-claim-role-roster:v1";
/// Domain of [`FinalClaimRoleBindingV1::digest`].
pub const FINAL_CLAIM_ROLE_BINDING_DOMAIN: &str = "DOM:final-claim-role-binding:v1";
/// Domain of [`OperationalM8ReadyBindingV2::digest`].
pub const OPERATIONAL_M8_READY_BINDING_DOMAIN: &str =
    "DOM:contracts-operational-m8-ready-binding:v2";

/// Exact encoded length of [`FinalClaimSecretSourceScopeV1`].
pub const FINAL_CLAIM_SECRET_SOURCE_SCOPE_ENCODED_LEN: usize = 305;
/// Exact encoded length of [`ComposedFinalClaimRolePlanV1`].
pub const COMPOSED_FINAL_CLAIM_ROLE_PLAN_ENCODED_LEN: usize = 504;
/// Fixed prefix and embedded-object length of [`FinalClaimRoleBindingV1`],
/// excluding the variable canonical settlement terms at its tail.
pub const FINAL_CLAIM_ROLE_BINDING_BASE_ENCODED_LEN: usize = 1_615;
/// Maximum role-binding length under the current settlement metadata bound.
pub const FINAL_CLAIM_ROLE_BINDING_MAX_ENCODED_LEN: usize = 6_418;
/// Exact encoded length of [`OperationalM8ReadyBindingV2`].
pub const OPERATIONAL_M8_READY_BINDING_ENCODED_LEN: usize = 608;

const SOURCE_SCOPE_MAGIC: &[u8; 8] = b"DOMFCSS1";
const ROLE_PLAN_MAGIC: &[u8; 8] = b"DOMFCRP1";
const ROLE_BINDING_MAGIC: &[u8; 8] = b"DOMFCRB1";
const READY_BINDING_MAGIC: &[u8; 8] = b"DOMM8RB2";
const READY_BINDING_PROFILE: &[u8; 4] = b"M8R2";
const V1: u16 = 1;
const V2: u16 = 2;
const ROLE_PLAN_ENTRY_LEN: usize = 196;
const ROSTER_ENTRY_LEN: usize = 99;
const PARTICIPANT_COUNT: u16 = 2;
const CLAIM_KERNEL_INDEX: u32 = 0;

/// Fail-closed refusal produced by the canonical role-binding layer.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum FinalClaimBindingError {
    /// The input has the wrong exact length or a length field is inconsistent.
    #[error("invalid canonical length")]
    InvalidLength,
    /// The encoding has the wrong magic.
    #[error("invalid canonical magic")]
    InvalidMagic,
    /// The encoding uses an unsupported version.
    #[error("invalid canonical version")]
    InvalidVersion,
    /// A closed enum contains an unknown tag.
    #[error("unknown canonical tag")]
    UnknownTag,
    /// Reserved bytes are not all zero.
    #[error("non-zero reserved bytes")]
    NonZeroReserved,
    /// A public field required to be non-zero is zero.
    #[error("zero field: {0}")]
    ZeroField(&'static str),
    /// A SEC1 point or Pedersen commitment is malformed.
    #[error("invalid curve point: {0}")]
    InvalidPoint(&'static str),
    /// Settlement terms are invalid or cannot be encoded canonically.
    #[error("invalid settlement terms")]
    InvalidTerms,
    /// The two-person roster is malformed or does not match settlement terms.
    #[error("invalid participant roster")]
    InvalidRoster,
    /// DOM and counterparty beneficiaries/refund owners are not mirrored.
    #[error("invalid bilateral settlement topology")]
    InvalidTopology,
    /// Sender, receiver, or origin is not the explicitly authorized role.
    #[error("invalid final-claim role relation")]
    InvalidRoleRelation,
    /// Reveal mode and secret source are not one of the two closed pairings.
    #[error("invalid reveal mode and secret source pairing")]
    InvalidModeSource,
    /// A secret-source scope does not authenticate the selected settlement.
    #[error("secret-source scope mismatch")]
    SourceScopeMismatch,
    /// A composed role plan does not authenticate the supplied composition.
    #[error("composed final-claim role plan mismatch")]
    RolePlanMismatch,
    /// Redundant canonical fields do not rebind byte-for-byte.
    #[error("canonical binding mismatch")]
    CanonicalMismatch,
}

/// Whether the DOM claim is the first reveal or reacts to a counterparty
/// claim that has already revealed the adaptor secret.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum FinalClaimRevealModeV1 {
    /// The DOM claim is the first publication of the adaptor secret.
    DomRevealsFirst = 0x01,
    /// The DOM sender reacts to a verified counterparty claim reveal.
    DomReactsToCounterpartyReveal = 0x02,
}

impl FinalClaimRevealModeV1 {
    /// Return the exact one-byte wire tag.
    pub const fn to_byte(self) -> u8 {
        self as u8
    }
}

impl TryFrom<u8> for FinalClaimRevealModeV1 {
    type Error = FinalClaimBindingError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x01 => Ok(Self::DomRevealsFirst),
            0x02 => Ok(Self::DomReactsToCounterpartyReveal),
            _ => Err(FinalClaimBindingError::UnknownTag),
        }
    }
}

/// Authority source from which the DOM broadcaster obtains the adaptor
/// secret.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum FinalClaimSecretSourceV1 {
    /// The DOM broadcaster is the original local owner of the secret.
    LocalOrigin = 0x01,
    /// The secret comes from an admitted and verified counterparty claim.
    VerifiedCounterpartyClaim = 0x02,
}

impl FinalClaimSecretSourceV1 {
    /// Return the exact one-byte wire tag.
    pub const fn to_byte(self) -> u8 {
        self as u8
    }
}

impl TryFrom<u8> for FinalClaimSecretSourceV1 {
    type Error = FinalClaimBindingError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x01 => Ok(Self::LocalOrigin),
            0x02 => Ok(Self::VerifiedCounterpartyClaim),
            _ => Err(FinalClaimBindingError::UnknownTag),
        }
    }
}

/// Explicit composed-settlement position.  This is scope only and never
/// selects or infers a participant role.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum ComposedSettlementLegV1 {
    /// The upstream settlement.
    Upstream = 0x01,
    /// The downstream settlement.
    Downstream = 0x02,
}

impl ComposedSettlementLegV1 {
    /// Return the exact one-byte wire tag.
    pub const fn to_byte(self) -> u8 {
        self as u8
    }
}

impl TryFrom<u8> for ComposedSettlementLegV1 {
    type Error = FinalClaimBindingError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x01 => Ok(Self::Upstream),
            0x02 => Ok(Self::Downstream),
            _ => Err(FinalClaimBindingError::UnknownTag),
        }
    }
}

/// Exact pre-funding scope of the claim from which a DOM broadcaster may
/// obtain the adaptor secret.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FinalClaimSecretSourceScopeV1 {
    secret_source: FinalClaimSecretSourceV1,
    reveal_mode: FinalClaimRevealModeV1,
    route_id: Digest32,
    composition_binding_digest: Digest32,
    source_chain_id: ChainId,
    source_settlement_id: SettlementId,
    source_session_id: SessionId,
    source_claim_template_hash: Digest32,
    adaptor_point_sec1: [u8; 33],
    adaptor_secret_origin_id: ParticipantId,
    dom_claim_sender_id: ParticipantId,
}

/// Complete typed input for one exact final-claim secret source scope.
///
/// Grouping these facts prevents positional argument swaps while leaving all
/// semantic validation in [`FinalClaimSecretSourceScopeV1::new`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FinalClaimSecretSourceScopeInputV1 {
    /// Explicit source of the adaptor secret.
    pub secret_source: FinalClaimSecretSourceV1,
    /// Explicit reveal mode for this settlement.
    pub reveal_mode: FinalClaimRevealModeV1,
    /// Route identifier.
    pub route_id: Digest32,
    /// Digest of the exact composed-route binding.
    pub composition_binding_digest: Digest32,
    /// Chain containing the source claim.
    pub source_chain_id: ChainId,
    /// Settlement containing the source claim.
    pub source_settlement_id: SettlementId,
    /// Session containing the source claim.
    pub source_session_id: SessionId,
    /// Exact source claim template hash.
    pub source_claim_template_hash: Digest32,
    /// Compressed adaptor point shared by the route.
    pub adaptor_point_sec1: [u8; 33],
    /// Participant that originally owns the adaptor secret.
    pub adaptor_secret_origin_id: ParticipantId,
    /// Participant authorized to broadcast the DOM claim.
    pub dom_claim_sender_id: ParticipantId,
}

impl FinalClaimSecretSourceScopeV1 {
    /// Construct and validate an exact source scope.  The source claim
    /// template is always explicit; it is never inferred from a route leg.
    pub fn new(input: FinalClaimSecretSourceScopeInputV1) -> Result<Self, FinalClaimBindingError> {
        let FinalClaimSecretSourceScopeInputV1 {
            secret_source,
            reveal_mode,
            route_id,
            composition_binding_digest,
            source_chain_id,
            source_settlement_id,
            source_session_id,
            source_claim_template_hash,
            adaptor_point_sec1,
            adaptor_secret_origin_id,
            dom_claim_sender_id,
        } = input;
        require_nonzero(&route_id, "route_id")?;
        require_nonzero(&composition_binding_digest, "composition_binding_digest")?;
        require_nonzero(&source_chain_id.0, "source_chain_id")?;
        require_nonzero(&source_settlement_id.0, "source_settlement_id")?;
        require_nonzero(&source_session_id.0, "source_session_id")?;
        require_nonzero(&source_claim_template_hash, "source_claim_template_hash")?;
        require_nonzero(&adaptor_secret_origin_id.0, "adaptor_secret_origin_id")?;
        require_nonzero(&dom_claim_sender_id.0, "dom_claim_sender_id")?;
        PublicKey::from_compressed_bytes(&adaptor_point_sec1)
            .map_err(|_| FinalClaimBindingError::InvalidPoint("adaptor_point_sec1"))?;
        validate_mode_source_roles(
            reveal_mode,
            secret_source,
            adaptor_secret_origin_id,
            dom_claim_sender_id,
        )?;
        Ok(Self {
            secret_source,
            reveal_mode,
            route_id,
            composition_binding_digest,
            source_chain_id,
            source_settlement_id,
            source_session_id,
            source_claim_template_hash,
            adaptor_point_sec1,
            adaptor_secret_origin_id,
            dom_claim_sender_id,
        })
    }

    /// Decode the exact closed canonical representation.
    pub fn decode_canonical(bytes: &[u8]) -> Result<Self, FinalClaimBindingError> {
        if bytes.len() != FINAL_CLAIM_SECRET_SOURCE_SCOPE_ENCODED_LEN {
            return Err(FinalClaimBindingError::InvalidLength);
        }
        if bytes.get(..8) != Some(SOURCE_SCOPE_MAGIC) {
            return Err(FinalClaimBindingError::InvalidMagic);
        }
        if read_u16_le(bytes, 8)? != V1 {
            return Err(FinalClaimBindingError::InvalidVersion);
        }
        if bytes.get(12..16) != Some(&[0_u8; 4]) {
            return Err(FinalClaimBindingError::NonZeroReserved);
        }
        Self::new(FinalClaimSecretSourceScopeInputV1 {
            secret_source: FinalClaimSecretSourceV1::try_from(bytes[10])?,
            reveal_mode: FinalClaimRevealModeV1::try_from(bytes[11])?,
            route_id: read_array(bytes, 16)?,
            composition_binding_digest: read_array(bytes, 48)?,
            source_chain_id: ChainId(read_array(bytes, 80)?),
            source_settlement_id: SettlementId(read_array(bytes, 112)?),
            source_session_id: SessionId(read_array(bytes, 144)?),
            source_claim_template_hash: read_array(bytes, 176)?,
            adaptor_point_sec1: read_array(bytes, 208)?,
            adaptor_secret_origin_id: ParticipantId(read_array(bytes, 241)?),
            dom_claim_sender_id: ParticipantId(read_array(bytes, 273)?),
        })
    }

    /// Return the exact 305-byte canonical representation.
    pub fn canonical_bytes(&self) -> [u8; FINAL_CLAIM_SECRET_SOURCE_SCOPE_ENCODED_LEN] {
        let mut out = [0_u8; FINAL_CLAIM_SECRET_SOURCE_SCOPE_ENCODED_LEN];
        out[..8].copy_from_slice(SOURCE_SCOPE_MAGIC);
        out[8..10].copy_from_slice(&V1.to_le_bytes());
        out[10] = self.secret_source.to_byte();
        out[11] = self.reveal_mode.to_byte();
        out[16..48].copy_from_slice(&self.route_id);
        out[48..80].copy_from_slice(&self.composition_binding_digest);
        out[80..112].copy_from_slice(&self.source_chain_id.0);
        out[112..144].copy_from_slice(&self.source_settlement_id.0);
        out[144..176].copy_from_slice(&self.source_session_id.0);
        out[176..208].copy_from_slice(&self.source_claim_template_hash);
        out[208..241].copy_from_slice(&self.adaptor_point_sec1);
        out[241..273].copy_from_slice(&self.adaptor_secret_origin_id.0);
        out[273..305].copy_from_slice(&self.dom_claim_sender_id.0);
        out
    }

    /// Return the tagged digest of the exact canonical representation.
    pub fn digest(&self) -> Digest32 {
        tagged_digest(
            FINAL_CLAIM_SECRET_SOURCE_SCOPE_DOMAIN,
            &self.canonical_bytes(),
        )
    }

    /// Configured secret source.
    pub const fn secret_source(&self) -> FinalClaimSecretSourceV1 {
        self.secret_source
    }
    /// Configured reveal mode.
    pub const fn reveal_mode(&self) -> FinalClaimRevealModeV1 {
        self.reveal_mode
    }
    /// Route identifier.
    pub const fn route_id(&self) -> Digest32 {
        self.route_id
    }
    /// Composed-route binding digest.
    pub const fn composition_binding_digest(&self) -> Digest32 {
        self.composition_binding_digest
    }
    /// Chain containing the source claim.
    pub const fn source_chain_id(&self) -> ChainId {
        self.source_chain_id
    }
    /// Settlement containing the source claim.
    pub const fn source_settlement_id(&self) -> SettlementId {
        self.source_settlement_id
    }
    /// Session containing the source claim.
    pub const fn source_session_id(&self) -> SessionId {
        self.source_session_id
    }
    /// Exact source-claim template digest.
    pub const fn source_claim_template_hash(&self) -> Digest32 {
        self.source_claim_template_hash
    }
    /// Shared adaptor point `T`, compressed SEC1.
    pub const fn adaptor_point_sec1(&self) -> [u8; 33] {
        self.adaptor_point_sec1
    }
    /// Participant that originally owns `t`.
    pub const fn adaptor_secret_origin_id(&self) -> ParticipantId {
        self.adaptor_secret_origin_id
    }
    /// Participant that broadcasts the DOM claim and consumes `t`.
    pub const fn dom_claim_sender_id(&self) -> ParticipantId {
        self.dom_claim_sender_id
    }
}

/// Explicit non-inferred roles and their already constructed source scope for
/// one composed settlement.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FinalClaimRoleSelectionV1 {
    adaptor_secret_origin_id: ParticipantId,
    dom_claim_sender_id: ParticipantId,
    final_claim_receiver_id: ParticipantId,
    reveal_mode: FinalClaimRevealModeV1,
    secret_source: FinalClaimSecretSourceV1,
    source_scope: FinalClaimSecretSourceScopeV1,
}

impl FinalClaimRoleSelectionV1 {
    /// Construct an explicit selection.  The scope is supplied in full so a
    /// claim template is never invented or inferred by the composer.
    pub fn new(
        adaptor_secret_origin_id: ParticipantId,
        dom_claim_sender_id: ParticipantId,
        final_claim_receiver_id: ParticipantId,
        reveal_mode: FinalClaimRevealModeV1,
        secret_source: FinalClaimSecretSourceV1,
        source_scope: FinalClaimSecretSourceScopeV1,
    ) -> Result<Self, FinalClaimBindingError> {
        require_nonzero(&final_claim_receiver_id.0, "final_claim_receiver_id")?;
        if source_scope.adaptor_secret_origin_id() != adaptor_secret_origin_id
            || source_scope.dom_claim_sender_id() != dom_claim_sender_id
            || source_scope.reveal_mode() != reveal_mode
            || source_scope.secret_source() != secret_source
        {
            return Err(FinalClaimBindingError::SourceScopeMismatch);
        }
        validate_bilateral_role_relation(
            reveal_mode,
            secret_source,
            adaptor_secret_origin_id,
            dom_claim_sender_id,
            final_claim_receiver_id,
        )?;
        Ok(Self {
            adaptor_secret_origin_id,
            dom_claim_sender_id,
            final_claim_receiver_id,
            reveal_mode,
            secret_source,
            source_scope,
        })
    }

    /// Participant that originally owns `t`.
    pub const fn adaptor_secret_origin_id(&self) -> ParticipantId {
        self.adaptor_secret_origin_id
    }
    /// Participant authorized to broadcast the DOM claim.
    pub const fn dom_claim_sender_id(&self) -> ParticipantId {
        self.dom_claim_sender_id
    }
    /// Participant authorized to receive the bilateral final-claim message.
    pub const fn final_claim_receiver_id(&self) -> ParticipantId {
        self.final_claim_receiver_id
    }
    /// Explicit reveal mode.
    pub const fn reveal_mode(&self) -> FinalClaimRevealModeV1 {
        self.reveal_mode
    }
    /// Explicit secret source.
    pub const fn secret_source(&self) -> FinalClaimSecretSourceV1 {
        self.secret_source
    }
    /// Exact prebuilt source scope.
    pub const fn source_scope(&self) -> &FinalClaimSecretSourceScopeV1 {
        &self.source_scope
    }
}

/// One explicit fixed-width entry in a composed final-claim role plan.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FinalClaimRolePlanEntryV1 {
    route_leg: ComposedSettlementLegV1,
    reveal_mode: FinalClaimRevealModeV1,
    secret_source: FinalClaimSecretSourceV1,
    settlement_id: SettlementId,
    session_id: SessionId,
    adaptor_secret_origin_id: ParticipantId,
    dom_claim_sender_id: ParticipantId,
    final_claim_receiver_id: ParticipantId,
    secret_source_scope_digest: Digest32,
}

impl FinalClaimRolePlanEntryV1 {
    fn from_selection(
        route_leg: ComposedSettlementLegV1,
        terms: &SettlementTermsV1,
        selection: &FinalClaimRoleSelectionV1,
    ) -> Self {
        Self {
            route_leg,
            reveal_mode: selection.reveal_mode,
            secret_source: selection.secret_source,
            settlement_id: terms.settlement_id,
            session_id: terms.session_id,
            adaptor_secret_origin_id: selection.adaptor_secret_origin_id,
            dom_claim_sender_id: selection.dom_claim_sender_id,
            final_claim_receiver_id: selection.final_claim_receiver_id,
            secret_source_scope_digest: selection.source_scope.digest(),
        }
    }

    /// Explicit settlement position.
    pub const fn route_leg(&self) -> ComposedSettlementLegV1 {
        self.route_leg
    }
    /// Explicit reveal mode.
    pub const fn reveal_mode(&self) -> FinalClaimRevealModeV1 {
        self.reveal_mode
    }
    /// Explicit secret source.
    pub const fn secret_source(&self) -> FinalClaimSecretSourceV1 {
        self.secret_source
    }
    /// Settlement identifier.
    pub const fn settlement_id(&self) -> SettlementId {
        self.settlement_id
    }
    /// Session identifier.
    pub const fn session_id(&self) -> SessionId {
        self.session_id
    }
    /// Participant that originally owns `t`.
    pub const fn adaptor_secret_origin_id(&self) -> ParticipantId {
        self.adaptor_secret_origin_id
    }
    /// Participant authorized to broadcast the DOM claim.
    pub const fn dom_claim_sender_id(&self) -> ParticipantId {
        self.dom_claim_sender_id
    }
    /// Participant authorized to receive the bilateral final-claim message.
    pub const fn final_claim_receiver_id(&self) -> ParticipantId {
        self.final_claim_receiver_id
    }
    /// Digest of the exact source scope.
    pub const fn secret_source_scope_digest(&self) -> Digest32 {
        self.secret_source_scope_digest
    }
}

/// Authenticated explicit role plan for both settlements of one composed
/// route.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ComposedFinalClaimRolePlanV1 {
    route_id: Digest32,
    route_scope_digest: Digest32,
    composition_binding_digest: Digest32,
    upstream: FinalClaimRolePlanEntryV1,
    downstream: FinalClaimRolePlanEntryV1,
}

/// Complete typed input for binding the two ordered settlement role plans.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ComposedFinalClaimRolePlanInputV1<'a> {
    /// Route identifier shared by both settlements.
    pub route_id: Digest32,
    /// Digest of the authenticated route scope.
    pub route_scope_digest: Digest32,
    /// Digest of the exact composed-route binding.
    pub composition_binding_digest: Digest32,
    /// Exact upstream settlement terms.
    pub upstream_terms: &'a SettlementTermsV1,
    /// Exact downstream settlement terms.
    pub downstream_terms: &'a SettlementTermsV1,
    /// Explicit upstream role selection.
    pub upstream_selection: FinalClaimRoleSelectionV1,
    /// Explicit downstream role selection.
    pub downstream_selection: FinalClaimRoleSelectionV1,
}

impl ComposedFinalClaimRolePlanV1 {
    /// Bind two explicit selections to the exact ordered settlement terms and
    /// composition.  Neither route position nor roster index selects a role.
    pub fn bind(
        input: ComposedFinalClaimRolePlanInputV1<'_>,
    ) -> Result<Self, FinalClaimBindingError> {
        let ComposedFinalClaimRolePlanInputV1 {
            route_id,
            route_scope_digest,
            composition_binding_digest,
            upstream_terms,
            downstream_terms,
            upstream_selection,
            downstream_selection,
        } = input;
        require_nonzero(&route_id, "route_id")?;
        require_nonzero(&route_scope_digest, "route_scope_digest")?;
        require_nonzero(&composition_binding_digest, "composition_binding_digest")?;
        upstream_terms
            .validate()
            .map_err(|_| FinalClaimBindingError::InvalidTerms)?;
        downstream_terms
            .validate()
            .map_err(|_| FinalClaimBindingError::InvalidTerms)?;
        if upstream_terms.adaptor_point_sec1 != downstream_terms.adaptor_point_sec1 {
            return Err(FinalClaimBindingError::RolePlanMismatch);
        }
        PublicKey::from_compressed_bytes(&upstream_terms.adaptor_point_sec1)
            .map_err(|_| FinalClaimBindingError::InvalidPoint("adaptor_point_sec1"))?;
        validate_selection_for_terms(
            route_id,
            composition_binding_digest,
            upstream_terms,
            &upstream_selection,
        )?;
        validate_selection_for_terms(
            route_id,
            composition_binding_digest,
            downstream_terms,
            &downstream_selection,
        )?;
        if upstream_selection.adaptor_secret_origin_id
            != downstream_selection.adaptor_secret_origin_id
        {
            return Err(FinalClaimBindingError::InvalidRoleRelation);
        }
        Ok(Self {
            route_id,
            route_scope_digest,
            composition_binding_digest,
            upstream: FinalClaimRolePlanEntryV1::from_selection(
                ComposedSettlementLegV1::Upstream,
                upstream_terms,
                &upstream_selection,
            ),
            downstream: FinalClaimRolePlanEntryV1::from_selection(
                ComposedSettlementLegV1::Downstream,
                downstream_terms,
                &downstream_selection,
            ),
        })
    }

    /// Strictly decode the closed structural wire representation.  Call
    /// [`Self::authenticate`] before treating decoded bytes as a composition
    /// authority.
    pub fn decode_canonical(bytes: &[u8]) -> Result<Self, FinalClaimBindingError> {
        if bytes.len() != COMPOSED_FINAL_CLAIM_ROLE_PLAN_ENCODED_LEN {
            return Err(FinalClaimBindingError::InvalidLength);
        }
        if bytes.get(..8) != Some(ROLE_PLAN_MAGIC) {
            return Err(FinalClaimBindingError::InvalidMagic);
        }
        if read_u16_le(bytes, 8)? != V1 {
            return Err(FinalClaimBindingError::InvalidVersion);
        }
        if bytes[10] != 2 {
            return Err(FinalClaimBindingError::InvalidLength);
        }
        if bytes.get(11..16) != Some(&[0_u8; 5]) {
            return Err(FinalClaimBindingError::NonZeroReserved);
        }
        let route_id = read_array(bytes, 16)?;
        let route_scope_digest = read_array(bytes, 48)?;
        let composition_binding_digest = read_array(bytes, 80)?;
        require_nonzero(&route_id, "route_id")?;
        require_nonzero(&route_scope_digest, "route_scope_digest")?;
        require_nonzero(&composition_binding_digest, "composition_binding_digest")?;
        let upstream = decode_plan_entry(
            bytes
                .get(112..308)
                .ok_or(FinalClaimBindingError::InvalidLength)?,
            ComposedSettlementLegV1::Upstream,
        )?;
        let downstream = decode_plan_entry(
            bytes
                .get(308..504)
                .ok_or(FinalClaimBindingError::InvalidLength)?,
            ComposedSettlementLegV1::Downstream,
        )?;
        if upstream.adaptor_secret_origin_id != downstream.adaptor_secret_origin_id {
            return Err(FinalClaimBindingError::InvalidRoleRelation);
        }
        Ok(Self {
            route_id,
            route_scope_digest,
            composition_binding_digest,
            upstream,
            downstream,
        })
    }

    /// Authenticate a structurally decoded plan against both exact terms and
    /// both complete source scopes, returning no weaker partial result.
    pub fn authenticate(
        &self,
        upstream_terms: &SettlementTermsV1,
        downstream_terms: &SettlementTermsV1,
        upstream_scope: FinalClaimSecretSourceScopeV1,
        downstream_scope: FinalClaimSecretSourceScopeV1,
    ) -> Result<(), FinalClaimBindingError> {
        let upstream_selection = selection_from_entry(self.upstream, upstream_scope)?;
        let downstream_selection = selection_from_entry(self.downstream, downstream_scope)?;
        let rebound = Self::bind(ComposedFinalClaimRolePlanInputV1 {
            route_id: self.route_id,
            route_scope_digest: self.route_scope_digest,
            composition_binding_digest: self.composition_binding_digest,
            upstream_terms,
            downstream_terms,
            upstream_selection,
            downstream_selection,
        })?;
        if rebound.canonical_bytes() != self.canonical_bytes() {
            return Err(FinalClaimBindingError::RolePlanMismatch);
        }
        Ok(())
    }

    /// Return the exact 504-byte canonical representation.
    pub fn canonical_bytes(&self) -> [u8; COMPOSED_FINAL_CLAIM_ROLE_PLAN_ENCODED_LEN] {
        let mut out = [0_u8; COMPOSED_FINAL_CLAIM_ROLE_PLAN_ENCODED_LEN];
        out[..8].copy_from_slice(ROLE_PLAN_MAGIC);
        out[8..10].copy_from_slice(&V1.to_le_bytes());
        out[10] = 2;
        out[16..48].copy_from_slice(&self.route_id);
        out[48..80].copy_from_slice(&self.route_scope_digest);
        out[80..112].copy_from_slice(&self.composition_binding_digest);
        encode_plan_entry(&mut out[112..308], self.upstream);
        encode_plan_entry(&mut out[308..504], self.downstream);
        out
    }

    /// Return the tagged digest of the exact canonical representation.
    pub fn digest(&self) -> Digest32 {
        tagged_digest(
            COMPOSED_FINAL_CLAIM_ROLE_PLAN_DOMAIN,
            &self.canonical_bytes(),
        )
    }

    /// Route identifier.
    pub const fn route_id(&self) -> Digest32 {
        self.route_id
    }
    /// Ordered terms-scope digest supplied by the composer.
    pub const fn route_scope_digest(&self) -> Digest32 {
        self.route_scope_digest
    }
    /// Exact composed-route binding digest.
    pub const fn composition_binding_digest(&self) -> Digest32 {
        self.composition_binding_digest
    }
    /// Explicit entry for the requested settlement position.
    pub const fn entry(&self, leg: ComposedSettlementLegV1) -> &FinalClaimRolePlanEntryV1 {
        match leg {
            ComposedSettlementLegV1::Upstream => &self.upstream,
            ComposedSettlementLegV1::Downstream => &self.downstream,
        }
    }
}

/// Self-contained binding of one settlement's DOM templates, complete roster,
/// explicit composed role plan, and exact source scope.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FinalClaimRoleBindingV1 {
    route_leg: ComposedSettlementLegV1,
    sender_direction: DirectionV1,
    receiver_direction: DirectionV1,
    origin_direction: DirectionV1,
    funding_template_hash: Digest32,
    claim_template_hash: Digest32,
    refund_template_hash: Digest32,
    shared_output_commitment: [u8; 33],
    roster_digest: Digest32,
    claim_kernel_index: u32,
    roster: ParticipantRosterV1,
    role_plan: ComposedFinalClaimRolePlanV1,
    source_scope: FinalClaimSecretSourceScopeV1,
    terms: SettlementTermsV1,
}

/// Public audit-only view of one retained participant entry.
///
/// The entry carries only canonical public bytes. It cannot be converted into
/// an operational `ParticipantIdentityV1`; that type remains constructible only
/// from an authenticated `TrustedChainIdV1` inside `dom-adaptor`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RetainedParticipantEntryAuditV1 {
    participant_id: Digest32,
    identity_public_key_sec1: [u8; 33],
    signing_public_key_sec1: [u8; 33],
    direction: DirectionV1,
}

impl RetainedParticipantEntryAuditV1 {
    /// Canonical participant identifier rederived during retained audit.
    pub const fn participant_id(&self) -> Digest32 {
        self.participant_id
    }

    /// Canonical compressed identity public key.
    pub const fn identity_public_key_sec1(&self) -> [u8; 33] {
        self.identity_public_key_sec1
    }

    /// Canonical compressed signing public key.
    pub const fn signing_public_key_sec1(&self) -> [u8; 33] {
        self.signing_public_key_sec1
    }

    /// Frozen bilateral direction.
    pub const fn direction(&self) -> DirectionV1 {
        self.direction
    }
}

/// Fully validated but deliberately non-operational retained role-binding audit.
///
/// This type permits a durable Store to reread and compare every public binding
/// fact using authenticated retained chain bytes. It contains no
/// `ParticipantIdentityV1` or `ParticipantRosterV1`, and implements no
/// conversion, dereference, or borrowing path to [`FinalClaimRoleBindingV1`].
/// Promotion requires calling [`FinalClaimRoleBindingV1::decode_canonical`] with
/// a real [`TrustedChainIdV1`] and [`Self::canonical_bytes`].
///
/// ```compile_fail
/// use dom_adaptor::ParticipantRosterV1;
/// use dom_final_claim_binding::RetainedFinalClaimRoleBindingAuditV1;
///
/// fn cannot_extract_operational_roster(audit: &RetainedFinalClaimRoleBindingAuditV1) {
///     let _: &ParticipantRosterV1 = audit.roster();
/// }
/// ```
///
/// ```compile_fail
/// use dom_final_claim_binding::{
///     FinalClaimRoleBindingV1, RetainedFinalClaimRoleBindingAuditV1,
/// };
///
/// fn cannot_promote_without_trusted_chain(audit: RetainedFinalClaimRoleBindingAuditV1) {
///     let _: FinalClaimRoleBindingV1 = audit.into();
/// }
/// ```
///
/// ```compile_fail
/// use dom_final_claim_binding::{
///     FinalClaimRoleBindingV1, RetainedFinalClaimRoleBindingAuditV1,
/// };
///
/// fn cannot_borrow_operational_binding(audit: &RetainedFinalClaimRoleBindingAuditV1) {
///     let _: &FinalClaimRoleBindingV1 = audit.as_ref();
/// }
/// ```
///
/// ```compile_fail
/// use dom_final_claim_binding::FinalClaimRoleBindingV1;
///
/// fn removed_operational_retained_decoder(chain_id: &[u8; 32], bytes: &[u8]) {
///     let _ = FinalClaimRoleBindingV1::decode_canonical_for_retained_chain(chain_id, bytes);
/// }
/// ```
///
/// ```compile_fail
/// use dom_final_claim_binding::{
///     OperationalM8ReadyBindingInputV2, OperationalM8ReadyBindingV2,
///     RetainedFinalClaimRoleBindingAuditV1,
/// };
///
/// fn cannot_enter_m8_or_downstream_f7(audit: &RetainedFinalClaimRoleBindingAuditV1) {
///     let _ = OperationalM8ReadyBindingV2::new(OperationalM8ReadyBindingInputV2 {
///         role_binding: audit,
///         m8_policy_digest: [1; 32],
///         refund_tx_hash: [2; 32],
///         bp_statement_hash: [3; 32],
///         recovery_binding_hash: [4; 32],
///         backup_receipt_hash: [5; 32],
///         refund_unlock_height: 1,
///     });
/// }
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
#[must_use]
pub struct RetainedFinalClaimRoleBindingAuditV1 {
    canonical_bytes: Box<[u8]>,
    digest: Digest32,
    route_leg: ComposedSettlementLegV1,
    sender_direction: DirectionV1,
    receiver_direction: DirectionV1,
    origin_direction: DirectionV1,
    funding_template_hash: Digest32,
    claim_template_hash: Digest32,
    refund_template_hash: Digest32,
    shared_output_commitment: [u8; 33],
    roster_digest: Digest32,
    claim_kernel_index: u32,
    roster_entries: [RetainedParticipantEntryAuditV1; 2],
    role_plan: ComposedFinalClaimRolePlanV1,
    source_scope: FinalClaimSecretSourceScopeV1,
    terms: SettlementTermsV1,
}

/// Complete typed input for binding one operational DOM settlement role.
#[derive(Clone, Copy, Debug)]
pub struct FinalClaimRoleBindingInputV1<'a> {
    /// Exact settlement terms.
    pub terms: &'a SettlementTermsV1,
    /// Complete authenticated participant roster.
    pub roster: &'a ParticipantRosterV1,
    /// Authenticated composed-route role plan.
    pub role_plan: &'a ComposedFinalClaimRolePlanV1,
    /// Exact secret source scope for this settlement.
    pub source_scope: &'a FinalClaimSecretSourceScopeV1,
    /// Ordered route position of this settlement.
    pub route_leg: ComposedSettlementLegV1,
    /// Exact funding transaction template hash.
    pub funding_template_hash: Digest32,
    /// Exact claim transaction template hash.
    pub claim_template_hash: Digest32,
    /// Exact refund transaction template hash.
    pub refund_template_hash: Digest32,
    /// Compressed shared-output commitment.
    pub shared_output_commitment: [u8; 33],
    /// Canonical claim kernel index.
    pub claim_kernel_index: u32,
}

struct RetainedFinalClaimRoleBindingInputsV1<'a> {
    terms: &'a SettlementTermsV1,
    roster_entries: &'a [RetainedParticipantEntryAuditV1; 2],
    role_plan: &'a ComposedFinalClaimRolePlanV1,
    source_scope: &'a FinalClaimSecretSourceScopeV1,
    route_leg: ComposedSettlementLegV1,
    funding_template_hash: Digest32,
    claim_template_hash: Digest32,
    refund_template_hash: Digest32,
    shared_output_commitment: [u8; 33],
    claim_kernel_index: u32,
}

impl FinalClaimRoleBindingV1 {
    /// Bind one exact settlement to its complete DOM roster, explicit
    /// composed-role plan, source scope, and three distinct transaction
    /// templates.  Directions are always derived from the complete roster.
    pub fn bind(
        trusted_chain_id: &TrustedChainIdV1,
        input: FinalClaimRoleBindingInputV1<'_>,
    ) -> Result<Self, FinalClaimBindingError> {
        Self::bind_for_expected_chain(trusted_chain_id.as_bytes(), input)
    }

    fn bind_for_expected_chain(
        expected_chain_id: &[u8; 32],
        inputs: FinalClaimRoleBindingInputV1<'_>,
    ) -> Result<Self, FinalClaimBindingError> {
        let FinalClaimRoleBindingInputV1 {
            terms,
            roster,
            role_plan,
            source_scope,
            route_leg,
            funding_template_hash,
            claim_template_hash,
            refund_template_hash,
            shared_output_commitment,
            claim_kernel_index,
        } = inputs;
        terms
            .validate()
            .map_err(|_| FinalClaimBindingError::InvalidTerms)?;
        let terms_bytes = terms
            .canonical_bytes()
            .map_err(|_| FinalClaimBindingError::InvalidTerms)?;
        if terms_bytes.len() + FINAL_CLAIM_ROLE_BINDING_BASE_ENCODED_LEN
            > FINAL_CLAIM_ROLE_BINDING_MAX_ENCODED_LEN
        {
            return Err(FinalClaimBindingError::InvalidLength);
        }
        if expected_chain_id == &[0; 32] || expected_chain_id != &terms.dom_leg.chain_id.0 {
            return Err(FinalClaimBindingError::InvalidRoster);
        }
        validate_terms_topology(terms)?;
        validate_roster_against_terms(roster, terms)?;
        validate_plan_entry_for_binding(role_plan, source_scope, route_leg, terms)?;
        require_nonzero(&funding_template_hash, "funding_template_hash")?;
        require_nonzero(&claim_template_hash, "claim_template_hash")?;
        require_nonzero(&refund_template_hash, "refund_template_hash")?;
        if funding_template_hash == claim_template_hash
            || funding_template_hash == refund_template_hash
            || claim_template_hash == refund_template_hash
        {
            return Err(FinalClaimBindingError::CanonicalMismatch);
        }
        if source_scope.secret_source() == FinalClaimSecretSourceV1::LocalOrigin
            && source_scope.source_claim_template_hash() != claim_template_hash
        {
            return Err(FinalClaimBindingError::SourceScopeMismatch);
        }
        PublicKey::from_compressed_bytes(&terms.adaptor_point_sec1)
            .map_err(|_| FinalClaimBindingError::InvalidPoint("adaptor_point_sec1"))?;
        Commitment::from_compressed_bytes(&shared_output_commitment)
            .map_err(|_| FinalClaimBindingError::InvalidPoint("shared_output_commitment"))?;
        if claim_kernel_index != CLAIM_KERNEL_INDEX {
            return Err(FinalClaimBindingError::CanonicalMismatch);
        }

        let entry = role_plan.entry(route_leg);
        let sender_direction = participant_direction(roster, entry.dom_claim_sender_id())?;
        let receiver_direction = participant_direction(roster, entry.final_claim_receiver_id())?;
        let origin_direction = participant_direction(roster, entry.adaptor_secret_origin_id())?;
        validate_direction_cardinality(roster)?;
        let roster_digest = roster_digest(roster);

        Ok(Self {
            route_leg,
            sender_direction,
            receiver_direction,
            origin_direction,
            funding_template_hash,
            claim_template_hash,
            refund_template_hash,
            shared_output_commitment,
            roster_digest,
            claim_kernel_index,
            roster: roster.clone(),
            role_plan: role_plan.clone(),
            source_scope: source_scope.clone(),
            terms: terms.clone(),
        })
    }

    /// Strictly decode and fully rebind a role binding under an authenticated
    /// local DOM chain identifier.
    pub fn decode_canonical(
        trusted_chain_id: &TrustedChainIdV1,
        bytes: &[u8],
    ) -> Result<Self, FinalClaimBindingError> {
        Self::decode_canonical_for_trusted_chain(trusted_chain_id, bytes)
    }

    fn decode_canonical_for_trusted_chain(
        trusted_chain_id: &TrustedChainIdV1,
        bytes: &[u8],
    ) -> Result<Self, FinalClaimBindingError> {
        if bytes.len() < FINAL_CLAIM_ROLE_BINDING_BASE_ENCODED_LEN
            || bytes.len() > FINAL_CLAIM_ROLE_BINDING_MAX_ENCODED_LEN
        {
            return Err(FinalClaimBindingError::InvalidLength);
        }
        if bytes.get(..8) != Some(ROLE_BINDING_MAGIC) {
            return Err(FinalClaimBindingError::InvalidMagic);
        }
        if read_u16_le(bytes, 8)? != V1 {
            return Err(FinalClaimBindingError::InvalidVersion);
        }
        FinalClaimRevealModeV1::try_from(bytes[10])?;
        FinalClaimSecretSourceV1::try_from(bytes[11])?;
        let route_leg = ComposedSettlementLegV1::try_from(bytes[12])?;
        DirectionV1::try_from(bytes[13]).map_err(|_| FinalClaimBindingError::UnknownTag)?;
        DirectionV1::try_from(bytes[14]).map_err(|_| FinalClaimBindingError::UnknownTag)?;
        DirectionV1::try_from(bytes[15]).map_err(|_| FinalClaimBindingError::UnknownTag)?;
        if read_u32_le(bytes, 594)? != CLAIM_KERNEL_INDEX
            || read_u16_le(bytes, 598)? != PARTICIPANT_COUNT
            || usize::from(read_u16_le(bytes, 600)?) != COMPOSED_FINAL_CLAIM_ROLE_PLAN_ENCODED_LEN
            || usize::from(read_u16_le(bytes, 602)?) != FINAL_CLAIM_SECRET_SOURCE_SCOPE_ENCODED_LEN
        {
            return Err(FinalClaimBindingError::InvalidLength);
        }
        let terms_len = usize::try_from(read_u32_le(bytes, 604)?)
            .map_err(|_| FinalClaimBindingError::InvalidLength)?;
        let expected_len = FINAL_CLAIM_ROLE_BINDING_BASE_ENCODED_LEN
            .checked_add(terms_len)
            .ok_or(FinalClaimBindingError::InvalidLength)?;
        if bytes.len() != expected_len {
            return Err(FinalClaimBindingError::InvalidLength);
        }

        let first = decode_operational_roster_entry(
            trusted_chain_id,
            bytes
                .get(608..707)
                .ok_or(FinalClaimBindingError::InvalidLength)?,
        )?;
        let second = decode_operational_roster_entry(
            trusted_chain_id,
            bytes
                .get(707..806)
                .ok_or(FinalClaimBindingError::InvalidLength)?,
        )?;
        let roster = ParticipantRosterV1::new(vec![first, second])
            .map_err(|_| FinalClaimBindingError::InvalidRoster)?;
        let role_plan = ComposedFinalClaimRolePlanV1::decode_canonical(
            bytes
                .get(806..1_310)
                .ok_or(FinalClaimBindingError::InvalidLength)?,
        )?;
        let source_scope = FinalClaimSecretSourceScopeV1::decode_canonical(
            bytes
                .get(1_310..1_615)
                .ok_or(FinalClaimBindingError::InvalidLength)?,
        )?;
        let terms = SettlementTermsV1::decode(
            bytes
                .get(1_615..)
                .ok_or(FinalClaimBindingError::InvalidLength)?,
        )
        .map_err(|_| FinalClaimBindingError::InvalidTerms)?;
        let rebound = Self::bind_for_expected_chain(
            trusted_chain_id.as_bytes(),
            FinalClaimRoleBindingInputV1 {
                terms: &terms,
                roster: &roster,
                role_plan: &role_plan,
                source_scope: &source_scope,
                route_leg,
                funding_template_hash: read_array(bytes, 433)?,
                claim_template_hash: read_array(bytes, 465)?,
                refund_template_hash: read_array(bytes, 497)?,
                shared_output_commitment: read_array(bytes, 529)?,
                claim_kernel_index: CLAIM_KERNEL_INDEX,
            },
        )?;
        if rebound.canonical_bytes()?.as_slice() != bytes {
            return Err(FinalClaimBindingError::CanonicalMismatch);
        }
        Ok(rebound)
    }

    /// Return the complete variable-length canonical representation.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, FinalClaimBindingError> {
        let terms_bytes = self
            .terms
            .canonical_bytes()
            .map_err(|_| FinalClaimBindingError::InvalidTerms)?;
        let terms_len =
            u32::try_from(terms_bytes.len()).map_err(|_| FinalClaimBindingError::InvalidLength)?;
        let mut out =
            Vec::with_capacity(FINAL_CLAIM_ROLE_BINDING_BASE_ENCODED_LEN + terms_bytes.len());
        let entry = self.role_plan.entry(self.route_leg);
        out.extend_from_slice(ROLE_BINDING_MAGIC);
        out.extend_from_slice(&V1.to_le_bytes());
        out.push(entry.reveal_mode().to_byte());
        out.push(entry.secret_source().to_byte());
        out.push(self.route_leg.to_byte());
        out.push(self.sender_direction.to_byte());
        out.push(self.receiver_direction.to_byte());
        out.push(self.origin_direction.to_byte());
        out.extend_from_slice(&self.role_plan.route_id());
        out.extend_from_slice(&self.role_plan.route_scope_digest());
        out.extend_from_slice(&self.role_plan.composition_binding_digest());
        out.extend_from_slice(&self.role_plan.digest());
        out.extend_from_slice(&self.source_scope.digest());
        out.extend_from_slice(&self.terms.dom_leg.chain_id.0);
        out.extend_from_slice(&self.terms.settlement_id.0);
        out.extend_from_slice(&self.terms.session_id.0);
        out.extend_from_slice(
            &self
                .terms
                .terms_hash()
                .map_err(|_| FinalClaimBindingError::InvalidTerms)?,
        );
        out.extend_from_slice(&entry.adaptor_secret_origin_id().0);
        out.extend_from_slice(&entry.dom_claim_sender_id().0);
        out.extend_from_slice(&entry.final_claim_receiver_id().0);
        out.extend_from_slice(&self.terms.adaptor_point_sec1);
        out.extend_from_slice(&self.funding_template_hash);
        out.extend_from_slice(&self.claim_template_hash);
        out.extend_from_slice(&self.refund_template_hash);
        out.extend_from_slice(&self.shared_output_commitment);
        out.extend_from_slice(&self.roster_digest);
        out.extend_from_slice(&self.claim_kernel_index.to_le_bytes());
        out.extend_from_slice(&PARTICIPANT_COUNT.to_le_bytes());
        out.extend_from_slice(&(COMPOSED_FINAL_CLAIM_ROLE_PLAN_ENCODED_LEN as u16).to_le_bytes());
        out.extend_from_slice(&(FINAL_CLAIM_SECRET_SOURCE_SCOPE_ENCODED_LEN as u16).to_le_bytes());
        out.extend_from_slice(&terms_len.to_le_bytes());
        encode_roster(&mut out, &self.roster);
        out.extend_from_slice(&self.role_plan.canonical_bytes());
        out.extend_from_slice(&self.source_scope.canonical_bytes());
        out.extend_from_slice(&terms_bytes);
        if out.len() != FINAL_CLAIM_ROLE_BINDING_BASE_ENCODED_LEN + terms_bytes.len() {
            return Err(FinalClaimBindingError::CanonicalMismatch);
        }
        Ok(out)
    }

    /// Return the tagged digest of the complete canonical representation.
    pub fn digest(&self) -> Result<Digest32, FinalClaimBindingError> {
        Ok(tagged_digest(
            FINAL_CLAIM_ROLE_BINDING_DOMAIN,
            &self.canonical_bytes()?,
        ))
    }

    /// Explicit composed-settlement position.
    pub const fn route_leg(&self) -> ComposedSettlementLegV1 {
        self.route_leg
    }
    /// Explicit reveal mode.
    pub fn reveal_mode(&self) -> FinalClaimRevealModeV1 {
        self.role_plan.entry(self.route_leg).reveal_mode()
    }
    /// Explicit secret source.
    pub fn secret_source(&self) -> FinalClaimSecretSourceV1 {
        self.role_plan.entry(self.route_leg).secret_source()
    }
    /// Route identifier.
    pub const fn route_id(&self) -> Digest32 {
        self.role_plan.route_id()
    }
    /// Ordered route-scope digest.
    pub const fn route_scope_digest(&self) -> Digest32 {
        self.role_plan.route_scope_digest()
    }
    /// Composed-route binding digest.
    pub const fn composition_binding_digest(&self) -> Digest32 {
        self.role_plan.composition_binding_digest()
    }
    /// Digest of the complete two-leg role plan.
    pub fn composed_role_plan_digest(&self) -> Digest32 {
        self.role_plan.digest()
    }
    /// Digest of the selected leg's source scope.
    pub fn secret_source_scope_digest(&self) -> Digest32 {
        self.source_scope.digest()
    }
    /// DOM chain identifier.
    pub const fn dom_chain_id(&self) -> ChainId {
        self.terms.dom_leg.chain_id
    }
    /// Settlement identifier.
    pub const fn settlement_id(&self) -> SettlementId {
        self.terms.settlement_id
    }
    /// Session identifier.
    pub const fn session_id(&self) -> SessionId {
        self.terms.session_id
    }
    /// Settlement terms hash.
    pub fn terms_hash(&self) -> Result<Digest32, FinalClaimBindingError> {
        self.terms
            .terms_hash()
            .map_err(|_| FinalClaimBindingError::InvalidTerms)
    }
    /// Original adaptor-secret owner.
    pub fn adaptor_secret_origin_id(&self) -> ParticipantId {
        self.role_plan
            .entry(self.route_leg)
            .adaptor_secret_origin_id()
    }
    /// DOM claim sender and broadcaster.
    pub fn dom_claim_sender_id(&self) -> ParticipantId {
        self.role_plan.entry(self.route_leg).dom_claim_sender_id()
    }
    /// Bilateral final-claim receiver.
    pub fn final_claim_receiver_id(&self) -> ParticipantId {
        self.role_plan
            .entry(self.route_leg)
            .final_claim_receiver_id()
    }
    /// Direction derived for the DOM claim sender.
    pub const fn sender_direction(&self) -> DirectionV1 {
        self.sender_direction
    }
    /// Direction derived for the final-claim receiver.
    pub const fn receiver_direction(&self) -> DirectionV1 {
        self.receiver_direction
    }
    /// Direction derived for the original adaptor-secret owner.
    pub const fn origin_direction(&self) -> DirectionV1 {
        self.origin_direction
    }
    /// Shared adaptor point `T`.
    pub const fn adaptor_point_sec1(&self) -> [u8; 33] {
        self.terms.adaptor_point_sec1
    }
    /// Funding transaction template hash.
    pub const fn funding_template_hash(&self) -> Digest32 {
        self.funding_template_hash
    }
    /// Claim transaction template hash.
    pub const fn claim_template_hash(&self) -> Digest32 {
        self.claim_template_hash
    }
    /// Refund transaction template hash.
    pub const fn refund_template_hash(&self) -> Digest32 {
        self.refund_template_hash
    }
    /// Shared-output Pedersen commitment.
    pub const fn shared_output_commitment(&self) -> [u8; 33] {
        self.shared_output_commitment
    }
    /// Complete roster digest including both identity and signing keys.
    pub const fn roster_digest(&self) -> Digest32 {
        self.roster_digest
    }
    /// Claim kernel index, fixed to zero for this profile.
    pub const fn claim_kernel_index(&self) -> u32 {
        self.claim_kernel_index
    }
    /// Exact frozen settlement terms.
    pub const fn terms(&self) -> &SettlementTermsV1 {
        &self.terms
    }
    /// Exact complete participant roster.
    pub const fn roster(&self) -> &ParticipantRosterV1 {
        &self.roster
    }
    /// Exact composed role plan.
    pub const fn role_plan(&self) -> &ComposedFinalClaimRolePlanV1 {
        &self.role_plan
    }
    /// Exact selected source scope.
    pub const fn source_scope(&self) -> &FinalClaimSecretSourceScopeV1 {
        &self.source_scope
    }
}

impl RetainedFinalClaimRoleBindingAuditV1 {
    /// Strictly audit retained canonical bytes against chain bytes already
    /// authenticated by the durable caller.
    ///
    /// Successful audit does not mint an operational role binding, participant
    /// identity, participant roster, readiness binding, or F7 authority.
    pub fn decode_canonical(
        expected_chain_id: &[u8; 32],
        bytes: &[u8],
    ) -> Result<Self, FinalClaimBindingError> {
        if expected_chain_id == &[0; 32] {
            return Err(FinalClaimBindingError::InvalidRoster);
        }
        if bytes.len() < FINAL_CLAIM_ROLE_BINDING_BASE_ENCODED_LEN
            || bytes.len() > FINAL_CLAIM_ROLE_BINDING_MAX_ENCODED_LEN
        {
            return Err(FinalClaimBindingError::InvalidLength);
        }
        if bytes.get(..8) != Some(ROLE_BINDING_MAGIC) {
            return Err(FinalClaimBindingError::InvalidMagic);
        }
        if read_u16_le(bytes, 8)? != V1 {
            return Err(FinalClaimBindingError::InvalidVersion);
        }
        FinalClaimRevealModeV1::try_from(bytes[10])?;
        FinalClaimSecretSourceV1::try_from(bytes[11])?;
        let route_leg = ComposedSettlementLegV1::try_from(bytes[12])?;
        DirectionV1::try_from(bytes[13]).map_err(|_| FinalClaimBindingError::UnknownTag)?;
        DirectionV1::try_from(bytes[14]).map_err(|_| FinalClaimBindingError::UnknownTag)?;
        DirectionV1::try_from(bytes[15]).map_err(|_| FinalClaimBindingError::UnknownTag)?;
        if read_u32_le(bytes, 594)? != CLAIM_KERNEL_INDEX
            || read_u16_le(bytes, 598)? != PARTICIPANT_COUNT
            || usize::from(read_u16_le(bytes, 600)?) != COMPOSED_FINAL_CLAIM_ROLE_PLAN_ENCODED_LEN
            || usize::from(read_u16_le(bytes, 602)?) != FINAL_CLAIM_SECRET_SOURCE_SCOPE_ENCODED_LEN
        {
            return Err(FinalClaimBindingError::InvalidLength);
        }
        let terms_len = usize::try_from(read_u32_le(bytes, 604)?)
            .map_err(|_| FinalClaimBindingError::InvalidLength)?;
        let expected_len = FINAL_CLAIM_ROLE_BINDING_BASE_ENCODED_LEN
            .checked_add(terms_len)
            .ok_or(FinalClaimBindingError::InvalidLength)?;
        if bytes.len() != expected_len {
            return Err(FinalClaimBindingError::InvalidLength);
        }

        let roster_entries = [
            decode_retained_roster_entry(
                expected_chain_id,
                bytes
                    .get(608..707)
                    .ok_or(FinalClaimBindingError::InvalidLength)?,
            )?,
            decode_retained_roster_entry(
                expected_chain_id,
                bytes
                    .get(707..806)
                    .ok_or(FinalClaimBindingError::InvalidLength)?,
            )?,
        ];
        let role_plan = ComposedFinalClaimRolePlanV1::decode_canonical(
            bytes
                .get(806..1_310)
                .ok_or(FinalClaimBindingError::InvalidLength)?,
        )?;
        let source_scope = FinalClaimSecretSourceScopeV1::decode_canonical(
            bytes
                .get(1_310..1_615)
                .ok_or(FinalClaimBindingError::InvalidLength)?,
        )?;
        let terms = SettlementTermsV1::decode(
            bytes
                .get(1_615..)
                .ok_or(FinalClaimBindingError::InvalidLength)?,
        )
        .map_err(|_| FinalClaimBindingError::InvalidTerms)?;
        Self::bind_for_expected_chain(
            expected_chain_id,
            RetainedFinalClaimRoleBindingInputsV1 {
                terms: &terms,
                roster_entries: &roster_entries,
                role_plan: &role_plan,
                source_scope: &source_scope,
                route_leg,
                funding_template_hash: read_array(bytes, 433)?,
                claim_template_hash: read_array(bytes, 465)?,
                refund_template_hash: read_array(bytes, 497)?,
                shared_output_commitment: read_array(bytes, 529)?,
                claim_kernel_index: CLAIM_KERNEL_INDEX,
            },
            bytes,
        )
    }

    fn bind_for_expected_chain(
        expected_chain_id: &[u8; 32],
        inputs: RetainedFinalClaimRoleBindingInputsV1<'_>,
        expected_canonical_bytes: &[u8],
    ) -> Result<Self, FinalClaimBindingError> {
        let RetainedFinalClaimRoleBindingInputsV1 {
            terms,
            roster_entries,
            role_plan,
            source_scope,
            route_leg,
            funding_template_hash,
            claim_template_hash,
            refund_template_hash,
            shared_output_commitment,
            claim_kernel_index,
        } = inputs;
        terms
            .validate()
            .map_err(|_| FinalClaimBindingError::InvalidTerms)?;
        let terms_bytes = terms
            .canonical_bytes()
            .map_err(|_| FinalClaimBindingError::InvalidTerms)?;
        if terms_bytes.len() + FINAL_CLAIM_ROLE_BINDING_BASE_ENCODED_LEN
            > FINAL_CLAIM_ROLE_BINDING_MAX_ENCODED_LEN
        {
            return Err(FinalClaimBindingError::InvalidLength);
        }
        if expected_chain_id == &[0; 32] || expected_chain_id != &terms.dom_leg.chain_id.0 {
            return Err(FinalClaimBindingError::InvalidRoster);
        }
        validate_terms_topology(terms)?;
        validate_retained_roster_against_terms(roster_entries, terms)?;
        validate_plan_entry_for_binding(role_plan, source_scope, route_leg, terms)?;
        require_nonzero(&funding_template_hash, "funding_template_hash")?;
        require_nonzero(&claim_template_hash, "claim_template_hash")?;
        require_nonzero(&refund_template_hash, "refund_template_hash")?;
        if funding_template_hash == claim_template_hash
            || funding_template_hash == refund_template_hash
            || claim_template_hash == refund_template_hash
        {
            return Err(FinalClaimBindingError::CanonicalMismatch);
        }
        if source_scope.secret_source() == FinalClaimSecretSourceV1::LocalOrigin
            && source_scope.source_claim_template_hash() != claim_template_hash
        {
            return Err(FinalClaimBindingError::SourceScopeMismatch);
        }
        PublicKey::from_compressed_bytes(&terms.adaptor_point_sec1)
            .map_err(|_| FinalClaimBindingError::InvalidPoint("adaptor_point_sec1"))?;
        Commitment::from_compressed_bytes(&shared_output_commitment)
            .map_err(|_| FinalClaimBindingError::InvalidPoint("shared_output_commitment"))?;
        if claim_kernel_index != CLAIM_KERNEL_INDEX {
            return Err(FinalClaimBindingError::CanonicalMismatch);
        }

        let entry = role_plan.entry(route_leg);
        let sender_direction =
            retained_participant_direction(roster_entries, entry.dom_claim_sender_id())?;
        let receiver_direction =
            retained_participant_direction(roster_entries, entry.final_claim_receiver_id())?;
        let origin_direction =
            retained_participant_direction(roster_entries, entry.adaptor_secret_origin_id())?;
        validate_retained_direction_cardinality(roster_entries)?;
        let roster_digest = retained_roster_digest(roster_entries);
        let mut audit = Self {
            canonical_bytes: Box::default(),
            digest: [0; 32],
            route_leg,
            sender_direction,
            receiver_direction,
            origin_direction,
            funding_template_hash,
            claim_template_hash,
            refund_template_hash,
            shared_output_commitment,
            roster_digest,
            claim_kernel_index,
            roster_entries: *roster_entries,
            role_plan: role_plan.clone(),
            source_scope: source_scope.clone(),
            terms: terms.clone(),
        };
        let canonical_bytes = audit.reencode_canonical()?;
        if canonical_bytes.as_slice() != expected_canonical_bytes {
            return Err(FinalClaimBindingError::CanonicalMismatch);
        }
        audit.digest = tagged_digest(FINAL_CLAIM_ROLE_BINDING_DOMAIN, &canonical_bytes);
        audit.canonical_bytes = canonical_bytes.into_boxed_slice();
        Ok(audit)
    }

    fn reencode_canonical(&self) -> Result<Vec<u8>, FinalClaimBindingError> {
        let terms_bytes = self
            .terms
            .canonical_bytes()
            .map_err(|_| FinalClaimBindingError::InvalidTerms)?;
        let terms_len =
            u32::try_from(terms_bytes.len()).map_err(|_| FinalClaimBindingError::InvalidLength)?;
        let mut out =
            Vec::with_capacity(FINAL_CLAIM_ROLE_BINDING_BASE_ENCODED_LEN + terms_bytes.len());
        let entry = self.role_plan.entry(self.route_leg);
        out.extend_from_slice(ROLE_BINDING_MAGIC);
        out.extend_from_slice(&V1.to_le_bytes());
        out.push(entry.reveal_mode().to_byte());
        out.push(entry.secret_source().to_byte());
        out.push(self.route_leg.to_byte());
        out.push(self.sender_direction.to_byte());
        out.push(self.receiver_direction.to_byte());
        out.push(self.origin_direction.to_byte());
        out.extend_from_slice(&self.role_plan.route_id());
        out.extend_from_slice(&self.role_plan.route_scope_digest());
        out.extend_from_slice(&self.role_plan.composition_binding_digest());
        out.extend_from_slice(&self.role_plan.digest());
        out.extend_from_slice(&self.source_scope.digest());
        out.extend_from_slice(&self.terms.dom_leg.chain_id.0);
        out.extend_from_slice(&self.terms.settlement_id.0);
        out.extend_from_slice(&self.terms.session_id.0);
        out.extend_from_slice(
            &self
                .terms
                .terms_hash()
                .map_err(|_| FinalClaimBindingError::InvalidTerms)?,
        );
        out.extend_from_slice(&entry.adaptor_secret_origin_id().0);
        out.extend_from_slice(&entry.dom_claim_sender_id().0);
        out.extend_from_slice(&entry.final_claim_receiver_id().0);
        out.extend_from_slice(&self.terms.adaptor_point_sec1);
        out.extend_from_slice(&self.funding_template_hash);
        out.extend_from_slice(&self.claim_template_hash);
        out.extend_from_slice(&self.refund_template_hash);
        out.extend_from_slice(&self.shared_output_commitment);
        out.extend_from_slice(&self.roster_digest);
        out.extend_from_slice(&self.claim_kernel_index.to_le_bytes());
        out.extend_from_slice(&PARTICIPANT_COUNT.to_le_bytes());
        out.extend_from_slice(&(COMPOSED_FINAL_CLAIM_ROLE_PLAN_ENCODED_LEN as u16).to_le_bytes());
        out.extend_from_slice(&(FINAL_CLAIM_SECRET_SOURCE_SCOPE_ENCODED_LEN as u16).to_le_bytes());
        out.extend_from_slice(&terms_len.to_le_bytes());
        encode_retained_roster(&mut out, &self.roster_entries);
        out.extend_from_slice(&self.role_plan.canonical_bytes());
        out.extend_from_slice(&self.source_scope.canonical_bytes());
        out.extend_from_slice(&terms_bytes);
        if out.len() != FINAL_CLAIM_ROLE_BINDING_BASE_ENCODED_LEN + terms_bytes.len() {
            return Err(FinalClaimBindingError::CanonicalMismatch);
        }
        Ok(out)
    }

    /// Exact retained canonical bytes that passed complete reencoding.
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }

    /// Tagged digest of the exact retained canonical bytes.
    pub const fn digest(&self) -> Digest32 {
        self.digest
    }

    /// Audit-only roster entries containing public canonical bytes.
    pub const fn roster_entries(&self) -> &[RetainedParticipantEntryAuditV1; 2] {
        &self.roster_entries
    }

    /// Explicit composed-settlement position.
    pub const fn route_leg(&self) -> ComposedSettlementLegV1 {
        self.route_leg
    }

    /// Explicit reveal mode.
    pub fn reveal_mode(&self) -> FinalClaimRevealModeV1 {
        self.role_plan.entry(self.route_leg).reveal_mode()
    }

    /// Explicit secret source.
    pub fn secret_source(&self) -> FinalClaimSecretSourceV1 {
        self.role_plan.entry(self.route_leg).secret_source()
    }

    /// Route identifier.
    pub const fn route_id(&self) -> Digest32 {
        self.role_plan.route_id()
    }

    /// Ordered route-scope digest.
    pub const fn route_scope_digest(&self) -> Digest32 {
        self.role_plan.route_scope_digest()
    }

    /// Composed-route binding digest.
    pub const fn composition_binding_digest(&self) -> Digest32 {
        self.role_plan.composition_binding_digest()
    }

    /// Digest of the complete two-leg role plan.
    pub fn composed_role_plan_digest(&self) -> Digest32 {
        self.role_plan.digest()
    }

    /// Digest of the selected leg's source scope.
    pub fn secret_source_scope_digest(&self) -> Digest32 {
        self.source_scope.digest()
    }

    /// DOM chain identifier retained in canonical settlement terms.
    pub const fn dom_chain_id(&self) -> ChainId {
        self.terms.dom_leg.chain_id
    }

    /// Settlement identifier.
    pub const fn settlement_id(&self) -> SettlementId {
        self.terms.settlement_id
    }

    /// Session identifier.
    pub const fn session_id(&self) -> SessionId {
        self.terms.session_id
    }

    /// Settlement terms hash.
    pub fn terms_hash(&self) -> Result<Digest32, FinalClaimBindingError> {
        self.terms
            .terms_hash()
            .map_err(|_| FinalClaimBindingError::InvalidTerms)
    }

    /// Original adaptor-secret owner.
    pub fn adaptor_secret_origin_id(&self) -> ParticipantId {
        self.role_plan
            .entry(self.route_leg)
            .adaptor_secret_origin_id()
    }

    /// DOM claim sender and broadcaster.
    pub fn dom_claim_sender_id(&self) -> ParticipantId {
        self.role_plan.entry(self.route_leg).dom_claim_sender_id()
    }

    /// Bilateral final-claim receiver.
    pub fn final_claim_receiver_id(&self) -> ParticipantId {
        self.role_plan
            .entry(self.route_leg)
            .final_claim_receiver_id()
    }

    /// Direction derived for the DOM claim sender.
    pub const fn sender_direction(&self) -> DirectionV1 {
        self.sender_direction
    }

    /// Direction derived for the final-claim receiver.
    pub const fn receiver_direction(&self) -> DirectionV1 {
        self.receiver_direction
    }

    /// Direction derived for the original adaptor-secret owner.
    pub const fn origin_direction(&self) -> DirectionV1 {
        self.origin_direction
    }

    /// Shared adaptor point `T`.
    pub const fn adaptor_point_sec1(&self) -> [u8; 33] {
        self.terms.adaptor_point_sec1
    }

    /// Funding transaction template hash.
    pub const fn funding_template_hash(&self) -> Digest32 {
        self.funding_template_hash
    }

    /// Claim transaction template hash.
    pub const fn claim_template_hash(&self) -> Digest32 {
        self.claim_template_hash
    }

    /// Refund transaction template hash.
    pub const fn refund_template_hash(&self) -> Digest32 {
        self.refund_template_hash
    }

    /// Shared-output Pedersen commitment.
    pub const fn shared_output_commitment(&self) -> [u8; 33] {
        self.shared_output_commitment
    }

    /// Digest of the complete audit-only roster encoding.
    pub const fn roster_digest(&self) -> Digest32 {
        self.roster_digest
    }

    /// Claim kernel index, fixed to zero for this profile.
    pub const fn claim_kernel_index(&self) -> u32 {
        self.claim_kernel_index
    }

    /// Exact frozen settlement terms.
    pub const fn terms(&self) -> &SettlementTermsV1 {
        &self.terms
    }

    /// Exact composed role plan.
    pub const fn role_plan(&self) -> &ComposedFinalClaimRolePlanV1 {
        &self.role_plan
    }

    /// Exact selected source scope.
    pub const fn source_scope(&self) -> &FinalClaimSecretSourceScopeV1 {
        &self.source_scope
    }
}

#[derive(Clone, Copy)]
struct ReadyRoleFactsV1 {
    route_id: Digest32,
    composition_binding_digest: Digest32,
    dom_chain_id: ChainId,
    settlement_id: SettlementId,
    session_id: SessionId,
    terms_hash: Digest32,
    final_claim_role_binding_digest: Digest32,
    roster_digest: Digest32,
    funding_template_hash: Digest32,
    claim_template_hash: Digest32,
    refund_template_hash: Digest32,
    shared_output_commitment: [u8; 33],
    adaptor_point_sec1: [u8; 33],
    claim_kernel_index: u32,
}

impl ReadyRoleFactsV1 {
    fn from_operational(
        role_binding: &FinalClaimRoleBindingV1,
    ) -> Result<Self, FinalClaimBindingError> {
        Ok(Self {
            route_id: role_binding.route_id(),
            composition_binding_digest: role_binding.composition_binding_digest(),
            dom_chain_id: role_binding.dom_chain_id(),
            settlement_id: role_binding.settlement_id(),
            session_id: role_binding.session_id(),
            terms_hash: role_binding.terms_hash()?,
            final_claim_role_binding_digest: role_binding.digest()?,
            roster_digest: role_binding.roster_digest(),
            funding_template_hash: role_binding.funding_template_hash(),
            claim_template_hash: role_binding.claim_template_hash(),
            refund_template_hash: role_binding.refund_template_hash(),
            shared_output_commitment: role_binding.shared_output_commitment(),
            adaptor_point_sec1: role_binding.adaptor_point_sec1(),
            claim_kernel_index: role_binding.claim_kernel_index(),
        })
    }

    fn from_retained(
        role_binding: &RetainedFinalClaimRoleBindingAuditV1,
    ) -> Result<Self, FinalClaimBindingError> {
        Ok(Self {
            route_id: role_binding.route_id(),
            composition_binding_digest: role_binding.composition_binding_digest(),
            dom_chain_id: role_binding.dom_chain_id(),
            settlement_id: role_binding.settlement_id(),
            session_id: role_binding.session_id(),
            terms_hash: role_binding.terms_hash()?,
            final_claim_role_binding_digest: role_binding.digest(),
            roster_digest: role_binding.roster_digest(),
            funding_template_hash: role_binding.funding_template_hash(),
            claim_template_hash: role_binding.claim_template_hash(),
            refund_template_hash: role_binding.refund_template_hash(),
            shared_output_commitment: role_binding.shared_output_commitment(),
            adaptor_point_sec1: role_binding.adaptor_point_sec1(),
            claim_kernel_index: role_binding.claim_kernel_index(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ReadyBindingFactsV2 {
    route_id: Digest32,
    composition_binding_digest: Digest32,
    dom_chain_id: ChainId,
    settlement_id: SettlementId,
    session_id: SessionId,
    terms_hash: Digest32,
    m8_policy_digest: Digest32,
    final_claim_role_binding_digest: Digest32,
    roster_digest: Digest32,
    funding_template_hash: Digest32,
    claim_template_hash: Digest32,
    refund_template_hash: Digest32,
    shared_output_commitment: [u8; 33],
    adaptor_point_sec1: [u8; 33],
    refund_tx_hash: Digest32,
    bp_statement_hash: Digest32,
    recovery_binding_hash: Digest32,
    backup_receipt_hash: Digest32,
    refund_unlock_height: u64,
    claim_kernel_index: u32,
}

impl ReadyBindingFactsV2 {
    fn new(
        role: ReadyRoleFactsV1,
        m8_policy_digest: Digest32,
        refund_tx_hash: Digest32,
        bp_statement_hash: Digest32,
        recovery_binding_hash: Digest32,
        backup_receipt_hash: Digest32,
        refund_unlock_height: u64,
    ) -> Result<Self, FinalClaimBindingError> {
        require_nonzero(&m8_policy_digest, "m8_policy_digest")?;
        require_nonzero(&refund_tx_hash, "refund_tx_hash")?;
        require_nonzero(&bp_statement_hash, "bp_statement_hash")?;
        require_nonzero(&recovery_binding_hash, "recovery_binding_hash")?;
        require_nonzero(&backup_receipt_hash, "backup_receipt_hash")?;
        if refund_unlock_height == 0 {
            return Err(FinalClaimBindingError::ZeroField("refund_unlock_height"));
        }
        Ok(Self {
            route_id: role.route_id,
            composition_binding_digest: role.composition_binding_digest,
            dom_chain_id: role.dom_chain_id,
            settlement_id: role.settlement_id,
            session_id: role.session_id,
            terms_hash: role.terms_hash,
            m8_policy_digest,
            final_claim_role_binding_digest: role.final_claim_role_binding_digest,
            roster_digest: role.roster_digest,
            funding_template_hash: role.funding_template_hash,
            claim_template_hash: role.claim_template_hash,
            refund_template_hash: role.refund_template_hash,
            shared_output_commitment: role.shared_output_commitment,
            adaptor_point_sec1: role.adaptor_point_sec1,
            refund_tx_hash,
            bp_statement_hash,
            recovery_binding_hash,
            backup_receipt_hash,
            refund_unlock_height,
            claim_kernel_index: role.claim_kernel_index,
        })
    }

    fn decode_canonical(
        role: ReadyRoleFactsV1,
        bytes: &[u8],
    ) -> Result<Self, FinalClaimBindingError> {
        if bytes.len() != OPERATIONAL_M8_READY_BINDING_ENCODED_LEN {
            return Err(FinalClaimBindingError::InvalidLength);
        }
        if bytes.get(..8) != Some(READY_BINDING_MAGIC) {
            return Err(FinalClaimBindingError::InvalidMagic);
        }
        if read_u16_le(bytes, 8)? != V2 {
            return Err(FinalClaimBindingError::InvalidVersion);
        }
        if bytes.get(10..14) != Some(READY_BINDING_PROFILE) {
            return Err(FinalClaimBindingError::InvalidMagic);
        }
        if bytes.get(14..16) != Some(&[0_u8; 2]) || bytes.get(606..608) != Some(&[0_u8; 2]) {
            return Err(FinalClaimBindingError::NonZeroReserved);
        }
        if read_u32_le(bytes, 602)? != CLAIM_KERNEL_INDEX {
            return Err(FinalClaimBindingError::CanonicalMismatch);
        }
        let rebound = Self::new(
            role,
            read_array(bytes, 208)?,
            read_array(bytes, 466)?,
            read_array(bytes, 498)?,
            read_array(bytes, 530)?,
            read_array(bytes, 562)?,
            read_u64_le(bytes, 594)?,
        )?;
        if rebound.canonical_bytes().as_slice() != bytes {
            return Err(FinalClaimBindingError::CanonicalMismatch);
        }
        Ok(rebound)
    }

    fn canonical_bytes(&self) -> [u8; OPERATIONAL_M8_READY_BINDING_ENCODED_LEN] {
        let mut out = [0_u8; OPERATIONAL_M8_READY_BINDING_ENCODED_LEN];
        out[..8].copy_from_slice(READY_BINDING_MAGIC);
        out[8..10].copy_from_slice(&V2.to_le_bytes());
        out[10..14].copy_from_slice(READY_BINDING_PROFILE);
        out[16..48].copy_from_slice(&self.route_id);
        out[48..80].copy_from_slice(&self.composition_binding_digest);
        out[80..112].copy_from_slice(&self.dom_chain_id.0);
        out[112..144].copy_from_slice(&self.settlement_id.0);
        out[144..176].copy_from_slice(&self.session_id.0);
        out[176..208].copy_from_slice(&self.terms_hash);
        out[208..240].copy_from_slice(&self.m8_policy_digest);
        out[240..272].copy_from_slice(&self.final_claim_role_binding_digest);
        out[272..304].copy_from_slice(&self.roster_digest);
        out[304..336].copy_from_slice(&self.funding_template_hash);
        out[336..368].copy_from_slice(&self.claim_template_hash);
        out[368..400].copy_from_slice(&self.refund_template_hash);
        out[400..433].copy_from_slice(&self.shared_output_commitment);
        out[433..466].copy_from_slice(&self.adaptor_point_sec1);
        out[466..498].copy_from_slice(&self.refund_tx_hash);
        out[498..530].copy_from_slice(&self.bp_statement_hash);
        out[530..562].copy_from_slice(&self.recovery_binding_hash);
        out[562..594].copy_from_slice(&self.backup_receipt_hash);
        out[594..602].copy_from_slice(&self.refund_unlock_height.to_le_bytes());
        out[602..606].copy_from_slice(&self.claim_kernel_index.to_le_bytes());
        out
    }
}

/// Bilateral, deterministic readiness binding signed by both `ReadyToFund`
/// voters.  Local height, wall clock, revision, tip, projection, and local
/// record digests are intentionally absent from this type and constructor.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OperationalM8ReadyBindingV2 {
    facts: ReadyBindingFactsV2,
}

/// Complete typed input for the deterministic bilateral M.8 readiness vote.
#[derive(Clone, Copy, Debug)]
pub struct OperationalM8ReadyBindingInputV2<'a> {
    /// Fully authenticated final-claim role binding.
    pub role_binding: &'a FinalClaimRoleBindingV1,
    /// Digest of the exact M.8 policy.
    pub m8_policy_digest: Digest32,
    /// Exact refund transaction hash.
    pub refund_tx_hash: Digest32,
    /// Exact Bulletproof statement hash.
    pub bp_statement_hash: Digest32,
    /// Exact recovery binding hash.
    pub recovery_binding_hash: Digest32,
    /// Exact backup receipt hash.
    pub backup_receipt_hash: Digest32,
    /// Absolute refund unlock height.
    pub refund_unlock_height: u64,
}

impl OperationalM8ReadyBindingV2 {
    /// Construct the deterministic bilateral vote payload binding.
    ///
    /// Local store facts are deliberately not accepted by this API.  They
    /// belong only to the owner-local funding-gate record.
    pub fn new(
        input: OperationalM8ReadyBindingInputV2<'_>,
    ) -> Result<Self, FinalClaimBindingError> {
        let OperationalM8ReadyBindingInputV2 {
            role_binding,
            m8_policy_digest,
            refund_tx_hash,
            bp_statement_hash,
            recovery_binding_hash,
            backup_receipt_hash,
            refund_unlock_height,
        } = input;
        Ok(Self {
            facts: ReadyBindingFactsV2::new(
                ReadyRoleFactsV1::from_operational(role_binding)?,
                m8_policy_digest,
                refund_tx_hash,
                bp_statement_hash,
                recovery_binding_hash,
                backup_receipt_hash,
                refund_unlock_height,
            )?,
        })
    }

    /// Decode and rebind exact canonical bytes against the supplied role
    /// binding.  A role-binding mismatch is rejected byte-for-byte.
    pub fn decode_canonical(
        role_binding: &FinalClaimRoleBindingV1,
        bytes: &[u8],
    ) -> Result<Self, FinalClaimBindingError> {
        Ok(Self {
            facts: ReadyBindingFactsV2::decode_canonical(
                ReadyRoleFactsV1::from_operational(role_binding)?,
                bytes,
            )?,
        })
    }

    /// Return the exact 608-byte canonical representation.
    pub fn canonical_bytes(&self) -> [u8; OPERATIONAL_M8_READY_BINDING_ENCODED_LEN] {
        self.facts.canonical_bytes()
    }

    /// Return the exact bilateral payload digest carried by both 0x11 votes.
    pub fn digest(&self) -> Digest32 {
        tagged_digest(
            OPERATIONAL_M8_READY_BINDING_DOMAIN,
            &self.facts.canonical_bytes(),
        )
    }

    /// Route identifier.
    pub const fn route_id(&self) -> Digest32 {
        self.facts.route_id
    }
    /// Composed-route binding digest.
    pub const fn composition_binding_digest(&self) -> Digest32 {
        self.facts.composition_binding_digest
    }
    /// DOM chain identifier.
    pub const fn dom_chain_id(&self) -> ChainId {
        self.facts.dom_chain_id
    }
    /// Settlement identifier.
    pub const fn settlement_id(&self) -> SettlementId {
        self.facts.settlement_id
    }
    /// Session identifier.
    pub const fn session_id(&self) -> SessionId {
        self.facts.session_id
    }
    /// Exact terms hash.
    pub const fn terms_hash(&self) -> Digest32 {
        self.facts.terms_hash
    }
    /// M.8 timing/recovery policy digest.
    pub const fn m8_policy_digest(&self) -> Digest32 {
        self.facts.m8_policy_digest
    }
    /// Exact final-claim role-binding digest.
    pub const fn final_claim_role_binding_digest(&self) -> Digest32 {
        self.facts.final_claim_role_binding_digest
    }
    /// Complete DOM roster digest.
    pub const fn roster_digest(&self) -> Digest32 {
        self.facts.roster_digest
    }
    /// Funding template hash.
    pub const fn funding_template_hash(&self) -> Digest32 {
        self.facts.funding_template_hash
    }
    /// Claim template hash.
    pub const fn claim_template_hash(&self) -> Digest32 {
        self.facts.claim_template_hash
    }
    /// Refund template hash.
    pub const fn refund_template_hash(&self) -> Digest32 {
        self.facts.refund_template_hash
    }
    /// Shared-output commitment.
    pub const fn shared_output_commitment(&self) -> [u8; 33] {
        self.facts.shared_output_commitment
    }
    /// Shared adaptor point `T`.
    pub const fn adaptor_point_sec1(&self) -> [u8; 33] {
        self.facts.adaptor_point_sec1
    }
    /// Pre-signed refund transaction hash.
    pub const fn refund_tx_hash(&self) -> Digest32 {
        self.facts.refund_tx_hash
    }
    /// Collaborative Bulletproof statement hash.
    pub const fn bp_statement_hash(&self) -> Digest32 {
        self.facts.bp_statement_hash
    }
    /// Recovery-binding hash.
    pub const fn recovery_binding_hash(&self) -> Digest32 {
        self.facts.recovery_binding_hash
    }
    /// Bilateral backup receipt hash.
    pub const fn backup_receipt_hash(&self) -> Digest32 {
        self.facts.backup_receipt_hash
    }
    /// Refund unlock height.
    pub const fn refund_unlock_height(&self) -> u64 {
        self.facts.refund_unlock_height
    }
    /// Claim kernel index, fixed to zero.
    pub const fn claim_kernel_index(&self) -> u32 {
        self.facts.claim_kernel_index
    }
}

/// Fully validated, deliberately non-operational audit of a retained M.8 V2
/// readiness binding.
///
/// This type can be reconstructed from an already authenticated retained role
/// audit without fabricating a [`TrustedChainIdV1`].  It exposes only public
/// canonical facts and has no conversion, dereference, or borrowing path to
/// [`OperationalM8ReadyBindingV2`].  A live operational binding still requires
/// decoding the role binding under a real trusted-chain authority first.
///
/// ```compile_fail
/// use dom_final_claim_binding::{
///     OperationalM8ReadyBindingV2, RetainedOperationalM8ReadyBindingAuditV2,
/// };
///
/// fn cannot_promote_retained_ready(
///     audit: RetainedOperationalM8ReadyBindingAuditV2,
/// ) {
///     let _: OperationalM8ReadyBindingV2 = audit.into();
/// }
/// ```
///
/// ```compile_fail
/// use dom_final_claim_binding::{
///     OperationalM8ReadyBindingV2, RetainedOperationalM8ReadyBindingAuditV2,
/// };
///
/// fn cannot_borrow_operational_ready(
///     audit: &RetainedOperationalM8ReadyBindingAuditV2,
/// ) {
///     let _: &OperationalM8ReadyBindingV2 = audit.as_ref();
/// }
/// ```
///
/// ```compile_fail
/// use dom_final_claim_binding::{
///     OperationalM8ReadyBindingV2, RetainedOperationalM8ReadyBindingAuditV2,
/// };
///
/// fn cannot_decode_operational_ready_from_retained_audit(
///     audit: &RetainedOperationalM8ReadyBindingAuditV2,
///     bytes: &[u8],
/// ) {
///     let _ = OperationalM8ReadyBindingV2::decode_canonical(audit, bytes);
/// }
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
#[must_use]
pub struct RetainedOperationalM8ReadyBindingAuditV2 {
    canonical_bytes: [u8; OPERATIONAL_M8_READY_BINDING_ENCODED_LEN],
    digest: Digest32,
    facts: ReadyBindingFactsV2,
}

impl RetainedOperationalM8ReadyBindingAuditV2 {
    /// Strictly audit retained canonical readiness bytes against an already
    /// fully reauthenticated retained role-binding audit.
    ///
    /// Success does not mint a funding gate, vote, funding authorization,
    /// post-anchor signing authorization, F7 capability, or operational role
    /// or readiness binding.
    pub fn decode_canonical(
        role_binding: &RetainedFinalClaimRoleBindingAuditV1,
        bytes: &[u8],
    ) -> Result<Self, FinalClaimBindingError> {
        let facts = ReadyBindingFactsV2::decode_canonical(
            ReadyRoleFactsV1::from_retained(role_binding)?,
            bytes,
        )?;
        let canonical_bytes = facts.canonical_bytes();
        Ok(Self {
            digest: tagged_digest(OPERATIONAL_M8_READY_BINDING_DOMAIN, &canonical_bytes),
            canonical_bytes,
            facts,
        })
    }

    /// Exact 608-byte retained canonical representation.
    pub const fn canonical_bytes(&self) -> &[u8; OPERATIONAL_M8_READY_BINDING_ENCODED_LEN] {
        &self.canonical_bytes
    }

    /// Exact bilateral payload digest carried by both retained 0x11 votes.
    pub const fn digest(&self) -> Digest32 {
        self.digest
    }

    /// Route identifier.
    pub const fn route_id(&self) -> Digest32 {
        self.facts.route_id
    }

    /// Composed-route binding digest.
    pub const fn composition_binding_digest(&self) -> Digest32 {
        self.facts.composition_binding_digest
    }

    /// DOM chain identifier.
    pub const fn dom_chain_id(&self) -> ChainId {
        self.facts.dom_chain_id
    }

    /// Settlement identifier.
    pub const fn settlement_id(&self) -> SettlementId {
        self.facts.settlement_id
    }

    /// Session identifier.
    pub const fn session_id(&self) -> SessionId {
        self.facts.session_id
    }

    /// Exact terms hash.
    pub const fn terms_hash(&self) -> Digest32 {
        self.facts.terms_hash
    }

    /// M.8 timing/recovery policy digest.
    pub const fn m8_policy_digest(&self) -> Digest32 {
        self.facts.m8_policy_digest
    }

    /// Exact retained final-claim role-binding digest.
    pub const fn final_claim_role_binding_digest(&self) -> Digest32 {
        self.facts.final_claim_role_binding_digest
    }

    /// Complete audit-only DOM roster digest.
    pub const fn roster_digest(&self) -> Digest32 {
        self.facts.roster_digest
    }

    /// Funding transaction template hash.
    pub const fn funding_template_hash(&self) -> Digest32 {
        self.facts.funding_template_hash
    }

    /// Claim transaction template hash.
    pub const fn claim_template_hash(&self) -> Digest32 {
        self.facts.claim_template_hash
    }

    /// Refund transaction template hash.
    pub const fn refund_template_hash(&self) -> Digest32 {
        self.facts.refund_template_hash
    }

    /// Shared-output commitment.
    pub const fn shared_output_commitment(&self) -> [u8; 33] {
        self.facts.shared_output_commitment
    }

    /// Shared adaptor point `T`.
    pub const fn adaptor_point_sec1(&self) -> [u8; 33] {
        self.facts.adaptor_point_sec1
    }

    /// Pre-signed refund transaction hash.
    pub const fn refund_tx_hash(&self) -> Digest32 {
        self.facts.refund_tx_hash
    }

    /// Collaborative Bulletproof statement hash.
    pub const fn bp_statement_hash(&self) -> Digest32 {
        self.facts.bp_statement_hash
    }

    /// Recovery-binding hash.
    pub const fn recovery_binding_hash(&self) -> Digest32 {
        self.facts.recovery_binding_hash
    }

    /// Bilateral backup receipt hash.
    pub const fn backup_receipt_hash(&self) -> Digest32 {
        self.facts.backup_receipt_hash
    }

    /// Refund unlock height.
    pub const fn refund_unlock_height(&self) -> u64 {
        self.facts.refund_unlock_height
    }

    /// Claim kernel index, fixed to zero.
    pub const fn claim_kernel_index(&self) -> u32 {
        self.facts.claim_kernel_index
    }
}

fn require_nonzero(value: &Digest32, name: &'static str) -> Result<(), FinalClaimBindingError> {
    if value == &[0_u8; 32] {
        return Err(FinalClaimBindingError::ZeroField(name));
    }
    Ok(())
}

fn tagged_digest(domain: &str, bytes: &[u8]) -> Digest32 {
    *blake2b_256_tagged(domain, bytes).as_bytes()
}

fn validate_mode_source_roles(
    reveal_mode: FinalClaimRevealModeV1,
    secret_source: FinalClaimSecretSourceV1,
    origin: ParticipantId,
    sender: ParticipantId,
) -> Result<(), FinalClaimBindingError> {
    match (reveal_mode, secret_source) {
        (FinalClaimRevealModeV1::DomRevealsFirst, FinalClaimSecretSourceV1::LocalOrigin) => {
            if origin != sender {
                return Err(FinalClaimBindingError::InvalidRoleRelation);
            }
        }
        (
            FinalClaimRevealModeV1::DomReactsToCounterpartyReveal,
            FinalClaimSecretSourceV1::VerifiedCounterpartyClaim,
        ) => {
            if origin == sender {
                return Err(FinalClaimBindingError::InvalidRoleRelation);
            }
        }
        _ => return Err(FinalClaimBindingError::InvalidModeSource),
    }
    Ok(())
}

fn validate_bilateral_role_relation(
    reveal_mode: FinalClaimRevealModeV1,
    secret_source: FinalClaimSecretSourceV1,
    origin: ParticipantId,
    sender: ParticipantId,
    receiver: ParticipantId,
) -> Result<(), FinalClaimBindingError> {
    validate_mode_source_roles(reveal_mode, secret_source, origin, sender)?;
    if sender == receiver {
        return Err(FinalClaimBindingError::InvalidRoleRelation);
    }
    match reveal_mode {
        FinalClaimRevealModeV1::DomRevealsFirst if origin == sender => Ok(()),
        FinalClaimRevealModeV1::DomReactsToCounterpartyReveal if origin == receiver => Ok(()),
        _ => Err(FinalClaimBindingError::InvalidRoleRelation),
    }
}

fn validate_terms_topology(terms: &SettlementTermsV1) -> Result<(), FinalClaimBindingError> {
    if terms.dom_leg.beneficiary == terms.dom_leg.refund_to
        || terms.dom_leg.beneficiary != terms.counterparty_leg.refund_to
        || terms.dom_leg.refund_to != terms.counterparty_leg.beneficiary
    {
        return Err(FinalClaimBindingError::InvalidTopology);
    }
    let first = terms.roster[0];
    let second = terms.roster[1];
    if !((terms.dom_leg.beneficiary == first && terms.dom_leg.refund_to == second)
        || (terms.dom_leg.beneficiary == second && terms.dom_leg.refund_to == first))
    {
        return Err(FinalClaimBindingError::InvalidTopology);
    }
    Ok(())
}

fn validate_selection_for_terms(
    route_id: Digest32,
    composition_binding_digest: Digest32,
    terms: &SettlementTermsV1,
    selection: &FinalClaimRoleSelectionV1,
) -> Result<(), FinalClaimBindingError> {
    validate_terms_topology(terms)?;
    if selection.dom_claim_sender_id != terms.dom_leg.beneficiary
        || selection.final_claim_receiver_id != terms.dom_leg.refund_to
    {
        return Err(FinalClaimBindingError::InvalidRoleRelation);
    }
    if !terms.roster.contains(&selection.adaptor_secret_origin_id) {
        return Err(FinalClaimBindingError::InvalidRoleRelation);
    }
    let scope = selection.source_scope();
    if scope.route_id() != route_id
        || scope.composition_binding_digest() != composition_binding_digest
        || scope.source_settlement_id() != terms.settlement_id
        || scope.source_session_id() != terms.session_id
        || scope.adaptor_point_sec1() != terms.adaptor_point_sec1
        || scope.adaptor_secret_origin_id() != selection.adaptor_secret_origin_id
        || scope.dom_claim_sender_id() != selection.dom_claim_sender_id
        || scope.reveal_mode() != selection.reveal_mode
        || scope.secret_source() != selection.secret_source
    {
        return Err(FinalClaimBindingError::SourceScopeMismatch);
    }
    let expected_source_chain = match selection.secret_source {
        FinalClaimSecretSourceV1::LocalOrigin => terms.dom_leg.chain_id,
        FinalClaimSecretSourceV1::VerifiedCounterpartyClaim => terms.counterparty_leg.chain_id,
    };
    if scope.source_chain_id() != expected_source_chain {
        return Err(FinalClaimBindingError::SourceScopeMismatch);
    }
    Ok(())
}

fn validate_plan_entry_for_binding(
    role_plan: &ComposedFinalClaimRolePlanV1,
    source_scope: &FinalClaimSecretSourceScopeV1,
    route_leg: ComposedSettlementLegV1,
    terms: &SettlementTermsV1,
) -> Result<(), FinalClaimBindingError> {
    let entry = *role_plan.entry(route_leg);
    let selection = selection_from_entry(entry, source_scope.clone())?;
    validate_selection_for_terms(
        role_plan.route_id(),
        role_plan.composition_binding_digest(),
        terms,
        &selection,
    )?;
    let rebound = FinalClaimRolePlanEntryV1::from_selection(route_leg, terms, &selection);
    if rebound != entry {
        return Err(FinalClaimBindingError::RolePlanMismatch);
    }
    Ok(())
}

fn selection_from_entry(
    entry: FinalClaimRolePlanEntryV1,
    source_scope: FinalClaimSecretSourceScopeV1,
) -> Result<FinalClaimRoleSelectionV1, FinalClaimBindingError> {
    FinalClaimRoleSelectionV1::new(
        entry.adaptor_secret_origin_id,
        entry.dom_claim_sender_id,
        entry.final_claim_receiver_id,
        entry.reveal_mode,
        entry.secret_source,
        source_scope,
    )
}

fn encode_plan_entry(out: &mut [u8], entry: FinalClaimRolePlanEntryV1) {
    debug_assert_eq!(out.len(), ROLE_PLAN_ENTRY_LEN);
    out[0] = entry.route_leg.to_byte();
    out[1] = entry.reveal_mode.to_byte();
    out[2] = entry.secret_source.to_byte();
    out[4..36].copy_from_slice(&entry.settlement_id.0);
    out[36..68].copy_from_slice(&entry.session_id.0);
    out[68..100].copy_from_slice(&entry.adaptor_secret_origin_id.0);
    out[100..132].copy_from_slice(&entry.dom_claim_sender_id.0);
    out[132..164].copy_from_slice(&entry.final_claim_receiver_id.0);
    out[164..196].copy_from_slice(&entry.secret_source_scope_digest);
}

fn decode_plan_entry(
    bytes: &[u8],
    expected_leg: ComposedSettlementLegV1,
) -> Result<FinalClaimRolePlanEntryV1, FinalClaimBindingError> {
    if bytes.len() != ROLE_PLAN_ENTRY_LEN {
        return Err(FinalClaimBindingError::InvalidLength);
    }
    let route_leg = ComposedSettlementLegV1::try_from(bytes[0])?;
    if route_leg != expected_leg {
        return Err(FinalClaimBindingError::RolePlanMismatch);
    }
    if bytes[3] != 0 {
        return Err(FinalClaimBindingError::NonZeroReserved);
    }
    let entry = FinalClaimRolePlanEntryV1 {
        route_leg,
        reveal_mode: FinalClaimRevealModeV1::try_from(bytes[1])?,
        secret_source: FinalClaimSecretSourceV1::try_from(bytes[2])?,
        settlement_id: SettlementId(read_array(bytes, 4)?),
        session_id: SessionId(read_array(bytes, 36)?),
        adaptor_secret_origin_id: ParticipantId(read_array(bytes, 68)?),
        dom_claim_sender_id: ParticipantId(read_array(bytes, 100)?),
        final_claim_receiver_id: ParticipantId(read_array(bytes, 132)?),
        secret_source_scope_digest: read_array(bytes, 164)?,
    };
    require_nonzero(&entry.settlement_id.0, "settlement_id")?;
    require_nonzero(&entry.session_id.0, "session_id")?;
    require_nonzero(
        &entry.adaptor_secret_origin_id.0,
        "adaptor_secret_origin_id",
    )?;
    require_nonzero(&entry.dom_claim_sender_id.0, "dom_claim_sender_id")?;
    require_nonzero(&entry.final_claim_receiver_id.0, "final_claim_receiver_id")?;
    require_nonzero(
        &entry.secret_source_scope_digest,
        "secret_source_scope_digest",
    )?;
    validate_bilateral_role_relation(
        entry.reveal_mode,
        entry.secret_source,
        entry.adaptor_secret_origin_id,
        entry.dom_claim_sender_id,
        entry.final_claim_receiver_id,
    )?;
    Ok(entry)
}

fn validate_roster_against_terms(
    roster: &ParticipantRosterV1,
    terms: &SettlementTermsV1,
) -> Result<(), FinalClaimBindingError> {
    let entries = roster.entries();
    if entries.len() != usize::from(PARTICIPANT_COUNT)
        || entries[0].participant_id() != &terms.roster[0].0
        || entries[1].participant_id() != &terms.roster[1].0
    {
        return Err(FinalClaimBindingError::InvalidRoster);
    }
    validate_direction_cardinality(roster)
}

fn validate_direction_cardinality(
    roster: &ParticipantRosterV1,
) -> Result<(), FinalClaimBindingError> {
    let initiators = roster
        .entries()
        .iter()
        .filter(|entry| entry.direction() == DirectionV1::Initiator)
        .count();
    let responders = roster
        .entries()
        .iter()
        .filter(|entry| entry.direction() == DirectionV1::Responder)
        .count();
    if initiators != 1 || responders != 1 {
        return Err(FinalClaimBindingError::InvalidRoster);
    }
    Ok(())
}

fn participant_direction(
    roster: &ParticipantRosterV1,
    participant_id: ParticipantId,
) -> Result<DirectionV1, FinalClaimBindingError> {
    roster
        .entries()
        .iter()
        .find(|entry| entry.participant_id() == &participant_id.0)
        .map(ParticipantIdentityV1::direction)
        .ok_or(FinalClaimBindingError::InvalidRoster)
}

fn encode_roster(out: &mut Vec<u8>, roster: &ParticipantRosterV1) {
    for entry in roster.entries() {
        out.extend_from_slice(entry.participant_id());
        out.extend_from_slice(&entry.identity_public_key().to_compressed_bytes());
        out.extend_from_slice(&entry.signing_public_key().to_compressed_bytes());
        out.push(entry.direction().to_byte());
    }
}

fn roster_digest(roster: &ParticipantRosterV1) -> Digest32 {
    let mut bytes = Vec::with_capacity(2 + usize::from(PARTICIPANT_COUNT) * ROSTER_ENTRY_LEN);
    bytes.extend_from_slice(&PARTICIPANT_COUNT.to_le_bytes());
    encode_roster(&mut bytes, roster);
    tagged_digest(FINAL_CLAIM_ROLE_ROSTER_DOMAIN, &bytes)
}

fn validate_retained_roster_against_terms(
    entries: &[RetainedParticipantEntryAuditV1; 2],
    terms: &SettlementTermsV1,
) -> Result<(), FinalClaimBindingError> {
    if entries[0].participant_id != terms.roster[0].0
        || entries[1].participant_id != terms.roster[1].0
        || entries[0].participant_id >= entries[1].participant_id
        || entries[0].identity_public_key_sec1 == entries[1].identity_public_key_sec1
        || entries[0].signing_public_key_sec1 == entries[1].signing_public_key_sec1
    {
        return Err(FinalClaimBindingError::InvalidRoster);
    }
    validate_retained_direction_cardinality(entries)
}

fn validate_retained_direction_cardinality(
    entries: &[RetainedParticipantEntryAuditV1; 2],
) -> Result<(), FinalClaimBindingError> {
    let initiators = entries
        .iter()
        .filter(|entry| entry.direction == DirectionV1::Initiator)
        .count();
    let responders = entries
        .iter()
        .filter(|entry| entry.direction == DirectionV1::Responder)
        .count();
    if initiators != 1 || responders != 1 {
        return Err(FinalClaimBindingError::InvalidRoster);
    }
    Ok(())
}

fn retained_participant_direction(
    entries: &[RetainedParticipantEntryAuditV1; 2],
    participant_id: ParticipantId,
) -> Result<DirectionV1, FinalClaimBindingError> {
    entries
        .iter()
        .find(|entry| entry.participant_id == participant_id.0)
        .map(|entry| entry.direction)
        .ok_or(FinalClaimBindingError::InvalidRoster)
}

fn encode_retained_roster(out: &mut Vec<u8>, entries: &[RetainedParticipantEntryAuditV1; 2]) {
    for entry in entries {
        out.extend_from_slice(&entry.participant_id);
        out.extend_from_slice(&entry.identity_public_key_sec1);
        out.extend_from_slice(&entry.signing_public_key_sec1);
        out.push(entry.direction.to_byte());
    }
}

fn retained_roster_digest(entries: &[RetainedParticipantEntryAuditV1; 2]) -> Digest32 {
    let mut bytes = Vec::with_capacity(2 + usize::from(PARTICIPANT_COUNT) * ROSTER_ENTRY_LEN);
    bytes.extend_from_slice(&PARTICIPANT_COUNT.to_le_bytes());
    encode_retained_roster(&mut bytes, entries);
    tagged_digest(FINAL_CLAIM_ROLE_ROSTER_DOMAIN, &bytes)
}

fn decode_operational_roster_entry(
    trusted_chain_id: &TrustedChainIdV1,
    bytes: &[u8],
) -> Result<ParticipantIdentityV1, FinalClaimBindingError> {
    if bytes.len() != ROSTER_ENTRY_LEN {
        return Err(FinalClaimBindingError::InvalidLength);
    }
    let encoded_id: Digest32 = read_array(bytes, 0)?;
    let identity_public_key = PublicKey::from_compressed_bytes(
        bytes
            .get(32..65)
            .ok_or(FinalClaimBindingError::InvalidLength)?,
    )
    .map_err(|_| FinalClaimBindingError::InvalidPoint("identity_public_key"))?;
    let signing_public_key = PublicKey::from_compressed_bytes(
        bytes
            .get(65..98)
            .ok_or(FinalClaimBindingError::InvalidLength)?,
    )
    .map_err(|_| FinalClaimBindingError::InvalidPoint("signing_public_key"))?;
    let direction =
        DirectionV1::try_from(bytes[98]).map_err(|_| FinalClaimBindingError::UnknownTag)?;
    let participant = ParticipantIdentityV1::new(
        trusted_chain_id,
        identity_public_key,
        signing_public_key,
        direction,
    )
    .map_err(|_| FinalClaimBindingError::InvalidRoster)?;
    if participant.participant_id() != &encoded_id {
        return Err(FinalClaimBindingError::InvalidRoster);
    }
    Ok(participant)
}

fn decode_retained_roster_entry(
    expected_chain_id: &[u8; 32],
    bytes: &[u8],
) -> Result<RetainedParticipantEntryAuditV1, FinalClaimBindingError> {
    if bytes.len() != ROSTER_ENTRY_LEN {
        return Err(FinalClaimBindingError::InvalidLength);
    }
    let participant_id: Digest32 = read_array(bytes, 0)?;
    let identity_public_key = PublicKey::from_compressed_bytes(
        bytes
            .get(32..65)
            .ok_or(FinalClaimBindingError::InvalidLength)?,
    )
    .map_err(|_| FinalClaimBindingError::InvalidPoint("identity_public_key"))?;
    let signing_public_key = PublicKey::from_compressed_bytes(
        bytes
            .get(65..98)
            .ok_or(FinalClaimBindingError::InvalidLength)?,
    )
    .map_err(|_| FinalClaimBindingError::InvalidPoint("signing_public_key"))?;
    let direction =
        DirectionV1::try_from(bytes[98]).map_err(|_| FinalClaimBindingError::UnknownTag)?;
    audit_retained_participant_id_v1(expected_chain_id, &participant_id, &identity_public_key)
        .map_err(|_| FinalClaimBindingError::InvalidRoster)?;
    Ok(RetainedParticipantEntryAuditV1 {
        participant_id,
        identity_public_key_sec1: identity_public_key.to_compressed_bytes(),
        signing_public_key_sec1: signing_public_key.to_compressed_bytes(),
        direction,
    })
}

fn read_array<const N: usize>(
    bytes: &[u8],
    offset: usize,
) -> Result<[u8; N], FinalClaimBindingError> {
    let end = offset
        .checked_add(N)
        .ok_or(FinalClaimBindingError::InvalidLength)?;
    bytes
        .get(offset..end)
        .ok_or(FinalClaimBindingError::InvalidLength)?
        .try_into()
        .map_err(|_| FinalClaimBindingError::InvalidLength)
}

fn read_u16_le(bytes: &[u8], offset: usize) -> Result<u16, FinalClaimBindingError> {
    Ok(u16::from_le_bytes(read_array(bytes, offset)?))
}

fn read_u32_le(bytes: &[u8], offset: usize) -> Result<u32, FinalClaimBindingError> {
    Ok(u32::from_le_bytes(read_array(bytes, offset)?))
}

fn read_u64_le(bytes: &[u8], offset: usize) -> Result<u64, FinalClaimBindingError> {
    Ok(u64::from_le_bytes(read_array(bytes, offset)?))
}
