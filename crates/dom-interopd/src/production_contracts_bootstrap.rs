//! Authenticated bilateral bootstrap material for the DOM Contracts sessions.
//!
//! Relay rosters authenticate Relay envelope keys. They deliberately do not
//! mint the independent Noise and DOM Schnorr identities used by DSC1. This
//! module closes that boundary with one exact, bounded, dual-signed artifact
//! covering both settlements. The decoded representation never escapes: only
//! a move-only value returned after every scope, commitment and signature has
//! been verified is observable by the production composition root.

use std::collections::BTreeMap;

use blake2::{
    digest::{Update, VariableOutput},
    Blake2bVar,
};
use btc_crypto::SecpContext;
use deployment_registry::ResolvedRegistryV1;
use dom_adaptor::{
    audit_retained_participant_id_v1, combine_decoy_capsule_v1, ContractKindV1, DecoyCommitmentV1,
    DecoyRevealV1, DirectionV1, DECOY_VARIABLE_LEN,
};
use dom_crypto::PublicKey;
use kaystra_core::{terms::SettlementTermsV1, types::ParticipantId};
use relay::SenderRoleV1;
use route_composer::ComposedBindingV2;

use crate::production_inputs::{ProductionRelayRosterBundleV1, ProductionRoutePositionV1};

const COMMIT_MAGIC_V1: &[u8; 8] = b"DOMCTC1\0";
const REVEAL_MAGIC_V1: &[u8; 8] = b"DOMCTR1\0";
const VERSION_V1: u16 = 1;
const LEG_COUNT_V1: u8 = 2;
const PARTICIPANT_COUNT_V1: u8 = 2;
const SIGNATURE_BYTES_V1: usize = 64;
const SCHNORR_KEY_BYTES_V1: usize = 33;
const SHARE_POINT_BYTES_V1: usize = 33;
const RECOVERY_CAPSULE_BYTES_V1: usize = 96;
const SIGNATURE_COUNT_V1: usize = 4;
const COMMIT_UNSIGNED_BYTES_V1: usize = 1_194;
const REVEAL_UNSIGNED_BYTES_V1: usize = 832;
const STAGE_SIGNATURE_BYTES_V1: usize = SIGNATURE_COUNT_V1 * SIGNATURE_BYTES_V1;
const REVEAL_STAGE_OFFSET_V1: usize = COMMIT_UNSIGNED_BYTES_V1 + STAGE_SIGNATURE_BYTES_V1;
pub(crate) const CONTRACTS_BOOTSTRAP_BYTES_V1: usize =
    REVEAL_STAGE_OFFSET_V1 + REVEAL_UNSIGNED_BYTES_V1 + STAGE_SIGNATURE_BYTES_V1;

const COMMIT_DIGEST_DOMAIN_V1: &[u8] = b"DOM-INTEROPD/PRODUCTION-CONTRACTS-BOOTSTRAP-COMMIT/V1\0";
const COMMIT_SIGNER_DIGEST_DOMAIN_V1: &[u8] =
    b"DOM-INTEROPD/PRODUCTION-CONTRACTS-BOOTSTRAP-COMMIT-SIGNER/V1\0";
const REVEAL_DIGEST_DOMAIN_V1: &[u8] = b"DOM-INTEROPD/PRODUCTION-CONTRACTS-BOOTSTRAP-REVEAL/V1\0";
const REVEAL_SIGNER_DIGEST_DOMAIN_V1: &[u8] =
    b"DOM-INTEROPD/PRODUCTION-CONTRACTS-BOOTSTRAP-REVEAL-SIGNER/V1\0";

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub(crate) enum ProductionContractsBootstrapErrorV1 {
    #[error("non-canonical Contracts bootstrap artifact")]
    NonCanonical,
    #[error("Contracts bootstrap scope does not match authenticated route facts")]
    ScopeMismatch,
    #[error("Contracts bootstrap contains invalid public cryptographic material")]
    InvalidCryptographicBinding,
    #[error("Contracts bootstrap violates identity separation")]
    IdentityCollision,
    #[error("Contracts bootstrap Relay authorization failed")]
    SignatureInvalid,
}

/// One authenticated Contracts participant in one settlement.
///
/// This type has no public constructor. Its fields are public data, but the
/// type itself is reachable only through [`AuthenticatedContractsBootstrapV1`].
pub(crate) struct AuthenticatedContractsParticipantV1 {
    participant_id: ParticipantId,
    direction: DirectionV1,
    key_reference: [u8; 32],
    noise_public_key: [u8; 32],
    schnorr_public_key: [u8; SCHNORR_KEY_BYTES_V1],
    share_point: [u8; SHARE_POINT_BYTES_V1],
    contribution_commitment: [u8; 32],
    contribution_reveal: [u8; DECOY_VARIABLE_LEN],
}

impl AuthenticatedContractsParticipantV1 {
    pub(crate) const fn participant_id(&self) -> ParticipantId {
        self.participant_id
    }

    pub(crate) const fn direction(&self) -> DirectionV1 {
        self.direction
    }

    pub(crate) const fn key_reference(&self) -> &[u8; 32] {
        &self.key_reference
    }

    pub(crate) const fn noise_public_key(&self) -> &[u8; 32] {
        &self.noise_public_key
    }

    pub(crate) const fn schnorr_public_key(&self) -> &[u8; SCHNORR_KEY_BYTES_V1] {
        &self.schnorr_public_key
    }

    pub(crate) const fn share_point(&self) -> &[u8; SHARE_POINT_BYTES_V1] {
        &self.share_point
    }

    pub(crate) const fn contribution_commitment(&self) -> &[u8; 32] {
        &self.contribution_commitment
    }

    pub(crate) const fn contribution_reveal(&self) -> &[u8; DECOY_VARIABLE_LEN] {
        &self.contribution_reveal
    }
}

/// One authenticated Contracts settlement bootstrap.
pub(crate) struct AuthenticatedContractsLegV1 {
    position: ProductionRoutePositionV1,
    session_id: [u8; 32],
    terms_hash: [u8; 32],
    #[expect(
        dead_code,
        reason = "retained surface not yet wired by the stage-7 composition root"
    )]
    roster_snapshot: [u8; 32],
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "retained surface not yet wired by the stage-7 composition root"
        )
    )]
    policy_version: u32,
    participants: [AuthenticatedContractsParticipantV1; 2],
    recovery_capsule: [u8; RECOVERY_CAPSULE_BYTES_V1],
}

impl AuthenticatedContractsLegV1 {
    pub(crate) const fn position(&self) -> ProductionRoutePositionV1 {
        self.position
    }

    pub(crate) const fn session_id(&self) -> &[u8; 32] {
        &self.session_id
    }

    pub(crate) const fn terms_hash(&self) -> &[u8; 32] {
        &self.terms_hash
    }

    #[expect(
        dead_code,
        reason = "retained surface not yet wired by the stage-7 composition root"
    )]
    pub(crate) const fn roster_snapshot(&self) -> &[u8; 32] {
        &self.roster_snapshot
    }

    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "retained surface not yet wired by the stage-7 composition root"
        )
    )]
    pub(crate) const fn policy_version(&self) -> u32 {
        self.policy_version
    }

    pub(crate) const fn participants(&self) -> &[AuthenticatedContractsParticipantV1; 2] {
        &self.participants
    }

    pub(crate) const fn recovery_capsule(&self) -> &[u8; RECOVERY_CAPSULE_BYTES_V1] {
        &self.recovery_capsule
    }
}

/// Move-only result of complete artifact authentication.
///
/// Absence of `Clone`, `Copy`, serialization and public construction keeps the
/// verified provenance attached to this exact instance until the Contracts
/// stores consume it.
pub(crate) struct AuthenticatedContractsBootstrapV1 {
    #[expect(
        dead_code,
        reason = "retained surface not yet wired by the stage-7 composition root"
    )]
    network_id: [u8; 32],
    route_id: [u8; 32],
    registry_digest: [u8; 32],
    registry_epoch: u64,
    dom_chain_id: [u8; 32],
    dom_genesis_hash: [u8; 32],
    contract_kind: ContractKindV1,
    legs: [AuthenticatedContractsLegV1; 2],
    commit_stage_digest: [u8; 32],
    reveal_stage_digest: [u8; 32],
}

impl AuthenticatedContractsBootstrapV1 {
    #[expect(
        dead_code,
        reason = "retained surface not yet wired by the stage-7 composition root"
    )]
    pub(crate) const fn network_id(&self) -> &[u8; 32] {
        &self.network_id
    }

    pub(crate) const fn route_id(&self) -> &[u8; 32] {
        &self.route_id
    }

    pub(crate) const fn registry_digest(&self) -> &[u8; 32] {
        &self.registry_digest
    }

    pub(crate) const fn registry_epoch(&self) -> u64 {
        self.registry_epoch
    }

    pub(crate) const fn dom_chain_id(&self) -> &[u8; 32] {
        &self.dom_chain_id
    }

    pub(crate) const fn dom_genesis_hash(&self) -> &[u8; 32] {
        &self.dom_genesis_hash
    }

    pub(crate) const fn contract_kind(&self) -> ContractKindV1 {
        self.contract_kind
    }

    pub(crate) const fn legs(&self) -> &[AuthenticatedContractsLegV1; 2] {
        &self.legs
    }

    pub(crate) const fn commit_stage_digest(&self) -> &[u8; 32] {
        &self.commit_stage_digest
    }

    pub(crate) const fn reveal_stage_digest(&self) -> &[u8; 32] {
        &self.reveal_stage_digest
    }
}

struct DecodedParticipantV1 {
    participant_id: ParticipantId,
    direction: DirectionV1,
    key_reference: [u8; 32],
    noise_public_key: [u8; 32],
    schnorr_public_key: [u8; SCHNORR_KEY_BYTES_V1],
    share_point: [u8; SHARE_POINT_BYTES_V1],
    contribution_commitment: [u8; 32],
    contribution_reveal: [u8; DECOY_VARIABLE_LEN],
}

type ParticipantPublicMaterialV1 = ([u8; 32], [u8; 32], [u8; 33]);

struct DecodedLegV1 {
    position: ProductionRoutePositionV1,
    session_id: [u8; 32],
    terms_hash: [u8; 32],
    roster_snapshot: [u8; 32],
    policy_version: u32,
    participants: [DecodedParticipantV1; 2],
    recovery_capsule: [u8; RECOVERY_CAPSULE_BYTES_V1],
}

struct DecodedBundleV1 {
    network_id: [u8; 32],
    route_id: [u8; 32],
    registry_digest: [u8; 32],
    registry_epoch: u64,
    dom_chain_id: [u8; 32],
    dom_genesis_hash: [u8; 32],
    contract_kind: ContractKindV1,
    legs: [DecodedLegV1; 2],
    claimed_commit_digest: [u8; 32],
    commit_signatures: [[u8; SIGNATURE_BYTES_V1]; SIGNATURE_COUNT_V1],
    reveal_signatures: [[u8; SIGNATURE_BYTES_V1]; SIGNATURE_COUNT_V1],
}

struct ExpectedLegV1 {
    session_id: [u8; 32],
    terms_hash: [u8; 32],
    roster: [ParticipantId; 2],
    roster_snapshot: [u8; 32],
    policy_version: u32,
}

struct ExpectedContextV1 {
    network_id: [u8; 32],
    route_id: [u8; 32],
    registry_digest: [u8; 32],
    registry_epoch: u64,
    dom_chain_id: [u8; 32],
    dom_genesis_hash: [u8; 32],
    legs: [ExpectedLegV1; 2],
}

/// Authenticate a pre-provisioned bilateral Contracts bootstrap artifact.
///
/// Every expected value is rederived from already-authenticated production
/// authorities. In particular, raw caller-provided hashes cannot reach the
/// verifier as an alternate success path.
pub(crate) fn authenticate_contracts_bootstrap_v1(
    bytes: &[u8],
    composition: &ComposedBindingV2,
    registry: &ResolvedRegistryV1,
    relay_rosters: &ProductionRelayRosterBundleV1,
    secp: &SecpContext,
) -> Result<AuthenticatedContractsBootstrapV1, ProductionContractsBootstrapErrorV1> {
    let expected = ExpectedContextV1::from_authenticated(composition, registry, relay_rosters)?;
    authenticate_against_expected_v1(bytes, &expected, relay_rosters, secp)
}

impl ExpectedContextV1 {
    fn from_authenticated(
        composition: &ComposedBindingV2,
        registry: &ResolvedRegistryV1,
        relay_rosters: &ProductionRelayRosterBundleV1,
    ) -> Result<Self, ProductionContractsBootstrapErrorV1> {
        let dom = registry
            .resolve_dom()
            .map_err(|_| ProductionContractsBootstrapErrorV1::ScopeMismatch)?;
        let deployment = dom.deployment();
        let terms = [composition.upstream(), composition.downstream()];
        let roster_legs = relay_rosters.legs();
        let mut legs = Vec::with_capacity(2);
        for index in 0..2 {
            legs.push(ExpectedLegV1::from_authenticated(
                terms[index],
                &roster_legs[index],
            )?);
        }
        let value = Self {
            network_id: relay_rosters.network_id(),
            route_id: relay_rosters.route_id(),
            registry_digest: registry.manifest_digest(),
            registry_epoch: registry.epoch(),
            dom_chain_id: deployment.chain_id.0,
            dom_genesis_hash: deployment.genesis_hash,
            legs: legs
                .try_into()
                .map_err(|_| ProductionContractsBootstrapErrorV1::ScopeMismatch)?,
        };
        if value.network_id == [0; 32]
            || value.network_id != registry.manifest().network_id
            || value.route_id == [0; 32]
            || value.registry_digest == [0; 32]
            || value.registry_epoch == 0
            || value.dom_chain_id == [0; 32]
            || value.dom_genesis_hash == [0; 32]
        {
            return Err(ProductionContractsBootstrapErrorV1::ScopeMismatch);
        }
        Ok(value)
    }
}

impl ExpectedLegV1 {
    fn from_authenticated(
        terms: &SettlementTermsV1,
        roster: &crate::production_inputs::ProductionRosterLegV1,
    ) -> Result<Self, ProductionContractsBootstrapErrorV1> {
        let terms_hash = terms
            .terms_hash()
            .map_err(|_| ProductionContractsBootstrapErrorV1::ScopeMismatch)?;
        if roster.session_id != terms.session_id.0
            || roster.policy_version != terms.policy_version
            || roster.members[0].participant_id != terms.roster[0]
            || roster.members[1].participant_id != terms.roster[1]
        {
            return Err(ProductionContractsBootstrapErrorV1::ScopeMismatch);
        }
        Ok(Self {
            session_id: terms.session_id.0,
            terms_hash,
            roster: terms.roster,
            roster_snapshot: roster.roster_snapshot,
            policy_version: terms.policy_version,
        })
    }
}

fn authenticate_against_expected_v1(
    bytes: &[u8],
    expected: &ExpectedContextV1,
    relay_rosters: &ProductionRelayRosterBundleV1,
    secp: &SecpContext,
) -> Result<AuthenticatedContractsBootstrapV1, ProductionContractsBootstrapErrorV1> {
    let decoded = decode_canonical_v1(bytes)?;
    verify_scope_v1(&decoded, expected, relay_rosters)?;
    let commit_unsigned = encode_commit_unsigned_v1(&decoded);
    if commit_unsigned.len() != COMMIT_UNSIGNED_BYTES_V1
        || bytes[..COMMIT_UNSIGNED_BYTES_V1] != commit_unsigned
    {
        return Err(ProductionContractsBootstrapErrorV1::NonCanonical);
    }
    let commit_digest = digest_v1(COMMIT_DIGEST_DOMAIN_V1, &commit_unsigned)?;
    if decoded.claimed_commit_digest != commit_digest {
        return Err(ProductionContractsBootstrapErrorV1::InvalidCryptographicBinding);
    }
    verify_stage_signatures_v1(
        &decoded,
        relay_rosters,
        secp,
        commit_digest,
        None,
        &decoded.commit_signatures,
        COMMIT_SIGNER_DIGEST_DOMAIN_V1,
    )?;

    // Reveals are not even interpreted as valid protocol material until the
    // independent commit stage above has authenticated under both Relay keys.
    verify_public_material_v1(&decoded, relay_rosters)?;
    let reveal_unsigned = encode_reveal_unsigned_v1(&decoded, commit_digest);
    let reveal_end = REVEAL_STAGE_OFFSET_V1 + REVEAL_UNSIGNED_BYTES_V1;
    if reveal_unsigned.len() != REVEAL_UNSIGNED_BYTES_V1
        || bytes[REVEAL_STAGE_OFFSET_V1..reveal_end] != reveal_unsigned
    {
        return Err(ProductionContractsBootstrapErrorV1::NonCanonical);
    }
    let reveal_digest = digest_v1(REVEAL_DIGEST_DOMAIN_V1, &reveal_unsigned)?;
    verify_stage_signatures_v1(
        &decoded,
        relay_rosters,
        secp,
        reveal_digest,
        Some(commit_digest),
        &decoded.reveal_signatures,
        REVEAL_SIGNER_DIGEST_DOMAIN_V1,
    )?;
    Ok(decoded.into_authenticated(commit_digest, reveal_digest))
}

fn decode_canonical_v1(
    bytes: &[u8],
) -> Result<DecodedBundleV1, ProductionContractsBootstrapErrorV1> {
    if bytes.len() != CONTRACTS_BOOTSTRAP_BYTES_V1 {
        return Err(ProductionContractsBootstrapErrorV1::NonCanonical);
    }
    let mut cursor = CursorV1::new(bytes);
    if cursor.take::<8>()? != *COMMIT_MAGIC_V1
        || cursor.u16()? != VERSION_V1
        || cursor.u16()? != 0
        || cursor.u8()? != LEG_COUNT_V1
        || cursor.take::<3>()? != [0; 3]
    {
        return Err(ProductionContractsBootstrapErrorV1::NonCanonical);
    }
    let network_id = cursor.take::<32>()?;
    let route_id = cursor.take::<32>()?;
    let registry_digest = cursor.take::<32>()?;
    let registry_epoch = cursor.u64()?;
    let dom_chain_id = cursor.take::<32>()?;
    let dom_genesis_hash = cursor.take::<32>()?;
    let contract_kind = ContractKindV1::try_from(cursor.u16()?)
        .map_err(|_| ProductionContractsBootstrapErrorV1::NonCanonical)?;
    let mut legs = Vec::with_capacity(2);
    for _ in 0..2 {
        let position = position_from_tag(cursor.u8()?)?;
        if cursor.take::<3>()? != [0; 3] {
            return Err(ProductionContractsBootstrapErrorV1::NonCanonical);
        }
        let session_id = cursor.take::<32>()?;
        let terms_hash = cursor.take::<32>()?;
        let roster_snapshot = cursor.take::<32>()?;
        let policy_version = cursor.u32()?;
        if cursor.u8()? != PARTICIPANT_COUNT_V1 || cursor.take::<3>()? != [0; 3] {
            return Err(ProductionContractsBootstrapErrorV1::NonCanonical);
        }
        let mut participants = Vec::with_capacity(2);
        for _ in 0..2 {
            let participant_id = ParticipantId(cursor.take::<32>()?);
            let direction = DirectionV1::try_from(cursor.u8()?)
                .map_err(|_| ProductionContractsBootstrapErrorV1::NonCanonical)?;
            if cursor.take::<3>()? != [0; 3] {
                return Err(ProductionContractsBootstrapErrorV1::NonCanonical);
            }
            participants.push(DecodedParticipantV1 {
                participant_id,
                direction,
                key_reference: cursor.take::<32>()?,
                noise_public_key: cursor.take::<32>()?,
                schnorr_public_key: cursor.take::<SCHNORR_KEY_BYTES_V1>()?,
                share_point: cursor.take::<SHARE_POINT_BYTES_V1>()?,
                contribution_commitment: cursor.take::<32>()?,
                contribution_reveal: [0; DECOY_VARIABLE_LEN],
            });
        }
        legs.push(DecodedLegV1 {
            position,
            session_id,
            terms_hash,
            roster_snapshot,
            policy_version,
            participants: participants
                .try_into()
                .map_err(|_| ProductionContractsBootstrapErrorV1::NonCanonical)?,
            recovery_capsule: [0; RECOVERY_CAPSULE_BYTES_V1],
        });
    }
    if cursor.position != COMMIT_UNSIGNED_BYTES_V1 {
        return Err(ProductionContractsBootstrapErrorV1::NonCanonical);
    }
    let mut commit_signatures = Vec::with_capacity(SIGNATURE_COUNT_V1);
    for _ in 0..SIGNATURE_COUNT_V1 {
        commit_signatures.push(cursor.take::<SIGNATURE_BYTES_V1>()?);
    }
    if cursor.position != REVEAL_STAGE_OFFSET_V1
        || cursor.take::<8>()? != *REVEAL_MAGIC_V1
        || cursor.u16()? != VERSION_V1
        || cursor.u16()? != 0
    {
        return Err(ProductionContractsBootstrapErrorV1::NonCanonical);
    }
    let claimed_commit_digest = cursor.take::<32>()?;
    if cursor.u8()? != LEG_COUNT_V1 || cursor.take::<3>()? != [0; 3] {
        return Err(ProductionContractsBootstrapErrorV1::NonCanonical);
    }
    for leg_index in 0..2 {
        let position = position_from_tag(cursor.u8()?)?;
        if cursor.take::<3>()? != [0; 3] {
            return Err(ProductionContractsBootstrapErrorV1::NonCanonical);
        }
        let session_id = cursor.take::<32>()?;
        if cursor.u8()? != PARTICIPANT_COUNT_V1 || cursor.take::<3>()? != [0; 3] {
            return Err(ProductionContractsBootstrapErrorV1::NonCanonical);
        }
        let commit_leg = legs
            .get_mut(leg_index)
            .ok_or(ProductionContractsBootstrapErrorV1::NonCanonical)?;
        if position != commit_leg.position || session_id != commit_leg.session_id {
            return Err(ProductionContractsBootstrapErrorV1::NonCanonical);
        }
        for participant_index in 0..2 {
            let participant_id = ParticipantId(cursor.take::<32>()?);
            let direction = DirectionV1::try_from(cursor.u8()?)
                .map_err(|_| ProductionContractsBootstrapErrorV1::NonCanonical)?;
            if cursor.take::<3>()? != [0; 3] {
                return Err(ProductionContractsBootstrapErrorV1::NonCanonical);
            }
            let commit_participant = commit_leg
                .participants
                .get_mut(participant_index)
                .ok_or(ProductionContractsBootstrapErrorV1::NonCanonical)?;
            if participant_id != commit_participant.participant_id
                || direction != commit_participant.direction
            {
                return Err(ProductionContractsBootstrapErrorV1::NonCanonical);
            }
            commit_participant.contribution_reveal = cursor.take::<DECOY_VARIABLE_LEN>()?;
        }
        commit_leg.recovery_capsule = cursor.take::<RECOVERY_CAPSULE_BYTES_V1>()?;
    }
    if cursor.position != REVEAL_STAGE_OFFSET_V1 + REVEAL_UNSIGNED_BYTES_V1 {
        return Err(ProductionContractsBootstrapErrorV1::NonCanonical);
    }
    let mut reveal_signatures = Vec::with_capacity(SIGNATURE_COUNT_V1);
    for _ in 0..SIGNATURE_COUNT_V1 {
        reveal_signatures.push(cursor.take::<SIGNATURE_BYTES_V1>()?);
    }
    cursor.finish()?;
    Ok(DecodedBundleV1 {
        network_id,
        route_id,
        registry_digest,
        registry_epoch,
        dom_chain_id,
        dom_genesis_hash,
        contract_kind,
        legs: legs
            .try_into()
            .map_err(|_| ProductionContractsBootstrapErrorV1::NonCanonical)?,
        claimed_commit_digest,
        commit_signatures: commit_signatures
            .try_into()
            .map_err(|_| ProductionContractsBootstrapErrorV1::NonCanonical)?,
        reveal_signatures: reveal_signatures
            .try_into()
            .map_err(|_| ProductionContractsBootstrapErrorV1::NonCanonical)?,
    })
}

fn verify_scope_v1(
    decoded: &DecodedBundleV1,
    expected: &ExpectedContextV1,
    relay_rosters: &ProductionRelayRosterBundleV1,
) -> Result<(), ProductionContractsBootstrapErrorV1> {
    if decoded.network_id != expected.network_id
        || decoded.route_id != expected.route_id
        || decoded.registry_digest != expected.registry_digest
        || decoded.registry_epoch != expected.registry_epoch
        || decoded.dom_chain_id != expected.dom_chain_id
        || decoded.dom_genesis_hash != expected.dom_genesis_hash
        || decoded.contract_kind != ContractKindV1::WitnessOrTimeout
        || decoded.legs[0].position != ProductionRoutePositionV1::Upstream
        || decoded.legs[1].position != ProductionRoutePositionV1::Downstream
    {
        return Err(ProductionContractsBootstrapErrorV1::ScopeMismatch);
    }
    for index in 0..2 {
        let leg = &decoded.legs[index];
        let expected_leg = &expected.legs[index];
        let relay_leg = &relay_rosters.legs()[index];
        if leg.session_id != expected_leg.session_id
            || leg.terms_hash != expected_leg.terms_hash
            || leg.roster_snapshot != expected_leg.roster_snapshot
            || leg.policy_version != expected_leg.policy_version
            || leg.position != relay_leg.position
        {
            return Err(ProductionContractsBootstrapErrorV1::ScopeMismatch);
        }
        for participant_index in 0..2 {
            let participant = &leg.participants[participant_index];
            let relay_member = relay_leg.members[participant_index];
            if participant.participant_id != expected_leg.roster[participant_index]
                || participant.participant_id != relay_member.participant_id
                || participant.direction != direction_for_relay_role(relay_member.role)?
            {
                return Err(ProductionContractsBootstrapErrorV1::ScopeMismatch);
            }
        }
    }
    Ok(())
}

fn verify_public_material_v1(
    decoded: &DecodedBundleV1,
    relay_rosters: &ProductionRelayRosterBundleV1,
) -> Result<(), ProductionContractsBootstrapErrorV1> {
    let relay_keys: Vec<[u8; 32]> = relay_rosters
        .legs()
        .iter()
        .flat_map(|leg| leg.members.iter().map(|member| member.xonly_key))
        .collect();
    let mut participant_identities: BTreeMap<ParticipantId, ParticipantPublicMaterialV1> =
        BTreeMap::new();
    let mut key_reference_owners = BTreeMap::new();
    let mut noise_owners = BTreeMap::new();
    let mut schnorr_owners = BTreeMap::new();
    let mut share_points = Vec::with_capacity(4);
    let mut reveals = Vec::with_capacity(4);

    for leg in &decoded.legs {
        if leg.session_id == [0; 32]
            || leg.terms_hash == [0; 32]
            || leg.roster_snapshot == [0; 32]
            || leg.policy_version == 0
            || leg.participants[0].participant_id >= leg.participants[1].participant_id
            || leg.participants[0].direction == leg.participants[1].direction
        {
            return Err(ProductionContractsBootstrapErrorV1::InvalidCryptographicBinding);
        }
        for participant in &leg.participants {
            if participant.participant_id.0 == [0; 32]
                || participant.key_reference == [0; 32]
                || participant.noise_public_key == [0; 32]
                || participant.contribution_commitment == [0; 32]
                || participant.contribution_reveal == [0; DECOY_VARIABLE_LEN]
                || relay_keys
                    .iter()
                    .any(|relay_key| relay_key == &participant.schnorr_public_key[1..])
            {
                return Err(ProductionContractsBootstrapErrorV1::InvalidCryptographicBinding);
            }
            let identity_key = PublicKey::from_compressed_bytes(&participant.schnorr_public_key)
                .map_err(|_| ProductionContractsBootstrapErrorV1::InvalidCryptographicBinding)?;
            PublicKey::from_compressed_bytes(&participant.share_point)
                .map_err(|_| ProductionContractsBootstrapErrorV1::InvalidCryptographicBinding)?;
            audit_retained_participant_id_v1(
                &decoded.dom_chain_id,
                &participant.participant_id.0,
                &identity_key,
            )
            .map_err(|_| ProductionContractsBootstrapErrorV1::InvalidCryptographicBinding)?;

            let identity = (
                participant.key_reference,
                participant.noise_public_key,
                participant.schnorr_public_key,
            );
            if participant_identities
                .insert(participant.participant_id, identity)
                .is_some_and(|retained| retained != identity)
                || owner_collision(
                    &mut key_reference_owners,
                    participant.key_reference,
                    participant.participant_id,
                )
                || owner_collision(
                    &mut noise_owners,
                    participant.noise_public_key,
                    participant.participant_id,
                )
                || owner_collision(
                    &mut schnorr_owners,
                    participant.schnorr_public_key,
                    participant.participant_id,
                )
                || share_points.contains(&participant.share_point)
                || reveals.contains(&participant.contribution_reveal)
            {
                return Err(ProductionContractsBootstrapErrorV1::IdentityCollision);
            }
            share_points.push(participant.share_point);
            reveals.push(participant.contribution_reveal);
        }
        verify_capsule_exchange_v1(leg)?;
    }
    Ok(())
}

fn owner_collision<const N: usize>(
    owners: &mut BTreeMap<[u8; N], ParticipantId>,
    value: [u8; N],
    participant: ParticipantId,
) -> bool {
    owners
        .insert(value, participant)
        .is_some_and(|retained| retained != participant)
}

fn verify_capsule_exchange_v1(
    leg: &DecodedLegV1,
) -> Result<(), ProductionContractsBootstrapErrorV1> {
    let first = DecoyRevealV1::from_bytes(leg.participants[0].contribution_reveal);
    let second = DecoyRevealV1::from_bytes(leg.participants[1].contribution_reveal);
    let second_commit = DecoyCommitmentV1::from_bytes(leg.participants[1].contribution_commitment);
    let capsule = combine_decoy_capsule_v1(&first, &second, &second_commit)
        .map_err(|_| ProductionContractsBootstrapErrorV1::InvalidCryptographicBinding)?;
    if capsule.as_bytes() != &leg.recovery_capsule {
        return Err(ProductionContractsBootstrapErrorV1::InvalidCryptographicBinding);
    }
    let first = DecoyRevealV1::from_bytes(leg.participants[0].contribution_reveal);
    let second = DecoyRevealV1::from_bytes(leg.participants[1].contribution_reveal);
    let first_commit = DecoyCommitmentV1::from_bytes(leg.participants[0].contribution_commitment);
    let reverse = combine_decoy_capsule_v1(&second, &first, &first_commit)
        .map_err(|_| ProductionContractsBootstrapErrorV1::InvalidCryptographicBinding)?;
    if reverse.as_bytes() != &leg.recovery_capsule {
        return Err(ProductionContractsBootstrapErrorV1::InvalidCryptographicBinding);
    }
    Ok(())
}

fn verify_stage_signatures_v1(
    decoded: &DecodedBundleV1,
    relay_rosters: &ProductionRelayRosterBundleV1,
    secp: &SecpContext,
    stage_digest: [u8; 32],
    preceding_commit_digest: Option<[u8; 32]>,
    signatures: &[[u8; SIGNATURE_BYTES_V1]; SIGNATURE_COUNT_V1],
    signer_domain: &[u8],
) -> Result<(), ProductionContractsBootstrapErrorV1> {
    let mut signature_index = 0;
    for leg_index in 0..2 {
        let leg = &decoded.legs[leg_index];
        let relay_leg = &relay_rosters.legs()[leg_index];
        for participant_index in 0..2 {
            let participant = &leg.participants[participant_index];
            let relay_member = relay_leg.members[participant_index];
            let signer_digest = stage_signer_digest_v1(
                signer_domain,
                stage_digest,
                preceding_commit_digest,
                leg,
                participant,
                relay_member.role,
                relay_member.xonly_key,
            )?;
            if secp
                .verify_bip340(
                    &relay_member.xonly_key,
                    &signer_digest,
                    &signatures[signature_index],
                )
                .is_err()
            {
                return Err(ProductionContractsBootstrapErrorV1::SignatureInvalid);
            }
            signature_index += 1;
        }
    }
    Ok(())
}

fn stage_signer_digest_v1(
    domain: &[u8],
    stage_digest: [u8; 32],
    preceding_commit_digest: Option<[u8; 32]>,
    leg: &DecodedLegV1,
    participant: &DecodedParticipantV1,
    relay_role: SenderRoleV1,
    relay_key: [u8; 32],
) -> Result<[u8; 32], ProductionContractsBootstrapErrorV1> {
    let mut body = Vec::with_capacity(32 * 6 + 4);
    body.extend_from_slice(&stage_digest);
    match preceding_commit_digest {
        Some(commit_digest) => {
            body.push(1);
            body.extend_from_slice(&commit_digest);
        }
        None => body.push(0),
    }
    body.push(position_tag(leg.position));
    body.extend_from_slice(&leg.session_id);
    body.extend_from_slice(&leg.roster_snapshot);
    body.extend_from_slice(&participant.participant_id.0);
    body.push(participant.direction.to_byte());
    body.push(relay_role_tag(relay_role)?);
    body.extend_from_slice(&relay_key);
    digest_v1(domain, &body)
}

fn encode_commit_unsigned_v1(decoded: &DecodedBundleV1) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(COMMIT_UNSIGNED_BYTES_V1);
    bytes.extend_from_slice(COMMIT_MAGIC_V1);
    bytes.extend_from_slice(&VERSION_V1.to_be_bytes());
    bytes.extend_from_slice(&0u16.to_be_bytes());
    bytes.push(LEG_COUNT_V1);
    bytes.extend_from_slice(&[0; 3]);
    bytes.extend_from_slice(&decoded.network_id);
    bytes.extend_from_slice(&decoded.route_id);
    bytes.extend_from_slice(&decoded.registry_digest);
    bytes.extend_from_slice(&decoded.registry_epoch.to_be_bytes());
    bytes.extend_from_slice(&decoded.dom_chain_id);
    bytes.extend_from_slice(&decoded.dom_genesis_hash);
    bytes.extend_from_slice(&(decoded.contract_kind as u16).to_be_bytes());
    for leg in &decoded.legs {
        bytes.push(position_tag(leg.position));
        bytes.extend_from_slice(&[0; 3]);
        bytes.extend_from_slice(&leg.session_id);
        bytes.extend_from_slice(&leg.terms_hash);
        bytes.extend_from_slice(&leg.roster_snapshot);
        bytes.extend_from_slice(&leg.policy_version.to_be_bytes());
        bytes.push(PARTICIPANT_COUNT_V1);
        bytes.extend_from_slice(&[0; 3]);
        for participant in &leg.participants {
            bytes.extend_from_slice(&participant.participant_id.0);
            bytes.push(participant.direction.to_byte());
            bytes.extend_from_slice(&[0; 3]);
            bytes.extend_from_slice(&participant.key_reference);
            bytes.extend_from_slice(&participant.noise_public_key);
            bytes.extend_from_slice(&participant.schnorr_public_key);
            bytes.extend_from_slice(&participant.share_point);
            bytes.extend_from_slice(&participant.contribution_commitment);
        }
    }
    bytes
}

fn encode_reveal_unsigned_v1(decoded: &DecodedBundleV1, commit_digest: [u8; 32]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(REVEAL_UNSIGNED_BYTES_V1);
    bytes.extend_from_slice(REVEAL_MAGIC_V1);
    bytes.extend_from_slice(&VERSION_V1.to_be_bytes());
    bytes.extend_from_slice(&0u16.to_be_bytes());
    bytes.extend_from_slice(&commit_digest);
    bytes.push(LEG_COUNT_V1);
    bytes.extend_from_slice(&[0; 3]);
    for leg in &decoded.legs {
        bytes.push(position_tag(leg.position));
        bytes.extend_from_slice(&[0; 3]);
        bytes.extend_from_slice(&leg.session_id);
        bytes.push(PARTICIPANT_COUNT_V1);
        bytes.extend_from_slice(&[0; 3]);
        for participant in &leg.participants {
            bytes.extend_from_slice(&participant.participant_id.0);
            bytes.push(participant.direction.to_byte());
            bytes.extend_from_slice(&[0; 3]);
            bytes.extend_from_slice(&participant.contribution_reveal);
        }
        bytes.extend_from_slice(&leg.recovery_capsule);
    }
    bytes
}

impl DecodedBundleV1 {
    fn into_authenticated(
        self,
        commit_stage_digest: [u8; 32],
        reveal_stage_digest: [u8; 32],
    ) -> AuthenticatedContractsBootstrapV1 {
        AuthenticatedContractsBootstrapV1 {
            network_id: self.network_id,
            route_id: self.route_id,
            registry_digest: self.registry_digest,
            registry_epoch: self.registry_epoch,
            dom_chain_id: self.dom_chain_id,
            dom_genesis_hash: self.dom_genesis_hash,
            contract_kind: self.contract_kind,
            legs: self.legs.map(DecodedLegV1::into_authenticated),
            commit_stage_digest,
            reveal_stage_digest,
        }
    }
}

impl DecodedLegV1 {
    fn into_authenticated(self) -> AuthenticatedContractsLegV1 {
        AuthenticatedContractsLegV1 {
            position: self.position,
            session_id: self.session_id,
            terms_hash: self.terms_hash,
            roster_snapshot: self.roster_snapshot,
            policy_version: self.policy_version,
            participants: self
                .participants
                .map(DecodedParticipantV1::into_authenticated),
            recovery_capsule: self.recovery_capsule,
        }
    }
}

impl DecodedParticipantV1 {
    fn into_authenticated(self) -> AuthenticatedContractsParticipantV1 {
        AuthenticatedContractsParticipantV1 {
            participant_id: self.participant_id,
            direction: self.direction,
            key_reference: self.key_reference,
            noise_public_key: self.noise_public_key,
            schnorr_public_key: self.schnorr_public_key,
            share_point: self.share_point,
            contribution_commitment: self.contribution_commitment,
            contribution_reveal: self.contribution_reveal,
        }
    }
}

fn digest_v1(domain: &[u8], body: &[u8]) -> Result<[u8; 32], ProductionContractsBootstrapErrorV1> {
    let mut hasher = Blake2bVar::new(32)
        .map_err(|_| ProductionContractsBootstrapErrorV1::InvalidCryptographicBinding)?;
    hasher.update(domain);
    hasher.update(body);
    let mut digest = [0; 32];
    hasher
        .finalize_variable(&mut digest)
        .map_err(|_| ProductionContractsBootstrapErrorV1::InvalidCryptographicBinding)?;
    Ok(digest)
}

const fn position_tag(position: ProductionRoutePositionV1) -> u8 {
    match position {
        ProductionRoutePositionV1::Upstream => 1,
        ProductionRoutePositionV1::Downstream => 2,
    }
}

fn position_from_tag(
    tag: u8,
) -> Result<ProductionRoutePositionV1, ProductionContractsBootstrapErrorV1> {
    match tag {
        1 => Ok(ProductionRoutePositionV1::Upstream),
        2 => Ok(ProductionRoutePositionV1::Downstream),
        _ => Err(ProductionContractsBootstrapErrorV1::NonCanonical),
    }
}

fn direction_for_relay_role(
    role: SenderRoleV1,
) -> Result<DirectionV1, ProductionContractsBootstrapErrorV1> {
    match role {
        SenderRoleV1::Initiator => Ok(DirectionV1::Initiator),
        SenderRoleV1::Solver => Ok(DirectionV1::Responder),
        SenderRoleV1::Observer => Err(ProductionContractsBootstrapErrorV1::ScopeMismatch),
    }
}

fn relay_role_tag(role: SenderRoleV1) -> Result<u8, ProductionContractsBootstrapErrorV1> {
    match role {
        SenderRoleV1::Initiator => Ok(1),
        SenderRoleV1::Solver => Ok(2),
        SenderRoleV1::Observer => Err(ProductionContractsBootstrapErrorV1::ScopeMismatch),
    }
}

struct CursorV1<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> CursorV1<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    fn take<const N: usize>(&mut self) -> Result<[u8; N], ProductionContractsBootstrapErrorV1> {
        let end = self
            .position
            .checked_add(N)
            .ok_or(ProductionContractsBootstrapErrorV1::NonCanonical)?;
        let slice = self
            .bytes
            .get(self.position..end)
            .ok_or(ProductionContractsBootstrapErrorV1::NonCanonical)?;
        self.position = end;
        slice
            .try_into()
            .map_err(|_| ProductionContractsBootstrapErrorV1::NonCanonical)
    }

    fn u8(&mut self) -> Result<u8, ProductionContractsBootstrapErrorV1> {
        Ok(self.take::<1>()?[0])
    }

    fn u16(&mut self) -> Result<u16, ProductionContractsBootstrapErrorV1> {
        Ok(u16::from_be_bytes(self.take()?))
    }

    fn u32(&mut self) -> Result<u32, ProductionContractsBootstrapErrorV1> {
        Ok(u32::from_be_bytes(self.take()?))
    }

    fn u64(&mut self) -> Result<u64, ProductionContractsBootstrapErrorV1> {
        Ok(u64::from_be_bytes(self.take()?))
    }

    fn finish(self) -> Result<(), ProductionContractsBootstrapErrorV1> {
        if self.position == self.bytes.len() {
            Ok(())
        } else {
            Err(ProductionContractsBootstrapErrorV1::NonCanonical)
        }
    }
}

#[cfg(test)]
mod tests {
    use dom_adaptor::{DecoyContributionV1, SessionId, SigningShareV1};
    use dom_crypto::SecretKey;
    use static_assertions::assert_not_impl_any;

    use super::*;
    use crate::production_inputs::{ProductionRosterLegV1, ProductionRosterMemberV1};

    const RELAY_SECRETS: [[u8; 32]; 3] = [[0x11; 32], [0x12; 32], [0x13; 32]];
    const DOM_CHAIN_ID: [u8; 32] = [0x44; 32];

    struct FixtureV1 {
        expected: ExpectedContextV1,
        roster: ProductionRelayRosterBundleV1,
        secp: SecpContext,
        bytes: Vec<u8>,
    }

    fn fixture() -> FixtureV1 {
        let secp = SecpContext::new(&[0xA1; 32]);
        let relay_keys = RELAY_SECRETS.map(|secret| {
            secp.sign_bip340(&secret, &[0x21; 32], &[0x22; 32])
                .expect("fixture relay key")
                .1
        });
        let participant_ids = [0u8, 1, 2]
            .map(|index| canonical_participant_id(DOM_CHAIN_ID, public_key(0x31 + index)));
        let mut upstream_members = [
            ProductionRosterMemberV1 {
                participant_id: participant_ids[0],
                xonly_key: relay_keys[0],
                role: SenderRoleV1::Initiator,
            },
            ProductionRosterMemberV1 {
                participant_id: participant_ids[1],
                xonly_key: relay_keys[1],
                role: SenderRoleV1::Solver,
            },
        ];
        upstream_members.sort_by_key(|member| member.participant_id);
        let mut downstream_members = [
            ProductionRosterMemberV1 {
                participant_id: participant_ids[0],
                xonly_key: relay_keys[0],
                role: SenderRoleV1::Initiator,
            },
            ProductionRosterMemberV1 {
                participant_id: participant_ids[2],
                xonly_key: relay_keys[2],
                role: SenderRoleV1::Solver,
            },
        ];
        downstream_members.sort_by_key(|member| member.participant_id);
        let roster = ProductionRelayRosterBundleV1::new(
            [0x41; 32],
            [0x42; 32],
            [
                ProductionRosterLegV1 {
                    position: ProductionRoutePositionV1::Upstream,
                    session_id: [0x51; 32],
                    roster_snapshot: [0x61; 32],
                    policy_version: 7,
                    members: upstream_members,
                },
                ProductionRosterLegV1 {
                    position: ProductionRoutePositionV1::Downstream,
                    session_id: [0x52; 32],
                    roster_snapshot: [0x62; 32],
                    policy_version: 8,
                    members: downstream_members,
                },
            ],
        )
        .expect("fixture roster");
        let expected = ExpectedContextV1 {
            network_id: roster.network_id(),
            route_id: roster.route_id(),
            registry_digest: [0x43; 32],
            registry_epoch: 9,
            dom_chain_id: DOM_CHAIN_ID,
            dom_genesis_hash: [0x45; 32],
            legs: [
                ExpectedLegV1 {
                    session_id: [0x51; 32],
                    terms_hash: [0x71; 32],
                    roster: upstream_members.map(|member| member.participant_id),
                    roster_snapshot: [0x61; 32],
                    policy_version: 7,
                },
                ExpectedLegV1 {
                    session_id: [0x52; 32],
                    terms_hash: [0x72; 32],
                    roster: downstream_members.map(|member| member.participant_id),
                    roster_snapshot: [0x62; 32],
                    policy_version: 8,
                },
            ],
        };
        let decoded = fixture_decoded(&expected);
        let bytes = signed_fixture_artifact(&decoded, &roster, &secp);
        FixtureV1 {
            expected,
            roster,
            secp,
            bytes,
        }
    }

    fn signed_fixture_artifact(
        decoded: &DecodedBundleV1,
        roster: &ProductionRelayRosterBundleV1,
        secp: &SecpContext,
    ) -> Vec<u8> {
        let commit_unsigned = encode_commit_unsigned_v1(&decoded);
        assert_eq!(commit_unsigned.len(), COMMIT_UNSIGNED_BYTES_V1);
        let commit_digest =
            digest_v1(COMMIT_DIGEST_DOMAIN_V1, &commit_unsigned).expect("commit digest");
        let commit_signatures = fixture_stage_signatures(
            &decoded,
            &roster,
            &secp,
            commit_digest,
            None,
            COMMIT_SIGNER_DIGEST_DOMAIN_V1,
            0x81,
        );
        let reveal_unsigned = encode_reveal_unsigned_v1(&decoded, commit_digest);
        assert_eq!(reveal_unsigned.len(), REVEAL_UNSIGNED_BYTES_V1);
        let reveal_digest =
            digest_v1(REVEAL_DIGEST_DOMAIN_V1, &reveal_unsigned).expect("reveal digest");
        let reveal_signatures = fixture_stage_signatures(
            &decoded,
            &roster,
            &secp,
            reveal_digest,
            Some(commit_digest),
            REVEAL_SIGNER_DIGEST_DOMAIN_V1,
            0x91,
        );
        let mut bytes = commit_unsigned;
        commit_signatures
            .iter()
            .for_each(|signature| bytes.extend_from_slice(signature));
        bytes.extend_from_slice(&reveal_unsigned);
        reveal_signatures
            .iter()
            .for_each(|signature| bytes.extend_from_slice(signature));
        assert_eq!(bytes.len(), CONTRACTS_BOOTSTRAP_BYTES_V1);
        bytes
    }

    fn fixture_decoded(expected: &ExpectedContextV1) -> DecodedBundleV1 {
        let legs = [0usize, 1].map(|leg_index| {
            let expected_leg = &expected.legs[leg_index];
            let participants = [0usize, 1].map(|participant_index| {
                let stable_participant = stable_participant_index(
                    expected.dom_chain_id,
                    expected_leg.roster[participant_index],
                );
                let leg_participant = leg_index * 3 + stable_participant;
                let contribution = DecoyContributionV1::derive(
                    &SigningShareV1::from_be_bytes([0x21 + leg_participant as u8; 32])
                        .expect("fixture share"),
                    &SessionId::from_bytes(expected_leg.session_id).expect("fixture session"),
                );
                let commitment = contribution.commitment().to_bytes();
                let reveal = contribution.into_reveal().to_bytes();
                DecodedParticipantV1 {
                    participant_id: expected_leg.roster[participant_index],
                    direction: if stable_participant == 0 {
                        DirectionV1::Initiator
                    } else {
                        DirectionV1::Responder
                    },
                    key_reference: [0x91 + stable_participant as u8; 32],
                    noise_public_key: [0xA1 + stable_participant as u8; 32],
                    schnorr_public_key: public_key(0x31 + stable_participant as u8),
                    share_point: public_key(0x51 + leg_participant as u8),
                    contribution_commitment: commitment,
                    contribution_reveal: reveal,
                }
            });
            DecodedLegV1 {
                position: if leg_index == 0 {
                    ProductionRoutePositionV1::Upstream
                } else {
                    ProductionRoutePositionV1::Downstream
                },
                session_id: expected_leg.session_id,
                terms_hash: expected_leg.terms_hash,
                roster_snapshot: expected_leg.roster_snapshot,
                policy_version: expected_leg.policy_version,
                recovery_capsule: fixture_recovery_capsule(&participants),
                participants,
            }
        });
        DecodedBundleV1 {
            network_id: expected.network_id,
            route_id: expected.route_id,
            registry_digest: expected.registry_digest,
            registry_epoch: expected.registry_epoch,
            dom_chain_id: expected.dom_chain_id,
            dom_genesis_hash: expected.dom_genesis_hash,
            contract_kind: ContractKindV1::WitnessOrTimeout,
            legs,
            claimed_commit_digest: [0; 32],
            commit_signatures: [[0; 64]; 4],
            reveal_signatures: [[0; 64]; 4],
        }
    }

    fn fixture_stage_signatures(
        decoded: &DecodedBundleV1,
        roster: &ProductionRelayRosterBundleV1,
        secp: &SecpContext,
        stage_digest: [u8; 32],
        preceding_commit_digest: Option<[u8; 32]>,
        signer_domain: &[u8],
        aux_seed: u8,
    ) -> [[u8; 64]; 4] {
        let mut signatures = Vec::with_capacity(4);
        for leg_index in 0..2 {
            for participant_index in 0..2 {
                let member = roster.legs()[leg_index].members[participant_index];
                let secret = RELAY_SECRETS
                    .iter()
                    .find(|secret| {
                        secp.sign_bip340(secret, &[0x21; 32], &[0x22; 32])
                            .expect("fixture relay key")
                            .1
                            == member.xonly_key
                    })
                    .expect("fixture Relay secret");
                let digest = stage_signer_digest_v1(
                    signer_domain,
                    stage_digest,
                    preceding_commit_digest,
                    &decoded.legs[leg_index],
                    &decoded.legs[leg_index].participants[participant_index],
                    member.role,
                    member.xonly_key,
                )
                .expect("signer digest");
                signatures.push(
                    secp.sign_bip340(
                        secret,
                        &digest,
                        &[aux_seed + (leg_index * 2 + participant_index) as u8; 32],
                    )
                    .expect("fixture signature")
                    .0,
                );
            }
        }
        signatures.try_into().expect("four fixture signatures")
    }

    fn public_key(seed: u8) -> [u8; 33] {
        SecretKey::from_bytes(&[seed; 32])
            .expect("fixture secret")
            .public_key()
            .to_compressed_bytes()
    }

    fn canonical_participant_id(
        chain_id: [u8; 32],
        identity_public_key: [u8; 33],
    ) -> ParticipantId {
        let mut body = [0u8; 65];
        body[..32].copy_from_slice(&chain_id);
        body[32..].copy_from_slice(&identity_public_key);
        ParticipantId(
            *dom_crypto::blake2b_256_tagged(dom_adaptor::DomainTag::Participant.as_str(), &body)
                .as_bytes(),
        )
    }

    fn stable_participant_index(chain_id: [u8; 32], participant_id: ParticipantId) -> usize {
        (0u8..3)
            .position(|index| {
                canonical_participant_id(chain_id, public_key(0x31 + index)) == participant_id
            })
            .expect("known fixture participant")
    }

    fn fixture_recovery_capsule(
        participants: &[DecodedParticipantV1; 2],
    ) -> [u8; RECOVERY_CAPSULE_BYTES_V1] {
        let first = DecoyRevealV1::from_bytes(participants[0].contribution_reveal);
        let second = DecoyRevealV1::from_bytes(participants[1].contribution_reveal);
        let second_commit = DecoyCommitmentV1::from_bytes(participants[1].contribution_commitment);
        *combine_decoy_capsule_v1(&first, &second, &second_commit)
            .expect("fixture capsule")
            .as_bytes()
    }

    fn authenticate(
        fixture: &FixtureV1,
        bytes: &[u8],
    ) -> Result<AuthenticatedContractsBootstrapV1, ProductionContractsBootstrapErrorV1> {
        authenticate_against_expected_v1(bytes, &fixture.expected, &fixture.roster, &fixture.secp)
    }

    #[test]
    fn exact_artifact_authenticates_and_retains_bilateral_material() {
        let fixture = fixture();
        let authenticated = authenticate(&fixture, &fixture.bytes).expect("authenticate");
        assert_eq!(authenticated.network_id(), &fixture.expected.network_id);
        assert_eq!(authenticated.route_id(), &fixture.expected.route_id);
        assert_eq!(
            authenticated.registry_digest(),
            &fixture.expected.registry_digest
        );
        assert_eq!(
            authenticated.registry_epoch(),
            fixture.expected.registry_epoch
        );
        assert_eq!(authenticated.dom_chain_id(), &fixture.expected.dom_chain_id);
        assert_eq!(
            authenticated.dom_genesis_hash(),
            &fixture.expected.dom_genesis_hash
        );
        assert_eq!(
            authenticated.contract_kind(),
            ContractKindV1::WitnessOrTimeout
        );
        assert_ne!(authenticated.commit_stage_digest(), &[0; 32]);
        assert_ne!(authenticated.reveal_stage_digest(), &[0; 32]);
        assert_ne!(
            authenticated.commit_stage_digest(),
            authenticated.reveal_stage_digest()
        );
        assert_eq!(authenticated.legs()[0].participants().len(), 2);
        assert_eq!(authenticated.legs()[1].recovery_capsule().len(), 96);
    }

    #[test]
    fn relay_authorized_participant_id_substitution_cannot_mint_contracts_identity() {
        let fixture = fixture();
        let mut decoded = decode_canonical_v1(&fixture.bytes).expect("decode fixture");
        let retained_id = fixture.roster.legs()[0]
            .members
            .iter()
            .find(|member| member.role == SenderRoleV1::Solver)
            .expect("upstream solver")
            .participant_id;
        let substituted_id = ParticipantId([0xFE; 32]);
        assert!(fixture.roster.legs().iter().all(|leg| leg
            .members
            .iter()
            .all(|member| member.participant_id != substituted_id)));

        let upstream = &mut decoded.legs[0];
        upstream
            .participants
            .iter_mut()
            .find(|participant| participant.participant_id == retained_id)
            .expect("decoded upstream solver")
            .participant_id = substituted_id;
        upstream
            .participants
            .sort_by_key(|participant| participant.participant_id);
        upstream.recovery_capsule = fixture_recovery_capsule(&upstream.participants);

        let mut roster_legs = *fixture.roster.legs();
        roster_legs[0]
            .members
            .iter_mut()
            .find(|member| member.participant_id == retained_id)
            .expect("Relay upstream solver")
            .participant_id = substituted_id;
        roster_legs[0]
            .members
            .sort_by_key(|member| member.participant_id);
        let roster = ProductionRelayRosterBundleV1::new(
            fixture.roster.network_id(),
            fixture.roster.route_id(),
            roster_legs,
        )
        .expect("substituted Relay roster");
        let expected = ExpectedContextV1 {
            network_id: fixture.expected.network_id,
            route_id: fixture.expected.route_id,
            registry_digest: fixture.expected.registry_digest,
            registry_epoch: fixture.expected.registry_epoch,
            dom_chain_id: fixture.expected.dom_chain_id,
            dom_genesis_hash: fixture.expected.dom_genesis_hash,
            legs: [
                ExpectedLegV1 {
                    session_id: fixture.expected.legs[0].session_id,
                    terms_hash: fixture.expected.legs[0].terms_hash,
                    roster: roster_legs[0].members.map(|member| member.participant_id),
                    roster_snapshot: fixture.expected.legs[0].roster_snapshot,
                    policy_version: fixture.expected.legs[0].policy_version,
                },
                ExpectedLegV1 {
                    session_id: fixture.expected.legs[1].session_id,
                    terms_hash: fixture.expected.legs[1].terms_hash,
                    roster: roster_legs[1].members.map(|member| member.participant_id),
                    roster_snapshot: fixture.expected.legs[1].roster_snapshot,
                    policy_version: fixture.expected.legs[1].policy_version,
                },
            ],
        };

        // The compromised Relay authorities recompute both stages over the
        // substituted identifier.  Contracts identity derivation must remain
        // an independent fail-closed boundary.
        let bytes = signed_fixture_artifact(&decoded, &roster, &fixture.secp);
        assert_eq!(
            authenticate_against_expected_v1(&bytes, &expected, &roster, &fixture.secp).err(),
            Some(ProductionContractsBootstrapErrorV1::InvalidCryptographicBinding)
        );
    }

    #[test]
    fn truncation_and_trailing_bytes_fail_closed() {
        let fixture = fixture();
        assert_eq!(
            authenticate(&fixture, &fixture.bytes[..fixture.bytes.len() - 1]).err(),
            Some(ProductionContractsBootstrapErrorV1::NonCanonical)
        );
        let mut trailing = fixture.bytes.clone();
        trailing.push(0);
        assert_eq!(
            authenticate(&fixture, &trailing).err(),
            Some(ProductionContractsBootstrapErrorV1::NonCanonical)
        );
    }

    #[test]
    fn every_commit_and_reveal_stage_byte_is_covered_by_signatures() {
        let fixture = fixture();
        let indexes = (0..COMMIT_UNSIGNED_BYTES_V1)
            .chain(REVEAL_STAGE_OFFSET_V1..REVEAL_STAGE_OFFSET_V1 + REVEAL_UNSIGNED_BYTES_V1);
        for index in indexes {
            let mut mutated = fixture.bytes.clone();
            mutated[index] ^= 1;
            assert!(authenticate(&fixture, &mutated).is_err(), "byte {index}");
        }
    }

    #[test]
    fn signature_transplant_between_legs_is_rejected_in_both_stages() {
        let fixture = fixture();
        for stage_start in [
            COMMIT_UNSIGNED_BYTES_V1,
            REVEAL_STAGE_OFFSET_V1 + REVEAL_UNSIGNED_BYTES_V1,
        ] {
            let mut transplanted = fixture.bytes.clone();
            let first = stage_start;
            let third = stage_start + 2 * SIGNATURE_BYTES_V1;
            let first_signature: [u8; 64] = transplanted[first..first + 64]
                .try_into()
                .expect("signature");
            transplanted[third..third + 64].copy_from_slice(&first_signature);
            assert_eq!(
                authenticate(&fixture, &transplanted).err(),
                Some(ProductionContractsBootstrapErrorV1::SignatureInvalid)
            );
        }
    }

    #[test]
    fn signatures_cannot_be_substituted_between_commit_and_reveal_stages() {
        let fixture = fixture();
        let commit_signature_start = COMMIT_UNSIGNED_BYTES_V1;
        let reveal_signature_start = REVEAL_STAGE_OFFSET_V1 + REVEAL_UNSIGNED_BYTES_V1;
        for (source, target) in [
            (reveal_signature_start, commit_signature_start),
            (commit_signature_start, reveal_signature_start),
        ] {
            let mut transplanted = fixture.bytes.clone();
            let signature: [u8; 64] = transplanted[source..source + 64]
                .try_into()
                .expect("signature");
            transplanted[target..target + 64].copy_from_slice(&signature);
            assert_eq!(
                authenticate(&fixture, &transplanted).err(),
                Some(ProductionContractsBootstrapErrorV1::SignatureInvalid)
            );
        }
    }

    #[test]
    fn commitment_and_reveal_wire_mutations_are_independently_rejected() {
        let fixture = fixture();
        let first_commitment_offset = 186 + 108 + 166;
        let first_reveal_offset = REVEAL_STAGE_OFFSET_V1 + 48 + 40 + 36;
        for offset in [first_commitment_offset, first_reveal_offset] {
            let mut mutated = fixture.bytes.clone();
            mutated[offset] ^= 1;
            assert!(authenticate(&fixture, &mutated).is_err());
        }
    }

    #[test]
    fn cross_leg_body_transplant_is_rejected() {
        let fixture = fixture();
        let mut transplanted = fixture.bytes.clone();
        let upstream_session_offset = 186 + 4;
        let downstream_session_offset = 186 + 504 + 4;
        let downstream_reveal_session_offset = REVEAL_STAGE_OFFSET_V1 + 48 + 392 + 4;
        let upstream: [u8; 32] = transplanted
            [upstream_session_offset..upstream_session_offset + 32]
            .try_into()
            .expect("session");
        transplanted[downstream_session_offset..downstream_session_offset + 32]
            .copy_from_slice(&upstream);
        transplanted[downstream_reveal_session_offset..downstream_reveal_session_offset + 32]
            .copy_from_slice(&upstream);
        assert_eq!(
            authenticate(&fixture, &transplanted).err(),
            Some(ProductionContractsBootstrapErrorV1::ScopeMismatch)
        );
    }

    #[test]
    fn role_mutation_is_rejected_before_signature_verification() {
        let fixture = fixture();
        let mut mutated = fixture.bytes.clone();
        let first_direction_offset = 186 + 108 + 32;
        let first_reveal_direction_offset = REVEAL_STAGE_OFFSET_V1 + 48 + 40 + 32;
        assert_eq!(
            mutated[first_direction_offset],
            mutated[first_reveal_direction_offset]
        );
        let substituted = match DirectionV1::try_from(mutated[first_direction_offset])
            .expect("canonical fixture direction")
        {
            DirectionV1::Initiator => DirectionV1::Responder,
            DirectionV1::Responder => DirectionV1::Initiator,
        };
        mutated[first_direction_offset] = substituted.to_byte();
        mutated[first_reveal_direction_offset] = substituted.to_byte();
        assert_ne!(mutated, fixture.bytes);
        assert_eq!(
            authenticate(&fixture, &mutated).err(),
            Some(ProductionContractsBootstrapErrorV1::ScopeMismatch)
        );
    }

    #[test]
    fn contracts_key_cannot_reuse_any_relay_x_coordinate() {
        let fixture = fixture();
        let mut decoded = decode_canonical_v1(&fixture.bytes).expect("decode");
        let relay_x = fixture.roster.legs()[0].members[0].xonly_key;
        let prefix = decoded.legs[0].participants[0].schnorr_public_key[0];
        decoded.legs[0].participants[0].schnorr_public_key[1..].copy_from_slice(&relay_x);
        decoded.legs[0].participants[0].schnorr_public_key[0] = prefix;
        assert_eq!(
            verify_public_material_v1(&decoded, &fixture.roster).err(),
            Some(ProductionContractsBootstrapErrorV1::InvalidCryptographicBinding)
        );
    }

    #[test]
    fn different_participants_cannot_share_reference_noise_or_schnorr_key() {
        let fixture = fixture();
        for field in 0..3 {
            let mut decoded = decode_canonical_v1(&fixture.bytes).expect("decode");
            match field {
                0 => {
                    decoded.legs[0].participants[1].key_reference =
                        decoded.legs[0].participants[0].key_reference;
                }
                1 => {
                    decoded.legs[0].participants[1].noise_public_key =
                        decoded.legs[0].participants[0].noise_public_key;
                }
                _ => {
                    decoded.legs[0].participants[1].schnorr_public_key =
                        decoded.legs[0].participants[0].schnorr_public_key;
                }
            }
            assert_eq!(
                verify_public_material_v1(&decoded, &fixture.roster).err(),
                Some(if field == 2 {
                    ProductionContractsBootstrapErrorV1::InvalidCryptographicBinding
                } else {
                    ProductionContractsBootstrapErrorV1::IdentityCollision
                })
            );
        }
    }

    #[test]
    fn reveal_commitment_and_capsule_mutations_fail_closed() {
        let fixture = fixture();
        let mut decoded = decode_canonical_v1(&fixture.bytes).expect("decode");
        decoded.legs[0].participants[0].contribution_reveal[0] ^= 1;
        assert_eq!(
            verify_public_material_v1(&decoded, &fixture.roster).err(),
            Some(ProductionContractsBootstrapErrorV1::InvalidCryptographicBinding)
        );
        let mut decoded = decode_canonical_v1(&fixture.bytes).expect("decode");
        decoded.legs[0].recovery_capsule[20] ^= 1;
        assert_eq!(
            verify_public_material_v1(&decoded, &fixture.roster).err(),
            Some(ProductionContractsBootstrapErrorV1::InvalidCryptographicBinding)
        );
    }

    #[test]
    fn authenticated_authority_is_move_only_and_redacted() {
        assert_not_impl_any!(AuthenticatedContractsBootstrapV1: Clone, Copy, core::fmt::Debug, Eq, PartialEq);
        assert_not_impl_any!(AuthenticatedContractsLegV1: Clone, Copy, core::fmt::Debug);
        assert_not_impl_any!(AuthenticatedContractsParticipantV1: Clone, Copy, core::fmt::Debug);
    }
}
