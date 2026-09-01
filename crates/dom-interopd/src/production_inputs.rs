//! Authenticated, secret-free public inputs for the production composition root.
//!
//! Bootstrap configuration carries commitments, never proof. This boundary
//! opens the retained registry, verifies three explicitly distinct BIP340
//! authority sets, decodes every canonical artifact, consumes the durable V2
//! time capability, builds the composition and only then asks route admission
//! to issue its capability. No endpoint, credential, signer or local clock is
//! accepted here.

use std::fs::File;
use std::io::Read;

use adapter_btc::roster::{BitcoinSignerRoleV1, ParticipantKeyRosterV1, ParticipantKeyV1};
use blake2::{
    digest::{Update, VariableOutput},
    Blake2bVar,
};
use btc_crypto::SecpContext;
use chain_profile::ChainKindV1;
use deployment_registry::{
    AuthoritySetV1, RegistryStoreV1, RegistryValidationPolicyV1, ResolvedBitcoinDeploymentV1,
    ResolvedMoneroDeploymentV1, ResolvedRegistryV1, ResolvedSolanaDeploymentV1,
    MAX_AUTHORITY_SET_BYTES,
};
use kaystra_core::{
    terms::SettlementTermsV1,
    types::{Digest32, ParticipantId},
};
use participant_binding::{
    bind_evm_session_v1, verify_evm_account_binding_v1, AuthenticatedEvmSessionBindingsV1,
    EvmAccountBindingProofV1, EvmBindingRoleV1, EvmSettlementPositionV1,
    EVM_ACCOUNT_BINDING_PROOF_BYTES_V1,
};
use relay::auth::{RosterMemberV1, RosterRegistryV1, RosterSnapshotV1};
use relay::SenderRoleV1;
use route_composer::ComposedBindingV2;
use route_executor::{
    CanonicalCodecV1, CommitOutcomeV1, DurableRouteStoreV1, FrozenRouteAdmissionCheckpointV2,
    LegIdV1, RouteEventV1, RouteIdV1, RouteStoreErrorV1,
};
use route_time_anchor::{
    route_scope_digest, DurableRouteTimeAnchorStoreV2, FrozenRouteTimeCheckpointV2,
    FrozenRouteTimeProofCheckpointV2, RouteTimeAnchorErrorV2, RouteTimeAnchorStoreConfigV2,
    RouteTimeEvidenceV2, RouteTimeEvidenceVerificationContextV2, RouteTimePolicyV2,
    RouteTimePolicyVerificationContextV2, SignedRouteTimeEvidenceV2, SignedRouteTimePolicyV2,
};
use solana_profile::{
    validate_setup as validate_solana_setup, SolanaAdapterProfileV1, SolanaAssetV1,
    SolanaNetwork as SolanaAdapterNetworkV1, SolanaSetupBindingV1, ValidatedSolanaSetup,
};
use solana_types::SolanaPubkey;
use xmr_dleq_sigma::{BoundCrossCurveProofV1, CrossCurveProofBytes, CrossCurvePublicClaim};
use xmr_setup_profile::{
    validate_setup as validate_xmr_setup, ValidatedXmrSetup, XmrAdapterProfileV1, XmrNetwork,
    XmrSetupBindingV1,
};

use crate::admission::{
    AuthenticatedRouteAdmissionV1, RegistryRouteAdmissionAuthorityV1, RouteRosterSnapshotsV1,
};
use crate::production_config::{
    ProductionBootstrapModeV1, ProductionPathRoleV1, ValidatedProductionBootstrapV1,
};
use crate::production_provisioning::{
    DurableProductionProvisioningJournalV1, ProductionProvisioningStageStateV1,
    ProductionProvisioningStageV1,
};

/// Maximum size of the three-set public authority bundle.
pub const MAX_PRODUCTION_AUTHORITY_BUNDLE_BYTES_V1: usize = 12 + 3 * (2 + MAX_AUTHORITY_SET_BYTES);
/// Exact size of the two-leg Relay roster bundle.
pub const PRODUCTION_ROSTER_BUNDLE_BYTES_V1: usize = 492;
/// Maximum size of a route's EVM-account and Bitcoin-key participant proofs.
pub const MAX_PRODUCTION_PARTICIPANT_BUNDLE_BYTES_V1: usize = 12
    + 32
    + 4
    + 2 * (4 + 2 * EVM_ACCOUNT_BINDING_PROOF_BYTES_V1)
    + 4
    + 2 * (4 + 2 * BITCOIN_PARTICIPANT_KEY_PROOF_BYTES_V1);
/// Exact encoding of one Relay-authenticated Bitcoin participant key proof.
pub const BITCOIN_PARTICIPANT_KEY_PROOF_BYTES_V1: usize = 32 + 1 + 33 + 64;
/// Fixed-width prefix of one Solana leg setup: adapter profile plus every
/// binding field except the variable-length DLEQ proof body.
pub const SOLANA_LEG_SETUP_FIXED_BYTES_V1: usize = 43 // adapter profile
    + 32 + 32                 // settlement_id, terms_hash
    + 2 + 32 + 32 + 1         // dleq envelope header
    + 2 + 65 + 4              // proof bundle header: version, claim, proof length
    + 32 * 4 + 3              // program and PDA identities, bumps
    + 1 + 32 + 1              // asset tag, mint, decimals
    + 32 * 3 + 8 + 8          // parties, amount, refund deadline
    + 32 + 32; // program_data_hash, setup_id
/// Maximum size of a participant bundle that also carries Solana leg setups.
/// The DLEQ proof body dominates; it is bounded by the proof system's own
/// frozen limit, never by what a peer claims.
pub const MAX_PRODUCTION_PARTICIPANT_BUNDLE_EXTENDED_BYTES_V1: usize =
    MAX_PRODUCTION_PARTICIPANT_BUNDLE_BYTES_V1
        + 4
        + 2 * (4 + SOLANA_LEG_SETUP_FIXED_BYTES_V1 + xmr_dleq_sigma::MAX_PROOF_BYTES)
        + 4
        + 2 * (4
            + XMR_LEG_SETUP_FIXED_BYTES_V1
            + 2 * xmr_dleq_sigma::MAX_PROOF_BYTES
            + xmr_live_sidecar_api::MAX_DESTINATION_BYTES);
/// Fixed-width prefix of one Monero leg setup: adapter profile plus every
/// binding field except the variable-length DLEQ proof body and destination.
pub const XMR_LEG_SETUP_FIXED_BYTES_V1: usize = 11 // adapter profile
    + 32 + 32                 // settlement_id, terms_hash
    + 2 + 32 + 32 + 1         // dleq envelope header
    + 2 + 65 + 4              // proof bundle header: version, claim, proof length
    + 32 + 8 + 2              // funding tx, amount, destination length
    + 32                      // combined spend public key
    + 1                       // refund-arm flag
    + 2 + 32 + 32 + 1         // refund dleq envelope header
    + 2 + 65 + 4              // refund proof bundle header
    + 32 + 33 + 32 + 8; // refund artifact: template, point, profile, deadline

const AUTHORITY_BUNDLE_MAGIC_V1: &[u8; 8] = b"DOMPAUB1";
const ROSTER_BUNDLE_MAGIC_V1: &[u8; 8] = b"DOMRSTR1";
const PARTICIPANT_BUNDLE_MAGIC_V1: &[u8; 8] = b"DOMPEVB1";
const INPUT_VERSION_V1: u16 = 1;
const ROSTER_BUNDLE_DIGEST_DOMAIN_V1: &[u8] = b"DOM-INTEROPD/PRODUCTION-RELAY-ROSTERS/V1\0";
const PARTICIPANT_BUNDLE_DIGEST_DOMAIN_V1: &[u8] =
    b"DOM-INTEROPD/PRODUCTION-PARTICIPANT-BINDINGS/V1\0";
const BITCOIN_PARTICIPANT_KEY_DOMAIN_V1: &[u8] =
    b"DOM-INTEROPD/PRODUCTION-BITCOIN-PARTICIPANT-KEY/V1\0";
const FREEZE_EVENT_ID_DOMAIN_V2: &[u8] = b"DOM-INTEROPD/PRODUCTION-FREEZE-TERMS/V2\0";
const VERIFICATION_CONTEXT_SEED_V1: [u8; 32] = [0xD4; 32];
const MAX_TERMS_ARTIFACT_BYTES_V1: u64 = 8 * 1024;
const MAX_SIGNED_TIME_POLICY_ARTIFACT_BYTES_V1: u64 = 4 * 1024;
const MAX_SIGNED_TIME_EVIDENCE_ARTIFACT_BYTES_V1: u64 = 8 * 1024;
const ZERO_DIGEST: Digest32 = [0; 32];

/// The fixed position of one settlement in a composed route.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ProductionRoutePositionV1 {
    /// Counterparty funds the DOM hub.
    Upstream,
    /// DOM hub funds the counterparty exit.
    Downstream,
}

impl ProductionRoutePositionV1 {
    const fn tag(self) -> u8 {
        match self {
            Self::Upstream => 1,
            Self::Downstream => 2,
        }
    }

    fn from_tag(tag: u8) -> Result<Self, ProductionInputErrorV1> {
        match tag {
            1 => Ok(Self::Upstream),
            2 => Ok(Self::Downstream),
            _ => Err(ProductionInputErrorV1::NonCanonicalEncoding),
        }
    }

    const fn evm_position(self) -> EvmSettlementPositionV1 {
        match self {
            Self::Upstream => EvmSettlementPositionV1::Upstream,
            Self::Downstream => EvmSettlementPositionV1::Downstream,
        }
    }

    const fn leg(self) -> LegIdV1 {
        match self {
            Self::Upstream => LegIdV1::Upstream,
            Self::Downstream => LegIdV1::Downstream,
        }
    }

    const fn index(self) -> usize {
        match self {
            Self::Upstream => 0,
            Self::Downstream => 1,
        }
    }
}

/// Canonical file containing independent registry, policy and evidence sets.
#[derive(Clone, Eq, PartialEq)]
pub struct ProductionAuthorityBundleV1 {
    registry: AuthoritySetV1,
    time_policy: AuthoritySetV1,
    time_evidence: AuthoritySetV1,
}

impl core::fmt::Debug for ProductionAuthorityBundleV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("ProductionAuthorityBundleV1")
            .field("registry_count", &self.registry.xonly_keys().len())
            .field("time_policy_count", &self.time_policy.xonly_keys().len())
            .field(
                "time_evidence_count",
                &self.time_evidence.xonly_keys().len(),
            )
            .finish()
    }
}

impl ProductionAuthorityBundleV1 {
    /// Builds a bundle only when all three roles use distinct sets.
    pub fn new(
        registry: AuthoritySetV1,
        time_policy: AuthoritySetV1,
        time_evidence: AuthoritySetV1,
    ) -> Result<Self, ProductionInputErrorV1> {
        if registry == time_policy || registry == time_evidence || time_policy == time_evidence {
            return Err(ProductionInputErrorV1::InvalidAuthorityBundle);
        }
        Ok(Self {
            registry,
            time_policy,
            time_evidence,
        })
    }

    /// Registry threshold set.
    pub const fn registry(&self) -> &AuthoritySetV1 {
        &self.registry
    }

    /// Independent static time-policy threshold set.
    pub const fn time_policy(&self) -> &AuthoritySetV1 {
        &self.time_policy
    }

    /// Independent live checkpoint-evidence threshold set.
    pub const fn time_evidence(&self) -> &AuthoritySetV1 {
        &self.time_evidence
    }

    /// Exact bounded representation for offline provisioning.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, ProductionInputErrorV1> {
        let sets = [
            self.registry.canonical_bytes(),
            self.time_policy.canonical_bytes(),
            self.time_evidence.canonical_bytes(),
        ];
        let mut bytes = Vec::with_capacity(MAX_PRODUCTION_AUTHORITY_BUNDLE_BYTES_V1);
        bytes.extend_from_slice(AUTHORITY_BUNDLE_MAGIC_V1);
        bytes.extend_from_slice(&INPUT_VERSION_V1.to_be_bytes());
        bytes.extend_from_slice(&0u16.to_be_bytes());
        for set in sets {
            let set = set.map_err(|_| ProductionInputErrorV1::InvalidAuthorityBundle)?;
            let length =
                u16::try_from(set.len()).map_err(|_| ProductionInputErrorV1::InputBoundExceeded)?;
            bytes.extend_from_slice(&length.to_be_bytes());
            bytes.extend_from_slice(&set);
        }
        if bytes.len() > MAX_PRODUCTION_AUTHORITY_BUNDLE_BYTES_V1 {
            return Err(ProductionInputErrorV1::InputBoundExceeded);
        }
        Ok(bytes)
    }

    /// Strictly decodes a three-set bundle and rejects trailing bytes.
    pub fn decode_canonical(bytes: &[u8]) -> Result<Self, ProductionInputErrorV1> {
        if bytes.len() > MAX_PRODUCTION_AUTHORITY_BUNDLE_BYTES_V1 {
            return Err(ProductionInputErrorV1::InputBoundExceeded);
        }
        let mut cursor = InputCursorV1::new(bytes);
        if cursor.take::<8>()? != *AUTHORITY_BUNDLE_MAGIC_V1
            || cursor.u16()? != INPUT_VERSION_V1
            || cursor.u16()? != 0
        {
            return Err(ProductionInputErrorV1::NonCanonicalEncoding);
        }
        let mut decode_set = || {
            let length = usize::from(cursor.u16()?);
            let encoded = cursor.bytes(length)?;
            AuthoritySetV1::decode_canonical(encoded)
                .map_err(|_| ProductionInputErrorV1::InvalidAuthorityBundle)
        };
        let value = Self::new(decode_set()?, decode_set()?, decode_set()?)?;
        cursor.finish()?;
        if value.canonical_bytes()?.as_slice() != bytes {
            return Err(ProductionInputErrorV1::NonCanonicalEncoding);
        }
        Ok(value)
    }
}

/// One authenticated Relay roster member retained in the public input file.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProductionRosterMemberV1 {
    /// Protocol participant identity from settlement terms.
    pub participant_id: ParticipantId,
    /// Exact BIP340 key at the frozen snapshot.
    pub xonly_key: [u8; 32],
    /// Relay role authorized at that snapshot.
    pub role: SenderRoleV1,
}

/// One settlement's exact Relay session/roster context.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProductionRosterLegV1 {
    /// Route position, encoded in canonical upstream/downstream order.
    pub position: ProductionRoutePositionV1,
    /// Settlement session identity.
    pub session_id: Digest32,
    /// Opaque snapshot identifier carried by Relay envelopes.
    pub roster_snapshot: Digest32,
    /// Settlement policy version.
    pub policy_version: u32,
    /// Exactly the two sorted settlement participants.
    pub members: [ProductionRosterMemberV1; 2],
}

/// Canonical public roster material for both independent settlements.
#[derive(Clone, Eq, PartialEq)]
pub struct ProductionRelayRosterBundleV1 {
    network_id: Digest32,
    route_id: RouteIdV1,
    legs: [ProductionRosterLegV1; 2],
}

impl core::fmt::Debug for ProductionRelayRosterBundleV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("ProductionRelayRosterBundleV1([public commitments])")
    }
}

impl ProductionRelayRosterBundleV1 {
    /// Builds one exact two-settlement roster bundle.
    pub fn new(
        network_id: Digest32,
        route_id: RouteIdV1,
        legs: [ProductionRosterLegV1; 2],
    ) -> Result<Self, ProductionInputErrorV1> {
        let value = Self {
            network_id,
            route_id,
            legs,
        };
        value.validate_shape()?;
        Ok(value)
    }

    /// Network frozen into both Relay contexts.
    pub const fn network_id(&self) -> Digest32 {
        self.network_id
    }

    /// Composed route frozen into both Relay contexts.
    pub const fn route_id(&self) -> RouteIdV1 {
        self.route_id
    }

    /// Canonical upstream/downstream contexts.
    pub const fn legs(&self) -> &[ProductionRosterLegV1; 2] {
        &self.legs
    }

    /// Exact fixed-size representation.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, ProductionInputErrorV1> {
        self.validate_shape()?;
        let mut bytes = Vec::with_capacity(PRODUCTION_ROSTER_BUNDLE_BYTES_V1);
        bytes.extend_from_slice(ROSTER_BUNDLE_MAGIC_V1);
        bytes.extend_from_slice(&INPUT_VERSION_V1.to_be_bytes());
        bytes.extend_from_slice(&0u16.to_be_bytes());
        bytes.push(2);
        bytes.extend_from_slice(&[0; 3]);
        bytes.extend_from_slice(&self.network_id);
        bytes.extend_from_slice(&self.route_id);
        for leg in self.legs {
            bytes.push(leg.position.tag());
            bytes.extend_from_slice(&[0; 3]);
            bytes.extend_from_slice(&leg.session_id);
            bytes.extend_from_slice(&leg.roster_snapshot);
            bytes.extend_from_slice(&leg.policy_version.to_be_bytes());
            bytes.push(2);
            bytes.extend_from_slice(&[0; 3]);
            for member in leg.members {
                bytes.extend_from_slice(&member.participant_id.0);
                bytes.extend_from_slice(&member.xonly_key);
                bytes.push(sender_role_tag(member.role));
            }
        }
        if bytes.len() != PRODUCTION_ROSTER_BUNDLE_BYTES_V1 {
            return Err(ProductionInputErrorV1::NonCanonicalEncoding);
        }
        Ok(bytes)
    }

    /// Strictly decodes both roster contexts.
    pub fn decode_canonical(bytes: &[u8]) -> Result<Self, ProductionInputErrorV1> {
        if bytes.len() != PRODUCTION_ROSTER_BUNDLE_BYTES_V1 {
            return Err(ProductionInputErrorV1::NonCanonicalEncoding);
        }
        let mut cursor = InputCursorV1::new(bytes);
        if cursor.take::<8>()? != *ROSTER_BUNDLE_MAGIC_V1
            || cursor.u16()? != INPUT_VERSION_V1
            || cursor.u16()? != 0
            || cursor.u8()? != 2
            || cursor.take::<3>()? != [0; 3]
        {
            return Err(ProductionInputErrorV1::NonCanonicalEncoding);
        }
        let network_id = cursor.take::<32>()?;
        let route_id = cursor.take::<32>()?;
        let mut legs = Vec::with_capacity(2);
        for _ in 0..2 {
            let position = ProductionRoutePositionV1::from_tag(cursor.u8()?)?;
            if cursor.take::<3>()? != [0; 3] {
                return Err(ProductionInputErrorV1::NonCanonicalEncoding);
            }
            let session_id = cursor.take::<32>()?;
            let roster_snapshot = cursor.take::<32>()?;
            let policy_version = cursor.u32()?;
            if cursor.u8()? != 2 || cursor.take::<3>()? != [0; 3] {
                return Err(ProductionInputErrorV1::NonCanonicalEncoding);
            }
            let mut members = Vec::with_capacity(2);
            for _ in 0..2 {
                members.push(ProductionRosterMemberV1 {
                    participant_id: ParticipantId(cursor.take::<32>()?),
                    xonly_key: cursor.take::<32>()?,
                    role: sender_role_from_tag(cursor.u8()?)?,
                });
            }
            legs.push(ProductionRosterLegV1 {
                position,
                session_id,
                roster_snapshot,
                policy_version,
                members: members
                    .try_into()
                    .map_err(|_| ProductionInputErrorV1::NonCanonicalEncoding)?,
            });
        }
        cursor.finish()?;
        let value = Self::new(
            network_id,
            route_id,
            legs.try_into()
                .map_err(|_| ProductionInputErrorV1::NonCanonicalEncoding)?,
        )?;
        if value.canonical_bytes()?.as_slice() != bytes {
            return Err(ProductionInputErrorV1::NonCanonicalEncoding);
        }
        Ok(value)
    }

    /// Domain-separated commitment pinned by production bootstrap.
    pub fn bundle_digest(&self) -> Result<Digest32, ProductionInputErrorV1> {
        digest_bytes(ROSTER_BUNDLE_DIGEST_DOMAIN_V1, &self.canonical_bytes()?)
    }

    fn validate_shape(&self) -> Result<(), ProductionInputErrorV1> {
        if self.network_id == ZERO_DIGEST
            || self.route_id == ZERO_DIGEST
            || self.legs[0].position != ProductionRoutePositionV1::Upstream
            || self.legs[1].position != ProductionRoutePositionV1::Downstream
            || self.legs[0].session_id == self.legs[1].session_id
            || self.legs[0].roster_snapshot == self.legs[1].roster_snapshot
        {
            return Err(ProductionInputErrorV1::InvalidRosterBundle);
        }
        for leg in self.legs {
            let members = leg.members;
            if leg.session_id == ZERO_DIGEST
                || leg.roster_snapshot == ZERO_DIGEST
                || leg.policy_version == 0
                || members[0].participant_id.0 == ZERO_DIGEST
                || members[0].participant_id >= members[1].participant_id
                || members[0].xonly_key == ZERO_DIGEST
                || members[1].xonly_key == ZERO_DIGEST
                || members[0].xonly_key == members[1].xonly_key
                || matches!(members[0].role, SenderRoleV1::Observer)
                || matches!(members[1].role, SenderRoleV1::Observer)
                || members[0].role == members[1].role
            {
                return Err(ProductionInputErrorV1::InvalidRosterBundle);
            }
        }
        Ok(())
    }

    fn member_key(
        &self,
        position: ProductionRoutePositionV1,
        participant: ParticipantId,
    ) -> Result<[u8; 32], ProductionInputErrorV1> {
        self.legs[position.index()]
            .members
            .iter()
            .find(|member| member.participant_id == participant)
            .map(|member| member.xonly_key)
            .ok_or(ProductionInputErrorV1::InvalidRosterBundle)
    }

    fn snapshots(&self) -> RouteRosterSnapshotsV1 {
        RouteRosterSnapshotsV1 {
            upstream: self.legs[0].roster_snapshot,
            downstream: self.legs[1].roster_snapshot,
        }
    }

    fn to_registry(&self) -> RosterRegistryV1 {
        let mut registry = RosterRegistryV1::new();
        for leg in self.legs {
            let mut snapshot = RosterSnapshotV1::new();
            for member in leg.members {
                snapshot = snapshot.with_member(
                    member.participant_id,
                    RosterMemberV1 {
                        xonly_key: member.xonly_key,
                        role: member.role,
                    },
                );
            }
            registry = registry.with_snapshot(leg.roster_snapshot, snapshot);
        }
        registry
    }
}

/// The two dual-signed account links for one EVM settlement.
#[derive(Clone, Eq, PartialEq)]
pub struct ProductionEvmLegProofsV1 {
    position: ProductionRoutePositionV1,
    funder: EvmAccountBindingProofV1,
    beneficiary: EvmAccountBindingProofV1,
}

impl core::fmt::Debug for ProductionEvmLegProofsV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("ProductionEvmLegProofsV1")
            .field("position", &self.position)
            .finish_non_exhaustive()
    }
}

impl ProductionEvmLegProofsV1 {
    /// Groups the mandatory funding and beneficiary proofs for one route leg.
    pub fn new(
        position: ProductionRoutePositionV1,
        funder: EvmAccountBindingProofV1,
        beneficiary: EvmAccountBindingProofV1,
    ) -> Result<Self, ProductionInputErrorV1> {
        if funder.statement().position != position.evm_position()
            || beneficiary.statement().position != position.evm_position()
            || funder.statement().role != EvmBindingRoleV1::Funder
            || beneficiary.statement().role != EvmBindingRoleV1::Beneficiary
        {
            return Err(ProductionInputErrorV1::InvalidParticipantBundle);
        }
        Ok(Self {
            position,
            funder,
            beneficiary,
        })
    }

    /// Route position of this proof pair.
    pub const fn position(&self) -> ProductionRoutePositionV1 {
        self.position
    }

    /// Funding-account proof.
    pub const fn funder(&self) -> &EvmAccountBindingProofV1 {
        &self.funder
    }

    /// Beneficiary-account proof.
    pub const fn beneficiary(&self) -> &EvmAccountBindingProofV1 {
        &self.beneficiary
    }
}

/// Exact public facts signed when a Relay participant binds its Bitcoin key.
///
/// The signature verifier reconstructs this value only from already
/// authenticated route, terms, roster and deployment facts.  Deployment
/// tooling may construct the same statement to obtain each participant's
/// BIP340 proof; no production authority is minted by this value.
pub struct ProductionBitcoinParticipantKeyStatementRequestV1 {
    /// Interoperability network authenticated by the registry and roster.
    pub network_id: Digest32,
    /// Composed route identity.
    pub route_id: RouteIdV1,
    /// Exact upstream or downstream position.
    pub position: ProductionRoutePositionV1,
    /// Settlement session identity.
    pub session_id: Digest32,
    /// Canonical settlement-terms digest.
    pub terms_digest: Digest32,
    /// Frozen Relay roster snapshot.
    pub roster_snapshot: Digest32,
    /// Stable participant identity from the terms roster.
    pub participant_id: ParticipantId,
    /// Maker/taker position in the Bitcoin signing roster.
    pub role: BitcoinSignerRoleV1,
    /// Relay BIP340 key authorized to make this binding.
    pub relay_xonly_key: [u8; 32],
    /// Compressed SEC1 Bitcoin claim-signing key being bound.
    pub bitcoin_public_key: [u8; 33],
    /// Threshold-authenticated registry manifest digest.
    pub registry_digest: Digest32,
    /// Threshold-authenticated registry epoch.
    pub registry_epoch: u64,
    /// Exact Bitcoin chain-profile digest.
    pub profile_digest: Digest32,
    /// Exact selected Bitcoin asset-binding digest.
    pub asset_binding_digest: Digest32,
    /// Registry-selected Bitcoin chain identifier.
    pub chain_id: Digest32,
    /// Registry-selected Bitcoin genesis hash.
    pub genesis_hash: Digest32,
}

impl ProductionBitcoinParticipantKeyStatementRequestV1 {
    /// Domain-separated digest signed by the participant's frozen Relay key.
    pub fn digest(&self) -> Result<Digest32, ProductionInputErrorV1> {
        let digests = [
            self.network_id,
            self.route_id,
            self.session_id,
            self.terms_digest,
            self.roster_snapshot,
            self.participant_id.0,
            self.relay_xonly_key,
            self.registry_digest,
            self.profile_digest,
            self.asset_binding_digest,
            self.chain_id,
            self.genesis_hash,
        ];
        if self.registry_epoch == 0
            || digests.contains(&ZERO_DIGEST)
            || !matches!(self.bitcoin_public_key[0], 0x02 | 0x03)
            || self.bitcoin_public_key[1..] == [0; 32]
        {
            return Err(ProductionInputErrorV1::InvalidParticipantBundle);
        }
        let mut bytes = Vec::with_capacity(431);
        bytes.extend_from_slice(&self.network_id);
        bytes.extend_from_slice(&self.route_id);
        bytes.push(self.position.tag());
        bytes.extend_from_slice(&self.session_id);
        bytes.extend_from_slice(&self.terms_digest);
        bytes.extend_from_slice(&self.roster_snapshot);
        bytes.extend_from_slice(&self.participant_id.0);
        bytes.push(self.role as u8);
        bytes.extend_from_slice(&self.relay_xonly_key);
        bytes.extend_from_slice(&self.bitcoin_public_key);
        bytes.extend_from_slice(&self.registry_digest);
        bytes.extend_from_slice(&self.registry_epoch.to_be_bytes());
        bytes.extend_from_slice(&self.profile_digest);
        bytes.extend_from_slice(&self.asset_binding_digest);
        bytes.extend_from_slice(&self.chain_id);
        bytes.extend_from_slice(&self.genesis_hash);
        digest_bytes(BITCOIN_PARTICIPANT_KEY_DOMAIN_V1, &bytes)
    }
}

/// One participant's signed Bitcoin key binding retained in the public bundle.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct ProductionBitcoinParticipantKeyProofV1 {
    participant_id: ParticipantId,
    role: BitcoinSignerRoleV1,
    compressed_key: [u8; 33],
    signature: [u8; 64],
}

impl core::fmt::Debug for ProductionBitcoinParticipantKeyProofV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("ProductionBitcoinParticipantKeyProofV1")
            .field("participant_id", &self.participant_id)
            .field("role", &self.role)
            .field("compressed_key", &"[redacted public key]")
            .field("signature", &"[redacted signature]")
            .finish()
    }
}

impl ProductionBitcoinParticipantKeyProofV1 {
    /// Construct one structurally canonical proof for later authentication.
    pub fn new(
        participant_id: ParticipantId,
        role: BitcoinSignerRoleV1,
        compressed_key: [u8; 33],
        signature: [u8; 64],
    ) -> Result<Self, ProductionInputErrorV1> {
        if participant_id.0 == ZERO_DIGEST
            || !matches!(compressed_key[0], 0x02 | 0x03)
            || compressed_key[1..] == [0; 32]
            || signature == [0; 64]
        {
            return Err(ProductionInputErrorV1::InvalidParticipantBundle);
        }
        Ok(Self {
            participant_id,
            role,
            compressed_key,
            signature,
        })
    }

    /// Stable participant identity from settlement terms.
    pub const fn participant_id(&self) -> ParticipantId {
        self.participant_id
    }

    /// Exact maker/taker role committed by this proof.
    pub const fn role(&self) -> BitcoinSignerRoleV1 {
        self.role
    }

    /// Bound compressed Bitcoin signing key.
    pub const fn compressed_key(&self) -> [u8; 33] {
        self.compressed_key
    }
}

/// Both Relay-authenticated Bitcoin participant keys for one settlement.
#[derive(Clone, Eq, PartialEq)]
pub struct ProductionBitcoinLegKeyProofsV1 {
    position: ProductionRoutePositionV1,
    participants: [ProductionBitcoinParticipantKeyProofV1; 2],
}

impl core::fmt::Debug for ProductionBitcoinLegKeyProofsV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("ProductionBitcoinLegKeyProofsV1")
            .field("position", &self.position)
            .finish_non_exhaustive()
    }
}

impl ProductionBitcoinLegKeyProofsV1 {
    /// Construct the exact terms-ordered maker/taker proof pair for one route leg.
    pub fn new(
        position: ProductionRoutePositionV1,
        participants: [ProductionBitcoinParticipantKeyProofV1; 2],
    ) -> Result<Self, ProductionInputErrorV1> {
        if participants[0].participant_id >= participants[1].participant_id
            || participants[0].role == participants[1].role
            || participants[0].compressed_key == participants[1].compressed_key
        {
            return Err(ProductionInputErrorV1::InvalidParticipantBundle);
        }
        Ok(Self {
            position,
            participants,
        })
    }

    /// Upstream or downstream route position.
    pub const fn position(&self) -> ProductionRoutePositionV1 {
        self.position
    }

    /// Canonical settlement-terms order, with exactly one maker and one taker.
    pub const fn participants(&self) -> &[ProductionBitcoinParticipantKeyProofV1; 2] {
        &self.participants
    }
}

/// One route leg's registered Solana escrow setup: the adapter profile the
/// frozen terms committed to and the DLEQ-bound setup binding. Unlike the EVM
/// and Bitcoin legs there is no participant signature to verify here — the
/// authentication anchor is the cross-curve DLEQ inside the binding, which
/// `solana_profile::validate_setup` verifies against the frozen terms.
#[derive(Clone, Eq, PartialEq)]
pub struct ProductionSolanaLegSetupV1 {
    pub(crate) position: ProductionRoutePositionV1,
    pub(crate) profile: SolanaAdapterProfileV1,
    pub(crate) binding: SolanaSetupBindingV1,
}

impl core::fmt::Debug for ProductionSolanaLegSetupV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("ProductionSolanaLegSetupV1")
            .field("position", &self.position)
            .finish_non_exhaustive()
    }
}

impl ProductionSolanaLegSetupV1 {
    /// Builds one Solana leg setup after structural zero/bounds checks. Full
    /// cryptographic authentication happens only inside bundle verification.
    pub fn new(
        position: ProductionRoutePositionV1,
        profile: SolanaAdapterProfileV1,
        binding: SolanaSetupBindingV1,
    ) -> Result<Self, ProductionInputErrorV1> {
        if profile.program_id.is_zero()
            || profile.rpc_quorum == 0
            || profile.rpc_quorum > profile.rpc_node_count
            || binding.settlement_id == ZERO_DIGEST
            || binding.terms_hash == ZERO_DIGEST
            || binding.program_id.is_zero()
            || binding.dleq.bundle.proof.is_empty()
            || binding.dleq.bundle.proof.len() > xmr_dleq_sigma::MAX_PROOF_BYTES
        {
            return Err(ProductionInputErrorV1::InvalidParticipantBundle);
        }
        Ok(Self {
            position,
            profile,
            binding,
        })
    }

    fn encode_into(&self, bytes: &mut Vec<u8>) -> Result<(), ProductionInputErrorV1> {
        bytes.push(self.position.tag());
        bytes.extend_from_slice(&[0; 3]);
        bytes.push(self.profile.network as u8);
        bytes.extend_from_slice(&self.profile.program_id.0);
        bytes.extend_from_slice(&self.profile.rpc_node_count.to_be_bytes());
        bytes.extend_from_slice(&self.profile.rpc_quorum.to_be_bytes());
        bytes.push(u8::from(self.profile.allow_legacy_spl));
        bytes.push(u8::from(self.profile.require_immutable_program));
        bytes.extend_from_slice(&self.profile.max_signed_transaction_bytes.to_be_bytes());
        let binding = &self.binding;
        bytes.extend_from_slice(&binding.settlement_id);
        bytes.extend_from_slice(&binding.terms_hash);
        bytes.extend_from_slice(&binding.dleq.version.to_be_bytes());
        bytes.extend_from_slice(&binding.dleq.settlement_id);
        bytes.extend_from_slice(&binding.dleq.context_hash);
        bytes.push(binding.dleq.role);
        bytes.extend_from_slice(&binding.dleq.bundle.version.to_be_bytes());
        bytes.extend_from_slice(&binding.dleq.bundle.claim.to_canonical_bytes());
        let proof_len = u32::try_from(binding.dleq.bundle.proof.len())
            .map_err(|_| ProductionInputErrorV1::InputBoundExceeded)?;
        bytes.extend_from_slice(&proof_len.to_be_bytes());
        bytes.extend_from_slice(&binding.dleq.bundle.proof);
        bytes.extend_from_slice(&binding.program_id.0);
        bytes.extend_from_slice(&binding.state_pda.0);
        bytes.extend_from_slice(&binding.vault_pda.0);
        bytes.extend_from_slice(&binding.vault_authority.0);
        bytes.push(binding.state_bump);
        bytes.push(binding.vault_bump);
        bytes.push(binding.authority_bump);
        match binding.asset {
            SolanaAssetV1::NativeSol => {
                bytes.push(1);
                bytes.extend_from_slice(&[0; 32]);
                bytes.push(0);
            }
            SolanaAssetV1::LegacySpl { mint, decimals } => {
                bytes.push(2);
                bytes.extend_from_slice(&mint.0);
                bytes.push(decimals);
            }
        }
        bytes.extend_from_slice(&binding.funder.0);
        bytes.extend_from_slice(&binding.recipient.0);
        bytes.extend_from_slice(&binding.refund_recipient.0);
        bytes.extend_from_slice(&binding.amount.to_be_bytes());
        bytes.extend_from_slice(&binding.refund_after_unix.to_be_bytes());
        bytes.extend_from_slice(&binding.program_data_hash);
        bytes.extend_from_slice(&binding.setup_id);
        Ok(())
    }

    fn decode_from(cursor: &mut InputCursorV1<'_>) -> Result<Self, ProductionInputErrorV1> {
        let position = ProductionRoutePositionV1::from_tag(cursor.u8()?)?;
        if cursor.take::<3>()? != [0; 3] {
            return Err(ProductionInputErrorV1::NonCanonicalEncoding);
        }
        let network = SolanaAdapterNetworkV1::from_u8(cursor.u8()?)
            .ok_or(ProductionInputErrorV1::InvalidParticipantBundle)?;
        let program_pubkey = SolanaPubkey(cursor.take::<32>()?);
        let rpc_node_count = cursor.u16()?;
        let rpc_quorum = cursor.u16()?;
        let allow_legacy_spl = decode_bool(cursor.u8()?)?;
        let require_immutable_program = decode_bool(cursor.u8()?)?;
        let max_signed_transaction_bytes = u32::from_be_bytes(cursor.take::<4>()?);
        let profile = SolanaAdapterProfileV1 {
            network,
            program_id: program_pubkey,
            rpc_node_count,
            rpc_quorum,
            allow_legacy_spl,
            require_immutable_program,
            max_signed_transaction_bytes,
        };
        let settlement_id = cursor.take::<32>()?;
        let terms_hash = cursor.take::<32>()?;
        let dleq_version = cursor.u16()?;
        let dleq_settlement_id = cursor.take::<32>()?;
        let dleq_context_hash = cursor.take::<32>()?;
        let dleq_role = cursor.u8()?;
        let bundle_version = cursor.u16()?;
        let claim = CrossCurvePublicClaim::from_canonical_bytes(&cursor.take::<65>()?)
            .ok_or(ProductionInputErrorV1::InvalidParticipantBundle)?;
        let proof_len = usize::try_from(u32::from_be_bytes(cursor.take::<4>()?))
            .map_err(|_| ProductionInputErrorV1::InputBoundExceeded)?;
        if proof_len == 0 || proof_len > xmr_dleq_sigma::MAX_PROOF_BYTES {
            return Err(ProductionInputErrorV1::InvalidParticipantBundle);
        }
        let proof = cursor.bytes(proof_len)?.to_vec();
        let program_id = SolanaPubkey(cursor.take::<32>()?);
        let state_pda = SolanaPubkey(cursor.take::<32>()?);
        let vault_pda = SolanaPubkey(cursor.take::<32>()?);
        let vault_authority = SolanaPubkey(cursor.take::<32>()?);
        let state_bump = cursor.u8()?;
        let vault_bump = cursor.u8()?;
        let authority_bump = cursor.u8()?;
        let asset_tag = cursor.u8()?;
        let mint = SolanaPubkey(cursor.take::<32>()?);
        let decimals = cursor.u8()?;
        let asset = match asset_tag {
            1 => {
                if !mint.is_zero() || decimals != 0 {
                    return Err(ProductionInputErrorV1::NonCanonicalEncoding);
                }
                SolanaAssetV1::NativeSol
            }
            2 => SolanaAssetV1::LegacySpl { mint, decimals },
            _ => return Err(ProductionInputErrorV1::InvalidParticipantBundle),
        };
        let funder = SolanaPubkey(cursor.take::<32>()?);
        let recipient = SolanaPubkey(cursor.take::<32>()?);
        let refund_recipient = SolanaPubkey(cursor.take::<32>()?);
        let amount = u64::from_be_bytes(cursor.take::<8>()?);
        let refund_after_unix = i64::from_be_bytes(cursor.take::<8>()?);
        let program_data_hash = cursor.take::<32>()?;
        let setup_id = cursor.take::<32>()?;
        Self::new(
            position,
            profile,
            SolanaSetupBindingV1 {
                settlement_id,
                terms_hash,
                dleq: BoundCrossCurveProofV1 {
                    version: dleq_version,
                    settlement_id: dleq_settlement_id,
                    context_hash: dleq_context_hash,
                    role: dleq_role,
                    bundle: CrossCurveProofBytes {
                        version: bundle_version,
                        proof,
                        claim,
                    },
                },
                program_id,
                state_pda,
                vault_pda,
                vault_authority,
                state_bump,
                vault_bump,
                authority_bump,
                asset,
                funder,
                recipient,
                refund_recipient,
                amount,
                refund_after_unix,
                program_data_hash,
                setup_id,
            },
        )
    }
}

fn decode_bool(value: u8) -> Result<bool, ProductionInputErrorV1> {
    match value {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(ProductionInputErrorV1::NonCanonicalEncoding),
    }
}

/// The Monero leg's refund arm: the role-2 cross-curve proof binding the
/// refund share to this settlement, plus the non-cooperative executor
/// artifact whose adaptor point that proof certifies. Verified end to end by
/// the refund-arming authority's Monero face, never here.
#[derive(Clone, Eq, PartialEq)]
pub struct ProductionXmrRefundBundleV1 {
    pub(crate) proof: BoundCrossCurveProofV1,
    pub(crate) template_hash: Digest32,
    pub(crate) adaptor_point_sec1: [u8; 33],
    pub(crate) executor_profile_hash: Digest32,
    pub(crate) deadline: u64,
}

impl core::fmt::Debug for ProductionXmrRefundBundleV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("ProductionXmrRefundBundleV1")
            .finish_non_exhaustive()
    }
}

/// One route leg's registered Monero shared-spend setup: the adapter profile
/// the frozen terms committed to and the DLEQ-bound setup binding. As with
/// Solana, there is no participant signature — the anchor is the cross-curve
/// DLEQ verified by `xmr_setup_profile::validate_setup` under the ratified
/// `CrossCurveSharedSpend` mechanism (no admission token).
#[derive(Clone, Eq, PartialEq)]
pub struct ProductionXmrLegSetupV1 {
    pub(crate) position: ProductionRoutePositionV1,
    pub(crate) profile: XmrAdapterProfileV1,
    pub(crate) binding: XmrSetupBindingV1,
    pub(crate) refund: Option<ProductionXmrRefundBundleV1>,
}

impl core::fmt::Debug for ProductionXmrLegSetupV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("ProductionXmrLegSetupV1")
            .field("position", &self.position)
            .finish_non_exhaustive()
    }
}

impl ProductionXmrLegSetupV1 {
    /// Builds one Monero leg setup after structural zero/bounds checks. Full
    /// cryptographic authentication happens only inside bundle verification.
    pub fn new(
        position: ProductionRoutePositionV1,
        profile: XmrAdapterProfileV1,
        binding: XmrSetupBindingV1,
    ) -> Result<Self, ProductionInputErrorV1> {
        if profile.rpc_node_count == 0
            || profile.rpc_quorum == 0
            || profile.rpc_quorum > profile.rpc_node_count
            || binding.settlement_id == ZERO_DIGEST
            || binding.terms_hash == ZERO_DIGEST
            || binding.funding_tx_hash == ZERO_DIGEST
            || binding.combined_spend_public_key == ZERO_DIGEST
            || binding.destination.is_empty()
            || binding.destination.len() > xmr_live_sidecar_api::MAX_DESTINATION_BYTES
            || !binding.destination.is_ascii()
            || binding.dleq.bundle.proof.is_empty()
            || binding.dleq.bundle.proof.len() > xmr_dleq_sigma::MAX_PROOF_BYTES
        {
            return Err(ProductionInputErrorV1::InvalidParticipantBundle);
        }
        Ok(Self {
            position,
            profile,
            binding,
            refund: None,
        })
    }

    /// Attaches the refund arm after structural bounds checks.
    pub fn with_refund(
        mut self,
        refund: ProductionXmrRefundBundleV1,
    ) -> Result<Self, ProductionInputErrorV1> {
        if refund.template_hash == ZERO_DIGEST
            || refund.executor_profile_hash == ZERO_DIGEST
            || refund.deadline == 0
            || refund.proof.bundle.proof.is_empty()
            || refund.proof.bundle.proof.len() > xmr_dleq_sigma::MAX_PROOF_BYTES
            || !matches!(refund.adaptor_point_sec1[0], 0x02 | 0x03)
        {
            return Err(ProductionInputErrorV1::InvalidParticipantBundle);
        }
        self.refund = Some(refund);
        Ok(self)
    }

    fn encode_into(&self, bytes: &mut Vec<u8>) -> Result<(), ProductionInputErrorV1> {
        bytes.push(self.position.tag());
        bytes.extend_from_slice(&[0; 3]);
        bytes.push(self.profile.network as u8);
        bytes.extend_from_slice(&self.profile.sidecar_api_version.to_be_bytes());
        bytes.extend_from_slice(&self.profile.rpc_node_count.to_be_bytes());
        bytes.extend_from_slice(&self.profile.rpc_quorum.to_be_bytes());
        bytes.extend_from_slice(&self.profile.max_raw_tx_bytes.to_be_bytes());
        let binding = &self.binding;
        bytes.extend_from_slice(&binding.settlement_id);
        bytes.extend_from_slice(&binding.terms_hash);
        bytes.extend_from_slice(&binding.dleq.version.to_be_bytes());
        bytes.extend_from_slice(&binding.dleq.settlement_id);
        bytes.extend_from_slice(&binding.dleq.context_hash);
        bytes.push(binding.dleq.role);
        bytes.extend_from_slice(&binding.dleq.bundle.version.to_be_bytes());
        bytes.extend_from_slice(&binding.dleq.bundle.claim.to_canonical_bytes());
        let proof_len = u32::try_from(binding.dleq.bundle.proof.len())
            .map_err(|_| ProductionInputErrorV1::InputBoundExceeded)?;
        bytes.extend_from_slice(&proof_len.to_be_bytes());
        bytes.extend_from_slice(&binding.dleq.bundle.proof);
        bytes.extend_from_slice(&binding.funding_tx_hash);
        bytes.extend_from_slice(&binding.expected_amount_piconero.to_be_bytes());
        let destination_len = u16::try_from(binding.destination.len())
            .map_err(|_| ProductionInputErrorV1::InputBoundExceeded)?;
        bytes.extend_from_slice(&destination_len.to_be_bytes());
        bytes.extend_from_slice(binding.destination.as_bytes());
        bytes.extend_from_slice(&binding.combined_spend_public_key);
        match &self.refund {
            None => bytes.push(0),
            Some(refund) => {
                bytes.push(1);
                bytes.extend_from_slice(&refund.proof.version.to_be_bytes());
                bytes.extend_from_slice(&refund.proof.settlement_id);
                bytes.extend_from_slice(&refund.proof.context_hash);
                bytes.push(refund.proof.role);
                bytes.extend_from_slice(&refund.proof.bundle.version.to_be_bytes());
                bytes.extend_from_slice(&refund.proof.bundle.claim.to_canonical_bytes());
                let proof_len = u32::try_from(refund.proof.bundle.proof.len())
                    .map_err(|_| ProductionInputErrorV1::InputBoundExceeded)?;
                bytes.extend_from_slice(&proof_len.to_be_bytes());
                bytes.extend_from_slice(&refund.proof.bundle.proof);
                bytes.extend_from_slice(&refund.template_hash);
                bytes.extend_from_slice(&refund.adaptor_point_sec1);
                bytes.extend_from_slice(&refund.executor_profile_hash);
                bytes.extend_from_slice(&refund.deadline.to_be_bytes());
            }
        }
        Ok(())
    }

    fn decode_from(cursor: &mut InputCursorV1<'_>) -> Result<Self, ProductionInputErrorV1> {
        let position = ProductionRoutePositionV1::from_tag(cursor.u8()?)?;
        if cursor.take::<3>()? != [0; 3] {
            return Err(ProductionInputErrorV1::NonCanonicalEncoding);
        }
        let network = match cursor.u8()? {
            1 => XmrNetwork::Mainnet,
            2 => XmrNetwork::Stagenet,
            3 => XmrNetwork::Testnet,
            _ => return Err(ProductionInputErrorV1::InvalidParticipantBundle),
        };
        let sidecar_api_version = cursor.u16()?;
        let rpc_node_count = cursor.u16()?;
        let rpc_quorum = cursor.u16()?;
        let max_raw_tx_bytes = u32::from_be_bytes(cursor.take::<4>()?);
        let profile = XmrAdapterProfileV1 {
            network,
            sidecar_api_version,
            rpc_node_count,
            rpc_quorum,
            max_raw_tx_bytes,
        };
        let settlement_id = cursor.take::<32>()?;
        let terms_hash = cursor.take::<32>()?;
        let dleq_version = cursor.u16()?;
        let dleq_settlement_id = cursor.take::<32>()?;
        let dleq_context_hash = cursor.take::<32>()?;
        let dleq_role = cursor.u8()?;
        let bundle_version = cursor.u16()?;
        let claim = CrossCurvePublicClaim::from_canonical_bytes(&cursor.take::<65>()?)
            .ok_or(ProductionInputErrorV1::InvalidParticipantBundle)?;
        let proof_len = usize::try_from(u32::from_be_bytes(cursor.take::<4>()?))
            .map_err(|_| ProductionInputErrorV1::InputBoundExceeded)?;
        if proof_len == 0 || proof_len > xmr_dleq_sigma::MAX_PROOF_BYTES {
            return Err(ProductionInputErrorV1::InvalidParticipantBundle);
        }
        let proof = cursor.bytes(proof_len)?.to_vec();
        let funding_tx_hash = cursor.take::<32>()?;
        let expected_amount_piconero = u64::from_be_bytes(cursor.take::<8>()?);
        let destination_len = usize::from(cursor.u16()?);
        if destination_len == 0 || destination_len > xmr_live_sidecar_api::MAX_DESTINATION_BYTES {
            return Err(ProductionInputErrorV1::InvalidParticipantBundle);
        }
        let destination = String::from_utf8(cursor.bytes(destination_len)?.to_vec())
            .map_err(|_| ProductionInputErrorV1::NonCanonicalEncoding)?;
        let combined_spend_public_key = cursor.take::<32>()?;
        let refund = match cursor.u8()? {
            0 => None,
            1 => {
                let version = cursor.u16()?;
                let settlement_id = cursor.take::<32>()?;
                let context_hash = cursor.take::<32>()?;
                let role = cursor.u8()?;
                let bundle_version = cursor.u16()?;
                let claim = CrossCurvePublicClaim::from_canonical_bytes(&cursor.take::<65>()?)
                    .ok_or(ProductionInputErrorV1::InvalidParticipantBundle)?;
                let proof_len = usize::try_from(u32::from_be_bytes(cursor.take::<4>()?))
                    .map_err(|_| ProductionInputErrorV1::InputBoundExceeded)?;
                if proof_len == 0 || proof_len > xmr_dleq_sigma::MAX_PROOF_BYTES {
                    return Err(ProductionInputErrorV1::InvalidParticipantBundle);
                }
                let proof = cursor.bytes(proof_len)?.to_vec();
                let template_hash = cursor.take::<32>()?;
                let adaptor_point_sec1 = cursor.take::<33>()?;
                let executor_profile_hash = cursor.take::<32>()?;
                let deadline = u64::from_be_bytes(cursor.take::<8>()?);
                Some(ProductionXmrRefundBundleV1 {
                    proof: BoundCrossCurveProofV1 {
                        version,
                        settlement_id,
                        context_hash,
                        role,
                        bundle: CrossCurveProofBytes {
                            version: bundle_version,
                            proof,
                            claim,
                        },
                    },
                    template_hash,
                    adaptor_point_sec1,
                    executor_profile_hash,
                    deadline,
                })
            }
            _ => return Err(ProductionInputErrorV1::NonCanonicalEncoding),
        };
        let value = Self::new(
            position,
            profile,
            XmrSetupBindingV1 {
                settlement_id,
                terms_hash,
                dleq: BoundCrossCurveProofV1 {
                    version: dleq_version,
                    settlement_id: dleq_settlement_id,
                    context_hash: dleq_context_hash,
                    role: dleq_role,
                    bundle: CrossCurveProofBytes {
                        version: bundle_version,
                        proof,
                        claim,
                    },
                },
                funding_tx_hash,
                expected_amount_piconero,
                destination,
                combined_spend_public_key,
            },
        )?;
        match refund {
            None => Ok(value),
            Some(refund) => value.with_refund(refund),
        }
    }
}

/// Canonical set of participant proofs for exactly the applicable route legs.
#[derive(Clone, Eq, PartialEq)]
pub struct ProductionParticipantBindingBundleV1 {
    route_id: RouteIdV1,
    legs: Vec<ProductionEvmLegProofsV1>,
    bitcoin_legs: Vec<ProductionBitcoinLegKeyProofsV1>,
    solana_legs: Vec<ProductionSolanaLegSetupV1>,
    monero_legs: Vec<ProductionXmrLegSetupV1>,
}

impl core::fmt::Debug for ProductionParticipantBindingBundleV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("ProductionParticipantBindingBundleV1")
            .field("evm_proof_leg_count", &self.legs.len())
            .field("bitcoin_proof_leg_count", &self.bitcoin_legs.len())
            .field("solana_setup_leg_count", &self.solana_legs.len())
            .field("monero_setup_leg_count", &self.monero_legs.len())
            .finish_non_exhaustive()
    }
}

impl ProductionParticipantBindingBundleV1 {
    /// Builds an ordered zero-to-two-leg proof bundle.
    pub fn new(
        route_id: RouteIdV1,
        legs: Vec<ProductionEvmLegProofsV1>,
    ) -> Result<Self, ProductionInputErrorV1> {
        Self::new_with_bitcoin_bindings(route_id, legs, Vec::new())
    }

    /// Builds ordered EVM and Bitcoin proof sets for their applicable legs.
    pub fn new_with_bitcoin_bindings(
        route_id: RouteIdV1,
        legs: Vec<ProductionEvmLegProofsV1>,
        bitcoin_legs: Vec<ProductionBitcoinLegKeyProofsV1>,
    ) -> Result<Self, ProductionInputErrorV1> {
        Self::new_with_counterparty_bindings(route_id, legs, bitcoin_legs, Vec::new())
    }

    /// Builds ordered EVM, Bitcoin and Solana proof sets for their legs.
    pub fn new_with_counterparty_bindings(
        route_id: RouteIdV1,
        legs: Vec<ProductionEvmLegProofsV1>,
        bitcoin_legs: Vec<ProductionBitcoinLegKeyProofsV1>,
        solana_legs: Vec<ProductionSolanaLegSetupV1>,
    ) -> Result<Self, ProductionInputErrorV1> {
        Self::new_with_all_counterparty_bindings(
            route_id,
            legs,
            bitcoin_legs,
            solana_legs,
            Vec::new(),
        )
    }

    /// Builds ordered EVM, Bitcoin, Solana and Monero sets for their legs.
    pub fn new_with_all_counterparty_bindings(
        route_id: RouteIdV1,
        legs: Vec<ProductionEvmLegProofsV1>,
        bitcoin_legs: Vec<ProductionBitcoinLegKeyProofsV1>,
        solana_legs: Vec<ProductionSolanaLegSetupV1>,
        monero_legs: Vec<ProductionXmrLegSetupV1>,
    ) -> Result<Self, ProductionInputErrorV1> {
        if route_id == ZERO_DIGEST
            || legs.len() > 2
            || bitcoin_legs.len() > 2
            || solana_legs.len() > 2
            || monero_legs.len() > 2
            || legs
                .windows(2)
                .any(|pair| pair[0].position >= pair[1].position)
            || bitcoin_legs
                .windows(2)
                .any(|pair| pair[0].position >= pair[1].position)
            || solana_legs
                .windows(2)
                .any(|pair| pair[0].position >= pair[1].position)
            || monero_legs
                .windows(2)
                .any(|pair| pair[0].position >= pair[1].position)
            || legs.iter().any(|leg| {
                leg.funder.statement().route_id != route_id
                    || leg.beneficiary.statement().route_id != route_id
            })
        {
            return Err(ProductionInputErrorV1::InvalidParticipantBundle);
        }
        Ok(Self {
            route_id,
            legs,
            bitcoin_legs,
            solana_legs,
            monero_legs,
        })
    }

    /// Route identity signed by every included proof.
    pub const fn route_id(&self) -> RouteIdV1 {
        self.route_id
    }

    /// Canonical EVM-applicable legs.
    pub fn legs(&self) -> &[ProductionEvmLegProofsV1] {
        &self.legs
    }

    /// Canonical Bitcoin-applicable legs and their two signed key bindings.
    pub fn bitcoin_legs(&self) -> &[ProductionBitcoinLegKeyProofsV1] {
        &self.bitcoin_legs
    }

    /// Canonical Solana-applicable legs and their DLEQ-bound setups.
    pub fn solana_legs(&self) -> &[ProductionSolanaLegSetupV1] {
        &self.solana_legs
    }

    /// Canonical Monero-applicable legs and their DLEQ-bound setups.
    pub fn monero_legs(&self) -> &[ProductionXmrLegSetupV1] {
        &self.monero_legs
    }

    /// Bounded reject-trailing representation.
    ///
    /// The reserved field after the version doubles as the layout marker: a
    /// bundle without Solana legs writes `0` and stays byte-identical to the
    /// pre-Solana encoding; a bundle with Solana legs writes `1` and appends
    /// the Solana section after the Bitcoin one.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, ProductionInputErrorV1> {
        Self::new_with_all_counterparty_bindings(
            self.route_id,
            self.legs.clone(),
            self.bitcoin_legs.clone(),
            self.solana_legs.clone(),
            self.monero_legs.clone(),
        )?;
        let mut layout: u16 = 0;
        if !self.solana_legs.is_empty() {
            layout |= 1;
        }
        if !self.monero_legs.is_empty() {
            layout |= 2;
        }
        let mut bytes = Vec::with_capacity(MAX_PRODUCTION_PARTICIPANT_BUNDLE_BYTES_V1);
        bytes.extend_from_slice(PARTICIPANT_BUNDLE_MAGIC_V1);
        bytes.extend_from_slice(&INPUT_VERSION_V1.to_be_bytes());
        bytes.extend_from_slice(&layout.to_be_bytes());
        bytes.extend_from_slice(&self.route_id);
        bytes.push(
            u8::try_from(self.legs.len())
                .map_err(|_| ProductionInputErrorV1::InputBoundExceeded)?,
        );
        bytes.extend_from_slice(&[0; 3]);
        for leg in &self.legs {
            bytes.push(leg.position.tag());
            bytes.extend_from_slice(&[0; 3]);
            bytes.extend_from_slice(
                &leg.funder
                    .canonical_bytes()
                    .map_err(|_| ProductionInputErrorV1::InvalidParticipantBundle)?,
            );
            bytes.extend_from_slice(
                &leg.beneficiary
                    .canonical_bytes()
                    .map_err(|_| ProductionInputErrorV1::InvalidParticipantBundle)?,
            );
        }
        bytes.push(
            u8::try_from(self.bitcoin_legs.len())
                .map_err(|_| ProductionInputErrorV1::InputBoundExceeded)?,
        );
        bytes.extend_from_slice(&[0; 3]);
        for leg in &self.bitcoin_legs {
            bytes.push(leg.position.tag());
            bytes.extend_from_slice(&[0; 3]);
            for participant in leg.participants {
                bytes.extend_from_slice(&participant.participant_id.0);
                bytes.push(participant.role as u8);
                bytes.extend_from_slice(&participant.compressed_key);
                bytes.extend_from_slice(&participant.signature);
            }
        }
        if layout & 1 != 0 {
            bytes.push(
                u8::try_from(self.solana_legs.len())
                    .map_err(|_| ProductionInputErrorV1::InputBoundExceeded)?,
            );
            bytes.extend_from_slice(&[0; 3]);
            for leg in &self.solana_legs {
                leg.encode_into(&mut bytes)?;
            }
        }
        if layout & 2 != 0 {
            bytes.push(
                u8::try_from(self.monero_legs.len())
                    .map_err(|_| ProductionInputErrorV1::InputBoundExceeded)?,
            );
            bytes.extend_from_slice(&[0; 3]);
            for leg in &self.monero_legs {
                leg.encode_into(&mut bytes)?;
            }
        }
        let bound = if layout == 0 {
            MAX_PRODUCTION_PARTICIPANT_BUNDLE_BYTES_V1
        } else {
            MAX_PRODUCTION_PARTICIPANT_BUNDLE_EXTENDED_BYTES_V1
        };
        if bytes.len() > bound {
            return Err(ProductionInputErrorV1::InputBoundExceeded);
        }
        Ok(bytes)
    }

    /// Strictly decodes a participant proof bundle.
    pub fn decode_canonical(bytes: &[u8]) -> Result<Self, ProductionInputErrorV1> {
        if bytes.len() > MAX_PRODUCTION_PARTICIPANT_BUNDLE_EXTENDED_BYTES_V1 {
            return Err(ProductionInputErrorV1::InputBoundExceeded);
        }
        let mut cursor = InputCursorV1::new(bytes);
        if cursor.take::<8>()? != *PARTICIPANT_BUNDLE_MAGIC_V1 || cursor.u16()? != INPUT_VERSION_V1
        {
            return Err(ProductionInputErrorV1::NonCanonicalEncoding);
        }
        let layout = cursor.u16()?;
        if layout > 3 {
            return Err(ProductionInputErrorV1::NonCanonicalEncoding);
        }
        if layout == 0 && bytes.len() > MAX_PRODUCTION_PARTICIPANT_BUNDLE_BYTES_V1 {
            return Err(ProductionInputErrorV1::InputBoundExceeded);
        }
        let route_id = cursor.take::<32>()?;
        let count = usize::from(cursor.u8()?);
        if count > 2 || cursor.take::<3>()? != [0; 3] {
            return Err(ProductionInputErrorV1::NonCanonicalEncoding);
        }
        let mut legs = Vec::with_capacity(count);
        for _ in 0..count {
            let position = ProductionRoutePositionV1::from_tag(cursor.u8()?)?;
            if cursor.take::<3>()? != [0; 3] {
                return Err(ProductionInputErrorV1::NonCanonicalEncoding);
            }
            let funder = EvmAccountBindingProofV1::decode_canonical(
                cursor.bytes(EVM_ACCOUNT_BINDING_PROOF_BYTES_V1)?,
            )
            .map_err(|_| ProductionInputErrorV1::InvalidParticipantBundle)?;
            let beneficiary = EvmAccountBindingProofV1::decode_canonical(
                cursor.bytes(EVM_ACCOUNT_BINDING_PROOF_BYTES_V1)?,
            )
            .map_err(|_| ProductionInputErrorV1::InvalidParticipantBundle)?;
            legs.push(ProductionEvmLegProofsV1::new(
                position,
                funder,
                beneficiary,
            )?);
        }
        let bitcoin_count = usize::from(cursor.u8()?);
        if bitcoin_count > 2 || cursor.take::<3>()? != [0; 3] {
            return Err(ProductionInputErrorV1::NonCanonicalEncoding);
        }
        let mut bitcoin_legs = Vec::with_capacity(bitcoin_count);
        for _ in 0..bitcoin_count {
            let position = ProductionRoutePositionV1::from_tag(cursor.u8()?)?;
            if cursor.take::<3>()? != [0; 3] {
                return Err(ProductionInputErrorV1::NonCanonicalEncoding);
            }
            let mut participants = Vec::with_capacity(2);
            for _ in 0..2 {
                participants.push(ProductionBitcoinParticipantKeyProofV1::new(
                    ParticipantId(cursor.take::<32>()?),
                    BitcoinSignerRoleV1::from_u8(cursor.u8()?)
                        .map_err(|_| ProductionInputErrorV1::InvalidParticipantBundle)?,
                    cursor.take::<33>()?,
                    cursor.take::<64>()?,
                )?);
            }
            bitcoin_legs.push(ProductionBitcoinLegKeyProofsV1::new(
                position,
                participants
                    .try_into()
                    .map_err(|_| ProductionInputErrorV1::NonCanonicalEncoding)?,
            )?);
        }
        let mut solana_legs = Vec::new();
        if layout & 1 != 0 {
            let solana_count = usize::from(cursor.u8()?);
            if solana_count == 0 || solana_count > 2 || cursor.take::<3>()? != [0; 3] {
                return Err(ProductionInputErrorV1::NonCanonicalEncoding);
            }
            for _ in 0..solana_count {
                solana_legs.push(ProductionSolanaLegSetupV1::decode_from(&mut cursor)?);
            }
        }
        let mut monero_legs = Vec::new();
        if layout & 2 != 0 {
            let monero_count = usize::from(cursor.u8()?);
            if monero_count == 0 || monero_count > 2 || cursor.take::<3>()? != [0; 3] {
                return Err(ProductionInputErrorV1::NonCanonicalEncoding);
            }
            for _ in 0..monero_count {
                monero_legs.push(ProductionXmrLegSetupV1::decode_from(&mut cursor)?);
            }
        }
        cursor.finish()?;
        let value = Self::new_with_all_counterparty_bindings(
            route_id,
            legs,
            bitcoin_legs,
            solana_legs,
            monero_legs,
        )?;
        if value.canonical_bytes()?.as_slice() != bytes {
            return Err(ProductionInputErrorV1::NonCanonicalEncoding);
        }
        Ok(value)
    }

    /// Domain-separated digest pinned in the bootstrap configuration.
    pub fn bundle_digest(&self) -> Result<Digest32, ProductionInputErrorV1> {
        digest_bytes(
            PARTICIPANT_BUNDLE_DIGEST_DOMAIN_V1,
            &self.canonical_bytes()?,
        )
    }
}

/// Fully verified Bitcoin participant-key roster for one admitted route leg.
///
/// Construction is private to the production input verifier.  The value
/// contains public keys only, but deliberately has no `Clone` or generic
/// constructor so callers cannot detach a roster from its authenticated
/// route/session/terms/deployment context.
pub struct AuthenticatedBitcoinParticipantBindingsV1 {
    position: ProductionRoutePositionV1,
    network_id: Digest32,
    route_id: RouteIdV1,
    session_id: Digest32,
    terms_digest: Digest32,
    roster_snapshot: Digest32,
    deployment: ResolvedBitcoinDeploymentV1,
    roster: ParticipantKeyRosterV1,
}

impl core::fmt::Debug for AuthenticatedBitcoinParticipantBindingsV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("AuthenticatedBitcoinParticipantBindingsV1")
            .field("position", &self.position)
            .finish_non_exhaustive()
    }
}

impl AuthenticatedBitcoinParticipantBindingsV1 {
    /// Upstream or downstream route position.
    pub const fn position(&self) -> ProductionRoutePositionV1 {
        self.position
    }

    /// Authenticated interoperability network.
    pub const fn network_id(&self) -> Digest32 {
        self.network_id
    }

    /// Exact composed route identity.
    pub const fn route_id(&self) -> RouteIdV1 {
        self.route_id
    }

    /// Exact settlement session identity.
    pub const fn session_id(&self) -> Digest32 {
        self.session_id
    }

    /// Canonical settlement-terms digest signed by both participant keys.
    pub const fn terms_digest(&self) -> Digest32 {
        self.terms_digest
    }

    /// Frozen Relay roster snapshot that authenticated the proofs.
    pub const fn roster_snapshot(&self) -> Digest32 {
        self.roster_snapshot
    }

    /// Threshold-authenticated Bitcoin deployment selected for this leg.
    pub const fn deployment(&self) -> &ResolvedBitcoinDeploymentV1 {
        &self.deployment
    }

    /// Ordered maker/taker Bitcoin key roster.
    pub const fn roster(&self) -> &ParticipantKeyRosterV1 {
        &self.roster
    }
}

/// Fully verified Solana escrow session for one admitted route leg.
///
/// Construction is private to the production input verifier. The anchor is
/// the registered setup's cross-curve DLEQ, verified against the frozen
/// settlement terms via `solana_profile::validate_setup`, plus the registry's
/// pinned escrow program identity. No `Clone` and no generic constructor, so
/// a validated setup cannot be detached from its authenticated route context.
pub struct AuthenticatedSolanaSessionBindingsV1 {
    position: ProductionRoutePositionV1,
    network_id: Digest32,
    route_id: RouteIdV1,
    session_id: Digest32,
    terms_digest: Digest32,
    deployment: ResolvedSolanaDeploymentV1,
    profile: SolanaAdapterProfileV1,
    setup: ValidatedSolanaSetup,
}

impl core::fmt::Debug for AuthenticatedSolanaSessionBindingsV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("AuthenticatedSolanaSessionBindingsV1")
            .field("position", &self.position)
            .finish_non_exhaustive()
    }
}

impl AuthenticatedSolanaSessionBindingsV1 {
    /// Upstream or downstream route position.
    pub const fn position(&self) -> ProductionRoutePositionV1 {
        self.position
    }

    /// Authenticated interoperability network.
    pub const fn network_id(&self) -> Digest32 {
        self.network_id
    }

    /// Exact composed route identity.
    pub const fn route_id(&self) -> RouteIdV1 {
        self.route_id
    }

    /// Exact settlement session identity.
    pub const fn session_id(&self) -> Digest32 {
        self.session_id
    }

    /// Canonical settlement-terms digest the DLEQ-bound setup commits to.
    pub const fn terms_digest(&self) -> Digest32 {
        self.terms_digest
    }

    /// Threshold-authenticated Solana deployment selected for this leg.
    pub const fn deployment(&self) -> &ResolvedSolanaDeploymentV1 {
        &self.deployment
    }

    /// Adapter profile the frozen terms committed to by hash.
    pub const fn profile(&self) -> &SolanaAdapterProfileV1 {
        &self.profile
    }

    /// DLEQ-verified, PDA-verified escrow setup.
    pub const fn setup(&self) -> &ValidatedSolanaSetup {
        &self.setup
    }
}

/// Fully verified Monero shared-spend session for one admitted route leg.
///
/// Construction is private to the production input verifier. The anchor is
/// the registered setup's cross-curve DLEQ under the ratified
/// `CrossCurveSharedSpend` mechanism, verified against the frozen terms via
/// `xmr_setup_profile::validate_setup`. No `Clone` and no generic
/// constructor.
pub struct AuthenticatedXmrSessionBindingsV1 {
    position: ProductionRoutePositionV1,
    network_id: Digest32,
    route_id: RouteIdV1,
    session_id: Digest32,
    terms_digest: Digest32,
    deployment: ResolvedMoneroDeploymentV1,
    profile: XmrAdapterProfileV1,
    setup: ValidatedXmrSetup,
    refund: Option<ProductionXmrRefundBundleV1>,
}

impl core::fmt::Debug for AuthenticatedXmrSessionBindingsV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("AuthenticatedXmrSessionBindingsV1")
            .field("position", &self.position)
            .finish_non_exhaustive()
    }
}

impl AuthenticatedXmrSessionBindingsV1 {
    /// Upstream or downstream route position.
    pub const fn position(&self) -> ProductionRoutePositionV1 {
        self.position
    }

    /// Authenticated interoperability network.
    pub const fn network_id(&self) -> Digest32 {
        self.network_id
    }

    /// Exact composed route identity.
    pub const fn route_id(&self) -> RouteIdV1 {
        self.route_id
    }

    /// Exact settlement session identity.
    pub const fn session_id(&self) -> Digest32 {
        self.session_id
    }

    /// Canonical settlement-terms digest the DLEQ-bound setup commits to.
    pub const fn terms_digest(&self) -> Digest32 {
        self.terms_digest
    }

    /// Threshold-authenticated Monero deployment selected for this leg.
    pub const fn deployment(&self) -> &ResolvedMoneroDeploymentV1 {
        &self.deployment
    }

    /// Adapter profile the frozen terms committed to by hash.
    pub const fn profile(&self) -> &XmrAdapterProfileV1 {
        &self.profile
    }

    /// DLEQ-verified shared-spend setup.
    pub const fn setup(&self) -> &ValidatedXmrSetup {
        &self.setup
    }

    /// The leg's refund arm, when the bundle registered one. Structural
    /// bounds are checked at decode; the role-2 proof itself is verified by
    /// the refund-arming authority's Monero face, which owns that meaning.
    pub const fn refund_bundle(&self) -> Option<&ProductionXmrRefundBundleV1> {
        self.refund.as_ref()
    }
}

/// Fully authenticated public input handoff for one route.
///
/// This type intentionally implements neither `Clone` nor `Debug`. Its fields
/// are crate-visible so the eventual production runner can move the concrete
/// authorities without exposing a public plugin or raw-constructor surface.
///
/// ```compile_fail
/// fn require_clone<T: Clone>() {}
/// require_clone::<dom_interopd::AuthenticatedProductionInputsV1>();
/// ```
///
/// ```compile_fail
/// fn require_debug<T: core::fmt::Debug>() {}
/// require_debug::<dom_interopd::AuthenticatedProductionInputsV1>();
/// ```
pub struct AuthenticatedProductionInputsV1 {
    pub(crate) admission: AuthenticatedRouteAdmissionV1,
    pub(crate) admission_authority: RegistryRouteAdmissionAuthorityV1,
    pub(crate) composition: ComposedBindingV2,
    pub(crate) resolved_registry: ResolvedRegistryV1,
    pub(crate) route_store: DurableRouteStoreV1,
    pub(crate) time_store: DurableRouteTimeAnchorStoreV2,
    pub(crate) time_policy_authorities: AuthoritySetV1,
    pub(crate) time_evidence_authorities: AuthoritySetV1,
    pub(crate) time_verification_context: SecpContext,
    pub(crate) signed_time_policy: SignedRouteTimePolicyV2,
    pub(crate) signed_time_evidence: SignedRouteTimeEvidenceV2,
    pub(crate) roster_registry: RosterRegistryV1,
    pub(crate) roster_bundle: ProductionRelayRosterBundleV1,
    pub(crate) evm_sessions: [Option<AuthenticatedEvmSessionBindingsV1>; 2],
    pub(crate) bitcoin_sessions: [Option<AuthenticatedBitcoinParticipantBindingsV1>; 2],
    pub(crate) solana_sessions: [Option<AuthenticatedSolanaSessionBindingsV1>; 2],
    pub(crate) monero_sessions: [Option<AuthenticatedXmrSessionBindingsV1>; 2],
    pub(crate) current_time_ancestry_ready: bool,
}

impl AuthenticatedProductionInputsV1 {
    /// Route-scoped admission produced only after all public proofs passed.
    pub const fn admission(&self) -> &AuthenticatedRouteAdmissionV1 {
        &self.admission
    }

    /// Exact threshold-authenticated mixed-clock composition.
    pub const fn composition(&self) -> &ComposedBindingV2 {
        &self.composition
    }

    /// Verified EVM account session for an applicable leg.
    pub fn evm_session(&self, leg: LegIdV1) -> Option<&AuthenticatedEvmSessionBindingsV1> {
        self.evm_sessions[leg_index(leg)].as_ref()
    }

    /// Verified Bitcoin participant-key session for an applicable route leg.
    pub fn bitcoin_session(
        &self,
        leg: LegIdV1,
    ) -> Option<&AuthenticatedBitcoinParticipantBindingsV1> {
        self.bitcoin_sessions[leg_index(leg)].as_ref()
    }

    /// Verified DLEQ-anchored Solana escrow session for an applicable leg.
    pub fn solana_session(&self, leg: LegIdV1) -> Option<&AuthenticatedSolanaSessionBindingsV1> {
        self.solana_sessions[leg_index(leg)].as_ref()
    }

    /// Verified DLEQ-anchored Monero shared-spend session for an applicable
    /// route leg.
    pub fn monero_session(&self, leg: LegIdV1) -> Option<&AuthenticatedXmrSessionBindingsV1> {
        self.monero_sessions[leg_index(leg)].as_ref()
    }

    /// Public Relay roster registry reconstructed from the pinned artifact.
    pub const fn roster_registry(&self) -> &RosterRegistryV1 {
        &self.roster_registry
    }

    /// Registry-backed admission authority retained for route recovery.
    pub const fn admission_authority(&self) -> &RegistryRouteAdmissionAuthorityV1 {
        &self.admission_authority
    }

    /// Threshold-authenticated registry snapshot used to build the route.
    pub const fn resolved_registry(&self) -> &ResolvedRegistryV1 {
        &self.resolved_registry
    }

    /// Whether bootstrap independently proved current temporal ancestry.
    ///
    /// This is diagnostic only and is never an economic authorization. A new
    /// funding action must still consume a fresh one-shot time-guard token.
    pub const fn current_time_ancestry_ready(&self) -> bool {
        self.current_time_ancestry_ready
    }

    /// Replays the route journal and returns its exact V2 admission checkpoint.
    pub fn audited_route_checkpoint(
        &self,
    ) -> Result<FrozenRouteAdmissionCheckpointV2, ProductionInputErrorV1> {
        self.route_store
            .audit_frozen_admission_checkpoint_v2(self.admission.route_id())
            .map_err(|_| ProductionInputErrorV1::RouteStateRefused)
    }

    /// Durable route-scoped time authority for later economic guards.
    pub fn time_store_mut(&mut self) -> &mut DurableRouteTimeAnchorStoreV2 {
        &mut self.time_store
    }

    /// Static time-policy threshold set pinned by the time store.
    pub const fn time_policy_authorities(&self) -> &AuthoritySetV1 {
        &self.time_policy_authorities
    }

    /// Live time-evidence threshold set pinned by the time store.
    pub const fn time_evidence_authorities(&self) -> &AuthoritySetV1 {
        &self.time_evidence_authorities
    }

    /// Verification-only secp256k1 context retained for time revalidation.
    pub const fn time_verification_context(&self) -> &SecpContext {
        &self.time_verification_context
    }

    /// Exact signed policy installed into the durable time authority.
    pub const fn signed_time_policy(&self) -> &SignedRouteTimePolicyV2 {
        &self.signed_time_policy
    }

    /// Exact signed evidence installed into the durable time authority.
    pub const fn signed_time_evidence(&self) -> &SignedRouteTimeEvidenceV2 {
        &self.signed_time_evidence
    }

    /// Canonical public route roster artifact used to build the Relay registry.
    pub const fn roster_bundle(&self) -> &ProductionRelayRosterBundleV1 {
        &self.roster_bundle
    }
}

/// Redacted, fail-closed production input refusal.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ProductionInputErrorV1 {
    /// An immutable input could not be opened or read.
    #[error("production public input unavailable")]
    InputUnavailable,
    /// A pre-allocation bound was exceeded.
    #[error("production public input exceeds its bound")]
    InputBoundExceeded,
    /// A canonical file was truncated, alternate or had trailing bytes.
    #[error("non-canonical production public input")]
    NonCanonicalEncoding,
    /// The three threshold roles reused the same authority set.
    #[error("invalid production authority bundle")]
    InvalidAuthorityBundle,
    /// Public roster facts were incomplete or did not match route terms.
    #[error("invalid production Relay roster bundle")]
    InvalidRosterBundle,
    /// Participant proof shape, scope or signatures were invalid.
    #[error("invalid production participant binding bundle")]
    InvalidParticipantBundle,
    /// A recomputed public commitment differed from bootstrap.
    #[error("production public input pin mismatch")]
    PinMismatch,
    /// The existing threshold-authenticated registry refused validation.
    #[error("production deployment registry refused input")]
    RegistryRefused,
    /// Canonical settlement terms refused validation.
    #[error("production settlement terms refused input")]
    TermsRefused,
    /// The durable route-time authority refused policy, evidence or capability.
    #[error("production route-time authority refused input")]
    TimeRefused,
    /// The V2 composer refused the authenticated inputs.
    #[error("production route composition refused input")]
    CompositionRefused,
    /// Registry-backed route admission refused the composition or recovery.
    #[error("production route admission refused input")]
    AdmissionRefused,
    /// The durable route journal, checkpoint or snapshot refused bootstrap.
    #[error("production route state refused input")]
    RouteStateRefused,
    /// The ordered create journal refused a transition or disagreed with the
    /// physical authority prefix.
    #[error("production provisioning journal refused input")]
    ProvisioningRefused,
}

/// Opens and authenticates every public route input using an explicit trusted
/// UNIX second supplied by the process composition root.
///
/// Registry state is never created. Create mode creates new route-time and
/// route stores and journals the full V2 admission checkpoint before returning.
/// Reopen mode opens both stores without migration, replays the route journal,
/// reconstructs the exact historical composition and separately checks current
/// time ancestry without turning that check into a replacement admission.
pub fn load_authenticated_production_inputs_v1(
    bootstrap: &ValidatedProductionBootstrapV1,
    trusted_now_seconds: u64,
) -> Result<AuthenticatedProductionInputsV1, ProductionInputErrorV1> {
    load_authenticated_production_inputs_inner_v1(bootstrap, trusted_now_seconds, None)
}

pub(crate) fn load_authenticated_production_inputs_with_provisioning_v1(
    bootstrap: &ValidatedProductionBootstrapV1,
    trusted_now_seconds: u64,
    provisioning: &mut DurableProductionProvisioningJournalV1,
) -> Result<AuthenticatedProductionInputsV1, ProductionInputErrorV1> {
    load_authenticated_production_inputs_inner_v1(
        bootstrap,
        trusted_now_seconds,
        Some(provisioning),
    )
}

fn load_authenticated_production_inputs_inner_v1(
    bootstrap: &ValidatedProductionBootstrapV1,
    trusted_now_seconds: u64,
    mut provisioning: Option<&mut DurableProductionProvisioningJournalV1>,
) -> Result<AuthenticatedProductionInputsV1, ProductionInputErrorV1> {
    if trusted_now_seconds == 0 {
        return Err(ProductionInputErrorV1::PinMismatch);
    }
    let config = bootstrap.config();
    let pins = config.pins();
    let layout = bootstrap.layout();
    let secp = SecpContext::new(&VERIFICATION_CONTEXT_SEED_V1);

    let authority_bytes = read_bounded(
        layout.path(ProductionPathRoleV1::RegistryAuthorities),
        MAX_PRODUCTION_AUTHORITY_BUNDLE_BYTES_V1 as u64,
    )?;
    let authority_bundle = ProductionAuthorityBundleV1::decode_canonical(&authority_bytes)?;
    authority_bundle
        .registry
        .validate_with_context(&secp)
        .map_err(|_| ProductionInputErrorV1::InvalidAuthorityBundle)?;
    authority_bundle
        .time_policy
        .validate_with_context(&secp)
        .map_err(|_| ProductionInputErrorV1::InvalidAuthorityBundle)?;
    authority_bundle
        .time_evidence
        .validate_with_context(&secp)
        .map_err(|_| ProductionInputErrorV1::InvalidAuthorityBundle)?;
    let registry_authority_set_digest = authority_bundle
        .registry
        .authority_set_digest()
        .map_err(|_| ProductionInputErrorV1::InvalidAuthorityBundle)?;
    if registry_authority_set_digest != pins.registry_authority_set_digest {
        return Err(ProductionInputErrorV1::PinMismatch);
    }

    let upstream = decode_terms(
        layout.path(ProductionPathRoleV1::UpstreamTerms),
        pins.upstream_terms_digest,
    )?;
    let downstream = decode_terms(
        layout.path(ProductionPathRoleV1::DownstreamTerms),
        pins.downstream_terms_digest,
    )?;
    if route_scope_digest(&upstream, &downstream)
        .map_err(|_| ProductionInputErrorV1::TimeRefused)?
        != pins.route_scope_digest
    {
        return Err(ProductionInputErrorV1::PinMismatch);
    }

    let roster_bytes = read_bounded(
        layout.path(ProductionPathRoleV1::RelayRoster),
        PRODUCTION_ROSTER_BUNDLE_BYTES_V1 as u64,
    )?;
    let roster_bundle = ProductionRelayRosterBundleV1::decode_canonical(&roster_bytes)?;
    if roster_bundle.bundle_digest()? != pins.relay_binding_digest
        || roster_bundle.network_id != pins.network_id
        || roster_bundle.route_id != pins.route_id
    {
        return Err(ProductionInputErrorV1::PinMismatch);
    }
    validate_roster_terms(&roster_bundle, &upstream, &downstream, &secp)?;

    let participant_bytes = read_bounded(
        layout.path(ProductionPathRoleV1::ParticipantBindings),
        MAX_PRODUCTION_PARTICIPANT_BUNDLE_BYTES_V1 as u64,
    )?;
    let participant_bundle =
        ProductionParticipantBindingBundleV1::decode_canonical(&participant_bytes)?;
    if participant_bundle.bundle_digest()? != pins.participant_bindings_digest
        || participant_bundle.route_id != pins.route_id
    {
        return Err(ProductionInputErrorV1::PinMismatch);
    }

    let signed_policy = SignedRouteTimePolicyV2::decode(&read_bounded(
        layout.path(ProductionPathRoleV1::TimePolicy),
        MAX_SIGNED_TIME_POLICY_ARTIFACT_BYTES_V1,
    )?)
    .map_err(|_| ProductionInputErrorV1::TimeRefused)?;
    let decoded_policy = RouteTimePolicyV2::decode(signed_policy.policy_bytes())
        .map_err(|_| ProductionInputErrorV1::TimeRefused)?;
    if decoded_policy
        .policy_digest()
        .map_err(|_| ProductionInputErrorV1::TimeRefused)?
        != pins.time_policy_digest
    {
        return Err(ProductionInputErrorV1::PinMismatch);
    }
    let signed_evidence = SignedRouteTimeEvidenceV2::decode(&read_bounded(
        layout.path(ProductionPathRoleV1::TimeEvidence),
        MAX_SIGNED_TIME_EVIDENCE_ARTIFACT_BYTES_V1,
    )?)
    .map_err(|_| ProductionInputErrorV1::TimeRefused)?;
    let decoded_evidence = RouteTimeEvidenceV2::decode(signed_evidence.evidence_bytes())
        .map_err(|_| ProductionInputErrorV1::TimeRefused)?;
    if decoded_evidence
        .evidence_digest()
        .map_err(|_| ProductionInputErrorV1::TimeRefused)?
        != pins.time_evidence_digest
    {
        return Err(ProductionInputErrorV1::PinMismatch);
    }

    let route_path = layout.path(ProductionPathRoleV1::RouteStore);
    let route_provisioning_state = if config.mode() == ProductionBootstrapModeV1::Create {
        match provisioning.as_deref_mut() {
            Some(journal) => Some(
                journal
                    .stage_state(ProductionProvisioningStageV1::RouteStore)
                    .map_err(|_| ProductionInputErrorV1::ProvisioningRefused)?,
            ),
            None => None,
        }
    } else {
        None
    };
    let mut route_store = match config.mode() {
        ProductionBootstrapModeV1::Create => match route_provisioning_state {
            Some(ProductionProvisioningStageStateV1::Started) if path_is_present(route_path)? => {
                Some(open_or_resume_started_route_store(route_path)?)
            }
            Some(ProductionProvisioningStageStateV1::Started)
                if sqlite_process_lock_is_present(route_path)? =>
            {
                Some(
                    DurableRouteStoreV1::resume_create_production(route_path)
                        .map_err(|_| ProductionInputErrorV1::RouteStateRefused)?,
                )
            }
            Some(ProductionProvisioningStageStateV1::Complete) => Some(
                DurableRouteStoreV1::open_existing(route_path)
                    .map_err(|_| ProductionInputErrorV1::RouteStateRefused)?,
            ),
            Some(ProductionProvisioningStageStateV1::Absent)
            | Some(ProductionProvisioningStageStateV1::Started)
            | None => None,
        },
        ProductionBootstrapModeV1::ReopenExisting => Some(
            DurableRouteStoreV1::open_existing(route_path)
                .map_err(|_| ProductionInputErrorV1::RouteStateRefused)?,
        ),
    };
    let route_resume_started =
        route_provisioning_state == Some(ProductionProvisioningStageStateV1::Started);
    let recovered_checkpoint = match route_store.as_ref() {
        Some(store) => match store.audit_frozen_admission_checkpoint_v2(pins.route_id) {
            Ok(checkpoint) => Some(checkpoint),
            Err(RouteStoreErrorV1::RouteNotFound) if route_resume_started => None,
            Err(_) => return Err(ProductionInputErrorV1::RouteStateRefused),
        },
        None => None,
    };
    let registry_store =
        RegistryStoreV1::open_existing(layout.path(ProductionPathRoleV1::RegistryStore))
            .map_err(|_| ProductionInputErrorV1::RegistryRefused)?;
    let resolved_registry = match recovered_checkpoint.as_ref() {
        None => registry_store
            .load_current(
                &authority_bundle.registry,
                &secp,
                RegistryValidationPolicyV1 {
                    now_seconds: trusted_now_seconds,
                    expected_network_id: pins.network_id,
                    minimum_epoch: pins.registry_minimum_epoch,
                },
            )
            .map_err(|_| ProductionInputErrorV1::RegistryRefused)?
            .ok_or(ProductionInputErrorV1::RegistryRefused)?,
        Some(checkpoint) => registry_store
            .load_pinned(
                checkpoint.registry_manifest_digest,
                &authority_bundle.registry,
                &secp,
                pins.network_id,
            )
            .map_err(|_| ProductionInputErrorV1::RegistryRefused)?
            .ok_or(ProductionInputErrorV1::RegistryRefused)?,
    };
    if resolved_registry.manifest().network_id != pins.network_id
        || resolved_registry.epoch() < pins.registry_minimum_epoch
        || match recovered_checkpoint.as_ref() {
            None => resolved_registry.manifest_digest() != pins.registry_manifest_digest,
            Some(checkpoint) => {
                resolved_registry.manifest_digest() != checkpoint.registry_manifest_digest
                    || resolved_registry.epoch() != checkpoint.registry_epoch
            }
        }
    {
        return Err(ProductionInputErrorV1::PinMismatch);
    }
    let reconstructed_policy = RouteTimePolicyV2::from_registry(
        &resolved_registry,
        &upstream,
        &downstream,
        decoded_policy.limits(),
    )
    .map_err(|_| ProductionInputErrorV1::TimeRefused)?;
    if reconstructed_policy != decoded_policy {
        return Err(ProductionInputErrorV1::TimeRefused);
    }

    let time_config = RouteTimeAnchorStoreConfigV2::new(
        &resolved_registry,
        &upstream,
        &downstream,
        &authority_bundle.time_policy,
        &authority_bundle.time_evidence,
        &secp,
    )
    .map_err(|_| ProductionInputErrorV1::TimeRefused)?;
    if time_config.network_id() != pins.network_id
        || time_config.registry_digest() != pins.registry_manifest_digest
        || time_config.route_scope_digest() != pins.route_scope_digest
        || time_config.policy_authority_set_digest() != pins.time_policy_authority_set_digest
        || time_config.evidence_authority_set_digest() != pins.time_evidence_authority_set_digest
    {
        return Err(ProductionInputErrorV1::PinMismatch);
    }
    let time_policy_authority_set_digest = time_config.policy_authority_set_digest();
    let time_evidence_authority_set_digest = time_config.evidence_authority_set_digest();
    if let Some(checkpoint) = recovered_checkpoint.as_ref() {
        validate_checkpoint_against_public_inputs(
            checkpoint,
            pins,
            roster_bundle.bundle_digest()?,
            participant_bundle.bundle_digest()?,
            registry_authority_set_digest,
            time_policy_authority_set_digest,
            time_evidence_authority_set_digest,
        )?;
    }
    let time_path = layout.path(ProductionPathRoleV1::TimeAnchorStore);
    let mut time_store = match config.mode() {
        ProductionBootstrapModeV1::Create => match provisioning.as_deref_mut() {
            Some(journal) => {
                let prior_state = journal
                    .stage_state(ProductionProvisioningStageV1::TimeAnchorStore)
                    .map_err(|_| ProductionInputErrorV1::ProvisioningRefused)?;
                let state = journal
                    .begin(ProductionProvisioningStageV1::TimeAnchorStore)
                    .map_err(|_| ProductionInputErrorV1::ProvisioningRefused)?;
                match (prior_state, state) {
                    (
                        ProductionProvisioningStageStateV1::Complete,
                        ProductionProvisioningStageStateV1::Complete,
                    ) => DurableRouteTimeAnchorStoreV2::open_existing(time_path, time_config),
                    (
                        ProductionProvisioningStageStateV1::Started,
                        ProductionProvisioningStageStateV1::Started,
                    ) if path_is_present(time_path)? => {
                        open_or_resume_started_time_store(time_path, time_config)
                    }
                    (
                        ProductionProvisioningStageStateV1::Started,
                        ProductionProvisioningStageStateV1::Started,
                    ) if sqlite_process_lock_is_present(time_path)? => {
                        DurableRouteTimeAnchorStoreV2::resume_create_production(
                            time_path,
                            time_config,
                        )
                    }
                    (
                        ProductionProvisioningStageStateV1::Started,
                        ProductionProvisioningStageStateV1::Started,
                    ) => DurableRouteTimeAnchorStoreV2::create(time_path, time_config),
                    (
                        ProductionProvisioningStageStateV1::Absent,
                        ProductionProvisioningStageStateV1::Started,
                    ) if !path_is_present(time_path)? => {
                        DurableRouteTimeAnchorStoreV2::create(time_path, time_config)
                    }
                    _ => return Err(ProductionInputErrorV1::ProvisioningRefused),
                }
            }
            None => DurableRouteTimeAnchorStoreV2::create(time_path, time_config),
        },
        ProductionBootstrapModeV1::ReopenExisting => {
            DurableRouteTimeAnchorStoreV2::open_existing(time_path, time_config)
        }
    }
    .map_err(|_| ProductionInputErrorV1::TimeRefused)?;
    let admission_authority = RegistryRouteAdmissionAuthorityV1::new(
        registry_store,
        authority_bundle.registry.clone(),
        SecpContext::new(&VERIFICATION_CONTEXT_SEED_V1),
        pins.network_id,
        pins.registry_minimum_epoch,
    )
    .map_err(|_| ProductionInputErrorV1::AdmissionRefused)?;
    let rosters = roster_bundle.snapshots();
    let time_policy_context = RouteTimePolicyVerificationContextV2::new(
        &authority_bundle.time_policy,
        &secp,
        &resolved_registry,
        &upstream,
        &downstream,
    );
    let time_evidence_context = RouteTimeEvidenceVerificationContextV2::new(
        time_policy_context,
        &authority_bundle.time_evidence,
    );

    let (admission, composition, participant_sessions, checkpoint, current_time_ancestry_ready) =
        match recovered_checkpoint {
            None => {
                let original_validation_seconds = decoded_evidence.observed_at_seconds();
                time_store
                    .install_policy(
                        &signed_policy,
                        time_policy_context,
                        original_validation_seconds,
                    )
                    .map_err(|_| ProductionInputErrorV1::TimeRefused)?;
                time_store
                    .install_evidence(
                        &signed_evidence,
                        time_evidence_context,
                        original_validation_seconds,
                    )
                    .map_err(|_| ProductionInputErrorV1::TimeRefused)?;
                let proof = time_store
                    .prove_route_ladder(time_evidence_context, original_validation_seconds)
                    .map_err(|_| ProductionInputErrorV1::TimeRefused)?;
                let original = time_store
                    .consume_capability_at(proof, original_validation_seconds)
                    .map_err(|_| ProductionInputErrorV1::TimeRefused)?;
                let composition =
                    ComposedBindingV2::bind(upstream.clone(), downstream.clone(), original)
                        .map_err(|_| ProductionInputErrorV1::CompositionRefused)?;
                validate_composition_stable_pins(&composition, pins)?;
                let admission = admission_authority
                    .admit_validated_composed_route_v2(
                        trusted_now_seconds,
                        pins.route_id,
                        &composition,
                        rosters,
                    )
                    .map_err(|_| ProductionInputErrorV1::AdmissionRefused)?;
                if admission.registry_digest() != resolved_registry.manifest_digest()
                    || admission.registry_epoch() != resolved_registry.epoch()
                {
                    return Err(ProductionInputErrorV1::PinMismatch);
                }
                let participant_sessions = authenticate_participant_bundle(
                    &participant_bundle,
                    ParticipantAuthenticationContextV1 {
                        secp: &secp,
                        rosters: &roster_bundle,
                        registry: &resolved_registry,
                        upstream: &upstream,
                        downstream: &downstream,
                        admission: &admission,
                        now: composition.time_proof_validated_at_seconds(),
                    },
                )?;
                if trusted_now_seconds != composition.time_proof_validated_at_seconds() {
                    let _ = authenticate_participant_bundle(
                        &participant_bundle,
                        ParticipantAuthenticationContextV1 {
                            secp: &secp,
                            rosters: &roster_bundle,
                            registry: &resolved_registry,
                            upstream: &upstream,
                            downstream: &downstream,
                            admission: &admission,
                            now: trusted_now_seconds,
                        },
                    )?;
                }
                let checkpoint = build_admission_checkpoint(AdmissionCheckpointContextV1 {
                    pins,
                    registry: &resolved_registry,
                    admission: &admission,
                    composition: &composition,
                    rosters: &roster_bundle,
                    participant_bindings_digest: participant_bundle.bundle_digest()?,
                    relay_binding_digest: roster_bundle.bundle_digest()?,
                    registry_authority_set_digest,
                    time_policy_authority_set_digest,
                    time_evidence_authority_set_digest,
                })?;
                prove_current_time_ancestry(
                    &mut time_store,
                    CurrentTimeAncestryContextV1 {
                        checkpoint: &checkpoint,
                        authorities: &authority_bundle,
                        secp: &secp,
                        registry: &resolved_registry,
                        upstream: &upstream,
                        downstream: &downstream,
                        trusted_now_seconds,
                        require_ready: true,
                    },
                )?;
                if let Some(journal) = provisioning.as_deref_mut() {
                    journal
                        .complete(ProductionProvisioningStageV1::TimeAnchorStore)
                        .map_err(|_| ProductionInputErrorV1::ProvisioningRefused)?;
                    journal
                        .begin(ProductionProvisioningStageV1::RouteStore)
                        .map_err(|_| ProductionInputErrorV1::ProvisioningRefused)?;
                }
                let mut created_route_store = match route_store.take() {
                    Some(store) => store,
                    None if path_is_present(route_path)? => {
                        return Err(ProductionInputErrorV1::RouteStateRefused)
                    }
                    None => DurableRouteStoreV1::create(route_path)
                        .map_err(|_| ProductionInputErrorV1::RouteStateRefused)?,
                };
                persist_new_route_checkpoint(
                    &mut created_route_store,
                    &checkpoint,
                    pins.process_owner_id,
                    trusted_now_seconds,
                    config.bounds().lease_duration_ms,
                )?;
                route_store = Some(created_route_store);
                (
                    admission,
                    composition,
                    participant_sessions,
                    checkpoint,
                    true,
                )
            }
            Some(checkpoint) => {
                let historical = time_store
                    .verify_frozen_route_ladder(
                        frozen_time_proof_checkpoint(&checkpoint)?,
                        &signed_policy,
                        &signed_evidence,
                        time_evidence_context,
                    )
                    .map_err(|_| ProductionInputErrorV1::TimeRefused)?;
                let composition = ComposedBindingV2::bind_recovered(
                    upstream.clone(),
                    downstream.clone(),
                    historical,
                )
                .map_err(|_| ProductionInputErrorV1::CompositionRefused)?;
                validate_composition_stable_pins(&composition, pins)?;
                if composition.binding_digest() != checkpoint.composition_v2_digest {
                    return Err(ProductionInputErrorV1::PinMismatch);
                }
                let admission = admission_authority
                    .recover_validated_composed_route_v2(pins.route_id, &composition, &checkpoint)
                    .map_err(|_| ProductionInputErrorV1::AdmissionRefused)?;
                let participant_sessions = authenticate_participant_bundle(
                    &participant_bundle,
                    ParticipantAuthenticationContextV1 {
                        secp: &secp,
                        rosters: &roster_bundle,
                        registry: &resolved_registry,
                        upstream: &upstream,
                        downstream: &downstream,
                        admission: &admission,
                        now: checkpoint.time.validated_at_seconds,
                    },
                )?;
                let current_time_ancestry_ready = prove_current_time_ancestry(
                    &mut time_store,
                    CurrentTimeAncestryContextV1 {
                        checkpoint: &checkpoint,
                        authorities: &authority_bundle,
                        secp: &secp,
                        registry: &resolved_registry,
                        upstream: &upstream,
                        downstream: &downstream,
                        trusted_now_seconds,
                        require_ready: false,
                    },
                )?;
                if let Some(journal) = provisioning.as_deref_mut() {
                    journal
                        .complete(ProductionProvisioningStageV1::TimeAnchorStore)
                        .map_err(|_| ProductionInputErrorV1::ProvisioningRefused)?;
                }
                (
                    admission,
                    composition,
                    participant_sessions,
                    checkpoint,
                    current_time_ancestry_ready,
                )
            }
        };
    let route_store = route_store.ok_or(ProductionInputErrorV1::RouteStateRefused)?;
    if route_store
        .audit_frozen_admission_checkpoint_v2(pins.route_id)
        .map_err(|_| ProductionInputErrorV1::RouteStateRefused)?
        != checkpoint
    {
        return Err(ProductionInputErrorV1::RouteStateRefused);
    }
    if let Some(journal) = provisioning {
        if journal
            .stage_state(ProductionProvisioningStageV1::RouteStore)
            .map_err(|_| ProductionInputErrorV1::ProvisioningRefused)?
            == ProductionProvisioningStageStateV1::Absent
        {
            journal
                .begin(ProductionProvisioningStageV1::RouteStore)
                .map_err(|_| ProductionInputErrorV1::ProvisioningRefused)?;
        }
        journal
            .complete(ProductionProvisioningStageV1::RouteStore)
            .map_err(|_| ProductionInputErrorV1::ProvisioningRefused)?;
    }

    Ok(AuthenticatedProductionInputsV1 {
        admission,
        admission_authority,
        composition,
        resolved_registry,
        route_store,
        time_store,
        time_policy_authorities: authority_bundle.time_policy,
        time_evidence_authorities: authority_bundle.time_evidence,
        time_verification_context: SecpContext::new(&VERIFICATION_CONTEXT_SEED_V1),
        signed_time_policy: signed_policy,
        signed_time_evidence: signed_evidence,
        roster_registry: roster_bundle.to_registry(),
        roster_bundle,
        evm_sessions: participant_sessions.evm,
        bitcoin_sessions: participant_sessions.bitcoin,
        solana_sessions: participant_sessions.solana,
        monero_sessions: participant_sessions.monero,
        current_time_ancestry_ready,
    })
}

fn validate_checkpoint_against_public_inputs(
    checkpoint: &FrozenRouteAdmissionCheckpointV2,
    pins: crate::production_config::ProductionRoutePinsV1,
    relay_binding_digest: Digest32,
    participant_bindings_digest: Digest32,
    registry_authority_set_digest: Digest32,
    time_policy_authority_set_digest: Digest32,
    time_evidence_authority_set_digest: Digest32,
) -> Result<(), ProductionInputErrorV1> {
    checkpoint
        .encode_canonical()
        .map_err(|_| ProductionInputErrorV1::RouteStateRefused)?;
    if checkpoint.network_id != pins.network_id
        || checkpoint.route_id != pins.route_id
        || checkpoint.registry_manifest_digest != pins.registry_manifest_digest
        || checkpoint.registry_epoch < pins.registry_minimum_epoch
        || checkpoint.upstream_terms_digest != pins.upstream_terms_digest
        || checkpoint.downstream_terms_digest != pins.downstream_terms_digest
        || checkpoint.upstream_roster_snapshot == checkpoint.downstream_roster_snapshot
        || checkpoint.participant_bindings_digest != participant_bindings_digest
        || checkpoint.relay_binding_digest != relay_binding_digest
        || checkpoint.registry_authority_set_digest != registry_authority_set_digest
        || checkpoint.time_policy_authority_set_digest != time_policy_authority_set_digest
        || checkpoint.time_evidence_authority_set_digest != time_evidence_authority_set_digest
        || checkpoint.time.route_scope_digest != pins.route_scope_digest
        || checkpoint.time.policy_digest != pins.time_policy_digest
        || checkpoint.time.evidence_digest != pins.time_evidence_digest
    {
        return Err(ProductionInputErrorV1::PinMismatch);
    }
    Ok(())
}

fn validate_composition_stable_pins(
    composition: &ComposedBindingV2,
    pins: crate::production_config::ProductionRoutePinsV1,
) -> Result<(), ProductionInputErrorV1> {
    if composition.route_scope_digest() != pins.route_scope_digest
        || composition.time_policy_digest() != pins.time_policy_digest
        || composition.time_evidence_digest() != pins.time_evidence_digest
        || composition
            .upstream()
            .terms_hash()
            .map_err(|_| ProductionInputErrorV1::TermsRefused)?
            != pins.upstream_terms_digest
        || composition
            .downstream()
            .terms_hash()
            .map_err(|_| ProductionInputErrorV1::TermsRefused)?
            != pins.downstream_terms_digest
    {
        return Err(ProductionInputErrorV1::PinMismatch);
    }
    Ok(())
}

struct AdmissionCheckpointContextV1<'a> {
    pins: crate::production_config::ProductionRoutePinsV1,
    registry: &'a ResolvedRegistryV1,
    admission: &'a AuthenticatedRouteAdmissionV1,
    composition: &'a ComposedBindingV2,
    rosters: &'a ProductionRelayRosterBundleV1,
    participant_bindings_digest: Digest32,
    relay_binding_digest: Digest32,
    registry_authority_set_digest: Digest32,
    time_policy_authority_set_digest: Digest32,
    time_evidence_authority_set_digest: Digest32,
}

fn build_admission_checkpoint(
    context: AdmissionCheckpointContextV1<'_>,
) -> Result<FrozenRouteAdmissionCheckpointV2, ProductionInputErrorV1> {
    let time = context
        .admission
        .route_time_binding_v2()
        .ok_or(ProductionInputErrorV1::AdmissionRefused)?
        .frozen_facts();
    let checkpoint = FrozenRouteAdmissionCheckpointV2 {
        network_id: context.pins.network_id,
        route_id: context.pins.route_id,
        bindings: context.admission.frozen_bindings().clone(),
        composition_v2_digest: context.composition.binding_digest(),
        registry_epoch: context.registry.epoch(),
        registry_manifest_digest: context.registry.manifest_digest(),
        upstream_terms_digest: context
            .composition
            .upstream()
            .terms_hash()
            .map_err(|_| ProductionInputErrorV1::TermsRefused)?,
        downstream_terms_digest: context
            .composition
            .downstream()
            .terms_hash()
            .map_err(|_| ProductionInputErrorV1::TermsRefused)?,
        upstream_roster_snapshot: context.rosters.legs[0].roster_snapshot,
        downstream_roster_snapshot: context.rosters.legs[1].roster_snapshot,
        participant_bindings_digest: context.participant_bindings_digest,
        relay_binding_digest: context.relay_binding_digest,
        registry_authority_set_digest: context.registry_authority_set_digest,
        time_policy_authority_set_digest: context.time_policy_authority_set_digest,
        time_evidence_authority_set_digest: context.time_evidence_authority_set_digest,
        time,
    };
    checkpoint
        .encode_canonical()
        .map_err(|_| ProductionInputErrorV1::RouteStateRefused)?;
    validate_checkpoint_against_public_inputs(
        &checkpoint,
        context.pins,
        context.relay_binding_digest,
        context.participant_bindings_digest,
        context.registry_authority_set_digest,
        context.time_policy_authority_set_digest,
        context.time_evidence_authority_set_digest,
    )?;
    Ok(checkpoint)
}

fn persist_new_route_checkpoint(
    route_store: &mut DurableRouteStoreV1,
    checkpoint: &FrozenRouteAdmissionCheckpointV2,
    owner_id: Digest32,
    trusted_now_seconds: u64,
    lease_duration_ms: u64,
) -> Result<(), ProductionInputErrorV1> {
    let now_unix_ms = trusted_now_seconds
        .checked_mul(1_000)
        .ok_or(ProductionInputErrorV1::RouteStateRefused)?;
    route_store
        .create_route(checkpoint.route_id, now_unix_ms)
        .map_err(|_| ProductionInputErrorV1::RouteStateRefused)?;
    let lease = route_store
        .acquire_lease(
            checkpoint.route_id,
            owner_id,
            now_unix_ms,
            lease_duration_ms,
        )
        .map_err(|_| ProductionInputErrorV1::RouteStateRefused)?
        .lease();
    let checkpoint_bytes = checkpoint
        .encode_canonical()
        .map_err(|_| ProductionInputErrorV1::RouteStateRefused)?;
    let event_id = digest_bytes(FREEZE_EVENT_ID_DOMAIN_V2, &checkpoint_bytes)?;
    if event_id == ZERO_DIGEST {
        return Err(ProductionInputErrorV1::RouteStateRefused);
    }
    match route_store
        .apply_event(
            lease,
            0,
            event_id,
            &RouteEventV1::FreezeTermsV2(Box::new(checkpoint.clone())),
            now_unix_ms,
        )
        .map_err(|_| ProductionInputErrorV1::RouteStateRefused)?
    {
        CommitOutcomeV1::Committed { revision: 1, .. } => {}
        CommitOutcomeV1::Committed { .. } | CommitOutcomeV1::DuplicateSameBytes { .. } => {
            return Err(ProductionInputErrorV1::RouteStateRefused)
        }
    }
    if route_store
        .audit_frozen_admission_checkpoint_v2(checkpoint.route_id)
        .map_err(|_| ProductionInputErrorV1::RouteStateRefused)?
        != *checkpoint
    {
        return Err(ProductionInputErrorV1::RouteStateRefused);
    }
    Ok(())
}

fn frozen_time_checkpoint(
    checkpoint: &FrozenRouteAdmissionCheckpointV2,
) -> Result<FrozenRouteTimeCheckpointV2, ProductionInputErrorV1> {
    FrozenRouteTimeCheckpointV2::new(
        checkpoint.time.route_scope_digest,
        checkpoint.time.policy_digest,
        checkpoint.time.evidence_digest,
        checkpoint.time.evidence_sequence,
    )
    .map_err(|_| ProductionInputErrorV1::TimeRefused)
}

fn frozen_time_proof_checkpoint(
    checkpoint: &FrozenRouteAdmissionCheckpointV2,
) -> Result<FrozenRouteTimeProofCheckpointV2, ProductionInputErrorV1> {
    FrozenRouteTimeProofCheckpointV2::new(
        frozen_time_checkpoint(checkpoint)?,
        checkpoint.time.proof_digest,
        checkpoint.time.issued_at_seconds,
        checkpoint.time.valid_until_seconds,
        checkpoint.time.validated_at_seconds,
    )
    .map_err(|_| ProductionInputErrorV1::TimeRefused)
}

struct CurrentTimeAncestryContextV1<'a> {
    checkpoint: &'a FrozenRouteAdmissionCheckpointV2,
    authorities: &'a ProductionAuthorityBundleV1,
    secp: &'a SecpContext,
    registry: &'a ResolvedRegistryV1,
    upstream: &'a SettlementTermsV1,
    downstream: &'a SettlementTermsV1,
    trusted_now_seconds: u64,
    require_ready: bool,
}

fn prove_current_time_ancestry(
    time_store: &mut DurableRouteTimeAnchorStoreV2,
    context: CurrentTimeAncestryContextV1<'_>,
) -> Result<bool, ProductionInputErrorV1> {
    match time_store.prove_current_route_ladder_from_checkpoint(
        frozen_time_checkpoint(context.checkpoint)?,
        RouteTimeEvidenceVerificationContextV2::new(
            RouteTimePolicyVerificationContextV2::new(
                &context.authorities.time_policy,
                context.secp,
                context.registry,
                context.upstream,
                context.downstream,
            ),
            &context.authorities.time_evidence,
        ),
        context.trusted_now_seconds,
    ) {
        Ok(_current) => Ok(true),
        Err(error) if !context.require_ready && current_time_economic_refusal(error) => Ok(false),
        Err(_) => Err(ProductionInputErrorV1::TimeRefused),
    }
}

const fn current_time_economic_refusal(error: RouteTimeAnchorErrorV2) -> bool {
    matches!(
        error,
        RouteTimeAnchorErrorV2::ClockRollback
            | RouteTimeAnchorErrorV2::PolicyExpired
            | RouteTimeAnchorErrorV2::EvidenceFromFuture
            | RouteTimeAnchorErrorV2::EvidenceStale
            | RouteTimeAnchorErrorV2::AnchorStale
            | RouteTimeAnchorErrorV2::AnchorReorged
            | RouteTimeAnchorErrorV2::EvidenceRollback
            | RouteTimeAnchorErrorV2::DeadlinePassed
            | RouteTimeAnchorErrorV2::ImpossibleInterval
            | RouteTimeAnchorErrorV2::UnsafeWindow
    )
}

fn decode_terms(
    path: &std::path::Path,
    expected_digest: Digest32,
) -> Result<SettlementTermsV1, ProductionInputErrorV1> {
    let bytes = read_bounded(path, MAX_TERMS_ARTIFACT_BYTES_V1)?;
    let terms =
        SettlementTermsV1::decode(&bytes).map_err(|_| ProductionInputErrorV1::TermsRefused)?;
    if terms
        .canonical_bytes()
        .map_err(|_| ProductionInputErrorV1::TermsRefused)?
        != bytes
        || terms
            .terms_hash()
            .map_err(|_| ProductionInputErrorV1::TermsRefused)?
            != expected_digest
    {
        return Err(ProductionInputErrorV1::PinMismatch);
    }
    Ok(terms)
}

fn validate_roster_terms(
    rosters: &ProductionRelayRosterBundleV1,
    upstream: &SettlementTermsV1,
    downstream: &SettlementTermsV1,
    secp: &SecpContext,
) -> Result<(), ProductionInputErrorV1> {
    for (leg, terms) in rosters.legs.iter().zip([upstream, downstream]) {
        if leg.session_id != terms.session_id.0
            || leg.policy_version != terms.policy_version
            || leg.members.map(|member| member.participant_id) != terms.roster
        {
            return Err(ProductionInputErrorV1::InvalidRosterBundle);
        }
        for member in leg.members {
            secp.validate_xonly_key(&member.xonly_key)
                .map_err(|_| ProductionInputErrorV1::InvalidRosterBundle)?;
        }
    }
    Ok(())
}

struct ParticipantAuthenticationContextV1<'a> {
    secp: &'a SecpContext,
    rosters: &'a ProductionRelayRosterBundleV1,
    registry: &'a ResolvedRegistryV1,
    upstream: &'a SettlementTermsV1,
    downstream: &'a SettlementTermsV1,
    admission: &'a AuthenticatedRouteAdmissionV1,
    now: u64,
}

struct AuthenticatedParticipantBundleV1 {
    evm: [Option<AuthenticatedEvmSessionBindingsV1>; 2],
    bitcoin: [Option<AuthenticatedBitcoinParticipantBindingsV1>; 2],
    solana: [Option<AuthenticatedSolanaSessionBindingsV1>; 2],
    monero: [Option<AuthenticatedXmrSessionBindingsV1>; 2],
}

fn authenticate_participant_bundle(
    bundle: &ProductionParticipantBindingBundleV1,
    context: ParticipantAuthenticationContextV1<'_>,
) -> Result<AuthenticatedParticipantBundleV1, ProductionInputErrorV1> {
    let mut evm_sessions: [Option<AuthenticatedEvmSessionBindingsV1>; 2] =
        std::array::from_fn(|_| None);
    let mut bitcoin_sessions: [Option<AuthenticatedBitcoinParticipantBindingsV1>; 2] =
        std::array::from_fn(|_| None);
    let mut solana_sessions: [Option<AuthenticatedSolanaSessionBindingsV1>; 2] =
        std::array::from_fn(|_| None);
    let mut monero_sessions: [Option<AuthenticatedXmrSessionBindingsV1>; 2] =
        std::array::from_fn(|_| None);
    let mut expected_evm_count = 0usize;
    let mut expected_bitcoin_count = 0usize;
    let mut expected_solana_count = 0usize;
    let mut expected_monero_count = 0usize;
    for (index, (position, terms)) in [
        (ProductionRoutePositionV1::Upstream, context.upstream),
        (ProductionRoutePositionV1::Downstream, context.downstream),
    ]
    .into_iter()
    .enumerate()
    {
        let chain = context
            .registry
            .resolve_chain(terms.counterparty_leg.chain_id)
            .ok_or(ProductionInputErrorV1::RegistryRefused)?;
        match chain.profile().kind {
            ChainKindV1::Evm { evm_chain_id, .. } => {
                expected_evm_count += 1;
                let proof_pair = bundle
                    .legs
                    .iter()
                    .find(|candidate| candidate.position == position)
                    .ok_or(ProductionInputErrorV1::InvalidParticipantBundle)?;
                let snapshot = context.rosters.legs[index].roster_snapshot;
                let funder_key = context
                    .rosters
                    .member_key(position, terms.counterparty_leg.refund_to)?;
                let beneficiary_key = context
                    .rosters
                    .member_key(position, terms.counterparty_leg.beneficiary)?;
                let funder = verify_evm_account_binding_v1(
                    &proof_pair.funder,
                    funder_key,
                    snapshot,
                    context.registry.manifest().network_id,
                    context.registry.manifest_digest(),
                    context.now,
                )
                .map_err(|_| ProductionInputErrorV1::InvalidParticipantBundle)?;
                let beneficiary = verify_evm_account_binding_v1(
                    &proof_pair.beneficiary,
                    beneficiary_key,
                    snapshot,
                    context.registry.manifest().network_id,
                    context.registry.manifest_digest(),
                    context.now,
                )
                .map_err(|_| ProductionInputErrorV1::InvalidParticipantBundle)?;
                let session = bind_evm_session_v1(
                    terms,
                    bundle.route_id,
                    context.admission.frozen_bindings().terms_digest,
                    position.evm_position(),
                    evm_chain_id,
                    context.registry.manifest().network_id,
                    context.registry.manifest_digest(),
                    context.now,
                    &funder,
                    &beneficiary,
                )
                .map_err(|_| ProductionInputErrorV1::InvalidParticipantBundle)?;
                context
                    .admission
                    .evm_deployment_capability(position.leg(), &session)
                    .map_err(|_| ProductionInputErrorV1::InvalidParticipantBundle)?;
                evm_sessions[index] = Some(session);
            }
            ChainKindV1::Bitcoin { .. } => {
                expected_bitcoin_count += 1;
                let proofs = bundle
                    .bitcoin_legs
                    .iter()
                    .find(|candidate| candidate.position == position)
                    .ok_or(ProductionInputErrorV1::InvalidParticipantBundle)?;
                if [
                    proofs.participants[0].participant_id,
                    proofs.participants[1].participant_id,
                ] != terms.roster
                {
                    return Err(ProductionInputErrorV1::InvalidParticipantBundle);
                }
                let deployment = context
                    .admission
                    .bitcoin_deployment_capability(position.leg())
                    .map_err(|_| ProductionInputErrorV1::InvalidParticipantBundle)?;
                let roster_leg = &context.rosters.legs[index];
                let terms_digest = terms
                    .terms_hash()
                    .map_err(|_| ProductionInputErrorV1::InvalidParticipantBundle)?;
                let participants = std::array::from_fn(|participant_index| {
                    let proof = &proofs.participants[participant_index];
                    ParticipantKeyV1 {
                        participant_id: proof.participant_id.0,
                        role: proof.role,
                        compressed_key: proof.compressed_key,
                    }
                });
                let roster = ParticipantKeyRosterV1::new(participants)
                    .map_err(|_| ProductionInputErrorV1::InvalidParticipantBundle)?;
                let ordered_keys = [
                    roster.participants()[0].compressed_key,
                    roster.participants()[1].compressed_key,
                ];
                context
                    .secp
                    .key_agg(&ordered_keys)
                    .map_err(|_| ProductionInputErrorV1::InvalidParticipantBundle)?;
                for (participant_index, proof) in proofs.participants.iter().enumerate() {
                    let relay = roster_leg.members[participant_index];
                    if relay.participant_id != proof.participant_id {
                        return Err(ProductionInputErrorV1::InvalidParticipantBundle);
                    }
                    let statement = ProductionBitcoinParticipantKeyStatementRequestV1 {
                        network_id: context.registry.manifest().network_id,
                        route_id: bundle.route_id,
                        position,
                        session_id: terms.session_id.0,
                        terms_digest,
                        roster_snapshot: roster_leg.roster_snapshot,
                        participant_id: proof.participant_id,
                        role: proof.role,
                        relay_xonly_key: relay.xonly_key,
                        bitcoin_public_key: proof.compressed_key,
                        registry_digest: deployment.registry_digest(),
                        registry_epoch: deployment.registry_epoch(),
                        profile_digest: deployment.profile_digest(),
                        asset_binding_digest: deployment.asset_binding_digest(),
                        chain_id: deployment.profile().chain_id.0,
                        genesis_hash: deployment.deployment().genesis_hash,
                    };
                    let digest = statement.digest()?;
                    context
                        .secp
                        .verify_bip340(&relay.xonly_key, &digest, &proof.signature)
                        .map_err(|_| ProductionInputErrorV1::InvalidParticipantBundle)?;
                }
                bitcoin_sessions[index] = Some(AuthenticatedBitcoinParticipantBindingsV1 {
                    position,
                    network_id: context.registry.manifest().network_id,
                    route_id: bundle.route_id,
                    session_id: terms.session_id.0,
                    terms_digest,
                    roster_snapshot: roster_leg.roster_snapshot,
                    deployment,
                    roster,
                });
            }
            ChainKindV1::Solana {
                network,
                escrow_program,
                program_data_hash,
            } => {
                expected_solana_count += 1;
                let leg = bundle
                    .solana_legs
                    .iter()
                    .find(|candidate| candidate.position == position)
                    .ok_or(ProductionInputErrorV1::InvalidParticipantBundle)?;
                // The registry, not the peer, names the escrow program, the
                // cluster and the immutable program hash. A profile that
                // disagrees with the pinned deployment authenticates nothing
                // even if its hash matches the frozen terms.
                if leg.profile.program_id.0 != escrow_program
                    || leg.binding.program_data_hash != program_data_hash
                    || leg.profile.network as u8 != network as u8
                    || !leg.profile.require_immutable_program
                {
                    return Err(ProductionInputErrorV1::InvalidParticipantBundle);
                }
                let deployment = context
                    .admission
                    .solana_deployment_capability(position.leg())
                    .map_err(|_| ProductionInputErrorV1::InvalidParticipantBundle)?;
                let terms_digest = terms
                    .terms_hash()
                    .map_err(|_| ProductionInputErrorV1::InvalidParticipantBundle)?;
                // The DLEQ inside the binding is the authentication anchor:
                // validate_setup verifies it against the frozen terms, the
                // adaptor point, the closed role byte and the derived PDAs.
                let setup = validate_solana_setup(&leg.profile, terms, leg.binding.clone())
                    .map_err(|_| ProductionInputErrorV1::InvalidParticipantBundle)?;
                solana_sessions[index] = Some(AuthenticatedSolanaSessionBindingsV1 {
                    position,
                    network_id: context.registry.manifest().network_id,
                    route_id: bundle.route_id,
                    session_id: terms.session_id.0,
                    terms_digest,
                    deployment,
                    profile: leg.profile,
                    setup,
                });
            }
            ChainKindV1::Monero { network } => {
                expected_monero_count += 1;
                let leg = bundle
                    .monero_legs
                    .iter()
                    .find(|candidate| candidate.position == position)
                    .ok_or(ProductionInputErrorV1::InvalidParticipantBundle)?;
                // The registry names the network; Monero mainnet is
                // unrepresentable there, so an adapter profile claiming
                // mainnet can never authenticate.
                if leg.profile.network as u8 != network as u8 {
                    return Err(ProductionInputErrorV1::InvalidParticipantBundle);
                }
                let deployment = context
                    .admission
                    .monero_deployment_capability(position.leg())
                    .map_err(|_| ProductionInputErrorV1::InvalidParticipantBundle)?;
                let terms_digest = terms
                    .terms_hash()
                    .map_err(|_| ProductionInputErrorV1::InvalidParticipantBundle)?;
                // The DLEQ inside the binding is the authentication anchor:
                // validate_setup verifies it against the frozen terms, the
                // adaptor point and the closed shared-spend role, under the
                // ratified mechanism (no admission token).
                let setup = validate_xmr_setup(terms, &leg.profile, leg.binding.clone(), None)
                    .map_err(|_| ProductionInputErrorV1::InvalidParticipantBundle)?;
                monero_sessions[index] = Some(AuthenticatedXmrSessionBindingsV1 {
                    position,
                    network_id: context.registry.manifest().network_id,
                    route_id: bundle.route_id,
                    session_id: terms.session_id.0,
                    terms_digest,
                    deployment,
                    profile: leg.profile,
                    setup,
                    refund: leg.refund.clone(),
                });
            }
        }
    }
    if bundle.legs.len() != expected_evm_count
        || bundle.bitcoin_legs.len() != expected_bitcoin_count
        || bundle.solana_legs.len() != expected_solana_count
        || bundle.monero_legs.len() != expected_monero_count
    {
        return Err(ProductionInputErrorV1::InvalidParticipantBundle);
    }
    Ok(AuthenticatedParticipantBundleV1 {
        evm: evm_sessions,
        bitcoin: bitcoin_sessions,
        solana: solana_sessions,
        monero: monero_sessions,
    })
}

fn path_is_present(path: &std::path::Path) -> Result<bool, ProductionInputErrorV1> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(_) => Err(ProductionInputErrorV1::ProvisioningRefused),
    }
}

fn sqlite_process_lock_is_present(path: &std::path::Path) -> Result<bool, ProductionInputErrorV1> {
    let mut lock = path.as_os_str().to_os_string();
    lock.push(".lock");
    path_is_present(std::path::Path::new(&lock))
}

fn open_or_resume_started_route_store(
    path: &std::path::Path,
) -> Result<DurableRouteStoreV1, ProductionInputErrorV1> {
    match DurableRouteStoreV1::open_existing(path) {
        Ok(store) => Ok(store),
        Err(RouteStoreErrorV1::CreationIncomplete) => {
            DurableRouteStoreV1::resume_create_production(path)
                .map_err(|_| ProductionInputErrorV1::RouteStateRefused)
        }
        Err(_) => Err(ProductionInputErrorV1::RouteStateRefused),
    }
}

fn open_or_resume_started_time_store(
    path: &std::path::Path,
    config: RouteTimeAnchorStoreConfigV2,
) -> Result<DurableRouteTimeAnchorStoreV2, RouteTimeAnchorErrorV2> {
    match DurableRouteTimeAnchorStoreV2::open_existing(path, config) {
        Ok(store) => Ok(store),
        Err(RouteTimeAnchorErrorV2::CreationIncomplete) => {
            DurableRouteTimeAnchorStoreV2::resume_create_production(path, config)
        }
        Err(error) => Err(error),
    }
}

fn read_bounded(path: &std::path::Path, maximum: u64) -> Result<Vec<u8>, ProductionInputErrorV1> {
    let mut file = File::open(path).map_err(|_| ProductionInputErrorV1::InputUnavailable)?;
    let metadata = file
        .metadata()
        .map_err(|_| ProductionInputErrorV1::InputUnavailable)?;
    if !metadata.is_file() || metadata.len() == 0 || metadata.len() > maximum {
        return Err(if metadata.len() > maximum {
            ProductionInputErrorV1::InputBoundExceeded
        } else {
            ProductionInputErrorV1::InputUnavailable
        });
    }
    let capacity =
        usize::try_from(metadata.len()).map_err(|_| ProductionInputErrorV1::InputBoundExceeded)?;
    let mut bytes = Vec::with_capacity(capacity);
    file.by_ref()
        .take(maximum.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|_| ProductionInputErrorV1::InputUnavailable)?;
    if bytes.len() as u64 != metadata.len() || bytes.len() as u64 > maximum {
        return Err(ProductionInputErrorV1::InputBoundExceeded);
    }
    Ok(bytes)
}

fn sender_role_tag(role: SenderRoleV1) -> u8 {
    match role {
        SenderRoleV1::Initiator => 1,
        SenderRoleV1::Solver => 2,
        SenderRoleV1::Observer => 3,
    }
}

fn sender_role_from_tag(tag: u8) -> Result<SenderRoleV1, ProductionInputErrorV1> {
    match tag {
        1 => Ok(SenderRoleV1::Initiator),
        2 => Ok(SenderRoleV1::Solver),
        3 => Ok(SenderRoleV1::Observer),
        _ => Err(ProductionInputErrorV1::NonCanonicalEncoding),
    }
}

const fn leg_index(leg: LegIdV1) -> usize {
    match leg {
        LegIdV1::Upstream => 0,
        LegIdV1::Downstream => 1,
    }
}

fn digest_bytes(domain: &[u8], bytes: &[u8]) -> Result<Digest32, ProductionInputErrorV1> {
    let mut hash = Blake2bVar::new(32).map_err(|_| ProductionInputErrorV1::NonCanonicalEncoding)?;
    hash.update(domain);
    hash.update(bytes);
    let mut output = [0; 32];
    hash.finalize_variable(&mut output)
        .map_err(|_| ProductionInputErrorV1::NonCanonicalEncoding)?;
    Ok(output)
}

struct InputCursorV1<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> InputCursorV1<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    fn bytes(&mut self, length: usize) -> Result<&'a [u8], ProductionInputErrorV1> {
        let end = self
            .position
            .checked_add(length)
            .ok_or(ProductionInputErrorV1::InputBoundExceeded)?;
        let value = self
            .bytes
            .get(self.position..end)
            .ok_or(ProductionInputErrorV1::NonCanonicalEncoding)?;
        self.position = end;
        Ok(value)
    }

    fn take<const N: usize>(&mut self) -> Result<[u8; N], ProductionInputErrorV1> {
        self.bytes(N)?
            .try_into()
            .map_err(|_| ProductionInputErrorV1::NonCanonicalEncoding)
    }

    fn u8(&mut self) -> Result<u8, ProductionInputErrorV1> {
        Ok(self.take::<1>()?[0])
    }

    fn u16(&mut self) -> Result<u16, ProductionInputErrorV1> {
        Ok(u16::from_be_bytes(self.take::<2>()?))
    }

    fn u32(&mut self) -> Result<u32, ProductionInputErrorV1> {
        Ok(u32::from_be_bytes(self.take::<4>()?))
    }

    fn finish(self) -> Result<(), ProductionInputErrorV1> {
        if self.position == self.bytes.len() {
            Ok(())
        } else {
            Err(ProductionInputErrorV1::NonCanonicalEncoding)
        }
    }
}

#[cfg(test)]
mod tests {

    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::path::{Path, PathBuf};

    use deployment_registry::{RegistrySignatureV1, SignedRegistryV1};
    use k256::ecdsa::SigningKey;
    use participant_binding::{evm_account_binding_digest_v1, EVM_ACCOUNT_SIGNATURE_BYTES_V1};
    use sha3::{Digest as _, Keccak256};

    use super::*;
    use crate::production_config::{
        load_production_create_bootstrap_v1, load_production_reopen_bootstrap_v1,
        ProductionBootstrapConfigV1, ProductionPathKindV1, ProductionPathReferencesV1,
        ProductionRoutePinsV1, ProductionRuntimeBoundsV1, PRODUCTION_CREATE_CONFIG_FILE_V1,
        PRODUCTION_REOPEN_CONFIG_FILE_V1,
    };
    #[cfg(feature = "production")]
    use crate::production_config::{
        load_production_create_or_resume_bootstrap_v3, provisioning_binding_for_v3_bootstrap,
        PRODUCTION_CREATE_CONFIG_FILE_V3, PRODUCTION_REOPEN_CONFIG_FILE_V3,
    };
    use crate::route_time_test_common as time_common;

    const ROUTE_ID: RouteIdV1 = [0xA7; 32];
    const UPSTREAM_ROSTER: Digest32 = [0xA8; 32];
    const DOWNSTREAM_ROSTER: Digest32 = [0xA9; 32];
    const REGISTRY_SECRETS: [[u8; 32]; 3] = [[0x03; 32], [0x04; 32], [0x05; 32]];
    const PARTICIPANT_SECRETS: [[u8; 32]; 2] = [[0x61; 32], [0x62; 32]];
    const BITCOIN_PARTICIPANT_SECRETS: [[u8; 32]; 2] = [[0x63; 32], [0x64; 32]];
    #[cfg(feature = "production")]
    const IDENTITY_STORE_PATH_V3: &str = "inputs/contracts-transport-identity-v3";
    #[cfg(feature = "production")]
    const BUDGET_POLICY_PATH_V3: &str = "inputs/contracts-budget-policy-v3";

    struct PreparedInputs {
        _directory: tempfile::TempDir,
        root: PathBuf,
        paths: ProductionPathReferencesV1,
        bounds: ProductionRuntimeBoundsV1,
        pins: ProductionRoutePinsV1,
    }

    fn input_error(
        result: Result<AuthenticatedProductionInputsV1, ProductionInputErrorV1>,
    ) -> ProductionInputErrorV1 {
        match result {
            Ok(_) => panic!("authenticated input loader unexpectedly succeeded"),
            Err(error) => error,
        }
    }

    #[test]
    fn bitcoin_proof_pair_preserves_terms_order_instead_of_role_order() {
        let proof = |id: u8, role, key_marker: u8| {
            let mut key = [key_marker; 33];
            key[0] = if key_marker & 1 == 0 { 0x02 } else { 0x03 };
            ProductionBitcoinParticipantKeyProofV1::new(
                ParticipantId([id; 32]),
                role,
                key,
                [id.wrapping_add(1); 64],
            )
            .expect("structural Bitcoin participant proof")
        };
        ProductionBitcoinLegKeyProofsV1::new(
            ProductionRoutePositionV1::Upstream,
            [
                proof(0x11, BitcoinSignerRoleV1::Taker, 0x24),
                proof(0x22, BitcoinSignerRoleV1::Maker, 0x25),
            ],
        )
        .expect("roles do not reorder the terms roster");
        assert!(ProductionBitcoinLegKeyProofsV1::new(
            ProductionRoutePositionV1::Upstream,
            [
                proof(0x11, BitcoinSignerRoleV1::Maker, 0x24),
                proof(0x22, BitcoinSignerRoleV1::Maker, 0x25),
            ],
        )
        .is_err());
    }

    impl PreparedInputs {
        fn path(&self, role: ProductionPathRoleV1) -> PathBuf {
            self.root.join(self.paths.get(role))
        }

        fn write_manifests(&self, pins: ProductionRoutePinsV1) {
            write_bootstrap_manifests(&self.root, pins, self.bounds, self.paths.clone());
        }

        #[cfg(feature = "production")]
        fn write_manifests_v3(&self) {
            make_owner_directory(&self.root.join(IDENTITY_STORE_PATH_V3));
            write_owner_file(
                &self.root.join(BUDGET_POLICY_PATH_V3),
                b"contracts-budget-policy-fixture-v1",
            );
            let create = ProductionBootstrapConfigV1::from_parts_v3(
                ProductionBootstrapModeV1::Create,
                self.pins,
                self.bounds,
                self.paths.clone(),
                IDENTITY_STORE_PATH_V3.to_owned(),
                BUDGET_POLICY_PATH_V3.to_owned(),
            )
            .expect("V3 create config");
            let reopen = ProductionBootstrapConfigV1::from_parts_v3(
                ProductionBootstrapModeV1::ReopenExisting,
                self.pins,
                self.bounds,
                self.paths.clone(),
                IDENTITY_STORE_PATH_V3.to_owned(),
                BUDGET_POLICY_PATH_V3.to_owned(),
            )
            .expect("V3 reopen config");
            write_owner_file(
                &self.root.join(PRODUCTION_CREATE_CONFIG_FILE_V3),
                &create.canonical_bytes().expect("V3 create bytes"),
            );
            write_owner_file(
                &self.root.join(PRODUCTION_REOPEN_CONFIG_FILE_V3),
                &reopen.canonical_bytes().expect("V3 reopen bytes"),
            );
        }

        fn create_remaining_managed_state(&self) {
            for role in ProductionPathRoleV1::ALL {
                let path = self.path(role);
                match role.kind() {
                    ProductionPathKindV1::InputFile
                    | ProductionPathKindV1::ExistingAuthorityDirectory => {}
                    ProductionPathKindV1::ManagedFile if path.exists() => {}
                    ProductionPathKindV1::ManagedFile => write_owner_file(&path, b"state-v1"),
                    ProductionPathKindV1::ManagedDirectory => make_owner_directory(&path),
                }
            }
        }
    }

    fn prepare_inputs() -> PreparedInputs {
        let directory = tempfile::tempdir().expect("temporary state");
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))
            .expect("owner state root");
        let root = fs::canonicalize(directory.path()).expect("canonical root");
        for child in ["inputs", "state", "planning"] {
            make_owner_directory(&root.join(child));
        }
        let fixture = time_common::fixture();
        let (registry_authorities, signed_registry) = registry_authority(&fixture);
        let authority_bundle = ProductionAuthorityBundleV1::new(
            registry_authorities.clone(),
            fixture.policy_authorities.clone(),
            fixture.evidence_authorities.clone(),
        )
        .expect("distinct authority roles");

        let paths = path_references();
        let registry_path = root.join(paths.get(ProductionPathRoleV1::RegistryStore));
        let mut registry_store = RegistryStoreV1::create(&registry_path).expect("registry create");
        registry_store
            .install(
                &signed_registry,
                &registry_authorities,
                &fixture.secp,
                RegistryValidationPolicyV1 {
                    now_seconds: time_common::EVIDENCE_TIME,
                    expected_network_id: time_common::REGISTRY_NETWORK,
                    minimum_epoch: 7,
                },
            )
            .expect("registry install");
        drop(registry_store);

        let policy_signed = time_common::signed_policy(&fixture);
        let evidence = time_common::evidence(&fixture.policy, 1, time_common::EVIDENCE_TIME, 0);
        let evidence_signed = time_common::signed_evidence(&fixture, &evidence);
        let time_config = RouteTimeAnchorStoreConfigV2::new(
            &fixture.registry,
            &fixture.upstream,
            &fixture.downstream,
            &fixture.policy_authorities,
            &fixture.evidence_authorities,
            &fixture.secp,
        )
        .expect("time config");
        let time_policy_authority_set_digest = time_config.policy_authority_set_digest();
        let time_evidence_authority_set_digest = time_config.evidence_authority_set_digest();
        let planning_path = root.join("planning/time.sqlite3");
        let mut planning = DurableRouteTimeAnchorStoreV2::create(&planning_path, time_config)
            .expect("planning time store");
        planning
            .install_policy(
                &policy_signed,
                fixture.policy_context(),
                time_common::EVIDENCE_TIME,
            )
            .expect("planning policy");
        planning
            .install_evidence(
                &evidence_signed,
                fixture.evidence_context(),
                time_common::EVIDENCE_TIME,
            )
            .expect("planning evidence");
        let proof = planning
            .prove_route_ladder(fixture.evidence_context(), time_common::EVIDENCE_TIME)
            .expect("planning proof");
        let current = planning
            .consume_capability_at(proof, time_common::EVIDENCE_TIME)
            .expect("current planning proof");
        let composition = ComposedBindingV2::bind(
            fixture.upstream.clone(),
            fixture.downstream.clone(),
            current,
        )
        .expect("mixed composition");

        let participant_keys = participant_keys(&fixture.secp);
        let roster_bundle = roster_bundle(&fixture, participant_keys);
        let registry_for_admission = RegistryStoreV1::open_existing(&registry_path)
            .expect("reopen registry for planning admission");
        let admission_authority = RegistryRouteAdmissionAuthorityV1::new(
            registry_for_admission,
            registry_authorities.clone(),
            SecpContext::new(&[0x7A; 32]),
            time_common::REGISTRY_NETWORK,
            7,
        )
        .expect("planning admission authority");
        let admission = admission_authority
            .admit_validated_composed_route_v2(
                time_common::EVIDENCE_TIME,
                ROUTE_ID,
                &composition,
                roster_bundle.snapshots(),
            )
            .expect("planning admission");
        let participant_bundle = participant_bundle(
            &fixture,
            participant_keys,
            admission.frozen_bindings().terms_digest,
        );

        let pins = ProductionRoutePinsV1 {
            network_id: time_common::REGISTRY_NETWORK,
            route_id: ROUTE_ID,
            registry_manifest_digest: fixture.registry.manifest_digest(),
            registry_minimum_epoch: 7,
            registry_authority_set_digest: registry_authorities
                .authority_set_digest()
                .expect("registry authority digest"),
            time_policy_authority_set_digest,
            time_evidence_authority_set_digest,
            upstream_terms_digest: fixture.upstream.terms_hash().expect("upstream digest"),
            downstream_terms_digest: fixture.downstream.terms_hash().expect("downstream digest"),
            route_scope_digest: composition.route_scope_digest(),
            participant_bindings_digest: participant_bundle
                .bundle_digest()
                .expect("participant bundle digest"),
            relay_binding_digest: roster_bundle.bundle_digest().expect("roster bundle digest"),
            time_policy_digest: fixture.policy.policy_digest().expect("policy digest"),
            time_evidence_digest: evidence.evidence_digest().expect("evidence digest"),
            process_owner_id: [0xE1; 32],
            coordinator_id: [0xE2; 32],
            coordinator_plan_authority_id: [0xE3; 32],
            actuator_bindings_digest: [0xE4; 32],
            solver_inventory_binding_digest: [0xE5; 32],
        };
        let bounds = runtime_bounds();

        write_owner_file(
            &root.join(paths.get(ProductionPathRoleV1::RegistryAuthorities)),
            &authority_bundle.canonical_bytes().expect("authority bytes"),
        );
        write_owner_file(
            &root.join(paths.get(ProductionPathRoleV1::UpstreamTerms)),
            &fixture.upstream.canonical_bytes().expect("upstream bytes"),
        );
        write_owner_file(
            &root.join(paths.get(ProductionPathRoleV1::DownstreamTerms)),
            &fixture
                .downstream
                .canonical_bytes()
                .expect("downstream bytes"),
        );
        write_owner_file(
            &root.join(paths.get(ProductionPathRoleV1::ParticipantBindings)),
            &participant_bundle
                .canonical_bytes()
                .expect("participant bytes"),
        );
        write_owner_file(
            &root.join(paths.get(ProductionPathRoleV1::RelayRoster)),
            &roster_bundle.canonical_bytes().expect("roster bytes"),
        );
        write_owner_file(
            &root.join(paths.get(ProductionPathRoleV1::TimePolicy)),
            &policy_signed
                .canonical_bytes()
                .expect("signed policy bytes"),
        );
        write_owner_file(
            &root.join(paths.get(ProductionPathRoleV1::TimeEvidence)),
            &evidence_signed
                .canonical_bytes()
                .expect("signed evidence bytes"),
        );
        write_owner_file(
            &root.join(paths.get(ProductionPathRoleV1::DomWallet)),
            b"encrypted-wallet-fixture",
        );
        write_bootstrap_manifests(&root, pins, bounds, paths.clone());

        PreparedInputs {
            _directory: directory,
            root,
            paths,
            bounds,
            pins,
        }
    }

    #[test]
    fn evm_dom_bitcoin_create_journals_and_reopens_the_exact_frozen_checkpoint() {
        let prepared = prepare_inputs();
        let create = load_production_create_bootstrap_v1(&prepared.root)
            .expect("validated create bootstrap");
        let created = load_authenticated_production_inputs_v1(&create, time_common::EVIDENCE_TIME)
            .expect("authenticated create inputs");
        let created_binding = created.composition().binding_digest();
        let created_frozen = created.admission().frozen_bindings().clone();
        assert_eq!(created.admission().route_id(), ROUTE_ID);
        assert!(created.evm_session(LegIdV1::Upstream).is_some());
        assert!(created.evm_session(LegIdV1::Downstream).is_none());
        assert!(created.bitcoin_session(LegIdV1::Upstream).is_none());
        let created_bitcoin = created
            .bitcoin_session(LegIdV1::Downstream)
            .expect("authenticated downstream Bitcoin roster");
        assert_eq!(
            created_bitcoin
                .roster()
                .participants()
                .map(|participant| participant.participant_id),
            fixture_participant_ids()
        );
        let created_bitcoin_roster = *created_bitcoin.roster();
        assert!(created
            .roster_registry()
            .snapshot(&UPSTREAM_ROSTER)
            .is_some());

        assert_eq!(
            input_error(load_authenticated_production_inputs_v1(
                &create,
                time_common::EVIDENCE_TIME,
            )),
            ProductionInputErrorV1::TimeRefused
        );
        drop(created);
        prepared.create_remaining_managed_state();
        let reopen = load_production_reopen_bootstrap_v1(&prepared.root)
            .expect("validated recovery bootstrap");
        let reopened =
            load_authenticated_production_inputs_v1(&reopen, time_common::EVIDENCE_TIME + 1)
                .expect("authenticated recovery inputs");
        assert_eq!(reopened.composition().binding_digest(), created_binding);
        assert_eq!(reopened.admission().frozen_bindings(), &created_frozen);
        assert_eq!(
            reopened
                .bitcoin_session(LegIdV1::Downstream)
                .expect("recovered downstream Bitcoin roster")
                .roster(),
            &created_bitcoin_roster
        );
        assert!(reopened.current_time_ancestry_ready());
    }

    #[cfg(feature = "production")]
    #[test]
    fn provisioning_resumes_after_time_lock_publication_and_is_idempotent() {
        let prepared = prepare_inputs();
        prepared.write_manifests_v3();
        let initial = load_production_create_or_resume_bootstrap_v3(&prepared.root)
            .expect("strict initial V3 bootstrap");
        let binding =
            provisioning_binding_for_v3_bootstrap(&initial).expect("exact provisioning binding");
        let mut journal = DurableProductionProvisioningJournalV1::create(&prepared.root, binding)
            .expect("journal create");
        assert_eq!(
            journal
                .begin(ProductionProvisioningStageV1::TimeAnchorStore)
                .expect("time stage begin"),
            ProductionProvisioningStageStateV1::Started
        );
        let time_path = prepared.path(ProductionPathRoleV1::TimeAnchorStore);
        write_owner_file(&PathBuf::from(format!("{}.lock", time_path.display())), b"");
        drop(journal);

        let resumed_bootstrap = load_production_create_or_resume_bootstrap_v3(&prepared.root)
            .expect("journal-authenticated V3 resume bootstrap");
        let mut resumed_journal =
            DurableProductionProvisioningJournalV1::open(&prepared.root, binding)
                .expect("journal reopen");
        let authenticated = load_authenticated_production_inputs_with_provisioning_v1(
            &resumed_bootstrap,
            time_common::EVIDENCE_TIME,
            &mut resumed_journal,
        )
        .expect("resume exact time prefix and finish route admission");
        assert_eq!(
            resumed_journal
                .stage_state(ProductionProvisioningStageV1::TimeAnchorStore)
                .expect("time state"),
            ProductionProvisioningStageStateV1::Complete
        );
        assert_eq!(
            resumed_journal
                .stage_state(ProductionProvisioningStageV1::RouteStore)
                .expect("route state"),
            ProductionProvisioningStageStateV1::Complete
        );
        drop(authenticated);
        drop(resumed_journal);

        let route_complete = prepared
            .root
            .join("production-provisioning-v1/02-route-store.complete");
        fs::remove_file(&route_complete).expect("simulate crash before Route Complete publish");
        File::open(route_complete.parent().expect("journal root"))
            .and_then(|directory| directory.sync_all())
            .expect("durable simulated crash layout");
        let checkpoint_resume = load_production_create_or_resume_bootstrap_v3(&prepared.root)
            .expect("checkpoint committed under Started is resumable");
        let mut checkpoint_journal =
            DurableProductionProvisioningJournalV1::open(&prepared.root, binding)
                .expect("checkpoint journal reopen");
        let reopened = load_authenticated_production_inputs_with_provisioning_v1(
            &checkpoint_resume,
            time_common::EVIDENCE_TIME + 1,
            &mut checkpoint_journal,
        )
        .expect("authenticated checkpoint resume");
        assert_eq!(reopened.admission().route_id(), ROUTE_ID);
        assert_eq!(
            checkpoint_journal
                .stage_state(ProductionProvisioningStageV1::RouteStore)
                .expect("recompleted route stage"),
            ProductionProvisioningStageStateV1::Complete
        );
    }

    #[test]
    fn expired_original_proofs_recover_without_issuing_current_authorization() {
        let prepared = prepare_inputs();
        let create = load_production_create_bootstrap_v1(&prepared.root)
            .expect("validated create bootstrap");
        let created = load_authenticated_production_inputs_v1(&create, time_common::EVIDENCE_TIME)
            .expect("authenticated create inputs");
        let checkpoint = created
            .audited_route_checkpoint()
            .expect("audited create checkpoint");
        let recovery_now = checkpoint
            .time
            .valid_until_seconds
            .max(time_common::EVIDENCE_TIME + 201);
        assert!(recovery_now >= checkpoint.time.valid_until_seconds);
        drop(created);

        prepared.create_remaining_managed_state();
        let reopen = load_production_reopen_bootstrap_v1(&prepared.root)
            .expect("validated recovery bootstrap");
        let recovered = load_authenticated_production_inputs_v1(&reopen, recovery_now)
            .expect("historically authenticated recovery");
        assert_eq!(
            recovered
                .audited_route_checkpoint()
                .expect("recovered checkpoint"),
            checkpoint
        );
        assert!(!recovered.current_time_ancestry_ready());
    }

    #[test]
    fn later_time_equivocation_preserves_historical_recovery_but_blocks_current_work() {
        let prepared = prepare_inputs();
        let create = load_production_create_bootstrap_v1(&prepared.root)
            .expect("validated create bootstrap");
        let mut created =
            load_authenticated_production_inputs_v1(&create, time_common::EVIDENCE_TIME)
                .expect("authenticated create inputs");
        let checkpoint = created
            .audited_route_checkpoint()
            .expect("audited create checkpoint");
        let fixture = time_common::fixture();
        let equivocation = time_common::evidence(
            &fixture.policy,
            checkpoint.time.evidence_sequence,
            checkpoint.time.issued_at_seconds,
            1,
        );
        assert_eq!(
            created.time_store_mut().install_evidence(
                &time_common::signed_evidence(&fixture, &equivocation),
                fixture.evidence_context(),
                checkpoint.time.issued_at_seconds,
            ),
            Err(RouteTimeAnchorErrorV2::EvidenceRollback)
        );
        drop(created);

        prepared.create_remaining_managed_state();
        let reopen = load_production_reopen_bootstrap_v1(&prepared.root)
            .expect("validated recovery bootstrap");
        let recovered =
            load_authenticated_production_inputs_v1(&reopen, checkpoint.time.issued_at_seconds + 1)
                .expect("historical checkpoint survives later equivocation");
        assert_eq!(
            recovered
                .audited_route_checkpoint()
                .expect("recovered checkpoint"),
            checkpoint
        );
        assert!(!recovered.current_time_ancestry_ready());
    }

    #[test]
    fn new_time_proof_cannot_masquerade_as_the_journaled_admission() {
        let prepared = prepare_inputs();
        let create = load_production_create_bootstrap_v1(&prepared.root)
            .expect("validated create bootstrap");
        let mut created =
            load_authenticated_production_inputs_v1(&create, time_common::EVIDENCE_TIME)
                .expect("authenticated create inputs");
        let fixture = time_common::fixture();
        let replacement =
            time_common::evidence(&fixture.policy, 2, time_common::EVIDENCE_TIME + 1, 1);
        let signed_replacement = time_common::signed_evidence(&fixture, &replacement);
        created
            .time_store_mut()
            .install_evidence(
                &signed_replacement,
                fixture.evidence_context(),
                time_common::EVIDENCE_TIME + 1,
            )
            .expect("install later evidence");
        drop(created);

        write_owner_file(
            &prepared.path(ProductionPathRoleV1::TimeEvidence),
            &signed_replacement
                .canonical_bytes()
                .expect("replacement evidence bytes"),
        );
        let mut pins = prepared.pins;
        pins.time_evidence_digest = replacement
            .evidence_digest()
            .expect("replacement evidence digest");
        prepared.write_manifests(pins);
        prepared.create_remaining_managed_state();
        let reopen = load_production_reopen_bootstrap_v1(&prepared.root)
            .expect("validated recovery bootstrap");
        assert_eq!(
            input_error(load_authenticated_production_inputs_v1(
                &reopen,
                time_common::EVIDENCE_TIME + 1,
            )),
            ProductionInputErrorV1::PinMismatch
        );
    }

    #[test]
    fn substituted_time_store_without_original_ancestry_is_refused() {
        let prepared = prepare_inputs();
        let create = load_production_create_bootstrap_v1(&prepared.root)
            .expect("validated create bootstrap");
        let created = load_authenticated_production_inputs_v1(&create, time_common::EVIDENCE_TIME)
            .expect("authenticated create inputs");
        drop(created);

        let fixture = time_common::fixture();
        let time_path = prepared.path(ProductionPathRoleV1::TimeAnchorStore);
        remove_sqlite_authority(&time_path);
        let time_config = RouteTimeAnchorStoreConfigV2::new(
            &fixture.registry,
            &fixture.upstream,
            &fixture.downstream,
            &fixture.policy_authorities,
            &fixture.evidence_authorities,
            &fixture.secp,
        )
        .expect("replacement time config");
        let mut substitute = DurableRouteTimeAnchorStoreV2::create(&time_path, time_config)
            .expect("substitute time store");
        let signed_policy = time_common::signed_policy(&fixture);
        substitute
            .install_policy(
                &signed_policy,
                fixture.policy_context(),
                time_common::EVIDENCE_TIME + 1,
            )
            .expect("substitute policy");
        let later = time_common::evidence(&fixture.policy, 2, time_common::EVIDENCE_TIME + 1, 1);
        substitute
            .install_evidence(
                &time_common::signed_evidence(&fixture, &later),
                fixture.evidence_context(),
                time_common::EVIDENCE_TIME + 1,
            )
            .expect("substitute evidence");
        drop(substitute);

        prepared.create_remaining_managed_state();
        let reopen = load_production_reopen_bootstrap_v1(&prepared.root)
            .expect("validated recovery bootstrap");
        assert_eq!(
            input_error(load_authenticated_production_inputs_v1(
                &reopen,
                time_common::EVIDENCE_TIME + 1,
            )),
            ProductionInputErrorV1::TimeRefused
        );
    }

    #[test]
    fn registry_upgrade_keeps_the_old_journal_pin_recoverable() {
        let prepared = prepare_inputs();
        let create = load_production_create_bootstrap_v1(&prepared.root)
            .expect("validated create bootstrap");
        let created = load_authenticated_production_inputs_v1(&create, time_common::EVIDENCE_TIME)
            .expect("authenticated create inputs");
        let checkpoint = created
            .audited_route_checkpoint()
            .expect("audited create checkpoint");
        drop(created);

        let fixture = time_common::fixture();
        let authorities = authority_set(&fixture.secp, &REGISTRY_SECRETS);
        let mut next_manifest = fixture.registry.manifest().clone();
        next_manifest.epoch = checkpoint.registry_epoch + 1;
        let next_digest = next_manifest
            .manifest_digest()
            .expect("next registry digest");
        let signatures = REGISTRY_SECRETS
            .iter()
            .enumerate()
            .map(|(index, secret)| {
                let (signature, _) = fixture
                    .secp
                    .sign_bip340(secret, &next_digest, &[0x55 + index as u8; 32])
                    .expect("next registry signature");
                RegistrySignatureV1 {
                    signer_index: index as u16,
                    signature,
                }
            })
            .collect();
        let signed_next =
            SignedRegistryV1::new(&next_manifest, signatures).expect("signed next registry");
        let mut registry =
            RegistryStoreV1::open_existing(&prepared.path(ProductionPathRoleV1::RegistryStore))
                .expect("reopen registry for upgrade");
        registry
            .install(
                &signed_next,
                &authorities,
                &fixture.secp,
                RegistryValidationPolicyV1 {
                    now_seconds: time_common::EVIDENCE_TIME + 1,
                    expected_network_id: time_common::REGISTRY_NETWORK,
                    minimum_epoch: checkpoint.registry_epoch,
                },
            )
            .expect("install registry upgrade");
        drop(registry);

        prepared.create_remaining_managed_state();
        let reopen = load_production_reopen_bootstrap_v1(&prepared.root)
            .expect("validated recovery bootstrap");
        let recovered =
            load_authenticated_production_inputs_v1(&reopen, time_common::EVIDENCE_TIME + 1)
                .expect("recover old registry pin after upgrade");
        assert_eq!(
            recovered.resolved_registry().manifest_digest(),
            checkpoint.registry_manifest_digest
        );
        assert_eq!(
            recovered.resolved_registry().epoch(),
            checkpoint.registry_epoch
        );
    }

    #[test]
    fn journal_and_snapshot_tamper_are_refused_by_the_loader() {
        let journal = prepare_inputs();
        let create =
            load_production_create_bootstrap_v1(&journal.root).expect("validated create bootstrap");
        let created = load_authenticated_production_inputs_v1(&create, time_common::EVIDENCE_TIME)
            .expect("authenticated create inputs");
        let checkpoint = created
            .audited_route_checkpoint()
            .expect("audited create checkpoint");
        let event_bytes = RouteEventV1::FreezeTermsV2(Box::new(checkpoint))
            .encode_canonical()
            .expect("freeze event bytes");
        drop(created);
        tamper_unique_sqlite_blob(
            &journal.path(ProductionPathRoleV1::RouteStore),
            &event_bytes,
        );
        journal.create_remaining_managed_state();
        let reopen = load_production_reopen_bootstrap_v1(&journal.root)
            .expect("validated journal recovery bootstrap");
        assert_eq!(
            input_error(load_authenticated_production_inputs_v1(
                &reopen,
                time_common::EVIDENCE_TIME + 1,
            )),
            ProductionInputErrorV1::RouteStateRefused
        );

        let snapshot = prepare_inputs();
        let create = load_production_create_bootstrap_v1(&snapshot.root)
            .expect("validated create bootstrap");
        let created = load_authenticated_production_inputs_v1(&create, time_common::EVIDENCE_TIME)
            .expect("authenticated create inputs");
        let snapshot_bytes = created
            .route_store
            .load_snapshot(ROUTE_ID)
            .expect("route snapshot")
            .encode_canonical()
            .expect("snapshot bytes");
        drop(created);
        tamper_unique_sqlite_blob(
            &snapshot.path(ProductionPathRoleV1::RouteStore),
            &snapshot_bytes,
        );
        snapshot.create_remaining_managed_state();
        let reopen = load_production_reopen_bootstrap_v1(&snapshot.root)
            .expect("validated snapshot recovery bootstrap");
        assert_eq!(
            input_error(load_authenticated_production_inputs_v1(
                &reopen,
                time_common::EVIDENCE_TIME + 1,
            )),
            ProductionInputErrorV1::RouteStateRefused
        );
    }

    #[test]
    fn authority_pin_terms_pin_and_stale_evidence_fail_closed() {
        let wrong_authority = prepare_inputs();
        let original = ProductionAuthorityBundleV1::decode_canonical(
            &fs::read(wrong_authority.path(ProductionPathRoleV1::RegistryAuthorities))
                .expect("authority file"),
        )
        .expect("authority bundle");
        let replacement = authority_set(
            &SecpContext::new(&[0x91; 32]),
            &[[0x31; 32], [0x32; 32], [0x33; 32]],
        );
        let altered = ProductionAuthorityBundleV1::new(
            original.registry.clone(),
            replacement,
            original.time_evidence.clone(),
        )
        .expect("distinct replacement");
        write_owner_file(
            &wrong_authority.path(ProductionPathRoleV1::RegistryAuthorities),
            &altered.canonical_bytes().expect("altered authority bytes"),
        );
        let bootstrap = load_production_create_bootstrap_v1(&wrong_authority.root)
            .expect("physical create bootstrap");
        assert_eq!(
            input_error(load_authenticated_production_inputs_v1(
                &bootstrap,
                time_common::EVIDENCE_TIME,
            )),
            ProductionInputErrorV1::PinMismatch
        );

        let terms_tamper = prepare_inputs();
        let terms_path = terms_tamper.path(ProductionPathRoleV1::UpstreamTerms);
        let mut terms = fs::read(&terms_path).expect("terms bytes");
        terms[74] ^= 1;
        write_owner_file(&terms_path, &terms);
        let bootstrap = load_production_create_bootstrap_v1(&terms_tamper.root)
            .expect("physical create bootstrap");
        assert_eq!(
            input_error(load_authenticated_production_inputs_v1(
                &bootstrap,
                time_common::EVIDENCE_TIME,
            )),
            ProductionInputErrorV1::PinMismatch
        );

        let stale = prepare_inputs();
        let bootstrap =
            load_production_create_bootstrap_v1(&stale.root).expect("physical create bootstrap");
        assert_eq!(
            input_error(load_authenticated_production_inputs_v1(
                &bootstrap,
                time_common::EVIDENCE_TIME + 300,
            )),
            ProductionInputErrorV1::AdmissionRefused
        );
    }

    #[test]
    fn participant_signature_bundle_pin_and_cross_leg_substitution_are_refused() {
        let signature_tamper = prepare_inputs();
        let participant_path = signature_tamper.path(ProductionPathRoleV1::ParticipantBindings);
        let mut bytes = fs::read(&participant_path).expect("participant bytes");
        let last = bytes.len() - 1;
        bytes[last] ^= 1;
        let tampered = ProductionParticipantBindingBundleV1::decode_canonical(&bytes)
            .expect("signature bytes remain canonical");
        write_owner_file(&participant_path, &bytes);
        let mut pins = signature_tamper.pins;
        pins.participant_bindings_digest = tampered.bundle_digest().expect("tampered digest");
        signature_tamper.write_manifests(pins);
        let bootstrap = load_production_create_bootstrap_v1(&signature_tamper.root)
            .expect("physical create bootstrap");
        assert_eq!(
            input_error(load_authenticated_production_inputs_v1(
                &bootstrap,
                time_common::EVIDENCE_TIME,
            )),
            ProductionInputErrorV1::InvalidParticipantBundle
        );

        let cross_leg = prepare_inputs();
        let participant_path = cross_leg.path(ProductionPathRoleV1::ParticipantBindings);
        let mut bytes = fs::read(&participant_path).expect("participant bytes");
        bytes[48] = 2;
        bytes[52 + 12 + 9 * 32 + 20] = 2;
        bytes[52 + EVM_ACCOUNT_BINDING_PROOF_BYTES_V1 + 12 + 9 * 32 + 20] = 2;
        let substituted = ProductionParticipantBindingBundleV1::decode_canonical(&bytes)
            .expect("cross-leg file remains canonical");
        write_owner_file(&participant_path, &bytes);
        let mut pins = cross_leg.pins;
        pins.participant_bindings_digest = substituted.bundle_digest().expect("cross-leg digest");
        cross_leg.write_manifests(pins);
        let bootstrap = load_production_create_bootstrap_v1(&cross_leg.root)
            .expect("physical create bootstrap");
        assert_eq!(
            input_error(load_authenticated_production_inputs_v1(
                &bootstrap,
                time_common::EVIDENCE_TIME,
            )),
            ProductionInputErrorV1::InvalidParticipantBundle
        );
    }

    #[test]
    fn bitcoin_key_bindings_refuse_cross_participant_and_cross_leg_transplants() {
        let cross_participant = prepare_inputs();
        let participant_path = cross_participant.path(ProductionPathRoleV1::ParticipantBindings);
        let mut bundle = ProductionParticipantBindingBundleV1::decode_canonical(
            &fs::read(&participant_path).expect("participant bytes"),
        )
        .expect("participant bundle");
        let first = bundle.bitcoin_legs[0].participants[0];
        let second = bundle.bitcoin_legs[0].participants[1];
        bundle.bitcoin_legs[0].participants[0].compressed_key = second.compressed_key;
        bundle.bitcoin_legs[0].participants[0].signature = second.signature;
        bundle.bitcoin_legs[0].participants[1].compressed_key = first.compressed_key;
        bundle.bitcoin_legs[0].participants[1].signature = first.signature;
        let bytes = bundle
            .canonical_bytes()
            .expect("cross-participant bundle remains canonical");
        write_owner_file(&participant_path, &bytes);
        let mut pins = cross_participant.pins;
        pins.participant_bindings_digest = bundle
            .bundle_digest()
            .expect("cross-participant bundle digest");
        cross_participant.write_manifests(pins);
        let bootstrap = load_production_create_bootstrap_v1(&cross_participant.root)
            .expect("physical create bootstrap");
        assert_eq!(
            input_error(load_authenticated_production_inputs_v1(
                &bootstrap,
                time_common::EVIDENCE_TIME,
            )),
            ProductionInputErrorV1::InvalidParticipantBundle
        );

        let cross_leg = prepare_inputs();
        let participant_path = cross_leg.path(ProductionPathRoleV1::ParticipantBindings);
        let mut bundle = ProductionParticipantBindingBundleV1::decode_canonical(
            &fs::read(&participant_path).expect("participant bytes"),
        )
        .expect("participant bundle");
        bundle.bitcoin_legs[0].position = ProductionRoutePositionV1::Upstream;
        let bytes = bundle
            .canonical_bytes()
            .expect("cross-leg bundle remains canonical");
        write_owner_file(&participant_path, &bytes);
        let mut pins = cross_leg.pins;
        pins.participant_bindings_digest = bundle.bundle_digest().expect("cross-leg bundle digest");
        cross_leg.write_manifests(pins);
        let bootstrap = load_production_create_bootstrap_v1(&cross_leg.root)
            .expect("physical create bootstrap");
        assert_eq!(
            input_error(load_authenticated_production_inputs_v1(
                &bootstrap,
                time_common::EVIDENCE_TIME,
            )),
            ProductionInputErrorV1::InvalidParticipantBundle
        );
    }

    #[test]
    fn participant_bundle_pin_mismatch_is_refused() {
        let pin_mismatch = prepare_inputs();
        let mut pins = pin_mismatch.pins;
        pins.participant_bindings_digest = [0xF1; 32];
        pin_mismatch.write_manifests(pins);
        let bootstrap = load_production_create_bootstrap_v1(&pin_mismatch.root)
            .expect("physical create bootstrap");
        assert_eq!(
            input_error(load_authenticated_production_inputs_v1(
                &bootstrap,
                time_common::EVIDENCE_TIME,
            )),
            ProductionInputErrorV1::PinMismatch
        );
    }

    #[test]
    fn all_public_bundle_codecs_reject_trailing_bytes() {
        let prepared = prepare_inputs();
        for (role, maximum) in [
            (
                ProductionPathRoleV1::RegistryAuthorities,
                MAX_PRODUCTION_AUTHORITY_BUNDLE_BYTES_V1,
            ),
            (
                ProductionPathRoleV1::RelayRoster,
                PRODUCTION_ROSTER_BUNDLE_BYTES_V1,
            ),
            (
                ProductionPathRoleV1::ParticipantBindings,
                MAX_PRODUCTION_PARTICIPANT_BUNDLE_BYTES_V1,
            ),
        ] {
            let mut bytes = fs::read(prepared.path(role)).expect("bundle bytes");
            bytes.push(0);
            let rejected = match role {
                ProductionPathRoleV1::RegistryAuthorities => {
                    ProductionAuthorityBundleV1::decode_canonical(&bytes).is_err()
                }
                ProductionPathRoleV1::RelayRoster => {
                    ProductionRelayRosterBundleV1::decode_canonical(&bytes).is_err()
                }
                ProductionPathRoleV1::ParticipantBindings => {
                    ProductionParticipantBindingBundleV1::decode_canonical(&bytes).is_err()
                }
                _ => unreachable!(),
            };
            assert!(rejected, "trailing bytes accepted for {role:?}/{maximum}");
        }
    }

    #[test]
    fn authority_roles_and_settlement_sessions_cannot_be_reused() {
        let fixture = time_common::fixture();
        assert_eq!(
            ProductionAuthorityBundleV1::new(
                fixture.policy_authorities.clone(),
                fixture.policy_authorities.clone(),
                fixture.evidence_authorities,
            )
            .expect_err("one set cannot govern two roles"),
            ProductionInputErrorV1::InvalidAuthorityBundle
        );

        let prepared = prepare_inputs();
        let roster = ProductionRelayRosterBundleV1::decode_canonical(
            &fs::read(prepared.path(ProductionPathRoleV1::RelayRoster))
                .expect("roster bundle bytes"),
        )
        .expect("canonical roster bundle");
        let mut legs = *roster.legs();
        legs[1].session_id = legs[0].session_id;
        assert_eq!(
            ProductionRelayRosterBundleV1::new(roster.network_id(), roster.route_id(), legs)
                .expect_err("two settlements cannot share a session"),
            ProductionInputErrorV1::InvalidRosterBundle
        );
    }

    #[test]
    fn oversized_signed_time_input_is_refused_before_decode_or_store_creation() {
        let prepared = prepare_inputs();
        write_owner_file(
            &prepared.path(ProductionPathRoleV1::TimePolicy),
            &vec![0xAA; MAX_SIGNED_TIME_POLICY_ARTIFACT_BYTES_V1 as usize + 1],
        );
        let bootstrap =
            load_production_create_bootstrap_v1(&prepared.root).expect("physical create bootstrap");
        assert_eq!(
            input_error(load_authenticated_production_inputs_v1(
                &bootstrap,
                time_common::EVIDENCE_TIME,
            )),
            ProductionInputErrorV1::InputBoundExceeded
        );
        assert!(!prepared
            .path(ProductionPathRoleV1::TimeAnchorStore)
            .exists());
    }

    fn registry_authority(fixture: &time_common::Fixture) -> (AuthoritySetV1, SignedRegistryV1) {
        let digest = fixture
            .registry
            .manifest()
            .manifest_digest()
            .expect("manifest digest");
        let authorities = authority_set(&fixture.secp, &REGISTRY_SECRETS);
        let signatures = REGISTRY_SECRETS
            .iter()
            .enumerate()
            .map(|(index, secret)| {
                let (signature, _) = fixture
                    .secp
                    .sign_bip340(secret, &digest, &[0x50 + index as u8; 32])
                    .expect("registry signature");
                RegistrySignatureV1 {
                    signer_index: index as u16,
                    signature,
                }
            })
            .collect();
        (
            authorities,
            SignedRegistryV1::new(fixture.registry.manifest(), signatures)
                .expect("signed registry"),
        )
    }

    fn authority_set(secp: &SecpContext, secrets: &[[u8; 32]]) -> AuthoritySetV1 {
        AuthoritySetV1::new(
            2,
            secrets
                .iter()
                .enumerate()
                .map(|(index, secret)| {
                    secp.sign_bip340(secret, &[0x41; 32], &[0x42 + index as u8; 32])
                        .expect("public key")
                        .1
                })
                .collect(),
        )
        .expect("authority set")
    }

    fn participant_keys(secp: &SecpContext) -> [[u8; 32]; 2] {
        std::array::from_fn(|index| {
            secp.sign_bip340(
                &PARTICIPANT_SECRETS[index],
                &[0x41; 32],
                &[0x81 + index as u8; 32],
            )
            .expect("participant key")
            .1
        })
    }

    fn roster_bundle(
        fixture: &time_common::Fixture,
        participant_keys: [[u8; 32]; 2],
    ) -> ProductionRelayRosterBundleV1 {
        let members = [
            ProductionRosterMemberV1 {
                participant_id: fixture.upstream.roster[0],
                xonly_key: participant_keys[0],
                role: SenderRoleV1::Initiator,
            },
            ProductionRosterMemberV1 {
                participant_id: fixture.upstream.roster[1],
                xonly_key: participant_keys[1],
                role: SenderRoleV1::Solver,
            },
        ];
        ProductionRelayRosterBundleV1::new(
            time_common::REGISTRY_NETWORK,
            ROUTE_ID,
            [
                ProductionRosterLegV1 {
                    position: ProductionRoutePositionV1::Upstream,
                    session_id: fixture.upstream.session_id.0,
                    roster_snapshot: UPSTREAM_ROSTER,
                    policy_version: fixture.upstream.policy_version,
                    members,
                },
                ProductionRosterLegV1 {
                    position: ProductionRoutePositionV1::Downstream,
                    session_id: fixture.downstream.session_id.0,
                    roster_snapshot: DOWNSTREAM_ROSTER,
                    policy_version: fixture.downstream.policy_version,
                    members,
                },
            ],
        )
        .expect("roster bundle")
    }

    fn participant_bundle(
        fixture: &time_common::Fixture,
        participant_keys: [[u8; 32]; 2],
        frozen_terms: Digest32,
    ) -> ProductionParticipantBindingBundleV1 {
        let funder_index = fixture
            .upstream
            .roster
            .iter()
            .position(|participant| *participant == fixture.upstream.counterparty_leg.refund_to)
            .expect("funder in roster");
        let beneficiary_index = fixture
            .upstream
            .roster
            .iter()
            .position(|participant| *participant == fixture.upstream.counterparty_leg.beneficiary)
            .expect("beneficiary in roster");
        let funder = signed_participant_proof(ParticipantProofFixtureV1 {
            terms: &fixture.upstream,
            registry_digest: fixture.registry.manifest_digest(),
            frozen_terms,
            roster_snapshot: UPSTREAM_ROSTER,
            position: ProductionRoutePositionV1::Upstream,
            role: EvmBindingRoleV1::Funder,
            participant_id: fixture.upstream.counterparty_leg.refund_to,
            participant_key: participant_keys[funder_index],
            participant_secret: PARTICIPANT_SECRETS[funder_index],
            evm_secret: [0x71; 32],
        });
        let beneficiary = signed_participant_proof(ParticipantProofFixtureV1 {
            terms: &fixture.upstream,
            registry_digest: fixture.registry.manifest_digest(),
            frozen_terms,
            roster_snapshot: UPSTREAM_ROSTER,
            position: ProductionRoutePositionV1::Upstream,
            role: EvmBindingRoleV1::Beneficiary,
            participant_id: fixture.upstream.counterparty_leg.beneficiary,
            participant_key: participant_keys[beneficiary_index],
            participant_secret: PARTICIPANT_SECRETS[beneficiary_index],
            evm_secret: [0x72; 32],
        });
        let deployment = fixture
            .registry
            .resolve_chain(time_common::BTC_CHAIN)
            .expect("Bitcoin chain")
            .bitcoin_deployment_capability()
            .expect("Bitcoin deployment");
        let bitcoin_participants = std::array::from_fn(|index| {
            let role = if index == 0 {
                BitcoinSignerRoleV1::Maker
            } else {
                BitcoinSignerRoleV1::Taker
            };
            let bitcoin_public_key = compressed_public_key(BITCOIN_PARTICIPANT_SECRETS[index]);
            let statement = ProductionBitcoinParticipantKeyStatementRequestV1 {
                network_id: time_common::REGISTRY_NETWORK,
                route_id: ROUTE_ID,
                position: ProductionRoutePositionV1::Downstream,
                session_id: fixture.downstream.session_id.0,
                terms_digest: fixture
                    .downstream
                    .terms_hash()
                    .expect("downstream terms digest"),
                roster_snapshot: DOWNSTREAM_ROSTER,
                participant_id: fixture.downstream.roster[index],
                role,
                relay_xonly_key: participant_keys[index],
                bitcoin_public_key,
                registry_digest: deployment.registry_digest(),
                registry_epoch: deployment.registry_epoch(),
                profile_digest: deployment.profile_digest(),
                asset_binding_digest: deployment.asset_binding_digest(),
                chain_id: deployment.profile().chain_id.0,
                genesis_hash: deployment.deployment().genesis_hash,
            };
            let digest = statement.digest().expect("Bitcoin key statement");
            let (signature, signer) = fixture
                .secp
                .sign_bip340(
                    &PARTICIPANT_SECRETS[index],
                    &digest,
                    &[0x91 + index as u8; 32],
                )
                .expect("Bitcoin key proof");
            assert_eq!(signer, participant_keys[index]);
            ProductionBitcoinParticipantKeyProofV1::new(
                fixture.downstream.roster[index],
                role,
                bitcoin_public_key,
                signature,
            )
            .expect("canonical Bitcoin participant proof")
        });
        ProductionParticipantBindingBundleV1::new_with_bitcoin_bindings(
            ROUTE_ID,
            vec![ProductionEvmLegProofsV1::new(
                ProductionRoutePositionV1::Upstream,
                funder,
                beneficiary,
            )
            .expect("upstream proof pair")],
            vec![ProductionBitcoinLegKeyProofsV1::new(
                ProductionRoutePositionV1::Downstream,
                bitcoin_participants,
            )
            .expect("downstream Bitcoin proof pair")],
        )
        .expect("participant bundle")
    }

    fn compressed_public_key(secret: [u8; 32]) -> [u8; 33] {
        SigningKey::from_slice(&secret)
            .expect("valid Bitcoin participant key")
            .verifying_key()
            .to_encoded_point(true)
            .as_bytes()
            .try_into()
            .expect("compressed SEC1 key")
    }

    const fn fixture_participant_ids() -> [[u8; 32]; 2] {
        [[0xb1; 32], [0xb2; 32]]
    }

    struct ParticipantProofFixtureV1<'a> {
        terms: &'a SettlementTermsV1,
        registry_digest: Digest32,
        frozen_terms: Digest32,
        roster_snapshot: Digest32,
        position: ProductionRoutePositionV1,
        role: EvmBindingRoleV1,
        participant_id: ParticipantId,
        participant_key: [u8; 32],
        participant_secret: [u8; 32],
        evm_secret: [u8; 32],
    }

    fn signed_participant_proof(input: ParticipantProofFixtureV1<'_>) -> EvmAccountBindingProofV1 {
        let statement = participant_binding::EvmAccountBindingStatementV1 {
            network_id: time_common::REGISTRY_NETWORK,
            registry_digest: input.registry_digest,
            route_id: ROUTE_ID,
            settlement_id: input.terms.settlement_id.0,
            session_id: input.terms.session_id.0,
            terms_digest: input.frozen_terms,
            roster_snapshot: input.roster_snapshot,
            participant_id: input.participant_id,
            participant_xonly_key: input.participant_key,
            account: evm_account(input.evm_secret),
            position: input.position.evm_position(),
            role: input.role,
            issued_at: time_common::EVIDENCE_TIME - 100,
            valid_until: time_common::EVIDENCE_TIME + 200,
            evm_chain_id: 31_337,
        };
        let digest = evm_account_binding_digest_v1(&statement).expect("EIP-712 digest");
        let signing = SigningKey::from_slice(&input.evm_secret).expect("EVM signing key");
        let (signature, recovery) = signing
            .sign_prehash_recoverable(&digest)
            .expect("recoverable EVM signature");
        let mut evm_signature = [0; EVM_ACCOUNT_SIGNATURE_BYTES_V1];
        evm_signature[..64].copy_from_slice(&signature.to_bytes());
        evm_signature[64] = 27 + recovery.to_byte();
        let secp = SecpContext::new(&[0x83; 32]);
        let (participant_signature, signed_key) = secp
            .sign_bip340(&input.participant_secret, &digest, &[0x84; 32])
            .expect("participant signature");
        assert_eq!(signed_key, input.participant_key);
        EvmAccountBindingProofV1::new(statement, evm_signature, participant_signature)
    }

    fn evm_account(secret: [u8; 32]) -> [u8; 20] {
        let key = SigningKey::from_slice(&secret).expect("valid EVM key");
        let encoded = key.verifying_key().to_encoded_point(false);
        let hash = Keccak256::digest(&encoded.as_bytes()[1..]);
        let mut account = [0; 20];
        account.copy_from_slice(&hash[12..]);
        account
    }

    fn path_references() -> ProductionPathReferencesV1 {
        ProductionPathReferencesV1::from_ordered(
            [
                "inputs/registry.sqlite3",
                "inputs/authorities.v1",
                "inputs/upstream-terms.v1",
                "inputs/downstream-terms.v1",
                "inputs/participant-bindings.v1",
                "inputs/relay-roster.v1",
                "inputs/time-policy.v2",
                "inputs/time-evidence.v2",
                "inputs/dom-wallet.v1",
                "state/route.sqlite3",
                "state/time-anchor.sqlite3",
                "state/coordinator.sqlite3",
                "state/dom-actuator.sqlite3",
                "state/evm-actuator.sqlite3",
                "state/bitcoin-actuator.sqlite3",
                "state/bitcoin-participant.v1",
                "state/dom-upstream-participant.v1",
                "state/dom-downstream-participant.v1",
                "state/solver-inventory.sqlite3",
                "state/relay-queue",
                "state/upstream-sender",
                "state/upstream-inbox",
                "state/upstream-frames",
                "state/upstream-contracts",
                "state/downstream-sender",
                "state/downstream-inbox",
                "state/downstream-frames",
                "state/downstream-contracts",
            ]
            .map(str::to_owned),
        )
        .expect("canonical path references")
    }

    const fn runtime_bounds() -> ProductionRuntimeBoundsV1 {
        ProductionRuntimeBoundsV1 {
            lease_duration_ms: 120_000,
            renew_before_ms: 30_000,
            dispatch_lease_ms: 20_000,
            coordinator_lease_ms: 60_000,
            actuator_lease_ms: 60_000,
            external_call_timeout_ms: 5_000,
            waiting_backoff_ms: 1_000,
            recovery_backoff_ms: 100,
            relay_poll_backoff_ms: 100,
            per_queue_batch_limit: 1,
        }
    }

    fn write_bootstrap_manifests(
        root: &Path,
        pins: ProductionRoutePinsV1,
        bounds: ProductionRuntimeBoundsV1,
        paths: ProductionPathReferencesV1,
    ) {
        let create = ProductionBootstrapConfigV1::from_parts(
            ProductionBootstrapModeV1::Create,
            pins,
            bounds,
            paths.clone(),
        )
        .expect("create config");
        let reopen = ProductionBootstrapConfigV1::from_parts(
            ProductionBootstrapModeV1::ReopenExisting,
            pins,
            bounds,
            paths,
        )
        .expect("reopen config");
        write_owner_file(
            &root.join(PRODUCTION_CREATE_CONFIG_FILE_V1),
            &create.canonical_bytes().expect("create config bytes"),
        );
        write_owner_file(
            &root.join(PRODUCTION_REOPEN_CONFIG_FILE_V1),
            &reopen.canonical_bytes().expect("reopen config bytes"),
        );
    }

    fn make_owner_directory(path: &Path) {
        fs::create_dir(path).expect("create owner directory");
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).expect("owner directory mode");
    }

    fn sqlite_sidecar(path: &Path, suffix: &str) -> PathBuf {
        let mut value = path.as_os_str().to_os_string();
        value.push(suffix);
        PathBuf::from(value)
    }

    fn remove_sqlite_authority(path: &Path) {
        for candidate in [
            path.to_path_buf(),
            sqlite_sidecar(path, "-wal"),
            sqlite_sidecar(path, "-shm"),
            sqlite_sidecar(path, "-journal"),
            sqlite_sidecar(path, ".lock"),
        ] {
            match fs::remove_file(&candidate) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => panic!("remove temporary SQLite authority: {error}"),
            }
        }
    }

    fn tamper_unique_sqlite_blob(path: &Path, needle: &[u8]) {
        assert!(!needle.is_empty());
        let candidates = [
            path.to_path_buf(),
            sqlite_sidecar(path, "-wal"),
            sqlite_sidecar(path, "-journal"),
        ];
        let mut located = Vec::new();
        for candidate in candidates {
            let Ok(bytes) = fs::read(&candidate) else {
                continue;
            };
            for offset in bytes
                .windows(needle.len())
                .enumerate()
                .filter_map(|(offset, bytes)| (bytes == needle).then_some(offset))
            {
                located.push((candidate.clone(), offset));
            }
        }
        assert_eq!(located.len(), 1, "expected one exact SQLite BLOB");
        let (candidate, offset) = located.pop().expect("one located BLOB");
        let mut bytes = fs::read(&candidate).expect("read retained SQLite bytes");
        let byte = offset + needle.len() - 1;
        bytes[byte] ^= 1;
        write_owner_file(&candidate, &bytes);
    }

    fn write_owner_file(path: &Path, bytes: &[u8]) {
        fs::write(path, bytes).expect("write owner file");
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).expect("owner file mode");
    }

    fn synthetic_solana_leg(position: ProductionRoutePositionV1) -> ProductionSolanaLegSetupV1 {
        let profile = SolanaAdapterProfileV1 {
            network: SolanaAdapterNetworkV1::Devnet,
            program_id: SolanaPubkey([0x11; 32]),
            rpc_node_count: 3,
            rpc_quorum: 2,
            allow_legacy_spl: false,
            require_immutable_program: true,
            max_signed_transaction_bytes: 1232,
        };
        let claim = {
            // A structurally valid 65-byte claim: compressed secp prefix plus
            // arbitrary coordinates. Codec tests never verify the DLEQ.
            let mut bytes = [0x22u8; 65];
            bytes[0] = 0x02;
            CrossCurvePublicClaim::from_canonical_bytes(&bytes).expect("claim bytes")
        };
        let binding = SolanaSetupBindingV1 {
            settlement_id: [0x31; 32],
            terms_hash: [0x32; 32],
            dleq: BoundCrossCurveProofV1 {
                version: 1,
                settlement_id: [0x31; 32],
                context_hash: [0x33; 32],
                role: 3,
                bundle: CrossCurveProofBytes {
                    version: 1,
                    proof: vec![0x44; 96],
                    claim,
                },
            },
            program_id: SolanaPubkey([0x11; 32]),
            state_pda: SolanaPubkey([0x51; 32]),
            vault_pda: SolanaPubkey([0x52; 32]),
            vault_authority: SolanaPubkey([0x53; 32]),
            state_bump: 254,
            vault_bump: 253,
            authority_bump: 252,
            asset: SolanaAssetV1::NativeSol,
            funder: SolanaPubkey([0x61; 32]),
            recipient: SolanaPubkey([0x62; 32]),
            refund_recipient: SolanaPubkey([0x63; 32]),
            amount: 5_000_000,
            refund_after_unix: 1_900_000_000,
            program_data_hash: [0x71; 32],
            setup_id: [0x72; 32],
        };
        ProductionSolanaLegSetupV1::new(position, profile, binding).expect("solana leg")
    }

    #[test]
    fn solana_leg_bundle_round_trips_canonically() {
        let bundle = ProductionParticipantBindingBundleV1::new_with_counterparty_bindings(
            ROUTE_ID,
            Vec::new(),
            Vec::new(),
            vec![synthetic_solana_leg(ProductionRoutePositionV1::Downstream)],
        )
        .expect("bundle");
        let bytes = bundle.canonical_bytes().expect("encode");
        let decoded =
            ProductionParticipantBindingBundleV1::decode_canonical(&bytes).expect("decode");
        assert_eq!(decoded.solana_legs().len(), 1);
        assert_eq!(decoded.canonical_bytes().expect("re-encode"), bytes);
        assert_eq!(decoded, bundle);
    }

    #[test]
    fn solana_leg_bundle_refuses_tampered_and_trailing_bytes() {
        let bundle = ProductionParticipantBindingBundleV1::new_with_counterparty_bindings(
            ROUTE_ID,
            Vec::new(),
            Vec::new(),
            vec![
                synthetic_solana_leg(ProductionRoutePositionV1::Upstream),
                synthetic_solana_leg(ProductionRoutePositionV1::Downstream),
            ],
        )
        .expect("bundle");
        let bytes = bundle.canonical_bytes().expect("encode");
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(ProductionParticipantBindingBundleV1::decode_canonical(&trailing).is_err());
        // A layout marker claiming the extended section without carrying it.
        let mut hollow = bytes.clone();
        hollow.truncate(bytes.len() - 1);
        assert!(ProductionParticipantBindingBundleV1::decode_canonical(&hollow).is_err());
        // Flipping the layout marker back to the legacy encoding must refuse
        // the trailing Solana section rather than silently ignoring it.
        let mut relabeled = bytes;
        relabeled[10] = 0;
        relabeled[11] = 0;
        assert!(ProductionParticipantBindingBundleV1::decode_canonical(&relabeled).is_err());
    }

    fn synthetic_monero_leg(position: ProductionRoutePositionV1) -> ProductionXmrLegSetupV1 {
        let profile = XmrAdapterProfileV1 {
            network: XmrNetwork::Stagenet,
            sidecar_api_version: 2,
            rpc_node_count: 3,
            rpc_quorum: 2,
            max_raw_tx_bytes: 131_072,
        };
        let claim = {
            let mut bytes = [0x25u8; 65];
            bytes[0] = 0x03;
            CrossCurvePublicClaim::from_canonical_bytes(&bytes).expect("claim bytes")
        };
        let binding = XmrSetupBindingV1 {
            settlement_id: [0x41; 32],
            terms_hash: [0x42; 32],
            dleq: BoundCrossCurveProofV1 {
                version: 1,
                settlement_id: [0x41; 32],
                context_hash: [0x43; 32],
                role: 1,
                bundle: CrossCurveProofBytes {
                    version: 1,
                    proof: vec![0x45; 128],
                    claim,
                },
            },
            funding_tx_hash: [0x46; 32],
            expected_amount_piconero: 7_000_000_000,
            destination: "5stagenetDestinationAddressFixture".to_string(),
            combined_spend_public_key: [0x47; 32],
        };
        ProductionXmrLegSetupV1::new(position, profile, binding).expect("monero leg")
    }

    #[test]
    fn monero_leg_refund_arm_round_trips_and_bounds_are_enforced() {
        let leg = synthetic_monero_leg(ProductionRoutePositionV1::Upstream);
        let refund_claim = {
            let mut bytes = [0x27u8; 65];
            bytes[0] = 0x02;
            CrossCurvePublicClaim::from_canonical_bytes(&bytes).expect("claim bytes")
        };
        let refund = ProductionXmrRefundBundleV1 {
            proof: BoundCrossCurveProofV1 {
                version: 1,
                settlement_id: [0x41; 32],
                context_hash: [0x48; 32],
                role: 2,
                bundle: CrossCurveProofBytes {
                    version: 1,
                    proof: vec![0x49; 64],
                    claim: refund_claim,
                },
            },
            template_hash: [0x4a; 32],
            adaptor_point_sec1: {
                let mut point = [0x4b; 33];
                point[0] = 0x02;
                point
            },
            executor_profile_hash: [0x4c; 32],
            deadline: 1_900_000_100,
        };
        let leg = leg.with_refund(refund.clone()).expect("refund arm");
        let bundle = ProductionParticipantBindingBundleV1::new_with_all_counterparty_bindings(
            ROUTE_ID,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            vec![leg.clone()],
        )
        .expect("bundle");
        let bytes = bundle.canonical_bytes().expect("encode");
        let decoded =
            ProductionParticipantBindingBundleV1::decode_canonical(&bytes).expect("decode");
        assert_eq!(decoded, bundle);
        assert_eq!(decoded.monero_legs()[0].refund, Some(refund.clone()));
        // A zero template hash cannot enter through the constructor.
        let mut broken = refund;
        broken.template_hash = ZERO_DIGEST;
        assert!(synthetic_monero_leg(ProductionRoutePositionV1::Upstream)
            .with_refund(broken)
            .is_err());
    }

    #[test]
    fn monero_leg_bundle_round_trips_canonically() {
        let bundle = ProductionParticipantBindingBundleV1::new_with_all_counterparty_bindings(
            ROUTE_ID,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            vec![synthetic_monero_leg(ProductionRoutePositionV1::Upstream)],
        )
        .expect("bundle");
        let bytes = bundle.canonical_bytes().expect("encode");
        // Layout bitmask: monero only.
        assert_eq!(&bytes[10..12], &[0, 2]);
        let decoded =
            ProductionParticipantBindingBundleV1::decode_canonical(&bytes).expect("decode");
        assert_eq!(decoded.monero_legs().len(), 1);
        assert_eq!(decoded.canonical_bytes().expect("re-encode"), bytes);
        assert_eq!(decoded, bundle);
    }

    #[test]
    fn combined_solana_and_monero_bundle_round_trips_and_refuses_tampering() {
        let bundle = ProductionParticipantBindingBundleV1::new_with_all_counterparty_bindings(
            ROUTE_ID,
            Vec::new(),
            Vec::new(),
            vec![synthetic_solana_leg(ProductionRoutePositionV1::Upstream)],
            vec![synthetic_monero_leg(ProductionRoutePositionV1::Downstream)],
        )
        .expect("bundle");
        let bytes = bundle.canonical_bytes().expect("encode");
        assert_eq!(&bytes[10..12], &[0, 3]);
        let decoded =
            ProductionParticipantBindingBundleV1::decode_canonical(&bytes).expect("decode");
        assert_eq!(decoded, bundle);
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(ProductionParticipantBindingBundleV1::decode_canonical(&trailing).is_err());
        // Claiming only the Solana section while carrying both refuses.
        let mut relabeled = bytes;
        relabeled[11] = 1;
        assert!(ProductionParticipantBindingBundleV1::decode_canonical(&relabeled).is_err());
    }

    #[test]
    fn legacy_bundle_encoding_is_unchanged_and_still_decodes() {
        let bundle = ProductionParticipantBindingBundleV1::new_with_bitcoin_bindings(
            ROUTE_ID,
            Vec::new(),
            Vec::new(),
        )
        .expect("bundle");
        let bytes = bundle.canonical_bytes().expect("encode");
        // Reserved field still zero: byte-identical to the pre-Solana layout.
        assert_eq!(&bytes[10..12], &[0, 0]);
        let decoded =
            ProductionParticipantBindingBundleV1::decode_canonical(&bytes).expect("decode");
        assert!(decoded.solana_legs().is_empty());
    }
}
