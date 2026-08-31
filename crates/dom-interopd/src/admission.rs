//! Linearizable admission of new routes from the authenticated current
//! deployment registry.

use std::path::Path;

use adapter_evm::EvmAdapterConfig;
use blake2::{
    digest::{Update, VariableOutput},
    Blake2bVar,
};
use btc_crypto::SecpContext;
use chain_profile::ChainKindV1;
#[cfg(any(feature = "development", feature = "simulation", test))]
use deployment_registry::EvmSessionBindingsV1;
use deployment_registry::{
    AuthoritySetV1, RegistryError, RegistryStoreV1, RegistryValidationPolicyV1,
    ResolvedBitcoinDeploymentV1, ResolvedDomDeploymentV1, ResolvedEvmDeploymentV1,
    ResolvedRegistryV1,
};
use kaystra_core::terms::SettlementTermsV1;
use kaystra_core::types::{AssetId, ChainId, Digest32, LockMechanism, TimelockSpec};
use participant_binding::{AuthenticatedEvmSessionBindingsV1, EvmSettlementPositionV1};
use route_composer::{ComposedBindingV1, ComposedBindingV2};
use route_executor::{
    CanonicalCodecV1, FrozenBindingsV1, FrozenRouteAdmissionCheckpointV2, FrozenRouteTimeFactsV2,
    LegIdV1, RouteIdV1,
};

const TERMS_DOMAIN: &[u8] = b"DOM-INTEROPD/ROUTE-TERMS-BINDING/V1\0";
const ROSTERED_TERMS_DOMAIN: &[u8] = b"DOM-INTEROPD/ROSTERED-ROUTE-TERMS/V1\0";
const PROFILE_BUNDLE_DOMAIN: &[u8] = b"DOM-INTEROPD/PROFILE-BUNDLE/V1\0";
const DOM_PROFILE_DOMAIN: &[u8] = b"DOM-INTEROPD/DOM-PROFILE/V1\0";

/// One exact counterparty chain/asset selected for a route leg.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RouteLegSelectionV1 {
    pub chain_id: ChainId,
    pub asset_id: AssetId,
}

/// Inputs that are not deployment configuration. The daemon binds them to the
/// current authenticated registry before they can become route terms.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RouteAdmissionRequestV1 {
    pub route_id: RouteIdV1,
    pub base_terms_digest: Digest32,
    pub dom: RouteLegSelectionV1,
    pub upstream: RouteLegSelectionV1,
    pub downstream: RouteLegSelectionV1,
}

/// Relay roster snapshots frozen for the two independent settlements.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RouteRosterSnapshotsV1 {
    /// Snapshot used by the upstream settlement transport.
    pub upstream: Digest32,
    /// Snapshot used by the downstream settlement transport.
    pub downstream: Digest32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ValidatedSettlementBindingV1 {
    settlement_id: Digest32,
    session_id: Digest32,
    terms_digest: Digest32,
    roster_snapshot: Digest32,
}

/// Threshold-authenticated time proof frozen into a V2 route admission.
///
/// This is a public-only checkpoint. It does not replace the route-time
/// authority's current capability: every later economic boundary must still
/// revalidate the durable authority before acting.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AuthenticatedRouteTimeBindingV2 {
    route_scope_digest: Digest32,
    policy_digest: Digest32,
    evidence_digest: Digest32,
    proof_digest: Digest32,
    evidence_sequence: u64,
    issued_at_seconds: u64,
    valid_until_seconds: u64,
    validated_at_seconds: u64,
}

impl AuthenticatedRouteTimeBindingV2 {
    /// Ordered settlement-terms scope authenticated by the time authority.
    pub const fn route_scope_digest(self) -> Digest32 {
        self.route_scope_digest
    }

    /// Digest of the threshold-authenticated static timing policy.
    pub const fn policy_digest(self) -> Digest32 {
        self.policy_digest
    }

    /// Digest of the threshold-authenticated chain checkpoints.
    pub const fn evidence_digest(self) -> Digest32 {
        self.evidence_digest
    }

    /// Digest of the exact worst-case ladder proof consumed by the composer.
    pub const fn proof_digest(self) -> Digest32 {
        self.proof_digest
    }

    /// Monotonic checkpoint-evidence sequence.
    pub const fn evidence_sequence(self) -> u64 {
        self.evidence_sequence
    }

    /// Trusted lower bound of the admission window.
    pub const fn issued_at_seconds(self) -> u64 {
        self.issued_at_seconds
    }

    /// Exclusive trusted upper bound of the admission window.
    pub const fn valid_until_seconds(self) -> u64 {
        self.valid_until_seconds
    }

    /// Trusted second of the last durable-store validation consumed by V2.
    pub const fn validated_at_seconds(self) -> u64 {
        self.validated_at_seconds
    }

    pub(crate) const fn frozen_facts(self) -> FrozenRouteTimeFactsV2 {
        FrozenRouteTimeFactsV2 {
            route_scope_digest: self.route_scope_digest,
            policy_digest: self.policy_digest,
            evidence_digest: self.evidence_digest,
            proof_digest: self.proof_digest,
            evidence_sequence: self.evidence_sequence,
            issued_at_seconds: self.issued_at_seconds,
            valid_until_seconds: self.valid_until_seconds,
            validated_at_seconds: self.validated_at_seconds,
        }
    }
}

/// A route-scoped registry capability. It remains valid for recovery of this
/// already-admitted route even if a newer registry becomes current; it must
/// never be reused to admit another route.
pub struct AuthenticatedRouteAdmissionV1 {
    route_id: RouteIdV1,
    upstream: RouteLegSelectionV1,
    downstream: RouteLegSelectionV1,
    registry: ResolvedRegistryV1,
    frozen_bindings: FrozenBindingsV1,
    dom_profile_digest: Digest32,
    upstream_profile_digest: Digest32,
    downstream_profile_digest: Digest32,
    dom_asset_binding_digest: Digest32,
    upstream_asset_binding_digest: Digest32,
    downstream_asset_binding_digest: Digest32,
    validated_settlements: Option<[ValidatedSettlementBindingV1; 2]>,
    route_time_binding_v2: Option<AuthenticatedRouteTimeBindingV2>,
}

impl core::fmt::Debug for AuthenticatedRouteAdmissionV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("AuthenticatedRouteAdmissionV1")
            .field("route_id", &self.route_id)
            .field("registry_epoch", &self.registry.epoch())
            .field("registry_digest", &self.registry.manifest_digest())
            .field("frozen_bindings", &self.frozen_bindings)
            .finish_non_exhaustive()
    }
}

/// Authority that rereads and authenticates the current registry for every new
/// route admission. It intentionally issues no generic "resolve config"
/// capability detached from a route.
pub struct RegistryRouteAdmissionAuthorityV1 {
    store: RegistryStoreV1,
    authorities: AuthoritySetV1,
    secp: SecpContext,
    expected_network_id: Digest32,
    minimum_epoch: u64,
}

impl core::fmt::Debug for RegistryRouteAdmissionAuthorityV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("RegistryRouteAdmissionAuthorityV1([redacted])")
    }
}

/// Fail-closed route-admission refusal.
#[derive(Debug, thiserror::Error)]
pub enum RouteAdmissionRefusalV1 {
    #[error("deployment registry refused route admission")]
    Registry(#[from] RegistryError),
    #[error("no authenticated deployment registry is installed")]
    RegistryMissing,
    #[error("invalid route admission request")]
    InvalidRequest,
    #[error("route selection is absent from the authenticated registry")]
    UnknownSelection,
    #[error("route session bindings do not match admitted terms")]
    SessionBindingMismatch,
    #[error("pinned route bindings do not match authenticated historical registry")]
    PinnedBindingMismatch,
    #[error("composed settlement terms do not match authenticated registry facts")]
    CompositionRegistryMismatch,
    #[error("authenticated route-time capability is not current")]
    TimeCapabilityNotCurrent,
    #[error("route binding digest could not be constructed")]
    DigestFailure,
}

impl RegistryRouteAdmissionAuthorityV1 {
    /// Opens the registry store that will be reread for every admission.
    pub fn open(
        path: &Path,
        authorities: AuthoritySetV1,
        secp: SecpContext,
        expected_network_id: Digest32,
        minimum_epoch: u64,
    ) -> Result<Self, RouteAdmissionRefusalV1> {
        Self::new(
            RegistryStoreV1::open_existing(path)?,
            authorities,
            secp,
            expected_network_id,
            minimum_epoch,
        )
    }

    /// Constructs the authority from an already-open durable registry.
    pub fn new(
        store: RegistryStoreV1,
        authorities: AuthoritySetV1,
        secp: SecpContext,
        expected_network_id: Digest32,
        minimum_epoch: u64,
    ) -> Result<Self, RouteAdmissionRefusalV1> {
        if expected_network_id == [0; 32] {
            return Err(RouteAdmissionRefusalV1::InvalidRequest);
        }
        Ok(Self {
            store,
            authorities,
            secp,
            expected_network_id,
            minimum_epoch,
        })
    }

    /// Authenticates the current durable registry at `now_seconds` and binds
    /// all selected deployments, profiles and assets into one route-scoped
    /// terms digest. This raw digest boundary exists only in development and
    /// simulation; production must present a validated [`ComposedBindingV1`].
    #[cfg(any(feature = "development", feature = "simulation", test))]
    pub fn admit_composed_route(
        &self,
        now_seconds: u64,
        request: RouteAdmissionRequestV1,
    ) -> Result<AuthenticatedRouteAdmissionV1, RouteAdmissionRefusalV1> {
        validate_request(request)?;
        let registry = self
            .store
            .load_current(
                &self.authorities,
                &self.secp,
                RegistryValidationPolicyV1 {
                    now_seconds,
                    expected_network_id: self.expected_network_id,
                    minimum_epoch: self.minimum_epoch,
                },
            )?
            .ok_or(RouteAdmissionRefusalV1::RegistryMissing)?;
        build_admission(registry, request)
    }

    /// Authenticates the current registry and admits only settlement terms
    /// that already passed `route-composer`, then cross-checks every DOM and
    /// counterparty profile/asset/finality fact against that registry.
    pub fn admit_validated_composed_route(
        &self,
        now_seconds: u64,
        route_id: RouteIdV1,
        composition: &ComposedBindingV1,
        roster_snapshots: RouteRosterSnapshotsV1,
    ) -> Result<AuthenticatedRouteAdmissionV1, RouteAdmissionRefusalV1> {
        let request = request_from_composition(route_id, composition)?;
        let registry = self
            .store
            .load_current(
                &self.authorities,
                &self.secp,
                RegistryValidationPolicyV1 {
                    now_seconds,
                    expected_network_id: self.expected_network_id,
                    minimum_epoch: self.minimum_epoch,
                },
            )?
            .ok_or(RouteAdmissionRefusalV1::RegistryMissing)?;
        let mut admission = build_admission(registry, request)?;
        validate_composition_registry_binding(composition, &admission)?;
        admission.bind_validated_settlements(composition, roster_snapshots)?;
        Ok(admission)
    }

    /// Authenticates and admits a mixed-clock route whose worst-case deadline
    /// ladder was proved by the durable threshold-authenticated V2 authority.
    ///
    /// The proof must still be current at `now_seconds`. The resulting public
    /// checkpoint is frozen for recovery, while economic actions must obtain a
    /// fresh current capability from the route-time store.
    pub fn admit_validated_composed_route_v2(
        &self,
        now_seconds: u64,
        route_id: RouteIdV1,
        composition: &ComposedBindingV2,
        roster_snapshots: RouteRosterSnapshotsV1,
    ) -> Result<AuthenticatedRouteAdmissionV1, RouteAdmissionRefusalV1> {
        let request = request_from_composition_v2(route_id, composition)?;
        let registry = self
            .store
            .load_current(
                &self.authorities,
                &self.secp,
                RegistryValidationPolicyV1 {
                    now_seconds,
                    expected_network_id: self.expected_network_id,
                    minimum_epoch: self.minimum_epoch,
                },
            )?
            .ok_or(RouteAdmissionRefusalV1::RegistryMissing)?;
        let mut admission = build_admission(registry, request)?;
        validate_composition_registry_binding_v2(composition, &admission)?;
        admission.bind_validated_settlements_v2(composition, roster_snapshots, now_seconds)?;
        Ok(admission)
    }

    /// Recovers an already-admitted route from its exact historical registry
    /// digest and re-derives every binding before issuing the capability.
    #[cfg(any(feature = "development", feature = "simulation", test))]
    pub fn recover_composed_route(
        &self,
        request: RouteAdmissionRequestV1,
        frozen_bindings: &FrozenBindingsV1,
    ) -> Result<AuthenticatedRouteAdmissionV1, RouteAdmissionRefusalV1> {
        validate_request(request)?;
        let registry = self
            .store
            .load_pinned(
                frozen_bindings.deployment_bundle_digest,
                &self.authorities,
                &self.secp,
                self.expected_network_id,
            )?
            .ok_or(RouteAdmissionRefusalV1::RegistryMissing)?;
        let admission = build_admission(registry, request)?;
        if admission.frozen_bindings() != frozen_bindings {
            return Err(RouteAdmissionRefusalV1::PinnedBindingMismatch);
        }
        Ok(admission)
    }

    /// Recovers one production route only from the same validated composition
    /// and exact pinned registry digest used at admission.
    pub fn recover_validated_composed_route(
        &self,
        route_id: RouteIdV1,
        composition: &ComposedBindingV1,
        roster_snapshots: RouteRosterSnapshotsV1,
        frozen_bindings: &FrozenBindingsV1,
    ) -> Result<AuthenticatedRouteAdmissionV1, RouteAdmissionRefusalV1> {
        let request = request_from_composition(route_id, composition)?;
        let registry = self
            .store
            .load_pinned(
                frozen_bindings.deployment_bundle_digest,
                &self.authorities,
                &self.secp,
                self.expected_network_id,
            )?
            .ok_or(RouteAdmissionRefusalV1::RegistryMissing)?;
        let mut admission = build_admission(registry, request)?;
        validate_composition_registry_binding(composition, &admission)?;
        admission.bind_validated_settlements(composition, roster_snapshots)?;
        if admission.frozen_bindings() != frozen_bindings {
            return Err(RouteAdmissionRefusalV1::PinnedBindingMismatch);
        }
        Ok(admission)
    }

    /// Recovers a V2 route only from its exact, journal-authenticated admission
    /// checkpoint and a composition reconstructed from historical signed time
    /// evidence.
    ///
    /// This path deliberately receives no current time. It authenticates the
    /// original admission and does not issue permission for new funding;
    /// current temporal ancestry is a separate economic gate.
    pub fn recover_validated_composed_route_v2(
        &self,
        route_id: RouteIdV1,
        composition: &ComposedBindingV2,
        checkpoint: &FrozenRouteAdmissionCheckpointV2,
    ) -> Result<AuthenticatedRouteAdmissionV1, RouteAdmissionRefusalV1> {
        checkpoint
            .encode_canonical()
            .map_err(|_| RouteAdmissionRefusalV1::PinnedBindingMismatch)?;
        let registry_authority_set_digest = self.authorities.authority_set_digest()?;
        let upstream_terms_digest = composition
            .upstream()
            .terms_hash()
            .map_err(|_| RouteAdmissionRefusalV1::DigestFailure)?;
        let downstream_terms_digest = composition
            .downstream()
            .terms_hash()
            .map_err(|_| RouteAdmissionRefusalV1::DigestFailure)?;
        let historical_time_binding = historical_time_binding_from_composition_v2(composition)?;
        if checkpoint.route_id != route_id
            || checkpoint.network_id != self.expected_network_id
            || checkpoint.composition_v2_digest != composition.binding_digest()
            || checkpoint.upstream_terms_digest != upstream_terms_digest
            || checkpoint.downstream_terms_digest != downstream_terms_digest
            || checkpoint.registry_authority_set_digest != registry_authority_set_digest
            || checkpoint.time != historical_time_binding.frozen_facts()
        {
            return Err(RouteAdmissionRefusalV1::PinnedBindingMismatch);
        }
        let request = request_from_composition_v2(route_id, composition)?;
        let registry = self
            .store
            .load_pinned(
                checkpoint.registry_manifest_digest,
                &self.authorities,
                &self.secp,
                self.expected_network_id,
            )?
            .ok_or(RouteAdmissionRefusalV1::RegistryMissing)?;
        if registry.epoch() != checkpoint.registry_epoch
            || registry.manifest_digest() != checkpoint.registry_manifest_digest
            || registry.manifest().network_id != checkpoint.network_id
        {
            return Err(RouteAdmissionRefusalV1::PinnedBindingMismatch);
        }
        let mut admission = build_admission(registry, request)?;
        validate_composition_registry_binding_v2(composition, &admission)?;
        admission.bind_validated_settlement_terms(
            composition.upstream(),
            composition.downstream(),
            RouteRosterSnapshotsV1 {
                upstream: checkpoint.upstream_roster_snapshot,
                downstream: checkpoint.downstream_roster_snapshot,
            },
        )?;
        admission.route_time_binding_v2 = Some(historical_time_binding);
        if admission.frozen_bindings() != &checkpoint.bindings
            || admission.route_time_binding_v2() != Some(historical_time_binding)
        {
            return Err(RouteAdmissionRefusalV1::PinnedBindingMismatch);
        }
        Ok(admission)
    }
}

fn build_admission(
    registry: ResolvedRegistryV1,
    request: RouteAdmissionRequestV1,
) -> Result<AuthenticatedRouteAdmissionV1, RouteAdmissionRefusalV1> {
    let dom = registry.resolve_dom()?;
    let dom_deployment = dom.deployment();
    if request.dom.chain_id != dom_deployment.chain_id
        || request.dom.asset_id != dom_deployment.native_asset
    {
        return Err(RouteAdmissionRefusalV1::UnknownSelection);
    }
    let upstream_profile = registry
        .resolve_chain(request.upstream.chain_id)
        .ok_or(RouteAdmissionRefusalV1::UnknownSelection)?;
    let downstream_profile = registry
        .resolve_chain(request.downstream.chain_id)
        .ok_or(RouteAdmissionRefusalV1::UnknownSelection)?;
    registry
        .resolve_asset(request.dom.chain_id, request.dom.asset_id)
        .ok_or(RouteAdmissionRefusalV1::UnknownSelection)?;
    registry
        .resolve_asset(request.upstream.chain_id, request.upstream.asset_id)
        .ok_or(RouteAdmissionRefusalV1::UnknownSelection)?;
    registry
        .resolve_asset(request.downstream.chain_id, request.downstream.asset_id)
        .ok_or(RouteAdmissionRefusalV1::UnknownSelection)?;
    let upstream_profile_digest = upstream_profile
        .profile()
        .profile_digest()
        .map_err(|_| RouteAdmissionRefusalV1::DigestFailure)?;
    let downstream_profile_digest = downstream_profile
        .profile()
        .profile_digest()
        .map_err(|_| RouteAdmissionRefusalV1::DigestFailure)?;
    let dom_profile_digest = dom_profile_digest(dom_deployment)?;
    let registry_digest = registry.manifest_digest();
    let dom_asset_binding_digest =
        registry.asset_binding_digest(request.dom.chain_id, request.dom.asset_id)?;
    let upstream_asset_binding_digest =
        registry.asset_binding_digest(request.upstream.chain_id, request.upstream.asset_id)?;
    let downstream_asset_binding_digest =
        registry.asset_binding_digest(request.downstream.chain_id, request.downstream.asset_id)?;
    let profile_bundle_digest = digest_parts(
        PROFILE_BUNDLE_DOMAIN,
        &[
            &registry_digest,
            &dom_profile_digest,
            &upstream_profile_digest,
            &downstream_profile_digest,
        ],
    )?;
    let terms_digest = digest_parts(
        TERMS_DOMAIN,
        &[
            &request.route_id,
            &request.base_terms_digest,
            &registry_digest,
            &request.dom.chain_id.0,
            &request.dom.asset_id.0,
            &dom_profile_digest,
            &dom_asset_binding_digest,
            &request.upstream.chain_id.0,
            &request.upstream.asset_id.0,
            &upstream_profile_digest,
            &upstream_asset_binding_digest,
            &request.downstream.chain_id.0,
            &request.downstream.asset_id.0,
            &downstream_profile_digest,
            &downstream_asset_binding_digest,
        ],
    )?;
    let frozen_bindings = FrozenBindingsV1 {
        terms_digest,
        profile_bundle_digest,
        deployment_bundle_digest: registry_digest,
    };
    Ok(AuthenticatedRouteAdmissionV1 {
        route_id: request.route_id,
        upstream: request.upstream,
        downstream: request.downstream,
        registry,
        frozen_bindings,
        dom_profile_digest,
        upstream_profile_digest,
        downstream_profile_digest,
        dom_asset_binding_digest,
        upstream_asset_binding_digest,
        downstream_asset_binding_digest,
        validated_settlements: None,
        route_time_binding_v2: None,
    })
}

fn request_from_composition(
    route_id: RouteIdV1,
    composition: &ComposedBindingV1,
) -> Result<RouteAdmissionRequestV1, RouteAdmissionRefusalV1> {
    request_from_composition_parts(
        route_id,
        composition.binding_digest(),
        composition.upstream(),
        composition.downstream(),
    )
}

fn request_from_composition_v2(
    route_id: RouteIdV1,
    composition: &ComposedBindingV2,
) -> Result<RouteAdmissionRequestV1, RouteAdmissionRefusalV1> {
    request_from_composition_parts(
        route_id,
        composition.binding_digest(),
        composition.upstream(),
        composition.downstream(),
    )
}

fn request_from_composition_parts(
    route_id: RouteIdV1,
    binding_digest: Digest32,
    upstream: &SettlementTermsV1,
    downstream: &SettlementTermsV1,
) -> Result<RouteAdmissionRequestV1, RouteAdmissionRefusalV1> {
    if route_id == [0; 32] {
        return Err(RouteAdmissionRefusalV1::InvalidRequest);
    }
    let request = RouteAdmissionRequestV1 {
        route_id,
        base_terms_digest: binding_digest,
        dom: RouteLegSelectionV1 {
            chain_id: upstream.dom_leg.chain_id,
            asset_id: upstream.dom_leg.asset_id,
        },
        upstream: RouteLegSelectionV1 {
            chain_id: upstream.counterparty_leg.chain_id,
            asset_id: upstream.counterparty_leg.asset_id,
        },
        downstream: RouteLegSelectionV1 {
            chain_id: downstream.counterparty_leg.chain_id,
            asset_id: downstream.counterparty_leg.asset_id,
        },
    };
    validate_request(request)?;
    Ok(request)
}

fn validate_composition_registry_binding(
    composition: &ComposedBindingV1,
    admission: &AuthenticatedRouteAdmissionV1,
) -> Result<(), RouteAdmissionRefusalV1> {
    validate_composition_registry_parts(
        composition.binding_digest(),
        composition.upstream(),
        composition.downstream(),
        admission,
    )
}

fn validate_composition_registry_binding_v2(
    composition: &ComposedBindingV2,
    admission: &AuthenticatedRouteAdmissionV1,
) -> Result<(), RouteAdmissionRefusalV1> {
    validate_composition_registry_parts(
        composition.binding_digest(),
        composition.upstream(),
        composition.downstream(),
        admission,
    )
}

fn validate_composition_registry_parts(
    binding_digest: Digest32,
    upstream: &SettlementTermsV1,
    downstream: &SettlementTermsV1,
    admission: &AuthenticatedRouteAdmissionV1,
) -> Result<(), RouteAdmissionRefusalV1> {
    let dom = admission.registry.resolve_dom()?;
    let dom_deployment = dom.deployment();
    let upstream_profile = admission
        .registry
        .resolve_chain(admission.upstream.chain_id)
        .ok_or(RouteAdmissionRefusalV1::UnknownSelection)?;
    let downstream_profile = admission
        .registry
        .resolve_chain(admission.downstream.chain_id)
        .ok_or(RouteAdmissionRefusalV1::UnknownSelection)?;
    if binding_digest == [0; 32]
        || upstream.dom_leg.chain_id != dom_deployment.chain_id
        || downstream.dom_leg.chain_id != dom_deployment.chain_id
        || upstream.dom_leg.asset_id != dom_deployment.native_asset
        || downstream.dom_leg.asset_id != dom_deployment.native_asset
        || upstream.dom_leg.adapter_profile_hash != admission.dom_profile_digest
        || downstream.dom_leg.adapter_profile_hash != admission.dom_profile_digest
        || upstream.dom_leg.finality != dom_deployment.finality
        || downstream.dom_leg.finality != dom_deployment.finality
        || !matches!(upstream.dom_leg.deadline, TimelockSpec::BlockHeight { .. })
        || !matches!(
            downstream.dom_leg.deadline,
            TimelockSpec::BlockHeight { .. }
        )
        || !counterparty_leg_matches_chain_kind(
            upstream.counterparty_leg.mechanism,
            upstream.counterparty_leg.deadline,
            upstream_profile.profile().kind,
        )
        || !counterparty_leg_matches_chain_kind(
            downstream.counterparty_leg.mechanism,
            downstream.counterparty_leg.deadline,
            downstream_profile.profile().kind,
        )
        || upstream.counterparty_leg.adapter_profile_hash != admission.upstream_profile_digest
        || downstream.counterparty_leg.adapter_profile_hash != admission.downstream_profile_digest
        || upstream.counterparty_leg.finality != upstream_profile.profile().finality
        || downstream.counterparty_leg.finality != downstream_profile.profile().finality
    {
        return Err(RouteAdmissionRefusalV1::CompositionRegistryMismatch);
    }
    Ok(())
}

fn time_binding_from_composition_v2(
    composition: &ComposedBindingV2,
    now_seconds: u64,
) -> Result<AuthenticatedRouteTimeBindingV2, RouteAdmissionRefusalV1> {
    let value = historical_time_binding_from_composition_v2(composition)?;
    if now_seconds < value.validated_at_seconds || now_seconds >= value.valid_until_seconds {
        return Err(RouteAdmissionRefusalV1::TimeCapabilityNotCurrent);
    }
    Ok(value)
}

fn historical_time_binding_from_composition_v2(
    composition: &ComposedBindingV2,
) -> Result<AuthenticatedRouteTimeBindingV2, RouteAdmissionRefusalV1> {
    let value = AuthenticatedRouteTimeBindingV2 {
        route_scope_digest: composition.route_scope_digest(),
        policy_digest: composition.time_policy_digest(),
        evidence_digest: composition.time_evidence_digest(),
        proof_digest: composition.time_proof_digest(),
        evidence_sequence: composition.evidence_sequence(),
        issued_at_seconds: composition.time_proof_issued_at_seconds(),
        valid_until_seconds: composition.time_proof_valid_until_seconds(),
        validated_at_seconds: composition.time_proof_validated_at_seconds(),
    };
    if value.route_scope_digest == [0; 32]
        || value.policy_digest == [0; 32]
        || value.evidence_digest == [0; 32]
        || value.proof_digest == [0; 32]
        || value.evidence_sequence == 0
        || value.issued_at_seconds == 0
        || value.validated_at_seconds < value.issued_at_seconds
        || value.validated_at_seconds >= value.valid_until_seconds
    {
        return Err(RouteAdmissionRefusalV1::TimeCapabilityNotCurrent);
    }
    Ok(value)
}

fn counterparty_leg_matches_chain_kind(
    mechanism: LockMechanism,
    deadline: TimelockSpec,
    kind: ChainKindV1,
) -> bool {
    match kind {
        ChainKindV1::Evm { .. } => {
            mechanism == LockMechanism::ConditionLock
                && matches!(deadline, TimelockSpec::TimestampSeconds { .. })
        }
        ChainKindV1::Bitcoin { .. } => {
            mechanism == LockMechanism::SchnorrAdaptor
                && matches!(
                    deadline,
                    TimelockSpec::BlockHeight { .. } | TimelockSpec::BtcTime512s { .. }
                )
        }
    }
}

fn dom_profile_digest(
    deployment: deployment_registry::DomDeploymentV1,
) -> Result<Digest32, RouteAdmissionRefusalV1> {
    digest_parts(
        DOM_PROFILE_DOMAIN,
        &[
            &deployment.chain_id.0,
            &deployment.genesis_hash,
            &deployment.consensus_rules_digest,
            &deployment.scriptless_api_version.to_be_bytes(),
            &deployment.timing.min_block_seconds.to_be_bytes(),
            &deployment.timing.max_block_seconds.to_be_bytes(),
            &deployment.timing.max_reorg_seconds.to_be_bytes(),
            &deployment.timing.observation_seconds.to_be_bytes(),
            &deployment.timing.broadcast_seconds.to_be_bytes(),
            &deployment.finality.min_confirmations.to_be_bytes(),
            &deployment.finality.max_reorg_depth.to_be_bytes(),
            &deployment.native_asset.0,
        ],
    )
}

impl AuthenticatedRouteAdmissionV1 {
    fn bind_validated_settlements(
        &mut self,
        composition: &ComposedBindingV1,
        roster_snapshots: RouteRosterSnapshotsV1,
    ) -> Result<(), RouteAdmissionRefusalV1> {
        self.bind_validated_settlement_terms(
            composition.upstream(),
            composition.downstream(),
            roster_snapshots,
        )
    }

    fn bind_validated_settlements_v2(
        &mut self,
        composition: &ComposedBindingV2,
        roster_snapshots: RouteRosterSnapshotsV1,
        now_seconds: u64,
    ) -> Result<(), RouteAdmissionRefusalV1> {
        let time_binding = time_binding_from_composition_v2(composition, now_seconds)?;
        self.bind_validated_settlement_terms(
            composition.upstream(),
            composition.downstream(),
            roster_snapshots,
        )?;
        self.route_time_binding_v2 = Some(time_binding);
        Ok(())
    }

    fn bind_validated_settlement_terms(
        &mut self,
        upstream: &SettlementTermsV1,
        downstream: &SettlementTermsV1,
        roster_snapshots: RouteRosterSnapshotsV1,
    ) -> Result<(), RouteAdmissionRefusalV1> {
        if roster_snapshots.upstream == [0; 32] || roster_snapshots.downstream == [0; 32] {
            return Err(RouteAdmissionRefusalV1::InvalidRequest);
        }
        self.frozen_bindings.terms_digest = digest_parts(
            ROSTERED_TERMS_DOMAIN,
            &[
                &self.frozen_bindings.terms_digest,
                &roster_snapshots.upstream,
                &roster_snapshots.downstream,
            ],
        )?;
        self.validated_settlements = Some([
            ValidatedSettlementBindingV1 {
                settlement_id: upstream.settlement_id.0,
                session_id: upstream.session_id.0,
                terms_digest: upstream
                    .terms_hash()
                    .map_err(|_| RouteAdmissionRefusalV1::DigestFailure)?,
                roster_snapshot: roster_snapshots.upstream,
            },
            ValidatedSettlementBindingV1 {
                settlement_id: downstream.settlement_id.0,
                session_id: downstream.session_id.0,
                terms_digest: downstream
                    .terms_hash()
                    .map_err(|_| RouteAdmissionRefusalV1::DigestFailure)?,
                roster_snapshot: roster_snapshots.downstream,
            },
        ]);
        Ok(())
    }

    pub const fn route_id(&self) -> RouteIdV1 {
        self.route_id
    }

    pub const fn registry_epoch(&self) -> u64 {
        self.registry.epoch()
    }

    pub const fn registry_digest(&self) -> Digest32 {
        self.registry.manifest_digest()
    }

    pub const fn frozen_bindings(&self) -> &FrozenBindingsV1 {
        &self.frozen_bindings
    }

    pub const fn dom_profile_digest(&self) -> Digest32 {
        self.dom_profile_digest
    }

    pub const fn upstream_profile_digest(&self) -> Digest32 {
        self.upstream_profile_digest
    }

    pub const fn downstream_profile_digest(&self) -> Digest32 {
        self.downstream_profile_digest
    }

    pub const fn dom_asset_binding_digest(&self) -> Digest32 {
        self.dom_asset_binding_digest
    }

    pub const fn upstream_asset_binding_digest(&self) -> Digest32 {
        self.upstream_asset_binding_digest
    }

    pub const fn downstream_asset_binding_digest(&self) -> Digest32 {
        self.downstream_asset_binding_digest
    }

    /// Public V2 time checkpoint frozen into this admission, when the route
    /// crossed mixed native timelock domains.
    pub const fn route_time_binding_v2(&self) -> Option<AuthenticatedRouteTimeBindingV2> {
        self.route_time_binding_v2
    }

    /// Returns the DOM authority facts authenticated for this route epoch.
    pub fn dom_deployment_capability(
        &self,
    ) -> Result<ResolvedDomDeploymentV1, RouteAdmissionRefusalV1> {
        self.registry
            .resolve_dom()
            .map_err(RouteAdmissionRefusalV1::Registry)
    }

    /// Returns the complete public Bitcoin capability for one selected leg.
    pub fn bitcoin_deployment_capability(
        &self,
        leg: LegIdV1,
    ) -> Result<ResolvedBitcoinDeploymentV1, RouteAdmissionRefusalV1> {
        let selection = match leg {
            LegIdV1::Upstream => self.upstream,
            LegIdV1::Downstream => self.downstream,
        };
        self.registry
            .resolve_chain(selection.chain_id)
            .ok_or(RouteAdmissionRefusalV1::UnknownSelection)?
            .bitcoin_deployment_capability()
            .map_err(RouteAdmissionRefusalV1::Registry)
    }

    /// Builds an EVM adapter only from dual-signed participant/account facts
    /// and the exact validated composed settlement admitted for this route.
    pub fn evm_adapter_config(
        &self,
        leg: LegIdV1,
        session: &AuthenticatedEvmSessionBindingsV1,
    ) -> Result<EvmAdapterConfig, RouteAdmissionRefusalV1> {
        Ok(self
            .evm_deployment_capability(leg, session)?
            .adapter_config())
    }

    /// Returns the complete route-scoped EVM deployment capability so the
    /// observer, token preflight and signer enforce deployment plus the two
    /// participant/account signatures. Caller-shaped account facts never
    /// reach this production boundary.
    pub fn evm_deployment_capability(
        &self,
        leg: LegIdV1,
        session: &AuthenticatedEvmSessionBindingsV1,
    ) -> Result<ResolvedEvmDeploymentV1, RouteAdmissionRefusalV1> {
        let settlements = self
            .validated_settlements
            .ok_or(RouteAdmissionRefusalV1::SessionBindingMismatch)?;
        let (position, settlement, selection) = match leg {
            LegIdV1::Upstream => (
                EvmSettlementPositionV1::Upstream,
                settlements[0],
                self.upstream,
            ),
            LegIdV1::Downstream => (
                EvmSettlementPositionV1::Downstream,
                settlements[1],
                self.downstream,
            ),
        };
        let chain = self
            .registry
            .resolve_chain(selection.chain_id)
            .ok_or(RouteAdmissionRefusalV1::UnknownSelection)?;
        let expected_evm_chain_id = match chain.profile().kind {
            ChainKindV1::Evm { evm_chain_id, .. } => evm_chain_id,
            ChainKindV1::Bitcoin { .. } => return Err(RouteAdmissionRefusalV1::UnknownSelection),
        };
        let bindings = session.bindings();
        if session.network_id() != self.registry.manifest().network_id
            || session.registry_digest() != self.registry.manifest_digest()
            || session.route_id() != self.route_id
            || session.settlement_id() != settlement.settlement_id
            || session.settlement_terms_digest() != settlement.terms_digest
            || session.roster_snapshot() != settlement.roster_snapshot
            || session.position() != position
            || session.evm_chain_id() != expected_evm_chain_id
            || bindings.session_id != settlement.session_id
            || bindings.terms_hash != self.frozen_bindings.terms_digest
            || bindings.direction != position.direction()
        {
            return Err(RouteAdmissionRefusalV1::SessionBindingMismatch);
        }
        chain
            .evm_deployment_capability(selection.asset_id, bindings)
            .map_err(RouteAdmissionRefusalV1::Registry)
    }

    /// Laboratory-only adapter construction from raw session fields.
    #[cfg(any(feature = "development", feature = "simulation", test))]
    pub fn evm_adapter_config_for_lab(
        &self,
        leg: LegIdV1,
        session: EvmSessionBindingsV1,
    ) -> Result<EvmAdapterConfig, RouteAdmissionRefusalV1> {
        Ok(self
            .evm_deployment_capability_for_lab(leg, session)?
            .adapter_config())
    }

    /// Laboratory-only deployment capability from raw session fields.
    #[cfg(any(feature = "development", feature = "simulation", test))]
    pub fn evm_deployment_capability_for_lab(
        &self,
        leg: LegIdV1,
        session: EvmSessionBindingsV1,
    ) -> Result<ResolvedEvmDeploymentV1, RouteAdmissionRefusalV1> {
        if session.terms_hash != self.frozen_bindings.terms_digest {
            return Err(RouteAdmissionRefusalV1::SessionBindingMismatch);
        }
        let selection = match leg {
            LegIdV1::Upstream => self.upstream,
            LegIdV1::Downstream => self.downstream,
        };
        self.registry
            .resolve_chain(selection.chain_id)
            .ok_or(RouteAdmissionRefusalV1::UnknownSelection)?
            .evm_deployment_capability(selection.asset_id, session)
            .map_err(RouteAdmissionRefusalV1::Registry)
    }
}

fn validate_request(request: RouteAdmissionRequestV1) -> Result<(), RouteAdmissionRefusalV1> {
    if request.route_id == [0; 32]
        || request.base_terms_digest == [0; 32]
        || request.dom.chain_id.0 == [0; 32]
        || request.dom.asset_id.0 == [0; 32]
        || request.upstream.chain_id.0 == [0; 32]
        || request.upstream.asset_id.0 == [0; 32]
        || request.downstream.chain_id.0 == [0; 32]
        || request.downstream.asset_id.0 == [0; 32]
    {
        return Err(RouteAdmissionRefusalV1::InvalidRequest);
    }
    Ok(())
}

fn digest_parts(domain: &[u8], parts: &[&[u8]]) -> Result<Digest32, RouteAdmissionRefusalV1> {
    let mut hash = Blake2bVar::new(32).map_err(|_| RouteAdmissionRefusalV1::DigestFailure)?;
    hash.update(domain);
    for part in parts {
        let length =
            u64::try_from(part.len()).map_err(|_| RouteAdmissionRefusalV1::DigestFailure)?;
        hash.update(&length.to_be_bytes());
        hash.update(part);
    }
    let mut digest = [0; 32];
    hash.finalize_variable(&mut digest)
        .map_err(|_| RouteAdmissionRefusalV1::DigestFailure)?;
    if digest == [0; 32] {
        return Err(RouteAdmissionRefusalV1::DigestFailure);
    }
    Ok(digest)
}
