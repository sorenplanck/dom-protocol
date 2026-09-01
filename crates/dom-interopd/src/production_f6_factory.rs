//! Threshold-authenticated Stage-7 inputs and the sole concrete F6 pair factory.
//!
//! The factory is deliberately RFQ-late. Both Relay messages are authenticated
//! before it derives the RFQ-scoped status/time pins, completes any lazy store
//! prefix, consumes payout owners, or permits route-terminal handles to exist.

use std::collections::BTreeSet;
use std::io::{Read, Write};
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::os::unix::net::UnixStream;
use std::path::{Component, Path, PathBuf};
use std::rc::Rc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use adapter_btc_live::AuthenticatedBitcoinPayoutFaceV1;
use blake2::digest::{consts::U32, KeyInit, Mac, Update, VariableOutput};
use blake2::{Blake2bMac, Blake2bVar};
use btc_crypto::SecpContext;
use deployment_registry::{
    AuthoritySetV1, ResolvedBitcoinDeploymentV1, ResolvedEvmDeploymentV1, ResolvedRegistryV1,
};
use dom_actuator::AuthenticatedDomPayoutFaceV1;
use f6_engine::candidate_book::{
    bond_reservation_authority_set_digest_v2, candidate_status_authority_set_digest_v2,
    BondReservationAttestationV2,
};
use kaystra_core::types::{Digest32, ParticipantId};
use relay::auth::RosterRegistryV1;
use relay::SenderRoleV1;
use rfq::v2::{RfqV2, SettlementPositionV2};
use route_composer::{
    ComposedBindingV2, ComposedFinalClaimRolePlanV1, FinalClaimSecretSourceScopeV1,
};
use route_time_anchor::{
    DurablePreF6TimeStoreV2, PreF6TimePolicyLimitsV2, PreF6TimePolicyV2, PreF6TimeScopeRequestV2,
    PreF6TimeScopeV2,
};
use route_transport::RouteWireContextV1;
use solver_inventory::{DurableInventoryStoreV1, InventoryLeaseV1, LeaseAcquireOutcomeV1};
use solver_status::{
    DurableSolverStatusStoreV1, SolverStatusFreshnessPolicyV1, SolverStatusScopeV1,
    SolverStatusStoreConfigV1,
};
use store::{ProductionStoreBindingV1, Store};
use zeroize::Zeroizing;

use crate::production_f6::candidate_attestation::{
    PreparedF6BondAttestationSigningRequestV2, ProductionF6BondAttestationSignatureV2,
    ProductionF6BondAttestationSignerV2, ProductionF6BondSignerErrorV2,
    ProductionF6CandidateAttestationAuthorityStoreV2, ProductionF6CandidateAuthorityInputsV2,
    ProductionF6ReservedSignerKeysV2,
};
use crate::production_f6::terminal_release::ProductionRouteTerminalAuthorityV2;
use crate::production_f6::terms::{
    AdapterAuthenticatedRefundFaceV2, ProductionAdapterF6TermsAuthorityV2,
};
use crate::production_f6::{
    ProductionF6AuthoritiesV2, ProductionF6PinsV2, ProductionF6SharedAuthorityOwnerV2,
    ProductionF6SourcesV2, ProductionSolverF6BindingV2,
};
use crate::production_f6_activation::{pair_factory_seal, ProductionF6PairAuthoritiesFactoryV2};
use crate::production_f6_lifecycle::ProductionF6ActivationRefusalV2;
use crate::production_inputs::{AuthenticatedProductionInputsV1, ProductionRosterLegV1};

const ZERO_DIGEST: Digest32 = [0; 32];
const BUNDLE_MAGIC_V7: &[u8; 8] = b"DOMF6A07";
const BUNDLE_VERSION_V7: u16 = 7;
const BUNDLE_DOMAIN_V7: &[u8] = b"DOM-INTEROP/INTEROPD/F6-AUTHORITY-BUNDLE/V7\0";
const PREPARED_DOMAIN_V7: &[u8] = b"DOM-INTEROP/INTEROPD/F6-EXTERNAL-PREPARED/V7\0";
const HSM_REQUEST_MAGIC_V7: &[u8; 8] = b"DOMF6HQ7";
const HSM_RESPONSE_MAGIC_V7: &[u8; 8] = b"DOMF6HS7";
const HSM_REQUEST_MAC_DOMAIN_V7: &[u8] = b"DOM-INTEROP/INTEROPD/F6-HSM-REQUEST-MAC/V7\0";
const HSM_VERSION_V7: u16 = 7;
const MAX_BUNDLE_BYTES_V7: usize = 32_768;
const MAX_AUTHORITY_BYTES_V7: usize = 1_024;
const MAX_SIGNERS_V7: usize = 16;
const MAX_ENDPOINT_BYTES_V7: usize = 512;
const MAX_ATTESTATION_BYTES_V7: usize = 4_096;
const MAX_HSM_RESPONSE_BYTES_V7: usize = 140;
const FINAL_CLAIM_ROLE_PLAN_BYTES_V7: usize = 504;
const FINAL_CLAIM_SOURCE_SCOPE_BYTES_V7: usize = 305;
const MAX_F6_INVENTORY_LEASE_DURATION_MS_V7: u64 = 86_400_000;

type Blake2bMac256 = Blake2bMac<U32>;

/// Six RFQ-dependent stores that Stage 11 may publish only as authenticated
/// lazy prefixes. The status stores are separate because the two Relay roster
/// snapshots are required to be distinct.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ProductionF6ExternalPreparedBindingsV7 {
    upstream_status: Digest32,
    downstream_status: Digest32,
    upstream_time: Digest32,
    downstream_time: Digest32,
    upstream_candidate: Digest32,
    downstream_candidate: Digest32,
}

impl ProductionF6ExternalPreparedBindingsV7 {
    pub(crate) fn derive_stage11(
        provisioning_binding: Digest32,
        route_id: Digest32,
        composition_digest: Digest32,
    ) -> Result<Self, ProductionF6ActivationRefusalV2> {
        if [provisioning_binding, route_id, composition_digest].contains(&ZERO_DIGEST) {
            return Err(ProductionF6ActivationRefusalV2::InvalidBinding);
        }
        let derive = |position: u8, role: u8| {
            digest_parts(&[
                PREPARED_DOMAIN_V7,
                &provisioning_binding,
                &route_id,
                &composition_digest,
                &[position],
                &[role],
            ])
        };
        let value = Self {
            upstream_status: derive(1, 1)?,
            downstream_status: derive(2, 1)?,
            upstream_time: derive(1, 2)?,
            downstream_time: derive(2, 2)?,
            upstream_candidate: derive(1, 3)?,
            downstream_candidate: derive(2, 3)?,
        };
        let distinct: BTreeSet<_> = value.all().into_iter().collect();
        if distinct.len() != value.all().len() || distinct.contains(&ZERO_DIGEST) {
            return Err(ProductionF6ActivationRefusalV2::InvalidBinding);
        }
        Ok(value)
    }

    fn all(self) -> [Digest32; 6] {
        [
            self.upstream_status,
            self.downstream_status,
            self.upstream_time,
            self.downstream_time,
            self.upstream_candidate,
            self.downstream_candidate,
        ]
    }

    /// Idempotently publishes all six authenticated prefix authorities. It
    /// creates no economic database and therefore cannot guess an RFQ scope.
    pub(crate) fn prepare_stage11(
        self,
        paths: &ProductionF6ExternalPathsV7,
    ) -> Result<(), ProductionF6ActivationRefusalV2> {
        for (path, digest) in paths.all().into_iter().zip(self.all()) {
            let binding = ProductionStoreBindingV1::new(digest)
                .map_err(|_| ProductionF6ActivationRefusalV2::InvalidBinding)?;
            Store::prepare_resume_create_production(path, binding)
                .map_err(|_| ProductionF6ActivationRefusalV2::Unavailable)?;
        }
        Ok(())
    }
}

/// Exact V7 paths. There is intentionally no adapter from the V4 singular
/// status path: production must explicitly configure both physical stores.
pub(crate) struct ProductionF6ExternalPathsV7 {
    upstream_status: PathBuf,
    downstream_status: PathBuf,
    upstream_time: PathBuf,
    downstream_time: PathBuf,
    upstream_candidate: PathBuf,
    downstream_candidate: PathBuf,
}

impl ProductionF6ExternalPathsV7 {
    pub(crate) fn new(
        state_root: &Path,
        paths: [PathBuf; 6],
    ) -> Result<Self, ProductionF6ActivationRefusalV2> {
        if !state_root.is_absolute() || !lexically_normal(state_root) {
            return Err(ProductionF6ActivationRefusalV2::InvalidBinding);
        }
        let mut distinct = BTreeSet::new();
        for path in &paths {
            let relative = path
                .strip_prefix(state_root)
                .map_err(|_| ProductionF6ActivationRefusalV2::InvalidBinding)?;
            if !path.is_absolute()
                || !lexically_normal(path)
                || relative.as_os_str().is_empty()
                || !distinct.insert(path.clone())
            {
                return Err(ProductionF6ActivationRefusalV2::InvalidBinding);
            }
        }
        let [upstream_status, downstream_status, upstream_time, downstream_time, upstream_candidate, downstream_candidate] =
            paths;
        Ok(Self {
            upstream_status,
            downstream_status,
            upstream_time,
            downstream_time,
            upstream_candidate,
            downstream_candidate,
        })
    }

    fn all(&self) -> [&Path; 6] {
        [
            &self.upstream_status,
            &self.downstream_status,
            &self.upstream_time,
            &self.downstream_time,
            &self.upstream_candidate,
            &self.downstream_candidate,
        ]
    }
}

impl core::fmt::Debug for ProductionF6ExternalPathsV7 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("ProductionF6ExternalPathsV7([paths redacted])")
    }
}

#[derive(Clone)]
struct ProductionF6BondSignerDescriptorV7 {
    independent_authority_id: Digest32,
    signer_index: u16,
    signer_public_key: [u8; 32],
    endpoint_uid: u32,
    endpoint: PathBuf,
}

/// Threshold-authenticated public authority input. Its fields are private and
/// the only production constructor verifies exact bytes with an already
/// trusted root authority set.
pub(crate) struct AuthenticatedProductionF6AuthorityBundleV7 {
    network_id: Digest32,
    route_id: Digest32,
    composition_digest: Digest32,
    route_scope_digest: Digest32,
    registry_digest: Digest32,
    registry_epoch: u64,
    profile_bundle_digest: Digest32,
    solver: ParticipantId,
    inventory_binding_digest: Digest32,
    bond_policy_hash: Digest32,
    bond_asset_binding_digest: Digest32,
    required_collateral: u128,
    status_max_lifetime_seconds: u64,
    pre_f6_limits: PreF6TimePolicyLimitsV2,
    bond_authorities: AuthoritySetV1,
    status_authorities: AuthoritySetV1,
    reserved_relay_keys: Vec<[u8; 32]>,
    reserved_participant_keys: Vec<[u8; 32]>,
    reserved_chain_keys: Vec<[u8; 32]>,
    upstream_signers: Vec<ProductionF6BondSignerDescriptorV7>,
    downstream_signers: Vec<ProductionF6BondSignerDescriptorV7>,
    role_plan: ComposedFinalClaimRolePlanV1,
    upstream_source_scope: FinalClaimSecretSourceScopeV1,
    downstream_source_scope: FinalClaimSecretSourceScopeV1,
}

impl core::fmt::Debug for AuthenticatedProductionF6AuthorityBundleV7 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("AuthenticatedProductionF6AuthorityBundleV7([authority redacted])")
    }
}

impl AuthenticatedProductionF6AuthorityBundleV7 {
    /// Solver identity authenticated by the threshold-signed bundle.
    ///
    /// This is the only pre-RFQ solver accessor exposed to the composition
    /// root. It carries no inventory lease, epoch, store handle or signer
    /// material, so callers cannot use it to anticipate an RFQ-late fence.
    pub(crate) const fn solver(&self) -> ParticipantId {
        self.solver
    }

    /// Acquires or renews the exact inventory lease only after both RFQs have
    /// authenticated. The solver comes solely from this threshold-signed
    /// bundle and wall time is sampled inside this boundary.
    fn bind_inventory_lease(
        &self,
        inventory: &mut DurableInventoryStoreV1,
        owner_id: Digest32,
        duration_ms: u64,
    ) -> Result<InventoryLeaseV1, ProductionF6ActivationRefusalV2> {
        let elapsed = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| ProductionF6ActivationRefusalV2::Unavailable)?;
        let now_unix_ms = u64::try_from(elapsed.as_millis())
            .map_err(|_| ProductionF6ActivationRefusalV2::Unavailable)?;
        self.bind_inventory_lease_at(inventory, owner_id, now_unix_ms, duration_ms)
    }

    fn bind_inventory_lease_at(
        &self,
        inventory: &mut DurableInventoryStoreV1,
        owner_id: Digest32,
        now_unix_ms: u64,
        duration_ms: u64,
    ) -> Result<InventoryLeaseV1, ProductionF6ActivationRefusalV2> {
        acquire_or_renew_inventory_lease_at(
            inventory,
            self.inventory_binding_digest,
            self.solver,
            owner_id,
            now_unix_ms,
            duration_ms,
        )
    }

    pub(crate) fn decode_and_authenticate(
        bytes: &[u8],
        authenticated: &AuthenticatedProductionInputsV1,
    ) -> Result<Self, ProductionF6ActivationRefusalV2> {
        if bytes.len() > MAX_BUNDLE_BYTES_V7 {
            return Err(ProductionF6ActivationRefusalV2::InvalidBinding);
        }
        let mut reader = BundleReaderV7::new(bytes);
        if reader.take::<8>()? != *BUNDLE_MAGIC_V7
            || reader.u16()? != BUNDLE_VERSION_V7
            || reader.u16()? != 0
        {
            return Err(ProductionF6ActivationRefusalV2::InvalidBinding);
        }
        let network_id = reader.take::<32>()?;
        let route_id = reader.take::<32>()?;
        let composition_digest = reader.take::<32>()?;
        let route_scope_digest = reader.take::<32>()?;
        let registry_digest = reader.take::<32>()?;
        let registry_epoch = reader.u64()?;
        let profile_bundle_digest = reader.take::<32>()?;
        let solver = ParticipantId(reader.take::<32>()?);
        let inventory_binding_digest = reader.take::<32>()?;
        let bond_policy_hash = reader.take::<32>()?;
        let bond_asset_binding_digest = reader.take::<32>()?;
        let required_collateral = reader.u128()?;
        let status_max_lifetime_seconds = reader.u64()?;
        let pre_f6_limits = PreF6TimePolicyLimitsV2 {
            valid_from_seconds: reader.u64()?,
            expires_at_seconds: reader.u64()?,
            max_evidence_age_seconds: reader.u64()?,
        };
        let bond_authorities = decode_authorities(&mut reader)?;
        let status_authorities = decode_authorities(&mut reader)?;
        let reserved_relay_keys = decode_keys(&mut reader)?;
        let reserved_participant_keys = decode_keys(&mut reader)?;
        let reserved_chain_keys = decode_keys(&mut reader)?;
        let upstream_signers = decode_signers(&mut reader)?;
        let downstream_signers = decode_signers(&mut reader)?;
        let role_plan = ComposedFinalClaimRolePlanV1::decode_canonical(
            reader.bytes_exact(FINAL_CLAIM_ROLE_PLAN_BYTES_V7)?,
        )
        .map_err(|_| ProductionF6ActivationRefusalV2::InvalidBinding)?;
        let upstream_source_scope = FinalClaimSecretSourceScopeV1::decode_canonical(
            reader.bytes_exact(FINAL_CLAIM_SOURCE_SCOPE_BYTES_V7)?,
        )
        .map_err(|_| ProductionF6ActivationRefusalV2::InvalidBinding)?;
        let downstream_source_scope = FinalClaimSecretSourceScopeV1::decode_canonical(
            reader.bytes_exact(FINAL_CLAIM_SOURCE_SCOPE_BYTES_V7)?,
        )
        .map_err(|_| ProductionF6ActivationRefusalV2::InvalidBinding)?;
        let signed_prefix_len = reader.position();
        verify_bundle_signatures(
            &mut reader,
            &bytes[..signed_prefix_len],
            authenticated.registry_authorities(),
            authenticated.time_verification_context(),
        )?;
        reader.finish()?;
        let value = Self {
            network_id,
            route_id,
            composition_digest,
            route_scope_digest,
            registry_digest,
            registry_epoch,
            profile_bundle_digest,
            solver,
            inventory_binding_digest,
            bond_policy_hash,
            bond_asset_binding_digest,
            required_collateral,
            status_max_lifetime_seconds,
            pre_f6_limits,
            bond_authorities,
            status_authorities,
            reserved_relay_keys,
            reserved_participant_keys,
            reserved_chain_keys,
            upstream_signers,
            downstream_signers,
            role_plan,
            upstream_source_scope,
            downstream_source_scope,
        };
        value.validate(authenticated.time_verification_context())?;
        if value.network_id != authenticated.roster_bundle().network_id()
            || value.route_id != authenticated.admission().route_id()
            || value.composition_digest != authenticated.composition().binding_digest()
            || value.route_scope_digest != authenticated.composition().route_scope_digest()
            || value.registry_digest != authenticated.resolved_registry().manifest_digest()
            || value.registry_epoch != authenticated.resolved_registry().epoch()
            || value.profile_bundle_digest
                != authenticated
                    .admission()
                    .frozen_bindings()
                    .profile_bundle_digest
        {
            return Err(ProductionF6ActivationRefusalV2::InvalidBinding);
        }
        let expected_relay_keys: Vec<_> = authenticated
            .roster_bundle()
            .legs()
            .iter()
            .flat_map(|leg| leg.members.iter().map(|member| member.xonly_key))
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        let expected_chain_keys: Vec<_> = authenticated
            .registry_authorities()
            .xonly_keys()
            .iter()
            .chain(authenticated.time_policy_authorities().xonly_keys())
            .chain(authenticated.time_evidence_authorities().xonly_keys())
            .copied()
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        let expected_chain_key_count = authenticated.registry_authorities().xonly_keys().len()
            + authenticated.time_policy_authorities().xonly_keys().len()
            + authenticated.time_evidence_authorities().xonly_keys().len();
        if expected_chain_keys.len() != expected_chain_key_count
            || value.reserved_relay_keys != expected_relay_keys
            || value.reserved_chain_keys != expected_chain_keys
        {
            return Err(ProductionF6ActivationRefusalV2::InvalidBinding);
        }
        value
            .role_plan
            .authenticate(
                authenticated.composition().upstream(),
                authenticated.composition().downstream(),
                value.upstream_source_scope.clone(),
                value.downstream_source_scope.clone(),
            )
            .map_err(|_| ProductionF6ActivationRefusalV2::InvalidBinding)?;
        Ok(value)
    }

    fn validate(&self, secp: &SecpContext) -> Result<(), ProductionF6ActivationRefusalV2> {
        if [
            self.network_id,
            self.route_id,
            self.composition_digest,
            self.route_scope_digest,
            self.registry_digest,
            self.profile_bundle_digest,
            self.solver.0,
            self.inventory_binding_digest,
            self.bond_policy_hash,
            self.bond_asset_binding_digest,
        ]
        .contains(&ZERO_DIGEST)
            || self.registry_epoch == 0
            || self.required_collateral == 0
            || self.status_max_lifetime_seconds == 0
            || self.pre_f6_limits.valid_from_seconds >= self.pre_f6_limits.expires_at_seconds
            || self.pre_f6_limits.max_evidence_age_seconds == 0
            || self.role_plan.route_id() != self.route_id
            || self.role_plan.route_scope_digest() != self.route_scope_digest
            || self.role_plan.composition_binding_digest() != self.composition_digest
            || self.bond_authorities.threshold() < 2
            || self.bond_authorities.xonly_keys().len() < 2
            || self.status_authorities.threshold() < 2
            || self.status_authorities.xonly_keys().len() < 2
        {
            return Err(ProductionF6ActivationRefusalV2::InvalidBinding);
        }
        bond_reservation_authority_set_digest_v2(&self.bond_authorities, secp)
            .map_err(|_| ProductionF6ActivationRefusalV2::InvalidBinding)?;
        candidate_status_authority_set_digest_v2(&self.status_authorities, secp)
            .map_err(|_| ProductionF6ActivationRefusalV2::InvalidBinding)?;
        let status_keys: BTreeSet<_> = self
            .status_authorities
            .xonly_keys()
            .iter()
            .copied()
            .collect();
        if self
            .bond_authorities
            .xonly_keys()
            .iter()
            .any(|key| status_keys.contains(key))
        {
            return Err(ProductionF6ActivationRefusalV2::InvalidBinding);
        }
        validate_signer_descriptors(&self.bond_authorities, &self.upstream_signers)?;
        validate_signer_descriptors(&self.bond_authorities, &self.downstream_signers)?;
        ProductionF6ReservedSignerKeysV2::new(
            self.reserved_relay_keys.clone(),
            self.reserved_participant_keys.clone(),
            self.reserved_chain_keys.clone(),
        )
        .map_err(|_| ProductionF6ActivationRefusalV2::InvalidBinding)?;
        let reserved: BTreeSet<_> = self
            .reserved_relay_keys
            .iter()
            .chain(&self.reserved_participant_keys)
            .chain(&self.reserved_chain_keys)
            .copied()
            .collect();
        if self
            .bond_authorities
            .xonly_keys()
            .iter()
            .chain(self.status_authorities.xonly_keys())
            .any(|key| reserved.contains(key))
        {
            return Err(ProductionF6ActivationRefusalV2::InvalidBinding);
        }
        Ok(())
    }
}

fn acquire_or_renew_inventory_lease_at(
    inventory: &mut DurableInventoryStoreV1,
    expected_store_binding: Digest32,
    authenticated_solver: ParticipantId,
    owner_id: Digest32,
    now_unix_ms: u64,
    duration_ms: u64,
) -> Result<InventoryLeaseV1, ProductionF6ActivationRefusalV2> {
    if inventory.binding_digest() != expected_store_binding
        || authenticated_solver.0 == ZERO_DIGEST
        || owner_id == ZERO_DIGEST
        || now_unix_ms == 0
        || duration_ms == 0
        || duration_ms > MAX_F6_INVENTORY_LEASE_DURATION_MS_V7
    {
        return Err(ProductionF6ActivationRefusalV2::InvalidBinding);
    }
    let outcome = inventory
        .acquire_lease(authenticated_solver, owner_id, now_unix_ms, duration_ms)
        .map_err(|_| ProductionF6ActivationRefusalV2::Unavailable)?;
    let lease = match outcome {
        LeaseAcquireOutcomeV1::Acquired(lease) => lease,
        LeaseAcquireOutcomeV1::AlreadyOwned(lease) => inventory
            .renew_lease(lease, now_unix_ms, duration_ms)
            .map_err(|_| ProductionF6ActivationRefusalV2::Unavailable)?,
    };
    let expected_until = now_unix_ms
        .checked_add(duration_ms)
        .ok_or(ProductionF6ActivationRefusalV2::InvalidBinding)?;
    if lease.authority_id != authenticated_solver
        || lease.owner_id != owner_id
        || lease.fencing_epoch == 0
        || lease.lease_until_unix_ms != expected_until
    {
        return Err(ProductionF6ActivationRefusalV2::Unavailable);
    }
    Ok(lease)
}

/// Route facts copied only from `AuthenticatedProductionInputsV1`.
pub(crate) struct ProductionF6AuthenticatedRouteContextV7 {
    network_id: Digest32,
    route_id: Digest32,
    composition_digest: Digest32,
    route_scope_digest: Digest32,
    profile_bundle_digest: Digest32,
    registry: ResolvedRegistryV1,
    rosters: RosterRegistryV1,
    roster_legs: [ProductionRosterLegV1; 2],
    pre_f6_authorities: AuthoritySetV1,
}

impl ProductionF6AuthenticatedRouteContextV7 {
    pub(crate) fn from_authenticated(inputs: &AuthenticatedProductionInputsV1) -> Self {
        Self {
            network_id: inputs.roster_bundle().network_id(),
            route_id: inputs.admission().route_id(),
            composition_digest: inputs.composition().binding_digest(),
            route_scope_digest: inputs.composition().route_scope_digest(),
            profile_bundle_digest: inputs.admission().frozen_bindings().profile_bundle_digest,
            registry: inputs.resolved_registry().clone(),
            rosters: inputs.roster_registry().clone(),
            roster_legs: *inputs.roster_bundle().legs(),
            pre_f6_authorities: inputs.time_evidence_authorities().clone(),
        }
    }
}

/// Concrete counterparty face owner for one position.
pub(crate) enum ProductionF6CounterpartyTermsOwnerV7 {
    Bitcoin {
        payout: AuthenticatedBitcoinPayoutFaceV1,
        deployment: ResolvedBitcoinDeploymentV1,
    },
    Evm(ResolvedEvmDeploymentV1),
}

/// Both DOM payout owners plus both exact counterparty deployments/owners.
pub(crate) struct ProductionF6TermsOwnersV7 {
    pub upstream_dom: AuthenticatedDomPayoutFaceV1,
    pub downstream_dom: AuthenticatedDomPayoutFaceV1,
    pub upstream_counterparty: ProductionF6CounterpartyTermsOwnerV7,
    pub downstream_counterparty: ProductionF6CounterpartyTermsOwnerV7,
}

/// One credential per signed signer descriptor, in exact authority-set order.
pub(crate) struct ProductionF6BondSignerCredentialsV7 {
    pub upstream: Vec<Zeroizing<[u8; 32]>>,
    pub downstream: Vec<Zeroizing<[u8; 32]>>,
}

/// Complete move-only request for the concrete pair factory. Grouping keeps
/// route, storage, payout and signer owners from being positionally swapped.
pub(crate) struct ProductionF6PairFactoryRequestV7 {
    pub bundle: AuthenticatedProductionF6AuthorityBundleV7,
    pub route: ProductionF6AuthenticatedRouteContextV7,
    pub composition: Rc<ComposedBindingV2>,
    pub paths: ProductionF6ExternalPathsV7,
    pub prepared: ProductionF6ExternalPreparedBindingsV7,
    pub inventory: DurableInventoryStoreV1,
    pub inventory_owner_id: Digest32,
    pub inventory_lease_duration_ms: u64,
    pub terms: ProductionF6TermsOwnersV7,
    pub credentials: ProductionF6BondSignerCredentialsV7,
}

/// One-shot final-claim plan authenticated by the same route/root bundle as
/// the F6 pair. It exposes no decoder or raw constructor and is consumed by
/// the settlement materialization owner.
pub(crate) struct AuthenticatedProductionF6FinalClaimPlanV7 {
    role_plan: ComposedFinalClaimRolePlanV1,
    upstream_source_scope: FinalClaimSecretSourceScopeV1,
    downstream_source_scope: FinalClaimSecretSourceScopeV1,
}

impl core::fmt::Debug for AuthenticatedProductionF6FinalClaimPlanV7 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("AuthenticatedProductionF6FinalClaimPlanV7([plan redacted])")
    }
}

impl AuthenticatedProductionF6FinalClaimPlanV7 {
    pub(crate) fn into_parts(
        self,
    ) -> (
        ComposedFinalClaimRolePlanV1,
        FinalClaimSecretSourceScopeV1,
        FinalClaimSecretSourceScopeV1,
    ) {
        (
            self.role_plan,
            self.upstream_source_scope,
            self.downstream_source_scope,
        )
    }
}

struct ProductionF6BoundPairV7 {
    upstream_binding: ProductionSolverF6BindingV2,
    downstream_binding: ProductionSolverF6BindingV2,
    shared: ProductionF6SharedAuthorityOwnerV2,
    upstream_candidate: ProductionF6CandidateAttestationAuthorityStoreV2,
    downstream_candidate: ProductionF6CandidateAttestationAuthorityStoreV2,
    upstream_terms: ProductionAdapterF6TermsAuthorityV2,
    downstream_terms: ProductionAdapterF6TermsAuthorityV2,
    upstream_secp: SecpContext,
    downstream_secp: SecpContext,
}

/// Move-only result proving that both Relay RFQs were authenticated and the
/// exact inventory lease was acquired or renewed afterwards.
///
/// Its constructor is private to this module. In particular, neither the
/// composition root nor the activation request can supply a caller-shaped
/// fencing epoch. The terminal split receives only the generation returned by
/// the inventory authority used to build the shared F6 owner.
pub(crate) struct AuthenticatedProductionF6PairBindingV7 {
    upstream: ProductionSolverF6BindingV2,
    downstream: ProductionSolverF6BindingV2,
    inventory_fencing_epoch: u64,
}

impl core::fmt::Debug for AuthenticatedProductionF6PairBindingV7 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("AuthenticatedProductionF6PairBindingV7([binding redacted])")
    }
}

impl AuthenticatedProductionF6PairBindingV7 {
    fn new(
        upstream: ProductionSolverF6BindingV2,
        downstream: ProductionSolverF6BindingV2,
        inventory_lease: InventoryLeaseV1,
    ) -> Result<Self, ProductionF6ActivationRefusalV2> {
        let inventory_fencing_epoch = exact_inventory_fencing_epoch(inventory_lease)?;
        Ok(Self {
            upstream,
            downstream,
            inventory_fencing_epoch,
        })
    }

    pub(crate) const fn into_parts(
        self,
    ) -> (
        ProductionSolverF6BindingV2,
        ProductionSolverF6BindingV2,
        u64,
    ) {
        (self.upstream, self.downstream, self.inventory_fencing_epoch)
    }
}

fn exact_inventory_fencing_epoch(
    inventory_lease: InventoryLeaseV1,
) -> Result<u64, ProductionF6ActivationRefusalV2> {
    if inventory_lease.authority_id.0 == ZERO_DIGEST
        || inventory_lease.owner_id == ZERO_DIGEST
        || inventory_lease.fencing_epoch == 0
        || inventory_lease.lease_until_unix_ms == 0
    {
        return Err(ProductionF6ActivationRefusalV2::InvalidBinding);
    }
    Ok(inventory_lease.fencing_epoch)
}

/// Sole concrete implementation of the sealed pair-factory trait.
pub(crate) struct ProductionF6PairAuthoritiesFactoryV7 {
    bundle: AuthenticatedProductionF6AuthorityBundleV7,
    route: ProductionF6AuthenticatedRouteContextV7,
    composition: Rc<ComposedBindingV2>,
    paths: ProductionF6ExternalPathsV7,
    prepared: ProductionF6ExternalPreparedBindingsV7,
    inventory: Option<DurableInventoryStoreV1>,
    inventory_owner_id: Digest32,
    inventory_lease_duration_ms: u64,
    terms: Option<ProductionF6TermsOwnersV7>,
    credentials: Option<ProductionF6BondSignerCredentialsV7>,
    final_claim_plan: Option<AuthenticatedProductionF6FinalClaimPlanV7>,
    bound: Option<ProductionF6BoundPairV7>,
    poisoned: bool,
}

impl core::fmt::Debug for ProductionF6PairAuthoritiesFactoryV7 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("ProductionF6PairAuthoritiesFactoryV7")
            .field("bound", &self.bound.is_some())
            .field("poisoned", &self.poisoned)
            .finish_non_exhaustive()
    }
}

impl ProductionF6PairAuthoritiesFactoryV7 {
    pub(crate) fn new(
        request: ProductionF6PairFactoryRequestV7,
    ) -> Result<Self, ProductionF6ActivationRefusalV2> {
        let ProductionF6PairFactoryRequestV7 {
            bundle,
            route,
            composition,
            paths,
            prepared,
            inventory,
            inventory_owner_id,
            inventory_lease_duration_ms,
            terms,
            credentials,
        } = request;
        if bundle.network_id != route.network_id
            || bundle.route_id != route.route_id
            || bundle.composition_digest != route.composition_digest
            || bundle.route_scope_digest != route.route_scope_digest
            || bundle.registry_digest != route.registry.manifest_digest()
            || bundle.registry_epoch != route.registry.epoch()
            || bundle.profile_bundle_digest != route.profile_bundle_digest
            || bundle.inventory_binding_digest != inventory.binding_digest()
            || inventory_owner_id == ZERO_DIGEST
            || inventory_lease_duration_ms == 0
            || inventory_lease_duration_ms > MAX_F6_INVENTORY_LEASE_DURATION_MS_V7
            || composition.binding_digest() != route.composition_digest
            || composition.route_scope_digest() != route.route_scope_digest
            || credentials.upstream.len() != bundle.upstream_signers.len()
            || credentials.downstream.len() != bundle.downstream_signers.len()
            || !credentials_are_independent(&credentials.upstream)
            || !credentials_are_independent(&credentials.downstream)
        {
            return Err(ProductionF6ActivationRefusalV2::InvalidBinding);
        }
        bundle
            .role_plan
            .authenticate(
                composition.upstream(),
                composition.downstream(),
                bundle.upstream_source_scope.clone(),
                bundle.downstream_source_scope.clone(),
            )
            .map_err(|_| ProductionF6ActivationRefusalV2::InvalidBinding)?;
        let final_claim_plan = AuthenticatedProductionF6FinalClaimPlanV7 {
            role_plan: bundle.role_plan.clone(),
            upstream_source_scope: bundle.upstream_source_scope.clone(),
            downstream_source_scope: bundle.downstream_source_scope.clone(),
        };
        Ok(Self {
            bundle,
            route,
            composition,
            paths,
            prepared,
            inventory: Some(inventory),
            inventory_owner_id,
            inventory_lease_duration_ms,
            terms: Some(terms),
            credentials: Some(credentials),
            final_claim_plan: Some(final_claim_plan),
            bound: None,
            poisoned: false,
        })
    }

    /// Separates the one authenticated public plan for the materializer before
    /// this factory is erased behind the sealed F6 trait.
    pub(crate) fn take_final_claim_plan(
        &mut self,
    ) -> Result<AuthenticatedProductionF6FinalClaimPlanV7, ProductionF6ActivationRefusalV2> {
        if self.poisoned || self.bound.is_some() {
            return Err(ProductionF6ActivationRefusalV2::Unavailable);
        }
        self.final_claim_plan
            .take()
            .ok_or(ProductionF6ActivationRefusalV2::Unavailable)
    }

    fn bind_pair_inner(
        &mut self,
        upstream_wire: RouteWireContextV1,
        upstream_rfq: RfqV2,
        downstream_wire: RouteWireContextV1,
        downstream_rfq: RfqV2,
    ) -> Result<AuthenticatedProductionF6PairBindingV7, ProductionF6ActivationRefusalV2> {
        if self.poisoned || self.bound.is_some() || self.final_claim_plan.is_some() {
            return Err(ProductionF6ActivationRefusalV2::Unavailable);
        }
        validate_wire_rfq(
            &self.route,
            &self.bundle,
            self.route.roster_legs[0],
            SettlementPositionV2::Upstream,
            upstream_wire,
            &upstream_rfq,
        )?;
        validate_wire_rfq(
            &self.route,
            &self.bundle,
            self.route.roster_legs[1],
            SettlementPositionV2::Downstream,
            downstream_wire,
            &downstream_rfq,
        )?;

        // This is the first durable economic effect: both Relay RFQs are
        // authenticated before a fresh lease is acquired or exactly renewed.
        let inventory_lease = self.bundle.bind_inventory_lease(
            self.inventory
                .as_mut()
                .ok_or(ProductionF6ActivationRefusalV2::Unavailable)?,
            self.inventory_owner_id,
            self.inventory_lease_duration_ms,
        )?;

        let upstream_secp = fresh_secp()?;
        let downstream_secp = fresh_secp()?;
        let upstream_scope = pre_f6_scope(&self.route, upstream_wire, &upstream_rfq)?;
        let downstream_scope = pre_f6_scope(&self.route, downstream_wire, &downstream_rfq)?;
        let upstream_policy = PreF6TimePolicyV2::from_registry(
            upstream_scope,
            &self.route.registry,
            self.bundle.pre_f6_limits,
        )
        .map_err(|_| ProductionF6ActivationRefusalV2::InvalidBinding)?;
        let downstream_policy = PreF6TimePolicyV2::from_registry(
            downstream_scope,
            &self.route.registry,
            self.bundle.pre_f6_limits,
        )
        .map_err(|_| ProductionF6ActivationRefusalV2::InvalidBinding)?;

        let upstream_status_config =
            status_config(&self.route, &self.bundle, upstream_wire, &upstream_secp)?;
        let downstream_status_config =
            status_config(&self.route, &self.bundle, downstream_wire, &downstream_secp)?;
        if upstream_scope.scope_digest() == downstream_scope.scope_digest()
            || upstream_status_config
                .store_binding_digest()
                .map_err(|_| ProductionF6ActivationRefusalV2::InvalidBinding)?
                == downstream_status_config
                    .store_binding_digest()
                    .map_err(|_| ProductionF6ActivationRefusalV2::InvalidBinding)?
        {
            return Err(ProductionF6ActivationRefusalV2::InvalidBinding);
        }
        let upstream_pins = pins(
            &self.bundle,
            upstream_status_config,
            upstream_scope.scope_digest(),
            &upstream_secp,
        )?;
        let downstream_pins = pins(
            &self.bundle,
            downstream_status_config,
            downstream_scope.scope_digest(),
            &downstream_secp,
        )?;
        let upstream_binding = ProductionSolverF6BindingV2::new(
            upstream_wire,
            &upstream_rfq,
            self.bundle.solver,
            self.route.registry.manifest().dom.chain_id,
            upstream_pins,
        )
        .map_err(|_| ProductionF6ActivationRefusalV2::InvalidBinding)?;
        let downstream_binding = ProductionSolverF6BindingV2::new(
            downstream_wire,
            &downstream_rfq,
            self.bundle.solver,
            self.route.registry.manifest().dom.chain_id,
            downstream_pins,
        )
        .map_err(|_| ProductionF6ActivationRefusalV2::InvalidBinding)?;

        let credentials = self
            .credentials
            .take()
            .ok_or(ProductionF6ActivationRefusalV2::Unavailable)?;
        let upstream_signers = open_signers(&self.bundle.upstream_signers, credentials.upstream)?;
        let downstream_signers =
            open_signers(&self.bundle.downstream_signers, credentials.downstream)?;
        let upstream_candidate = open_candidate(
            &self.paths.upstream_candidate,
            self.prepared.upstream_candidate,
            upstream_binding,
            &self.bundle,
            upstream_signers,
        )?;
        let downstream_candidate = open_candidate(
            &self.paths.downstream_candidate,
            self.prepared.downstream_candidate,
            downstream_binding,
            &self.bundle,
            downstream_signers,
        )?;
        let upstream_status = DurableSolverStatusStoreV1::open_or_resume_prepared_production(
            &self.paths.upstream_status,
            self.prepared.upstream_status,
            upstream_status_config,
            self.bundle.status_authorities.clone(),
            &upstream_secp,
        )
        .map_err(|_| ProductionF6ActivationRefusalV2::Unavailable)?;
        let downstream_status = DurableSolverStatusStoreV1::open_or_resume_prepared_production(
            &self.paths.downstream_status,
            self.prepared.downstream_status,
            downstream_status_config,
            self.bundle.status_authorities.clone(),
            &downstream_secp,
        )
        .map_err(|_| ProductionF6ActivationRefusalV2::Unavailable)?;
        let upstream_time = DurablePreF6TimeStoreV2::open_or_resume_prepared_production(
            &self.paths.upstream_time,
            self.prepared.upstream_time,
            upstream_policy,
            self.route.pre_f6_authorities.clone(),
            &upstream_secp,
        )
        .map_err(|_| ProductionF6ActivationRefusalV2::Unavailable)?;
        let downstream_time = DurablePreF6TimeStoreV2::open_or_resume_prepared_production(
            &self.paths.downstream_time,
            self.prepared.downstream_time,
            downstream_policy,
            self.route.pre_f6_authorities.clone(),
            &downstream_secp,
        )
        .map_err(|_| ProductionF6ActivationRefusalV2::Unavailable)?;
        let inventory = self
            .inventory
            .take()
            .ok_or(ProductionF6ActivationRefusalV2::Unavailable)?;
        let shared = ProductionF6SharedAuthorityOwnerV2::new(
            inventory,
            inventory_lease,
            self.inventory_owner_id,
            self.inventory_lease_duration_ms,
            upstream_status,
            downstream_status,
            upstream_time,
            downstream_time,
        );
        let terms = self
            .terms
            .take()
            .ok_or(ProductionF6ActivationRefusalV2::Unavailable)?;
        let (upstream_terms, downstream_terms) = build_terms_pair(
            &self.route,
            &self.composition,
            upstream_binding,
            downstream_binding,
            terms,
        )?;
        let authenticated_pair = AuthenticatedProductionF6PairBindingV7::new(
            upstream_binding,
            downstream_binding,
            inventory_lease,
        )?;
        self.bound = Some(ProductionF6BoundPairV7 {
            upstream_binding,
            downstream_binding,
            shared,
            upstream_candidate,
            downstream_candidate,
            upstream_terms,
            downstream_terms,
            upstream_secp,
            downstream_secp,
        });
        Ok(authenticated_pair)
    }
}

impl pair_factory_seal::Sealed for ProductionF6PairAuthoritiesFactoryV7 {}

impl ProductionF6PairAuthoritiesFactoryV2 for ProductionF6PairAuthoritiesFactoryV7 {
    fn bind_pair(
        &mut self,
        upstream_wire: RouteWireContextV1,
        upstream_rfq: RfqV2,
        downstream_wire: RouteWireContextV1,
        downstream_rfq: RfqV2,
    ) -> Result<AuthenticatedProductionF6PairBindingV7, ProductionF6ActivationRefusalV2> {
        let result =
            self.bind_pair_inner(upstream_wire, upstream_rfq, downstream_wire, downstream_rfq);
        if result.is_err() {
            self.poisoned = true;
        }
        result
    }

    fn build_authorities(
        &mut self,
        upstream_binding: ProductionSolverF6BindingV2,
        upstream_terminal: ProductionRouteTerminalAuthorityV2,
        downstream_binding: ProductionSolverF6BindingV2,
        downstream_terminal: ProductionRouteTerminalAuthorityV2,
    ) -> Result<
        (ProductionF6AuthoritiesV2, ProductionF6AuthoritiesV2),
        ProductionF6ActivationRefusalV2,
    > {
        if self.poisoned {
            return Err(ProductionF6ActivationRefusalV2::Unavailable);
        }
        let bound = self
            .bound
            .take()
            .ok_or(ProductionF6ActivationRefusalV2::Unavailable)?;
        if bound.upstream_binding != upstream_binding
            || bound.downstream_binding != downstream_binding
        {
            self.poisoned = true;
            return Err(ProductionF6ActivationRefusalV2::InvalidBinding);
        }
        let (upstream_shared, downstream_shared) = bound.shared.into_two_legs();
        let upstream = ProductionF6AuthoritiesV2 {
            shared: upstream_shared,
            bond_attestation_authorities: self.bundle.bond_authorities.clone(),
            remote_status_authorities: self.bundle.status_authorities.clone(),
            secp: bound.upstream_secp,
            rosters: self.route.rosters.clone(),
            sources: ProductionF6SourcesV2::new(
                Box::new(bound.upstream_terms),
                Box::new(upstream_terminal),
                Box::new(bound.upstream_candidate),
            ),
        };
        let downstream = ProductionF6AuthoritiesV2 {
            shared: downstream_shared,
            bond_attestation_authorities: self.bundle.bond_authorities.clone(),
            remote_status_authorities: self.bundle.status_authorities.clone(),
            secp: bound.downstream_secp,
            rosters: self.route.rosters.clone(),
            sources: ProductionF6SourcesV2::new(
                Box::new(bound.downstream_terms),
                Box::new(downstream_terminal),
                Box::new(bound.downstream_candidate),
            ),
        };
        Ok((upstream, downstream))
    }
}

struct ProductionF6UnixBondSignerV7 {
    descriptor: ProductionF6BondSignerDescriptorV7,
    credential: Zeroizing<[u8; 32]>,
    endpoint_device: u64,
    endpoint_inode: u64,
}

/// Authenticated, purpose-limited request exposed to the independent signer
/// service. Decoding verifies the client MAC and the canonical public bond
/// statement before the HSM policy is allowed to consider signing it.
pub(crate) struct ProductionF6HsmSigningRequestV7 {
    signer_index: u16,
    signer_public_key: [u8; 32],
    intent_digest: Digest32,
    attestation_digest: Digest32,
    attestation: BondReservationAttestationV2,
}

impl ProductionF6HsmSigningRequestV7 {
    #[expect(
        dead_code,
        reason = "retained surface not yet wired by the stage-7 composition root"
    )]
    pub(crate) fn decode_and_authenticate(
        bytes: &[u8],
        credential: &[u8; 32],
        expected_signer_index: u16,
        expected_signer_public_key: [u8; 32],
    ) -> Result<Self, ProductionF6BondSignerErrorV2> {
        if credential.iter().all(|byte| *byte == 0)
            || bytes.len() < 144
            || bytes.len() > 144 + MAX_ATTESTATION_BYTES_V7
            || bytes.get(..8) != Some(HSM_REQUEST_MAGIC_V7.as_slice())
            || bytes.get(8..10) != Some(HSM_VERSION_V7.to_be_bytes().as_slice())
        {
            return Err(ProductionF6BondSignerErrorV2::Refused);
        }
        let signer_index = u16::from_be_bytes(
            bytes[10..12]
                .try_into()
                .map_err(|_| ProductionF6BondSignerErrorV2::Refused)?,
        );
        let signer_public_key = bytes[12..44]
            .try_into()
            .map_err(|_| ProductionF6BondSignerErrorV2::Refused)?;
        let intent_digest = bytes[44..76]
            .try_into()
            .map_err(|_| ProductionF6BondSignerErrorV2::Refused)?;
        let attestation_digest = bytes[76..108]
            .try_into()
            .map_err(|_| ProductionF6BondSignerErrorV2::Refused)?;
        let statement_len = usize::try_from(u32::from_be_bytes(
            bytes[108..112]
                .try_into()
                .map_err(|_| ProductionF6BondSignerErrorV2::Refused)?,
        ))
        .map_err(|_| ProductionF6BondSignerErrorV2::Refused)?;
        let tag_offset = 112_usize
            .checked_add(statement_len)
            .ok_or(ProductionF6BondSignerErrorV2::Refused)?;
        let expected_len = tag_offset
            .checked_add(32)
            .ok_or(ProductionF6BondSignerErrorV2::Refused)?;
        if statement_len == 0
            || statement_len > MAX_ATTESTATION_BYTES_V7
            || bytes.len() != expected_len
            || signer_index != expected_signer_index
            || signer_public_key != expected_signer_public_key
            || intent_digest == ZERO_DIGEST
            || attestation_digest == ZERO_DIGEST
        {
            return Err(ProductionF6BondSignerErrorV2::Refused);
        }
        let mut mac = <Blake2bMac256 as KeyInit>::new_from_slice(credential)
            .map_err(|_| ProductionF6BondSignerErrorV2::Refused)?;
        Mac::update(&mut mac, HSM_REQUEST_MAC_DOMAIN_V7);
        Mac::update(&mut mac, &bytes[..tag_offset]);
        mac.verify_slice(&bytes[tag_offset..])
            .map_err(|_| ProductionF6BondSignerErrorV2::Refused)?;
        let statement = &bytes[112..tag_offset];
        let attestation = BondReservationAttestationV2::decode(statement)
            .map_err(|_| ProductionF6BondSignerErrorV2::Refused)?;
        if attestation
            .attestation_digest()
            .map_err(|_| ProductionF6BondSignerErrorV2::Refused)?
            != attestation_digest
        {
            return Err(ProductionF6BondSignerErrorV2::Refused);
        }
        Ok(Self {
            signer_index,
            signer_public_key,
            intent_digest,
            attestation_digest,
            attestation,
        })
    }

    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "retained surface not yet wired by the stage-7 composition root"
        )
    )]
    pub(crate) const fn signer_index(&self) -> u16 {
        self.signer_index
    }

    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "retained surface not yet wired by the stage-7 composition root"
        )
    )]
    pub(crate) const fn signer_public_key(&self) -> [u8; 32] {
        self.signer_public_key
    }

    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "retained surface not yet wired by the stage-7 composition root"
        )
    )]
    pub(crate) const fn intent_digest(&self) -> Digest32 {
        self.intent_digest
    }

    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "retained surface not yet wired by the stage-7 composition root"
        )
    )]
    pub(crate) const fn attestation_digest(&self) -> Digest32 {
        self.attestation_digest
    }

    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "retained surface not yet wired by the stage-7 composition root"
        )
    )]
    pub(crate) const fn attestation(&self) -> BondReservationAttestationV2 {
        self.attestation
    }
}

/// Fixed response codec emitted by the signer service after its own policy
/// approves an authenticated request. The daemon still verifies the BIP340
/// signature against the threshold authority key before accepting it.
pub(crate) struct ProductionF6HsmSigningResponseV7 {
    signer_index: u16,
    intent_digest: Digest32,
    attestation_digest: Digest32,
    signature: [u8; 64],
}

impl ProductionF6HsmSigningResponseV7 {
    #[expect(
        dead_code,
        reason = "retained surface not yet wired by the stage-7 composition root"
    )]
    pub(crate) fn new(request: &ProductionF6HsmSigningRequestV7, signature: [u8; 64]) -> Self {
        Self {
            signer_index: request.signer_index,
            intent_digest: request.intent_digest,
            attestation_digest: request.attestation_digest,
            signature,
        }
    }

    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "retained surface not yet wired by the stage-7 composition root"
        )
    )]
    pub(crate) fn canonical_bytes(&self) -> [u8; MAX_HSM_RESPONSE_BYTES_V7] {
        let mut bytes = [0_u8; MAX_HSM_RESPONSE_BYTES_V7];
        bytes[..8].copy_from_slice(HSM_RESPONSE_MAGIC_V7);
        bytes[8..10].copy_from_slice(&HSM_VERSION_V7.to_be_bytes());
        bytes[10..12].copy_from_slice(&self.signer_index.to_be_bytes());
        bytes[12..44].copy_from_slice(&self.intent_digest);
        bytes[44..76].copy_from_slice(&self.attestation_digest);
        bytes[76..140].copy_from_slice(&self.signature);
        bytes
    }

    fn decode(
        bytes: &[u8; MAX_HSM_RESPONSE_BYTES_V7],
    ) -> Result<Self, ProductionF6BondSignerErrorV2> {
        if bytes[..8] != *HSM_RESPONSE_MAGIC_V7
            || u16::from_be_bytes([bytes[8], bytes[9]]) != HSM_VERSION_V7
        {
            return Err(ProductionF6BondSignerErrorV2::Refused);
        }
        Ok(Self {
            signer_index: u16::from_be_bytes([bytes[10], bytes[11]]),
            intent_digest: bytes[12..44]
                .try_into()
                .map_err(|_| ProductionF6BondSignerErrorV2::Refused)?,
            attestation_digest: bytes[44..76]
                .try_into()
                .map_err(|_| ProductionF6BondSignerErrorV2::Refused)?,
            signature: bytes[76..140]
                .try_into()
                .map_err(|_| ProductionF6BondSignerErrorV2::Refused)?,
        })
    }
}

impl ProductionF6UnixBondSignerV7 {
    fn open(
        descriptor: ProductionF6BondSignerDescriptorV7,
        credential: Zeroizing<[u8; 32]>,
    ) -> Result<Self, ProductionF6ActivationRefusalV2> {
        if credential.as_slice().iter().all(|byte| *byte == 0) {
            return Err(ProductionF6ActivationRefusalV2::InvalidBinding);
        }
        let metadata =
            authenticated_socket_metadata(&descriptor.endpoint, descriptor.endpoint_uid)?;
        Ok(Self {
            descriptor,
            credential,
            endpoint_device: metadata.dev(),
            endpoint_inode: metadata.ino(),
        })
    }

    fn request_bytes(
        &self,
        request: &PreparedF6BondAttestationSigningRequestV2,
    ) -> Result<Vec<u8>, ProductionF6BondSignerErrorV2> {
        let statement = request.attestation_bytes();
        if statement.is_empty() || statement.len() > MAX_ATTESTATION_BYTES_V7 {
            return Err(ProductionF6BondSignerErrorV2::Refused);
        }
        let length =
            u32::try_from(statement.len()).map_err(|_| ProductionF6BondSignerErrorV2::Refused)?;
        let mut bytes = Vec::with_capacity(144 + statement.len());
        bytes.extend_from_slice(HSM_REQUEST_MAGIC_V7);
        bytes.extend_from_slice(&HSM_VERSION_V7.to_be_bytes());
        bytes.extend_from_slice(&request.signer_index().to_be_bytes());
        bytes.extend_from_slice(&request.signer_public_key());
        bytes.extend_from_slice(&request.intent_digest());
        bytes.extend_from_slice(&request.attestation_digest());
        bytes.extend_from_slice(&length.to_be_bytes());
        bytes.extend_from_slice(statement);
        let mut mac = <Blake2bMac256 as KeyInit>::new_from_slice(self.credential.as_slice())
            .map_err(|_| ProductionF6BondSignerErrorV2::Refused)?;
        Mac::update(&mut mac, HSM_REQUEST_MAC_DOMAIN_V7);
        Mac::update(&mut mac, &bytes);
        bytes.extend_from_slice(&mac.finalize().into_bytes());
        Ok(bytes)
    }
}

impl crate::production_f6::source_seal::Sealed for ProductionF6UnixBondSignerV7 {}

impl ProductionF6BondAttestationSignerV2 for ProductionF6UnixBondSignerV7 {
    fn independent_authority_id(&self) -> Digest32 {
        self.descriptor.independent_authority_id
    }

    fn signer_index(&self) -> u16 {
        self.descriptor.signer_index
    }

    fn signer_public_key(&self) -> [u8; 32] {
        self.descriptor.signer_public_key
    }

    fn sign_bond_attestation(
        &mut self,
        request: &PreparedF6BondAttestationSigningRequestV2,
    ) -> Result<ProductionF6BondAttestationSignatureV2, ProductionF6BondSignerErrorV2> {
        if request.signer_index() != self.descriptor.signer_index
            || request.signer_public_key() != self.descriptor.signer_public_key
        {
            return Err(ProductionF6BondSignerErrorV2::Refused);
        }
        let metadata =
            authenticated_socket_metadata(&self.descriptor.endpoint, self.descriptor.endpoint_uid)
                .map_err(|_| ProductionF6BondSignerErrorV2::Unavailable)?;
        if metadata.dev() != self.endpoint_device || metadata.ino() != self.endpoint_inode {
            return Err(ProductionF6BondSignerErrorV2::Refused);
        }
        let mut stream = UnixStream::connect(&self.descriptor.endpoint)
            .map_err(|_| ProductionF6BondSignerErrorV2::Unavailable)?;
        let timeout = Some(Duration::from_secs(5));
        stream
            .set_read_timeout(timeout)
            .and_then(|_| stream.set_write_timeout(timeout))
            .map_err(|_| ProductionF6BondSignerErrorV2::Unavailable)?;
        let bytes = Zeroizing::new(self.request_bytes(request)?);
        stream
            .write_all(bytes.as_slice())
            .and_then(|_| stream.flush())
            .map_err(|_| ProductionF6BondSignerErrorV2::Unavailable)?;
        let mut response = [0_u8; MAX_HSM_RESPONSE_BYTES_V7];
        stream
            .read_exact(&mut response)
            .map_err(|_| ProductionF6BondSignerErrorV2::Unavailable)?;
        let response = ProductionF6HsmSigningResponseV7::decode(&response)?;
        if response.signer_index != request.signer_index()
            || response.intent_digest != request.intent_digest()
            || response.attestation_digest != request.attestation_digest()
        {
            return Err(ProductionF6BondSignerErrorV2::Refused);
        }
        Ok(ProductionF6BondAttestationSignatureV2::new(
            request.signer_index(),
            request.intent_digest(),
            request.attestation_digest(),
            response.signature,
        ))
    }
}

fn validate_wire_rfq(
    route: &ProductionF6AuthenticatedRouteContextV7,
    bundle: &AuthenticatedProductionF6AuthorityBundleV7,
    roster: ProductionRosterLegV1,
    position: SettlementPositionV2,
    wire: RouteWireContextV1,
    rfq: &RfqV2,
) -> Result<(), ProductionF6ActivationRefusalV2> {
    rfq.validate()
        .map_err(|_| ProductionF6ActivationRefusalV2::InvalidBinding)?;
    let expected_position = match position {
        SettlementPositionV2::Upstream => {
            crate::production_inputs::ProductionRoutePositionV1::Upstream
        }
        SettlementPositionV2::Downstream => {
            crate::production_inputs::ProductionRoutePositionV1::Downstream
        }
    };
    if wire.network_id != route.network_id
        || wire.route_id != route.route_id
        || wire.session_id != roster.session_id
        || wire.roster_snapshot != roster.roster_snapshot
        || wire.policy_version != roster.policy_version
        || roster.position != expected_position
        || rfq.session_id != wire.session_id
        || rfq.route.position != position
        || rfq.route.composition_id != route.composition_digest
        || rfq.initiator == bundle.solver
        || rfq.negotiation_clock.chain_id != route.registry.manifest().dom.chain_id
    {
        return Err(ProductionF6ActivationRefusalV2::InvalidBinding);
    }
    let solver_member = roster
        .members
        .iter()
        .find(|member| member.role == SenderRoleV1::Solver)
        .map(|member| member.participant_id);
    let initiator_member = roster
        .members
        .iter()
        .find(|member| member.role == SenderRoleV1::Initiator)
        .map(|member| member.participant_id);
    if solver_member != Some(bundle.solver) || initiator_member != Some(rfq.initiator) {
        return Err(ProductionF6ActivationRefusalV2::InvalidBinding);
    }
    Ok(())
}

fn pre_f6_scope(
    route: &ProductionF6AuthenticatedRouteContextV7,
    wire: RouteWireContextV1,
    rfq: &RfqV2,
) -> Result<PreF6TimeScopeV2, ProductionF6ActivationRefusalV2> {
    PreF6TimeScopeV2::new(PreF6TimeScopeRequestV2 {
        network_id: wire.network_id,
        session_id: wire.session_id,
        route_id: wire.route_id,
        composition_id: rfq.route.composition_id,
        rfq_id: rfq.rfq_id,
        negotiation_clock: rfq.negotiation_clock,
        registry_digest: route.registry.manifest_digest(),
        registry_epoch: route.registry.epoch(),
        profile_bundle_digest: route.profile_bundle_digest,
    })
    .map_err(|_| ProductionF6ActivationRefusalV2::InvalidBinding)
}

fn status_config(
    route: &ProductionF6AuthenticatedRouteContextV7,
    bundle: &AuthenticatedProductionF6AuthorityBundleV7,
    wire: RouteWireContextV1,
    secp: &SecpContext,
) -> Result<SolverStatusStoreConfigV1, ProductionF6ActivationRefusalV2> {
    SolverStatusStoreConfigV1::new(
        SolverStatusScopeV1 {
            network_id: wire.network_id,
            registry_digest: route.registry.manifest_digest(),
            registry_epoch: route.registry.epoch(),
            roster_snapshot: wire.roster_snapshot,
            solver_id: bundle.solver,
        },
        &bundle.status_authorities,
        secp,
        SolverStatusFreshnessPolicyV1 {
            max_status_lifetime_seconds: bundle.status_max_lifetime_seconds,
        },
    )
    .map_err(|_| ProductionF6ActivationRefusalV2::InvalidBinding)
}

fn pins(
    bundle: &AuthenticatedProductionF6AuthorityBundleV7,
    status: SolverStatusStoreConfigV1,
    pre_f6_scope_digest: Digest32,
    secp: &SecpContext,
) -> Result<ProductionF6PinsV2, ProductionF6ActivationRefusalV2> {
    Ok(ProductionF6PinsV2 {
        inventory_binding_digest: bundle.inventory_binding_digest,
        registry_digest: bundle.registry_digest,
        registry_epoch: bundle.registry_epoch,
        profile_bundle_digest: bundle.profile_bundle_digest,
        bond_policy_hash: bundle.bond_policy_hash,
        bond_asset_binding_digest: bundle.bond_asset_binding_digest,
        required_collateral: bundle.required_collateral,
        bond_attestation_authority_set_digest: bond_reservation_authority_set_digest_v2(
            &bundle.bond_authorities,
            secp,
        )
        .map_err(|_| ProductionF6ActivationRefusalV2::InvalidBinding)?,
        remote_status_authority_set_digest: candidate_status_authority_set_digest_v2(
            &bundle.status_authorities,
            secp,
        )
        .map_err(|_| ProductionF6ActivationRefusalV2::InvalidBinding)?,
        solver_status_scope_digest: status
            .store_binding_digest()
            .map_err(|_| ProductionF6ActivationRefusalV2::InvalidBinding)?,
        pre_f6_time_scope_digest: pre_f6_scope_digest,
    })
}

fn open_candidate(
    path: &Path,
    prepared: Digest32,
    binding: ProductionSolverF6BindingV2,
    bundle: &AuthenticatedProductionF6AuthorityBundleV7,
    signers: Vec<Box<dyn ProductionF6BondAttestationSignerV2>>,
) -> Result<ProductionF6CandidateAttestationAuthorityStoreV2, ProductionF6ActivationRefusalV2> {
    let secp = fresh_secp()?;
    let reserved = ProductionF6ReservedSignerKeysV2::new(
        bundle.reserved_relay_keys.clone(),
        bundle.reserved_participant_keys.clone(),
        bundle.reserved_chain_keys.clone(),
    )
    .map_err(|_| ProductionF6ActivationRefusalV2::InvalidBinding)?;
    ProductionF6CandidateAttestationAuthorityStoreV2::open_or_resume_prepared_production(
        path,
        prepared,
        binding,
        ProductionF6CandidateAuthorityInputsV2::new(
            bundle.bond_authorities.clone(),
            bundle.status_authorities.clone(),
            reserved,
            secp,
            signers,
        ),
    )
    .map_err(|_| ProductionF6ActivationRefusalV2::Unavailable)
}

fn build_terms_pair(
    route: &ProductionF6AuthenticatedRouteContextV7,
    composition: &ComposedBindingV2,
    upstream_binding: ProductionSolverF6BindingV2,
    downstream_binding: ProductionSolverF6BindingV2,
    owners: ProductionF6TermsOwnersV7,
) -> Result<
    (
        ProductionAdapterF6TermsAuthorityV2,
        ProductionAdapterF6TermsAuthorityV2,
    ),
    ProductionF6ActivationRefusalV2,
> {
    let dom_deployment = route
        .registry
        .resolve_dom()
        .map_err(|_| ProductionF6ActivationRefusalV2::InvalidBinding)?;
    let upstream_dom = AdapterAuthenticatedRefundFaceV2::from_dom(
        owners.upstream_dom,
        &upstream_binding,
        composition.upstream(),
        composition,
        dom_deployment,
    )
    .map_err(|_| ProductionF6ActivationRefusalV2::InvalidBinding)?;
    let downstream_dom = AdapterAuthenticatedRefundFaceV2::from_dom(
        owners.downstream_dom,
        &downstream_binding,
        composition.downstream(),
        composition,
        dom_deployment,
    )
    .map_err(|_| ProductionF6ActivationRefusalV2::InvalidBinding)?;
    let upstream_counterparty = counterparty_face(
        owners.upstream_counterparty,
        &upstream_binding,
        composition.upstream(),
        composition,
    )?;
    let downstream_counterparty = counterparty_face(
        owners.downstream_counterparty,
        &downstream_binding,
        composition.downstream(),
        composition,
    )?;
    Ok((
        ProductionAdapterF6TermsAuthorityV2::new(
            upstream_binding,
            composition,
            upstream_dom,
            upstream_counterparty,
        )
        .map_err(|_| ProductionF6ActivationRefusalV2::InvalidBinding)?,
        ProductionAdapterF6TermsAuthorityV2::new(
            downstream_binding,
            composition,
            downstream_dom,
            downstream_counterparty,
        )
        .map_err(|_| ProductionF6ActivationRefusalV2::InvalidBinding)?,
    ))
}

fn counterparty_face(
    owner: ProductionF6CounterpartyTermsOwnerV7,
    binding: &ProductionSolverF6BindingV2,
    settlement: &kaystra_core::terms::SettlementTermsV1,
    composition: &ComposedBindingV2,
) -> Result<AdapterAuthenticatedRefundFaceV2, ProductionF6ActivationRefusalV2> {
    match owner {
        ProductionF6CounterpartyTermsOwnerV7::Bitcoin { payout, deployment } => {
            AdapterAuthenticatedRefundFaceV2::from_btc(
                payout,
                binding,
                settlement,
                composition,
                deployment,
            )
        }
        ProductionF6CounterpartyTermsOwnerV7::Evm(deployment) => {
            AdapterAuthenticatedRefundFaceV2::from_evm(binding, settlement, deployment)
        }
    }
    .map_err(|_| ProductionF6ActivationRefusalV2::InvalidBinding)
}

fn open_signers(
    descriptors: &[ProductionF6BondSignerDescriptorV7],
    credentials: Vec<Zeroizing<[u8; 32]>>,
) -> Result<Vec<Box<dyn ProductionF6BondAttestationSignerV2>>, ProductionF6ActivationRefusalV2> {
    if descriptors.len() != credentials.len() {
        return Err(ProductionF6ActivationRefusalV2::InvalidBinding);
    }
    descriptors
        .iter()
        .cloned()
        .zip(credentials)
        .map(|(descriptor, credential)| {
            ProductionF6UnixBondSignerV7::open(descriptor, credential)
                .map(|signer| Box::new(signer) as Box<dyn ProductionF6BondAttestationSignerV2>)
        })
        .collect()
}

fn credentials_are_independent(credentials: &[Zeroizing<[u8; 32]>]) -> bool {
    credentials.iter().enumerate().all(|(index, credential)| {
        credential.as_slice().iter().any(|byte| *byte != 0)
            && credentials[..index]
                .iter()
                .all(|previous| previous.as_slice() != credential.as_slice())
    })
}

fn authenticated_socket_metadata(
    path: &Path,
    expected_uid: u32,
) -> Result<std::fs::Metadata, ProductionF6ActivationRefusalV2> {
    if !path.is_absolute() || !lexically_normal(path) {
        return Err(ProductionF6ActivationRefusalV2::InvalidBinding);
    }
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|_| ProductionF6ActivationRefusalV2::Unavailable)?;
    if !metadata.file_type().is_socket()
        || metadata.uid() != expected_uid
        || metadata.permissions().mode() & 0o777 != 0o600
    {
        return Err(ProductionF6ActivationRefusalV2::InvalidBinding);
    }
    Ok(metadata)
}

fn fresh_secp() -> Result<SecpContext, ProductionF6ActivationRefusalV2> {
    let mut seed = Zeroizing::new([0_u8; 32]);
    getrandom::getrandom(seed.as_mut())
        .map_err(|_| ProductionF6ActivationRefusalV2::Unavailable)?;
    if seed.as_slice().iter().all(|byte| *byte == 0) {
        return Err(ProductionF6ActivationRefusalV2::Unavailable);
    }
    Ok(SecpContext::new(&seed))
}

fn verify_bundle_signatures(
    reader: &mut BundleReaderV7<'_>,
    signed_prefix: &[u8],
    trusted_roots: &AuthoritySetV1,
    secp: &SecpContext,
) -> Result<(), ProductionF6ActivationRefusalV2> {
    let count = usize::from(reader.u16()?);
    if count < usize::from(trusted_roots.threshold()) || count > trusted_roots.xonly_keys().len() {
        return Err(ProductionF6ActivationRefusalV2::InvalidBinding);
    }
    let digest = digest_parts(&[BUNDLE_DOMAIN_V7, signed_prefix])?;
    let mut previous = None;
    for _ in 0..count {
        let index = reader.u16()?;
        if previous.is_some_and(|value| value >= index) {
            return Err(ProductionF6ActivationRefusalV2::InvalidBinding);
        }
        let key = trusted_roots
            .xonly_keys()
            .get(usize::from(index))
            .ok_or(ProductionF6ActivationRefusalV2::InvalidBinding)?;
        let signature = reader.take::<64>()?;
        secp.verify_bip340(key, &digest, &signature)
            .map_err(|_| ProductionF6ActivationRefusalV2::InvalidBinding)?;
        previous = Some(index);
    }
    Ok(())
}

fn decode_authorities(
    reader: &mut BundleReaderV7<'_>,
) -> Result<AuthoritySetV1, ProductionF6ActivationRefusalV2> {
    let bytes = reader.length_prefixed(MAX_AUTHORITY_BYTES_V7)?;
    AuthoritySetV1::decode_canonical(bytes)
        .map_err(|_| ProductionF6ActivationRefusalV2::InvalidBinding)
}

fn decode_keys(
    reader: &mut BundleReaderV7<'_>,
) -> Result<Vec<[u8; 32]>, ProductionF6ActivationRefusalV2> {
    let count = usize::from(reader.u16()?);
    if count == 0 || count > MAX_SIGNERS_V7 {
        return Err(ProductionF6ActivationRefusalV2::InvalidBinding);
    }
    let mut keys = Vec::with_capacity(count);
    for _ in 0..count {
        let key = reader.take::<32>()?;
        if key == ZERO_DIGEST || keys.last().is_some_and(|previous| *previous >= key) {
            return Err(ProductionF6ActivationRefusalV2::InvalidBinding);
        }
        keys.push(key);
    }
    Ok(keys)
}

fn decode_signers(
    reader: &mut BundleReaderV7<'_>,
) -> Result<Vec<ProductionF6BondSignerDescriptorV7>, ProductionF6ActivationRefusalV2> {
    let count = usize::from(reader.u16()?);
    if !(2..=MAX_SIGNERS_V7).contains(&count) {
        return Err(ProductionF6ActivationRefusalV2::InvalidBinding);
    }
    let mut signers = Vec::with_capacity(count);
    for _ in 0..count {
        let independent_authority_id = reader.take::<32>()?;
        let signer_index = reader.u16()?;
        let signer_public_key = reader.take::<32>()?;
        let endpoint_uid = reader.u32()?;
        let endpoint_bytes = reader.length_prefixed(MAX_ENDPOINT_BYTES_V7)?;
        let endpoint_text = std::str::from_utf8(endpoint_bytes)
            .map_err(|_| ProductionF6ActivationRefusalV2::InvalidBinding)?;
        if endpoint_text
            .bytes()
            .any(|byte| byte == 0 || byte.is_ascii_control())
        {
            return Err(ProductionF6ActivationRefusalV2::InvalidBinding);
        }
        let endpoint = PathBuf::from(endpoint_text);
        if !endpoint.is_absolute() || !lexically_normal(&endpoint) {
            return Err(ProductionF6ActivationRefusalV2::InvalidBinding);
        }
        signers.push(ProductionF6BondSignerDescriptorV7 {
            independent_authority_id,
            signer_index,
            signer_public_key,
            endpoint_uid,
            endpoint,
        });
    }
    Ok(signers)
}

fn validate_signer_descriptors(
    authorities: &AuthoritySetV1,
    signers: &[ProductionF6BondSignerDescriptorV7],
) -> Result<(), ProductionF6ActivationRefusalV2> {
    if signers.len() != authorities.xonly_keys().len() {
        return Err(ProductionF6ActivationRefusalV2::InvalidBinding);
    }
    let mut previous = None;
    let mut ids = BTreeSet::new();
    let mut endpoints = BTreeSet::new();
    for signer in signers {
        if signer.independent_authority_id == ZERO_DIGEST
            || previous.is_some_and(|value| value >= signer.signer_index)
            || authorities
                .xonly_keys()
                .get(usize::from(signer.signer_index))
                .copied()
                != Some(signer.signer_public_key)
            || !ids.insert(signer.independent_authority_id)
            || !endpoints.insert(signer.endpoint.clone())
        {
            return Err(ProductionF6ActivationRefusalV2::InvalidBinding);
        }
        previous = Some(signer.signer_index);
    }
    Ok(())
}

fn lexically_normal(path: &Path) -> bool {
    path.components().all(|component| {
        matches!(
            component,
            Component::RootDir | Component::Normal(_) | Component::Prefix(_)
        )
    })
}

fn digest_parts(parts: &[&[u8]]) -> Result<Digest32, ProductionF6ActivationRefusalV2> {
    let mut hasher =
        Blake2bVar::new(32).map_err(|_| ProductionF6ActivationRefusalV2::InvalidBinding)?;
    for part in parts {
        hasher.update(part);
    }
    let mut digest = [0_u8; 32];
    hasher
        .finalize_variable(&mut digest)
        .map_err(|_| ProductionF6ActivationRefusalV2::InvalidBinding)?;
    if digest == ZERO_DIGEST {
        return Err(ProductionF6ActivationRefusalV2::InvalidBinding);
    }
    Ok(digest)
}

struct BundleReaderV7<'a> {
    bytes: &'a [u8],
    cursor: usize,
}

impl<'a> BundleReaderV7<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, cursor: 0 }
    }

    const fn position(&self) -> usize {
        self.cursor
    }

    fn take<const N: usize>(&mut self) -> Result<[u8; N], ProductionF6ActivationRefusalV2> {
        let end = self
            .cursor
            .checked_add(N)
            .ok_or(ProductionF6ActivationRefusalV2::InvalidBinding)?;
        let bytes = self
            .bytes
            .get(self.cursor..end)
            .ok_or(ProductionF6ActivationRefusalV2::InvalidBinding)?;
        self.cursor = end;
        bytes
            .try_into()
            .map_err(|_| ProductionF6ActivationRefusalV2::InvalidBinding)
    }

    fn bytes_exact(&mut self, length: usize) -> Result<&'a [u8], ProductionF6ActivationRefusalV2> {
        let end = self
            .cursor
            .checked_add(length)
            .ok_or(ProductionF6ActivationRefusalV2::InvalidBinding)?;
        let bytes = self
            .bytes
            .get(self.cursor..end)
            .ok_or(ProductionF6ActivationRefusalV2::InvalidBinding)?;
        self.cursor = end;
        Ok(bytes)
    }

    fn length_prefixed(
        &mut self,
        maximum: usize,
    ) -> Result<&'a [u8], ProductionF6ActivationRefusalV2> {
        let length = usize::from(self.u16()?);
        if length == 0 || length > maximum {
            return Err(ProductionF6ActivationRefusalV2::InvalidBinding);
        }
        self.bytes_exact(length)
    }

    fn u16(&mut self) -> Result<u16, ProductionF6ActivationRefusalV2> {
        Ok(u16::from_be_bytes(self.take()?))
    }

    fn u64(&mut self) -> Result<u64, ProductionF6ActivationRefusalV2> {
        Ok(u64::from_be_bytes(self.take()?))
    }

    fn u32(&mut self) -> Result<u32, ProductionF6ActivationRefusalV2> {
        Ok(u32::from_be_bytes(self.take()?))
    }

    fn u128(&mut self) -> Result<u128, ProductionF6ActivationRefusalV2> {
        Ok(u128::from_be_bytes(self.take()?))
    }

    fn finish(self) -> Result<(), ProductionF6ActivationRefusalV2> {
        if self.cursor == self.bytes.len() {
            Ok(())
        } else {
            Err(ProductionF6ActivationRefusalV2::InvalidBinding)
        }
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use f6_engine::candidate_book::BondReservationAttestationRequestV2;
    use static_assertions::assert_not_impl_any;

    use super::*;

    assert_not_impl_any!(AuthenticatedProductionF6AuthorityBundleV7: Clone, Copy);
    assert_not_impl_any!(AuthenticatedProductionF6FinalClaimPlanV7: Clone, Copy);
    assert_not_impl_any!(AuthenticatedProductionF6PairBindingV7: Clone, Copy);
    assert_not_impl_any!(ProductionF6BondSignerCredentialsV7: Clone, Copy);
    assert_not_impl_any!(ProductionF6UnixBondSignerV7: Clone, Copy);

    fn digest(byte: u8) -> Digest32 {
        [byte; 32]
    }

    fn test_attestation() -> BondReservationAttestationV2 {
        BondReservationAttestationV2::new(BondReservationAttestationRequestV2 {
            network_id: digest(1),
            composition_id: digest(2),
            position: SettlementPositionV2::Upstream,
            rfq_id: digest(3),
            quote_id: digest(4),
            solver: ParticipantId(digest(5)),
            reservation_id: digest(6),
            bond_policy_hash: digest(7),
            registry_digest: digest(8),
            registry_epoch: 1,
            bond_asset_binding_digest: digest(9),
            required_collateral: 10,
            reserved_collateral: 10,
            reservation_state_digest: digest(11),
            source_evidence_digest: digest(12),
            solver_status_statement_digest: digest(13),
            solver_status_epoch: 1,
            solver_status_valid_until_seconds: 300,
            observed_at_seconds: 100,
            valid_until_seconds: 200,
            sequence: 1,
            previous_attestation_digest: ZERO_DIGEST,
        })
        .expect("valid attestation")
    }

    fn hsm_request_bytes(
        credential: &[u8; 32],
        signer_index: u16,
        signer_public_key: [u8; 32],
        intent_digest: Digest32,
        attestation: BondReservationAttestationV2,
    ) -> Vec<u8> {
        let statement = attestation
            .canonical_bytes()
            .expect("canonical attestation");
        let attestation_digest = attestation
            .attestation_digest()
            .expect("attestation digest");
        let mut bytes = Vec::new();
        bytes.extend_from_slice(HSM_REQUEST_MAGIC_V7);
        bytes.extend_from_slice(&HSM_VERSION_V7.to_be_bytes());
        bytes.extend_from_slice(&signer_index.to_be_bytes());
        bytes.extend_from_slice(&signer_public_key);
        bytes.extend_from_slice(&intent_digest);
        bytes.extend_from_slice(&attestation_digest);
        bytes.extend_from_slice(
            &u32::try_from(statement.len())
                .expect("bounded statement")
                .to_be_bytes(),
        );
        bytes.extend_from_slice(&statement);
        let mut mac = <Blake2bMac256 as KeyInit>::new_from_slice(credential).expect("MAC key");
        Mac::update(&mut mac, HSM_REQUEST_MAC_DOMAIN_V7);
        Mac::update(&mut mac, &bytes);
        bytes.extend_from_slice(&mac.finalize().into_bytes());
        bytes
    }

    #[test]
    fn external_paths_require_six_distinct_children_of_state_root() {
        let paths = [
            "/state/up-status",
            "/state/down-status",
            "/state/up-time",
            "/state/down-time",
            "/state/up-candidate",
            "/state/down-candidate",
        ]
        .map(PathBuf::from);
        assert!(ProductionF6ExternalPathsV7::new(Path::new("/state"), paths.clone()).is_ok());

        let mut duplicate = paths.clone();
        duplicate[1] = duplicate[0].clone();
        assert!(ProductionF6ExternalPathsV7::new(Path::new("/state"), duplicate).is_err());

        let mut escaped = paths;
        escaped[5] = PathBuf::from("/other/down-candidate");
        assert!(ProductionF6ExternalPathsV7::new(Path::new("/state"), escaped).is_err());
    }

    #[test]
    fn prepared_bindings_are_position_and_role_distinct() {
        let prepared =
            ProductionF6ExternalPreparedBindingsV7::derive_stage11(digest(1), digest(2), digest(3))
                .expect("prepared bindings");
        let unique: BTreeSet<_> = prepared.all().into_iter().collect();
        assert_eq!(unique.len(), 6);
    }

    #[test]
    fn delayed_rfq_replaces_stale_pre_rfq_lease_with_fresh_deadline() {
        let directory = tempfile::tempdir().expect("temporary inventory directory");
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))
            .expect("private inventory directory");
        let binding = digest(0x31);
        let solver = ParticipantId(digest(0x32));
        let owner = digest(0x33);
        let mut inventory =
            DurableInventoryStoreV1::create(&directory.path().join("inventory.sqlite3"), binding)
                .expect("inventory store");
        let stale = inventory
            .acquire_lease(solver, owner, 1_000, 100)
            .expect("early lease")
            .lease();

        let bound = acquire_or_renew_inventory_lease_at(
            &mut inventory,
            binding,
            solver,
            owner,
            5_000,
            10_000,
        )
        .expect("RFQ-time lease");
        assert_eq!(bound.authority_id, solver);
        assert_eq!(bound.owner_id, owner);
        assert_eq!(bound.fencing_epoch, stale.fencing_epoch + 1);
        assert_eq!(
            exact_inventory_fencing_epoch(bound).expect("authenticated terminal epoch"),
            stale.fencing_epoch + 1
        );
        assert_eq!(bound.lease_until_unix_ms, 15_000);
    }

    #[test]
    fn lease_bind_refuses_wrong_store_owner_solver_and_bound_before_mutation() {
        let directory = tempfile::tempdir().expect("temporary inventory directory");
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))
            .expect("private inventory directory");
        let binding = digest(0x34);
        let solver = ParticipantId(digest(0x35));
        let owner = digest(0x36);
        let mut inventory =
            DurableInventoryStoreV1::create(&directory.path().join("inventory.sqlite3"), binding)
                .expect("inventory store");

        assert!(matches!(
            acquire_or_renew_inventory_lease_at(
                &mut inventory,
                digest(0x37),
                solver,
                owner,
                1_000,
                1_000,
            ),
            Err(ProductionF6ActivationRefusalV2::InvalidBinding)
        ));
        assert!(matches!(
            acquire_or_renew_inventory_lease_at(
                &mut inventory,
                binding,
                ParticipantId(ZERO_DIGEST),
                owner,
                1_000,
                1_000,
            ),
            Err(ProductionF6ActivationRefusalV2::InvalidBinding)
        ));
        assert!(matches!(
            acquire_or_renew_inventory_lease_at(
                &mut inventory,
                binding,
                solver,
                ZERO_DIGEST,
                1_000,
                1_000,
            ),
            Err(ProductionF6ActivationRefusalV2::InvalidBinding)
        ));
        assert!(matches!(
            acquire_or_renew_inventory_lease_at(
                &mut inventory,
                binding,
                solver,
                owner,
                1_000,
                MAX_F6_INVENTORY_LEASE_DURATION_MS_V7 + 1,
            ),
            Err(ProductionF6ActivationRefusalV2::InvalidBinding)
        ));

        let lease = inventory
            .acquire_lease(solver, owner, 1_000, 1_000)
            .expect("preflight refusals did not mutate")
            .lease();
        assert_eq!(lease.fencing_epoch, 1);
    }

    #[test]
    fn live_rfq_lease_is_exactly_renewed_without_refencing() {
        let directory = tempfile::tempdir().expect("temporary inventory directory");
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))
            .expect("private inventory directory");
        let binding = digest(0x38);
        let solver = ParticipantId(digest(0x39));
        let owner = digest(0x3a);
        let mut inventory =
            DurableInventoryStoreV1::create(&directory.path().join("inventory.sqlite3"), binding)
                .expect("inventory store");
        let early = inventory
            .acquire_lease(solver, owner, 1_000, 10_000)
            .expect("early live lease")
            .lease();
        let renewed = acquire_or_renew_inventory_lease_at(
            &mut inventory,
            binding,
            solver,
            owner,
            5_000,
            10_000,
        )
        .expect("renewed lease");
        assert_eq!(renewed.fencing_epoch, early.fencing_epoch);
        assert_eq!(
            exact_inventory_fencing_epoch(renewed).expect("authenticated terminal epoch"),
            early.fencing_epoch
        );
        assert_eq!(renewed.lease_until_unix_ms, 15_000);

        assert!(matches!(
            acquire_or_renew_inventory_lease_at(
                &mut inventory,
                binding,
                solver,
                digest(0x3b),
                6_000,
                10_000,
            ),
            Err(ProductionF6ActivationRefusalV2::Unavailable)
        ));
        let still_exact = inventory
            .renew_lease(renewed, 6_000, 10_000)
            .expect("wrong owner did not replace lease");
        assert_eq!(still_exact.fencing_epoch, early.fencing_epoch);
    }

    #[test]
    fn terminal_epoch_refuses_unowned_or_caller_shaped_lease_material() {
        let exact = InventoryLeaseV1 {
            authority_id: ParticipantId(digest(0x71)),
            owner_id: digest(0x72),
            fencing_epoch: 9,
            lease_until_unix_ms: 10_000,
        };
        assert_eq!(
            exact_inventory_fencing_epoch(exact).expect("exact inventory epoch"),
            9
        );
        assert!(exact_inventory_fencing_epoch(InventoryLeaseV1 {
            fencing_epoch: 0,
            ..exact
        })
        .is_err());
        assert!(exact_inventory_fencing_epoch(InventoryLeaseV1 {
            authority_id: ParticipantId(ZERO_DIGEST),
            ..exact
        })
        .is_err());
        assert!(exact_inventory_fencing_epoch(InventoryLeaseV1 {
            owner_id: ZERO_DIGEST,
            ..exact
        })
        .is_err());
        assert!(exact_inventory_fencing_epoch(InventoryLeaseV1 {
            lease_until_unix_ms: 0,
            ..exact
        })
        .is_err());
    }

    #[test]
    fn signer_credentials_refuse_zero_and_same_authority_reuse() {
        let independent = vec![Zeroizing::new(digest(1)), Zeroizing::new(digest(2))];
        assert!(credentials_are_independent(&independent));
        assert!(!credentials_are_independent(&[
            Zeroizing::new(digest(1)),
            Zeroizing::new(digest(1)),
        ]));
        assert!(!credentials_are_independent(&[
            Zeroizing::new(digest(1)),
            Zeroizing::new(ZERO_DIGEST),
        ]));
    }

    #[test]
    fn hsm_codec_authenticates_client_and_canonical_statement() {
        let credential = digest(0x41);
        let signer_key = digest(0x42);
        let intent = digest(0x43);
        let attestation = test_attestation();
        let bytes = hsm_request_bytes(&credential, 1, signer_key, intent, attestation);
        let decoded = ProductionF6HsmSigningRequestV7::decode_and_authenticate(
            &bytes,
            &credential,
            1,
            signer_key,
        )
        .expect("authenticated request");
        assert_eq!(decoded.signer_index(), 1);
        assert_eq!(decoded.signer_public_key(), signer_key);
        assert_eq!(decoded.intent_digest(), intent);
        assert_eq!(decoded.attestation(), attestation);
        let response = ProductionF6HsmSigningResponseV7::new(&decoded, [0x45; 64]);
        let response = ProductionF6HsmSigningResponseV7::decode(&response.canonical_bytes())
            .expect("canonical response");
        assert_eq!(response.signer_index, 1);
        assert_eq!(response.intent_digest, intent);
        assert_eq!(response.attestation_digest, decoded.attestation_digest());
        assert_eq!(response.signature, [0x45; 64]);

        assert!(ProductionF6HsmSigningRequestV7::decode_and_authenticate(
            &bytes,
            &digest(0x44),
            1,
            signer_key,
        )
        .is_err());
        assert!(ProductionF6HsmSigningRequestV7::decode_and_authenticate(
            &bytes,
            &credential,
            2,
            signer_key,
        )
        .is_err());

        let mut tampered = bytes;
        tampered[112] ^= 1;
        assert!(ProductionF6HsmSigningRequestV7::decode_and_authenticate(
            &tampered,
            &credential,
            1,
            signer_key,
        )
        .is_err());
    }

    #[test]
    fn registry_signature_cannot_be_transplanted_to_another_root_set() {
        let secp = SecpContext::new(&digest(0x51));
        let signed_prefix = b"threshold-authenticated-f6-v7";
        let message = digest_parts(&[BUNDLE_DOMAIN_V7, signed_prefix]).expect("message digest");
        let (signature, signer_key) = secp
            .sign_bip340(&digest(0x52), &message, &digest(0x53))
            .expect("signature");
        let (_, foreign_key) = secp
            .sign_bip340(&digest(0x54), &message, &digest(0x55))
            .expect("foreign key");
        let roots = AuthoritySetV1::new(1, vec![signer_key]).expect("root set");
        let foreign = AuthoritySetV1::new(1, vec![foreign_key]).expect("foreign root set");
        let mut signatures = Vec::new();
        signatures.extend_from_slice(&1_u16.to_be_bytes());
        signatures.extend_from_slice(&0_u16.to_be_bytes());
        signatures.extend_from_slice(&signature);

        assert!(verify_bundle_signatures(
            &mut BundleReaderV7::new(&signatures),
            signed_prefix,
            &roots,
            &secp,
        )
        .is_ok());
        assert!(verify_bundle_signatures(
            &mut BundleReaderV7::new(&signatures),
            signed_prefix,
            &foreign,
            &secp,
        )
        .is_err());
    }
}
