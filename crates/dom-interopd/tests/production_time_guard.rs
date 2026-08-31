//! Production funding-time guard against the real V2 admission and durable
//! time authority.

#[path = "../../route-time-anchor/tests/common/mod.rs"]
mod time_common;

mod admission {
    pub use dom_interopd::{AuthenticatedRouteAdmissionV1, AuthenticatedRouteTimeBindingV2};
}

#[cfg(feature = "production")]
mod supervisor {
    pub(crate) use dom_interopd::AuthorityRefusalV1;
}

#[cfg(feature = "production")]
mod production_settlement {
    use route_executor::EventIdV1;
    use settlement_coordinator::{
        CompositeSettlementPlanV1, CoordinatorLeaseV1, Digest32, DurableSettlementCoordinatorV1,
        SettlementPlanViewV1, StoredSettlementPlanV1,
    };

    use crate::supervisor::AuthorityRefusalV1;

    pub(crate) trait ProductionSettlementPlanPersistenceV1 {
        fn install_new_plan(
            &mut self,
            coordinator: &mut DurableSettlementCoordinatorV1,
            plan: CompositeSettlementPlanV1,
            route_event_id: EventIdV1,
            trusted_now_unix_ms: u64,
        ) -> Result<SettlementPlanViewV1, AuthorityRefusalV1>;

        fn revalidate_preinstalled_new_plan(
            &mut self,
            stored: &StoredSettlementPlanV1,
            route_event_id: EventIdV1,
            trusted_now_unix_ms: u64,
        ) -> Result<(), AuthorityRefusalV1>;

        fn refence_preinstalled_new_plan(
            &mut self,
            coordinator: &mut DurableSettlementCoordinatorV1,
            lease: CoordinatorLeaseV1,
            replacement: CompositeSettlementPlanV1,
            progress_evidence_digest: Digest32,
            route_event_id: EventIdV1,
            trusted_now_unix_ms: u64,
        ) -> Result<SettlementPlanViewV1, AuthorityRefusalV1>;

        fn refence_existing_plan(
            &mut self,
            coordinator: &mut DurableSettlementCoordinatorV1,
            lease: CoordinatorLeaseV1,
            replacement: CompositeSettlementPlanV1,
            progress_evidence_digest: Digest32,
            trusted_now_unix_ms: u64,
        ) -> Result<SettlementPlanViewV1, AuthorityRefusalV1>;
    }
}

#[path = "../src/production_time_guard.rs"]
mod production_time_guard;

use std::{fs, path::PathBuf};

#[cfg(feature = "production")]
use std::path::Path;

use btc_crypto::SecpContext;
use deployment_registry::{
    AuthoritySetV1, RegistrySignatureV1, RegistryStoreV1, RegistryValidationPolicyV1,
    ResolvedRegistryV1, SignedRegistryV1,
};
use dom_interopd::{
    AuthenticatedRouteAdmissionV1, RegistryRouteAdmissionAuthorityV1, RouteRosterSnapshotsV1,
};
use kaystra_core::terms::SettlementTermsV1;
use route_composer::ComposedBindingV2;
use route_executor::{ActionKindV1, ActionProgressV1, CanonicalCodecV1, LegIdV1};
use route_time_anchor::{
    DurableRouteTimeAnchorStoreV2, RouteTimeAnchorErrorV2, RouteTimeAnchorStoreConfigV2,
    RouteTimeEvidenceV2, RouteTimeEvidenceVerificationContextV2, RouteTimePolicyLimitsV2,
    RouteTimePolicyV2, RouteTimePolicyVerificationContextV2, SignedRouteTimeEvidenceV2,
    SignedRouteTimePolicyV2,
};
use tempfile::TempDir;

use production_time_guard::{
    economic_boundary_time_requirement_v2, EconomicBoundaryTimeRequirementV2,
    FundingTimeAuthorizationScopeV2, FundingTimeAuthorizationV2, ProductionRouteTimeGuardContextV2,
    ProductionRouteTimeGuardV2, ProductionTimeGuardErrorV2,
};

#[cfg(feature = "production")]
use std::{cell::RefCell, os::unix::fs::PermissionsExt, rc::Rc};

#[cfg(feature = "production")]
use dom_interopd::AuthorityRefusalV1;
#[cfg(feature = "production")]
use production_settlement::ProductionSettlementPlanPersistenceV1;
#[cfg(feature = "production")]
use production_time_guard::{combine_plan_authorization, ProductionTimeGuardedPlanPersistenceV2};
#[cfg(feature = "production")]
use route_executor::derive_effect_id_v1;
#[cfg(feature = "production")]
use settlement_coordinator::{
    CanonicalSettlementPlanV1, ChildExposureV1, CompositeSettlementPlanV1, CoordinatorErrorV1,
    CustodyTakeoverStatusV1, DurableSettlementCoordinatorV1, PlanAuthorityRefusalV1,
    PlanAuthorizationRequestV1, PlanAuthorizationV1, SecretRequirementV1, SettlementActionV1,
    SettlementChildPlanV1, SettlementChildrenV1, SettlementFaceV1, SettlementLegV1,
    SettlementPlanAuthorityV1, SettlementPlanBindingsV1,
};
use time_common::{
    checkpoints, evidence, fixture, sign_digest, signed_evidence, signed_policy, Fixture,
    EVIDENCE_SECRETS, EVIDENCE_TIME, POLICY_SECRETS,
};

const ROUTE_ID: [u8; 32] = [0xa7; 32];
const REGISTRY_SECRETS: [[u8; 32]; 3] = [[0x03; 32], [0x04; 32], [0x05; 32]];

#[cfg(feature = "production")]
const COORDINATOR_ID: [u8; 32] = [0xc1; 32];
#[cfg(feature = "production")]
const PLAN_AUTHORITY_ID: [u8; 32] = [0xc2; 32];
#[cfg(feature = "production")]
const COORDINATOR_OWNER: [u8; 32] = [0xc3; 32];

#[derive(Clone)]
struct GuardContext {
    registry: ResolvedRegistryV1,
    upstream: SettlementTermsV1,
    downstream: SettlementTermsV1,
    policy_authorities: AuthoritySetV1,
    evidence_authorities: AuthoritySetV1,
}

struct AdmittedHarness {
    _directory: TempDir,
    time_path: PathBuf,
    time_config: RouteTimeAnchorStoreConfigV2,
    time_store: DurableRouteTimeAnchorStoreV2,
    admission: AuthenticatedRouteAdmissionV1,
    context: GuardContext,
    policy: RouteTimePolicyV2,
}

fn registry_authority(fixture: &Fixture) -> (AuthoritySetV1, SignedRegistryV1) {
    let digest = fixture.registry.manifest().manifest_digest().unwrap();
    let keys = REGISTRY_SECRETS
        .iter()
        .enumerate()
        .map(|(index, secret)| {
            fixture
                .secp
                .sign_bip340(secret, &[0x41; 32], &[0x42 + index as u8; 32])
                .unwrap()
                .1
        })
        .collect();
    let signatures = REGISTRY_SECRETS
        .iter()
        .enumerate()
        .map(|(index, secret)| {
            let (signature, _) = fixture
                .secp
                .sign_bip340(secret, &digest, &[0x50 + index as u8; 32])
                .unwrap();
            RegistrySignatureV1 {
                signer_index: index as u16,
                signature,
            }
        })
        .collect();
    (
        AuthoritySetV1::new(2, keys).unwrap(),
        SignedRegistryV1::new(fixture.registry.manifest(), signatures).unwrap(),
    )
}

fn owner_only_directory() -> TempDir {
    let directory = tempfile::tempdir().unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
    }
    directory
}

fn admitted_harness() -> AdmittedHarness {
    admitted_harness_with_evidence_expiry(EVIDENCE_TIME + 300)
}

fn admitted_harness_with_evidence_expiry(evidence_expiry: u64) -> AdmittedHarness {
    let fixture = fixture();
    let directory = owner_only_directory();
    let (registry_authorities, signed_registry) = registry_authority(&fixture);
    let registry_path = directory.path().join("registry.sqlite3");
    let mut registry_store = RegistryStoreV1::create(&registry_path).unwrap();
    registry_store
        .install(
            &signed_registry,
            &registry_authorities,
            &fixture.secp,
            RegistryValidationPolicyV1 {
                now_seconds: EVIDENCE_TIME,
                expected_network_id: time_common::REGISTRY_NETWORK,
                minimum_epoch: 7,
            },
        )
        .unwrap();
    let admission_authority = RegistryRouteAdmissionAuthorityV1::new(
        registry_store,
        registry_authorities,
        SecpContext::new(&[0x7a; 32]),
        time_common::REGISTRY_NETWORK,
        7,
    )
    .unwrap();

    let time_config = RouteTimeAnchorStoreConfigV2::new(
        &fixture.registry,
        &fixture.upstream,
        &fixture.downstream,
        &fixture.policy_authorities,
        &fixture.evidence_authorities,
        &fixture.secp,
    )
    .unwrap();
    let time_path = directory.path().join("route-time.sqlite3");
    let mut time_store = DurableRouteTimeAnchorStoreV2::create(&time_path, time_config).unwrap();
    time_store
        .install_policy(
            &signed_policy(&fixture),
            fixture.policy_context(),
            EVIDENCE_TIME,
        )
        .unwrap();
    let initial_evidence = RouteTimeEvidenceV2::new(
        &fixture.policy,
        1,
        EVIDENCE_TIME,
        evidence_expiry,
        checkpoints(&fixture.policy, 0, 0),
    )
    .unwrap();
    time_store
        .install_evidence(
            &signed_evidence(&fixture, &initial_evidence),
            fixture.evidence_context(),
            EVIDENCE_TIME,
        )
        .unwrap();
    let proof = time_store
        .prove_route_ladder(fixture.evidence_context(), EVIDENCE_TIME)
        .unwrap();
    let current = time_store
        .consume_capability_at(proof, EVIDENCE_TIME)
        .unwrap();
    let composition = ComposedBindingV2::bind(
        fixture.upstream.clone(),
        fixture.downstream.clone(),
        current,
    )
    .unwrap();
    let admission = admission_authority
        .admit_validated_composed_route_v2(
            EVIDENCE_TIME,
            ROUTE_ID,
            &composition,
            RouteRosterSnapshotsV1 {
                upstream: [0xa8; 32],
                downstream: [0xa9; 32],
            },
        )
        .unwrap();
    let context = GuardContext {
        registry: fixture.registry.clone(),
        upstream: fixture.upstream.clone(),
        downstream: fixture.downstream.clone(),
        policy_authorities: fixture.policy_authorities.clone(),
        evidence_authorities: fixture.evidence_authorities.clone(),
    };
    AdmittedHarness {
        _directory: directory,
        time_path,
        time_config,
        time_store,
        admission,
        context,
        policy: fixture.policy,
    }
}

fn guard_from(
    store: DurableRouteTimeAnchorStoreV2,
    admission: &AuthenticatedRouteAdmissionV1,
    context: &GuardContext,
) -> ProductionRouteTimeGuardV2 {
    ProductionRouteTimeGuardV2::new(
        store,
        admission,
        ProductionRouteTimeGuardContextV2 {
            policy_authorities: context.policy_authorities.clone(),
            evidence_authorities: context.evidence_authorities.clone(),
            secp: SecpContext::new(&[0x7b; 32]),
            registry: context.registry.clone(),
            upstream: context.upstream.clone(),
            downstream: context.downstream.clone(),
        },
    )
    .unwrap()
}

fn scope(
    route_id: [u8; 32],
    leg: LegIdV1,
    fence: u64,
    effect: u8,
    event: u8,
) -> FundingTimeAuthorizationScopeV2 {
    FundingTimeAuthorizationScopeV2::new(
        route_id,
        leg,
        ActionKindV1::Funding,
        fence,
        [effect; 32],
        [event; 32],
        [0xd1; 32],
    )
    .unwrap()
}

fn sign_new_evidence(evidence: &RouteTimeEvidenceV2) -> SignedRouteTimeEvidenceV2 {
    let secp = SecpContext::new(&[0x7c; 32]);
    let digest = evidence.evidence_digest().unwrap();
    SignedRouteTimeEvidenceV2::new(
        evidence,
        sign_digest(&secp, &EVIDENCE_SECRETS, &digest, 0x70),
    )
    .unwrap()
}

fn sign_new_policy(policy: &RouteTimePolicyV2) -> SignedRouteTimePolicyV2 {
    let secp = SecpContext::new(&[0x7f; 32]);
    let digest = policy.policy_digest().unwrap();
    SignedRouteTimePolicyV2::new(policy, sign_digest(&secp, &POLICY_SECRETS, &digest, 0x60))
        .unwrap()
}

#[cfg(feature = "production")]
#[derive(Default)]
struct BasePlanAuthorityState {
    calls: usize,
}

#[cfg(feature = "production")]
struct TestBasePlanAuthority {
    state: Rc<RefCell<BasePlanAuthorityState>>,
}

#[cfg(feature = "production")]
impl SettlementPlanAuthorityV1 for TestBasePlanAuthority {
    fn authorize_plan(
        &mut self,
        request: PlanAuthorizationRequestV1<'_>,
    ) -> Result<PlanAuthorizationV1, PlanAuthorityRefusalV1> {
        self.state.borrow_mut().calls += 1;
        PlanAuthorizationV1::new(
            PLAN_AUTHORITY_ID,
            request.plan_digest(),
            [0xe1; 32],
            u64::MAX,
        )
        .map_err(|_| PlanAuthorityRefusalV1::Conflict)
    }
}

#[cfg(feature = "production")]
fn coordinator_state_path() -> (TempDir, PathBuf) {
    let directory = tempfile::tempdir().unwrap();
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let canonical = fs::canonicalize(directory.path()).unwrap();
    let path = canonical.join("coordinator.sqlite3");
    (directory, path)
}

#[cfg(feature = "production")]
fn create_coordinator(path: &Path) -> DurableSettlementCoordinatorV1 {
    DurableSettlementCoordinatorV1::create(
        path,
        COORDINATOR_ID,
        PLAN_AUTHORITY_ID,
        EVIDENCE_TIME * 1_000,
    )
    .unwrap()
}

#[cfg(feature = "production")]
fn plan_for_event(
    action: SettlementActionV1,
    leg: LegIdV1,
    fence: u64,
    event_id: [u8; 32],
    variant: u8,
) -> CompositeSettlementPlanV1 {
    let settlement_leg = match leg {
        LegIdV1::Upstream => SettlementLegV1::Upstream,
        LegIdV1::Downstream => SettlementLegV1::Downstream,
    };
    let route_action = match action {
        SettlementActionV1::Funding => ActionKindV1::Funding,
        SettlementActionV1::Claim => ActionKindV1::Claim,
        SettlementActionV1::Refund => ActionKindV1::Refund,
    };
    let semantic_digest = [variant; 32];
    let effect_id = derive_effect_id_v1(
        ROUTE_ID,
        event_id,
        fence,
        leg,
        route_action,
        semantic_digest,
    );
    let (secret_requirement, exposures) = match action {
        SettlementActionV1::Funding | SettlementActionV1::Refund => (
            SecretRequirementV1::None,
            [ChildExposureV1::NonSecret, ChildExposureV1::NonSecret],
        ),
        SettlementActionV1::Claim => (
            SecretRequirementV1::FirstExposureRequired,
            [
                ChildExposureV1::FirstSecretExposure,
                ChildExposureV1::UsesPublicSecret,
            ],
        ),
    };
    CompositeSettlementPlanV1::new(
        SettlementPlanBindingsV1 {
            route_id: ROUTE_ID,
            effect_id,
            settlement_id: [variant.wrapping_add(1); 32],
            leg: settlement_leg,
            action,
            fencing_epoch: fence,
            semantic_digest,
            terms_digest: [0xd1; 32],
            registry_digest: [0xd2; 32],
            dom_profile_digest: [0xd3; 32],
            dom_deployment_digest: [0xd4; 32],
            counterparty_profile_digest: [0xd5; 32],
            counterparty_deployment_digest: [0xd6; 32],
        },
        secret_requirement,
        None,
        [
            SettlementChildPlanV1 {
                face: SettlementFaceV1::Evm,
                exposure: exposures[0],
                chain_id: [variant.wrapping_add(10); 32],
                expected_transaction_id: [variant.wrapping_add(11); 32],
                intent_digest: [variant.wrapping_add(12); 32],
                custody_digest: [variant.wrapping_add(13); 32],
            },
            SettlementChildPlanV1 {
                face: SettlementFaceV1::Dom,
                exposure: exposures[1],
                chain_id: [variant.wrapping_add(14); 32],
                expected_transaction_id: [variant.wrapping_add(15); 32],
                intent_digest: [variant.wrapping_add(16); 32],
                custody_digest: [variant.wrapping_add(17); 32],
            },
        ],
    )
    .unwrap()
}

#[cfg(feature = "production")]
fn refenced_plan(
    original: &CompositeSettlementPlanV1,
    event_id: [u8; 32],
    new_fence: u64,
) -> CompositeSettlementPlanV1 {
    let mut bindings = original.bindings().clone();
    let leg = match bindings.leg {
        SettlementLegV1::Upstream => LegIdV1::Upstream,
        SettlementLegV1::Downstream => LegIdV1::Downstream,
    };
    let action = match bindings.action {
        SettlementActionV1::Funding => ActionKindV1::Funding,
        SettlementActionV1::Claim => ActionKindV1::Claim,
        SettlementActionV1::Refund => ActionKindV1::Refund,
    };
    bindings.fencing_epoch = new_fence;
    bindings.effect_id = derive_effect_id_v1(
        bindings.route_id,
        event_id,
        new_fence,
        leg,
        action,
        bindings.semantic_digest,
    );
    match original.child_layout().clone() {
        SettlementChildrenV1::Materialized(children) => CompositeSettlementPlanV1::new(
            bindings,
            original.secret_requirement(),
            original.preexisting_secret_evidence_digest(),
            children,
        ),
        SettlementChildrenV1::FirstExposureStaged { first, deferred } => {
            CompositeSettlementPlanV1::new_first_exposure_staged(bindings, first, deferred)
        }
    }
    .unwrap()
}

#[cfg(feature = "production")]
fn adapter_from(
    store: DurableRouteTimeAnchorStoreV2,
    admission: &AuthenticatedRouteAdmissionV1,
    context: &GuardContext,
    state: Rc<RefCell<BasePlanAuthorityState>>,
) -> ProductionTimeGuardedPlanPersistenceV2<TestBasePlanAuthority> {
    let guard = guard_from(store, admission, context);
    ProductionTimeGuardedPlanPersistenceV2::new(guard, TestBasePlanAuthority { state })
}

#[test]
fn token_is_move_only_non_debug_nonserializable_and_thread_bound() {
    trait AmbiguousIfClone<A> {
        fn marker() {}
    }
    impl<T: ?Sized> AmbiguousIfClone<()> for T {}
    impl<T: Clone> AmbiguousIfClone<u8> for T {}

    trait AmbiguousIfCopy<A> {
        fn marker() {}
    }
    impl<T: ?Sized> AmbiguousIfCopy<()> for T {}
    impl<T: Copy> AmbiguousIfCopy<u8> for T {}

    trait AmbiguousIfDebug<A> {
        fn marker() {}
    }
    impl<T: ?Sized> AmbiguousIfDebug<()> for T {}
    impl<T: ?Sized + core::fmt::Debug> AmbiguousIfDebug<u8> for T {}

    trait AmbiguousIfSerialize<A> {
        fn marker() {}
    }
    impl<T: ?Sized> AmbiguousIfSerialize<()> for T {}
    impl<T: ?Sized + serde::Serialize> AmbiguousIfSerialize<u8> for T {}

    trait AmbiguousIfCodec<A> {
        fn marker() {}
    }
    impl<T: ?Sized> AmbiguousIfCodec<()> for T {}
    impl<T: CanonicalCodecV1> AmbiguousIfCodec<u8> for T {}

    trait AmbiguousIfSend<A> {
        fn marker() {}
    }
    impl<T: ?Sized> AmbiguousIfSend<()> for T {}
    impl<T: ?Sized + Send> AmbiguousIfSend<u8> for T {}

    trait AmbiguousIfSync<A> {
        fn marker() {}
    }
    impl<T: ?Sized> AmbiguousIfSync<()> for T {}
    impl<T: ?Sized + Sync> AmbiguousIfSync<u8> for T {}

    let _ = <FundingTimeAuthorizationV2<'static> as AmbiguousIfClone<_>>::marker;
    let _ = <FundingTimeAuthorizationV2<'static> as AmbiguousIfCopy<_>>::marker;
    let _ = <FundingTimeAuthorizationV2<'static> as AmbiguousIfDebug<_>>::marker;
    let _ = <FundingTimeAuthorizationV2<'static> as AmbiguousIfSerialize<_>>::marker;
    let _ = <FundingTimeAuthorizationV2<'static> as AmbiguousIfCodec<_>>::marker;
    let _ = <FundingTimeAuthorizationV2<'static> as AmbiguousIfSend<_>>::marker;
    let _ = <FundingTimeAuthorizationV2<'static> as AmbiguousIfSync<_>>::marker;
}

#[test]
fn current_token_is_consumed_synchronously_and_new_evidence_survives_restart() {
    let harness = admitted_harness();
    let original_binding = harness.admission.route_time_binding_v2().unwrap();
    let context = harness.context.clone();
    let time_path = harness.time_path.clone();
    let time_config = harness.time_config;
    let policy = harness.policy.clone();
    let mut guard = guard_from(harness.time_store, &harness.admission, &context);

    let first_scope = scope(ROUTE_ID, LegIdV1::Upstream, 1, 0x31, 0x41);
    let refused: Result<(), u8> = guard
        .authorize_new_funding_with(EVIDENCE_TIME, first_scope, |_authorization| Err(7))
        .unwrap();
    assert_eq!(refused, Err(7));
    let first_digest = guard
        .authorize_new_funding_with(EVIDENCE_TIME, first_scope, |authorization| {
            assert_eq!(authorization.scope(), first_scope);
            assert_eq!(
                authorization.route_scope_digest(),
                original_binding.route_scope_digest()
            );
            assert_eq!(
                authorization.policy_digest(),
                original_binding.policy_digest()
            );
            assert_eq!(
                authorization.admission_evidence_digest(),
                original_binding.evidence_digest()
            );
            assert_eq!(authorization.admission_evidence_sequence(), 1);
            assert_eq!(authorization.current_evidence_sequence(), 1);
            assert_eq!(
                authorization.current_evidence_digest(),
                original_binding.evidence_digest()
            );
            assert_eq!(
                authorization.current_proof_digest(),
                original_binding.proof_digest()
            );
            assert_eq!(
                authorization.admission_proof_digest(),
                original_binding.proof_digest()
            );
            assert_eq!(
                authorization.admission_issued_at_seconds(),
                original_binding.issued_at_seconds()
            );
            assert_eq!(
                authorization.admission_validated_at_seconds(),
                original_binding.validated_at_seconds()
            );
            assert_eq!(
                authorization.admission_valid_until_seconds(),
                original_binding.valid_until_seconds()
            );
            assert_eq!(authorization.issued_at_seconds(), EVIDENCE_TIME);
            assert_eq!(authorization.validated_at_seconds(), EVIDENCE_TIME);
            assert_eq!(
                authorization.valid_until_seconds(),
                original_binding.valid_until_seconds()
            );
            let digest = authorization.authorization_digest();
            Ok::<_, ProductionTimeGuardErrorV2>(
                authorization
                    .consume_after_verified_plan(first_scope, digest)
                    .unwrap(),
            )
        })
        .unwrap()
        .unwrap();
    assert_ne!(first_digest, [0; 32]);

    let refreshed = evidence(&policy, 2, EVIDENCE_TIME + 20, 1);
    guard
        .install_evidence(&sign_new_evidence(&refreshed), EVIDENCE_TIME + 20)
        .unwrap();
    let second_scope = scope(ROUTE_ID, LegIdV1::Downstream, 1, 0x32, 0x42);
    let (second_digest, second_proof) = guard
        .authorize_new_funding_with(EVIDENCE_TIME + 20, second_scope, |authorization| {
            assert_eq!(authorization.current_evidence_sequence(), 2);
            assert_ne!(
                authorization.current_evidence_digest(),
                authorization.admission_evidence_digest()
            );
            let proof = authorization.current_proof_digest();
            let digest = authorization.authorization_digest();
            Ok::<_, ProductionTimeGuardErrorV2>(
                authorization
                    .consume_after_verified_plan(second_scope, (digest, proof))
                    .unwrap(),
            )
        })
        .unwrap()
        .unwrap();
    assert_ne!(first_digest, second_digest);
    assert_ne!(original_binding.proof_digest(), second_proof);

    drop(guard);
    let reopened = DurableRouteTimeAnchorStoreV2::open_existing(&time_path, time_config).unwrap();
    let mut restarted = guard_from(reopened, &harness.admission, &context);
    let restart_scope = scope(ROUTE_ID, LegIdV1::Downstream, 2, 0x33, 0x43);
    restarted
        .authorize_new_funding_with(EVIDENCE_TIME + 21, restart_scope, |authorization| {
            assert_eq!(authorization.current_evidence_sequence(), 2);
            Ok::<_, ProductionTimeGuardErrorV2>(
                authorization
                    .consume_after_verified_plan(restart_scope, ())
                    .unwrap(),
            )
        })
        .unwrap()
        .unwrap();
}

#[test]
fn expiry_and_clock_rollback_block_only_new_funding_not_recovery_exits() {
    let harness = admitted_harness_with_evidence_expiry(EVIDENCE_TIME + 15);
    let expiry = harness
        .admission
        .route_time_binding_v2()
        .unwrap()
        .valid_until_seconds();
    let context = harness.context.clone();
    let path = harness.time_path.clone();
    let config = harness.time_config;
    let mut guard = guard_from(harness.time_store, &harness.admission, &context);
    let first_scope = scope(ROUTE_ID, LegIdV1::Upstream, 1, 0x51, 0x61);
    guard
        .authorize_new_funding_with(EVIDENCE_TIME + 10, first_scope, |authorization| {
            Ok::<_, ProductionTimeGuardErrorV2>(
                authorization
                    .consume_after_verified_plan(first_scope, ())
                    .unwrap(),
            )
        })
        .unwrap()
        .unwrap();

    let rollback_scope = scope(ROUTE_ID, LegIdV1::Downstream, 1, 0x52, 0x62);
    assert_eq!(
        guard
            .authorize_new_funding_with(EVIDENCE_TIME + 9, rollback_scope, |authorization| {
                Ok::<_, ProductionTimeGuardErrorV2>(
                    authorization
                        .consume_after_verified_plan(rollback_scope, ())
                        .unwrap(),
                )
            })
            .unwrap_err(),
        ProductionTimeGuardErrorV2::TimeAuthority(RouteTimeAnchorErrorV2::ClockRollback)
    );

    let last_valid_scope = scope(ROUTE_ID, LegIdV1::Downstream, 1, 0x54, 0x64);
    guard
        .authorize_new_funding_with(expiry - 1, last_valid_scope, |authorization| {
            assert_eq!(authorization.valid_until_seconds(), expiry);
            Ok::<_, ProductionTimeGuardErrorV2>(
                authorization
                    .consume_after_verified_plan(last_valid_scope, ())
                    .unwrap(),
            )
        })
        .unwrap()
        .unwrap();

    let expired_scope = scope(ROUTE_ID, LegIdV1::Downstream, 1, 0x53, 0x63);
    assert_eq!(
        guard
            .authorize_new_funding_with(expiry, expired_scope, |authorization| {
                Ok::<_, ProductionTimeGuardErrorV2>(
                    authorization
                        .consume_after_verified_plan(expired_scope, ())
                        .unwrap(),
                )
            })
            .unwrap_err(),
        ProductionTimeGuardErrorV2::TimeAuthority(RouteTimeAnchorErrorV2::EvidenceStale)
    );
    assert_eq!(
        guard
            .authorize_new_funding_with(expiry - 1, expired_scope, |authorization| {
                Ok::<_, ProductionTimeGuardErrorV2>(
                    authorization
                        .consume_after_verified_plan(expired_scope, ())
                        .unwrap(),
                )
            })
            .unwrap_err(),
        ProductionTimeGuardErrorV2::TimeAuthority(RouteTimeAnchorErrorV2::ClockRollback)
    );

    for action in [
        ActionKindV1::Funding,
        ActionKindV1::Claim,
        ActionKindV1::Refund,
    ] {
        for progress in [
            ActionProgressV1::NotPrepared,
            ActionProgressV1::Committed,
            ActionProgressV1::Externalized,
            ActionProgressV1::Final,
        ] {
            let expected =
                if action == ActionKindV1::Funding && progress == ActionProgressV1::NotPrepared {
                    EconomicBoundaryTimeRequirementV2::CurrentCapabilityForNewFunding
                } else {
                    EconomicBoundaryTimeRequirementV2::RecoveryExitWithoutTimeGate
                };
            assert_eq!(
                economic_boundary_time_requirement_v2(action, progress),
                expected
            );
        }
    }

    drop(guard);
    let reopened = DurableRouteTimeAnchorStoreV2::open_existing(&path, config).unwrap();
    let _recovery_guard = guard_from(reopened, &harness.admission, &context);
}

#[test]
fn cross_scope_consumption_and_stale_route_or_policy_are_refused() {
    let harness = admitted_harness();
    let context = harness.context.clone();
    let mut guard = guard_from(harness.time_store, &harness.admission, &context);
    let correct = scope(ROUTE_ID, LegIdV1::Upstream, 7, 0x71, 0x81);

    let cross_route = scope([0xb7; 32], LegIdV1::Upstream, 7, 0x71, 0x81);
    assert_eq!(
        guard
            .authorize_new_funding_with(EVIDENCE_TIME, cross_route, |authorization| {
                Ok::<_, ProductionTimeGuardErrorV2>(
                    authorization
                        .consume_after_verified_plan(cross_route, ())
                        .unwrap(),
                )
            })
            .unwrap_err(),
        ProductionTimeGuardErrorV2::CrossRouteFundingBoundary
    );

    let wrong_plan = FundingTimeAuthorizationScopeV2::new(
        ROUTE_ID,
        LegIdV1::Upstream,
        ActionKindV1::Funding,
        7,
        [0x71; 32],
        [0x81; 32],
        [0xd2; 32],
    )
    .unwrap();
    let correct_authorization_digest = guard
        .authorize_new_funding_with(EVIDENCE_TIME, correct, |authorization| {
            let digest = authorization.authorization_digest();
            Ok::<_, ProductionTimeGuardErrorV2>(
                authorization
                    .consume_after_verified_plan(correct, digest)
                    .unwrap(),
            )
        })
        .unwrap()
        .unwrap();
    for wrong in [
        scope(ROUTE_ID, LegIdV1::Downstream, 7, 0x71, 0x81),
        scope(ROUTE_ID, LegIdV1::Upstream, 8, 0x71, 0x81),
        scope(ROUTE_ID, LegIdV1::Upstream, 7, 0x72, 0x81),
        scope(ROUTE_ID, LegIdV1::Upstream, 7, 0x71, 0x82),
        wrong_plan,
    ] {
        assert_eq!(
            guard
                .authorize_new_funding_with(EVIDENCE_TIME, correct, |authorization| {
                    authorization.consume_after_verified_plan(wrong, ())
                })
                .unwrap()
                .unwrap_err(),
            ProductionTimeGuardErrorV2::PlanConsumptionMismatch
        );
        let wrong_authorization_digest = guard
            .authorize_new_funding_with(EVIDENCE_TIME, wrong, |authorization| {
                let digest = authorization.authorization_digest();
                Ok::<_, ProductionTimeGuardErrorV2>(
                    authorization
                        .consume_after_verified_plan(wrong, digest)
                        .unwrap(),
                )
            })
            .unwrap()
            .unwrap();
        assert_ne!(wrong_authorization_digest, correct_authorization_digest);
    }
    assert_eq!(
        FundingTimeAuthorizationScopeV2::new(
            ROUTE_ID,
            LegIdV1::Upstream,
            ActionKindV1::Claim,
            7,
            [0x71; 32],
            [0x81; 32],
            [0xd1; 32],
        )
        .unwrap_err(),
        ProductionTimeGuardErrorV2::RecoveryActionMustNotUseTimeGate
    );
    drop(guard);

    let stale_route = admitted_harness();
    let mut wrong_downstream = stale_route.context.downstream.clone();
    wrong_downstream.metadata.push(1);
    assert_eq!(
        ProductionRouteTimeGuardV2::new(
            stale_route.time_store,
            &stale_route.admission,
            ProductionRouteTimeGuardContextV2 {
                policy_authorities: stale_route.context.policy_authorities.clone(),
                evidence_authorities: stale_route.context.evidence_authorities.clone(),
                secp: SecpContext::new(&[0x7d; 32]),
                registry: stale_route.context.registry.clone(),
                upstream: stale_route.context.upstream.clone(),
                downstream: wrong_downstream,
            },
        )
        .unwrap_err(),
        ProductionTimeGuardErrorV2::AuthenticatedContextMismatch
    );

    // A replacement database cannot claim continuity merely by beginning at
    // a numerically newer signed evidence sequence. The exact admission row
    // must be retained as the first authenticated ancestor.
    let missing_ancestry = admitted_harness();
    let ancestry_directory = owner_only_directory();
    let ancestry_path = ancestry_directory.path().join("missing-ancestry.sqlite3");
    let mut ancestry_store =
        DurableRouteTimeAnchorStoreV2::create(&ancestry_path, missing_ancestry.time_config)
            .unwrap();
    ancestry_store
        .install_policy(
            &sign_new_policy(&missing_ancestry.policy),
            RouteTimePolicyVerificationContextV2::new(
                &missing_ancestry.context.policy_authorities,
                &SecpContext::new(&[0x70; 32]),
                &missing_ancestry.context.registry,
                &missing_ancestry.context.upstream,
                &missing_ancestry.context.downstream,
            ),
            EVIDENCE_TIME,
        )
        .unwrap();
    let starts_at_two = evidence(&missing_ancestry.policy, 2, EVIDENCE_TIME + 20, 1);
    ancestry_store
        .install_evidence(
            &sign_new_evidence(&starts_at_two),
            RouteTimeEvidenceVerificationContextV2::new(
                RouteTimePolicyVerificationContextV2::new(
                    &missing_ancestry.context.policy_authorities,
                    &SecpContext::new(&[0x71; 32]),
                    &missing_ancestry.context.registry,
                    &missing_ancestry.context.upstream,
                    &missing_ancestry.context.downstream,
                ),
                &missing_ancestry.context.evidence_authorities,
            ),
            EVIDENCE_TIME + 20,
        )
        .unwrap();
    let mut ancestry_guard = guard_from(
        ancestry_store,
        &missing_ancestry.admission,
        &missing_ancestry.context,
    );
    assert_eq!(
        ancestry_guard
            .authorize_new_funding_with(EVIDENCE_TIME + 20, correct, |authorization| {
                Ok::<_, ProductionTimeGuardErrorV2>(
                    authorization
                        .consume_after_verified_plan(correct, ())
                        .unwrap(),
                )
            })
            .unwrap_err(),
        ProductionTimeGuardErrorV2::TimeAuthority(RouteTimeAnchorErrorV2::FrozenCheckpointMismatch)
    );

    let policy_mismatch = admitted_harness();
    let alternate_directory = owner_only_directory();
    let alternate_path = alternate_directory.path().join("alternate-time.sqlite3");
    let mut alternate_store =
        DurableRouteTimeAnchorStoreV2::create(&alternate_path, policy_mismatch.time_config)
            .unwrap();
    let mut limits: RouteTimePolicyLimitsV2 = time_common::limits();
    limits.max_evidence_age_seconds += 1;
    let alternate_policy = RouteTimePolicyV2::from_registry(
        &policy_mismatch.context.registry,
        &policy_mismatch.context.upstream,
        &policy_mismatch.context.downstream,
        limits,
    )
    .unwrap();
    let policy_digest = alternate_policy.policy_digest().unwrap();
    let signing_context = SecpContext::new(&[0x7e; 32]);
    let signed_alternate_policy = SignedRouteTimePolicyV2::new(
        &alternate_policy,
        sign_digest(&signing_context, &POLICY_SECRETS, &policy_digest, 0x60),
    )
    .unwrap();
    alternate_store
        .install_policy(
            &signed_alternate_policy,
            RouteTimePolicyVerificationContextV2::new(
                &policy_mismatch.context.policy_authorities,
                &signing_context,
                &policy_mismatch.context.registry,
                &policy_mismatch.context.upstream,
                &policy_mismatch.context.downstream,
            ),
            EVIDENCE_TIME,
        )
        .unwrap();
    let alternate_evidence = evidence(&alternate_policy, 1, EVIDENCE_TIME, 0);
    alternate_store
        .install_evidence(
            &sign_new_evidence(&alternate_evidence),
            RouteTimeEvidenceVerificationContextV2::new(
                RouteTimePolicyVerificationContextV2::new(
                    &policy_mismatch.context.policy_authorities,
                    &signing_context,
                    &policy_mismatch.context.registry,
                    &policy_mismatch.context.upstream,
                    &policy_mismatch.context.downstream,
                ),
                &policy_mismatch.context.evidence_authorities,
            ),
            EVIDENCE_TIME,
        )
        .unwrap();
    let mut alternate_guard = guard_from(
        alternate_store,
        &policy_mismatch.admission,
        &policy_mismatch.context,
    );
    assert_eq!(
        alternate_guard
            .authorize_new_funding_with(EVIDENCE_TIME, correct, |authorization| {
                Ok::<_, ProductionTimeGuardErrorV2>(
                    authorization
                        .consume_after_verified_plan(correct, ())
                        .unwrap(),
                )
            })
            .unwrap_err(),
        ProductionTimeGuardErrorV2::TimeAuthority(RouteTimeAnchorErrorV2::FrozenCheckpointMismatch)
    );
}

#[test]
fn equivocation_and_reorg_invalidate_funding_but_not_exit_classification() {
    let equivocation_harness = admitted_harness();
    let context = equivocation_harness.context.clone();
    let path = equivocation_harness.time_path.clone();
    let config = equivocation_harness.time_config;
    let policy = equivocation_harness.policy.clone();
    let mut guard = guard_from(
        equivocation_harness.time_store,
        &equivocation_harness.admission,
        &context,
    );
    let conflicting = evidence(&policy, 1, EVIDENCE_TIME, 1);
    assert_eq!(
        guard
            .install_evidence(&sign_new_evidence(&conflicting), EVIDENCE_TIME)
            .unwrap_err(),
        ProductionTimeGuardErrorV2::TimeAuthority(RouteTimeAnchorErrorV2::EvidenceRollback)
    );
    let funding_scope = scope(ROUTE_ID, LegIdV1::Upstream, 1, 0x91, 0xa1);
    assert_eq!(
        guard
            .authorize_new_funding_with(EVIDENCE_TIME, funding_scope, |authorization| {
                Ok::<_, ProductionTimeGuardErrorV2>(
                    authorization
                        .consume_after_verified_plan(funding_scope, ())
                        .unwrap(),
                )
            })
            .unwrap_err(),
        ProductionTimeGuardErrorV2::TimeAuthority(RouteTimeAnchorErrorV2::AnchorReorged)
    );
    drop(guard);
    let reopened = DurableRouteTimeAnchorStoreV2::open_existing(&path, config).unwrap();
    let mut restarted = guard_from(reopened, &equivocation_harness.admission, &context);
    assert_eq!(
        restarted
            .authorize_new_funding_with(EVIDENCE_TIME, funding_scope, |authorization| {
                Ok::<_, ProductionTimeGuardErrorV2>(
                    authorization
                        .consume_after_verified_plan(funding_scope, ())
                        .unwrap(),
                )
            })
            .unwrap_err(),
        ProductionTimeGuardErrorV2::TimeAuthority(RouteTimeAnchorErrorV2::AnchorReorged)
    );

    let reorg_harness = admitted_harness();
    let mut reorg_guard = guard_from(
        reorg_harness.time_store,
        &reorg_harness.admission,
        &reorg_harness.context,
    );
    let mut moved_anchors = checkpoints(&reorg_harness.policy, 0, 1);
    moved_anchors[2].anchor_hash[0] ^= 1;
    let reorg_evidence = RouteTimeEvidenceV2::new(
        &reorg_harness.policy,
        2,
        EVIDENCE_TIME + 20,
        EVIDENCE_TIME + 320,
        moved_anchors,
    )
    .unwrap();
    assert_eq!(
        reorg_guard
            .install_evidence(&sign_new_evidence(&reorg_evidence), EVIDENCE_TIME + 20)
            .unwrap_err(),
        ProductionTimeGuardErrorV2::TimeAuthority(RouteTimeAnchorErrorV2::AnchorReorged)
    );
    assert_eq!(
        economic_boundary_time_requirement_v2(ActionKindV1::Claim, ActionProgressV1::NotPrepared),
        EconomicBoundaryTimeRequirementV2::RecoveryExitWithoutTimeGate
    );
    assert_eq!(
        economic_boundary_time_requirement_v2(ActionKindV1::Refund, ActionProgressV1::NotPrepared),
        EconomicBoundaryTimeRequirementV2::RecoveryExitWithoutTimeGate
    );
}

#[cfg(feature = "production")]
#[test]
fn persistence_adapter_binds_evidence_and_enforces_exact_millisecond_boundary() {
    let harness = admitted_harness_with_evidence_expiry(EVIDENCE_TIME + 15);
    let expiry_seconds = harness
        .admission
        .route_time_binding_v2()
        .unwrap()
        .valid_until_seconds();
    let AdmittedHarness {
        _directory: time_directory,
        time_path,
        time_config,
        time_store,
        admission,
        context,
        ..
    } = harness;
    let state = Rc::new(RefCell::new(BasePlanAuthorityState::default()));
    let mut persistence = adapter_from(time_store, &admission, &context, Rc::clone(&state));
    let (coordinator_directory, coordinator_path) = coordinator_state_path();
    let mut coordinator = create_coordinator(&coordinator_path);
    let event_id = [0xb1; 32];
    let plan = plan_for_event(
        SettlementActionV1::Funding,
        LegIdV1::Upstream,
        1,
        event_id,
        0x31,
    );
    let last_valid_unix_ms = expiry_seconds.checked_mul(1_000).unwrap() - 1;
    let shorter_base = PlanAuthorizationV1::new(
        PLAN_AUTHORITY_ID,
        plan.canonical_digest().unwrap(),
        [0xe1; 32],
        last_valid_unix_ms - 1,
    )
    .unwrap();
    let combined = combine_plan_authorization(shorter_base, [0xe4; 32], last_valid_unix_ms)
        .expect("domain-separated authorization");
    assert_eq!(combined.authority_id(), shorter_base.authority_id());
    assert_eq!(combined.plan_digest(), shorter_base.plan_digest());
    assert_ne!(combined.evidence_digest(), shorter_base.evidence_digest());
    assert_eq!(
        combined.valid_until_unix_ms(),
        shorter_base.valid_until_unix_ms()
    );

    let installed = persistence
        .install_new_plan(&mut coordinator, plan.clone(), event_id, last_valid_unix_ms)
        .unwrap();
    let stored = coordinator
        .load_plan_for_effect(plan.bindings().effect_id)
        .unwrap();
    assert_eq!(&installed, stored.view());
    assert_eq!(state.borrow().calls, 1);
    drop(persistence);
    drop(coordinator);

    let reopened_time = DurableRouteTimeAnchorStoreV2::open_existing(&time_path, time_config)
        .expect("reopen time authority");
    let mut persistence = adapter_from(reopened_time, &admission, &context, Rc::clone(&state));
    let mut coordinator = DurableSettlementCoordinatorV1::open_existing(
        &coordinator_path,
        COORDINATOR_ID,
        PLAN_AUTHORITY_ID,
    )
    .expect("reopen coordinator");
    let stored = coordinator
        .load_plan_for_effect(plan.bindings().effect_id)
        .unwrap();

    persistence
        .revalidate_preinstalled_new_plan(&stored, event_id, last_valid_unix_ms)
        .unwrap();
    assert_eq!(state.borrow().calls, 1);
    assert_eq!(
        persistence
            .revalidate_preinstalled_new_plan(&stored, [0xb2; 32], last_valid_unix_ms)
            .unwrap_err(),
        AuthorityRefusalV1::Inconsistent
    );
    assert_eq!(
        persistence
            .revalidate_preinstalled_new_plan(
                &stored,
                event_id,
                expiry_seconds.checked_mul(1_000).unwrap(),
            )
            .unwrap_err(),
        AuthorityRefusalV1::Refused
    );
    assert_eq!(state.borrow().calls, 1);

    let second_event = [0xb3; 32];
    let second_plan = plan_for_event(
        SettlementActionV1::Funding,
        LegIdV1::Downstream,
        1,
        second_event,
        0x32,
    );
    assert_eq!(
        persistence
            .install_new_plan(
                &mut coordinator,
                second_plan.clone(),
                second_event,
                expiry_seconds.checked_mul(1_000).unwrap(),
            )
            .unwrap_err(),
        AuthorityRefusalV1::Refused
    );
    assert_eq!(state.borrow().calls, 1);
    assert_eq!(
        coordinator
            .load_plan_for_effect(second_plan.bindings().effect_id)
            .unwrap_err(),
        CoordinatorErrorV1::PlanNotFound
    );

    let mut base_only = TestBasePlanAuthority {
        state: Rc::clone(&state),
    };
    assert_eq!(
        coordinator
            .install_plan(&mut base_only, plan, last_valid_unix_ms)
            .unwrap_err(),
        CoordinatorErrorV1::IdempotencyConflict
    );
    assert_eq!(state.borrow().calls, 2);
    drop(coordinator);
    drop(coordinator_directory);
    drop(time_directory);
}

#[cfg(feature = "production")]
#[test]
fn persistence_adapter_refences_preinstalled_funding_only_with_current_same_event() {
    let harness = admitted_harness();
    let AdmittedHarness {
        _directory: time_directory,
        time_store,
        admission,
        context,
        policy,
        ..
    } = harness;
    let state = Rc::new(RefCell::new(BasePlanAuthorityState::default()));
    let mut persistence = adapter_from(time_store, &admission, &context, Rc::clone(&state));
    let (coordinator_directory, coordinator_path) = coordinator_state_path();
    let mut coordinator = create_coordinator(&coordinator_path);
    let event_id = [0xb4; 32];
    let old_plan = plan_for_event(
        SettlementActionV1::Funding,
        LegIdV1::Upstream,
        1,
        event_id,
        0x33,
    );
    persistence
        .install_new_plan(
            &mut coordinator,
            old_plan.clone(),
            event_id,
            EVIDENCE_TIME * 1_000,
        )
        .unwrap();
    let refreshed = evidence(&policy, 2, EVIDENCE_TIME + 20, 1);
    persistence
        .install_time_evidence(&sign_new_evidence(&refreshed), EVIDENCE_TIME + 20)
        .unwrap();

    let old = coordinator
        .load_plan_for_effect(old_plan.bindings().effect_id)
        .unwrap();
    let takeover_now = (EVIDENCE_TIME + 20) * 1_000;
    let lease = coordinator
        .acquire_takeover_lease(
            old.view().plan_id,
            COORDINATOR_OWNER,
            2,
            [0xe2; 32],
            takeover_now,
            10_000,
        )
        .unwrap()
        .lease();
    let progress_evidence = match coordinator.takeover_status(lease, takeover_now).unwrap() {
        CustodyTakeoverStatusV1::NothingExternalized { evidence_digest } => evidence_digest,
        other => panic!("unexpected takeover status: {other:?}"),
    };
    let replacement = refenced_plan(&old_plan, event_id, 2);

    assert_eq!(
        persistence
            .refence_preinstalled_new_plan(
                &mut coordinator,
                lease,
                replacement.clone(),
                progress_evidence,
                [0xb5; 32],
                takeover_now,
            )
            .unwrap_err(),
        AuthorityRefusalV1::Inconsistent
    );
    assert_eq!(state.borrow().calls, 1);

    let refenced = persistence
        .refence_preinstalled_new_plan(
            &mut coordinator,
            lease,
            replacement.clone(),
            progress_evidence,
            event_id,
            takeover_now,
        )
        .unwrap();
    assert_eq!(refenced.fencing_epoch, 2);
    assert_eq!(state.borrow().calls, 2);
    assert_eq!(
        coordinator
            .load_plan_for_effect(old_plan.bindings().effect_id)
            .unwrap_err(),
        CoordinatorErrorV1::StaleFencing
    );
    assert_eq!(
        coordinator
            .load_plan_for_effect(replacement.bindings().effect_id)
            .unwrap()
            .plan(),
        &replacement
    );
    drop(coordinator);
    drop(coordinator_directory);
    drop(time_directory);
}

#[cfg(feature = "production")]
#[test]
fn persistence_adapter_never_uses_expiring_guard_for_recovery_claim_or_refund() {
    let harness = admitted_harness_with_evidence_expiry(EVIDENCE_TIME + 15);
    let expiry_unix_ms = harness
        .admission
        .route_time_binding_v2()
        .unwrap()
        .valid_until_seconds()
        .checked_mul(1_000)
        .unwrap();
    let AdmittedHarness {
        _directory: time_directory,
        time_store,
        admission,
        context,
        ..
    } = harness;
    let state = Rc::new(RefCell::new(BasePlanAuthorityState::default()));
    let mut persistence = adapter_from(time_store, &admission, &context, Rc::clone(&state));
    let (coordinator_directory, coordinator_path) = coordinator_state_path();
    let mut coordinator = create_coordinator(&coordinator_path);

    let funding_event = [0xb6; 32];
    let funding = plan_for_event(
        SettlementActionV1::Funding,
        LegIdV1::Upstream,
        1,
        funding_event,
        0x34,
    );
    persistence
        .install_new_plan(
            &mut coordinator,
            funding.clone(),
            funding_event,
            EVIDENCE_TIME * 1_000,
        )
        .unwrap();
    let stored = coordinator
        .load_plan_for_effect(funding.bindings().effect_id)
        .unwrap();
    let lease = coordinator
        .acquire_takeover_lease(
            stored.view().plan_id,
            COORDINATOR_OWNER,
            2,
            [0xe3; 32],
            expiry_unix_ms,
            10_000,
        )
        .unwrap()
        .lease();
    let progress_evidence = match coordinator.takeover_status(lease, expiry_unix_ms).unwrap() {
        CustodyTakeoverStatusV1::NothingExternalized { evidence_digest } => evidence_digest,
        other => panic!("unexpected takeover status: {other:?}"),
    };
    let replacement = refenced_plan(&funding, funding_event, 2);
    persistence
        .refence_existing_plan(
            &mut coordinator,
            lease,
            replacement,
            progress_evidence,
            expiry_unix_ms,
        )
        .unwrap();

    for (action, leg, event, variant) in [
        (
            SettlementActionV1::Claim,
            LegIdV1::Downstream,
            [0xb7; 32],
            0x35,
        ),
        (
            SettlementActionV1::Refund,
            LegIdV1::Downstream,
            [0xb8; 32],
            0x36,
        ),
    ] {
        persistence
            .install_new_plan(
                &mut coordinator,
                plan_for_event(action, leg, 2, event, variant),
                event,
                expiry_unix_ms,
            )
            .unwrap();
    }
    assert_eq!(state.borrow().calls, 4);
    drop(coordinator);
    drop(coordinator_directory);
    drop(time_directory);
}
