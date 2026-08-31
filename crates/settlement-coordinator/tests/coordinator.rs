use std::collections::VecDeque;
use std::fs;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;

use settlement_coordinator::{
    AggregateStageV1, CanonicalSettlementPlanV1, ChildAuthorityRefusalV1, ChildDispatchRequestV1,
    ChildExecutionOutcomeV1, ChildExposureV1, ChildExternalizationReceiptV1,
    ChildObservationOutcomeV1, ChildObservationRequestV1, ChildReconciliationOutcomeV1,
    ChildReconciliationRequestV1, CompositeSettlementPlanV1, CoordinatorDriveOutcomeV1,
    CoordinatorErrorV1, CoordinatorLeaseV1, CoordinatorObservationOutcomeV1,
    CustodyTakeoverStatusV1, DeferredChildMaterializationCapabilityV1,
    DeferredChildMaterializationResultV1, DeferredSettlementChildV1, Digest32,
    DurableSettlementCoordinatorV1, PlanAuthorityRefusalV1, PlanAuthorizationRequestV1,
    PlanAuthorizationV1, SecretRequirementV1, SettlementActionV1, SettlementChildAuthorityV1,
    SettlementChildObserverV1, SettlementChildPlanV1, SettlementDeferredChildAuthorityV1,
    SettlementFaceV1, SettlementLegV1, SettlementPlanAuthorityV1, SettlementPlanBindingsV1,
};
use tempfile::TempDir;

const COORDINATOR_ID: Digest32 = [241; 32];
const AUTHORITY_ID: Digest32 = [242; 32];
const OWNER_A: Digest32 = [243; 32];
const OWNER_B: Digest32 = [244; 32];
const DEFERRED_AUTHORITY_ID: Digest32 = [246; 32];
const RECONCILIATION_CRASH_PATH: &str = "DOM_INTEROP_COORDINATOR_RECONCILIATION_CRASH_PATH";
const RECONCILIATION_CRASH_EXIT: i32 = 86;

fn digest(value: u8) -> Digest32 {
    [value; 32]
}

fn state_path() -> (TempDir, PathBuf) {
    let root = tempfile::tempdir().expect("tempdir");
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).expect("mode");
    let canonical = fs::canonicalize(root.path()).expect("canonical root");
    let path = canonical.join("settlement-coordinator.sqlite3");
    (root, path)
}

fn plan(action: SettlementActionV1, fence: u64, effect: u8) -> CompositeSettlementPlanV1 {
    let (secret_requirement, preexisting, exposures) = match action {
        SettlementActionV1::Funding | SettlementActionV1::Refund => (
            SecretRequirementV1::None,
            None,
            [ChildExposureV1::NonSecret, ChildExposureV1::NonSecret],
        ),
        SettlementActionV1::Claim => (
            SecretRequirementV1::FirstExposureRequired,
            None,
            [
                ChildExposureV1::FirstSecretExposure,
                ChildExposureV1::UsesPublicSecret,
            ],
        ),
    };
    CompositeSettlementPlanV1::new(
        SettlementPlanBindingsV1 {
            route_id: digest(1),
            effect_id: digest(effect),
            settlement_id: digest(3),
            leg: SettlementLegV1::Downstream,
            action,
            fencing_epoch: fence,
            semantic_digest: digest(4),
            terms_digest: digest(5),
            registry_digest: digest(6),
            dom_profile_digest: digest(7),
            dom_deployment_digest: digest(8),
            counterparty_profile_digest: digest(9),
            counterparty_deployment_digest: digest(10),
        },
        secret_requirement,
        preexisting,
        [
            SettlementChildPlanV1 {
                face: SettlementFaceV1::Evm,
                exposure: exposures[0],
                chain_id: digest(11),
                expected_transaction_id: digest(12),
                intent_digest: digest(13),
                custody_digest: digest(14),
            },
            SettlementChildPlanV1 {
                face: SettlementFaceV1::Dom,
                exposure: exposures[1],
                chain_id: digest(15),
                expected_transaction_id: digest(16),
                intent_digest: digest(17),
                custody_digest: digest(18),
            },
        ],
    )
    .expect("valid plan")
}

fn replacement(
    original: &CompositeSettlementPlanV1,
    fence: u64,
    effect: u8,
) -> CompositeSettlementPlanV1 {
    let mut bindings = original.bindings().clone();
    bindings.fencing_epoch = fence;
    bindings.effect_id = digest(effect);
    CompositeSettlementPlanV1::new(
        bindings,
        original.secret_requirement(),
        original.preexisting_secret_evidence_digest(),
        original
            .materialized_children()
            .expect("materialized")
            .clone(),
    )
    .expect("replacement")
}

fn already_public_claim_plan(fence: u64, effect: u8) -> CompositeSettlementPlanV1 {
    let base = plan(SettlementActionV1::Claim, fence, effect);
    let mut children = base.materialized_children().expect("materialized").clone();
    for child in &mut children {
        child.exposure = ChildExposureV1::UsesPublicSecret;
    }
    CompositeSettlementPlanV1::new(
        base.bindings().clone(),
        SecretRequirementV1::AlreadyPublic,
        Some(digest(19)),
        children,
    )
    .expect("already-public plan")
}

fn staged_claim_plan(fence: u64, effect: u8) -> CompositeSettlementPlanV1 {
    let base = plan(SettlementActionV1::Claim, fence, effect);
    CompositeSettlementPlanV1::new_first_exposure_staged(
        base.bindings().clone(),
        SettlementChildPlanV1 {
            face: SettlementFaceV1::Dom,
            exposure: ChildExposureV1::FirstSecretExposure,
            chain_id: digest(15),
            expected_transaction_id: digest(16),
            intent_digest: digest(17),
            custody_digest: digest(18),
        },
        DeferredSettlementChildV1 {
            face: SettlementFaceV1::Evm,
            chain_id: digest(11),
            route_scope_digest: digest(20),
            composition_digest: digest(21),
            role_plan_digest: digest(22),
            source_scope_digest: digest(23),
            materializer_authority_id: DEFERRED_AUTHORITY_ID,
        },
    )
    .expect("staged plan")
}

struct DeferredAuthority {
    authority_id: Digest32,
    child: SettlementChildPlanV1,
    calls: Vec<Digest32>,
    refuse_after_capability: bool,
}

impl DeferredAuthority {
    fn exact() -> Self {
        Self {
            authority_id: DEFERRED_AUTHORITY_ID,
            child: SettlementChildPlanV1 {
                face: SettlementFaceV1::Evm,
                exposure: ChildExposureV1::UsesPublicSecret,
                chain_id: digest(11),
                expected_transaction_id: digest(24),
                intent_digest: digest(25),
                custody_digest: digest(26),
            },
            calls: Vec::new(),
            refuse_after_capability: false,
        }
    }
}

impl SettlementDeferredChildAuthorityV1 for DeferredAuthority {
    fn authority_id(&self) -> Digest32 {
        self.authority_id
    }

    fn materialize_deferred_child(
        &mut self,
        capability: DeferredChildMaterializationCapabilityV1,
    ) -> Result<DeferredChildMaterializationResultV1, ChildAuthorityRefusalV1> {
        self.calls.push(capability.attempt_id());
        if self.refuse_after_capability {
            return Err(ChildAuthorityRefusalV1::Unavailable);
        }
        DeferredChildMaterializationResultV1::complete(
            capability,
            self.authority_id,
            self.child.clone(),
        )
        .map_err(|_| ChildAuthorityRefusalV1::Conflict)
    }
}

struct PlanAuthority {
    evidence: Digest32,
}

impl PlanAuthority {
    fn new() -> Self {
        Self {
            evidence: digest(245),
        }
    }
}

impl SettlementPlanAuthorityV1 for PlanAuthority {
    fn authorize_plan(
        &mut self,
        request: PlanAuthorizationRequestV1<'_>,
    ) -> Result<PlanAuthorizationV1, PlanAuthorityRefusalV1> {
        PlanAuthorizationV1::new(
            AUTHORITY_ID,
            request.plan_digest(),
            self.evidence,
            1_000_000,
        )
        .map_err(|_| PlanAuthorityRefusalV1::Refused)
    }
}

struct RecombinedPlanAuthority;

impl SettlementPlanAuthorityV1 for RecombinedPlanAuthority {
    fn authorize_plan(
        &mut self,
        request: PlanAuthorizationRequestV1<'_>,
    ) -> Result<PlanAuthorizationV1, PlanAuthorityRefusalV1> {
        let base = PlanAuthority::new().authorize_plan(request)?;
        let mut recombined_evidence = base.evidence_digest();
        recombined_evidence[0] ^= 1;
        PlanAuthorizationV1::new(
            base.authority_id(),
            base.plan_digest(),
            recombined_evidence,
            base.valid_until_unix_ms(),
        )
        .map_err(|_| PlanAuthorityRefusalV1::Refused)
    }
}

#[derive(Clone, Copy)]
enum DispatchMode {
    Externalized(u8),
    Retryable(u8),
    Unknown(u8),
}

#[derive(Clone, Copy)]
enum ReconcileMode {
    Externalized(u8),
    NotExternalized(u8),
    Unknown(u8),
}

#[derive(Default)]
struct ChildAuthority {
    dispatch: VecDeque<DispatchMode>,
    reconcile: VecDeque<ReconcileMode>,
    calls: Vec<(u8, Digest32, Digest32)>,
    reconciliations: Vec<Digest32>,
}

impl ChildAuthority {
    fn receipt(request: &ChildDispatchRequestV1, evidence: u8) -> ChildExternalizationReceiptV1 {
        ChildExternalizationReceiptV1 {
            plan_id: request.plan_id(),
            child_index: request.child_index(),
            face: request.face(),
            chain_id: request.chain_id(),
            transaction_id: request.expected_transaction_id(),
            intent_digest: request.intent_digest(),
            custody_digest: request.custody_digest(),
            externalization_evidence_digest: digest(evidence),
            first_exposure_evidence_digest: (request.exposure()
                == ChildExposureV1::FirstSecretExposure)
                .then(|| digest(evidence.wrapping_add(50))),
        }
    }
}

impl SettlementChildAuthorityV1 for ChildAuthority {
    fn externalize_child(
        &mut self,
        request: &ChildDispatchRequestV1,
    ) -> Result<ChildExecutionOutcomeV1, ChildAuthorityRefusalV1> {
        self.calls.push((
            request.child_index(),
            request.profile_digest(),
            request.deployment_digest(),
        ));
        match self
            .dispatch
            .pop_front()
            .ok_or(ChildAuthorityRefusalV1::Unavailable)?
        {
            DispatchMode::Externalized(evidence) => Ok(ChildExecutionOutcomeV1::Externalized(
                Self::receipt(request, evidence),
            )),
            DispatchMode::Retryable(value) => {
                Ok(ChildExecutionOutcomeV1::RetryableBeforeExternalization {
                    evidence_digest: digest(value),
                })
            }
            DispatchMode::Unknown(value) => Ok(ChildExecutionOutcomeV1::Unknown {
                evidence_digest: digest(value),
            }),
        }
    }

    fn reconcile_child(
        &mut self,
        request: &ChildReconciliationRequestV1,
    ) -> Result<ChildReconciliationOutcomeV1, ChildAuthorityRefusalV1> {
        self.reconciliations.push(request.reconciliation_attempt_id);
        match self
            .reconcile
            .pop_front()
            .ok_or(ChildAuthorityRefusalV1::Unavailable)?
        {
            ReconcileMode::Externalized(evidence) => {
                Ok(ChildReconciliationOutcomeV1::Externalized(Self::receipt(
                    &request.dispatch,
                    evidence,
                )))
            }
            ReconcileMode::NotExternalized(value) => {
                Ok(ChildReconciliationOutcomeV1::ProvenNotExternalized {
                    evidence_digest: digest(value),
                })
            }
            ReconcileMode::Unknown(value) => Ok(ChildReconciliationOutcomeV1::Unknown {
                evidence_digest: digest(value),
            }),
        }
    }
}

#[derive(Default)]
struct Observer {
    outcomes: VecDeque<ChildObservationOutcomeV1>,
    requests: Vec<ChildObservationRequestV1>,
}

impl SettlementChildObserverV1 for Observer {
    fn observe_child(
        &mut self,
        request: &ChildObservationRequestV1,
    ) -> Result<ChildObservationOutcomeV1, ChildAuthorityRefusalV1> {
        self.requests.push(*request);
        self.outcomes
            .pop_front()
            .ok_or(ChildAuthorityRefusalV1::Unavailable)
    }
}

fn create_store(path: &Path) -> DurableSettlementCoordinatorV1 {
    DurableSettlementCoordinatorV1::create(path, COORDINATOR_ID, AUTHORITY_ID, 1_000)
        .expect("create store")
}

fn open_store(path: &Path) -> DurableSettlementCoordinatorV1 {
    DurableSettlementCoordinatorV1::open_existing(path, COORDINATOR_ID, AUTHORITY_ID)
        .expect("open store")
}

fn install(
    store: &mut DurableSettlementCoordinatorV1,
    plan: CompositeSettlementPlanV1,
) -> (Digest32, CoordinatorLeaseV1) {
    let view = store
        .install_plan(&mut PlanAuthority::new(), plan.clone(), 1_001)
        .expect("install");
    let lease = store
        .acquire_lease(
            view.plan_id,
            OWNER_A,
            plan.bindings().fencing_epoch,
            1_002,
            500,
        )
        .expect("lease")
        .lease();
    (view.plan_id, lease)
}

#[test]
fn strict_order_reveal_and_aggregate_receipt() {
    let (_root, path) = state_path();
    let mut store = create_store(&path);
    let (plan_id, lease) = install(&mut store, plan(SettlementActionV1::Claim, 1, 2));
    let mut authority = ChildAuthority {
        dispatch: [
            DispatchMode::Externalized(30),
            DispatchMode::Externalized(31),
        ]
        .into(),
        ..ChildAuthority::default()
    };

    assert!(matches!(
        store
            .current_custody_progress(lease, 1_002)
            .expect("read current empty prefix"),
        CoordinatorDriveOutcomeV1::Waiting { .. }
    ));
    assert_eq!(
        store.authenticate_first_public_exposure(plan_id).err(),
        Some(CoordinatorErrorV1::InvalidState)
    );
    assert!(
        authority.calls.is_empty(),
        "status read must not call a child"
    );

    let first = store
        .drive_one(lease, &mut authority, 1_003)
        .expect("first child");
    let progress = match first {
        CoordinatorDriveOutcomeV1::PartialProgress(progress) => progress,
        other => panic!("unexpected first outcome: {other:?}"),
    };
    assert_eq!(progress.completed_prefix, 1);
    let exposure = progress.exposure.expect("first exposure");
    assert_eq!(exposure.child_index, 0);
    assert_eq!(exposure.transaction_id, digest(12));
    assert_eq!(exposure.observed_at_unix_ms, 1_003);
    let authenticated = store
        .authenticate_first_public_exposure(plan_id)
        .expect("fully audited first-exposure capability");
    assert_eq!(authenticated.route_id(), digest(1));
    assert_eq!(authenticated.plan_id(), plan_id);
    assert_eq!(authenticated.settlement_id(), digest(3));
    assert_eq!(authenticated.exposure(), &exposure);
    assert_ne!(authenticated.plan_digest(), [0; 32]);
    assert_ne!(authenticated.journal_head(), [0; 32]);
    let authenticated_view = store
        .load_plan(plan_id)
        .expect("reload the exact audited plan behind the capability");
    assert_eq!(authenticated.plan_digest(), authenticated_view.plan_digest);
    assert_eq!(authenticated.plan_revision(), authenticated_view.revision);
    assert_eq!(
        store
            .current_custody_progress(lease, 1_003)
            .expect("recover lost partial receipt"),
        CoordinatorDriveOutcomeV1::PartialProgress(progress)
    );
    assert_eq!(authority.calls.len(), 1, "status read must stay read-only");
    let active = store.load_plan(plan_id).expect("active view");
    assert_eq!(active.stage, AggregateStageV1::Active);

    let aggregate = match store
        .drive_one(lease, &mut authority, 1_004)
        .expect("second child")
    {
        CoordinatorDriveOutcomeV1::AggregateExternalized(receipt) => receipt,
        other => panic!("unexpected aggregate outcome: {other:?}"),
    };
    assert_eq!(aggregate.first_exposure, Some(exposure));
    assert_eq!(
        store
            .current_custody_progress(lease, 1_004)
            .expect("recover lost aggregate receipt"),
        CoordinatorDriveOutcomeV1::AggregateExternalized(aggregate)
    );
    assert_eq!(aggregate.aggregate_action_id, progress.aggregate_action_id);
    assert_eq!(authority.calls[0], (0, digest(9), digest(10)));
    assert_eq!(authority.calls[1], (1, digest(7), digest(8)));
    assert_eq!(
        store.load_plan(plan_id).expect("view").stage,
        AggregateStageV1::Externalized
    );
}

#[test]
fn staged_child_is_secret_free_restartable_and_authority_pinned() {
    let (_root, path) = state_path();
    let mut store = create_store(&path);
    let (plan_id, lease) = install(&mut store, staged_claim_plan(1, 27));
    let installed = store.load_plan(plan_id).expect("installed staged");
    assert_eq!(
        installed.children[1].stage,
        settlement_coordinator::ChildStageV1::Deferred
    );
    assert_eq!(installed.children[1].transaction_id, None);

    let mut child_authority = ChildAuthority {
        dispatch: [DispatchMode::Externalized(30)].into(),
        ..ChildAuthority::default()
    };
    let first = store
        .drive_one(lease, &mut child_authority, 1_003)
        .expect("DOM first exposure");
    let progress = match first {
        CoordinatorDriveOutcomeV1::PartialProgress(progress) => progress,
        other => panic!("unexpected staged first-exposure result: {other:?}"),
    };
    let authenticated = store
        .authenticate_first_public_exposure(plan_id)
        .expect("authenticate staged DOM exposure before deferred materialization");
    assert_eq!(
        authenticated.exposure(),
        &progress.exposure.expect("exposure")
    );
    assert_eq!(child_authority.calls.len(), 1);

    let before_wrong_authority = store.load_plan(plan_id).expect("before wrong authority");
    let mut wrong_authority = DeferredAuthority::exact();
    wrong_authority.authority_id = digest(99);
    assert_eq!(
        store
            .materialize_deferred_child_one(lease, &mut wrong_authority, 1_004, || Ok(1_005))
            .unwrap_err(),
        CoordinatorErrorV1::ChildAuthorityRefused
    );
    assert!(wrong_authority.calls.is_empty());
    assert_eq!(
        store.load_plan(plan_id).expect("after wrong authority"),
        before_wrong_authority
    );

    let mut interrupted = DeferredAuthority::exact();
    interrupted.refuse_after_capability = true;
    assert_eq!(
        store
            .materialize_deferred_child_one(lease, &mut interrupted, 1_004, || Ok(1_005))
            .unwrap_err(),
        CoordinatorErrorV1::ChildAuthorityRefused
    );
    assert_eq!(interrupted.calls.len(), 1);
    let durable_attempt = interrupted.calls[0];
    drop(store);

    let mut store = open_store(&path);
    let mut resumed = DeferredAuthority::exact();
    let materialized = store
        .materialize_deferred_child_one(lease, &mut resumed, 1_005, || Ok(1_006))
        .expect("resume exact pending materialization");
    assert_eq!(resumed.calls, vec![durable_attempt]);
    assert_eq!(
        materialized.children[1].stage,
        settlement_coordinator::ChildStageV1::Planned
    );
    assert_eq!(materialized.children[1].transaction_id, Some(digest(24)));

    let mut forbidden_recall = DeferredAuthority::exact();
    let replay = store
        .materialize_deferred_child_one(lease, &mut forbidden_recall, 1_006, || Ok(1_007))
        .expect("completed materialization replay");
    assert!(forbidden_recall.calls.is_empty());
    assert_eq!(replay, materialized);

    child_authority
        .dispatch
        .push_back(DispatchMode::Externalized(31));
    assert!(matches!(
        store
            .drive_one(lease, &mut child_authority, 1_007)
            .expect("dispatch only on later drive"),
        CoordinatorDriveOutcomeV1::AggregateExternalized(_)
    ));
    assert_eq!(child_authority.calls.len(), 2);
}

#[test]
fn deferred_completion_timestamp_tamper_is_rejected_on_restart() {
    let (_root, path) = state_path();
    let mut store = create_store(&path);
    let (plan_id, lease) = install(&mut store, staged_claim_plan(1, 28));
    let mut child_authority = ChildAuthority {
        dispatch: [DispatchMode::Externalized(32)].into(),
        ..ChildAuthority::default()
    };
    assert!(matches!(
        store
            .drive_one(lease, &mut child_authority, 1_003)
            .expect("DOM first exposure"),
        CoordinatorDriveOutcomeV1::PartialProgress(_)
    ));
    store
        .materialize_deferred_child_one(lease, &mut DeferredAuthority::exact(), 1_004, || Ok(1_005))
        .expect("complete deferred materialization");
    drop(store);

    let connection = rusqlite::Connection::open(&path).expect("raw connection");
    assert_eq!(
        connection
            .execute(
                "UPDATE deferred_child_materializations
                 SET completed_at_be=?2 WHERE plan_id=?1",
                rusqlite::params![plan_id.as_slice(), 1_u64.to_be_bytes().as_slice()],
            )
            .expect("tamper completion timestamp"),
        1
    );
    drop(connection);

    assert_eq!(
        DurableSettlementCoordinatorV1::open_existing(&path, COORDINATOR_ID, AUTHORITY_ID)
            .unwrap_err(),
        CoordinatorErrorV1::CorruptState
    );
}

#[test]
fn exact_takeover_lease_can_resume_but_never_change_owner_or_route_fence() {
    let (_root, path) = state_path();
    let mut store = create_store(&path);
    let (plan_id, _) = install(&mut store, plan(SettlementActionV1::Funding, 1, 2));
    let takeover = store
        .acquire_takeover_lease(plan_id, OWNER_B, 2, digest(70), 1_600, 100)
        .expect("initial takeover")
        .lease();

    let live = store
        .resume_takeover_lease(plan_id, OWNER_B, 2, 1_650, 100)
        .expect("resume live takeover");
    assert!(matches!(
        live,
        settlement_coordinator::CoordinatorLeaseAcquireV1::AlreadyOwned(_)
    ));
    let live = live.lease();
    assert_eq!(
        live.coordinator_fencing_epoch(),
        takeover.coordinator_fencing_epoch()
    );
    assert_eq!(live.lease_until_unix_ms(), 1_750);
    assert_eq!(
        store
            .resume_takeover_lease(plan_id, OWNER_A, 2, 1_651, 100)
            .unwrap_err(),
        CoordinatorErrorV1::StaleFencing
    );
    assert_eq!(
        store
            .resume_takeover_lease(plan_id, OWNER_B, 3, 1_651, 100)
            .unwrap_err(),
        CoordinatorErrorV1::StaleFencing
    );

    let expired = store
        .resume_takeover_lease(plan_id, OWNER_B, 2, 1_751, 100)
        .expect("resume expired takeover");
    assert!(matches!(
        expired,
        settlement_coordinator::CoordinatorLeaseAcquireV1::Acquired(_)
    ));
    let expired = expired.lease();
    assert_eq!(
        expired.coordinator_fencing_epoch(),
        takeover.coordinator_fencing_epoch() + 1
    );
    assert_eq!(
        store.takeover_status(takeover, 1_752).unwrap_err(),
        CoordinatorErrorV1::StaleFencing
    );
    assert!(matches!(
        store
            .takeover_status(expired, 1_752)
            .expect("new generation is live"),
        CustodyTakeoverStatusV1::NothingExternalized { .. }
    ));
    assert_eq!(
        store
            .acquire_takeover_lease(plan_id, OWNER_B, 2, digest(70), 1_752, 100)
            .unwrap_err(),
        CoordinatorErrorV1::StaleFencing
    );
}

#[test]
fn stable_replacement_lookup_audits_restart_and_ignores_only_effect_and_fence() {
    let (_root, path) = state_path();
    let original = plan(SettlementActionV1::Funding, 1, 2);
    let original_effect = original.bindings().effect_id;
    let expected_plan_id = {
        let mut store = create_store(&path);
        let (plan_id, _) = install(&mut store, original.clone());
        let next = replacement(&original, 2, 3);
        let stored = store
            .load_plan_for_stable_replacement(&next)
            .expect("stable replacement lookup");
        assert_eq!(stored.view().plan_id, plan_id);
        assert_eq!(stored.plan(), &original);
        assert_eq!(stored.view().effect_id, original_effect);
        plan_id
    };

    let store = open_store(&path);
    let next = replacement(&original, 2, 3);
    let stored = store
        .load_plan_for_stable_replacement(&next)
        .expect("restart stable replacement lookup");
    assert_eq!(stored.view().plan_id, expected_plan_id);
    assert_eq!(stored.plan(), &original);

    let mut divergent_bindings = next.bindings().clone();
    divergent_bindings.semantic_digest = digest(200);
    let divergent = CompositeSettlementPlanV1::new(
        divergent_bindings,
        next.secret_requirement(),
        next.preexisting_secret_evidence_digest(),
        next.materialized_children().expect("materialized").clone(),
    )
    .expect("valid divergent plan");
    assert_eq!(
        store
            .load_plan_for_stable_replacement(&divergent)
            .unwrap_err(),
        CoordinatorErrorV1::PlanNotFound
    );
}

#[test]
fn recombined_authorization_evidence_is_durable_and_idempotency_bound() {
    let (_root, path) = state_path();
    let exact_plan = plan(SettlementActionV1::Funding, 1, 201);
    let plan_id = {
        let mut store = create_store(&path);
        store
            .install_plan(&mut RecombinedPlanAuthority, exact_plan.clone(), 1_001)
            .expect("install recombined authorization")
            .plan_id
    };

    let mut store = open_store(&path);
    assert_eq!(
        store
            .install_plan(&mut PlanAuthority::new(), exact_plan, 1_002)
            .unwrap_err(),
        CoordinatorErrorV1::IdempotencyConflict
    );
    assert_eq!(
        store.load_plan(plan_id).expect("failed-closed view").stage,
        AggregateStageV1::FailedClosed
    );
}

#[test]
fn crash_boundaries_preserve_pending_and_secret_public_partial() {
    let (_root, path) = state_path();
    let original = plan(SettlementActionV1::Claim, 1, 2);
    let (plan_id, old_lease) = {
        let mut store = create_store(&path);
        let (plan_id, lease) = install(&mut store, original.clone());
        let pending = store
            .prepare_next_child_call(lease, 1_003)
            .expect("persist before authority");
        assert_eq!(pending.request().child_index(), 0);
        (plan_id, lease)
    };

    let mut store = open_store(&path);
    let takeover = store
        .acquire_takeover_lease(plan_id, OWNER_B, 2, digest(70), 1_100, 500)
        .expect("takeover")
        .lease();
    assert!(matches!(
        store.takeover_status(takeover, 1_101).expect("status"),
        CustodyTakeoverStatusV1::Unknown { .. }
    ));
    assert_eq!(
        store.prepare_next_child_call(old_lease, 1_101).unwrap_err(),
        CoordinatorErrorV1::StaleFencing
    );

    let mut reconcile = ChildAuthority {
        reconcile: [ReconcileMode::Externalized(40)].into(),
        ..ChildAuthority::default()
    };
    let status = store
        .reconcile_takeover_one(takeover, &mut reconcile, 1_102)
        .expect("reconcile externalized");
    let partial = match status {
        CustodyTakeoverStatusV1::SecretPublicPartial(progress) => progress,
        other => panic!("must expose partial secret state: {other:?}"),
    };
    assert_eq!(partial.completed_prefix, 1);
    assert_eq!(
        partial.exposure.expect("exposure").transaction_id,
        digest(12)
    );
    drop(store);

    let mut store = open_store(&path);
    let status = store
        .takeover_status(takeover, 1_103)
        .expect("status after supervisor crash");
    let durable = match status {
        CustodyTakeoverStatusV1::SecretPublicPartial(progress) => progress,
        other => panic!("durable exposure lost: {other:?}"),
    };
    assert_eq!(durable, partial);

    let replacement = replacement(&original, 2, 80);
    let view = store
        .refence_plan(
            takeover,
            replacement,
            durable.progress_evidence_digest,
            &mut PlanAuthority::new(),
            1_104,
        )
        .expect("refence secret-public partial");
    assert_eq!(view.fencing_epoch, 2);
    assert_eq!(view.aggregate_action_id, partial.aggregate_action_id);
}

#[test]
fn nonsecret_partial_takeover_refence_and_stale_fence() {
    let (_root, path) = state_path();
    let original = plan(SettlementActionV1::Funding, 1, 22);
    let mut store = create_store(&path);
    let (plan_id, old_lease) = install(&mut store, original.clone());
    let mut first = ChildAuthority {
        dispatch: [DispatchMode::Externalized(41)].into(),
        ..ChildAuthority::default()
    };
    let partial = match store
        .drive_one(old_lease, &mut first, 1_003)
        .expect("first")
    {
        CoordinatorDriveOutcomeV1::PartialProgress(progress) => progress,
        other => panic!("unexpected: {other:?}"),
    };
    assert!(partial.exposure.is_none());

    let takeover = store
        .acquire_takeover_lease(plan_id, OWNER_B, 2, digest(71), 1_004, 500)
        .expect("takeover")
        .lease();
    let safe = match store.takeover_status(takeover, 1_005).expect("status") {
        CustodyTakeoverStatusV1::SafeToResumeCustody(progress) => progress,
        other => panic!("must be safe non-secret prefix: {other:?}"),
    };
    assert_eq!(safe, partial);
    store
        .refence_plan(
            takeover,
            replacement(&original, 2, 81),
            safe.progress_evidence_digest,
            &mut PlanAuthority::new(),
            1_006,
        )
        .expect("refence");
    assert_eq!(
        store.prepare_next_child_call(old_lease, 1_007).unwrap_err(),
        CoordinatorErrorV1::StaleFencing
    );
    let mut second = ChildAuthority {
        dispatch: [DispatchMode::Externalized(42)].into(),
        ..ChildAuthority::default()
    };
    let receipt = match store
        .drive_one(takeover, &mut second, 1_007)
        .expect("finish")
    {
        CoordinatorDriveOutcomeV1::AggregateExternalized(receipt) => receipt,
        other => panic!("unexpected: {other:?}"),
    };
    assert_eq!(receipt.aggregate_action_id, safe.aggregate_action_id);
}

#[test]
fn already_public_claim_needs_no_duplicate_exposure_receipt() {
    let (_root, path) = state_path();
    let original = already_public_claim_plan(1, 32);
    let mut store = create_store(&path);
    let (plan_id, lease) = install(&mut store, original.clone());
    let mut first = ChildAuthority {
        dispatch: [DispatchMode::Externalized(43)].into(),
        ..ChildAuthority::default()
    };
    let partial = match store.drive_one(lease, &mut first, 1_003).expect("first") {
        CoordinatorDriveOutcomeV1::PartialProgress(progress) => progress,
        other => panic!("unexpected: {other:?}"),
    };
    assert!(partial.exposure.is_none());
    let takeover = store
        .acquire_takeover_lease(plan_id, OWNER_B, 2, digest(74), 1_004, 500)
        .expect("takeover")
        .lease();
    assert!(matches!(
        store.takeover_status(takeover, 1_005).expect("status"),
        CustodyTakeoverStatusV1::SafeToResumeCustody(progress)
            if progress.exposure.is_none()
    ));
    store
        .refence_plan(
            takeover,
            replacement(&original, 2, 83),
            partial.progress_evidence_digest,
            &mut PlanAuthority::new(),
            1_006,
        )
        .expect("refence");
    let mut second = ChildAuthority {
        dispatch: [DispatchMode::Externalized(44)].into(),
        ..ChildAuthority::default()
    };
    let aggregate = match store
        .drive_one(takeover, &mut second, 1_007)
        .expect("aggregate")
    {
        CoordinatorDriveOutcomeV1::AggregateExternalized(receipt) => receipt,
        other => panic!("unexpected: {other:?}"),
    };
    assert!(aggregate.first_exposure.is_none());
}

#[test]
fn unknown_never_becomes_not_externalized_without_reconciliation() {
    let (_root, path) = state_path();
    let original = plan(SettlementActionV1::Funding, 1, 23);
    let mut store = create_store(&path);
    let (plan_id, lease) = install(&mut store, original);
    let mut authority = ChildAuthority {
        dispatch: [DispatchMode::Unknown(50)].into(),
        ..ChildAuthority::default()
    };
    assert!(matches!(
        store.drive_one(lease, &mut authority, 1_003).expect("unknown"),
        CoordinatorDriveOutcomeV1::Unknown { evidence_digest } if evidence_digest == digest(50)
    ));
    let takeover = store
        .acquire_takeover_lease(plan_id, OWNER_B, 2, digest(72), 1_004, 500)
        .expect("takeover")
        .lease();
    assert!(matches!(
        store
            .takeover_status(takeover, 1_005)
            .expect("unknown status"),
        CustodyTakeoverStatusV1::Unknown { .. }
    ));
    let mut reconcile = ChildAuthority {
        reconcile: [ReconcileMode::Unknown(51)].into(),
        ..ChildAuthority::default()
    };
    assert!(matches!(
        store
            .reconcile_takeover_one(takeover, &mut reconcile, 1_006)
            .expect("still unknown"),
        CustodyTakeoverStatusV1::Unknown { .. }
    ));
    let mut resolved = ChildAuthority {
        reconcile: [ReconcileMode::NotExternalized(52)].into(),
        ..ChildAuthority::default()
    };
    assert!(matches!(
        store
            .reconcile_takeover_one(takeover, &mut resolved, 1_007)
            .expect("now proven absent"),
        CustodyTakeoverStatusV1::NothingExternalized { .. }
    ));
}

#[test]
fn same_fence_unknown_reconciliation_is_sequenced_and_replays_exposure_time() {
    let (_root, path) = state_path();
    let mut store = create_store(&path);
    let (_plan_id, lease) = install(&mut store, plan(SettlementActionV1::Claim, 1, 35));
    let mut authority = ChildAuthority {
        dispatch: [DispatchMode::Unknown(53)].into(),
        reconcile: [ReconcileMode::Unknown(54), ReconcileMode::Externalized(55)].into(),
        ..ChildAuthority::default()
    };
    assert!(matches!(
        store
            .drive_one(lease, &mut authority, 1_003)
            .expect("original ambiguity"),
        CoordinatorDriveOutcomeV1::Unknown { evidence_digest } if evidence_digest == digest(53)
    ));
    assert!(matches!(
        store
            .reconcile_current_child_one(lease, &mut authority, 1_004)
            .expect("first reconciliation remains ambiguous"),
        CoordinatorDriveOutcomeV1::Unknown { .. }
    ));
    let progress = match store
        .reconcile_current_child_one(lease, &mut authority, 1_005)
        .expect("second reconciliation resolves exact child")
    {
        CoordinatorDriveOutcomeV1::PartialProgress(progress) => progress,
        other => panic!("unexpected resolution: {other:?}"),
    };
    assert_eq!(
        authority.calls.len(),
        1,
        "original dispatch must not replay"
    );
    assert_eq!(authority.reconciliations.len(), 2);
    assert_ne!(authority.reconciliations[0], authority.reconciliations[1]);
    let exposure = progress.exposure.expect("resolved first exposure");
    assert_eq!(exposure.observed_at_unix_ms, 1_005);

    drop(store);
    let mut reopened = open_store(&path);
    let replayed = match reopened
        .current_custody_progress(lease, 1_100)
        .expect("replay at later clock")
    {
        CoordinatorDriveOutcomeV1::PartialProgress(value) => value,
        other => panic!("unexpected replay: {other:?}"),
    };
    assert_eq!(replayed, progress);
    assert_eq!(
        replayed
            .exposure
            .expect("replayed exposure")
            .observed_at_unix_ms,
        1_005
    );
}

#[test]
fn one_reconciliation_attempt_cannot_accept_two_outcomes() {
    let (_root, path) = state_path();
    let mut store = create_store(&path);
    let (plan_id, lease) = install(&mut store, plan(SettlementActionV1::Funding, 1, 36));
    let mut authority = ChildAuthority {
        dispatch: [DispatchMode::Unknown(56)].into(),
        ..ChildAuthority::default()
    };
    store
        .drive_one(lease, &mut authority, 1_003)
        .expect("original ambiguity");
    let first = store
        .prepare_current_reconciliation(lease, 1_004)
        .expect("first token");
    let duplicate = store
        .prepare_current_reconciliation(lease, 1_004)
        .expect("duplicate token");
    assert_eq!(
        first.request().reconciliation_attempt_id,
        duplicate.request().reconciliation_attempt_id
    );
    let conflicting_receipt = ChildAuthority::receipt(&duplicate.request().dispatch, 57);
    store
        .complete_current_reconciliation(
            lease,
            first,
            ChildReconciliationOutcomeV1::Unknown {
                evidence_digest: digest(58),
            },
            1_005,
        )
        .expect("first exact result");
    assert_eq!(
        store
            .complete_current_reconciliation(
                lease,
                duplicate,
                ChildReconciliationOutcomeV1::Externalized(conflicting_receipt),
                1_006,
            )
            .unwrap_err(),
        CoordinatorErrorV1::IdempotencyConflict
    );
    assert_eq!(
        store.load_plan(plan_id).expect("failed-closed view").stage,
        AggregateStageV1::FailedClosed
    );
}

#[test]
fn prepared_reconciliation_is_superseded_after_expiry_and_new_fence_restart() {
    let (_root, path) = state_path();
    let (plan_id, old_lease, stale_before_supersession, stale_after_supersession, old_attempt_id) = {
        let mut store = create_store(&path);
        let (plan_id, lease) = install(&mut store, plan(SettlementActionV1::Funding, 1, 40));
        let mut authority = ChildAuthority {
            dispatch: [DispatchMode::Unknown(66)].into(),
            ..ChildAuthority::default()
        };
        store
            .drive_one(lease, &mut authority, 1_003)
            .expect("original ambiguity");
        let pending = store
            .prepare_current_reconciliation(lease, 1_004)
            .expect("durable old-fence reconciliation");
        let duplicate = store
            .prepare_current_reconciliation(lease, 1_004)
            .expect("same-fence idempotent preparation");
        let attempt_id = pending.request().reconciliation_attempt_id;
        assert_eq!(duplicate.request().reconciliation_attempt_id, attempt_id);
        (plan_id, lease, pending, duplicate, attempt_id)
    };

    let mut reopened = open_store(&path);
    let new_lease = reopened
        .acquire_takeover_lease(plan_id, OWNER_B, 2, digest(67), 1_600, 500)
        .expect("expired lease takeover")
        .lease();
    assert!(new_lease.route_fencing_epoch() > old_lease.route_fencing_epoch());
    assert!(new_lease.coordinator_fencing_epoch() > old_lease.coordinator_fencing_epoch());
    assert_eq!(
        reopened
            .complete_takeover_reconciliation(
                new_lease,
                stale_before_supersession,
                ChildReconciliationOutcomeV1::Unknown {
                    evidence_digest: digest(68),
                },
                1_601,
            )
            .unwrap_err(),
        CoordinatorErrorV1::StaleFencing,
        "a token prepared under an old fence must not complete under the new lease"
    );
    let replacement = reopened
        .prepare_takeover_reconciliation(new_lease, 1_601)
        .expect("supersede stale prepared reconciliation");
    let replacement_attempt_id = replacement.request().reconciliation_attempt_id;
    assert_ne!(replacement_attempt_id, old_attempt_id);
    assert_eq!(
        replacement.request().current_route_fencing_epoch,
        new_lease.route_fencing_epoch()
    );
    assert_eq!(
        replacement.request().current_coordinator_fencing_epoch,
        new_lease.coordinator_fencing_epoch()
    );
    let replacement_duplicate = reopened
        .prepare_takeover_reconciliation(new_lease, 1_601)
        .expect("replacement preparation is idempotent");
    assert_eq!(
        replacement_duplicate.request().reconciliation_attempt_id,
        replacement_attempt_id
    );

    assert_eq!(
        reopened
            .complete_takeover_reconciliation(
                new_lease,
                stale_after_supersession,
                ChildReconciliationOutcomeV1::Unknown {
                    evidence_digest: digest(68),
                },
                1_602,
            )
            .unwrap_err(),
        CoordinatorErrorV1::StaleFencing
    );
    assert!(matches!(
        reopened
            .takeover_status(new_lease, 1_602)
            .expect("stale completion cannot resolve ambiguity"),
        CustodyTakeoverStatusV1::Unknown { .. }
    ));

    let mut authority = ChildAuthority {
        reconcile: [ReconcileMode::NotExternalized(69)].into(),
        ..ChildAuthority::default()
    };
    assert!(matches!(
        reopened
            .reconcile_takeover_one(new_lease, &mut authority, 1_603)
            .expect("only replacement authorization is sent"),
        CustodyTakeoverStatusV1::NothingExternalized { .. }
    ));
    assert_eq!(authority.reconciliations, [replacement_attempt_id]);
    drop(reopened);

    let reopened = open_store(&path);
    assert!(matches!(
        reopened
            .takeover_status(new_lease, 1_604)
            .expect("append-only supersession survives restart"),
        CustodyTakeoverStatusV1::NothingExternalized { .. }
    ));
}

#[test]
fn prepared_reconciliation_crash_helper() {
    let Some(path) = std::env::var_os(RECONCILIATION_CRASH_PATH) else {
        return;
    };
    let mut store = open_store(Path::new(&path));
    let plan_id = store
        .load_plan_for_effect(digest(43))
        .expect("crash fixture plan")
        .view()
        .plan_id;
    let lease = store
        .acquire_lease(plan_id, OWNER_A, 1, 1_004, 498)
        .expect("resume exact live lease in crash helper")
        .lease();
    store
        .prepare_current_reconciliation(lease, 1_004)
        .expect("persist reconciliation before hard exit");
    std::process::exit(RECONCILIATION_CRASH_EXIT);
}

#[test]
fn prepared_reconciliation_survives_hard_exit_and_is_superseded_after_takeover() {
    let (_root, path) = state_path();
    let plan_id = {
        let mut store = create_store(&path);
        let (plan_id, lease) = install(&mut store, plan(SettlementActionV1::Funding, 1, 43));
        let mut authority = ChildAuthority {
            dispatch: [DispatchMode::Unknown(74)].into(),
            ..ChildAuthority::default()
        };
        store
            .drive_one(lease, &mut authority, 1_003)
            .expect("original ambiguity before helper crash");
        plan_id
    };

    let status = Command::new(std::env::current_exe().expect("current test binary"))
        .arg("--exact")
        .arg("prepared_reconciliation_crash_helper")
        .arg("--nocapture")
        .env(RECONCILIATION_CRASH_PATH, &path)
        .status()
        .expect("run reconciliation crash helper");
    assert_eq!(status.code(), Some(RECONCILIATION_CRASH_EXIT));

    let mut reopened = open_store(&path);
    let takeover = reopened
        .acquire_takeover_lease(plan_id, OWNER_B, 2, digest(75), 1_600, 500)
        .expect("take over after hard process exit")
        .lease();
    let replacement = reopened
        .prepare_takeover_reconciliation(takeover, 1_601)
        .expect("append-only supersession after hard exit");
    let replacement_attempt_id = replacement.request().reconciliation_attempt_id;
    let duplicate = reopened
        .prepare_takeover_reconciliation(takeover, 1_601)
        .expect("replacement survives exact replay");
    assert_eq!(
        duplicate.request().reconciliation_attempt_id,
        replacement_attempt_id
    );

    let mut authority = ChildAuthority {
        reconcile: [ReconcileMode::NotExternalized(76)].into(),
        ..ChildAuthority::default()
    };
    assert!(matches!(
        reopened
            .reconcile_takeover_one(takeover, &mut authority, 1_602)
            .expect("resolve only through replacement authorization"),
        CustodyTakeoverStatusV1::NothingExternalized { .. }
    ));
    assert_eq!(authority.reconciliations, [replacement_attempt_id]);
    drop(reopened);

    let reopened = open_store(&path);
    assert!(matches!(
        reopened
            .takeover_status(takeover, 1_603)
            .expect("terminal reconciliation survives second restart"),
        CustodyTakeoverStatusV1::NothingExternalized { .. }
    ));
    drop(reopened);

    let connection = rusqlite::Connection::open(&path).expect("raw reconciliation audit");
    let mut statement = connection
        .prepare(
            "SELECT outcome_tag FROM child_reconciliation_calls
             WHERE plan_id=?1 ORDER BY sequence_be",
        )
        .expect("query append-only outcomes");
    let tags: Vec<i64> = statement
        .query_map(rusqlite::params![plan_id.as_slice()], |row| row.get(0))
        .expect("map append-only outcomes")
        .collect::<rusqlite::Result<_>>()
        .expect("collect append-only outcomes");
    assert_eq!(tags, [4, 1]);
}

#[test]
fn unknown_materialization_cannot_be_tampered_into_planned() {
    let (_root, path) = state_path();
    let plan_id = {
        let mut store = create_store(&path);
        let (plan_id, lease) = install(&mut store, plan(SettlementActionV1::Funding, 1, 41));
        let mut authority = ChildAuthority {
            dispatch: [DispatchMode::Unknown(70)].into(),
            ..ChildAuthority::default()
        };
        store
            .drive_one(lease, &mut authority, 1_003)
            .expect("durable unknown");
        plan_id
    };
    let connection = rusqlite::Connection::open(&path).expect("raw connection");
    connection
        .execute(
            "UPDATE settlement_children SET stage_tag=1,pending_attempt_id=NULL,
             pending_call_digest=NULL,last_ambiguity_evidence=NULL,
             reconciliation_attempt_id=NULL,reconciliation_record_digest=NULL
             WHERE plan_id=?1 AND child_index=0",
            rusqlite::params![plan_id.as_slice()],
        )
        .expect("tamper Unknown into Planned");
    drop(connection);
    assert_eq!(
        DurableSettlementCoordinatorV1::open_existing(&path, COORDINATOR_ID, AUTHORITY_ID)
            .unwrap_err(),
        CoordinatorErrorV1::CorruptState
    );
}

#[test]
fn proven_not_externalized_materialization_is_bound_to_latest_evidence() {
    let (_root, path) = state_path();
    let plan_id = {
        let mut store = create_store(&path);
        let (plan_id, lease) = install(&mut store, plan(SettlementActionV1::Funding, 1, 42));
        let mut authority = ChildAuthority {
            dispatch: [DispatchMode::Unknown(71)].into(),
            reconcile: [ReconcileMode::NotExternalized(72)].into(),
            ..ChildAuthority::default()
        };
        store
            .drive_one(lease, &mut authority, 1_003)
            .expect("durable unknown");
        store
            .reconcile_current_child_one(lease, &mut authority, 1_004)
            .expect("proven not externalized");
        plan_id
    };
    let connection = rusqlite::Connection::open(&path).expect("raw connection");
    connection
        .execute(
            "UPDATE settlement_children SET last_ambiguity_evidence=?1
             WHERE plan_id=?2 AND child_index=0",
            rusqlite::params![digest(73).as_slice(), plan_id.as_slice()],
        )
        .expect("tamper terminal reconciliation evidence");
    drop(connection);
    assert_eq!(
        DurableSettlementCoordinatorV1::open_existing(&path, COORDINATOR_ID, AUTHORITY_ID)
            .unwrap_err(),
        CoordinatorErrorV1::CorruptState
    );
}

#[test]
fn reconciliation_resolution_does_not_rewrite_original_unknown_outcome() {
    let (_root, path) = state_path();
    let mut store = create_store(&path);
    let (_plan_id, lease) = install(&mut store, plan(SettlementActionV1::Funding, 1, 39));
    let first = store
        .prepare_next_child_call(lease, 1_003)
        .expect("original token");
    let exact_replay = store
        .prepare_next_child_call(lease, 1_003)
        .expect("duplicate original token");
    store
        .complete_child_call(
            lease,
            first,
            ChildExecutionOutcomeV1::Unknown {
                evidence_digest: digest(62),
            },
            1_004,
        )
        .expect("immutable original ambiguity");
    let mut forbidden_replay = ChildAuthority {
        dispatch: [DispatchMode::Externalized(64)].into(),
        ..ChildAuthority::default()
    };
    assert_eq!(
        store
            .drive_one(lease, &mut forbidden_replay, 1_005)
            .unwrap_err(),
        CoordinatorErrorV1::ReconciliationRequired
    );
    assert!(
        forbidden_replay.calls.is_empty(),
        "an ambiguous original dispatch must never be replayed"
    );
    let mut authority = ChildAuthority {
        reconcile: [ReconcileMode::Externalized(63)].into(),
        ..ChildAuthority::default()
    };
    assert!(matches!(
        store
            .reconcile_current_child_one(lease, &mut authority, 1_006)
            .expect("reconciled externalization"),
        CoordinatorDriveOutcomeV1::PartialProgress(_)
    ));
    assert!(matches!(
        store
            .complete_child_call(
                lease,
                exact_replay,
                ChildExecutionOutcomeV1::Unknown {
                    evidence_digest: digest(62),
                },
                1_007,
            )
            .expect("exact replay remains original Unknown"),
        CoordinatorDriveOutcomeV1::Unknown { evidence_digest } if evidence_digest == digest(62)
    ));
    assert!(matches!(
        store
            .current_custody_progress(lease, 1_007)
            .expect("reconciliation progress remains committed"),
        CoordinatorDriveOutcomeV1::PartialProgress(progress) if progress.completed_prefix == 1
    ));
}

#[test]
fn first_exposure_timestamp_tamper_fails_reopen_audit() {
    let (_root, path) = state_path();
    let plan_id = {
        let mut store = create_store(&path);
        let (plan_id, lease) = install(&mut store, plan(SettlementActionV1::Claim, 1, 37));
        let mut authority = ChildAuthority {
            dispatch: [DispatchMode::Externalized(59)].into(),
            ..ChildAuthority::default()
        };
        store
            .drive_one(lease, &mut authority, 1_003)
            .expect("first exposure");
        plan_id
    };
    let connection = rusqlite::Connection::open(&path).expect("raw connection");
    connection
        .execute(
            "UPDATE settlement_plans SET first_exposure_observed_at_be=?1 WHERE plan_id=?2",
            rusqlite::params![1_004u64.to_be_bytes().as_slice(), plan_id.as_slice()],
        )
        .expect("tamper exposure timestamp");
    drop(connection);
    assert_eq!(
        DurableSettlementCoordinatorV1::open_existing(&path, COORDINATOR_ID, AUTHORITY_ID)
            .unwrap_err(),
        CoordinatorErrorV1::CorruptState
    );
}

#[test]
fn reconciliation_sequence_tamper_fails_reopen_audit() {
    let (_root, path) = state_path();
    let reconciliation_attempt_id = {
        let mut store = create_store(&path);
        let (_plan_id, lease) = install(&mut store, plan(SettlementActionV1::Funding, 1, 38));
        let mut authority = ChildAuthority {
            dispatch: [DispatchMode::Unknown(60)].into(),
            reconcile: [ReconcileMode::Unknown(61)].into(),
            ..ChildAuthority::default()
        };
        store
            .drive_one(lease, &mut authority, 1_003)
            .expect("original ambiguity");
        store
            .reconcile_current_child_one(lease, &mut authority, 1_004)
            .expect("reconciliation ambiguity");
        authority.reconciliations[0]
    };
    let connection = rusqlite::Connection::open(&path).expect("raw connection");
    connection
        .execute(
            "UPDATE child_reconciliation_calls SET sequence_be=?1 WHERE reconciliation_attempt_id=?2",
            rusqlite::params![2u64.to_be_bytes().as_slice(), reconciliation_attempt_id.as_slice()],
        )
        .expect("tamper reconciliation sequence");
    drop(connection);
    assert_eq!(
        DurableSettlementCoordinatorV1::open_existing(&path, COORDINATOR_ID, AUTHORITY_ID)
            .unwrap_err(),
        CoordinatorErrorV1::CorruptState
    );
}

#[test]
fn retryable_call_is_persisted_before_a_new_attempt() {
    let (_root, path) = state_path();
    let mut store = create_store(&path);
    let (_plan_id, lease) = install(&mut store, plan(SettlementActionV1::Funding, 1, 24));
    let mut authority = ChildAuthority {
        dispatch: [DispatchMode::Retryable(60), DispatchMode::Externalized(61)].into(),
        ..ChildAuthority::default()
    };
    assert!(matches!(
        store.drive_one(lease, &mut authority, 1_003).expect("retryable"),
        CoordinatorDriveOutcomeV1::Waiting { evidence_digest } if evidence_digest == digest(60)
    ));
    let progress = match store
        .drive_one(lease, &mut authority, 1_004)
        .expect("retry")
    {
        CoordinatorDriveOutcomeV1::PartialProgress(progress) => progress,
        other => panic!("unexpected: {other:?}"),
    };
    assert_eq!(progress.completed_prefix, 1);
    assert_eq!(authority.calls.len(), 2);
}

#[test]
fn authority_refusal_after_persist_resumes_same_attempt_after_restart() {
    let (_root, path) = state_path();
    let lease = {
        let mut store = create_store(&path);
        let (_plan_id, lease) = install(&mut store, plan(SettlementActionV1::Funding, 1, 30));
        let mut unavailable = ChildAuthority::default();
        assert_eq!(
            store.drive_one(lease, &mut unavailable, 1_003).unwrap_err(),
            CoordinatorErrorV1::ChildAuthorityRefused
        );
        assert_eq!(unavailable.calls.len(), 1);
        lease
    };
    let mut store = open_store(&path);
    let mut resumed = ChildAuthority {
        dispatch: [DispatchMode::Externalized(62)].into(),
        ..ChildAuthority::default()
    };
    let progress = match store
        .drive_one(lease, &mut resumed, 1_004)
        .expect("same pending attempt")
    {
        CoordinatorDriveOutcomeV1::PartialProgress(progress) => progress,
        other => panic!("unexpected: {other:?}"),
    };
    assert_eq!(progress.completed_prefix, 1);
    assert_eq!(resumed.calls.len(), 1);
}

#[test]
fn pending_observation_survives_takeover_and_aggregate_refence() {
    let (_root, path) = state_path();
    let original = plan(SettlementActionV1::Funding, 1, 31);
    let mut store = create_store(&path);
    let (plan_id, lease) = install(&mut store, original.clone());
    let mut authority = ChildAuthority {
        dispatch: [
            DispatchMode::Externalized(63),
            DispatchMode::Externalized(64),
        ]
        .into(),
        ..ChildAuthority::default()
    };
    store
        .drive_one(lease, &mut authority, 1_003)
        .expect("first");
    store
        .drive_one(lease, &mut authority, 1_004)
        .expect("second");
    let mut unavailable = Observer::default();
    assert_eq!(
        store
            .observe_child_once(lease, 0, &mut unavailable, 1_005)
            .unwrap_err(),
        CoordinatorErrorV1::ChildObserverRefused
    );
    assert_eq!(unavailable.requests.len(), 1);
    let original_request = unavailable.requests[0];
    assert_eq!(original_request.route_id, original.bindings().route_id);
    assert_eq!(original_request.effect_id, original.bindings().effect_id);
    assert_eq!(
        original_request.settlement_id,
        original.bindings().settlement_id
    );
    assert_eq!(original_request.leg, original.bindings().leg);
    assert_eq!(original_request.action, original.bindings().action);
    assert_eq!(
        original_request.semantic_digest,
        original.bindings().semantic_digest
    );
    assert_eq!(
        original_request.exposure,
        original.materialized_children().expect("materialized")[0].exposure
    );
    assert_eq!(
        original_request.intent_digest,
        original.materialized_children().expect("materialized")[0].intent_digest
    );
    assert_eq!(
        original_request.custody_digest,
        original.materialized_children().expect("materialized")[0].custody_digest
    );

    let takeover = store
        .acquire_takeover_lease(plan_id, OWNER_B, 2, digest(73), 1_006, 500)
        .expect("takeover")
        .lease();
    let receipt = match store.takeover_status(takeover, 1_007).expect("aggregate") {
        CustodyTakeoverStatusV1::AggregateExternalized(receipt) => receipt,
        other => panic!("unexpected: {other:?}"),
    };
    store
        .refence_plan(
            takeover,
            replacement(&original, 2, 82),
            receipt.child_receipts_digest,
            &mut PlanAuthority::new(),
            1_008,
        )
        .expect("aggregate refence");
    let mut observer = Observer {
        outcomes: [ChildObservationOutcomeV1::Final {
            evidence_digest: digest(84),
        }]
        .into(),
        ..Observer::default()
    };
    assert!(matches!(
        store
            .observe_child_once(takeover, 0, &mut observer, 1_009)
            .expect("resume historical observation"),
        CoordinatorObservationOutcomeV1::ChildFinalized { child_index: 0, .. }
    ));
    assert_eq!(observer.requests[0], original_request);
}

#[test]
fn pending_observation_rejects_cross_route_request_digest_transplant() {
    let (_root, path) = state_path();
    let (second_lease, first_attempt, second_attempt) = {
        let mut store = create_store(&path);
        let (_first_plan_id, first_lease) =
            install(&mut store, plan(SettlementActionV1::Funding, 1, 132));
        let mut first_authority = ChildAuthority {
            dispatch: [
                DispatchMode::Externalized(133),
                DispatchMode::Externalized(134),
            ]
            .into(),
            ..ChildAuthority::default()
        };
        store
            .drive_one(first_lease, &mut first_authority, 1_003)
            .expect("first route child zero");
        store
            .drive_one(first_lease, &mut first_authority, 1_004)
            .expect("first route child one");

        let second_base = plan(SettlementActionV1::Funding, 1, 135);
        let mut second_bindings = second_base.bindings().clone();
        second_bindings.route_id = digest(136);
        second_bindings.settlement_id = digest(137);
        let second_plan = CompositeSettlementPlanV1::new(
            second_bindings,
            second_base.secret_requirement(),
            second_base.preexisting_secret_evidence_digest(),
            second_base
                .materialized_children()
                .expect("materialized")
                .clone(),
        )
        .expect("second route plan");
        let second_view = store
            .install_plan(&mut PlanAuthority::new(), second_plan, 1_004)
            .expect("install second route");
        let second_plan_id = second_view.plan_id;
        let second_lease = store
            .acquire_lease(second_plan_id, OWNER_A, 1, 1_004, 500)
            .expect("second route lease")
            .lease();
        assert_ne!(first_lease.plan_id(), second_plan_id);
        let mut second_authority = ChildAuthority {
            dispatch: [
                DispatchMode::Externalized(138),
                DispatchMode::Externalized(139),
            ]
            .into(),
            ..ChildAuthority::default()
        };
        store
            .drive_one(second_lease, &mut second_authority, 1_005)
            .expect("second route child zero");
        store
            .drive_one(second_lease, &mut second_authority, 1_006)
            .expect("second route child one");

        let mut first_observer = Observer::default();
        assert_eq!(
            store
                .observe_child_once(first_lease, 0, &mut first_observer, 1_007)
                .unwrap_err(),
            CoordinatorErrorV1::ChildObserverRefused
        );
        let mut second_observer = Observer::default();
        assert_eq!(
            store
                .observe_child_once(second_lease, 0, &mut second_observer, 1_008)
                .unwrap_err(),
            CoordinatorErrorV1::ChildObserverRefused
        );
        assert_ne!(
            first_observer.requests[0].route_id,
            second_observer.requests[0].route_id
        );
        assert_ne!(
            first_observer.requests[0].settlement_id,
            second_observer.requests[0].settlement_id
        );
        (
            second_lease,
            first_observer.requests[0].observation_attempt_id,
            second_observer.requests[0].observation_attempt_id,
        )
    };

    let connection = rusqlite::Connection::open(&path).expect("raw connection");
    let first_request_digest: Vec<u8> = connection
        .query_row(
            "SELECT request_digest FROM observation_calls WHERE observation_attempt_id=?1",
            rusqlite::params![first_attempt.as_slice()],
            |row| row.get(0),
        )
        .expect("first request digest");
    connection
        .execute(
            "UPDATE observation_calls SET request_digest=?1 WHERE observation_attempt_id=?2",
            rusqlite::params![first_request_digest, second_attempt.as_slice()],
        )
        .expect("transplant request digest");
    drop(connection);

    match DurableSettlementCoordinatorV1::open_existing(&path, COORDINATOR_ID, AUTHORITY_ID) {
        Err(error) => assert_eq!(error, CoordinatorErrorV1::CorruptState),
        Ok(mut store) => {
            let mut observer = Observer::default();
            assert_eq!(
                store
                    .observe_child_once(second_lease, 0, &mut observer, 1_009)
                    .unwrap_err(),
                CoordinatorErrorV1::CorruptState
            );
            assert!(observer.requests.is_empty());
        }
    }
}

#[test]
fn indexed_restart_lookup_supports_late_refence_without_memory_map() {
    let (_root, path) = state_path();
    let original = plan(SettlementActionV1::Funding, 1, 34);
    let (plan_id, old_effect, aggregate_action, aggregate_custody) = {
        let mut store = create_store(&path);
        let (plan_id, lease) = install(&mut store, original);
        let initial = store.load_plan(plan_id).expect("initial view");
        let mut first = ChildAuthority {
            dispatch: [DispatchMode::Externalized(65)].into(),
            ..ChildAuthority::default()
        };
        store.drive_one(lease, &mut first, 1_003).expect("partial");
        (
            plan_id,
            initial.effect_id,
            initial.aggregate_action_id,
            initial.aggregate_custody_digest,
        )
    };

    let mut store = open_store(&path);
    let by_effect = store
        .load_plan_for_effect(old_effect)
        .expect("current old effect during takeover");
    assert_eq!(by_effect.view().plan_id, plan_id);
    let by_aggregate = store
        .load_plan_for_aggregate(aggregate_action, aggregate_custody)
        .expect("stable aggregate lookup");
    assert_eq!(by_aggregate, by_effect);
    assert_eq!(
        store
            .load_plan_for_aggregate(aggregate_action, digest(222))
            .unwrap_err(),
        CoordinatorErrorV1::IdempotencyConflict
    );
    assert_eq!(
        store
            .load_plan_for_aggregate(digest(221), digest(222))
            .unwrap_err(),
        CoordinatorErrorV1::PlanNotFound
    );

    let takeover = store
        .acquire_takeover_lease(plan_id, OWNER_B, 2, digest(75), 1_004, 500)
        .expect("takeover")
        .lease();
    let progress = match store.takeover_status(takeover, 1_005).expect("safe prefix") {
        CustodyTakeoverStatusV1::SafeToResumeCustody(progress) => progress,
        other => panic!("unexpected: {other:?}"),
    };
    let replacement = replacement(by_aggregate.plan(), 2, 85);
    store
        .refence_plan(
            takeover,
            replacement,
            progress.progress_evidence_digest,
            &mut PlanAuthority::new(),
            1_006,
        )
        .expect("late refence");
    assert_eq!(
        store.load_plan_for_effect(old_effect).unwrap_err(),
        CoordinatorErrorV1::StaleFencing
    );
    let current = store
        .load_plan_for_effect(digest(85))
        .expect("new effect lookup");
    assert_eq!(current.view().aggregate_action_id, aggregate_action);
    assert_eq!(current.view().aggregate_custody_digest, aggregate_custody);
    let stable_again = store
        .load_plan_for_aggregate(aggregate_action, aggregate_custody)
        .expect("stable lookup after refence");
    assert_eq!(stable_again, current);

    let recycled_base = plan(SettlementActionV1::Funding, 1, 34);
    let mut recycled_bindings = recycled_base.bindings().clone();
    recycled_bindings.route_id = digest(220);
    let recycled_effect = CompositeSettlementPlanV1::new(
        recycled_bindings,
        recycled_base.secret_requirement(),
        recycled_base.preexisting_secret_evidence_digest(),
        recycled_base
            .materialized_children()
            .expect("materialized")
            .clone(),
    )
    .expect("otherwise valid recycled effect");
    assert_eq!(
        store
            .install_plan(&mut PlanAuthority::new(), recycled_effect, 1_007)
            .unwrap_err(),
        CoordinatorErrorV1::IdempotencyConflict
    );
    assert_eq!(
        store
            .load_plan(plan_id)
            .expect("failed-closed original")
            .stage,
        AggregateStageV1::FailedClosed
    );
}

#[test]
fn aggregate_action_lookup_resumes_observation_after_restart_and_is_unique() {
    let (_root, path) = state_path();
    let (plan_id, aggregate_action, second_plan_id, second_action) = {
        let mut store = create_store(&path);
        let (plan_id, lease) = install(&mut store, plan(SettlementActionV1::Funding, 1, 88));
        let mut authority = ChildAuthority {
            dispatch: [
                DispatchMode::Externalized(60),
                DispatchMode::Externalized(61),
            ]
            .into(),
            ..ChildAuthority::default()
        };
        store
            .drive_one(lease, &mut authority, 1_003)
            .expect("first child");
        let aggregate = store
            .drive_one(lease, &mut authority, 1_004)
            .expect("aggregate");
        let aggregate_action = match aggregate {
            CoordinatorDriveOutcomeV1::AggregateExternalized(receipt) => {
                receipt.aggregate_action_id
            }
            other => panic!("unexpected: {other:?}"),
        };

        let second_base = plan(SettlementActionV1::Funding, 1, 89);
        let mut second_bindings = second_base.bindings().clone();
        second_bindings.route_id = digest(219);
        let second = CompositeSettlementPlanV1::new(
            second_bindings,
            second_base.secret_requirement(),
            second_base.preexisting_secret_evidence_digest(),
            second_base
                .materialized_children()
                .expect("materialized")
                .clone(),
        )
        .expect("second plan");
        let second_view = store
            .install_plan(&mut PlanAuthority::new(), second, 1_005)
            .expect("install second");
        (
            plan_id,
            aggregate_action,
            second_view.plan_id,
            second_view.aggregate_action_id,
        )
    };

    let mut store = open_store(&path);
    let restored = store
        .load_plan_for_aggregate_action(aggregate_action)
        .expect("action-only restart lookup");
    assert_eq!(restored.view().plan_id, plan_id);
    assert_eq!(
        store
            .load_plan_for_aggregate_action(digest(218))
            .unwrap_err(),
        CoordinatorErrorV1::PlanNotFound
    );
    let lease = store
        .acquire_lease(plan_id, OWNER_A, 1, 1_006, 500)
        .expect("resume lease")
        .lease();
    let mut observer = Observer {
        outcomes: [
            ChildObservationOutcomeV1::Final {
                evidence_digest: digest(62),
            },
            ChildObservationOutcomeV1::Final {
                evidence_digest: digest(63),
            },
        ]
        .into(),
        ..Observer::default()
    };
    store
        .observe_child_once(lease, 0, &mut observer, 1_007)
        .expect("first finality after restart");
    assert!(matches!(
        store
            .observe_child_once(lease, 1, &mut observer, 1_008)
            .expect("aggregate finality after restart"),
        CoordinatorObservationOutcomeV1::AggregateFinal(_)
    ));
    drop(store);

    let connection = rusqlite::Connection::open(&path).expect("raw connection");
    assert!(connection
        .execute(
            "UPDATE settlement_plans SET aggregate_action_id=?1 WHERE plan_id=?2",
            rusqlite::params![aggregate_action.as_slice(), second_plan_id.as_slice()],
        )
        .is_err());
    drop(connection);
    let store = open_store(&path);
    assert_eq!(
        store
            .load_plan_for_aggregate_action(aggregate_action)
            .expect("first still unique")
            .view()
            .plan_id,
        plan_id
    );
    assert_eq!(
        store
            .load_plan_for_aggregate_action(second_action)
            .expect("second still unique")
            .view()
            .plan_id,
        second_plan_id
    );
}

#[test]
fn aggregate_finality_reorg_and_refinality_require_both_children() {
    let (_root, path) = state_path();
    let mut store = create_store(&path);
    let (plan_id, lease) = install(&mut store, plan(SettlementActionV1::Funding, 1, 25));
    let mut authority = ChildAuthority {
        dispatch: [
            DispatchMode::Externalized(70),
            DispatchMode::Externalized(71),
        ]
        .into(),
        ..ChildAuthority::default()
    };
    store
        .drive_one(lease, &mut authority, 1_003)
        .expect("first");
    store
        .drive_one(lease, &mut authority, 1_004)
        .expect("second");

    let mut observer = Observer {
        outcomes: [
            ChildObservationOutcomeV1::Final {
                evidence_digest: digest(80),
            },
            ChildObservationOutcomeV1::Final {
                evidence_digest: digest(81),
            },
            ChildObservationOutcomeV1::FinalityInvalidated {
                prior_finality_evidence_digest: digest(80),
                reorg_evidence_digest: digest(82),
            },
            ChildObservationOutcomeV1::Final {
                evidence_digest: digest(83),
            },
        ]
        .into(),
        ..Observer::default()
    };
    assert!(matches!(
        store
            .observe_child_once(lease, 0, &mut observer, 1_005)
            .expect("first final"),
        CoordinatorObservationOutcomeV1::ChildFinalized { child_index: 0, .. }
    ));
    assert_eq!(
        store.load_plan(plan_id).expect("view").stage,
        AggregateStageV1::Externalized
    );
    assert!(matches!(
        store
            .observe_child_once(lease, 1, &mut observer, 1_006)
            .expect("aggregate final"),
        CoordinatorObservationOutcomeV1::AggregateFinal(_)
    ));
    assert_eq!(
        store.load_plan(plan_id).expect("view").stage,
        AggregateStageV1::Final
    );
    assert!(matches!(
        store
            .observe_child_once(lease, 0, &mut observer, 1_007)
            .expect("reorg"),
        CoordinatorObservationOutcomeV1::AggregateInvalidated(_)
    ));
    assert_eq!(
        store.load_plan(plan_id).expect("view").stage,
        AggregateStageV1::FinalityInvalidated
    );
    assert!(matches!(
        store
            .observe_child_once(lease, 0, &mut observer, 1_008)
            .expect("refinal"),
        CoordinatorObservationOutcomeV1::AggregateFinal(_)
    ));
    assert_eq!(
        store.load_plan(plan_id).expect("view").stage,
        AggregateStageV1::Final
    );
    assert_eq!(observer.requests[0].profile_digest, digest(9));
    assert_eq!(observer.requests[1].profile_digest, digest(7));
}

#[test]
fn aggregate_receipt_and_finality_commitment_tamper_fail_reopen_audit() {
    let (_root, path) = state_path();
    let plan_id = {
        let mut store = create_store(&path);
        let (plan_id, lease) = install(&mut store, plan(SettlementActionV1::Funding, 1, 86));
        let mut authority = ChildAuthority {
            dispatch: [
                DispatchMode::Externalized(70),
                DispatchMode::Externalized(71),
            ]
            .into(),
            ..ChildAuthority::default()
        };
        store
            .drive_one(lease, &mut authority, 1_003)
            .expect("first child");
        store
            .drive_one(lease, &mut authority, 1_004)
            .expect("aggregate externalized");
        plan_id
    };
    let connection = rusqlite::Connection::open(&path).expect("raw connection");
    connection
        .execute(
            "UPDATE settlement_plans SET aggregate_receipt_digest=?1 WHERE plan_id=?2",
            rusqlite::params![digest(211).as_slice(), plan_id.as_slice()],
        )
        .expect("tamper aggregate receipt");
    drop(connection);
    assert_eq!(
        DurableSettlementCoordinatorV1::open_existing(&path, COORDINATOR_ID, AUTHORITY_ID)
            .unwrap_err(),
        CoordinatorErrorV1::CorruptState
    );

    let (_root, path) = state_path();
    let plan_id = {
        let mut store = create_store(&path);
        let (plan_id, lease) = install(&mut store, plan(SettlementActionV1::Funding, 1, 87));
        let mut authority = ChildAuthority {
            dispatch: [
                DispatchMode::Externalized(72),
                DispatchMode::Externalized(73),
            ]
            .into(),
            ..ChildAuthority::default()
        };
        store
            .drive_one(lease, &mut authority, 1_003)
            .expect("first child");
        store
            .drive_one(lease, &mut authority, 1_004)
            .expect("aggregate externalized");
        let mut observer = Observer {
            outcomes: [
                ChildObservationOutcomeV1::Final {
                    evidence_digest: digest(80),
                },
                ChildObservationOutcomeV1::Final {
                    evidence_digest: digest(81),
                },
            ]
            .into(),
            ..Observer::default()
        };
        store
            .observe_child_once(lease, 0, &mut observer, 1_005)
            .expect("first finality");
        store
            .observe_child_once(lease, 1, &mut observer, 1_006)
            .expect("aggregate finality");
        plan_id
    };
    let connection = rusqlite::Connection::open(&path).expect("raw connection");
    connection
        .execute(
            "UPDATE settlement_plans SET aggregate_finality_digest=?1 WHERE plan_id=?2",
            rusqlite::params![digest(212).as_slice(), plan_id.as_slice()],
        )
        .expect("tamper aggregate finality");
    drop(connection);
    assert_eq!(
        DurableSettlementCoordinatorV1::open_existing(&path, COORDINATOR_ID, AUTHORITY_ID)
            .unwrap_err(),
        CoordinatorErrorV1::CorruptState
    );
}

#[test]
fn duplicate_plan_is_idempotent_and_conflicting_effect_fails_closed() {
    let (_root, path) = state_path();
    let mut store = create_store(&path);
    let original = plan(SettlementActionV1::Funding, 1, 26);
    let first = store
        .install_plan(&mut PlanAuthority::new(), original.clone(), 1_001)
        .expect("first");
    let duplicate = store
        .install_plan(&mut PlanAuthority::new(), original.clone(), 1_002)
        .expect("duplicate");
    assert_eq!(first, duplicate);

    let mut children = original
        .materialized_children()
        .expect("materialized")
        .clone();
    children[1].intent_digest = digest(99);
    let conflicting = CompositeSettlementPlanV1::new(
        original.bindings().clone(),
        original.secret_requirement(),
        None,
        children,
    )
    .expect("different plan sharing effect");
    assert_eq!(
        store
            .install_plan(&mut PlanAuthority::new(), conflicting, 1_003)
            .unwrap_err(),
        CoordinatorErrorV1::IdempotencyConflict
    );
    assert_eq!(
        store.load_plan(first.plan_id).expect("failed view").stage,
        AggregateStageV1::FailedClosed
    );
}

#[test]
fn mismatched_child_receipt_never_advances_or_unlocks_later_child() {
    let (_root, path) = state_path();
    let mut store = create_store(&path);
    let (plan_id, lease) = install(&mut store, plan(SettlementActionV1::Funding, 1, 33));
    let pending = store
        .prepare_next_child_call(lease, 1_003)
        .expect("pending intent");
    let mut wrong = ChildAuthority::receipt(pending.request(), 91);
    wrong.transaction_id = digest(200);
    assert_eq!(
        store
            .complete_child_call(
                lease,
                pending,
                ChildExecutionOutcomeV1::Externalized(wrong),
                1_004,
            )
            .unwrap_err(),
        CoordinatorErrorV1::ChildReceiptMismatch
    );
    let view = store.load_plan(plan_id).expect("unchanged");
    assert_eq!(view.completed_prefix, 0);
    let mut correct = ChildAuthority {
        dispatch: [DispatchMode::Externalized(92)].into(),
        ..ChildAuthority::default()
    };
    assert!(matches!(
        store.drive_one(lease, &mut correct, 1_005).expect("resume exact child"),
        CoordinatorDriveOutcomeV1::PartialProgress(progress)
            if progress.completed_prefix == 1
    ));
}

#[test]
fn storage_authority_lock_modes_symlink_schema_and_row_corruption_fail_closed() {
    let (_root, path) = state_path();
    assert_eq!(
        DurableSettlementCoordinatorV1::open_existing(&path, COORDINATOR_ID, AUTHORITY_ID)
            .unwrap_err(),
        CoordinatorErrorV1::DatabaseMissing
    );
    let store = create_store(&path);
    assert_eq!(
        DurableSettlementCoordinatorV1::create(&path, COORDINATOR_ID, AUTHORITY_ID, 1_000)
            .unwrap_err(),
        CoordinatorErrorV1::DatabasePresent
    );
    assert_eq!(
        DurableSettlementCoordinatorV1::open_existing(&path, COORDINATOR_ID, AUTHORITY_ID)
            .unwrap_err(),
        CoordinatorErrorV1::StorageUnavailable
    );
    drop(store);

    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).expect("weaken mode");
    assert_eq!(
        DurableSettlementCoordinatorV1::open_existing(&path, COORDINATOR_ID, AUTHORITY_ID)
            .unwrap_err(),
        CoordinatorErrorV1::InvalidStorageAuthority
    );
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("restore mode");

    let link = path.with_file_name("coordinator-link.sqlite3");
    symlink(&path, &link).expect("symlink");
    assert_eq!(
        DurableSettlementCoordinatorV1::open_existing(&link, COORDINATOR_ID, AUTHORITY_ID)
            .unwrap_err(),
        CoordinatorErrorV1::InvalidStorageAuthority
    );

    let connection = rusqlite::Connection::open(&path).expect("raw connection");
    connection
        .execute_batch("CREATE TABLE injected(value INTEGER) STRICT;")
        .expect("inject schema");
    drop(connection);
    assert_eq!(
        DurableSettlementCoordinatorV1::open_existing(&path, COORDINATOR_ID, AUTHORITY_ID)
            .unwrap_err(),
        CoordinatorErrorV1::CorruptState
    );

    let (_root, path) = state_path();
    let original = plan(SettlementActionV1::Funding, 1, 27);
    let plan_id = {
        let mut store = create_store(&path);
        store
            .install_plan(&mut PlanAuthority::new(), original, 1_001)
            .expect("install")
            .plan_id
    };
    let connection = rusqlite::Connection::open(&path).expect("raw connection");
    connection
        .execute(
            "UPDATE settlement_children SET expected_tx_id=?1 WHERE plan_id=?2 AND child_index=0",
            rusqlite::params![digest(101).as_slice(), plan_id.as_slice()],
        )
        .expect("tamper row");
    drop(connection);
    assert_eq!(
        DurableSettlementCoordinatorV1::open_existing(&path, COORDINATOR_ID, AUTHORITY_ID)
            .unwrap_err(),
        CoordinatorErrorV1::CorruptState
    );
}

#[test]
fn schema_v1_is_rejected_without_silent_migration() {
    let (_root, path) = state_path();
    drop(create_store(&path));
    let connection = rusqlite::Connection::open(&path).expect("raw connection");
    let mode: String = connection
        .query_row("PRAGMA journal_mode=DELETE", [], |row| row.get(0))
        .expect("disable WAL before legacy preflight fixture");
    assert!(mode.eq_ignore_ascii_case("delete"));
    connection
        .execute_batch("PRAGMA user_version = 1;")
        .expect("mark legacy schema");
    drop(connection);
    let before = fs::read(&path).expect("legacy bytes before refusal");
    let sidecars = [
        PathBuf::from(format!("{}-wal", path.display())),
        PathBuf::from(format!("{}-shm", path.display())),
        PathBuf::from(format!("{}-journal", path.display())),
    ];
    assert!(sidecars.iter().all(|candidate| !candidate.exists()));

    assert_eq!(
        DurableSettlementCoordinatorV1::open_existing(&path, COORDINATOR_ID, AUTHORITY_ID)
            .unwrap_err(),
        CoordinatorErrorV1::UnsupportedFormat
    );
    assert_eq!(
        fs::read(&path).expect("legacy bytes after refusal"),
        before,
        "read-only preflight must not rewrite a legacy database"
    );
    assert!(
        sidecars.iter().all(|candidate| !candidate.exists()),
        "legacy refusal must not create WAL, SHM, or rollback journals"
    );
    let connection = rusqlite::Connection::open(&path).expect("raw connection after refusal");
    let version: i64 = connection
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .expect("retained schema version");
    assert_eq!(version, 1, "open must never migrate legacy storage");
}

#[test]
fn schema_v2_is_rejected_without_silent_migration() {
    let (_root, path) = state_path();
    drop(create_store(&path));
    let connection = rusqlite::Connection::open(&path).expect("raw connection");
    let mode: String = connection
        .query_row("PRAGMA journal_mode=DELETE", [], |row| row.get(0))
        .expect("disable WAL before legacy preflight fixture");
    assert!(mode.eq_ignore_ascii_case("delete"));
    connection
        .execute_batch("PRAGMA user_version = 2;")
        .expect("mark V2 schema");
    drop(connection);
    let before = fs::read(&path).expect("V2 bytes before refusal");
    let sidecars = [
        PathBuf::from(format!("{}-wal", path.display())),
        PathBuf::from(format!("{}-shm", path.display())),
        PathBuf::from(format!("{}-journal", path.display())),
    ];
    assert!(sidecars.iter().all(|candidate| !candidate.exists()));

    assert_eq!(
        DurableSettlementCoordinatorV1::open_existing(&path, COORDINATOR_ID, AUTHORITY_ID)
            .unwrap_err(),
        CoordinatorErrorV1::UnsupportedFormat
    );
    assert_eq!(
        fs::read(&path).expect("V2 bytes after refusal"),
        before,
        "read-only preflight must not rewrite a V2 database"
    );
    assert!(
        sidecars.iter().all(|candidate| !candidate.exists()),
        "V2 refusal must not create WAL, SHM, or rollback journals"
    );
    let connection = rusqlite::Connection::open(&path).expect("raw connection after refusal");
    let version: i64 = connection
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .expect("retained schema version");
    assert_eq!(version, 2, "open must never migrate V2 storage");
}

#[test]
fn valid_economic_store_reopens_but_strict_creation_resume_refuses_it() {
    let (_root, path) = state_path();
    let (plan_id, expected_view) = {
        let mut store = create_store(&path);
        let plan = plan(SettlementActionV1::Funding, 1, 29);
        let (plan_id, _lease) = install(&mut store, plan);
        let view = store
            .load_plan(plan_id)
            .expect("authenticated economic state");
        (plan_id, view)
    };

    assert_eq!(
        DurableSettlementCoordinatorV1::resume_create_production(
            &path,
            COORDINATOR_ID,
            AUTHORITY_ID,
            1_000,
        )
        .unwrap_err(),
        CoordinatorErrorV1::CorruptState
    );
    let reopened =
        DurableSettlementCoordinatorV1::open_existing(&path, COORDINATOR_ID, AUTHORITY_ID)
            .expect("valid committed economic state must reopen under Started recovery");
    assert_eq!(
        reopened.load_plan(plan_id).expect("fully audited plan"),
        expected_view
    );
}

#[test]
fn database_contains_no_secret_scalar_or_transaction_bytes() {
    let (_root, path) = state_path();
    {
        let mut store = create_store(&path);
        let (_plan_id, lease) = install(&mut store, plan(SettlementActionV1::Claim, 1, 28));
        let mut authority = ChildAuthority {
            dispatch: [DispatchMode::Externalized(90)].into(),
            ..ChildAuthority::default()
        };
        store
            .drive_one(lease, &mut authority, 1_003)
            .expect("partial claim");
    }
    let forbidden = b"DO_NOT_STORE_ROUTE_SCALAR_OR_RAW_TX";
    for candidate in [
        path.clone(),
        PathBuf::from(format!("{}-wal", path.display())),
        PathBuf::from(format!("{}-shm", path.display())),
    ] {
        if let Ok(bytes) = fs::read(candidate) {
            assert!(!bytes
                .windows(forbidden.len())
                .any(|window| window == forbidden));
        }
    }
}

#[test]
fn strict_codec_refuses_wrong_reveal_order_and_trailing_material() {
    let valid = plan(SettlementActionV1::Claim, 1, 29);
    let mut children = valid.materialized_children().expect("materialized").clone();
    children.swap(0, 1);
    assert_eq!(
        CompositeSettlementPlanV1::new(
            valid.bindings().clone(),
            SecretRequirementV1::FirstExposureRequired,
            None,
            children,
        )
        .unwrap_err(),
        CoordinatorErrorV1::InvalidPlan
    );
    let mut encoded = valid.encode_canonical().expect("encode");
    encoded.push(0);
    assert_eq!(
        CompositeSettlementPlanV1::decode_canonical(&encoded).unwrap_err(),
        CoordinatorErrorV1::InvalidCanonicalMaterial
    );
}
