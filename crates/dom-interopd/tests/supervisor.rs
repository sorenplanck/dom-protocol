#![cfg(any(feature = "development", feature = "simulation"))]

use std::collections::BTreeMap;
use std::error::Error;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use dom_interopd::{
    ActionExternalizationReceiptV1, AuthorityRefusalV1, ChainObservationAuthority,
    ChainObservationQueryV1, ChainObservationRequestV1, CustodyDispatchOutcomeV1,
    ExternalCustodyActionRequestV1, ExternalCustodyAuthority, ManualClockV1,
    ReconciliationRequestV1, RefundArmingAuthority, RefundArmingRequestV1, RouteActionAuthority,
    RouteActionAuthorizationRequestV1, RouteSupervisorConfigV1, RouteSupervisorErrorV1,
    RouteSupervisorV1, RunnerActionAuthority, RunnerActionRequestV1,
    TakeoverReconciliationAuthority, TakeoverReconciliationOutcomeV1, TimerAuthority,
    TimerDispatchV1, TimerEventCommitV1, VerifiedChainObservationV1,
};
use route_executor::{
    digest_bytes_v1, ActionIntentV1, ActionKindV1, ActionProgressV1, ActionStateV1,
    CommitOutcomeV1, Digest32, DurableRouteStoreV1, EffectDispatchV1, ExposureSourceV1,
    FrozenBindingsV1, HealthStateV1, LegIdV1, PublicExposureV1, RefundBindingsV1, RouteEventV1,
    RouteStoreErrorV1, TimerKindV1,
};

const ROUTE: Digest32 = [1; 32];
const OWNER_A: Digest32 = [2; 32];
const OWNER_B: Digest32 = [3; 32];
const TERMS: Digest32 = [10; 32];
const PROFILES: Digest32 = [11; 32];
const DEPLOYMENTS: Digest32 = [12; 32];

fn id(value: u8) -> Digest32 {
    [value; 32]
}

fn config() -> RouteSupervisorConfigV1 {
    RouteSupervisorConfigV1::new(1_000, 200, 100, 8).expect("valid supervisor config")
}

struct FixedRunner(Digest32);

impl RunnerActionAuthority for FixedRunner {
    fn externalize_runner_action(
        &mut self,
        request: RunnerActionRequestV1<'_>,
    ) -> Result<ActionExternalizationReceiptV1, AuthorityRefusalV1> {
        if digest_bytes_v1(request.payload()) != request.capability().dispatch_digest() {
            return Err(AuthorityRefusalV1::Inconsistent);
        }
        Ok(ActionExternalizationReceiptV1::public(self.0))
    }
}

struct FixedRefunds(RefundBindingsV1);

impl RefundArmingAuthority for FixedRefunds {
    fn arm_refunds(
        &mut self,
        request: RefundArmingRequestV1<'_>,
    ) -> Result<RefundBindingsV1, AuthorityRefusalV1> {
        assert_eq!(request.route_id(), ROUTE);
        assert_eq!(request.bindings().terms_digest, TERMS);
        assert!(request.snapshot().revision >= 1);
        assert_eq!(request.fencing_epoch(), 1);
        assert_ne!(request.event_id(), [0; 32]);
        Ok(self.0.clone())
    }
}

struct FixedAction(Option<ActionIntentV1>);

impl RouteActionAuthority for FixedAction {
    fn authorize_route_action(
        &mut self,
        request: RouteActionAuthorizationRequestV1<'_>,
    ) -> Result<ActionIntentV1, AuthorityRefusalV1> {
        assert_eq!(request.route_id(), ROUTE);
        assert_eq!(request.bindings().terms_digest, TERMS);
        assert_eq!(request.snapshot().route_id, ROUTE);
        assert_ne!(request.event_id(), [0; 32]);
        assert!(request.fencing_epoch() > 0);
        self.0.take().ok_or(AuthorityRefusalV1::Inconsistent)
    }
}

struct FixedObservation {
    expected: ChainObservationQueryV1,
    verified: VerifiedChainObservationV1,
}

impl ChainObservationAuthority for FixedObservation {
    fn verify_chain_observation(
        &mut self,
        request: ChainObservationRequestV1<'_>,
    ) -> Result<VerifiedChainObservationV1, AuthorityRefusalV1> {
        assert_eq!(request.route_id(), ROUTE);
        assert_eq!(request.query(), self.expected);
        assert_eq!(request.bindings().terms_digest, TERMS);
        assert_eq!(request.snapshot().route_id, ROUTE);
        assert_ne!(request.event_id(), [0; 32]);
        assert!(request.fencing_epoch() > 0);
        Ok(self.verified)
    }
}

struct Fixture {
    _temporary: tempfile::TempDir,
    database: PathBuf,
    clock: ManualClockV1,
    supervisor: RouteSupervisorV1<ManualClockV1>,
    next_event: u8,
}

impl Fixture {
    fn new() -> Self {
        Self::with_config(config())
    }

    fn with_config(config: RouteSupervisorConfigV1) -> Self {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let database = temporary.path().join("routes.sqlite3");
        let mut store = DurableRouteStoreV1::open(&database).expect("open route store");
        store.create_route(ROUTE, 90).expect("create route");
        let setup_lease = store
            .acquire_lease(ROUTE, OWNER_A, 90, config.lease_duration_ms())
            .expect("setup lease")
            .lease();
        store
            .apply_event(
                setup_lease,
                0,
                id(19),
                &RouteEventV1::FreezeTerms(FrozenBindingsV1 {
                    terms_digest: TERMS,
                    profile_bundle_digest: PROFILES,
                    deployment_bundle_digest: DEPLOYMENTS,
                }),
                90,
            )
            .expect("test-only authenticated admission fixture");
        let clock = ManualClockV1::new(100).expect("manual clock");
        let supervisor = RouteSupervisorV1::acquire(store, ROUTE, OWNER_A, config, clock.clone())
            .expect("acquire route");
        Self {
            _temporary: temporary,
            database,
            clock,
            supervisor,
            next_event: 20,
        }
    }

    fn next_event_id(&mut self) -> Digest32 {
        let event_id = id(self.next_event);
        self.next_event = self.next_event.checked_add(1).expect("test event ids");
        event_id
    }

    fn arm(&mut self) {
        let event_id = self.next_event_id();
        let mut authority = FixedRefunds(RefundBindingsV1 {
            upstream_refund_digest: id(13),
            downstream_refund_digest: id(14),
        });
        self.supervisor
            .arm_refunds(event_id, &mut authority)
            .expect("typed refund arming");
    }

    fn authorize(&mut self, intent: ActionIntentV1) -> CommitOutcomeV1 {
        let event_id = self.next_event_id();
        let leg = intent.leg;
        let action = intent.kind;
        self.supervisor
            .authorize_action(event_id, leg, action, &mut FixedAction(Some(intent)))
            .expect("typed action authorization")
    }

    fn schedule_timer(
        &mut self,
        kind: TimerKindV1,
        deadline_unix_ms: u64,
        context_digest: Digest32,
    ) -> CommitOutcomeV1 {
        let event_id = self.next_event_id();
        self.supervisor
            .schedule_timer(event_id, kind, deadline_unix_ms, context_digest)
            .expect("explicit timer schedule")
    }

    fn observe_finality(
        &mut self,
        leg: LegIdV1,
        action: ActionKindV1,
        transaction_id: Digest32,
        evidence_digest: Digest32,
    ) -> CommitOutcomeV1 {
        let event_id = self.next_event_id();
        let query = ChainObservationQueryV1::Finality {
            leg,
            action,
            transaction_id,
        };
        self.supervisor
            .record_chain_observation(
                event_id,
                query,
                &mut FixedObservation {
                    expected: query,
                    verified: VerifiedChainObservationV1::Finality { evidence_digest },
                },
            )
            .expect("typed finality observation")
    }

    fn observe_secret(&mut self, exposure: PublicExposureV1) -> CommitOutcomeV1 {
        let event_id = self.next_event_id();
        let query = ChainObservationQueryV1::SecretExposure {
            chain_id: exposure.chain_id,
            transaction_id: exposure.transaction_id,
        };
        self.supervisor
            .record_chain_observation(
                event_id,
                query,
                &mut FixedObservation {
                    expected: query,
                    verified: VerifiedChainObservationV1::SecretExposure {
                        source: exposure.source,
                        evidence_digest: exposure.evidence_digest,
                        observed_at_unix_ms: exposure.observed_at_unix_ms,
                    },
                },
            )
            .expect("typed secret observation")
    }

    fn runner_intent(&self, leg: LegIdV1, action: ActionKindV1, value: u8) -> ActionIntentV1 {
        let payload = vec![value; 31];
        ActionIntentV1 {
            leg,
            kind: action,
            semantic_digest: id(value),
            contains_route_secret: false,
            dispatch: EffectDispatchV1::RunnerPayload {
                payload_digest: digest_bytes_v1(&payload),
                payload,
            },
        }
    }

    fn custody_claim(&self, leg: LegIdV1, value: u8) -> ActionIntentV1 {
        self.custody_intent(leg, ActionKindV1::Claim, value, true)
    }

    fn custody_intent(
        &self,
        leg: LegIdV1,
        kind: ActionKindV1,
        value: u8,
        contains_route_secret: bool,
    ) -> ActionIntentV1 {
        ActionIntentV1 {
            leg,
            kind,
            semantic_digest: id(value),
            contains_route_secret,
            dispatch: EffectDispatchV1::ExternalCustody {
                custody_digest: id(value.wrapping_add(1)),
                transaction_id: id(value.wrapping_add(2)),
            },
        }
    }

    fn finalize_funding(&mut self, leg: LegIdV1, value: u8) {
        self.authorize(self.runner_intent(leg, ActionKindV1::Funding, value));
        let transaction_id = id(value.wrapping_add(1));
        self.supervisor
            .tick(
                &mut FixedRunner(transaction_id),
                &mut IdempotentCustody::default(),
                &mut inert_timer(),
            )
            .expect("typed funding externalization");
        self.observe_finality(
            leg,
            ActionKindV1::Funding,
            transaction_id,
            id(value.wrapping_add(2)),
        );
    }
}

#[derive(Clone, Debug)]
struct CapturedCapability {
    route_id: Digest32,
    effect_id: Digest32,
    leg: LegIdV1,
    action: ActionKindV1,
    semantic_digest: Digest32,
    terms_digest: Digest32,
    profiles_digest: Digest32,
    deployments_digest: Digest32,
    fence: u64,
    dispatch_digest: Digest32,
    expiry: u64,
    attempt: u64,
    one_shot_attempt_id: Digest32,
    expected_tx: Option<Digest32>,
    contains_secret: bool,
    debug_text: String,
}

impl CapturedCapability {
    fn runner(request: &RunnerActionRequestV1<'_>) -> Self {
        let capability = request.capability();
        Self {
            route_id: capability.route_id(),
            effect_id: capability.effect_id(),
            leg: capability.leg(),
            action: capability.action(),
            semantic_digest: capability.semantic_digest(),
            terms_digest: capability.terms_digest(),
            profiles_digest: capability.profile_bundle_digest(),
            deployments_digest: capability.deployment_bundle_digest(),
            fence: capability.fencing_epoch(),
            dispatch_digest: capability.dispatch_digest(),
            expiry: capability.expires_at_unix_ms(),
            attempt: capability.attempt(),
            one_shot_attempt_id: capability.one_shot_attempt_id(),
            expected_tx: capability.expected_transaction_id(),
            contains_secret: capability.contains_route_secret(),
            debug_text: format!("{capability:?}"),
        }
    }
}

#[derive(Default)]
struct IdempotentRunner {
    transactions: BTreeMap<Digest32, Digest32>,
    capabilities: Vec<CapturedCapability>,
    payloads: Vec<Vec<u8>>,
    lose_first_receipt: bool,
    calls: usize,
    order: Option<Arc<Mutex<Vec<&'static str>>>>,
}

impl RunnerActionAuthority for IdempotentRunner {
    fn externalize_runner_action(
        &mut self,
        request: RunnerActionRequestV1<'_>,
    ) -> Result<ActionExternalizationReceiptV1, AuthorityRefusalV1> {
        self.calls += 1;
        if let Some(order) = &self.order {
            order.lock().expect("order lock").push("runner");
        }
        let captured = CapturedCapability::runner(&request);
        assert_eq!(digest_bytes_v1(request.payload()), captured.dispatch_digest);
        let tx = *self
            .transactions
            .entry(captured.effect_id)
            .or_insert_with(|| id(160));
        self.payloads.push(request.payload().to_vec());
        self.capabilities.push(captured);
        if self.lose_first_receipt && self.calls == 1 {
            // Economic externalization is retained by this authority, while
            // the response is lost before ActionExternalized can commit.
            return Err(AuthorityRefusalV1::Unavailable);
        }
        Ok(ActionExternalizationReceiptV1::public(tx))
    }
}

#[derive(Default)]
struct IdempotentCustody {
    calls: usize,
    order: Option<Arc<Mutex<Vec<&'static str>>>>,
    acknowledged_progress: Vec<Option<Digest32>>,
}

impl ExternalCustodyAuthority for IdempotentCustody {
    fn externalize_custodied_action(
        &mut self,
        request: ExternalCustodyActionRequestV1,
    ) -> Result<CustodyDispatchOutcomeV1, AuthorityRefusalV1> {
        self.calls += 1;
        let capability = request.capability();
        self.acknowledged_progress.push(
            capability
                .acknowledged_custody_progress()
                .map(|progress| progress.progress_evidence_digest()),
        );
        if let Some(order) = &self.order {
            order
                .lock()
                .expect("order lock")
                .push(if capability.contains_route_secret() {
                    "urgent"
                } else {
                    "custody"
                });
        }
        let expected = capability
            .expected_transaction_id()
            .ok_or(AuthorityRefusalV1::Inconsistent)?;
        if capability.contains_route_secret() {
            Ok(CustodyDispatchOutcomeV1::AggregateExternalized(
                ActionExternalizationReceiptV1::secret_revealing(expected, id(161), id(162)),
            ))
        } else {
            Ok(CustodyDispatchOutcomeV1::AggregateExternalized(
                ActionExternalizationReceiptV1::public(expected),
            ))
        }
    }
}

#[derive(Default)]
struct UnavailableCustody {
    calls: usize,
}

impl ExternalCustodyAuthority for UnavailableCustody {
    fn externalize_custodied_action(
        &mut self,
        _request: ExternalCustodyActionRequestV1,
    ) -> Result<CustodyDispatchOutcomeV1, AuthorityRefusalV1> {
        self.calls += 1;
        Err(AuthorityRefusalV1::Unavailable)
    }
}

struct PrefixThenAggregateCustody {
    calls: usize,
    progress_evidence_digest: Digest32,
    exposure: PublicExposureV1,
}

#[derive(Default)]
struct UnknownOutcomeCustody {
    calls: usize,
}

impl ExternalCustodyAuthority for UnknownOutcomeCustody {
    fn externalize_custodied_action(
        &mut self,
        _request: ExternalCustodyActionRequestV1,
    ) -> Result<CustodyDispatchOutcomeV1, AuthorityRefusalV1> {
        self.calls += 1;
        Ok(CustodyDispatchOutcomeV1::Unknown)
    }
}

impl ExternalCustodyAuthority for PrefixThenAggregateCustody {
    fn externalize_custodied_action(
        &mut self,
        request: ExternalCustodyActionRequestV1,
    ) -> Result<CustodyDispatchOutcomeV1, AuthorityRefusalV1> {
        self.calls += 1;
        let expected = request
            .capability()
            .expected_transaction_id()
            .ok_or(AuthorityRefusalV1::Inconsistent)?;
        let acknowledged = request.capability().acknowledged_custody_progress();
        let route_exposure = request.capability().route_first_public_exposure();
        match self.calls {
            1 => {
                assert!(acknowledged.is_none());
                assert!(route_exposure.is_none());
                Ok(CustodyDispatchOutcomeV1::PartialProgress {
                    progress_evidence_digest: self.progress_evidence_digest,
                    exposure: Some(self.exposure.clone()),
                })
            }
            2 => {
                let acknowledged = acknowledged.expect("route journaled child prefix");
                assert_eq!(
                    acknowledged.progress_evidence_digest(),
                    self.progress_evidence_digest
                );
                assert_eq!(acknowledged.exposure(), Some(&self.exposure));
                assert_eq!(route_exposure, Some(&self.exposure));
                Ok(CustodyDispatchOutcomeV1::PartialProgress {
                    progress_evidence_digest: self.progress_evidence_digest,
                    exposure: Some(self.exposure.clone()),
                })
            }
            _ => {
                let acknowledged = acknowledged.expect("route retained child prefix");
                assert_eq!(
                    acknowledged.progress_evidence_digest(),
                    self.progress_evidence_digest
                );
                assert_eq!(acknowledged.exposure(), Some(&self.exposure));
                assert_eq!(route_exposure, Some(&self.exposure));
                Ok(CustodyDispatchOutcomeV1::AggregateExternalized(
                    ActionExternalizationReceiptV1::public(expected),
                ))
            }
        }
    }
}

#[derive(Clone)]
struct DeterministicTimer {
    event: RouteEventV1,
    fail_commit_barrier_once: bool,
    event_calls: usize,
    commit_calls: usize,
    order: Option<Arc<Mutex<Vec<&'static str>>>>,
}

impl TimerAuthority for DeterministicTimer {
    fn event_for_due_timer(
        &mut self,
        timer: TimerDispatchV1,
    ) -> Result<RouteEventV1, AuthorityRefusalV1> {
        assert_eq!(timer.route_id(), ROUTE);
        assert_ne!(timer.timer_id(), [0; 32]);
        assert_ne!(timer.event_id(), [0; 32]);
        assert!(timer.attempt() > 0);
        self.event_calls += 1;
        if let Some(order) = &self.order {
            order.lock().expect("order lock").push("timer");
        }
        Ok(self.event.clone())
    }

    fn event_committed(&mut self, commit: TimerEventCommitV1) -> Result<(), AuthorityRefusalV1> {
        assert_ne!(commit.event_id, [0; 32]);
        self.commit_calls += 1;
        if self.fail_commit_barrier_once && self.commit_calls == 1 {
            return Err(AuthorityRefusalV1::Unavailable);
        }
        Ok(())
    }
}

fn inert_timer() -> DeterministicTimer {
    DeterministicTimer {
        event: RouteEventV1::SetHealth {
            target: HealthStateV1::Running,
            reason_digest: id(170),
        },
        fail_commit_barrier_once: false,
        event_calls: 0,
        commit_calls: 0,
        order: None,
    }
}

#[test]
fn config_clock_typed_boundaries_and_operational_cas_are_fail_closed() -> Result<(), Box<dyn Error>>
{
    for invalid in [
        RouteSupervisorConfigV1::new(0, 1, 1, 1),
        RouteSupervisorConfigV1::new(100, 100, 1, 1),
        RouteSupervisorConfigV1::new(100, 20, 21, 1),
        RouteSupervisorConfigV1::new(100, 20, 10, 0),
        RouteSupervisorConfigV1::new(100, 20, 10, 65),
    ] {
        assert!(matches!(
            invalid,
            Err(RouteSupervisorErrorV1::InvalidConfiguration)
        ));
    }

    let mut fixture = Fixture::new();
    let lease_status = fixture.supervisor.lease_status();
    assert_eq!(lease_status.route_id(), ROUTE);
    assert_eq!(lease_status.fencing_epoch(), 1);
    assert!(!format!("{:?}", fixture.supervisor).contains(&format!("{OWNER_A:?}")));
    let event_id = id(90);
    assert!(matches!(
        fixture
            .supervisor
            .set_health(event_id, HealthStateV1::Running, id(91))?,
        CommitOutcomeV1::Committed { revision: 2, .. }
    ));
    assert_eq!(
        fixture
            .supervisor
            .set_health(event_id, HealthStateV1::Running, id(91))?,
        CommitOutcomeV1::DuplicateSameBytes { revision: 2 }
    );
    assert!(matches!(
        fixture
            .supervisor
            .set_health(event_id, HealthStateV1::Running, id(92)),
        Err(RouteSupervisorErrorV1::Store(
            RouteStoreErrorV1::IdempotencyConflict
        ))
    ));

    fixture.arm();
    let wrong_intent = fixture.runner_intent(LegIdV1::Downstream, ActionKindV1::Funding, 93);
    assert!(matches!(
        fixture.supervisor.authorize_action(
            id(94),
            LegIdV1::Upstream,
            ActionKindV1::Funding,
            &mut FixedAction(Some(wrong_intent)),
        ),
        Err(RouteSupervisorErrorV1::InvalidAuthorityResponse)
    ));
    let query = ChainObservationQueryV1::Finality {
        leg: LegIdV1::Upstream,
        action: ActionKindV1::Funding,
        transaction_id: id(95),
    };
    assert!(matches!(
        fixture.supervisor.record_chain_observation(
            id(96),
            query,
            &mut FixedObservation {
                expected: query,
                verified: VerifiedChainObservationV1::Invalidation {
                    reorg_evidence_digest: id(97),
                },
            },
        ),
        Err(RouteSupervisorErrorV1::InvalidAuthorityResponse)
    ));
    let old_until = fixture.supervisor.lease_status().lease_until_unix_ms();
    fixture.clock.set(old_until - 100)?;
    let renewed = fixture.supervisor.renew()?;
    assert!(renewed.lease_until_unix_ms() > old_until);
    assert_eq!(renewed.fencing_epoch(), 1);
    Ok(())
}

#[test]
fn runner_broadcast_receipt_loss_retries_same_tx_and_capability_has_no_secret(
) -> Result<(), Box<dyn Error>> {
    let mut fixture = Fixture::new();
    fixture.arm();
    let payload_marker = 77;
    fixture.authorize(fixture.runner_intent(
        LegIdV1::Upstream,
        ActionKindV1::Funding,
        payload_marker,
    ));
    let effect_id = fixture
        .supervisor
        .snapshot()?
        .upstream
        .funding
        .effect()
        .expect("committed funding")
        .effect_id;
    let mut runner = IdempotentRunner {
        lose_first_receipt: true,
        ..IdempotentRunner::default()
    };
    let mut custody = IdempotentCustody::default();
    let mut timer = inert_timer();

    assert!(matches!(
        fixture
            .supervisor
            .tick(&mut runner, &mut custody, &mut timer),
        Err(RouteSupervisorErrorV1::RunnerAuthority(
            AuthorityRefusalV1::Unavailable
        ))
    ));
    assert_eq!(
        fixture.supervisor.snapshot()?.upstream.funding.progress(),
        ActionProgressV1::Committed
    );
    fixture.clock.advance(101)?;
    drop(fixture.supervisor);
    let recovered_store = DurableRouteStoreV1::open(&fixture.database)?;
    fixture.supervisor = RouteSupervisorV1::acquire(
        recovered_store,
        ROUTE,
        OWNER_A,
        config(),
        fixture.clock.clone(),
    )?;
    let report = fixture
        .supervisor
        .tick(&mut runner, &mut custody, &mut timer)?;
    assert_eq!(report.runner_externalized, 1);
    assert_eq!(runner.calls, 2);
    assert_eq!(runner.transactions.len(), 1);
    assert_eq!(
        fixture
            .supervisor
            .snapshot()?
            .upstream
            .funding
            .transaction_id(),
        Some(id(160))
    );

    let first = &runner.capabilities[0];
    let second = &runner.capabilities[1];
    assert_eq!(first.route_id, ROUTE);
    assert_eq!(first.effect_id, effect_id);
    assert_eq!(first.leg, LegIdV1::Upstream);
    assert_eq!(first.action, ActionKindV1::Funding);
    assert_eq!(first.semantic_digest, id(payload_marker));
    assert_eq!(first.terms_digest, TERMS);
    assert_eq!(first.profiles_digest, PROFILES);
    assert_eq!(first.deployments_digest, DEPLOYMENTS);
    assert_eq!(
        first.fence,
        fixture.supervisor.lease_status().fencing_epoch()
    );
    assert!(first.expiry <= fixture.supervisor.lease_status().lease_until_unix_ms());
    assert_eq!((first.attempt, second.attempt), (1, 2));
    assert_ne!(first.one_shot_attempt_id, second.one_shot_attempt_id);
    assert_eq!(first.expected_tx, None);
    assert!(!first.contains_secret);
    assert!(!first.debug_text.contains("payload"));
    assert!(!first.debug_text.contains("route_scalar"));
    assert_eq!(runner.payloads[0], vec![payload_marker; 31]);
    Ok(())
}

#[test]
fn restart_after_externalized_event_never_broadcasts_again() -> Result<(), Box<dyn Error>> {
    let mut fixture = Fixture::new();
    fixture.arm();
    fixture.authorize(fixture.runner_intent(LegIdV1::Upstream, ActionKindV1::Funding, 80));
    let mut first_runner = IdempotentRunner::default();
    fixture.supervisor.tick(
        &mut first_runner,
        &mut IdempotentCustody::default(),
        &mut inert_timer(),
    )?;
    assert_eq!(first_runner.calls, 1);
    assert_eq!(fixture.supervisor.pending_effect_count()?, 0);

    let lease = fixture.supervisor.lease_status();
    drop(fixture.supervisor);
    let store = DurableRouteStoreV1::open(&fixture.database)?;
    let mut recovered =
        RouteSupervisorV1::acquire(store, ROUTE, OWNER_A, config(), fixture.clock.clone())?;
    assert_eq!(
        recovered.lease_status().fencing_epoch(),
        lease.fencing_epoch()
    );
    let mut second_runner = IdempotentRunner::default();
    let report = recovered.tick(
        &mut second_runner,
        &mut IdempotentCustody::default(),
        &mut inert_timer(),
    )?;
    assert_eq!(report.runner_externalized, 0);
    assert_eq!(second_runner.calls, 0);
    assert_eq!(recovered.pending_effect_count()?, 0);
    Ok(())
}

#[test]
fn custody_prefix_exposes_real_child_but_closes_only_on_aggregate_receipt(
) -> Result<(), Box<dyn Error>> {
    let mut fixture = Fixture::new();
    fixture.arm();
    fixture.finalize_funding(LegIdV1::Upstream, 0xd0);
    fixture.finalize_funding(LegIdV1::Downstream, 0xd1);
    let intent = fixture.custody_claim(LegIdV1::Downstream, 0xd2);
    let aggregate_action_id = match intent.dispatch {
        EffectDispatchV1::ExternalCustody { transaction_id, .. } => transaction_id,
        EffectDispatchV1::RunnerPayload { .. } => unreachable!("custody claim"),
    };
    fixture.authorize(intent);
    let effect_id = fixture
        .supervisor
        .snapshot()?
        .downstream
        .claim
        .effect()
        .expect("aggregate effect")
        .effect_id;
    let progress_evidence_digest = id(0xd5);
    let child_exposure = PublicExposureV1 {
        source: ExposureSourceV1::Externalized,
        chain_id: id(0xd6),
        transaction_id: id(0xd7),
        evidence_digest: id(0xd8),
        observed_at_unix_ms: 100,
    };
    let mut custody = PrefixThenAggregateCustody {
        calls: 0,
        progress_evidence_digest,
        exposure: child_exposure.clone(),
    };

    let first = fixture
        .supervisor
        .dispatch_one_effect(&mut IdempotentRunner::default(), &mut custody)?;
    assert_eq!(first.custody_partial_progress, 1);
    assert_eq!(first.custody_externalized, 0);
    let after_prefix = fixture.supervisor.snapshot()?;
    assert!(matches!(
        after_prefix.downstream.claim,
        ActionStateV1::Committed(ref retained) if retained.effect_id == effect_id
    ));
    assert_eq!(
        after_prefix.secret_visibility,
        route_executor::SecretVisibilityV1::Public {
            first_exposure: child_exposure.clone()
        }
    );
    assert_eq!(fixture.supervisor.pending_effect_count()?, 1);

    // Replaying the same durable child prefix neither grows the journal nor
    // holds the aggregate dispatch lease until timeout.
    let revision_after_prefix = after_prefix.revision;
    let repeated = fixture
        .supervisor
        .dispatch_one_effect(&mut IdempotentRunner::default(), &mut custody)?;
    assert_eq!(repeated.custody_progress_unchanged, 1);
    assert_eq!(
        fixture.supervisor.snapshot()?.revision,
        revision_after_prefix
    );

    let aggregate = fixture
        .supervisor
        .dispatch_one_effect(&mut IdempotentRunner::default(), &mut custody)?;
    assert_eq!(aggregate.custody_externalized, 1);
    assert_eq!(aggregate.urgent_externalized, 0);
    let final_snapshot = fixture.supervisor.snapshot()?;
    assert!(matches!(
        final_snapshot.downstream.claim,
        ActionStateV1::Externalized {
            ref effect,
            transaction_id,
        } if effect.effect_id == effect_id && transaction_id == aggregate_action_id
    ));
    assert_eq!(
        final_snapshot.secret_visibility,
        route_executor::SecretVisibilityV1::Public {
            first_exposure: child_exposure
        }
    );
    assert_eq!(fixture.supervisor.pending_effect_count()?, 0);
    assert_eq!(
        fixture
            .supervisor
            .journal()?
            .iter()
            .filter(|entry| matches!(
                entry.event,
                RouteEventV1::CustodyProgressRecorded {
                    progress_evidence_digest: digest,
                    ..
                } if digest == progress_evidence_digest
            ))
            .count(),
        1
    );
    Ok(())
}

#[test]
fn unknown_custody_outcome_keeps_effect_inert_until_reconciliation_or_lease_expiry(
) -> Result<(), Box<dyn Error>> {
    let mut fixture = Fixture::new();
    fixture.arm();
    fixture.finalize_funding(LegIdV1::Upstream, 0xb0);
    fixture.finalize_funding(LegIdV1::Downstream, 0xb1);
    fixture.authorize(fixture.custody_claim(LegIdV1::Downstream, 0xb2));
    let revision = fixture.supervisor.snapshot()?.revision;
    let mut custody = UnknownOutcomeCustody::default();
    let first = fixture
        .supervisor
        .dispatch_one_effect(&mut IdempotentRunner::default(), &mut custody)?;
    assert_eq!(first.custody_unknown, 1);
    assert_eq!(custody.calls, 1);
    assert_eq!(fixture.supervisor.snapshot()?.revision, revision);
    assert!(matches!(
        fixture.supervisor.snapshot()?.downstream.claim,
        ActionStateV1::Committed(_)
    ));
    assert!(matches!(
        fixture.supervisor.snapshot()?.secret_visibility,
        route_executor::SecretVisibilityV1::Private
    ));

    let leased = fixture
        .supervisor
        .dispatch_one_effect(&mut IdempotentRunner::default(), &mut custody)?;
    assert_eq!(leased, Default::default());
    assert_eq!(
        custody.calls, 1,
        "ambiguous call must not be retried blindly"
    );
    assert_eq!(fixture.supervisor.pending_effect_count()?, 1);
    Ok(())
}

#[test]
fn timer_event_commit_then_crash_redelivers_duplicate_before_completion(
) -> Result<(), Box<dyn Error>> {
    let mut fixture = Fixture::new();
    fixture.arm();
    fixture.schedule_timer(TimerKindV1::Reconcile, 100, id(100));
    let mut forged = DeterministicTimer {
        event: RouteEventV1::ActionExternalized {
            leg: LegIdV1::Upstream,
            kind: ActionKindV1::Funding,
            effect_id: id(102),
            transaction_id: id(103),
            exposure: None,
        },
        fail_commit_barrier_once: false,
        event_calls: 0,
        commit_calls: 0,
        order: None,
    };
    assert!(matches!(
        fixture.supervisor.tick(
            &mut IdempotentRunner::default(),
            &mut IdempotentCustody::default(),
            &mut forged,
        ),
        Err(RouteSupervisorErrorV1::InvalidTimerEvent)
    ));
    assert_eq!(fixture.supervisor.active_timer_count()?, 1);
    fixture.clock.advance(101)?;

    let forged_intent = fixture.runner_intent(LegIdV1::Upstream, ActionKindV1::Funding, 104);
    let mut forged_action = DeterministicTimer {
        event: RouteEventV1::CommitAction(forged_intent),
        fail_commit_barrier_once: false,
        event_calls: 0,
        commit_calls: 0,
        order: None,
    };
    assert!(matches!(
        fixture.supervisor.tick(
            &mut IdempotentRunner::default(),
            &mut IdempotentCustody::default(),
            &mut forged_action,
        ),
        Err(RouteSupervisorErrorV1::InvalidTimerEvent)
    ));
    assert_eq!(fixture.supervisor.active_timer_count()?, 1);
    fixture.clock.advance(101)?;

    let event = RouteEventV1::SetHealth {
        target: HealthStateV1::Degraded,
        reason_digest: id(101),
    };
    let mut timer = DeterministicTimer {
        event: event.clone(),
        fail_commit_barrier_once: true,
        event_calls: 0,
        commit_calls: 0,
        order: None,
    };
    assert!(matches!(
        fixture.supervisor.tick(
            &mut IdempotentRunner::default(),
            &mut IdempotentCustody::default(),
            &mut timer,
        ),
        Err(RouteSupervisorErrorV1::TimerAuthority(
            AuthorityRefusalV1::Unavailable
        ))
    ));
    assert_eq!(
        fixture.supervisor.snapshot()?.health,
        HealthStateV1::Degraded
    );
    assert_eq!(fixture.supervisor.active_timer_count()?, 1);
    let first_revision = fixture.supervisor.snapshot()?.revision;

    fixture.clock.advance(101)?;
    drop(fixture.supervisor);
    let store = DurableRouteStoreV1::open(&fixture.database)?;
    let mut recovered =
        RouteSupervisorV1::acquire(store, ROUTE, OWNER_A, config(), fixture.clock.clone())?;
    let report = recovered.tick(
        &mut IdempotentRunner::default(),
        &mut IdempotentCustody::default(),
        &mut timer,
    )?;
    assert_eq!(
        (report.timers_completed, report.duplicate_timer_events),
        (1, 1)
    );
    assert_eq!(recovered.active_timer_count()?, 0);
    assert_eq!(recovered.snapshot()?.revision, first_revision);
    assert_eq!(
        recovered
            .journal()?
            .iter()
            .filter(|entry| entry.event == event)
            .count(),
        1
    );
    Ok(())
}

struct ProveNotExternalized {
    calls: usize,
}

struct ProveExternalized {
    receipt: ActionExternalizationReceiptV1,
    calls: usize,
}

struct ResumePartialCustody {
    calls: usize,
}

struct ResumeSecretPartialCustody {
    calls: usize,
    progress_evidence_digest: Digest32,
    exposure: PublicExposureV1,
}

struct UnknownReconciliation {
    calls: usize,
}

impl TakeoverReconciliationAuthority for UnknownReconciliation {
    fn reconcile_committed_action(
        &mut self,
        request: ReconciliationRequestV1<'_>,
    ) -> Result<TakeoverReconciliationOutcomeV1, AuthorityRefusalV1> {
        self.calls += 1;
        assert!(request.prior_fence() < request.current_fence());
        Ok(TakeoverReconciliationOutcomeV1::Unknown)
    }
}

impl TakeoverReconciliationAuthority for ProveExternalized {
    fn reconcile_committed_action(
        &mut self,
        request: ReconciliationRequestV1<'_>,
    ) -> Result<TakeoverReconciliationOutcomeV1, AuthorityRefusalV1> {
        self.calls += 1;
        assert!(request.prior_fence() < request.current_fence());
        assert!(request.intent().contains_route_secret);
        assert!(matches!(
            request.intent().dispatch,
            EffectDispatchV1::ExternalCustody { .. }
        ));
        Ok(TakeoverReconciliationOutcomeV1::Externalized(self.receipt))
    }
}

impl TakeoverReconciliationAuthority for ProveNotExternalized {
    fn reconcile_committed_action(
        &mut self,
        request: ReconciliationRequestV1<'_>,
    ) -> Result<TakeoverReconciliationOutcomeV1, AuthorityRefusalV1> {
        self.calls += 1;
        assert!(request.prior_fence() < request.current_fence());
        assert_eq!(request.bindings().terms_digest, TERMS);
        Ok(TakeoverReconciliationOutcomeV1::ProvenNotExternalized {
            intent: request.intent().clone(),
            evidence_digest: id(180),
        })
    }
}

impl TakeoverReconciliationAuthority for ResumePartialCustody {
    fn reconcile_committed_action(
        &mut self,
        request: ReconciliationRequestV1<'_>,
    ) -> Result<TakeoverReconciliationOutcomeV1, AuthorityRefusalV1> {
        self.calls += 1;
        assert!(request.prior_fence() < request.current_fence());
        assert!(matches!(
            request.intent().dispatch,
            EffectDispatchV1::ExternalCustody { .. }
        ));
        Ok(TakeoverReconciliationOutcomeV1::SafeToResumeCustody {
            intent: request.intent().clone(),
            evidence_digest: id(0xc7),
        })
    }
}

impl TakeoverReconciliationAuthority for ResumeSecretPartialCustody {
    fn reconcile_committed_action(
        &mut self,
        request: ReconciliationRequestV1<'_>,
    ) -> Result<TakeoverReconciliationOutcomeV1, AuthorityRefusalV1> {
        self.calls += 1;
        assert!(request.prior_fence() < request.current_fence());
        assert!(request.intent().contains_route_secret);
        Ok(
            TakeoverReconciliationOutcomeV1::SecretPublicPartialCustody {
                intent: request.intent().clone(),
                progress_evidence_digest: self.progress_evidence_digest,
                exposure: self.exposure.clone(),
            },
        )
    }
}

#[test]
fn takeover_never_dispatches_stale_effect_before_reconciliation_and_refence(
) -> Result<(), Box<dyn Error>> {
    let takeover_config = RouteSupervisorConfigV1::new(100, 40, 20, 8)?;
    let mut fixture = Fixture::with_config(takeover_config);
    fixture.arm();
    fixture.authorize(fixture.runner_intent(LegIdV1::Upstream, ActionKindV1::Funding, 110));
    let old_lease = fixture.supervisor.lease_status();
    let old_effect = fixture
        .supervisor
        .snapshot()?
        .upstream
        .funding
        .effect()
        .expect("old effect")
        .effect_id;
    fixture.clock.advance(101)?;
    let second_store = DurableRouteStoreV1::open(&fixture.database)?;
    let mut takeover = RouteSupervisorV1::acquire(
        second_store,
        ROUTE,
        OWNER_B,
        takeover_config,
        fixture.clock.clone(),
    )?;
    assert_eq!(
        takeover.lease_status().fencing_epoch(),
        old_lease.fencing_epoch() + 1
    );
    assert!(matches!(
        fixture
            .supervisor
            .schedule_timer(id(181), TimerKindV1::Retry, 500, id(182),),
        Err(RouteSupervisorErrorV1::Store(
            RouteStoreErrorV1::StaleFencing
        ))
    ));

    let mut runner = IdempotentRunner::default();
    let before = takeover.tick(
        &mut runner,
        &mut IdempotentCustody::default(),
        &mut inert_timer(),
    )?;
    assert_eq!(before.runner_externalized, 0);
    assert_eq!(runner.calls, 0, "new fence cannot blindly send old effect");

    let mut reconciler = ProveNotExternalized { calls: 0 };
    let report = takeover.reconcile_takeover(&mut reconciler)?;
    assert_eq!(
        (report.reauthorized, report.externalized, report.unknown),
        (1, 0, 0)
    );
    assert_eq!(reconciler.calls, 1);
    let replacement = takeover
        .snapshot()?
        .upstream
        .funding
        .effect()
        .expect("replacement effect")
        .clone();
    assert_ne!(replacement.effect_id, old_effect);
    assert_eq!(
        replacement.fencing_epoch,
        takeover.lease_status().fencing_epoch()
    );
    assert_eq!(takeover.pending_effect_count()?, 1);
    fixture.clock.advance(21)?;
    assert_eq!(
        takeover
            .tick(
                &mut runner,
                &mut IdempotentCustody::default(),
                &mut inert_timer(),
            )?
            .runner_externalized,
        1
    );
    assert_eq!(runner.calls, 1);
    Ok(())
}

#[test]
fn takeover_externalized_proof_checks_expected_tx_and_records_secret_without_rebroadcast(
) -> Result<(), Box<dyn Error>> {
    let takeover_config = RouteSupervisorConfigV1::new(100, 40, 20, 8)?;
    let mut fixture = Fixture::with_config(takeover_config);
    fixture.arm();
    fixture.finalize_funding(LegIdV1::Upstream, 131);
    fixture.finalize_funding(LegIdV1::Downstream, 134);
    let claim = fixture.custody_claim(LegIdV1::Downstream, 137);
    let expected_tx = match claim.dispatch {
        EffectDispatchV1::ExternalCustody { transaction_id, .. } => transaction_id,
        EffectDispatchV1::RunnerPayload { .. } => unreachable!("custody claim"),
    };
    fixture.authorize(claim);
    assert!(matches!(
        fixture.supervisor.snapshot()?.secret_visibility,
        route_executor::SecretVisibilityV1::Private
    ));

    // The old custody authority has durably externalized its expected
    // transaction but its receipt was lost before the supervisor event.
    fixture.clock.advance(101)?;
    let second_store = DurableRouteStoreV1::open(&fixture.database)?;
    let mut takeover = RouteSupervisorV1::acquire(
        second_store,
        ROUTE,
        OWNER_B,
        takeover_config,
        fixture.clock.clone(),
    )?;

    let mut wrong = ProveExternalized {
        receipt: ActionExternalizationReceiptV1::secret_revealing(id(199), id(140), id(141)),
        calls: 0,
    };
    assert!(matches!(
        takeover.reconcile_takeover(&mut wrong),
        Err(RouteSupervisorErrorV1::ExpectedTransactionMismatch)
    ));
    assert!(matches!(
        takeover.snapshot()?.downstream.claim,
        ActionStateV1::Committed(_)
    ));
    assert_eq!(takeover.pending_effect_count()?, 1);

    let chain_id = id(140);
    let evidence_digest = id(141);
    let mut reconciler = ProveExternalized {
        receipt: ActionExternalizationReceiptV1::secret_revealing(
            expected_tx,
            chain_id,
            evidence_digest,
        ),
        calls: 0,
    };
    let report = takeover.reconcile_takeover(&mut reconciler)?;
    assert_eq!(
        (report.externalized, report.reauthorized, report.unknown),
        (1, 0, 0)
    );
    assert_eq!(reconciler.calls, 1);
    assert_eq!(takeover.pending_effect_count()?, 0);
    let snapshot = takeover.snapshot()?;
    assert_eq!(
        snapshot.downstream.claim.transaction_id(),
        Some(expected_tx)
    );
    assert!(matches!(
        snapshot.secret_visibility,
        route_executor::SecretVisibilityV1::Public {
            first_exposure: PublicExposureV1 {
                source: ExposureSourceV1::Externalized,
                chain_id: observed_chain,
                transaction_id: observed_tx,
                evidence_digest: observed_evidence,
                observed_at_unix_ms: 201,
            }
        } if observed_chain == chain_id
            && observed_tx == expected_tx
            && observed_evidence == evidence_digest
    ));

    let mut custody = IdempotentCustody::default();
    let tick = takeover.tick(
        &mut IdempotentRunner::default(),
        &mut custody,
        &mut inert_timer(),
    )?;
    assert_eq!(tick.urgent_externalized + tick.custody_externalized, 0);
    assert_eq!(
        custody.calls, 0,
        "reconciled tx must not be broadcast again"
    );
    Ok(())
}

#[test]
fn partially_externalized_custody_refences_without_faking_aggregate_externalization(
) -> Result<(), Box<dyn Error>> {
    let takeover_config = RouteSupervisorConfigV1::new(100, 40, 20, 8)?;
    let mut fixture = Fixture::with_config(takeover_config);
    fixture.arm();
    fixture.finalize_funding(LegIdV1::Upstream, 0xc0);
    fixture.finalize_funding(LegIdV1::Downstream, 0xc1);
    fixture.authorize(fixture.custody_claim(LegIdV1::Downstream, 0xc2));
    let old_effect = fixture
        .supervisor
        .snapshot()?
        .downstream
        .claim
        .effect()
        .expect("old aggregate claim")
        .clone();

    fixture.clock.advance(101)?;
    let second_store = DurableRouteStoreV1::open(&fixture.database)?;
    let mut takeover = RouteSupervisorV1::acquire(
        second_store,
        ROUTE,
        OWNER_B,
        takeover_config,
        fixture.clock.clone(),
    )?;
    let mut reconciler = ResumePartialCustody { calls: 0 };
    let report = takeover.reconcile_takeover(&mut reconciler)?;
    assert_eq!(report.partial_custody_resumed, 1);
    assert_eq!(
        (report.externalized, report.reauthorized, report.unknown),
        (0, 0, 0)
    );
    assert_eq!(reconciler.calls, 1);

    let snapshot = takeover.snapshot()?;
    assert!(matches!(
        snapshot.secret_visibility,
        route_executor::SecretVisibilityV1::Private
    ));
    let replacement = snapshot
        .downstream
        .claim
        .effect()
        .expect("resumed aggregate claim");
    assert_ne!(replacement.effect_id, old_effect.effect_id);
    assert_eq!(
        replacement.fencing_epoch,
        takeover.lease_status().fencing_epoch()
    );
    assert_eq!(takeover.pending_effect_count()?, 1);
    assert!(takeover.journal()?.iter().any(|entry| matches!(
        entry.event,
        RouteEventV1::ReauthorizePartiallyExternalizedCustody { .. }
    )));

    fixture.clock.advance(21)?;
    let mut custody = IdempotentCustody::default();
    let tick = takeover.tick(
        &mut IdempotentRunner::default(),
        &mut custody,
        &mut inert_timer(),
    )?;
    assert_eq!(tick.custody_externalized, 1);
    assert_eq!(custody.calls, 1);
    assert_eq!(custody.acknowledged_progress, vec![Some(id(0xc7))]);
    assert!(matches!(
        takeover.snapshot()?.secret_visibility,
        route_executor::SecretVisibilityV1::Public { .. }
    ));
    Ok(())
}

#[test]
fn stale_fence_urgent_claim_requires_reconciliation_and_unknown_keeps_signal(
) -> Result<(), Box<dyn Error>> {
    let takeover_config = RouteSupervisorConfigV1::new(100, 40, 20, 8)?;
    let mut fixture = Fixture::with_config(takeover_config);
    fixture.arm();
    fixture.finalize_funding(LegIdV1::Upstream, 142);
    fixture.finalize_funding(LegIdV1::Downstream, 145);
    fixture.observe_secret(PublicExposureV1 {
        source: ExposureSourceV1::Block,
        chain_id: id(148),
        transaction_id: id(149),
        evidence_digest: id(150),
        observed_at_unix_ms: 100,
    });
    fixture.authorize(fixture.custody_claim(LegIdV1::Upstream, 151));
    let old_reference = fixture
        .supervisor
        .snapshot()?
        .upstream
        .claim
        .effect()
        .expect("urgent claim")
        .clone();

    fixture.clock.advance(101)?;
    let second_store = DurableRouteStoreV1::open(&fixture.database)?;
    let mut takeover = RouteSupervisorV1::acquire(
        second_store,
        ROUTE,
        OWNER_B,
        takeover_config,
        fixture.clock.clone(),
    )?;
    assert!(old_reference.fencing_epoch < takeover.lease_status().fencing_epoch());
    let mut custody = IdempotentCustody::default();
    let blocked = takeover.tick(
        &mut IdempotentRunner::default(),
        &mut custody,
        &mut inert_timer(),
    )?;
    assert!(blocked.takeover_reconciliation_required);
    assert!(!blocked.urgent_in_flight);
    assert_eq!(custody.calls, 0);

    let mut unknown = UnknownReconciliation { calls: 0 };
    let unknown_report = takeover.reconcile_takeover(&mut unknown)?;
    assert_eq!(unknown_report.unknown, 1);
    assert_eq!(unknown.calls, 1);
    let still_blocked = takeover.tick(
        &mut IdempotentRunner::default(),
        &mut custody,
        &mut inert_timer(),
    )?;
    assert!(still_blocked.takeover_reconciliation_required);
    assert_eq!(custody.calls, 0);

    let mut safe = ProveNotExternalized { calls: 0 };
    let reconciliation = takeover.reconcile_takeover(&mut safe)?;
    assert_eq!(reconciliation.reauthorized, 1);
    assert_eq!(safe.calls, 1);
    let dispatched = takeover.tick(
        &mut IdempotentRunner::default(),
        &mut custody,
        &mut inert_timer(),
    )?;
    assert_eq!(dispatched.urgent_externalized, 1);
    assert!(!dispatched.takeover_reconciliation_required);
    assert_eq!(custody.calls, 1);
    Ok(())
}

#[test]
fn takeover_journals_secret_child_before_refencing_incomplete_aggregate(
) -> Result<(), Box<dyn Error>> {
    let takeover_config = RouteSupervisorConfigV1::new(100, 40, 20, 8)?;
    let mut fixture = Fixture::with_config(takeover_config);
    fixture.arm();
    fixture.finalize_funding(LegIdV1::Upstream, 0xe0);
    fixture.finalize_funding(LegIdV1::Downstream, 0xe1);
    fixture.authorize(fixture.custody_claim(LegIdV1::Downstream, 0xe2));
    let old_effect = fixture
        .supervisor
        .snapshot()?
        .downstream
        .claim
        .effect()
        .expect("old aggregate claim")
        .clone();
    let progress_evidence_digest = id(0xe5);
    let child_exposure = PublicExposureV1 {
        source: ExposureSourceV1::Externalized,
        chain_id: id(0xe6),
        transaction_id: id(0xe7),
        evidence_digest: id(0xe8),
        observed_at_unix_ms: 100,
    };

    fixture.clock.advance(101)?;
    let second_store = DurableRouteStoreV1::open(&fixture.database)?;
    let mut takeover = RouteSupervisorV1::acquire(
        second_store,
        ROUTE,
        OWNER_B,
        takeover_config,
        fixture.clock.clone(),
    )?;
    let mut reconciler = ResumeSecretPartialCustody {
        calls: 0,
        progress_evidence_digest,
        exposure: child_exposure.clone(),
    };
    let report = takeover.reconcile_takeover(&mut reconciler)?;
    assert_eq!(report.partial_secret_custody_resumed, 1);
    assert_eq!(report.partial_custody_resumed, 0);
    assert_eq!(reconciler.calls, 1);

    let snapshot = takeover.snapshot()?;
    let replacement = snapshot
        .downstream
        .claim
        .effect()
        .expect("resumed aggregate claim");
    assert_ne!(replacement.effect_id, old_effect.effect_id);
    assert_eq!(
        replacement.fencing_epoch,
        takeover.lease_status().fencing_epoch()
    );
    assert!(matches!(
        snapshot.downstream.claim,
        ActionStateV1::Committed(_)
    ));
    assert_eq!(
        snapshot.secret_visibility,
        route_executor::SecretVisibilityV1::Public {
            first_exposure: child_exposure
        }
    );
    assert_eq!(takeover.pending_effect_count()?, 1);
    let journal = takeover.journal()?;
    let progress_position = journal
        .iter()
        .position(|entry| matches!(entry.event, RouteEventV1::CustodyProgressRecorded { .. }))
        .expect("partial secret progress journaled");
    let refence_position = journal
        .iter()
        .position(|entry| {
            matches!(
                entry.event,
                RouteEventV1::ReauthorizePartiallyExternalizedCustody { .. }
            )
        })
        .expect("aggregate refenced");
    assert!(progress_position < refence_position);
    Ok(())
}

#[test]
fn secret_public_urgent_action_precedes_timer_then_merged_normal_effects(
) -> Result<(), Box<dyn Error>> {
    let mut fixture = Fixture::new();
    fixture.arm();
    fixture.finalize_funding(LegIdV1::Upstream, 120);
    fixture.finalize_funding(LegIdV1::Downstream, 121);
    fixture.schedule_timer(TimerKindV1::Deadline, 100, id(123));
    fixture.authorize(fixture.custody_intent(
        LegIdV1::Downstream,
        ActionKindV1::Refund,
        124,
        false,
    ));
    fixture.observe_secret(PublicExposureV1 {
        source: ExposureSourceV1::PeerEvidence,
        chain_id: id(125),
        transaction_id: id(126),
        evidence_digest: id(127),
        observed_at_unix_ms: 100,
    });
    fixture.authorize(fixture.custody_claim(LegIdV1::Upstream, 128));
    assert!(matches!(
        fixture.supervisor.snapshot()?.upstream.claim,
        ActionStateV1::Committed(_)
    ));

    let order = Arc::new(Mutex::new(Vec::new()));
    let mut runner = IdempotentRunner {
        order: Some(order.clone()),
        ..IdempotentRunner::default()
    };
    let mut custody = IdempotentCustody {
        order: Some(order.clone()),
        ..IdempotentCustody::default()
    };
    let mut timer = DeterministicTimer {
        event: RouteEventV1::SetHealth {
            target: HealthStateV1::Running,
            reason_digest: id(129),
        },
        fail_commit_barrier_once: false,
        event_calls: 0,
        commit_calls: 0,
        order: Some(order.clone()),
    };

    let mut unavailable = UnavailableCustody::default();
    assert!(matches!(
        fixture
            .supervisor
            .tick(&mut runner, &mut unavailable, &mut timer),
        Err(RouteSupervisorErrorV1::ExternalCustodyAuthority(
            AuthorityRefusalV1::Unavailable
        ))
    ));
    assert_eq!(unavailable.calls, 1);
    let in_flight = fixture
        .supervisor
        .tick(&mut runner, &mut custody, &mut timer)?;
    assert!(in_flight.urgent_in_flight);
    assert_eq!(custody.calls, 0);
    assert_eq!(timer.event_calls, 0);
    fixture.clock.advance(101)?;
    let urgent = fixture
        .supervisor
        .tick(&mut runner, &mut custody, &mut timer)?;
    assert_eq!(urgent.urgent_externalized, 1);
    assert_eq!(*order.lock().expect("order lock"), vec!["urgent"]);
    let normal = fixture
        .supervisor
        .tick(&mut runner, &mut custody, &mut timer)?;
    assert_eq!(
        (normal.timers_completed, normal.custody_externalized),
        (1, 1)
    );
    assert_eq!(
        *order.lock().expect("order lock"),
        vec!["urgent", "timer", "custody"]
    );
    assert!(matches!(
        fixture.supervisor.snapshot()?.secret_visibility,
        route_executor::SecretVisibilityV1::Public { .. }
    ));
    Ok(())
}
