use std::path::{Path, PathBuf};
#[cfg(target_os = "linux")]
use std::{fs, os::unix::fs::PermissionsExt};

use route_executor::{
    digest_bytes_v1, ActionIntentV1, ActionKindV1, ActionProgressV1, ActionStateV1,
    ClaimedRouteWorkV1, CommitOutcomeV1, CompletionOutcomeV1, DurableRouteStoreV1,
    EffectDispatchV1, EffectPriorityV1, ExposureSourceV1, FrozenBindingsV1,
    FrozenRouteAdmissionCheckpointV2, FrozenRouteTimeFactsV2, HealthStateV1, LeaseAcquireOutcomeV1,
    LegIdV1, PublicExposureV1, RefundBindingsV1, RouteEventV1, RouteInventoryReleaseDispositionV1,
    RouteLeaseV1, RouteSnapshotV1, RouteStoreErrorV1, SecretVisibilityV1, TimerKindV1,
};
use tempfile::TempDir;

fn id(value: u8) -> [u8; 32] {
    [value; 32]
}

fn frozen_admission_v2() -> FrozenRouteAdmissionCheckpointV2 {
    FrozenRouteAdmissionCheckpointV2 {
        network_id: id(100),
        route_id: id(1),
        bindings: FrozenBindingsV1 {
            terms_digest: id(101),
            profile_bundle_digest: id(102),
            deployment_bundle_digest: id(103),
        },
        composition_v2_digest: id(104),
        registry_epoch: 7,
        registry_manifest_digest: id(103),
        upstream_terms_digest: id(105),
        downstream_terms_digest: id(106),
        upstream_roster_snapshot: id(107),
        downstream_roster_snapshot: id(108),
        participant_bindings_digest: id(109),
        relay_binding_digest: id(110),
        registry_authority_set_digest: id(111),
        time_policy_authority_set_digest: id(112),
        time_evidence_authority_set_digest: id(113),
        time: FrozenRouteTimeFactsV2 {
            route_scope_digest: id(114),
            policy_digest: id(115),
            evidence_digest: id(116),
            proof_digest: id(117),
            evidence_sequence: 1,
            issued_at_seconds: 1_000,
            valid_until_seconds: 2_000,
            validated_at_seconds: 1_100,
        },
    }
}

struct Fixture {
    _directory: TempDir,
    database: PathBuf,
    store: DurableRouteStoreV1,
    lease: RouteLeaseV1,
    revision: u64,
    next_event: u8,
    now: u64,
}

impl Fixture {
    fn new(lease_duration_ms: u64) -> Self {
        let directory = tempfile::tempdir().expect("temporary directory");
        #[cfg(target_os = "linux")]
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))
            .expect("owner-only temporary directory");
        let database = directory.path().join("route.sqlite3");
        let mut store = DurableRouteStoreV1::create(&database).expect("create store");
        store.create_route(id(1), 1).expect("create route");
        let lease = store
            .acquire_lease(id(1), id(2), 2, lease_duration_ms)
            .expect("acquire route")
            .lease();
        Self {
            _directory: directory,
            database,
            store,
            lease,
            revision: 0,
            next_event: 10,
            now: 3,
        }
    }

    fn apply(&mut self, event: RouteEventV1) -> CommitOutcomeV1 {
        let event_id = id(self.next_event);
        self.next_event = self.next_event.checked_add(1).expect("test event id");
        self.now = self.now.checked_add(1).expect("test time");
        let outcome = self
            .store
            .apply_event(self.lease, self.revision, event_id, &event, self.now)
            .expect("commit event");
        match outcome {
            CommitOutcomeV1::Committed { revision, .. } => self.revision = revision,
            CommitOutcomeV1::DuplicateSameBytes { .. } => panic!("unexpected duplicate"),
        }
        outcome
    }

    fn arm_refunds(&mut self) {
        self.apply(RouteEventV1::FreezeTerms(FrozenBindingsV1 {
            terms_digest: id(20),
            profile_bundle_digest: id(21),
            deployment_bundle_digest: id(22),
        }));
        self.apply(RouteEventV1::ArmRefunds(RefundBindingsV1 {
            upstream_refund_digest: id(23),
            downstream_refund_digest: id(24),
        }));
    }

    fn arm_refunds_v2(&mut self) {
        self.apply(RouteEventV1::FreezeTermsV2(Box::new(frozen_admission_v2())));
        self.apply(RouteEventV1::ArmRefunds(RefundBindingsV1 {
            upstream_refund_digest: id(23),
            downstream_refund_digest: id(24),
        }));
    }

    fn runner_intent(&self, leg: LegIdV1, kind: ActionKindV1, value: u8) -> ActionIntentV1 {
        let payload = vec![value; 24];
        ActionIntentV1 {
            leg,
            kind,
            semantic_digest: id(value),
            contains_route_secret: false,
            dispatch: EffectDispatchV1::RunnerPayload {
                payload_digest: digest_bytes_v1(&payload),
                payload,
            },
        }
    }

    fn external_claim_intent(&self, leg: LegIdV1, value: u8) -> ActionIntentV1 {
        ActionIntentV1 {
            leg,
            kind: ActionKindV1::Claim,
            semantic_digest: id(value),
            contains_route_secret: true,
            dispatch: EffectDispatchV1::ExternalCustody {
                custody_digest: id(value.wrapping_add(1)),
                transaction_id: id(value.wrapping_add(2)),
            },
        }
    }

    fn external_refund_intent(&self, leg: LegIdV1, value: u8) -> ActionIntentV1 {
        ActionIntentV1 {
            leg,
            kind: ActionKindV1::Refund,
            semantic_digest: id(value),
            contains_route_secret: false,
            dispatch: EffectDispatchV1::ExternalCustody {
                custody_digest: id(value.wrapping_add(1)),
                transaction_id: id(value.wrapping_add(2)),
            },
        }
    }

    fn fund_and_finalize(&mut self, leg: LegIdV1, value: u8) -> [u8; 32] {
        self.apply(RouteEventV1::CommitAction(self.runner_intent(
            leg,
            ActionKindV1::Funding,
            value,
        )));
        let snapshot = self.store.load_snapshot(id(1)).expect("snapshot");
        let effect_id = match snapshot.leg(leg).funding {
            ActionStateV1::Committed(ref effect) => effect.effect_id,
            _ => panic!("funding effect must be committed"),
        };
        let transaction_id = id(value.wrapping_add(1));
        self.apply(RouteEventV1::ActionExternalized {
            leg,
            kind: ActionKindV1::Funding,
            effect_id,
            transaction_id,
            exposure: None,
        });
        self.apply(RouteEventV1::ActionFinalized {
            leg,
            kind: ActionKindV1::Funding,
            transaction_id,
            evidence_digest: id(value.wrapping_add(2)),
        });
        transaction_id
    }

    fn claim_and_finalize(&mut self, leg: LegIdV1, value: u8, exposure: Option<PublicExposureV1>) {
        let intent = self.external_claim_intent(leg, value);
        let transaction_id = match intent.dispatch {
            EffectDispatchV1::ExternalCustody { transaction_id, .. } => transaction_id,
            EffectDispatchV1::RunnerPayload { .. } => unreachable!("custody claim"),
        };
        self.apply(RouteEventV1::CommitAction(intent));
        let effect_id = self
            .store
            .load_snapshot(id(1))
            .expect("claim snapshot")
            .leg(leg)
            .claim
            .effect()
            .expect("claim effect")
            .effect_id;
        self.apply(RouteEventV1::ActionExternalized {
            leg,
            kind: ActionKindV1::Claim,
            effect_id,
            transaction_id,
            exposure,
        });
        self.apply(RouteEventV1::ActionFinalized {
            leg,
            kind: ActionKindV1::Claim,
            transaction_id,
            evidence_digest: id(value.wrapping_add(3)),
        });
    }

    fn refund_and_finalize(&mut self, leg: LegIdV1, value: u8) {
        let intent = self.external_refund_intent(leg, value);
        let transaction_id = match intent.dispatch {
            EffectDispatchV1::ExternalCustody { transaction_id, .. } => transaction_id,
            EffectDispatchV1::RunnerPayload { .. } => unreachable!("custody refund"),
        };
        self.apply(RouteEventV1::CommitAction(intent));
        let effect_id = self
            .store
            .load_snapshot(id(1))
            .expect("refund snapshot")
            .leg(leg)
            .refund
            .effect()
            .expect("refund effect")
            .effect_id;
        self.apply(RouteEventV1::ActionExternalized {
            leg,
            kind: ActionKindV1::Refund,
            effect_id,
            transaction_id,
            exposure: None,
        });
        self.apply(RouteEventV1::ActionFinalized {
            leg,
            kind: ActionKindV1::Refund,
            transaction_id,
            evidence_digest: id(value.wrapping_add(3)),
        });
    }
}

#[test]
fn retirement_capability_requires_v2_public_and_both_terminal_without_open_funds() {
    let mut fixture = Fixture::new(10_000);
    fixture.arm_refunds_v2();
    fixture.fund_and_finalize(LegIdV1::Upstream, 30);
    fixture.fund_and_finalize(LegIdV1::Downstream, 40);
    assert_eq!(
        fixture
            .store
            .mint_route_secret_retirement_capability_v1(id(1))
            .map(|_| ()),
        Err(RouteStoreErrorV1::SecretRetirementUnavailable)
    );
    let downstream_tx = id(52);
    let exposure = PublicExposureV1 {
        source: ExposureSourceV1::Externalized,
        chain_id: id(71),
        transaction_id: downstream_tx,
        evidence_digest: id(72),
        observed_at_unix_ms: 100,
    };
    fixture.claim_and_finalize(LegIdV1::Downstream, 50, Some(exposure.clone()));
    assert_eq!(
        fixture
            .store
            .mint_route_secret_retirement_capability_v1(id(1))
            .map(|_| ()),
        Err(RouteStoreErrorV1::SecretRetirementUnavailable)
    );
    fixture.claim_and_finalize(LegIdV1::Upstream, 60, None);
    let capability = fixture
        .store
        .mint_route_secret_retirement_capability_v1(id(1))
        .expect("fully terminal authenticated capability");
    assert_eq!(capability.route_id(), id(1));
    assert_eq!(capability.composition_v2_digest(), id(104));
    assert_eq!(capability.first_exposure(), &exposure);
}

#[test]
fn inventory_release_requires_authenticated_terminal_replay_or_explicit_unfunded_abort() {
    let mut settled = Fixture::new(10_000);
    settled.arm_refunds_v2();
    assert_eq!(
        settled
            .store
            .mint_route_inventory_release_capability_v1(id(1))
            .map(|_| ()),
        Err(RouteStoreErrorV1::InventoryReleaseUnavailable)
    );
    settled.fund_and_finalize(LegIdV1::Upstream, 30);
    settled.fund_and_finalize(LegIdV1::Downstream, 40);
    settled.refund_and_finalize(LegIdV1::Downstream, 50);
    assert_eq!(
        settled
            .store
            .mint_route_inventory_release_capability_v1(id(1))
            .map(|_| ()),
        Err(RouteStoreErrorV1::InventoryReleaseUnavailable)
    );
    settled.refund_and_finalize(LegIdV1::Upstream, 60);
    let terminal = settled
        .store
        .mint_route_inventory_release_capability_v1(id(1))
        .expect("two-leg terminal inventory release");
    assert_eq!(terminal.route_id(), id(1));
    assert_eq!(terminal.composition_v2_digest(), id(104));
    assert_eq!(
        terminal.disposition(),
        RouteInventoryReleaseDispositionV1::BothLegsTerminal
    );
    assert_ne!(terminal.release_evidence_digest(), [0; 32]);

    let mut aborted = Fixture::new(10_000);
    aborted.apply(RouteEventV1::FreezeTermsV2(Box::new(frozen_admission_v2())));
    aborted.apply(RouteEventV1::AbortUnfunded {
        reason_digest: id(70),
    });
    let unfunded = aborted
        .store
        .mint_route_inventory_release_capability_v1(id(1))
        .expect("explicit unfunded abort release");
    assert_eq!(
        unfunded.disposition(),
        RouteInventoryReleaseDispositionV1::AbortedUnfunded
    );
    assert_ne!(
        terminal.release_evidence_digest(),
        unfunded.release_evidence_digest()
    );

    let mut legacy = Fixture::new(10_000);
    legacy.apply(RouteEventV1::FreezeTerms(FrozenBindingsV1 {
        terms_digest: id(71),
        profile_bundle_digest: id(72),
        deployment_bundle_digest: id(73),
    }));
    legacy.apply(RouteEventV1::AbortUnfunded {
        reason_digest: id(74),
    });
    assert_eq!(
        legacy
            .store
            .mint_route_inventory_release_capability_v1(id(1))
            .map(|_| ()),
        Err(RouteStoreErrorV1::AdmissionCheckpointUnavailable)
    );
}

fn reopen(path: &Path) -> DurableRouteStoreV1 {
    DurableRouteStoreV1::open_existing(path).expect("reopen route store")
}

#[test]
fn journal_replay_matches_the_materialized_multidimensional_snapshot() {
    let mut fixture = Fixture::new(10_000);
    fixture.arm_refunds();
    fixture.fund_and_finalize(LegIdV1::Upstream, 30);
    fixture.fund_and_finalize(LegIdV1::Downstream, 40);

    let replayed = fixture.store.verify_replay(id(1)).expect("verified replay");
    let materialized = fixture.store.load_snapshot(id(1)).expect("snapshot");
    assert_eq!(replayed, materialized);
    assert_eq!(fixture.store.journal(id(1)).expect("journal").len(), 8);
    assert_eq!(materialized.revision, 8);
    assert_eq!(
        materialized.downstream.funding.progress(),
        ActionProgressV1::Final
    );
}

#[test]
fn production_external_custody_audit_accepts_only_custody_history_after_restart() {
    let mut fixture = Fixture::new(10_000);
    fixture.arm_refunds();
    fixture.apply(RouteEventV1::CommitAction(ActionIntentV1 {
        leg: LegIdV1::Upstream,
        kind: ActionKindV1::Funding,
        semantic_digest: id(31),
        contains_route_secret: false,
        dispatch: EffectDispatchV1::ExternalCustody {
            custody_digest: id(32),
            transaction_id: id(33),
        },
    }));
    let expected = fixture.store.load_snapshot(id(1)).expect("snapshot");
    assert_eq!(
        fixture.store.audit_external_custody_only_v1(id(1)),
        Ok(expected.clone())
    );

    let database = fixture.database.clone();
    drop(fixture.store);
    assert_eq!(
        reopen(&database).audit_external_custody_only_v1(id(1)),
        Ok(expected)
    );
}

#[test]
fn production_external_custody_audit_rejects_completed_historical_runner_effect() {
    let mut fixture = Fixture::new(10_000);
    fixture.arm_refunds();
    fixture.fund_and_finalize(LegIdV1::Upstream, 30);
    assert_eq!(
        fixture.store.audit_external_custody_only_v1(id(1)),
        Err(RouteStoreErrorV1::CorruptState)
    );

    let database = fixture.database.clone();
    drop(fixture.store);
    assert_eq!(
        reopen(&database).audit_external_custody_only_v1(id(1)),
        Err(RouteStoreErrorV1::CorruptState)
    );
}

#[test]
fn v2_admission_checkpoint_is_replayed_exactly_and_v1_never_becomes_a_recovery_checkpoint() {
    let mut fixture = Fixture::new(10_000);
    let checkpoint = frozen_admission_v2();
    fixture.apply(RouteEventV1::FreezeTermsV2(Box::new(checkpoint.clone())));
    assert_eq!(
        fixture.store.audit_frozen_admission_checkpoint_v2(id(1)),
        Ok(checkpoint.clone())
    );
    let database = fixture.database.clone();
    drop(fixture.store);
    let reopened = reopen(&database);
    assert_eq!(
        reopened.audit_frozen_admission_checkpoint_v2(id(1)),
        Ok(checkpoint)
    );

    let mut legacy = Fixture::new(10_000);
    legacy.apply(RouteEventV1::FreezeTerms(FrozenBindingsV1 {
        terms_digest: id(120),
        profile_bundle_digest: id(121),
        deployment_bundle_digest: id(122),
    }));
    assert_eq!(
        legacy.store.audit_frozen_admission_checkpoint_v2(id(1)),
        Err(RouteStoreErrorV1::AdmissionCheckpointUnavailable)
    );
}

#[test]
fn v2_admission_checkpoint_audit_rejects_journal_and_snapshot_tamper() {
    let mut journal_fixture = Fixture::new(10_000);
    journal_fixture.apply(RouteEventV1::FreezeTermsV2(Box::new(frozen_admission_v2())));
    let journal_database = journal_fixture.database.clone();
    drop(journal_fixture.store);
    let raw = rusqlite::Connection::open(&journal_database).expect("tamper connection");
    raw.execute(
        "UPDATE route_journal SET entry_hash = ?1 WHERE route_id = ?2 AND sequence = 1",
        rusqlite::params![id(123).as_slice(), id(1).as_slice()],
    )
    .expect("tamper journal hash");
    drop(raw);
    assert_eq!(
        DurableRouteStoreV1::open_existing(&journal_database)
            .expect_err("restart must reject tampered journal"),
        RouteStoreErrorV1::CorruptState
    );

    let mut snapshot_fixture = Fixture::new(10_000);
    snapshot_fixture.apply(RouteEventV1::FreezeTermsV2(Box::new(frozen_admission_v2())));
    let snapshot_database = snapshot_fixture.database.clone();
    drop(snapshot_fixture.store);
    let raw = rusqlite::Connection::open(&snapshot_database).expect("tamper connection");
    raw.execute(
        "UPDATE route_snapshots SET snapshot_hash = ?1 WHERE route_id = ?2",
        rusqlite::params![id(124).as_slice(), id(1).as_slice()],
    )
    .expect("tamper snapshot hash");
    drop(raw);
    assert_eq!(
        DurableRouteStoreV1::open_existing(&snapshot_database)
            .expect_err("restart must reject tampered snapshot"),
        RouteStoreErrorV1::CorruptState
    );
}

#[test]
fn duplicate_is_an_idempotent_ack_and_conflicting_bytes_fail_closed() {
    let mut fixture = Fixture::new(10_000);
    let event_id = id(90);
    let freeze = RouteEventV1::FreezeTerms(FrozenBindingsV1 {
        terms_digest: id(3),
        profile_bundle_digest: id(4),
        deployment_bundle_digest: id(5),
    });
    assert_eq!(
        fixture
            .store
            .apply_event(fixture.lease, 0, event_id, &freeze, 3)
            .expect("first commit"),
        CommitOutcomeV1::Committed {
            revision: 1,
            effects_created: 0,
            timers_created: 0,
        }
    );
    assert_eq!(
        fixture
            .store
            .apply_event(fixture.lease, 0, event_id, &freeze, 4)
            .expect("duplicate ack"),
        CommitOutcomeV1::DuplicateSameBytes { revision: 1 }
    );
    let arm = RouteEventV1::ArmRefunds(RefundBindingsV1 {
        upstream_refund_digest: id(7),
        downstream_refund_digest: id(8),
    });
    assert_eq!(
        fixture.store.apply_event(fixture.lease, 0, id(91), &arm, 4),
        Err(RouteStoreErrorV1::RevisionConflict)
    );

    let conflict = RouteEventV1::FreezeTerms(FrozenBindingsV1 {
        terms_digest: id(6),
        profile_bundle_digest: id(4),
        deployment_bundle_digest: id(5),
    });
    assert_eq!(
        fixture
            .store
            .apply_event(fixture.lease, 1, event_id, &conflict, 5),
        Err(RouteStoreErrorV1::IdempotencyConflict)
    );
    assert_eq!(
        fixture
            .store
            .load_snapshot(id(1))
            .expect("snapshot")
            .revision,
        1
    );
    assert_eq!(fixture.store.journal(id(1)).expect("journal").len(), 1);
}

#[test]
fn committed_effect_survives_reopen_and_is_never_visible_before_its_decision() {
    let mut fixture = Fixture::new(10_000);
    fixture.arm_refunds();
    assert_eq!(fixture.store.pending_effect_count(id(1)), Ok(0));

    let funding_event = RouteEventV1::CommitAction(fixture.runner_intent(
        LegIdV1::Upstream,
        ActionKindV1::Funding,
        50,
    ));
    let outcome = fixture.apply(funding_event.clone());
    assert_eq!(
        outcome,
        CommitOutcomeV1::Committed {
            revision: 3,
            effects_created: 1,
            timers_created: 0,
        }
    );
    assert_eq!(fixture.store.pending_effect_count(id(1)), Ok(1));
    assert_eq!(
        fixture
            .store
            .apply_event(fixture.lease, 2, id(12), &funding_event, fixture.now + 1),
        Ok(CommitOutcomeV1::DuplicateSameBytes { revision: 3 })
    );
    assert_eq!(fixture.store.pending_effect_count(id(1)), Ok(1));
    assert_eq!(fixture.store.journal(id(1)).expect("journal").len(), 3);
    assert_eq!(
        fixture
            .store
            .load_snapshot(id(1))
            .expect("snapshot")
            .revision,
        3
    );

    let lease = fixture.lease;
    let database = fixture.database.clone();
    drop(fixture.store);
    let mut store = reopen(&database);
    assert_eq!(store.verify_replay(id(1)).expect("replay").revision, 3);
    assert_eq!(store.pending_effect_count(id(1)), Ok(1));
    let effect_id = store
        .load_snapshot(id(1))
        .expect("snapshot")
        .upstream
        .funding
        .effect()
        .expect("committed effect")
        .effect_id;
    let recovered_intent = store
        .committed_action_intent(lease, effect_id, 9)
        .expect("intent survives reopen");
    assert_eq!(
        recovered_intent,
        match &funding_event {
            RouteEventV1::CommitAction(intent) => intent.clone(),
            _ => panic!("funding event"),
        }
    );
    assert_eq!(
        store.committed_action_intent(lease, id(86), 9),
        Err(RouteStoreErrorV1::EffectNotFound)
    );
    let claimed = store
        .claim_effects(lease, 10, 100, 4)
        .expect("claim committed effect");
    assert_eq!(claimed.len(), 1);
    assert_eq!(claimed[0].effect.fencing_epoch, lease.fencing_epoch);
    assert_eq!(claimed[0].attempts, 1);
    assert_eq!(
        store.apply_event(
            lease,
            3,
            id(89),
            &RouteEventV1::ActionFinalized {
                leg: LegIdV1::Upstream,
                kind: ActionKindV1::Funding,
                transaction_id: id(88),
                evidence_digest: id(87),
            },
            11,
        ),
        Err(RouteStoreErrorV1::TransitionRejected)
    );
    assert_eq!(store.pending_effect_count(id(1)), Ok(1));
    assert_eq!(
        store
            .load_snapshot(id(1))
            .expect("dispatch claim is not externalization")
            .upstream
            .funding
            .progress(),
        ActionProgressV1::Committed
    );
    assert_eq!(
        store.apply_event(
            lease,
            3,
            id(85),
            &RouteEventV1::ActionExternalized {
                leg: LegIdV1::Upstream,
                kind: ActionKindV1::Funding,
                effect_id,
                transaction_id: id(88),
                exposure: None,
            },
            12,
        ),
        Ok(CommitOutcomeV1::Committed {
            revision: 4,
            effects_created: 0,
            timers_created: 0,
        })
    );
    assert_eq!(store.pending_effect_count(id(1)), Ok(0));
    assert_eq!(
        store.committed_action_intent(lease, effect_id, 13),
        Err(RouteStoreErrorV1::EffectNotFound)
    );
}

#[test]
fn unified_single_claim_leases_only_one_dispatch_class_per_call() {
    let mut fixture = Fixture::new(10_000);
    fixture.arm_refunds();
    fixture.fund_and_finalize(LegIdV1::Upstream, 30);
    fixture.fund_and_finalize(LegIdV1::Downstream, 40);
    fixture.apply(RouteEventV1::SetHealth {
        target: HealthStateV1::RecoveryOnly,
        reason_digest: id(50),
    });
    fixture.apply(RouteEventV1::CommitAction(fixture.runner_intent(
        LegIdV1::Upstream,
        ActionKindV1::Refund,
        51,
    )));
    fixture.apply(RouteEventV1::CommitAction(
        fixture.external_refund_intent(LegIdV1::Downstream, 52),
    ));

    let first = fixture
        .store
        .claim_next_effect(fixture.lease, fixture.now, 100)
        .expect("first unified claim")
        .expect("runner row");
    assert!(matches!(
        first,
        ClaimedRouteWorkV1::Runner(ref claimed)
            if claimed.effect.leg == LegIdV1::Upstream
                && claimed.effect.kind == ActionKindV1::Refund
                && claimed.attempts == 1
    ));

    // The first call did not pre-lease the other dispatch class. A second
    // call at the same instant can claim it independently.
    let second = fixture
        .store
        .claim_next_effect(fixture.lease, fixture.now, 100)
        .expect("second unified claim")
        .expect("custody row");
    assert!(matches!(
        second,
        ClaimedRouteWorkV1::ExternalCustody(ref claimed)
            if claimed.leg == LegIdV1::Downstream
                && claimed.kind == ActionKindV1::Refund
                && claimed.attempts == 1
    ));
    assert!(fixture
        .store
        .claim_next_effect(fixture.lease, fixture.now, 100)
        .expect("both rows are leased")
        .is_none());
    assert_eq!(fixture.store.pending_effect_count(id(1)), Ok(2));
}

#[test]
fn failed_timer_mutation_rolls_back_snapshot_and_journal() {
    let mut fixture = Fixture::new(10_000);
    fixture.arm_refunds();
    let before = fixture.store.load_snapshot(id(1)).expect("before");
    let before_journal = fixture.store.journal(id(1)).expect("journal").len();
    assert_eq!(
        fixture.store.apply_event(
            fixture.lease,
            before.revision,
            id(99),
            &RouteEventV1::CancelTimer { timer_id: id(98) },
            20,
        ),
        Err(RouteStoreErrorV1::TimerNotFound)
    );
    assert_eq!(fixture.store.load_snapshot(id(1)), Ok(before));
    assert_eq!(
        fixture.store.journal(id(1)).expect("journal").len(),
        before_journal
    );
}

#[test]
fn timer_is_committed_claimed_and_completed_under_the_same_fence() {
    let mut fixture = Fixture::new(10_000);
    fixture.arm_refunds();
    assert_eq!(
        fixture.apply(RouteEventV1::ScheduleTimer {
            kind: TimerKindV1::Reconcile,
            deadline_unix_ms: 50,
            context_digest: id(70),
        }),
        CommitOutcomeV1::Committed {
            revision: 3,
            effects_created: 0,
            timers_created: 1,
        }
    );
    assert_eq!(fixture.store.active_timer_count(id(1)), Ok(1));
    assert!(fixture
        .store
        .claim_due_timers(fixture.lease, 49, 10, 1)
        .expect("not due")
        .is_empty());
    let due = fixture
        .store
        .claim_due_timers(fixture.lease, 50, 10, 1)
        .expect("due timer");
    assert_eq!(due.len(), 1);
    assert_eq!(
        fixture
            .store
            .complete_timer(fixture.lease, due[0].timer.timer_id, due[0].timer_hash, 51,),
        Ok(CompletionOutcomeV1::Completed)
    );
    assert_eq!(fixture.store.active_timer_count(id(1)), Ok(0));
}

#[test]
fn public_secret_survives_reorg_and_forces_recovery_until_funds_close() {
    let mut fixture = Fixture::new(10_000);
    fixture.arm_refunds();
    fixture.fund_and_finalize(LegIdV1::Upstream, 30);
    fixture.fund_and_finalize(LegIdV1::Downstream, 40);

    let intent = fixture.external_claim_intent(LegIdV1::Downstream, 60);
    let transaction_id = match intent.dispatch {
        EffectDispatchV1::ExternalCustody { transaction_id, .. } => transaction_id,
        EffectDispatchV1::RunnerPayload { .. } => unreachable!("test constructs custody"),
    };
    fixture.apply(RouteEventV1::CommitAction(intent.clone()));
    let committed = fixture.store.load_snapshot(id(1)).expect("snapshot");
    let effect_id = committed
        .downstream
        .claim
        .effect()
        .expect("claim effect")
        .effect_id;
    let custody_intent = fixture
        .store
        .committed_action_intent(fixture.lease, effect_id, fixture.now)
        .expect("custody intent commitments");
    assert_eq!(custody_intent, intent);
    assert!(matches!(
        custody_intent.dispatch,
        EffectDispatchV1::ExternalCustody { .. }
    ));
    assert!(fixture
        .store
        .claim_effects(fixture.lease, fixture.now, 100, 4)
        .expect("generic effects")
        .is_empty());
    let custody_first = fixture
        .store
        .claim_external_custody_effects(fixture.lease, fixture.now, 2, 4)
        .expect("custody commitment");
    assert_eq!(custody_first.len(), 1);
    assert_eq!(custody_first[0].effect_id, effect_id);
    assert_eq!(custody_first[0].transaction_id, transaction_id);
    assert!(custody_first[0].contains_route_secret);
    assert!(fixture
        .store
        .claim_external_custody_effects(fixture.lease, fixture.now + 1, 2, 4)
        .expect("lease still active")
        .is_empty());
    fixture.now += 3;
    let custody_retry = fixture
        .store
        .claim_external_custody_effects(fixture.lease, fixture.now, 2, 4)
        .expect("same commitment after crash/retry");
    assert_eq!(custody_retry.len(), 1);
    assert_eq!(custody_retry[0].effect_id, effect_id);
    assert_eq!(
        custody_retry[0].custody_digest,
        custody_first[0].custody_digest
    );
    assert_eq!(custody_retry[0].attempts, 2);

    let first = PublicExposureV1 {
        source: ExposureSourceV1::Externalized,
        chain_id: id(71),
        transaction_id,
        evidence_digest: id(72),
        observed_at_unix_ms: 100,
    };
    fixture.apply(RouteEventV1::ActionExternalized {
        leg: LegIdV1::Downstream,
        kind: ActionKindV1::Claim,
        effect_id,
        transaction_id,
        exposure: Some(first.clone()),
    });
    fixture.apply(RouteEventV1::ActionFinalized {
        leg: LegIdV1::Downstream,
        kind: ActionKindV1::Claim,
        transaction_id,
        evidence_digest: id(73),
    });
    fixture.apply(RouteEventV1::ObservationInvalidated {
        leg: LegIdV1::Downstream,
        kind: ActionKindV1::Claim,
        transaction_id,
        reorg_evidence_digest: id(74),
    });

    let after_reorg = fixture.store.load_snapshot(id(1)).expect("after reorg");
    assert_eq!(
        after_reorg.secret_visibility,
        SecretVisibilityV1::Public {
            first_exposure: first.clone()
        }
    );
    assert_eq!(after_reorg.health, HealthStateV1::RecoveryOnly);
    assert!(after_reorg.secret_public_but_upstream_unclaimed());

    let old_revision = fixture.revision;
    assert_eq!(
        fixture.store.apply_event(
            fixture.lease,
            old_revision,
            id(80),
            &RouteEventV1::SetHealth {
                target: HealthStateV1::Running,
                reason_digest: id(81),
            },
            fixture.now + 1,
        ),
        Err(RouteStoreErrorV1::TransitionRejected)
    );

    let upstream_claim = fixture.external_claim_intent(LegIdV1::Upstream, 82);
    let decision = route_executor::reduce_route_v1(
        &after_reorg,
        id(83),
        &RouteEventV1::CommitAction(upstream_claim.clone()),
        fixture.lease.fencing_epoch,
    )
    .expect("urgent upstream claim remains authorized");
    assert_eq!(
        decision.effects[0].priority,
        EffectPriorityV1::SecretPublicUrgent
    );
    fixture.apply(RouteEventV1::CommitAction(upstream_claim));

    let later = PublicExposureV1 {
        source: ExposureSourceV1::Block,
        chain_id: id(84),
        transaction_id: id(85),
        evidence_digest: id(86),
        observed_at_unix_ms: 200,
    };
    fixture.apply(RouteEventV1::SecretObserved(later));
    assert_eq!(
        fixture
            .store
            .load_snapshot(id(1))
            .expect("snapshot")
            .secret_visibility,
        SecretVisibilityV1::Public {
            first_exposure: first
        }
    );
    fixture
        .store
        .verify_replay(id(1))
        .expect("replay after reorg");
}

#[test]
fn upstream_claim_remains_urgent_and_dispatchable_after_funding_finality_reorg() {
    let mut fixture = Fixture::new(10_000);
    fixture.arm_refunds();
    let upstream_funding_tx = fixture.fund_and_finalize(LegIdV1::Upstream, 130);
    fixture.fund_and_finalize(LegIdV1::Downstream, 133);

    let downstream_claim = fixture.external_claim_intent(LegIdV1::Downstream, 136);
    let downstream_claim_tx = match downstream_claim.dispatch {
        EffectDispatchV1::ExternalCustody { transaction_id, .. } => transaction_id,
        EffectDispatchV1::RunnerPayload { .. } => unreachable!("custody intent"),
    };
    fixture.apply(RouteEventV1::CommitAction(downstream_claim));
    let downstream_effect_id = fixture
        .store
        .load_snapshot(id(1))
        .expect("downstream claim committed")
        .downstream
        .claim
        .effect()
        .expect("downstream effect")
        .effect_id;
    let first_exposure = PublicExposureV1 {
        source: ExposureSourceV1::Externalized,
        chain_id: id(139),
        transaction_id: downstream_claim_tx,
        evidence_digest: id(140),
        observed_at_unix_ms: 100,
    };
    fixture.apply(RouteEventV1::ActionExternalized {
        leg: LegIdV1::Downstream,
        kind: ActionKindV1::Claim,
        effect_id: downstream_effect_id,
        transaction_id: downstream_claim_tx,
        exposure: Some(first_exposure.clone()),
    });
    fixture.apply(RouteEventV1::ObservationInvalidated {
        leg: LegIdV1::Upstream,
        kind: ActionKindV1::Funding,
        transaction_id: upstream_funding_tx,
        reorg_evidence_digest: id(141),
    });

    let recovery = fixture
        .store
        .load_snapshot(id(1))
        .expect("recovery snapshot");
    assert!(matches!(
        recovery.upstream.funding,
        ActionStateV1::FinalityInvalidated { .. }
    ));
    assert_eq!(recovery.health, HealthStateV1::RecoveryOnly);
    assert_eq!(
        recovery.secret_visibility,
        SecretVisibilityV1::Public {
            first_exposure: first_exposure.clone()
        }
    );

    let urgent_claim = fixture.external_claim_intent(LegIdV1::Upstream, 142);
    let urgent_claim_tx = match urgent_claim.dispatch {
        EffectDispatchV1::ExternalCustody { transaction_id, .. } => transaction_id,
        EffectDispatchV1::RunnerPayload { .. } => unreachable!("custody intent"),
    };
    let commit = fixture.apply(RouteEventV1::CommitAction(urgent_claim));
    assert_eq!(
        commit,
        CommitOutcomeV1::Committed {
            revision: fixture.revision,
            effects_created: 1,
            timers_created: 0,
        }
    );
    let urgent_effect_id = fixture
        .store
        .load_snapshot(id(1))
        .expect("urgent claim committed")
        .upstream
        .claim
        .effect()
        .expect("urgent effect")
        .effect_id;
    let claimed = fixture
        .store
        .claim_external_custody_effects(fixture.lease, fixture.now, 100, 4)
        .expect("urgent recovery claim remains dispatchable");
    assert_eq!(claimed.len(), 1);
    assert_eq!(claimed[0].effect_id, urgent_effect_id);
    assert_eq!(claimed[0].transaction_id, urgent_claim_tx);
    assert_eq!(claimed[0].priority, EffectPriorityV1::SecretPublicUrgent);
    assert!(claimed[0].contains_route_secret);
    fixture
        .store
        .verify_replay(id(1))
        .expect("urgent recovery replay");
}

#[test]
fn stale_fencing_cannot_commit_or_dispatch_after_takeover() {
    let mut fixture = Fixture::new(10);
    fixture.arm_refunds();
    let funding_intent = fixture.runner_intent(LegIdV1::Upstream, ActionKindV1::Funding, 90);
    fixture.apply(RouteEventV1::CommitAction(funding_intent.clone()));
    let prior_effect_id = fixture
        .store
        .load_snapshot(id(1))
        .expect("snapshot")
        .upstream
        .funding
        .effect()
        .expect("prior effect")
        .effect_id;
    let old_lease = fixture.lease;
    let new_lease = match fixture
        .store
        .acquire_lease(id(1), id(3), 13, 100)
        .expect("take over expired lease")
    {
        LeaseAcquireOutcomeV1::Acquired(lease) => lease,
        LeaseAcquireOutcomeV1::AlreadyOwned(_) => panic!("different owner must take over"),
    };
    assert_eq!(new_lease.fencing_epoch, old_lease.fencing_epoch + 1);

    assert_eq!(
        fixture.store.apply_event(
            old_lease,
            fixture.revision,
            id(91),
            &RouteEventV1::ScheduleTimer {
                kind: TimerKindV1::Retry,
                deadline_unix_ms: 20,
                context_digest: id(92),
            },
            13,
        ),
        Err(RouteStoreErrorV1::StaleFencing)
    );
    assert_eq!(
        fixture.store.claim_effects(old_lease, 13, 10, 4),
        Err(RouteStoreErrorV1::StaleFencing)
    );
    assert!(fixture
        .store
        .claim_effects(new_lease, 13, 10, 4)
        .expect("new owner query")
        .is_empty());
    assert_eq!(fixture.store.pending_effect_count(id(1)), Ok(1));
    assert_eq!(
        fixture
            .store
            .committed_action_intent(new_lease, prior_effect_id, 13),
        Ok(funding_intent.clone())
    );

    let outcome = fixture
        .store
        .apply_event(
            new_lease,
            fixture.revision,
            id(93),
            &RouteEventV1::ReauthorizeCommittedAction {
                prior_effect_id,
                non_externalization_evidence_digest: id(94),
                intent: funding_intent.clone(),
            },
            14,
        )
        .expect("re-fence reconciled action");
    fixture.revision = match outcome {
        CommitOutcomeV1::Committed { revision, .. } => revision,
        CommitOutcomeV1::DuplicateSameBytes { .. } => panic!("new event"),
    };
    assert_eq!(fixture.store.pending_effect_count(id(1)), Ok(1));
    let replacement_effect_id = fixture
        .store
        .load_snapshot(id(1))
        .expect("replacement snapshot")
        .upstream
        .funding
        .effect()
        .expect("replacement effect")
        .effect_id;
    assert_eq!(
        fixture
            .store
            .committed_action_intent(new_lease, prior_effect_id, 15),
        Err(RouteStoreErrorV1::EffectNotFound)
    );
    assert_eq!(
        fixture
            .store
            .committed_action_intent(new_lease, replacement_effect_id, 15),
        Ok(funding_intent)
    );
    let replacement = fixture
        .store
        .claim_effects(new_lease, 15, 10, 4)
        .expect("newly fenced effect");
    assert_eq!(replacement.len(), 1);
    assert_ne!(replacement[0].effect.effect_id, prior_effect_id);
    assert_eq!(replacement[0].effect.effect_id, replacement_effect_id);
    assert_eq!(replacement[0].effect.fencing_epoch, new_lease.fencing_epoch);
    assert_eq!(replacement[0].effect.semantic_digest, id(90));
    assert_eq!(
        fixture.store.claim_effects(old_lease, 15, 1, 4),
        Err(RouteStoreErrorV1::StaleFencing)
    );
    fixture.store.verify_replay(id(1)).expect("takeover replay");

    let snapshot: RouteSnapshotV1 = fixture.store.load_snapshot(id(1)).expect("snapshot");
    assert_eq!(snapshot.revision, fixture.revision);
}

#[test]
fn crash_after_secret_prefix_before_refence_reopens_committed_and_public() {
    let mut fixture = Fixture::new(20);
    fixture.arm_refunds();
    fixture.fund_and_finalize(LegIdV1::Upstream, 0xd0);
    fixture.fund_and_finalize(LegIdV1::Downstream, 0xd1);
    let intent = fixture.external_claim_intent(LegIdV1::Downstream, 0xd2);
    fixture.apply(RouteEventV1::CommitAction(intent.clone()));
    let prior_effect_id = fixture
        .store
        .load_snapshot(id(1))
        .expect("committed snapshot")
        .downstream
        .claim
        .effect()
        .expect("aggregate claim")
        .effect_id;
    let new_lease = fixture
        .store
        .acquire_lease(id(1), id(3), 23, 100)
        .expect("take over expired route")
        .lease();
    let exposure = PublicExposureV1 {
        source: ExposureSourceV1::Externalized,
        chain_id: id(0xd5),
        transaction_id: id(0xd6),
        evidence_digest: id(0xd7),
        observed_at_unix_ms: 12,
    };
    let outcome = fixture
        .store
        .apply_event(
            new_lease,
            fixture.revision,
            id(0xd8),
            &RouteEventV1::CustodyProgressRecorded {
                leg: LegIdV1::Downstream,
                kind: ActionKindV1::Claim,
                effect_id: prior_effect_id,
                progress_evidence_digest: id(0xd9),
                exposure: Some(exposure.clone()),
            },
            23,
        )
        .expect("journal secret-bearing proper prefix");
    fixture.revision = match outcome {
        CommitOutcomeV1::Committed { revision, .. } => revision,
        CommitOutcomeV1::DuplicateSameBytes { .. } => panic!("new progress event"),
    };

    let Fixture {
        _directory,
        database,
        store,
        revision,
        ..
    } = fixture;
    drop(store); // crash after SecretPublic, before the aggregate is re-fenced.
    let mut recovered = reopen(&database);
    let snapshot = recovered.load_snapshot(id(1)).expect("recovered snapshot");
    assert!(matches!(
        snapshot.downstream.claim,
        ActionStateV1::Committed(ref reference) if reference.effect_id == prior_effect_id
    ));
    assert_eq!(
        snapshot.secret_visibility,
        SecretVisibilityV1::Public {
            first_exposure: exposure
        }
    );
    assert_eq!(
        recovered.committed_action_intent(new_lease, prior_effect_id, 24),
        Ok(intent.clone())
    );

    recovered
        .apply_event(
            new_lease,
            revision,
            id(0xda),
            &RouteEventV1::ReauthorizePartiallyExternalizedCustody {
                prior_effect_id,
                partial_externalization_evidence_digest: id(0xd9),
                intent,
            },
            24,
        )
        .expect("resume same incomplete aggregate after restart");
    let resumed = recovered.load_snapshot(id(1)).expect("resumed snapshot");
    let replacement = resumed
        .downstream
        .claim
        .effect()
        .expect("replacement aggregate effect");
    assert_ne!(replacement.effect_id, prior_effect_id);
    assert_eq!(replacement.fencing_epoch, new_lease.fencing_epoch);
    assert!(matches!(
        resumed.secret_visibility,
        SecretVisibilityV1::Public { .. }
    ));
    recovered
        .verify_replay(id(1))
        .expect("replay after crash cut");
    drop(_directory);
}

#[test]
fn internal_timer_survives_takeover_but_stale_owner_cannot_complete_it() {
    let mut fixture = Fixture::new(10);
    fixture.arm_refunds();
    fixture.apply(RouteEventV1::ScheduleTimer {
        kind: TimerKindV1::Deadline,
        deadline_unix_ms: 20,
        context_digest: id(95),
    });
    let old_lease = fixture.lease;
    let new_lease = fixture
        .store
        .acquire_lease(id(1), id(3), 13, 100)
        .expect("takeover")
        .lease();
    let timers = fixture
        .store
        .claim_due_timers(new_lease, 20, 10, 4)
        .expect("old internal timer adopted by new owner");
    assert_eq!(timers.len(), 1);
    assert_eq!(timers[0].timer.fencing_epoch, old_lease.fencing_epoch);
    assert_eq!(
        fixture.store.complete_timer(
            old_lease,
            timers[0].timer.timer_id,
            timers[0].timer_hash,
            21,
        ),
        Err(RouteStoreErrorV1::StaleFencing)
    );
    assert_eq!(
        fixture.store.complete_timer(
            new_lease,
            timers[0].timer.timer_id,
            timers[0].timer_hash,
            21,
        ),
        Ok(CompletionOutcomeV1::Completed)
    );
}

#[test]
fn refund_cannot_race_a_merely_committed_funding_effect() {
    let mut fixture = Fixture::new(10_000);
    fixture.arm_refunds();
    fixture.apply(RouteEventV1::CommitAction(fixture.runner_intent(
        LegIdV1::Upstream,
        ActionKindV1::Funding,
        100,
    )));
    let committed = fixture.store.load_snapshot(id(1)).expect("snapshot");
    let funding_effect_id = committed
        .upstream
        .funding
        .effect()
        .expect("funding effect")
        .effect_id;
    let refund = RouteEventV1::CommitAction(fixture.runner_intent(
        LegIdV1::Upstream,
        ActionKindV1::Refund,
        101,
    ));
    assert_eq!(
        fixture.store.apply_event(
            fixture.lease,
            fixture.revision,
            id(102),
            &refund,
            fixture.now + 1,
        ),
        Err(RouteStoreErrorV1::TransitionRejected)
    );
    assert_eq!(fixture.store.pending_effect_count(id(1)), Ok(1));

    fixture.apply(RouteEventV1::ActionExternalized {
        leg: LegIdV1::Upstream,
        kind: ActionKindV1::Funding,
        effect_id: funding_effect_id,
        transaction_id: id(103),
        exposure: None,
    });
    assert_eq!(fixture.store.pending_effect_count(id(1)), Ok(0));
    fixture.apply(refund);
    assert_eq!(fixture.store.pending_effect_count(id(1)), Ok(1));
    let claimed = fixture
        .store
        .claim_effects(fixture.lease, fixture.now + 1, 10, 4)
        .expect("refund only");
    assert_eq!(claimed.len(), 1);
    assert_eq!(claimed[0].effect.kind, ActionKindV1::Refund);
    assert_ne!(claimed[0].effect.effect_id, funding_effect_id);
    assert!(!fixture
        .store
        .load_snapshot(id(1))
        .expect("snapshot")
        .upstream
        .is_terminal());
}

#[test]
fn dispatch_claim_revalidates_route_after_reorg() {
    let mut fixture = Fixture::new(10_000);
    fixture.arm_refunds();
    let upstream_tx = fixture.fund_and_finalize(LegIdV1::Upstream, 110);
    fixture.apply(RouteEventV1::CommitAction(fixture.runner_intent(
        LegIdV1::Downstream,
        ActionKindV1::Funding,
        111,
    )));
    assert_eq!(fixture.store.pending_effect_count(id(1)), Ok(1));
    fixture.apply(RouteEventV1::ObservationInvalidated {
        leg: LegIdV1::Upstream,
        kind: ActionKindV1::Funding,
        transaction_id: upstream_tx,
        reorg_evidence_digest: id(112),
    });
    assert_eq!(
        fixture.store.load_snapshot(id(1)).expect("snapshot").health,
        HealthStateV1::RecoveryOnly
    );
    assert!(fixture
        .store
        .claim_effects(fixture.lease, fixture.now + 1, 10, 4)
        .expect("fresh route check")
        .is_empty());
    assert_eq!(fixture.store.pending_effect_count(id(1)), Ok(1));

    let mut reveal_fixture = Fixture::new(10_000);
    reveal_fixture.arm_refunds();
    let reveal_upstream_tx = reveal_fixture.fund_and_finalize(LegIdV1::Upstream, 113);
    reveal_fixture.fund_and_finalize(LegIdV1::Downstream, 116);
    reveal_fixture.apply(RouteEventV1::CommitAction(
        reveal_fixture.external_claim_intent(LegIdV1::Downstream, 119),
    ));
    reveal_fixture.apply(RouteEventV1::ObservationInvalidated {
        leg: LegIdV1::Upstream,
        kind: ActionKindV1::Funding,
        transaction_id: reveal_upstream_tx,
        reorg_evidence_digest: id(122),
    });
    assert!(reveal_fixture
        .store
        .claim_external_custody_effects(reveal_fixture.lease, reveal_fixture.now + 1, 10, 4,)
        .expect("fresh reveal check")
        .is_empty());
    assert!(matches!(
        reveal_fixture
            .store
            .load_snapshot(id(1))
            .expect("snapshot")
            .secret_visibility,
        SecretVisibilityV1::Private
    ));
}
