#![cfg(feature = "development")]

use std::cell::Cell;
use std::collections::VecDeque;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::rc::Rc;
use std::time::Duration;

use adapter_btc::timelock::ChainTimingBoundsV1;
use btc_crypto::SecpContext;
use chain_profile::{ChainKindV1, ChainProfileV1};
use deployment_registry::{
    AssetBindingV1, AssetRepresentationV1, AuthoritySetV1, ChainDeploymentV1, DomDeploymentV1,
    DomNetworkV1, DomRuntimeIdentityV1, EvmDeploymentV1, RegistryChainProfileV1,
    RegistryManifestV1, RegistrySignatureV1, RegistryStoreV1, RegistryValidationPolicyV1,
    SignedRegistryV1,
};
use dom_interopd::{
    drive_route_once_v1, ActionExternalizationReceiptV1, AuthenticatedRouteAdmissionV1,
    AuthorityRefusalV1, ChainObservationAuthority, ChainObservationQueryV1,
    ChainObservationRequestV1, CustodyDispatchOutcomeV1, ExternalCustodyActionRequestV1,
    ExternalCustodyAuthority, ManualClockV1, ProductionRouteRuntimeV1, ReconciliationRequestV1,
    RefundArmingAuthority, RefundArmingRequestV1, RegistryRouteAdmissionAuthorityV1,
    RouteActionAuthority, RouteActionAuthorizationRequestV1, RouteAdmissionRequestV1,
    RouteDriveDispositionV1, RouteDriveReportV1, RouteDriveStageV1, RouteDriverAuthoritiesV1,
    RouteDriverErrorV1, RouteLegSelectionV1, RouteRunControlErrorV1, RouteRunControlV1,
    RouteRuntimeAuthoritiesV1, RouteRuntimeConfigV1, RouteRuntimeErrorV1, RouteRuntimeExitV1,
    RouteRuntimeOperationalAuthoritiesV1, RouteRuntimeRecoveryAuthoritiesV1,
    RouteSecretRetirementAuthority, RouteSupervisorConfigV1, RouteSupervisorV1,
    RunnerActionAuthority, RunnerActionRequestV1, TakeoverReconciliationAuthority,
    TakeoverReconciliationOutcomeV1, TimerAuthority, TimerDispatchV1, VerifiedChainObservationV1,
};
use kaystra_core::types::{AssetId, ChainId, FinalityPolicyV1};
use route_executor::{
    digest_bytes_v1, ActionIntentV1, ActionKindV1, ActionProgressV1, ActionStateV1,
    CommitOutcomeV1, CoordinationPhaseV1, Digest32, DurableRouteStoreV1, EffectDispatchV1,
    ExposureSourceV1, FrozenRouteAdmissionCheckpointV2, FrozenRouteTimeFactsV2, HealthStateV1,
    LegIdV1, PublicExposureV1, RefundBindingsV1, RouteEventV1, RouteSecretRetirementCapabilityV1,
    TimerKindV1,
};

const NETWORK: Digest32 = [0x90; 32];
const ROUTE: Digest32 = [0x51; 32];
const OWNER_A: Digest32 = [0x52; 32];
const OWNER_B: Digest32 = [0x53; 32];
const DOM_CHAIN: ChainId = ChainId([
    0x22, 0x38, 0x4b, 0x4c, 0xbf, 0xaa, 0xe3, 0x06, 0xa7, 0xbd, 0xb2, 0x3a, 0x82, 0x24, 0x42, 0xf7,
    0xe6, 0x8f, 0xb5, 0x1f, 0x65, 0x32, 0x86, 0x97, 0xa7, 0x54, 0xa9, 0xf3, 0xab, 0xd6, 0x98, 0xe1,
]);
const DOM_GENESIS: Digest32 = [
    0xfd, 0xda, 0x02, 0x7e, 0x4a, 0x46, 0xdd, 0x36, 0x67, 0x17, 0xc6, 0xe0, 0xa9, 0x76, 0xbf, 0x3e,
    0x0a, 0x75, 0x12, 0xc5, 0xed, 0xf0, 0x84, 0x70, 0xb0, 0xdc, 0xa9, 0x9d, 0xde, 0xe3, 0xfe, 0x1f,
];
const EVM_CHAIN: ChainId = ChainId([0x02; 32]);
const DOM_ASSET: AssetId = AssetId([0x11; 32]);
const EVM_NATIVE: AssetId = AssetId([0x12; 32]);
const EVM_TOKEN: AssetId = AssetId([0x13; 32]);
const AUTHORITY_SECRET: Digest32 = [0x03; 32];

fn id(value: u8) -> Digest32 {
    [value; 32]
}

fn timing() -> ChainTimingBoundsV1 {
    ChainTimingBoundsV1 {
        min_block_seconds: 5,
        max_block_seconds: 20,
        max_reorg_seconds: 200,
        observation_seconds: 30,
        broadcast_seconds: 20,
    }
}

fn finality() -> FinalityPolicyV1 {
    FinalityPolicyV1 {
        min_confirmations: 2,
        max_reorg_depth: 3,
    }
}

fn manifest() -> RegistryManifestV1 {
    RegistryManifestV1 {
        network_id: NETWORK,
        epoch: 1,
        valid_from: 1_000,
        expires_at: 10_000,
        dom: DomDeploymentV1 {
            chain_id: DOM_CHAIN,
            genesis_hash: DOM_GENESIS,
            runtime_identity: DomRuntimeIdentityV1::pinned(DomNetworkV1::Regtest),
            consensus_rules_digest: id(0x22),
            scriptless_api_version: 1,
            timing: timing(),
            finality: finality(),
            native_asset: DOM_ASSET,
        },
        chains: vec![RegistryChainProfileV1 {
            profile: ChainProfileV1 {
                chain_id: EVM_CHAIN,
                kind: ChainKindV1::Evm {
                    evm_chain_id: 31_337,
                    native_lock_contract: [0x31; 20],
                    native_code_hash: id(0x32),
                    erc20_lock_contract: Some(([0x33; 20], id(0x34))),
                },
                timing: timing(),
                finality: finality(),
                native_asset: EVM_NATIVE,
                allowed_assets: vec![EVM_TOKEN],
            },
            deployment: ChainDeploymentV1::Evm(EvmDeploymentV1 {
                genesis_hash: id(0x35),
                native_start_block: 10,
                erc20_start_block: Some(11),
                abi_digest: id(0x36),
                compiler_digest: id(0x37),
                source_digest: id(0x38),
                deployment_digest: id(0x39),
                finalized_tag_required: true,
                page_size: 256,
                gas_limit_hint: 300_000,
                max_fee_per_gas: 100_000_000_000,
                max_priority_fee_per_gas: 2_000_000_000,
            }),
        }],
        assets: vec![
            AssetBindingV1 {
                chain_id: EVM_CHAIN,
                asset_id: EVM_NATIVE,
                decimals: 18,
                representation: AssetRepresentationV1::Native,
            },
            AssetBindingV1 {
                chain_id: EVM_CHAIN,
                asset_id: EVM_TOKEN,
                decimals: 6,
                representation: AssetRepresentationV1::EvmErc20 {
                    token: [0x42; 20],
                    token_code_hash: id(0x43),
                },
            },
            AssetBindingV1 {
                chain_id: DOM_CHAIN,
                asset_id: DOM_ASSET,
                decimals: 9,
                representation: AssetRepresentationV1::Native,
            },
        ],
    }
}

fn authenticated_admission(
    path: &std::path::Path,
    base_terms_digest: Digest32,
) -> AuthenticatedRouteAdmissionV1 {
    let secp = SecpContext::new(&id(0x70));
    let manifest = manifest();
    let digest = manifest.manifest_digest().expect("manifest digest");
    let (signature, public_key) = secp
        .sign_bip340(&AUTHORITY_SECRET, &digest, &id(0x71))
        .expect("registry signature");
    let authorities = AuthoritySetV1::new(1, vec![public_key]).expect("authority set");
    let signed = SignedRegistryV1::new(
        &manifest,
        vec![RegistrySignatureV1 {
            signer_index: 0,
            signature,
        }],
    )
    .expect("signed registry");
    let mut store = RegistryStoreV1::create(path).expect("create registry store");
    store
        .install(
            &signed,
            &authorities,
            &secp,
            RegistryValidationPolicyV1 {
                now_seconds: 2_000,
                expected_network_id: NETWORK,
                minimum_epoch: 1,
            },
        )
        .expect("install signed registry");
    RegistryRouteAdmissionAuthorityV1::new(
        store,
        authorities,
        SecpContext::new(&id(0x72)),
        NETWORK,
        1,
    )
    .expect("registry admission authority")
    .admit_composed_route(
        2_000,
        RouteAdmissionRequestV1 {
            route_id: ROUTE,
            base_terms_digest,
            dom: RouteLegSelectionV1 {
                chain_id: DOM_CHAIN,
                asset_id: DOM_ASSET,
            },
            upstream: RouteLegSelectionV1 {
                chain_id: EVM_CHAIN,
                asset_id: EVM_NATIVE,
            },
            downstream: RouteLegSelectionV1 {
                chain_id: EVM_CHAIN,
                asset_id: EVM_TOKEN,
            },
        },
    )
    .expect("authenticated route admission")
}

fn tx_for(leg: LegIdV1, action: ActionKindV1) -> Digest32 {
    id(match (leg, action) {
        (LegIdV1::Upstream, ActionKindV1::Funding) => 0x31,
        (LegIdV1::Downstream, ActionKindV1::Funding) => 0x32,
        (LegIdV1::Upstream, ActionKindV1::Claim) => 0x41,
        (LegIdV1::Downstream, ActionKindV1::Claim) => 0x42,
        (LegIdV1::Upstream, ActionKindV1::Refund) => 0x51,
        (LegIdV1::Downstream, ActionKindV1::Refund) => 0x52,
    })
}

fn action_intent(leg: LegIdV1, action: ActionKindV1) -> ActionIntentV1 {
    let marker = match (leg, action) {
        (LegIdV1::Upstream, ActionKindV1::Funding) => 0x61,
        (LegIdV1::Downstream, ActionKindV1::Funding) => 0x62,
        (LegIdV1::Upstream, ActionKindV1::Claim) => 0x63,
        (LegIdV1::Downstream, ActionKindV1::Claim) => 0x64,
        (LegIdV1::Upstream, ActionKindV1::Refund) => 0x65,
        (LegIdV1::Downstream, ActionKindV1::Refund) => 0x66,
    };
    if action == ActionKindV1::Claim {
        ActionIntentV1 {
            leg,
            kind: action,
            semantic_digest: id(marker),
            contains_route_secret: true,
            dispatch: EffectDispatchV1::ExternalCustody {
                custody_digest: id(marker.wrapping_add(0x10)),
                transaction_id: tx_for(leg, action),
            },
        }
    } else {
        let payload = vec![marker; 31];
        ActionIntentV1 {
            leg,
            kind: action,
            semantic_digest: id(marker),
            contains_route_secret: false,
            dispatch: EffectDispatchV1::RunnerPayload {
                payload_digest: digest_bytes_v1(&payload),
                payload,
            },
        }
    }
}

#[derive(Default)]
struct TestRefunds {
    calls: Vec<Digest32>,
    unavailable_once: bool,
}

impl RefundArmingAuthority for TestRefunds {
    fn arm_refunds(
        &mut self,
        request: RefundArmingRequestV1<'_>,
    ) -> Result<RefundBindingsV1, AuthorityRefusalV1> {
        self.calls.push(request.event_id());
        if self.unavailable_once {
            self.unavailable_once = false;
            return Err(AuthorityRefusalV1::Unavailable);
        }
        Ok(RefundBindingsV1 {
            upstream_refund_digest: id(0x81),
            downstream_refund_digest: id(0x82),
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ActionCall {
    event_id: Digest32,
    leg: LegIdV1,
    action: ActionKindV1,
}

#[derive(Default)]
struct TestActions {
    calls: Vec<ActionCall>,
    unavailable_once: Option<(LegIdV1, ActionKindV1)>,
}

impl RouteActionAuthority for TestActions {
    fn authorize_route_action(
        &mut self,
        request: RouteActionAuthorizationRequestV1<'_>,
    ) -> Result<ActionIntentV1, AuthorityRefusalV1> {
        self.calls.push(ActionCall {
            event_id: request.event_id(),
            leg: request.leg(),
            action: request.action(),
        });
        if self.unavailable_once == Some((request.leg(), request.action())) {
            self.unavailable_once = None;
            return Err(AuthorityRefusalV1::Unavailable);
        }
        Ok(action_intent(request.leg(), request.action()))
    }
}

#[derive(Default)]
struct TestObserver {
    calls: Vec<(Digest32, ChainObservationQueryV1)>,
    unavailable_once: bool,
}

impl ChainObservationAuthority for TestObserver {
    fn verify_chain_observation(
        &mut self,
        request: ChainObservationRequestV1<'_>,
    ) -> Result<VerifiedChainObservationV1, AuthorityRefusalV1> {
        self.calls.push((request.event_id(), request.query()));
        if self.unavailable_once {
            self.unavailable_once = false;
            return Err(AuthorityRefusalV1::Unavailable);
        }
        match request.query() {
            ChainObservationQueryV1::Finality {
                leg,
                action,
                transaction_id,
            } if transaction_id == tx_for(leg, action) => {
                Ok(VerifiedChainObservationV1::Finality {
                    evidence_digest: id(0x90 + u8::from(leg == LegIdV1::Downstream)),
                })
            }
            ChainObservationQueryV1::Invalidation {
                leg,
                action,
                transaction_id,
            } if transaction_id == tx_for(leg, action) => {
                Ok(VerifiedChainObservationV1::Invalidation {
                    reorg_evidence_digest: id(0xa0),
                })
            }
            ChainObservationQueryV1::SecretExposure { .. } => {
                Ok(VerifiedChainObservationV1::SecretExposure {
                    source: ExposureSourceV1::PeerEvidence,
                    evidence_digest: id(0xa1),
                    observed_at_unix_ms: 2_000,
                })
            }
            _ => Err(AuthorityRefusalV1::Inconsistent),
        }
    }
}

#[derive(Default)]
struct TestRunner {
    calls: Vec<(LegIdV1, ActionKindV1)>,
    unavailable_once: bool,
}

impl RunnerActionAuthority for TestRunner {
    fn externalize_runner_action(
        &mut self,
        request: RunnerActionRequestV1<'_>,
    ) -> Result<ActionExternalizationReceiptV1, AuthorityRefusalV1> {
        let capability = request.capability();
        self.calls.push((capability.leg(), capability.action()));
        if self.unavailable_once {
            self.unavailable_once = false;
            return Err(AuthorityRefusalV1::Unavailable);
        }
        if digest_bytes_v1(request.payload()) != capability.dispatch_digest() {
            return Err(AuthorityRefusalV1::Inconsistent);
        }
        Ok(ActionExternalizationReceiptV1::public(tx_for(
            capability.leg(),
            capability.action(),
        )))
    }
}

#[derive(Default)]
struct TestCustody {
    calls: Vec<(LegIdV1, ActionKindV1)>,
    unavailable_once: bool,
    partial_downstream_claim_once: bool,
    downstream_partial_emitted: bool,
}

impl ExternalCustodyAuthority for TestCustody {
    fn externalize_custodied_action(
        &mut self,
        request: ExternalCustodyActionRequestV1,
    ) -> Result<CustodyDispatchOutcomeV1, AuthorityRefusalV1> {
        let capability = request.capability();
        self.calls.push((capability.leg(), capability.action()));
        if self.unavailable_once {
            self.unavailable_once = false;
            return Err(AuthorityRefusalV1::Unavailable);
        }
        let transaction_id = tx_for(capability.leg(), capability.action());
        if capability.expected_transaction_id() != Some(transaction_id)
            || !capability.contains_route_secret()
        {
            return Err(AuthorityRefusalV1::Inconsistent);
        }
        if capability.leg() == LegIdV1::Downstream
            && capability.action() == ActionKindV1::Claim
            && self.partial_downstream_claim_once
        {
            self.partial_downstream_claim_once = false;
            self.downstream_partial_emitted = true;
            return Ok(CustodyDispatchOutcomeV1::PartialProgress {
                progress_evidence_digest: id(0xd4),
                exposure: Some(PublicExposureV1 {
                    source: ExposureSourceV1::Externalized,
                    chain_id: id(0xd5),
                    transaction_id: id(0xd6),
                    evidence_digest: id(0xd7),
                    observed_at_unix_ms: 2_000,
                }),
            });
        }
        if capability.leg() == LegIdV1::Downstream
            && capability.action() == ActionKindV1::Claim
            && self.downstream_partial_emitted
        {
            return Ok(CustodyDispatchOutcomeV1::AggregateExternalized(
                ActionExternalizationReceiptV1::public(transaction_id),
            ));
        }
        Ok(CustodyDispatchOutcomeV1::AggregateExternalized(
            ActionExternalizationReceiptV1::secret_revealing(
                transaction_id,
                id(0xb0 + u8::from(capability.leg() == LegIdV1::Downstream)),
                id(0xc0 + u8::from(capability.leg() == LegIdV1::Downstream)),
            ),
        ))
    }
}

#[derive(Default)]
struct TestTimer {
    calls: usize,
    enter_recovery: bool,
    schedule_follow_up: bool,
}

impl TimerAuthority for TestTimer {
    fn event_for_due_timer(
        &mut self,
        _timer: TimerDispatchV1,
    ) -> Result<RouteEventV1, AuthorityRefusalV1> {
        self.calls += 1;
        if self.enter_recovery {
            Ok(RouteEventV1::SetHealth {
                target: HealthStateV1::RecoveryOnly,
                reason_digest: id(0xd1),
            })
        } else if self.schedule_follow_up {
            Ok(RouteEventV1::ScheduleTimer {
                kind: TimerKindV1::Retry,
                deadline_unix_ms: 10_000,
                context_digest: id(0xd2),
            })
        } else {
            Err(AuthorityRefusalV1::Inconsistent)
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
enum ReconcileMode {
    #[default]
    Unknown,
    ProveNotExternalized,
}

#[derive(Default)]
struct TestReconciler {
    calls: usize,
    mode: ReconcileMode,
}

struct TestRetirement {
    calls: Rc<Cell<usize>>,
    outcomes: VecDeque<Result<(), AuthorityRefusalV1>>,
}

impl Default for TestRetirement {
    fn default() -> Self {
        Self {
            calls: Rc::new(Cell::new(0)),
            outcomes: VecDeque::new(),
        }
    }
}

impl RouteSecretRetirementAuthority for TestRetirement {
    fn retire_route_secret(
        &mut self,
        _capability: RouteSecretRetirementCapabilityV1,
    ) -> Result<(), AuthorityRefusalV1> {
        self.calls.set(self.calls.get() + 1);
        self.outcomes.pop_front().unwrap_or(Ok(()))
    }
}

#[derive(Default)]
struct TestRunControl {
    shutdown: bool,
    waits: Vec<Duration>,
    reports: Vec<RouteDriveReportV1>,
}

impl RouteRunControlV1 for TestRunControl {
    fn shutdown_requested(&mut self) -> Result<bool, RouteRunControlErrorV1> {
        Ok(self.shutdown)
    }

    fn wait(&mut self, duration: Duration) -> Result<(), RouteRunControlErrorV1> {
        self.waits.push(duration);
        Ok(())
    }

    fn record_progress(
        &mut self,
        report: RouteDriveReportV1,
    ) -> Result<(), RouteRunControlErrorV1> {
        self.reports.push(report);
        Ok(())
    }
}

impl TakeoverReconciliationAuthority for TestReconciler {
    fn reconcile_committed_action(
        &mut self,
        request: ReconciliationRequestV1<'_>,
    ) -> Result<TakeoverReconciliationOutcomeV1, AuthorityRefusalV1> {
        self.calls += 1;
        Ok(match self.mode {
            ReconcileMode::Unknown => TakeoverReconciliationOutcomeV1::Unknown,
            ReconcileMode::ProveNotExternalized => {
                TakeoverReconciliationOutcomeV1::ProvenNotExternalized {
                    intent: request.intent().clone(),
                    evidence_digest: id(0xd0),
                }
            }
        })
    }
}

struct Fixture {
    _temporary: tempfile::TempDir,
    route_database: PathBuf,
    clock: ManualClockV1,
    supervisor: Option<RouteSupervisorV1<ManualClockV1>>,
    admission: AuthenticatedRouteAdmissionV1,
    refunds: TestRefunds,
    actions: TestActions,
    observer: TestObserver,
    runner: TestRunner,
    custody: TestCustody,
    timers: TestTimer,
    reconciler: TestReconciler,
    retirement: TestRetirement,
}

type TestRouteRuntime = ProductionRouteRuntimeV1<
    ManualClockV1,
    TestRefunds,
    TestActions,
    TestObserver,
    TestRunner,
    TestCustody,
    TestTimer,
    TestReconciler,
    TestRetirement,
>;

impl Fixture {
    /// Legacy-admission fixture: the route is created bare and the driver
    /// journals `FreezeTerms` itself, so the stage sequence starts at
    /// Admission. Routes born this way can run to terminal but can never
    /// retire a public secret: that gate demands the V2 checkpoint.
    fn new() -> Self {
        Self::build(false)
    }

    /// Production-shaped fixture: the route is born with its V2 admission
    /// checkpoint as revision 1, exactly as `persist_new_route_checkpoint`
    /// journals it, so the retirement gate has its checkpoint and the drive
    /// sequence starts past admission.
    fn new_production() -> Self {
        Self::build(true)
    }

    fn build(production_checkpoint: bool) -> Self {
        let temporary = tempfile::tempdir().expect("temporary directory");
        std::fs::set_permissions(temporary.path(), std::fs::Permissions::from_mode(0o700))
            .expect("owner-only test directory");
        let admission =
            authenticated_admission(&temporary.path().join("registry.sqlite3"), id(0x73));
        let route_database = temporary.path().join("routes.sqlite3");
        let mut store = DurableRouteStoreV1::create(&route_database).expect("create route store");
        store.create_route(ROUTE, 1_990).expect("create route");
        if production_checkpoint {
            Self::freeze_production_checkpoint(&mut store, &admission);
        }
        let clock = ManualClockV1::new(2_000).expect("manual clock");
        let supervisor =
            RouteSupervisorV1::acquire(store, ROUTE, OWNER_A, Self::config(), clock.clone())
                .expect("acquire route");
        Self {
            _temporary: temporary,
            route_database,
            clock,
            supervisor: Some(supervisor),
            admission,
            refunds: TestRefunds::default(),
            actions: TestActions::default(),
            observer: TestObserver::default(),
            runner: TestRunner::default(),
            custody: TestCustody::default(),
            timers: TestTimer::default(),
            reconciler: TestReconciler::default(),
            retirement: TestRetirement::default(),
        }
    }

    fn freeze_production_checkpoint(
        store: &mut DurableRouteStoreV1,
        admission: &AuthenticatedRouteAdmissionV1,
    ) {
        // The bindings must equal the authenticated admission's, or the
        // driver refuses the route as an admission mismatch.
        let checkpoint = FrozenRouteAdmissionCheckpointV2 {
            network_id: NETWORK,
            route_id: ROUTE,
            bindings: admission.frozen_bindings().clone(),
            composition_v2_digest: id(0x61),
            registry_epoch: 1,
            // The store validator demands this equal the bindings deployment
            // bundle digest, as production admission produces.
            registry_manifest_digest: admission.frozen_bindings().deployment_bundle_digest,
            upstream_terms_digest: id(0x63),
            downstream_terms_digest: id(0x64),
            upstream_roster_snapshot: id(0x65),
            downstream_roster_snapshot: id(0x66),
            participant_bindings_digest: id(0x67),
            relay_binding_digest: id(0x68),
            registry_authority_set_digest: id(0x69),
            time_policy_authority_set_digest: id(0x6a),
            time_evidence_authority_set_digest: id(0x6b),
            time: FrozenRouteTimeFactsV2 {
                route_scope_digest: id(0x6c),
                policy_digest: id(0x6d),
                evidence_digest: id(0x6e),
                proof_digest: id(0x6f),
                evidence_sequence: 1,
                issued_at_seconds: 1_900,
                valid_until_seconds: 1_000_000,
                validated_at_seconds: 1_950,
            },
        };
        let freeze_lease = store
            .acquire_lease(ROUTE, OWNER_A, 1_995, 1_000)
            .expect("freeze lease")
            .lease();
        let outcome = store
            .apply_event(
                freeze_lease,
                0,
                id(0x70),
                &RouteEventV1::FreezeTermsV2(Box::new(checkpoint)),
                1_995,
            )
            .expect("freeze production checkpoint");
        assert!(matches!(
            outcome,
            CommitOutcomeV1::Committed { revision: 1, .. }
        ));
    }

    fn config() -> RouteSupervisorConfigV1 {
        RouteSupervisorConfigV1::new(1_000, 200, 100, 1).expect("driver test config")
    }

    fn into_runtime(self) -> (tempfile::TempDir, TestRouteRuntime) {
        let Self {
            _temporary,
            supervisor,
            admission,
            refunds,
            actions,
            observer,
            runner,
            custody,
            timers,
            reconciler,
            retirement,
            ..
        } = self;
        let config =
            RouteRuntimeConfigV1::new(50, 75, Self::config()).expect("route runtime test config");
        let authorities = RouteRuntimeAuthoritiesV1::new(
            RouteRuntimeOperationalAuthoritiesV1 {
                refund: refunds,
                action: actions,
                observer,
                runner,
            },
            RouteRuntimeRecoveryAuthoritiesV1 {
                custody,
                timers,
                reconciler,
                retirement,
            },
        );
        let runtime = ProductionRouteRuntimeV1::new(
            supervisor.expect("live supervisor"),
            admission,
            authorities,
            config,
        )
        .expect("route runtime");
        (_temporary, runtime)
    }

    fn supervisor(&self) -> &RouteSupervisorV1<ManualClockV1> {
        self.supervisor.as_ref().expect("live supervisor")
    }

    fn supervisor_mut(&mut self) -> &mut RouteSupervisorV1<ManualClockV1> {
        self.supervisor.as_mut().expect("live supervisor")
    }

    fn authority_calls(&self) -> usize {
        self.refunds.calls.len()
            + self.actions.calls.len()
            + self.observer.calls.len()
            + self.runner.calls.len()
            + self.custody.calls.len()
            + self.timers.calls
            + self.reconciler.calls
    }

    fn drive(&mut self) -> RouteDriveReportV1 {
        let before_revision = self
            .supervisor()
            .snapshot()
            .expect("snapshot before drive")
            .revision;
        let calls_before = self.authority_calls();
        let mut authorities = RouteDriverAuthoritiesV1 {
            refund: &mut self.refunds,
            action: &mut self.actions,
            observer: &mut self.observer,
            runner: &mut self.runner,
            external_custody: &mut self.custody,
            timers: &mut self.timers,
            reconciler: &mut self.reconciler,
        };
        let report = drive_route_once_v1(
            self.supervisor.as_mut().expect("live supervisor"),
            &self.admission,
            &mut authorities,
        )
        .expect("driver step");
        assert_eq!(report.before_revision, before_revision);
        assert_eq!(
            report.after_revision,
            self.supervisor().snapshot().unwrap().revision
        );
        match report.disposition {
            RouteDriveDispositionV1::Progressed => {
                assert_eq!(report.after_revision, before_revision + 1)
            }
            RouteDriveDispositionV1::Waiting
            | RouteDriveDispositionV1::RecoveryRequired
            | RouteDriveDispositionV1::Terminal => {
                assert_eq!(report.after_revision, before_revision)
            }
        }
        assert!(
            self.authority_calls() - calls_before <= 1,
            "one driver call crossed more than one authority class"
        );
        report
    }

    fn assert_step(&mut self, stage: RouteDriveStageV1, disposition: RouteDriveDispositionV1) {
        let report = self.drive();
        assert_eq!(report.stage, stage);
        assert_eq!(report.disposition, disposition);
    }

    fn reach_both_funding_final(&mut self) {
        // A production-born route already carries its V2 admission
        // checkpoint, so the drive sequence starts past admission.
        let already_admitted = self
            .supervisor()
            .snapshot()
            .expect("snapshot")
            .bindings
            .is_some();
        for stage in [
            RouteDriveStageV1::Admission,
            RouteDriveStageV1::RefundArming,
            RouteDriveStageV1::UpstreamFunding,
            RouteDriveStageV1::UpstreamFunding,
            RouteDriveStageV1::UpstreamFunding,
            RouteDriveStageV1::DownstreamFunding,
            RouteDriveStageV1::DownstreamFunding,
            RouteDriveStageV1::DownstreamFunding,
        ] {
            if already_admitted && stage == RouteDriveStageV1::Admission {
                continue;
            }
            self.assert_step(stage, RouteDriveDispositionV1::Progressed);
        }
        let snapshot = self.supervisor().snapshot().unwrap();
        assert_eq!(
            snapshot.upstream.funding.progress(),
            ActionProgressV1::Final
        );
        assert_eq!(
            snapshot.downstream.funding.progress(),
            ActionProgressV1::Final
        );
    }

    fn reach_downstream_claim_externalized(&mut self) {
        self.reach_both_funding_final();
        self.assert_step(
            RouteDriveStageV1::DownstreamClaim,
            RouteDriveDispositionV1::Progressed,
        );
        self.assert_step(
            RouteDriveStageV1::DownstreamClaim,
            RouteDriveDispositionV1::Progressed,
        );
        assert!(self
            .supervisor()
            .snapshot()
            .unwrap()
            .secret_public_but_upstream_unclaimed());
    }

    fn take_over(&mut self) {
        self.clock.advance(1_001).expect("expire first lease");
        drop(self.supervisor.take());
        let store =
            DurableRouteStoreV1::open_existing(&self.route_database).expect("reopen route store");
        self.supervisor = Some(
            RouteSupervisorV1::acquire(store, ROUTE, OWNER_B, Self::config(), self.clock.clone())
                .expect("take over route"),
        );
        assert_eq!(self.supervisor().lease_status().fencing_epoch(), 2);
    }

    fn invalidate(&mut self, leg: LegIdV1, action: ActionKindV1, event_id: Digest32) {
        let query = ChainObservationQueryV1::Invalidation {
            leg,
            action,
            transaction_id: tx_for(leg, action),
        };
        let mut observer = std::mem::take(&mut self.observer);
        self.supervisor_mut()
            .record_chain_observation(event_id, query, &mut observer)
            .expect("record reorg invalidation");
        self.observer = observer;
    }

    fn expose_secret(&mut self, event_id: Digest32) {
        let query = ChainObservationQueryV1::SecretExposure {
            chain_id: id(0xe8),
            transaction_id: id(0xe9),
        };
        let mut observer = std::mem::take(&mut self.observer);
        self.supervisor_mut()
            .record_chain_observation(event_id, query, &mut observer)
            .expect("record independent secret exposure");
        self.observer = observer;
    }

    fn set_recovery(&mut self, event_id: Digest32) {
        self.supervisor_mut()
            .set_health(event_id, HealthStateV1::RecoveryOnly, id(0xe0))
            .expect("set recovery-only health");
    }
}

#[test]
fn complete_claim_route_is_incremental_and_secret_handoff_is_urgent() {
    let mut fixture = Fixture::new();
    fixture.reach_downstream_claim_externalized();
    for stage in [
        RouteDriveStageV1::UpstreamClaim,
        RouteDriveStageV1::UpstreamClaim,
        RouteDriveStageV1::UpstreamClaim,
        RouteDriveStageV1::DownstreamClaim,
    ] {
        fixture.assert_step(stage, RouteDriveDispositionV1::Progressed);
    }
    fixture.assert_step(
        RouteDriveStageV1::Terminal,
        RouteDriveDispositionV1::Terminal,
    );
    let snapshot = fixture.supervisor().snapshot().unwrap();
    assert_eq!(snapshot.upstream.claim.progress(), ActionProgressV1::Final);
    assert_eq!(
        snapshot.downstream.claim.progress(),
        ActionProgressV1::Final
    );
    assert_eq!(
        fixture.custody.calls[0],
        (LegIdV1::Downstream, ActionKindV1::Claim)
    );
    assert_eq!(
        fixture.custody.calls[1],
        (LegIdV1::Upstream, ActionKindV1::Claim)
    );
    assert!(fixture
        .actions
        .calls
        .iter()
        .all(|call| { call.action != ActionKindV1::Refund }));
}

#[test]
fn partial_downstream_claim_hands_off_secret_before_aggregate_completion() {
    let mut fixture = Fixture::new();
    fixture.custody.partial_downstream_claim_once = true;
    fixture.reach_both_funding_final();
    for (index, stage) in [
        RouteDriveStageV1::DownstreamClaim,
        RouteDriveStageV1::DownstreamClaim,
        RouteDriveStageV1::UpstreamClaim,
        RouteDriveStageV1::UpstreamClaim,
        RouteDriveStageV1::UpstreamClaim,
        RouteDriveStageV1::DownstreamClaim,
        RouteDriveStageV1::DownstreamClaim,
    ]
    .into_iter()
    .enumerate()
    {
        let report = fixture.drive();
        assert_eq!(report.stage, stage, "unexpected stage at step {index}");
        assert_eq!(
            report.disposition,
            RouteDriveDispositionV1::Progressed,
            "unexpected disposition at step {index} ({stage:?})"
        );
    }
    fixture.assert_step(
        RouteDriveStageV1::Terminal,
        RouteDriveDispositionV1::Terminal,
    );
    let snapshot = fixture.supervisor().snapshot().unwrap();
    assert_eq!(snapshot.upstream.claim.progress(), ActionProgressV1::Final);
    assert_eq!(
        snapshot.downstream.claim.progress(),
        ActionProgressV1::Final
    );
    assert!(matches!(
        snapshot.secret_visibility,
        route_executor::SecretVisibilityV1::Public {
            first_exposure: PublicExposureV1 {
                transaction_id,
                ..
            }
        } if transaction_id == id(0xd6)
    ));
    assert_eq!(
        fixture.custody.calls,
        vec![
            (LegIdV1::Downstream, ActionKindV1::Claim),
            (LegIdV1::Upstream, ActionKindV1::Claim),
            (LegIdV1::Downstream, ActionKindV1::Claim),
        ]
    );
}

#[test]
fn recovery_refunds_downstream_then_upstream_and_never_exposes_secret() {
    let mut fixture = Fixture::new();
    fixture.reach_both_funding_final();
    fixture.set_recovery(id(0xe1));
    for stage in [
        RouteDriveStageV1::DownstreamRefund,
        RouteDriveStageV1::DownstreamRefund,
        RouteDriveStageV1::DownstreamRefund,
        RouteDriveStageV1::UpstreamRefund,
        RouteDriveStageV1::UpstreamRefund,
        RouteDriveStageV1::UpstreamRefund,
    ] {
        fixture.assert_step(stage, RouteDriveDispositionV1::Progressed);
    }
    fixture.assert_step(
        RouteDriveStageV1::Terminal,
        RouteDriveDispositionV1::Terminal,
    );
    let snapshot = fixture.supervisor().snapshot().unwrap();
    assert_eq!(
        snapshot.downstream.refund.progress(),
        ActionProgressV1::Final
    );
    assert_eq!(snapshot.upstream.refund.progress(), ActionProgressV1::Final);
    assert!(fixture.custody.calls.is_empty());
}

#[test]
fn unavailable_authorities_wait_without_changing_the_durable_step_identity() {
    let mut fixture = Fixture::new();
    fixture.assert_step(
        RouteDriveStageV1::Admission,
        RouteDriveDispositionV1::Progressed,
    );

    fixture.refunds.unavailable_once = true;
    fixture.assert_step(
        RouteDriveStageV1::RefundArming,
        RouteDriveDispositionV1::Waiting,
    );
    fixture.assert_step(
        RouteDriveStageV1::RefundArming,
        RouteDriveDispositionV1::Progressed,
    );
    assert_eq!(fixture.refunds.calls[0], fixture.refunds.calls[1]);

    fixture.actions.unavailable_once = Some((LegIdV1::Upstream, ActionKindV1::Funding));
    fixture.assert_step(
        RouteDriveStageV1::UpstreamFunding,
        RouteDriveDispositionV1::Waiting,
    );
    fixture.assert_step(
        RouteDriveStageV1::UpstreamFunding,
        RouteDriveDispositionV1::Progressed,
    );
    assert_eq!(
        fixture.actions.calls[0].event_id,
        fixture.actions.calls[1].event_id
    );

    fixture.runner.unavailable_once = true;
    fixture.assert_step(
        RouteDriveStageV1::UpstreamFunding,
        RouteDriveDispositionV1::Waiting,
    );
    let runner_calls = fixture.runner.calls.len();
    fixture.assert_step(
        RouteDriveStageV1::UpstreamFunding,
        RouteDriveDispositionV1::Waiting,
    );
    assert_eq!(fixture.runner.calls.len(), runner_calls);
    fixture.clock.advance(101).unwrap();
    fixture.assert_step(
        RouteDriveStageV1::UpstreamFunding,
        RouteDriveDispositionV1::Progressed,
    );

    fixture.observer.unavailable_once = true;
    fixture.assert_step(
        RouteDriveStageV1::UpstreamFunding,
        RouteDriveDispositionV1::Waiting,
    );
    fixture.assert_step(
        RouteDriveStageV1::UpstreamFunding,
        RouteDriveDispositionV1::Progressed,
    );
    let observations = &fixture.observer.calls;
    assert_eq!(observations[0].0, observations[1].0);
}

#[test]
fn takeover_stays_inert_until_non_externalization_is_proven_and_refenced() {
    let mut fixture = Fixture::new();
    for stage in [
        RouteDriveStageV1::Admission,
        RouteDriveStageV1::RefundArming,
        RouteDriveStageV1::UpstreamFunding,
    ] {
        fixture.assert_step(stage, RouteDriveDispositionV1::Progressed);
    }
    assert!(matches!(
        fixture.supervisor().snapshot().unwrap().upstream.funding,
        ActionStateV1::Committed(_)
    ));
    fixture.take_over();

    fixture.assert_step(
        RouteDriveStageV1::Takeover,
        RouteDriveDispositionV1::Waiting,
    );
    assert!(fixture.runner.calls.is_empty());
    fixture.reconciler.mode = ReconcileMode::ProveNotExternalized;
    fixture.assert_step(
        RouteDriveStageV1::Takeover,
        RouteDriveDispositionV1::Progressed,
    );
    assert!(fixture.runner.calls.is_empty());
    let reference = match fixture.supervisor().snapshot().unwrap().upstream.funding {
        ActionStateV1::Committed(reference) => reference,
        state => panic!("expected refenced action, got {state:?}"),
    };
    assert_eq!(reference.fencing_epoch, 2);

    fixture.assert_step(
        RouteDriveStageV1::UpstreamFunding,
        RouteDriveDispositionV1::Progressed,
    );
    assert_eq!(fixture.runner.calls.len(), 1);
}

#[test]
fn reorg_after_exposure_keeps_upstream_claim_urgent_and_re_finality_is_distinct() {
    let mut fixture = Fixture::new();
    fixture.reach_downstream_claim_externalized();
    fixture.invalidate(LegIdV1::Upstream, ActionKindV1::Funding, id(0xe2));
    assert_eq!(
        fixture.supervisor().snapshot().unwrap().health,
        HealthStateV1::RecoveryOnly
    );

    for stage in [
        RouteDriveStageV1::UpstreamClaim,
        RouteDriveStageV1::UpstreamClaim,
        RouteDriveStageV1::UpstreamClaim,
        RouteDriveStageV1::DownstreamClaim,
    ] {
        fixture.assert_step(stage, RouteDriveDispositionV1::Progressed);
    }
    fixture.assert_step(
        RouteDriveStageV1::Terminal,
        RouteDriveDispositionV1::Terminal,
    );
    assert!(fixture
        .actions
        .calls
        .iter()
        .all(|call| { call.action != ActionKindV1::Refund }));

    let first_downstream_finality_event = fixture
        .observer
        .calls
        .iter()
        .find_map(|(event_id, query)| {
            (*query
                == ChainObservationQueryV1::Finality {
                    leg: LegIdV1::Downstream,
                    action: ActionKindV1::Claim,
                    transaction_id: tx_for(LegIdV1::Downstream, ActionKindV1::Claim),
                })
            .then_some(*event_id)
        })
        .expect("first downstream claim finality");
    fixture.invalidate(LegIdV1::Downstream, ActionKindV1::Claim, id(0xe3));
    fixture.assert_step(
        RouteDriveStageV1::DownstreamClaim,
        RouteDriveDispositionV1::Progressed,
    );
    let second_downstream_finality_event = fixture.observer.calls.last().unwrap().0;
    assert_ne!(
        first_downstream_finality_event,
        second_downstream_finality_event
    );
    fixture.assert_step(
        RouteDriveStageV1::Terminal,
        RouteDriveDispositionV1::Terminal,
    );
}

#[test]
fn recovery_does_not_compete_with_a_committed_funding_or_claim() {
    let mut before_admission = Fixture::new();
    before_admission.set_recovery(id(0xe6));
    before_admission.assert_step(
        RouteDriveStageV1::Recovery,
        RouteDriveDispositionV1::RecoveryRequired,
    );
    assert!(before_admission.refunds.calls.is_empty());
    assert!(before_admission.actions.calls.is_empty());

    let mut committed_funding = Fixture::new();
    for stage in [
        RouteDriveStageV1::Admission,
        RouteDriveStageV1::RefundArming,
        RouteDriveStageV1::UpstreamFunding,
    ] {
        committed_funding.assert_step(stage, RouteDriveDispositionV1::Progressed);
    }
    committed_funding.set_recovery(id(0xe4));
    committed_funding.assert_step(
        RouteDriveStageV1::Recovery,
        RouteDriveDispositionV1::RecoveryRequired,
    );
    assert_eq!(
        committed_funding
            .actions
            .calls
            .iter()
            .filter(|call| call.action == ActionKindV1::Refund)
            .count(),
        0
    );

    let mut committed_claim = Fixture::new();
    committed_claim.reach_both_funding_final();
    committed_claim.assert_step(
        RouteDriveStageV1::DownstreamClaim,
        RouteDriveDispositionV1::Progressed,
    );
    committed_claim.set_recovery(id(0xe5));
    committed_claim.assert_step(
        RouteDriveStageV1::Recovery,
        RouteDriveDispositionV1::RecoveryRequired,
    );
    assert!(committed_claim.custody.calls.is_empty());
    assert!(committed_claim
        .actions
        .calls
        .iter()
        .all(|call| { call.action != ActionKindV1::Refund }));
}

#[test]
fn independently_public_secret_never_dispatches_unexternalized_funding() {
    let mut not_prepared = Fixture::new();
    for stage in [
        RouteDriveStageV1::Admission,
        RouteDriveStageV1::RefundArming,
    ] {
        not_prepared.assert_step(stage, RouteDriveDispositionV1::Progressed);
    }
    not_prepared.expose_secret(id(0xea));
    not_prepared.assert_step(
        RouteDriveStageV1::Recovery,
        RouteDriveDispositionV1::RecoveryRequired,
    );
    assert!(not_prepared.actions.calls.is_empty());
    assert!(not_prepared.runner.calls.is_empty());

    let mut committed = Fixture::new();
    for stage in [
        RouteDriveStageV1::Admission,
        RouteDriveStageV1::RefundArming,
        RouteDriveStageV1::UpstreamFunding,
    ] {
        committed.assert_step(stage, RouteDriveDispositionV1::Progressed);
    }
    committed.expose_secret(id(0xeb));
    committed.assert_step(
        RouteDriveStageV1::Recovery,
        RouteDriveDispositionV1::RecoveryRequired,
    );
    assert!(committed.runner.calls.is_empty());

    let mut externalized = Fixture::new();
    for stage in [
        RouteDriveStageV1::Admission,
        RouteDriveStageV1::RefundArming,
        RouteDriveStageV1::UpstreamFunding,
        RouteDriveStageV1::UpstreamFunding,
    ] {
        externalized.assert_step(stage, RouteDriveDispositionV1::Progressed);
    }
    externalized.expose_secret(id(0xec));
    externalized.assert_step(
        RouteDriveStageV1::UpstreamFunding,
        RouteDriveDispositionV1::Progressed,
    );
    externalized.assert_step(
        RouteDriveStageV1::UpstreamClaim,
        RouteDriveDispositionV1::Progressed,
    );
}

#[test]
fn due_deadline_timer_preempts_authorization_of_new_funding() {
    let mut fixture = Fixture::new();
    for stage in [
        RouteDriveStageV1::Admission,
        RouteDriveStageV1::RefundArming,
    ] {
        fixture.assert_step(stage, RouteDriveDispositionV1::Progressed);
    }
    fixture
        .supervisor_mut()
        .schedule_timer(id(0xed), TimerKindV1::Deadline, 2_000, id(0xee))
        .expect("schedule due deadline");
    fixture.timers.enter_recovery = true;

    fixture.assert_step(
        RouteDriveStageV1::Timer,
        RouteDriveDispositionV1::Progressed,
    );
    assert!(fixture.actions.calls.is_empty());
    assert!(fixture.runner.calls.is_empty());
    assert_eq!(
        fixture.supervisor().snapshot().unwrap().health,
        HealthStateV1::RecoveryOnly
    );
    fixture.assert_step(
        RouteDriveStageV1::Recovery,
        RouteDriveDispositionV1::RecoveryRequired,
    );

    let mut committed = Fixture::new();
    for stage in [
        RouteDriveStageV1::Admission,
        RouteDriveStageV1::RefundArming,
        RouteDriveStageV1::UpstreamFunding,
    ] {
        committed.assert_step(stage, RouteDriveDispositionV1::Progressed);
    }
    committed
        .supervisor_mut()
        .schedule_timer(id(0xef), TimerKindV1::Deadline, 2_000, id(0xf0))
        .expect("schedule due deadline for committed funding");
    committed.timers.enter_recovery = true;
    committed.assert_step(
        RouteDriveStageV1::Timer,
        RouteDriveDispositionV1::Progressed,
    );
    assert!(matches!(
        committed.supervisor().snapshot().unwrap().upstream.funding,
        ActionStateV1::Committed(_)
    ));
    assert!(committed.runner.calls.is_empty());
}

#[test]
fn due_timer_that_preserves_health_cannot_dispatch_or_prelease_effect() {
    let mut fixture = Fixture::new();
    for stage in [
        RouteDriveStageV1::Admission,
        RouteDriveStageV1::RefundArming,
        RouteDriveStageV1::UpstreamFunding,
    ] {
        fixture.assert_step(stage, RouteDriveDispositionV1::Progressed);
    }
    fixture
        .supervisor_mut()
        .schedule_timer(id(0xf3), TimerKindV1::Retry, 2_000, id(0xf4))
        .expect("schedule due retry timer");
    fixture.timers.schedule_follow_up = true;

    fixture.assert_step(
        RouteDriveStageV1::Timer,
        RouteDriveDispositionV1::Progressed,
    );
    assert_eq!(fixture.timers.calls, 1);
    assert!(fixture.runner.calls.is_empty());
    assert_eq!(
        fixture.supervisor().snapshot().unwrap().health,
        HealthStateV1::Running
    );
    assert!(matches!(
        fixture.supervisor().snapshot().unwrap().upstream.funding,
        ActionStateV1::Committed(_)
    ));

    // The timer-only step did not lease the economic row. The immediately
    // following drive can claim and externalize that same committed funding.
    fixture.timers.schedule_follow_up = false;
    fixture.assert_step(
        RouteDriveStageV1::UpstreamFunding,
        RouteDriveDispositionV1::Progressed,
    );
    assert_eq!(fixture.runner.calls.len(), 1);
}

#[test]
fn public_secret_claim_authorization_preempts_an_unavailable_due_timer() {
    let mut fixture = Fixture::new();
    fixture.reach_downstream_claim_externalized();
    fixture
        .supervisor_mut()
        .schedule_timer(id(0xf1), TimerKindV1::Deadline, 2_000, id(0xf2))
        .expect("schedule timer competing with urgent claim");

    fixture.assert_step(
        RouteDriveStageV1::UpstreamClaim,
        RouteDriveDispositionV1::Progressed,
    );
    assert_eq!(fixture.timers.calls, 0);
    assert!(matches!(
        fixture.supervisor().snapshot().unwrap().upstream.claim,
        ActionStateV1::Committed(_)
    ));
}

#[test]
fn mismatched_pinned_admission_is_rejected_before_takeover_reconciliation() {
    let mut fixture = Fixture::new();
    for stage in [
        RouteDriveStageV1::Admission,
        RouteDriveStageV1::RefundArming,
        RouteDriveStageV1::UpstreamFunding,
    ] {
        fixture.assert_step(stage, RouteDriveDispositionV1::Progressed);
    }
    fixture.take_over();
    let wrong_admission = authenticated_admission(
        &fixture._temporary.path().join("wrong-registry.sqlite3"),
        id(0x74),
    );
    let before = fixture.supervisor().snapshot().unwrap().revision;
    let mut authorities = RouteDriverAuthoritiesV1 {
        refund: &mut fixture.refunds,
        action: &mut fixture.actions,
        observer: &mut fixture.observer,
        runner: &mut fixture.runner,
        external_custody: &mut fixture.custody,
        timers: &mut fixture.timers,
        reconciler: &mut fixture.reconciler,
    };
    let error = drive_route_once_v1(
        fixture.supervisor.as_mut().expect("live supervisor"),
        &wrong_admission,
        &mut authorities,
    )
    .expect_err("mismatched pinned admission must fail closed");
    assert!(matches!(error, RouteDriverErrorV1::AdmissionMismatch));
    assert_eq!(fixture.reconciler.calls, 0);
    assert_eq!(fixture.supervisor().snapshot().unwrap().revision, before);
}

#[test]
fn runtime_stops_without_a_step_when_shutdown_is_safe_and_unfunded() {
    let (_temporary, mut runtime) = Fixture::new().into_runtime();
    let mut control = TestRunControl {
        shutdown: true,
        ..TestRunControl::default()
    };
    assert_eq!(
        runtime.run_bounded(&mut control, 1).expect("safe stop"),
        RouteRuntimeExitV1::SafeShutdown {
            revision: 0,
            steps: 0,
        }
    );
    assert!(control.reports.is_empty());
    assert!(control.waits.is_empty());
}

#[test]
fn runtime_owns_the_incremental_loop_until_both_legs_are_terminal() {
    let (_temporary, mut runtime) = Fixture::new_production().into_runtime();
    let mut control = TestRunControl::default();
    let exit = runtime
        .run_bounded(&mut control, 64)
        .expect("terminal route loop");
    let RouteRuntimeExitV1::Terminal { revision, steps } = exit else {
        panic!("route did not terminate: {exit:?}");
    };
    assert!(steps > 1);
    assert_eq!(runtime.snapshot().unwrap().revision, revision);
    assert_eq!(control.reports.len(), usize::try_from(steps).unwrap());
    assert!(control.waits.is_empty());
}

#[test]
fn runtime_never_reports_public_terminal_until_retirement_retry_succeeds() {
    let mut fixture = Fixture::new_production();
    fixture
        .retirement
        .outcomes
        .push_back(Err(AuthorityRefusalV1::Unavailable));
    let retirement_calls = Rc::clone(&fixture.retirement.calls);
    let (_temporary, mut runtime) = fixture.into_runtime();
    let mut control = TestRunControl::default();

    let error = runtime
        .run_bounded(&mut control, 64)
        .expect_err("first terminal retirement attempt must fail closed");
    assert!(matches!(
        error,
        RouteRuntimeErrorV1::SecretRetirement(AuthorityRefusalV1::Unavailable)
    ));
    assert_eq!(
        runtime.snapshot().unwrap().coordination,
        CoordinationPhaseV1::Terminal
    );
    assert_eq!(retirement_calls.get(), 1);

    // A restarted loop replays the terminal Store predicate, receives a new
    // move-only capability and retries the idempotent retirement before it is
    // allowed to report Terminal.
    assert!(matches!(
        runtime
            .run_bounded(&mut control, 1)
            .expect("retirement retry"),
        RouteRuntimeExitV1::Terminal { steps: 0, .. }
    ));
    assert_eq!(retirement_calls.get(), 2);
}

#[test]
fn private_refund_terminal_does_not_mint_a_public_secret_retirement() {
    let mut fixture = Fixture::new();
    fixture.reach_both_funding_final();
    fixture.set_recovery(id(0xE7));
    let retirement_calls = Rc::clone(&fixture.retirement.calls);
    let (_temporary, mut runtime) = fixture.into_runtime();
    let mut control = TestRunControl::default();

    assert!(matches!(
        runtime
            .run_bounded(&mut control, 64)
            .expect("private refund terminal"),
        RouteRuntimeExitV1::Terminal { .. }
    ));
    assert_eq!(retirement_calls.get(), 0);
}

#[test]
fn shutdown_is_deferred_through_the_public_secret_urgent_lane() {
    let mut fixture = Fixture::new_production();
    fixture.reach_downstream_claim_externalized();
    assert!(fixture
        .supervisor()
        .snapshot()
        .unwrap()
        .secret_public_but_upstream_unclaimed());
    let (_temporary, mut runtime) = fixture.into_runtime();
    let mut control = TestRunControl {
        shutdown: true,
        ..TestRunControl::default()
    };

    let exit = runtime
        .run_bounded(&mut control, 32)
        .expect("urgent route drains despite shutdown");
    assert!(matches!(exit, RouteRuntimeExitV1::Terminal { .. }));
    assert!(!control.reports.is_empty());
    assert!(!runtime
        .snapshot()
        .unwrap()
        .secret_public_but_upstream_unclaimed());
}
