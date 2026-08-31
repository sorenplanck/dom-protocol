//! Deterministic, durable end-to-end exercise driven by the daemon binary.
//!
//! The simulation deliberately keeps the route journal and the simulated
//! chain authority in separate SQLite databases.  The chain authority commits
//! an idempotent public transaction record before returning a receipt, so a
//! process exit at that boundary exercises the same ambiguity a production
//! broadcaster must reconcile.  No route scalar or secret-bearing transaction
//! bytes are represented by this module.

use std::cell::RefCell;
use std::collections::BTreeSet;
use std::fs::{self, File, OpenOptions};
use std::path::{Path, PathBuf};
use std::process;
use std::rc::Rc;

use adapter_btc::timelock::ChainTimingBoundsV1;
use blake2::{digest::consts::U32, Blake2b, Digest as BlakeDigest};
use btc_crypto::SecpContext;
use chain_profile::{ChainKindV1, ChainProfileV1};
use deployment_registry::{
    AssetBindingV1, AssetRepresentationV1, AuthoritySetV1, ChainDeploymentV1, DomDeploymentV1,
    DomNetworkV1, DomRuntimeIdentityV1, EvmDeploymentV1, RegistryChainProfileV1,
    RegistryManifestV1, RegistrySignatureV1, RegistryStoreV1, RegistryValidationPolicyV1,
    SignedRegistryV1,
};
use fs2::FileExt;
use kaystra_core::types::{AssetId, ChainId, FinalityPolicyV1};
use route_executor::{
    digest_bytes_v1, ActionIntentV1, ActionKindV1, ActionProgressV1, CoordinationPhaseV1, Digest32,
    DurableRouteStoreV1, EffectDispatchV1, FrozenBindingsV1, LegIdV1, RefundBindingsV1,
    RouteEventV1, RouteStoreErrorV1, SecretVisibilityV1, TimerKindV1,
};
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use serde::Serialize;

use crate::admission::{
    AuthenticatedRouteAdmissionV1, RegistryRouteAdmissionAuthorityV1, RouteAdmissionRefusalV1,
    RouteAdmissionRequestV1, RouteLegSelectionV1,
};
use crate::supervisor::{
    ActionExternalizationReceiptV1, AuthorityRefusalV1, ChainObservationAuthority,
    ChainObservationQueryV1, ChainObservationRequestV1, ClockErrorV1, CustodyDispatchOutcomeV1,
    ExternalCustodyActionRequestV1, ExternalCustodyAuthority, ManualClockV1,
    ReconciliationRequestV1, RefundArmingAuthority, RefundArmingRequestV1, RouteActionAuthority,
    RouteActionAuthorizationRequestV1, RouteSupervisorConfigV1, RouteSupervisorErrorV1,
    RouteSupervisorTickReportV1, RouteSupervisorV1, RunnerActionAuthority, RunnerActionRequestV1,
    TakeoverReconciliationAuthority, TakeoverReconciliationOutcomeV1,
    TakeoverReconciliationReportV1, TimerAuthority, TimerDispatchV1, TimerEventCommitV1,
    VerifiedChainObservationV1,
};

/// Exit status used only for a requested abrupt simulation cut.
pub const SIMULATION_CRASH_EXIT_CODE_V1: u8 = 86;

const AUTHORITY_SCHEMA_VERSION: i64 = 2;
const AUTHORITY_APPLICATION_ID: i64 = 0x444f_4d53;
const INITIAL_CLOCK_MS: u64 = 1_000_000;
const INVOCATION_CLOCK_STEP_MS: u64 = 10_000;
const LEASE_DURATION_MS: u64 = 1_000;
const RENEW_BEFORE_MS: u64 = 300;
const DISPATCH_LEASE_MS: u64 = 200;
const DOWNSTREAM_REFUND_DEADLINE_MS: u64 = 1_010_400;
const UPSTREAM_REFUND_DEADLINE_MS: u64 = 1_010_800;
const ZERO_DIGEST: Digest32 = [0; 32];

const ROUTE_DOMAIN: &[u8] = b"DOM-INTEROPD/SIMULATION/ROUTE/V1\0";
const OWNER_DOMAIN: &[u8] = b"DOM-INTEROPD/SIMULATION/OWNER/V1\0";
const EVENT_DOMAIN: &[u8] = b"DOM-INTEROPD/SIMULATION/EVENT/V1\0";
const MATERIAL_DOMAIN: &[u8] = b"DOM-INTEROPD/SIMULATION/MATERIAL/V1\0";
const RUNNER_TRANSACTION_DOMAIN: &[u8] = b"DOM-INTEROPD/SIMULATION/RUNNER-TX/V1\0";
const CHAIN_DOMAIN: &[u8] = b"DOM-INTEROPD/SIMULATION/CHAIN/V1\0";
const EXPOSURE_DOMAIN: &[u8] = b"DOM-INTEROPD/SIMULATION/EXPOSURE/V1\0";
const RECONCILIATION_DOMAIN: &[u8] = b"DOM-INTEROPD/SIMULATION/RECONCILIATION/V1\0";
const AUTHORITY_STATE_DOMAIN: &[u8] = b"DOM-INTEROPD/SIMULATION/AUTHORITY-STATE/V1\0";

const SIMULATION_NETWORK: Digest32 = [0x90; 32];
const SIMULATION_DOM_CHAIN: ChainId = ChainId([
    0x22, 0x38, 0x4b, 0x4c, 0xbf, 0xaa, 0xe3, 0x06, 0xa7, 0xbd, 0xb2, 0x3a, 0x82, 0x24, 0x42, 0xf7,
    0xe6, 0x8f, 0xb5, 0x1f, 0x65, 0x32, 0x86, 0x97, 0xa7, 0x54, 0xa9, 0xf3, 0xab, 0xd6, 0x98, 0xe1,
]);
const SIMULATION_DOM_GENESIS: Digest32 = [
    0xfd, 0xda, 0x02, 0x7e, 0x4a, 0x46, 0xdd, 0x36, 0x67, 0x17, 0xc6, 0xe0, 0xa9, 0x76, 0xbf, 0x3e,
    0x0a, 0x75, 0x12, 0xc5, 0xed, 0xf0, 0x84, 0x70, 0xb0, 0xdc, 0xa9, 0x9d, 0xde, 0xe3, 0xfe, 0x1f,
];
const SIMULATION_EVM_CHAIN: ChainId = ChainId([0x20; 32]);
const SIMULATION_DOM_ASSET: AssetId = AssetId([0x30; 32]);
const SIMULATION_EVM_NATIVE: AssetId = AssetId([0x40; 32]);
const SIMULATION_EVM_TOKEN: AssetId = AssetId([0x41; 32]);

type RefundArmRowV1 = (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>);
type DeadlineFiringRowV1 = (Vec<u8>, i64, i64, Vec<u8>, Vec<u8>);

/// Closed simulation route outcome.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SimulationScenarioV1 {
    /// Both legs finalize through their claim paths.
    Claim,
    /// Both legs finalize through deadline-authorized refund paths.
    Refund,
}

impl SimulationScenarioV1 {
    fn tag(self) -> &'static str {
        match self {
            Self::Claim => "claim",
            Self::Refund => "refund",
        }
    }
}

/// Explicit process-cut boundary available only in the simulation feature.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SimulationCrashPointV1 {
    /// Exit after the chain authority durably records a new broadcast but
    /// before the receipt can drive `ActionExternalized`.
    AfterAuthorityPersist,
    /// Exit after a timer's route event committed but before timer completion.
    AfterTimerEventCommit,
}

impl SimulationCrashPointV1 {
    fn tag(self) -> i64 {
        match self {
            Self::AfterAuthorityPersist => 1,
            Self::AfterTimerEventCommit => 2,
        }
    }
}

/// Inputs to one resumable daemon simulation invocation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SimulationOptionsV1 {
    /// Directory retaining both independent durable databases and the process
    /// lock.  A directory is permanently bound to one scenario.
    pub state_dir: PathBuf,
    /// Claim or refund route to drive to a terminal state.
    pub scenario: SimulationScenarioV1,
    /// Optional one-shot abrupt process cut.
    pub crash_after: Option<SimulationCrashPointV1>,
}

/// One public chain-authority row included in the terminal proof.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct SimulationExternalizationV1 {
    /// Durable effect idempotency key in lowercase hexadecimal.
    pub effect_id: String,
    /// Stable public transaction id in lowercase hexadecimal.
    pub transaction_id: String,
    /// `upstream` or `downstream`.
    pub leg: &'static str,
    /// `funding`, `claim`, or `refund`.
    pub action: &'static str,
    /// Whether the external authority owns secret-bearing bytes.  Such bytes
    /// are not present in either simulation database or this report.
    pub externally_custodied: bool,
    /// Economic externalizations for this exact effect; invariantly one.
    pub broadcast_count: u64,
    /// Scoped capability deliveries, including idempotent retries.
    pub delivery_attempts: u64,
}

/// Machine-verifiable terminal result emitted as one JSON object.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct SimulationReportV1 {
    /// Stable report schema identifier.
    pub schema: &'static str,
    /// Closed build mode used for this execution.
    pub build_mode: &'static str,
    /// Requested terminal path.
    pub scenario: SimulationScenarioV1,
    /// Stable route id in lowercase hexadecimal.
    pub route_id: String,
    /// Durable invocation counter for this state directory.
    pub invocation: u64,
    /// Fencing generation held by the successful process.
    pub fencing_epoch: u64,
    /// Final route snapshot revision.
    pub revision: u64,
    /// Number of replay-verified journal entries.
    pub journal_entries: u64,
    /// Last canonical route event digest.
    pub journal_head_digest: String,
    /// Always true after all final invariants have been checked.
    pub terminal: bool,
    /// Whether public exposure was irreversibly recorded.
    pub secret_public: bool,
    /// Final upstream economic outcome.
    pub upstream_outcome: &'static str,
    /// Final downstream economic outcome.
    pub downstream_outcome: &'static str,
    /// Remaining economic outbox rows.
    pub pending_effects: u64,
    /// Remaining active timers.
    pub active_timers: u64,
    /// Old-fence broadcasts recovered from the chain authority.
    pub takeover_externalized: u64,
    /// Old-fence actions proven absent and safely re-fenced.
    pub takeover_reauthorized: u64,
    /// Old-fence actions deliberately left inert due to unknown evidence.
    pub takeover_unknown: u64,
    /// Timer events recognized as byte-identical durable duplicates.
    pub duplicate_timer_events: u64,
    /// Secret-public upstream actions dispatched through the urgent lane.
    pub urgent_externalizations: u64,
    /// Count of unique public economic transactions.
    pub unique_externalizations: u64,
    /// Sum of per-effect broadcast counts; equals unique externalizations.
    pub economic_broadcasts: u64,
    /// Count of consumed one-shot dispatch capabilities.
    pub consumed_attempt_capabilities: u64,
    /// BLAKE2b-256 commitment to every field in the ordered public
    /// externalization rows.
    pub authority_state_digest: String,
    /// Ordered public transaction proof rows.
    pub externalizations: Vec<SimulationExternalizationV1>,
}

/// Fail-closed simulation error.  Paths and persisted opaque bytes are not
/// included in display strings.
#[derive(Debug, thiserror::Error)]
pub enum SimulationErrorV1 {
    /// The simulation state directory or SQLite authority was unavailable.
    #[error("simulation durable state unavailable")]
    StateUnavailable,
    /// Another daemon currently owns the state directory.
    #[error("simulation state is already owned by another process")]
    StateInUse,
    /// Existing state belongs to a different scenario.
    #[error("simulation state scenario mismatch")]
    ScenarioMismatch,
    /// The authority schema is absent, newer, or structurally incompatible.
    #[error("unsupported simulation authority state")]
    UnsupportedState,
    /// A retained authority row conflicts with an exact scoped capability.
    #[error("simulation authority state is inconsistent")]
    InconsistentAuthorityState,
    /// The selected crash point cannot occur in this scenario.
    #[error("invalid simulation crash point for scenario")]
    InvalidCrashPoint,
    /// The real signed deployment-registry admission path refused startup.
    #[error("simulation authenticated route admission failed")]
    AuthenticatedAdmission,
    /// Durable route store refused an operation.
    #[error("simulation route store: {0}")]
    RouteStore(#[from] RouteStoreErrorV1),
    /// Route supervisor refused an operation.
    #[error("simulation supervisor: {0}")]
    Supervisor(#[from] RouteSupervisorErrorV1),
    /// Deterministic clock refused an operation.
    #[error("simulation clock: {0}")]
    Clock(#[from] ClockErrorV1),
    /// The route stopped short of the requested exact terminal result.
    #[error("simulation terminal invariants were not satisfied")]
    TerminalInvariant,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ExternalizationRecordV1 {
    effect_id: Digest32,
    route_id: Digest32,
    leg: LegIdV1,
    action: ActionKindV1,
    semantic_digest: Digest32,
    terms_digest: Digest32,
    profile_digest: Digest32,
    deployment_digest: Digest32,
    fencing_epoch: u64,
    dispatch_digest: Digest32,
    expected_transaction_id: Option<Digest32>,
    contains_route_secret: bool,
    transaction_id: Digest32,
    chain_id: Option<Digest32>,
    evidence_digest: Option<Digest32>,
    broadcast_count: u64,
    delivery_attempts: u64,
}

struct SimulationAuthorityDbV1 {
    connection: Connection,
    scenario: SimulationScenarioV1,
    crash_after: Option<SimulationCrashPointV1>,
}

struct SimulationSessionV1 {
    _lock: File,
    authority: Rc<RefCell<SimulationAuthorityDbV1>>,
    invocation: u64,
    now_unix_ms: u64,
}

impl SimulationSessionV1 {
    fn open(options: &SimulationOptionsV1) -> Result<Self, SimulationErrorV1> {
        if options.state_dir.as_os_str().is_empty() {
            return Err(SimulationErrorV1::StateUnavailable);
        }
        if options.crash_after == Some(SimulationCrashPointV1::AfterTimerEventCommit)
            && options.scenario != SimulationScenarioV1::Refund
        {
            return Err(SimulationErrorV1::InvalidCrashPoint);
        }
        fs::create_dir_all(&options.state_dir).map_err(|_| SimulationErrorV1::StateUnavailable)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            fs::set_permissions(&options.state_dir, fs::Permissions::from_mode(0o700))
                .map_err(|_| SimulationErrorV1::StateUnavailable)?;
        }
        let lock_path = options.state_dir.join("simulation.lock");
        let lock = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(lock_path)
            .map_err(|_| SimulationErrorV1::StateUnavailable)?;
        FileExt::try_lock_exclusive(&lock).map_err(|_| SimulationErrorV1::StateInUse)?;

        let database_path = options.state_dir.join("chain-authority.sqlite3");
        let mut connection =
            Connection::open(database_path).map_err(|_| SimulationErrorV1::StateUnavailable)?;
        configure_authority_connection(&connection)?;
        initialize_authority_schema(&connection, options.scenario)?;
        let InvocationStartV1 {
            invocation,
            now_unix_ms,
        } = begin_invocation(&mut connection)?;
        Ok(Self {
            _lock: lock,
            authority: Rc::new(RefCell::new(SimulationAuthorityDbV1 {
                connection,
                scenario: options.scenario,
                crash_after: options.crash_after,
            })),
            invocation,
            now_unix_ms,
        })
    }

    fn persist_clock(&self, now_unix_ms: u64) -> Result<(), SimulationErrorV1> {
        self.authority
            .try_borrow_mut()
            .map_err(|_| SimulationErrorV1::InconsistentAuthorityState)?
            .persist_clock(now_unix_ms)
    }
}

impl SimulationAuthorityDbV1 {
    fn persist_clock(&mut self, now_unix_ms: u64) -> Result<(), SimulationErrorV1> {
        let value = to_i64(now_unix_ms)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| SimulationErrorV1::StateUnavailable)?;
        let current: i64 = transaction
            .query_row(
                "SELECT clock_high_water_ms FROM simulation_meta WHERE singleton = 1",
                [],
                |row| row.get(0),
            )
            .map_err(|_| SimulationErrorV1::UnsupportedState)?;
        if value < current {
            return Err(SimulationErrorV1::InconsistentAuthorityState);
        }
        transaction
            .execute(
                "UPDATE simulation_meta SET clock_high_water_ms = ?1 WHERE singleton = 1",
                params![value],
            )
            .map_err(|_| SimulationErrorV1::StateUnavailable)?;
        transaction
            .commit()
            .map_err(|_| SimulationErrorV1::StateUnavailable)
    }

    fn arm_refunds(
        &mut self,
        route_id: Digest32,
        bindings: &FrozenBindingsV1,
    ) -> Result<RefundBindingsV1, AuthorityRefusalV1> {
        if route_id != crate::simulation::route_id(self.scenario) {
            return Err(AuthorityRefusalV1::Inconsistent);
        }
        let refunds = RefundBindingsV1 {
            upstream_refund_digest: digest_parts(
                MATERIAL_DOMAIN,
                &[
                    b"durable-upstream-refund",
                    &route_id,
                    &bindings.terms_digest,
                    &bindings.profile_bundle_digest,
                    &bindings.deployment_bundle_digest,
                ],
            ),
            downstream_refund_digest: digest_parts(
                MATERIAL_DOMAIN,
                &[
                    b"durable-downstream-refund",
                    &route_id,
                    &bindings.terms_digest,
                    &bindings.profile_bundle_digest,
                    &bindings.deployment_bundle_digest,
                ],
            ),
        };
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| AuthorityRefusalV1::Unavailable)?;
        let existing: Option<RefundArmRowV1> = transaction
            .query_row(
                "SELECT terms_digest, profile_digest, deployment_digest,
                        upstream_refund_digest, downstream_refund_digest
                 FROM refund_arms WHERE route_id = ?1",
                params![route_id.as_slice()],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                    ))
                },
            )
            .optional()
            .map_err(|_| AuthorityRefusalV1::Unavailable)?;
        if let Some((terms, profile, deployment, upstream, downstream)) = existing {
            let matches = blob32(terms).ok() == Some(bindings.terms_digest)
                && blob32(profile).ok() == Some(bindings.profile_bundle_digest)
                && blob32(deployment).ok() == Some(bindings.deployment_bundle_digest)
                && blob32(upstream).ok() == Some(refunds.upstream_refund_digest)
                && blob32(downstream).ok() == Some(refunds.downstream_refund_digest);
            if !matches {
                return Err(AuthorityRefusalV1::Inconsistent);
            }
        } else {
            let changed = transaction
                .execute(
                    "INSERT INTO refund_arms (
                         route_id, terms_digest, profile_digest, deployment_digest,
                         upstream_refund_digest, downstream_refund_digest
                     ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                    params![
                        route_id.as_slice(),
                        bindings.terms_digest.as_slice(),
                        bindings.profile_bundle_digest.as_slice(),
                        bindings.deployment_bundle_digest.as_slice(),
                        refunds.upstream_refund_digest.as_slice(),
                        refunds.downstream_refund_digest.as_slice(),
                    ],
                )
                .map_err(|_| AuthorityRefusalV1::Unavailable)?;
            if changed != 1 {
                return Err(AuthorityRefusalV1::Inconsistent);
            }
        }
        transaction
            .commit()
            .map_err(|_| AuthorityRefusalV1::Unavailable)?;
        Ok(refunds)
    }

    fn verify_finality(
        &self,
        request: &ChainObservationRequestV1<'_>,
        leg: LegIdV1,
        action: ActionKindV1,
        transaction_id: Digest32,
    ) -> Result<VerifiedChainObservationV1, AuthorityRefusalV1> {
        let state = request.snapshot().leg(leg).action(action);
        if state.progress() != ActionProgressV1::Externalized
            || state.transaction_id() != Some(transaction_id)
        {
            return Err(AuthorityRefusalV1::Refused);
        }
        let effect = state.effect().ok_or(AuthorityRefusalV1::Inconsistent)?;
        let retained = load_externalization(&self.connection, effect.effect_id)
            .map_err(|_| AuthorityRefusalV1::Inconsistent)?
            .ok_or(AuthorityRefusalV1::Inconsistent)?;
        if retained.route_id != request.route_id()
            || retained.leg != leg
            || retained.action != action
            || retained.transaction_id != transaction_id
            || retained.semantic_digest != effect.semantic_digest
            || retained.terms_digest != request.bindings().terms_digest
            || retained.profile_digest != request.bindings().profile_bundle_digest
            || retained.deployment_digest != request.bindings().deployment_bundle_digest
        {
            return Err(AuthorityRefusalV1::Inconsistent);
        }
        Ok(VerifiedChainObservationV1::Finality {
            evidence_digest: digest_parts(
                MATERIAL_DOMAIN,
                &[
                    b"simulated-finality",
                    &request.route_id(),
                    &effect.effect_id,
                    &transaction_id,
                ],
            ),
        })
    }

    fn record_deadline(
        &mut self,
        timer: &TimerDispatchV1,
        leg: LegIdV1,
    ) -> Result<Digest32, AuthorityRefusalV1> {
        if timer.route_id() != route_id(self.scenario) {
            return Err(AuthorityRefusalV1::Inconsistent);
        }
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| AuthorityRefusalV1::Unavailable)?;
        let existing: Option<DeadlineFiringRowV1> = transaction
            .query_row(
                "SELECT route_id, leg_tag, deadline_unix_ms, context_digest,
                        timer_event_id
                 FROM deadline_firings WHERE timer_id = ?1",
                params![timer.timer_id().as_slice()],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                    ))
                },
            )
            .optional()
            .map_err(|_| AuthorityRefusalV1::Unavailable)?;
        if let Some((retained_route, retained_leg, deadline, context, event_id)) = existing {
            if blob32(retained_route).ok() != Some(timer.route_id())
                || retained_leg != leg_tag(leg)
                || from_i64(deadline).ok() != Some(timer.deadline_unix_ms())
                || blob32(context).ok() != Some(timer.context_digest())
                || blob32(event_id).ok() != Some(timer.event_id())
            {
                return Err(AuthorityRefusalV1::Inconsistent);
            }
        } else {
            let changed = transaction
                .execute(
                    "INSERT INTO deadline_firings (
                         timer_id, route_id, leg_tag, deadline_unix_ms,
                         context_digest, timer_event_id
                     ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                    params![
                        timer.timer_id().as_slice(),
                        timer.route_id().as_slice(),
                        leg_tag(leg),
                        to_i64(timer.deadline_unix_ms())
                            .map_err(|_| AuthorityRefusalV1::Inconsistent)?,
                        timer.context_digest().as_slice(),
                        timer.event_id().as_slice(),
                    ],
                )
                .map_err(|_| AuthorityRefusalV1::Unavailable)?;
            if changed != 1 {
                return Err(AuthorityRefusalV1::Inconsistent);
            }
        }
        transaction
            .commit()
            .map_err(|_| AuthorityRefusalV1::Unavailable)?;
        Ok(digest_parts(
            MATERIAL_DOMAIN,
            &[
                b"deadline-fired",
                &timer.route_id(),
                &timer.timer_id(),
                &[match leg {
                    LegIdV1::Upstream => 0,
                    LegIdV1::Downstream => 1,
                }],
                &timer.deadline_unix_ms().to_be_bytes(),
                &timer.context_digest(),
            ],
        ))
    }

    fn deadline_fired(
        &self,
        requested_route: Digest32,
        leg: LegIdV1,
    ) -> Result<bool, AuthorityRefusalV1> {
        let (deadline, context) = match leg {
            LegIdV1::Upstream => (
                UPSTREAM_REFUND_DEADLINE_MS,
                material("upstream-refund-deadline"),
            ),
            LegIdV1::Downstream => (
                DOWNSTREAM_REFUND_DEADLINE_MS,
                material("downstream-refund-deadline"),
            ),
        };
        let count: i64 = self
            .connection
            .query_row(
                "SELECT COUNT(*) FROM deadline_firings
                 WHERE route_id = ?1 AND leg_tag = ?2
                   AND deadline_unix_ms = ?3 AND context_digest = ?4",
                params![
                    requested_route.as_slice(),
                    leg_tag(leg),
                    to_i64(deadline).map_err(|_| AuthorityRefusalV1::Inconsistent)?,
                    context.as_slice(),
                ],
                |row| row.get(0),
            )
            .map_err(|_| AuthorityRefusalV1::Unavailable)?;
        Ok(count == 1)
    }

    fn externalize(
        &mut self,
        request: ExternalizationRecordV1,
        attempt_id: Digest32,
    ) -> Result<ActionExternalizationReceiptV1, AuthorityRefusalV1> {
        if attempt_id == ZERO_DIGEST || request.route_id != route_id(self.scenario) {
            return Err(AuthorityRefusalV1::Inconsistent);
        }
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| AuthorityRefusalV1::Unavailable)?;
        match transaction.execute(
            "INSERT INTO consumed_attempts (attempt_id, effect_id)
             VALUES (?1, ?2)",
            params![attempt_id.as_slice(), request.effect_id.as_slice()],
        ) {
            Ok(1) => {}
            Ok(_) => return Err(AuthorityRefusalV1::Inconsistent),
            Err(error) if is_constraint(&error) => return Err(AuthorityRefusalV1::Inconsistent),
            Err(_) => return Err(AuthorityRefusalV1::Unavailable),
        }

        let existing = load_externalization(&transaction, request.effect_id)
            .map_err(|_| AuthorityRefusalV1::Inconsistent)?;
        let newly_externalized = if let Some(mut retained) = existing {
            let retained_attempts = retained.delivery_attempts;
            retained.delivery_attempts = request.delivery_attempts;
            if retained != request || retained_attempts == u64::MAX {
                return Err(AuthorityRefusalV1::Inconsistent);
            }
            transaction
                .execute(
                    "UPDATE externalizations
                     SET delivery_attempts = delivery_attempts + 1
                     WHERE effect_id = ?1",
                    params![request.effect_id.as_slice()],
                )
                .map_err(|_| AuthorityRefusalV1::Unavailable)?;
            false
        } else {
            insert_externalization(&transaction, &request)
                .map_err(|_| AuthorityRefusalV1::Inconsistent)?;
            true
        };
        transaction
            .commit()
            .map_err(|_| AuthorityRefusalV1::Unavailable)?;
        if newly_externalized
            && request.contains_route_secret
            && self.crash_after == Some(SimulationCrashPointV1::AfterAuthorityPersist)
            && self
                .mark_fault_once(SimulationCrashPointV1::AfterAuthorityPersist)
                .map_err(|_| AuthorityRefusalV1::Unavailable)?
        {
            process::exit(SIMULATION_CRASH_EXIT_CODE_V1.into());
        }
        Ok(receipt_for_record(&request))
    }

    fn reconcile(
        &mut self,
        request: ReconciliationRequestV1<'_>,
    ) -> Result<TakeoverReconciliationOutcomeV1, AuthorityRefusalV1> {
        let existing = load_externalization(&self.connection, request.effect_id())
            .map_err(|_| AuthorityRefusalV1::Inconsistent)?;
        if let Some(retained) = existing {
            if !reconciliation_matches(&retained, &request) {
                return Err(AuthorityRefusalV1::Inconsistent);
            }
            return Ok(TakeoverReconciliationOutcomeV1::Externalized(
                receipt_for_record(&retained),
            ));
        }
        let evidence = digest_parts(
            RECONCILIATION_DOMAIN,
            &[
                &request.route_id(),
                &request.effect_id(),
                &request.prior_fence().to_be_bytes(),
                &request.current_fence().to_be_bytes(),
                &request.dispatch_digest(),
            ],
        );
        Ok(TakeoverReconciliationOutcomeV1::ProvenNotExternalized {
            intent: request.intent().clone(),
            evidence_digest: evidence,
        })
    }

    fn mark_fault_once(
        &mut self,
        point: SimulationCrashPointV1,
    ) -> Result<bool, SimulationErrorV1> {
        let changed = self
            .connection
            .execute(
                "INSERT OR IGNORE INTO injected_faults (fault_tag) VALUES (?1)",
                params![point.tag()],
            )
            .map_err(|_| SimulationErrorV1::StateUnavailable)?;
        Ok(changed == 1)
    }

    fn terminal_stats(&self) -> Result<AuthorityStatsV1, SimulationErrorV1> {
        let mut statement = self
            .connection
            .prepare(
                "SELECT effect_id, route_id, leg_tag, action_tag, semantic_digest,
                        terms_digest, profile_digest, deployment_digest,
                        fencing_epoch, dispatch_digest, expected_transaction_id,
                        contains_route_secret, transaction_id, chain_id,
                        evidence_digest, broadcast_count, delivery_attempts
                 FROM externalizations ORDER BY effect_id ASC",
            )
            .map_err(|_| SimulationErrorV1::StateUnavailable)?;
        let rows = statement
            .query_map([], read_externalization_row)
            .map_err(|_| SimulationErrorV1::StateUnavailable)?;
        let mut records = Vec::new();
        for row in rows {
            records.push(row.map_err(|_| SimulationErrorV1::InconsistentAuthorityState)??);
        }
        let consumed_attempts: i64 = self
            .connection
            .query_row("SELECT COUNT(*) FROM consumed_attempts", [], |row| {
                row.get(0)
            })
            .map_err(|_| SimulationErrorV1::StateUnavailable)?;
        AuthorityStatsV1::from_records(records, from_i64(consumed_attempts)?)
    }
}

#[derive(Clone)]
struct AuthorityHandleV1(Rc<RefCell<SimulationAuthorityDbV1>>);

struct SimulatedRunnerV1(AuthorityHandleV1);
struct SimulatedCustodyV1(AuthorityHandleV1);
struct SimulatedTimerV1(AuthorityHandleV1);
struct SimulatedReconcilerV1(AuthorityHandleV1);
struct SimulatedRefundArmerV1(AuthorityHandleV1);
struct SimulatedObserverV1(AuthorityHandleV1);

struct SimulatedActionAuthorizerV1 {
    authority: AuthorityHandleV1,
    scenario: SimulationScenarioV1,
    route_id: Digest32,
    bindings: FrozenBindingsV1,
}

impl RefundArmingAuthority for SimulatedRefundArmerV1 {
    fn arm_refunds(
        &mut self,
        request: RefundArmingRequestV1<'_>,
    ) -> Result<RefundBindingsV1, AuthorityRefusalV1> {
        if request.snapshot().route_id != request.route_id()
            || request.snapshot().bindings.as_ref() != Some(request.bindings())
        {
            return Err(AuthorityRefusalV1::Inconsistent);
        }
        self.0
             .0
            .try_borrow_mut()
            .map_err(|_| AuthorityRefusalV1::Inconsistent)?
            .arm_refunds(request.route_id(), request.bindings())
    }
}

impl RouteActionAuthority for SimulatedActionAuthorizerV1 {
    fn authorize_route_action(
        &mut self,
        request: RouteActionAuthorizationRequestV1<'_>,
    ) -> Result<ActionIntentV1, AuthorityRefusalV1> {
        if request.route_id() != self.route_id
            || request.snapshot().route_id != self.route_id
            || request.bindings() != &self.bindings
            || request.snapshot().bindings.as_ref() != Some(&self.bindings)
            || request.event_id() != action_event_id(request.leg(), request.action())
        {
            return Err(AuthorityRefusalV1::Inconsistent);
        }
        match (self.scenario, request.action()) {
            (_, ActionKindV1::Funding) => Ok(funding_intent(request.leg())),
            (SimulationScenarioV1::Claim, ActionKindV1::Claim) => Ok(claim_intent(request.leg())),
            (SimulationScenarioV1::Refund, ActionKindV1::Refund)
                if request.snapshot().health == route_executor::HealthStateV1::RecoveryOnly
                    && self
                        .authority
                        .0
                        .try_borrow()
                        .map_err(|_| AuthorityRefusalV1::Inconsistent)?
                        .deadline_fired(self.route_id, request.leg())? =>
            {
                Ok(refund_intent(request.leg()))
            }
            _ => Err(AuthorityRefusalV1::Refused),
        }
    }
}

impl ChainObservationAuthority for SimulatedObserverV1 {
    fn verify_chain_observation(
        &mut self,
        request: ChainObservationRequestV1<'_>,
    ) -> Result<VerifiedChainObservationV1, AuthorityRefusalV1> {
        match request.query() {
            ChainObservationQueryV1::Finality {
                leg,
                action,
                transaction_id,
            } => self
                .0
                 .0
                .try_borrow()
                .map_err(|_| AuthorityRefusalV1::Inconsistent)?
                .verify_finality(&request, leg, action, transaction_id),
            ChainObservationQueryV1::Invalidation { .. }
            | ChainObservationQueryV1::SecretExposure { .. } => Err(AuthorityRefusalV1::Refused),
        }
    }
}

impl RunnerActionAuthority for SimulatedRunnerV1 {
    fn externalize_runner_action(
        &mut self,
        request: RunnerActionRequestV1<'_>,
    ) -> Result<ActionExternalizationReceiptV1, AuthorityRefusalV1> {
        let capability = request.capability();
        if capability.contains_route_secret()
            || capability.expected_transaction_id().is_some()
            || digest_bytes_v1(request.payload()) != capability.dispatch_digest()
        {
            return Err(AuthorityRefusalV1::Inconsistent);
        }
        let record = record_from_capability(capability, None);
        let attempt_id = capability.one_shot_attempt_id();
        self.0
             .0
            .try_borrow_mut()
            .map_err(|_| AuthorityRefusalV1::Inconsistent)?
            .externalize(record, attempt_id)
    }
}

impl ExternalCustodyAuthority for SimulatedCustodyV1 {
    fn externalize_custodied_action(
        &mut self,
        request: ExternalCustodyActionRequestV1,
    ) -> Result<CustodyDispatchOutcomeV1, AuthorityRefusalV1> {
        let capability = request.capability();
        let expected = capability
            .expected_transaction_id()
            .ok_or(AuthorityRefusalV1::Inconsistent)?;
        let record = record_from_capability(capability, Some(expected));
        let attempt_id = capability.one_shot_attempt_id();
        self.0
             .0
            .try_borrow_mut()
            .map_err(|_| AuthorityRefusalV1::Inconsistent)?
            .externalize(record, attempt_id)
            .map(CustodyDispatchOutcomeV1::AggregateExternalized)
    }
}

impl TakeoverReconciliationAuthority for SimulatedReconcilerV1 {
    fn reconcile_committed_action(
        &mut self,
        request: ReconciliationRequestV1<'_>,
    ) -> Result<TakeoverReconciliationOutcomeV1, AuthorityRefusalV1> {
        self.0
             .0
            .try_borrow_mut()
            .map_err(|_| AuthorityRefusalV1::Inconsistent)?
            .reconcile(request)
    }
}

impl TimerAuthority for SimulatedTimerV1 {
    fn event_for_due_timer(
        &mut self,
        timer: TimerDispatchV1,
    ) -> Result<RouteEventV1, AuthorityRefusalV1> {
        if timer.kind() != TimerKindV1::Deadline || timer.attempt() == 0 {
            return Err(AuthorityRefusalV1::Refused);
        }
        let leg = if timer.context_digest() == material("downstream-refund-deadline")
            && timer.deadline_unix_ms() == DOWNSTREAM_REFUND_DEADLINE_MS
        {
            LegIdV1::Downstream
        } else if timer.context_digest() == material("upstream-refund-deadline")
            && timer.deadline_unix_ms() == UPSTREAM_REFUND_DEADLINE_MS
        {
            LegIdV1::Upstream
        } else {
            return Err(AuthorityRefusalV1::Refused);
        };
        let reason_digest = self
            .0
             .0
            .try_borrow_mut()
            .map_err(|_| AuthorityRefusalV1::Inconsistent)?
            .record_deadline(&timer, leg)?;
        Ok(RouteEventV1::SetHealth {
            target: route_executor::HealthStateV1::RecoveryOnly,
            reason_digest,
        })
    }

    fn event_committed(&mut self, commit: TimerEventCommitV1) -> Result<(), AuthorityRefusalV1> {
        if !commit.duplicate {
            let mut authority = self
                .0
                 .0
                .try_borrow_mut()
                .map_err(|_| AuthorityRefusalV1::Inconsistent)?;
            if authority.crash_after == Some(SimulationCrashPointV1::AfterTimerEventCommit)
                && authority
                    .mark_fault_once(SimulationCrashPointV1::AfterTimerEventCommit)
                    .map_err(|_| AuthorityRefusalV1::Unavailable)?
            {
                process::exit(SIMULATION_CRASH_EXIT_CODE_V1.into());
            }
        }
        Ok(())
    }
}

#[derive(Default)]
struct SimulationProgressV1 {
    takeover_externalized: u64,
    takeover_reauthorized: u64,
    takeover_unknown: u64,
    duplicate_timer_events: u64,
    urgent_externalizations: u64,
}

impl SimulationProgressV1 {
    fn absorb_takeover(
        &mut self,
        report: TakeoverReconciliationReportV1,
    ) -> Result<(), SimulationErrorV1> {
        self.takeover_externalized = self
            .takeover_externalized
            .checked_add(to_u64(report.externalized)?)
            .ok_or(SimulationErrorV1::TerminalInvariant)?;
        self.takeover_reauthorized = self
            .takeover_reauthorized
            .checked_add(to_u64(report.reauthorized)?)
            .ok_or(SimulationErrorV1::TerminalInvariant)?;
        self.takeover_unknown = self
            .takeover_unknown
            .checked_add(to_u64(report.unknown)?)
            .ok_or(SimulationErrorV1::TerminalInvariant)?;
        Ok(())
    }

    fn absorb_tick(
        &mut self,
        report: RouteSupervisorTickReportV1,
    ) -> Result<(), SimulationErrorV1> {
        if report.takeover_reconciliation_required || report.urgent_in_flight {
            return Err(SimulationErrorV1::TerminalInvariant);
        }
        self.duplicate_timer_events = self
            .duplicate_timer_events
            .checked_add(to_u64(report.duplicate_timer_events)?)
            .ok_or(SimulationErrorV1::TerminalInvariant)?;
        self.urgent_externalizations = self
            .urgent_externalizations
            .checked_add(to_u64(report.urgent_externalized)?)
            .ok_or(SimulationErrorV1::TerminalInvariant)?;
        Ok(())
    }
}

/// Opens or creates the two durable authorities, resumes the route under a
/// fresh fencing owner, and drives the selected scenario to its exact terminal
/// state.  A requested crash point exits the process with
/// [`SIMULATION_CRASH_EXIT_CODE_V1`] after the relevant durable commit.
pub fn run_simulation_v1(
    options: SimulationOptionsV1,
) -> Result<SimulationReportV1, SimulationErrorV1> {
    let session = SimulationSessionV1::open(&options)?;
    let route = route_id(options.scenario);
    let admission = authenticated_admission(&options.state_dir, session.now_unix_ms, route)?;
    if admission.route_id() != route {
        return Err(SimulationErrorV1::AuthenticatedAdmission);
    }

    let route_database = options.state_dir.join("routes.sqlite3");
    let mut store = if route_database.exists() {
        DurableRouteStoreV1::open_existing(&route_database)
    } else {
        DurableRouteStoreV1::create(&route_database)
    }?;
    match store.create_route(route, session.now_unix_ms) {
        Ok(_) | Err(RouteStoreErrorV1::RouteAlreadyExists) => {}
        Err(error) => return Err(error.into()),
    }
    let clock = ManualClockV1::new(session.now_unix_ms)?;
    let config =
        RouteSupervisorConfigV1::new(LEASE_DURATION_MS, RENEW_BEFORE_MS, DISPATCH_LEASE_MS, 8)?;
    let mut supervisor = RouteSupervisorV1::acquire(
        store,
        route,
        owner_id(options.scenario, session.invocation),
        config,
        clock.clone(),
    )?;

    let handle = AuthorityHandleV1(session.authority.clone());
    let mut runner = SimulatedRunnerV1(handle.clone());
    let mut custody = SimulatedCustodyV1(handle.clone());
    let mut timers = SimulatedTimerV1(handle.clone());
    let mut reconciler = SimulatedReconcilerV1(handle.clone());
    let mut refund_armer = SimulatedRefundArmerV1(handle.clone());
    let mut observer = SimulatedObserverV1(handle.clone());
    let mut progress = SimulationProgressV1::default();
    progress.absorb_takeover(supervisor.reconcile_takeover(&mut reconciler)?)?;

    let initial = supervisor.snapshot()?;
    if initial.bindings.is_none() {
        supervisor.admit_route(event_id("authenticated-admission"), &admission)?;
    } else if initial.bindings.as_ref() != Some(admission.frozen_bindings()) {
        return Err(SimulationErrorV1::TerminalInvariant);
    }
    let after_admission = supervisor.snapshot()?;
    if after_admission.refunds.is_none() {
        supervisor.arm_refunds(event_id("durable-refund-arming"), &mut refund_armer)?;
    }
    let bindings = admission.frozen_bindings().clone();
    let mut action_authority = SimulatedActionAuthorizerV1 {
        authority: handle,
        scenario: options.scenario,
        route_id: route,
        bindings,
    };
    let mut drive_authorities = SimulationDriveAuthoritiesV1 {
        action: &mut action_authority,
        runner: &mut runner,
        custody: &mut custody,
        timers: &mut timers,
        observer: &mut observer,
        progress: &mut progress,
    };

    drive_funding(&mut supervisor, LegIdV1::Upstream, &mut drive_authorities)?;
    drive_funding(&mut supervisor, LegIdV1::Downstream, &mut drive_authorities)?;

    let mut logical_now = session.now_unix_ms;
    match options.scenario {
        SimulationScenarioV1::Claim => drive_claims(&mut supervisor, &mut drive_authorities)?,
        SimulationScenarioV1::Refund => drive_refunds(
            &session,
            &clock,
            &mut logical_now,
            &mut supervisor,
            &mut drive_authorities,
        )?,
    }

    build_terminal_report(&session, &supervisor, options.scenario, progress)
}

struct SimulationDriveAuthoritiesV1<'a> {
    action: &'a mut SimulatedActionAuthorizerV1,
    runner: &'a mut SimulatedRunnerV1,
    custody: &'a mut SimulatedCustodyV1,
    timers: &'a mut SimulatedTimerV1,
    observer: &'a mut SimulatedObserverV1,
    progress: &'a mut SimulationProgressV1,
}

fn drive_funding(
    supervisor: &mut RouteSupervisorV1<ManualClockV1>,
    leg: LegIdV1,
    authorities: &mut SimulationDriveAuthoritiesV1<'_>,
) -> Result<(), SimulationErrorV1> {
    drive_to_externalized(supervisor, leg, ActionKindV1::Funding, authorities)?;
    finalize_action(supervisor, leg, ActionKindV1::Funding, authorities.observer)?;
    if supervisor.snapshot()?.leg(leg).funding.progress() != ActionProgressV1::Final {
        return Err(SimulationErrorV1::TerminalInvariant);
    }
    Ok(())
}

fn drive_to_externalized(
    supervisor: &mut RouteSupervisorV1<ManualClockV1>,
    leg: LegIdV1,
    action: ActionKindV1,
    authorities: &mut SimulationDriveAuthoritiesV1<'_>,
) -> Result<(), SimulationErrorV1> {
    let state = supervisor.snapshot()?.leg(leg).action(action).clone();
    if state.progress() == ActionProgressV1::NotPrepared {
        supervisor.authorize_action(
            action_event_id(leg, action),
            leg,
            action,
            authorities.action,
        )?;
    }
    if supervisor.snapshot()?.leg(leg).action(action).progress() == ActionProgressV1::Committed {
        authorities.progress.absorb_tick(supervisor.tick(
            authorities.runner,
            authorities.custody,
            authorities.timers,
        )?)?;
    }
    if !matches!(
        supervisor.snapshot()?.leg(leg).action(action).progress(),
        ActionProgressV1::Externalized | ActionProgressV1::Final
    ) {
        return Err(SimulationErrorV1::TerminalInvariant);
    }
    Ok(())
}

fn finalize_action(
    supervisor: &mut RouteSupervisorV1<ManualClockV1>,
    leg: LegIdV1,
    action: ActionKindV1,
    observer: &mut SimulatedObserverV1,
) -> Result<(), SimulationErrorV1> {
    let state = supervisor.snapshot()?.leg(leg).action(action).clone();
    match state.progress() {
        ActionProgressV1::Final => Ok(()),
        ActionProgressV1::Externalized => {
            let transaction_id = state
                .transaction_id()
                .ok_or(SimulationErrorV1::TerminalInvariant)?;
            supervisor.record_chain_observation(
                finality_event_id(leg, action),
                ChainObservationQueryV1::Finality {
                    leg,
                    action,
                    transaction_id,
                },
                observer,
            )?;
            Ok(())
        }
        ActionProgressV1::NotPrepared | ActionProgressV1::Committed => {
            Err(SimulationErrorV1::TerminalInvariant)
        }
    }
}

fn drive_claims(
    supervisor: &mut RouteSupervisorV1<ManualClockV1>,
    authorities: &mut SimulationDriveAuthoritiesV1<'_>,
) -> Result<(), SimulationErrorV1> {
    drive_to_externalized(
        supervisor,
        LegIdV1::Downstream,
        ActionKindV1::Claim,
        authorities,
    )?;
    if !matches!(
        supervisor.snapshot()?.secret_visibility,
        SecretVisibilityV1::Public { .. }
    ) {
        return Err(SimulationErrorV1::TerminalInvariant);
    }
    drive_to_externalized(
        supervisor,
        LegIdV1::Upstream,
        ActionKindV1::Claim,
        authorities,
    )?;
    finalize_action(
        supervisor,
        LegIdV1::Downstream,
        ActionKindV1::Claim,
        authorities.observer,
    )?;
    finalize_action(
        supervisor,
        LegIdV1::Upstream,
        ActionKindV1::Claim,
        authorities.observer,
    )
}

fn drive_refunds(
    session: &SimulationSessionV1,
    clock: &ManualClockV1,
    logical_now: &mut u64,
    supervisor: &mut RouteSupervisorV1<ManualClockV1>,
    authorities: &mut SimulationDriveAuthoritiesV1<'_>,
) -> Result<(), SimulationErrorV1> {
    supervisor.schedule_timer(
        event_id("schedule-downstream-refund"),
        TimerKindV1::Deadline,
        DOWNSTREAM_REFUND_DEADLINE_MS,
        material("downstream-refund-deadline"),
    )?;
    supervisor.schedule_timer(
        event_id("schedule-upstream-refund"),
        TimerKindV1::Deadline,
        UPSTREAM_REFUND_DEADLINE_MS,
        material("upstream-refund-deadline"),
    )?;

    advance_clock_to(session, clock, logical_now, DOWNSTREAM_REFUND_DEADLINE_MS)?;
    authorities.progress.absorb_tick(supervisor.tick(
        authorities.runner,
        authorities.custody,
        authorities.timers,
    )?)?;
    drive_to_externalized(
        supervisor,
        LegIdV1::Downstream,
        ActionKindV1::Refund,
        authorities,
    )?;
    finalize_action(
        supervisor,
        LegIdV1::Downstream,
        ActionKindV1::Refund,
        authorities.observer,
    )?;

    advance_clock_to(session, clock, logical_now, UPSTREAM_REFUND_DEADLINE_MS)?;
    authorities.progress.absorb_tick(supervisor.tick(
        authorities.runner,
        authorities.custody,
        authorities.timers,
    )?)?;
    drive_to_externalized(
        supervisor,
        LegIdV1::Upstream,
        ActionKindV1::Refund,
        authorities,
    )?;
    finalize_action(
        supervisor,
        LegIdV1::Upstream,
        ActionKindV1::Refund,
        authorities.observer,
    )
}

fn advance_clock_to(
    session: &SimulationSessionV1,
    clock: &ManualClockV1,
    logical_now: &mut u64,
    target: u64,
) -> Result<(), SimulationErrorV1> {
    if *logical_now < target {
        session.persist_clock(target)?;
        clock.set(target)?;
        *logical_now = target;
    }
    Ok(())
}

fn build_terminal_report(
    session: &SimulationSessionV1,
    supervisor: &RouteSupervisorV1<ManualClockV1>,
    scenario: SimulationScenarioV1,
    progress: SimulationProgressV1,
) -> Result<SimulationReportV1, SimulationErrorV1> {
    let snapshot = supervisor.snapshot()?;
    let pending_effects = supervisor.pending_effect_count()?;
    let active_timers = supervisor.active_timer_count()?;
    let journal = supervisor.journal()?;
    let secret_public = matches!(
        snapshot.secret_visibility,
        SecretVisibilityV1::Public { .. }
    );
    let (upstream_outcome, downstream_outcome) = match scenario {
        SimulationScenarioV1::Claim => {
            if snapshot.upstream.claim.progress() != ActionProgressV1::Final
                || snapshot.downstream.claim.progress() != ActionProgressV1::Final
                || snapshot.upstream.refund.progress() != ActionProgressV1::NotPrepared
                || snapshot.downstream.refund.progress() != ActionProgressV1::NotPrepared
                || !secret_public
            {
                return Err(SimulationErrorV1::TerminalInvariant);
            }
            ("claim_final", "claim_final")
        }
        SimulationScenarioV1::Refund => {
            if snapshot.upstream.refund.progress() != ActionProgressV1::Final
                || snapshot.downstream.refund.progress() != ActionProgressV1::Final
                || snapshot.upstream.claim.progress() != ActionProgressV1::NotPrepared
                || snapshot.downstream.claim.progress() != ActionProgressV1::NotPrepared
                || secret_public
            {
                return Err(SimulationErrorV1::TerminalInvariant);
            }
            ("refund_final", "refund_final")
        }
    };
    if snapshot.coordination != CoordinationPhaseV1::Terminal
        || snapshot.upstream.funding.progress() != ActionProgressV1::Final
        || snapshot.downstream.funding.progress() != ActionProgressV1::Final
        || snapshot.has_open_funds()
        || pending_effects != 0
        || active_timers != 0
        || journal.len() != usize::try_from(snapshot.revision).unwrap_or(usize::MAX)
        || progress.takeover_unknown != 0
    {
        return Err(SimulationErrorV1::TerminalInvariant);
    }
    let authority = session
        .authority
        .try_borrow()
        .map_err(|_| SimulationErrorV1::InconsistentAuthorityState)?;
    let stats = authority.terminal_stats()?;
    if stats.unique_externalizations != 4
        || stats.economic_broadcasts != 4
        || stats.consumed_attempts != 4
    {
        return Err(SimulationErrorV1::TerminalInvariant);
    }
    Ok(SimulationReportV1 {
        schema: "dom-interopd-simulation-v1",
        build_mode: "simulation",
        scenario,
        route_id: hex32(snapshot.route_id),
        invocation: session.invocation,
        fencing_epoch: supervisor.lease_status().fencing_epoch(),
        revision: snapshot.revision,
        journal_entries: u64::try_from(journal.len())
            .map_err(|_| SimulationErrorV1::TerminalInvariant)?,
        journal_head_digest: hex32(snapshot.last_event_digest),
        terminal: true,
        secret_public,
        upstream_outcome,
        downstream_outcome,
        pending_effects,
        active_timers,
        takeover_externalized: progress.takeover_externalized,
        takeover_reauthorized: progress.takeover_reauthorized,
        takeover_unknown: progress.takeover_unknown,
        duplicate_timer_events: progress.duplicate_timer_events,
        urgent_externalizations: progress.urgent_externalizations,
        unique_externalizations: stats.unique_externalizations,
        economic_broadcasts: stats.economic_broadcasts,
        consumed_attempt_capabilities: stats.consumed_attempts,
        authority_state_digest: hex32(stats.state_digest),
        externalizations: stats.externalizations,
    })
}

fn authenticated_admission(
    state_dir: &Path,
    now_unix_ms: u64,
    route_id: Digest32,
) -> Result<AuthenticatedRouteAdmissionV1, SimulationErrorV1> {
    let registry_path = state_dir.join("deployment-registry.sqlite3");
    let mut store = if registry_path.exists() {
        RegistryStoreV1::open_existing(&registry_path)
    } else {
        RegistryStoreV1::create(&registry_path)
    }
    .map_err(|_| SimulationErrorV1::AuthenticatedAdmission)?;
    let manifest = simulation_registry_manifest();
    let manifest_digest = manifest
        .manifest_digest()
        .map_err(|_| SimulationErrorV1::AuthenticatedAdmission)?;
    let secp = SecpContext::new(&material("simulation-registry-context"));
    // This is deliberately public laboratory material, compiled only into the
    // mutually-exclusive simulation feature.  It authenticates repeatable
    // fixtures and has no authority over any deployment or real funds.
    let laboratory_signing_key = material("public-simulation-registry-signer");
    let (signature, public_key) = secp
        .sign_bip340(
            &laboratory_signing_key,
            &manifest_digest,
            &material("simulation-registry-aux"),
        )
        .map_err(|_| SimulationErrorV1::AuthenticatedAdmission)?;
    let authorities = AuthoritySetV1::new(1, vec![public_key])
        .map_err(|_| SimulationErrorV1::AuthenticatedAdmission)?;
    let signed = SignedRegistryV1::new(
        &manifest,
        vec![RegistrySignatureV1 {
            signer_index: 0,
            signature,
        }],
    )
    .map_err(|_| SimulationErrorV1::AuthenticatedAdmission)?;
    let now_seconds = now_unix_ms / 1_000;
    store
        .install(
            &signed,
            &authorities,
            &secp,
            RegistryValidationPolicyV1 {
                now_seconds,
                expected_network_id: SIMULATION_NETWORK,
                minimum_epoch: 1,
            },
        )
        .map_err(|_| SimulationErrorV1::AuthenticatedAdmission)?;
    let admission = RegistryRouteAdmissionAuthorityV1::new(
        store,
        authorities,
        SecpContext::new(&material("simulation-registry-verifier")),
        SIMULATION_NETWORK,
        1,
    )
    .map_err(|_| SimulationErrorV1::AuthenticatedAdmission)?;
    admission
        .admit_composed_route(
            now_seconds,
            RouteAdmissionRequestV1 {
                route_id,
                base_terms_digest: material("simulation-base-terms"),
                dom: RouteLegSelectionV1 {
                    chain_id: SIMULATION_DOM_CHAIN,
                    asset_id: SIMULATION_DOM_ASSET,
                },
                upstream: RouteLegSelectionV1 {
                    chain_id: SIMULATION_EVM_CHAIN,
                    asset_id: SIMULATION_EVM_NATIVE,
                },
                downstream: RouteLegSelectionV1 {
                    chain_id: SIMULATION_EVM_CHAIN,
                    asset_id: SIMULATION_EVM_TOKEN,
                },
            },
        )
        .map_err(|_: RouteAdmissionRefusalV1| SimulationErrorV1::AuthenticatedAdmission)
}

fn simulation_registry_manifest() -> RegistryManifestV1 {
    let timing = ChainTimingBoundsV1 {
        min_block_seconds: 5,
        max_block_seconds: 20,
        max_reorg_seconds: 200,
        observation_seconds: 30,
        broadcast_seconds: 20,
    };
    let finality = FinalityPolicyV1 {
        min_confirmations: 2,
        max_reorg_depth: 3,
    };
    RegistryManifestV1 {
        network_id: SIMULATION_NETWORK,
        epoch: 1,
        valid_from: 1,
        expires_at: 10_000_000,
        dom: DomDeploymentV1 {
            chain_id: SIMULATION_DOM_CHAIN,
            genesis_hash: SIMULATION_DOM_GENESIS,
            runtime_identity: DomRuntimeIdentityV1::pinned(DomNetworkV1::Regtest),
            consensus_rules_digest: material("simulation-dom-consensus"),
            scriptless_api_version: 1,
            timing,
            finality,
            native_asset: SIMULATION_DOM_ASSET,
        },
        chains: vec![RegistryChainProfileV1 {
            profile: ChainProfileV1 {
                chain_id: SIMULATION_EVM_CHAIN,
                kind: ChainKindV1::Evm {
                    evm_chain_id: 31_337,
                    native_lock_contract: [0x51; 20],
                    native_code_hash: material("simulation-native-lock-code"),
                    erc20_lock_contract: Some(([0x53; 20], material("simulation-erc20-lock-code"))),
                },
                timing,
                finality,
                native_asset: SIMULATION_EVM_NATIVE,
                allowed_assets: vec![SIMULATION_EVM_TOKEN],
            },
            deployment: ChainDeploymentV1::Evm(EvmDeploymentV1 {
                genesis_hash: material("simulation-evm-genesis"),
                native_start_block: 10,
                erc20_start_block: Some(11),
                abi_digest: material("simulation-lock-abi"),
                compiler_digest: material("simulation-lock-compiler"),
                source_digest: material("simulation-lock-source"),
                deployment_digest: material("simulation-lock-deployment"),
                finalized_tag_required: true,
                page_size: 256,
                gas_limit_hint: 300_000,
                max_fee_per_gas: 100_000_000_000,
                max_priority_fee_per_gas: 2_000_000_000,
            }),
        }],
        assets: vec![
            AssetBindingV1 {
                chain_id: SIMULATION_EVM_CHAIN,
                asset_id: SIMULATION_EVM_NATIVE,
                decimals: 18,
                representation: AssetRepresentationV1::Native,
            },
            AssetBindingV1 {
                chain_id: SIMULATION_EVM_CHAIN,
                asset_id: SIMULATION_EVM_TOKEN,
                decimals: 6,
                representation: AssetRepresentationV1::EvmErc20 {
                    token: [0x60; 20],
                    token_code_hash: material("simulation-token-code"),
                },
            },
            AssetBindingV1 {
                chain_id: SIMULATION_DOM_CHAIN,
                asset_id: SIMULATION_DOM_ASSET,
                decimals: 9,
                representation: AssetRepresentationV1::Native,
            },
        ],
    }
}

fn configure_authority_connection(connection: &Connection) -> Result<(), SimulationErrorV1> {
    connection
        .busy_timeout(std::time::Duration::from_secs(5))
        .map_err(|_| SimulationErrorV1::StateUnavailable)?;
    connection
        .execute_batch(
            "PRAGMA journal_mode = WAL;
             PRAGMA synchronous = FULL;
             PRAGMA foreign_keys = ON;
             PRAGMA trusted_schema = OFF;",
        )
        .map_err(|_| SimulationErrorV1::StateUnavailable)
}

fn initialize_authority_schema(
    connection: &Connection,
    scenario: SimulationScenarioV1,
) -> Result<(), SimulationErrorV1> {
    let version: i64 = connection
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .map_err(|_| SimulationErrorV1::StateUnavailable)?;
    let application_id: i64 = connection
        .query_row("PRAGMA application_id", [], |row| row.get(0))
        .map_err(|_| SimulationErrorV1::StateUnavailable)?;
    if version == 0 && application_id == 0 {
        connection
            .execute_batch(
                "BEGIN IMMEDIATE;
                 CREATE TABLE simulation_meta (
                     singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                     scenario_tag TEXT NOT NULL CHECK (scenario_tag IN ('claim', 'refund')),
                     invocations INTEGER NOT NULL CHECK (invocations >= 0),
                     clock_high_water_ms INTEGER NOT NULL CHECK (clock_high_water_ms > 0)
                 );
                 CREATE TABLE externalizations (
                     effect_id BLOB PRIMARY KEY CHECK (length(effect_id) = 32),
                     route_id BLOB NOT NULL CHECK (length(route_id) = 32),
                     leg_tag INTEGER NOT NULL CHECK (leg_tag IN (0, 1)),
                     action_tag INTEGER NOT NULL CHECK (action_tag IN (0, 1, 2)),
                     semantic_digest BLOB NOT NULL CHECK (length(semantic_digest) = 32),
                     terms_digest BLOB NOT NULL CHECK (length(terms_digest) = 32),
                     profile_digest BLOB NOT NULL CHECK (length(profile_digest) = 32),
                     deployment_digest BLOB NOT NULL CHECK (length(deployment_digest) = 32),
                     fencing_epoch INTEGER NOT NULL CHECK (fencing_epoch > 0),
                     dispatch_digest BLOB NOT NULL CHECK (length(dispatch_digest) = 32),
                     expected_transaction_id BLOB CHECK (
                         expected_transaction_id IS NULL OR length(expected_transaction_id) = 32
                     ),
                     contains_route_secret INTEGER NOT NULL CHECK (contains_route_secret IN (0, 1)),
                     transaction_id BLOB NOT NULL CHECK (length(transaction_id) = 32),
                     chain_id BLOB CHECK (chain_id IS NULL OR length(chain_id) = 32),
                     evidence_digest BLOB CHECK (
                         evidence_digest IS NULL OR length(evidence_digest) = 32
                     ),
                     broadcast_count INTEGER NOT NULL CHECK (broadcast_count = 1),
                     delivery_attempts INTEGER NOT NULL CHECK (delivery_attempts > 0),
                     CHECK ((contains_route_secret = 0 AND chain_id IS NULL AND evidence_digest IS NULL)
                         OR (contains_route_secret = 1 AND chain_id IS NOT NULL AND evidence_digest IS NOT NULL))
                 ) WITHOUT ROWID;
                 CREATE TABLE consumed_attempts (
                     attempt_id BLOB PRIMARY KEY CHECK (length(attempt_id) = 32),
                     effect_id BLOB NOT NULL CHECK (length(effect_id) = 32)
                 ) WITHOUT ROWID;
                 CREATE TABLE refund_arms (
                     route_id BLOB PRIMARY KEY CHECK (length(route_id) = 32),
                     terms_digest BLOB NOT NULL CHECK (length(terms_digest) = 32),
                     profile_digest BLOB NOT NULL CHECK (length(profile_digest) = 32),
                     deployment_digest BLOB NOT NULL CHECK (length(deployment_digest) = 32),
                     upstream_refund_digest BLOB NOT NULL CHECK (length(upstream_refund_digest) = 32),
                     downstream_refund_digest BLOB NOT NULL CHECK (length(downstream_refund_digest) = 32)
                 ) WITHOUT ROWID;
                 CREATE TABLE deadline_firings (
                     timer_id BLOB PRIMARY KEY CHECK (length(timer_id) = 32),
                     route_id BLOB NOT NULL CHECK (length(route_id) = 32),
                     leg_tag INTEGER NOT NULL CHECK (leg_tag IN (0, 1)),
                     deadline_unix_ms INTEGER NOT NULL CHECK (deadline_unix_ms > 0),
                     context_digest BLOB NOT NULL CHECK (length(context_digest) = 32),
                     timer_event_id BLOB NOT NULL CHECK (length(timer_event_id) = 32)
                 ) WITHOUT ROWID;
                 CREATE TABLE injected_faults (
                     fault_tag INTEGER PRIMARY KEY CHECK (fault_tag IN (1, 2))
                 ) WITHOUT ROWID;
                 PRAGMA application_id = 1146047827;
                 PRAGMA user_version = 2;
                 COMMIT;",
            )
            .map_err(|_| SimulationErrorV1::UnsupportedState)?;
        connection
            .execute(
                "INSERT INTO simulation_meta
                 (singleton, scenario_tag, invocations, clock_high_water_ms)
                 VALUES (1, ?1, 0, ?2)",
                params![scenario.tag(), to_i64(INITIAL_CLOCK_MS)?],
            )
            .map_err(|_| SimulationErrorV1::StateUnavailable)?;
    } else if version != AUTHORITY_SCHEMA_VERSION || application_id != AUTHORITY_APPLICATION_ID {
        return Err(SimulationErrorV1::UnsupportedState);
    }
    let retained: String = connection
        .query_row(
            "SELECT scenario_tag FROM simulation_meta WHERE singleton = 1",
            [],
            |row| row.get(0),
        )
        .map_err(|_| SimulationErrorV1::UnsupportedState)?;
    if retained != scenario.tag() {
        return Err(SimulationErrorV1::ScenarioMismatch);
    }
    let quick_check: String = connection
        .query_row("PRAGMA quick_check(1)", [], |row| row.get(0))
        .map_err(|_| SimulationErrorV1::StateUnavailable)?;
    if quick_check != "ok" {
        return Err(SimulationErrorV1::InconsistentAuthorityState);
    }
    Ok(())
}

/// The invocation counter and the clock this run starts from.
///
/// **No lint reaches this one either, and that is why it is written down.** A
/// two-element tuple never trips `clippy::type-complexity`, so nothing would
/// ever have complained; the reason to name the fields is the one the lint
/// happens to catch elsewhere and misses here. Both values are `u64`, they sat
/// side by side and anonymous in the return position, and the single caller
/// took them by position — so putting the clock in the counter and the counter
/// in the clock compiled, read correctly, and was wrong.
///
/// The risk here is a simulation's bookkeeping rather than a settlement's, and
/// it is closed anyway: an anonymous pair of one type is a trap wherever it
/// lives, and this is the third of them found in a single pass.
struct InvocationStartV1 {
    /// One-based count of this invocation, after the increment is durable.
    invocation: u64,
    /// Simulation clock in milliseconds, stepped past the stored high water.
    now_unix_ms: u64,
}

fn begin_invocation(connection: &mut Connection) -> Result<InvocationStartV1, SimulationErrorV1> {
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|_| SimulationErrorV1::StateUnavailable)?;
    let (invocations, high_water): (i64, i64) = transaction
        .query_row(
            "SELECT invocations, clock_high_water_ms
             FROM simulation_meta WHERE singleton = 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .map_err(|_| SimulationErrorV1::UnsupportedState)?;
    let invocation = from_i64(invocations)?
        .checked_add(1)
        .ok_or(SimulationErrorV1::InconsistentAuthorityState)?;
    let prior_clock = from_i64(high_water)?;
    let now = prior_clock
        .checked_add(INVOCATION_CLOCK_STEP_MS)
        .ok_or(SimulationErrorV1::InconsistentAuthorityState)?;
    transaction
        .execute(
            "UPDATE simulation_meta
             SET invocations = ?1, clock_high_water_ms = ?2
             WHERE singleton = 1",
            params![to_i64(invocation)?, to_i64(now)?],
        )
        .map_err(|_| SimulationErrorV1::StateUnavailable)?;
    transaction
        .commit()
        .map_err(|_| SimulationErrorV1::StateUnavailable)?;
    Ok(InvocationStartV1 {
        invocation,
        now_unix_ms: now,
    })
}

fn record_from_capability(
    capability: &crate::SignerCapabilityV1,
    expected_transaction_id: Option<Digest32>,
) -> ExternalizationRecordV1 {
    let transaction_id = expected_transaction_id.unwrap_or_else(|| {
        digest_parts(
            RUNNER_TRANSACTION_DOMAIN,
            &[
                &capability.route_id(),
                &capability.effect_id(),
                &capability.dispatch_digest(),
            ],
        )
    });
    let (chain_id, evidence_digest) = if capability.contains_route_secret() {
        let leg_marker = [match capability.leg() {
            LegIdV1::Upstream => 0,
            LegIdV1::Downstream => 1,
        }];
        let chain = digest_parts(CHAIN_DOMAIN, &[&capability.route_id(), &leg_marker]);
        let evidence = digest_parts(
            EXPOSURE_DOMAIN,
            &[&capability.effect_id(), &transaction_id, &chain],
        );
        (Some(chain), Some(evidence))
    } else {
        (None, None)
    };
    ExternalizationRecordV1 {
        effect_id: capability.effect_id(),
        route_id: capability.route_id(),
        leg: capability.leg(),
        action: capability.action(),
        semantic_digest: capability.semantic_digest(),
        terms_digest: capability.terms_digest(),
        profile_digest: capability.profile_bundle_digest(),
        deployment_digest: capability.deployment_bundle_digest(),
        fencing_epoch: capability.fencing_epoch(),
        dispatch_digest: capability.dispatch_digest(),
        expected_transaction_id,
        contains_route_secret: capability.contains_route_secret(),
        transaction_id,
        chain_id,
        evidence_digest,
        broadcast_count: 1,
        delivery_attempts: 1,
    }
}

fn receipt_for_record(record: &ExternalizationRecordV1) -> ActionExternalizationReceiptV1 {
    match (record.chain_id, record.evidence_digest) {
        (Some(chain_id), Some(evidence_digest)) => {
            ActionExternalizationReceiptV1::secret_revealing(
                record.transaction_id,
                chain_id,
                evidence_digest,
            )
        }
        _ => ActionExternalizationReceiptV1::public(record.transaction_id),
    }
}

fn reconciliation_matches(
    retained: &ExternalizationRecordV1,
    request: &ReconciliationRequestV1<'_>,
) -> bool {
    let intent = request.intent();
    retained.route_id == request.route_id()
        && retained.effect_id == request.effect_id()
        && retained.leg == intent.leg
        && retained.action == intent.kind
        && retained.semantic_digest == intent.semantic_digest
        && retained.terms_digest == request.bindings().terms_digest
        && retained.profile_digest == request.bindings().profile_bundle_digest
        && retained.deployment_digest == request.bindings().deployment_bundle_digest
        && retained.fencing_epoch == request.prior_fence()
        && retained.dispatch_digest == request.dispatch_digest()
        && retained.expected_transaction_id == request.expected_transaction_id()
        && retained.contains_route_secret == intent.contains_route_secret
}

fn insert_externalization(
    transaction: &rusqlite::Transaction<'_>,
    record: &ExternalizationRecordV1,
) -> Result<(), SimulationErrorV1> {
    let changed = transaction
        .execute(
            "INSERT INTO externalizations (
                 effect_id, route_id, leg_tag, action_tag, semantic_digest,
                 terms_digest, profile_digest, deployment_digest,
                 fencing_epoch, dispatch_digest, expected_transaction_id,
                 contains_route_secret, transaction_id, chain_id,
                 evidence_digest, broadcast_count, delivery_attempts
             ) VALUES (
                 ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11,
                 ?12, ?13, ?14, ?15, 1, 1
             )",
            params![
                record.effect_id.as_slice(),
                record.route_id.as_slice(),
                leg_tag(record.leg),
                action_tag(record.action),
                record.semantic_digest.as_slice(),
                record.terms_digest.as_slice(),
                record.profile_digest.as_slice(),
                record.deployment_digest.as_slice(),
                to_i64(record.fencing_epoch)?,
                record.dispatch_digest.as_slice(),
                record.expected_transaction_id.map(|value| value.to_vec()),
                i64::from(record.contains_route_secret),
                record.transaction_id.as_slice(),
                record.chain_id.map(|value| value.to_vec()),
                record.evidence_digest.map(|value| value.to_vec()),
            ],
        )
        .map_err(|_| SimulationErrorV1::InconsistentAuthorityState)?;
    if changed != 1 {
        return Err(SimulationErrorV1::InconsistentAuthorityState);
    }
    Ok(())
}

fn load_externalization(
    connection: &Connection,
    effect_id: Digest32,
) -> Result<Option<ExternalizationRecordV1>, SimulationErrorV1> {
    query_externalization(connection, effect_id).map_err(|_| SimulationErrorV1::StateUnavailable)
}

fn query_externalization(
    connection: &Connection,
    effect_id: Digest32,
) -> rusqlite::Result<Option<ExternalizationRecordV1>> {
    connection
        .query_row(
            "SELECT effect_id, route_id, leg_tag, action_tag, semantic_digest,
                    terms_digest, profile_digest, deployment_digest,
                    fencing_epoch, dispatch_digest, expected_transaction_id,
                    contains_route_secret, transaction_id, chain_id,
                    evidence_digest, broadcast_count, delivery_attempts
             FROM externalizations WHERE effect_id = ?1",
            params![effect_id.as_slice()],
            |row| {
                read_externalization_row(row)
                    .and_then(|result| result.map_err(|_| rusqlite::Error::InvalidQuery))
            },
        )
        .optional()
}

fn read_externalization_row(
    row: &rusqlite::Row<'_>,
) -> rusqlite::Result<Result<ExternalizationRecordV1, SimulationErrorV1>> {
    let effect_id: Vec<u8> = row.get(0)?;
    let route_id: Vec<u8> = row.get(1)?;
    let leg: i64 = row.get(2)?;
    let action: i64 = row.get(3)?;
    let semantic_digest: Vec<u8> = row.get(4)?;
    let terms_digest: Vec<u8> = row.get(5)?;
    let profile_digest: Vec<u8> = row.get(6)?;
    let deployment_digest: Vec<u8> = row.get(7)?;
    let fencing_epoch: i64 = row.get(8)?;
    let dispatch_digest: Vec<u8> = row.get(9)?;
    let expected_transaction_id: Option<Vec<u8>> = row.get(10)?;
    let contains_route_secret: i64 = row.get(11)?;
    let transaction_id: Vec<u8> = row.get(12)?;
    let chain_id: Option<Vec<u8>> = row.get(13)?;
    let evidence_digest: Option<Vec<u8>> = row.get(14)?;
    let broadcast_count: i64 = row.get(15)?;
    let delivery_attempts: i64 = row.get(16)?;
    Ok((|| {
        Ok(ExternalizationRecordV1 {
            effect_id: blob32(effect_id)?,
            route_id: blob32(route_id)?,
            leg: decode_leg(leg)?,
            action: decode_action(action)?,
            semantic_digest: blob32(semantic_digest)?,
            terms_digest: blob32(terms_digest)?,
            profile_digest: blob32(profile_digest)?,
            deployment_digest: blob32(deployment_digest)?,
            fencing_epoch: from_i64(fencing_epoch)?,
            dispatch_digest: blob32(dispatch_digest)?,
            expected_transaction_id: optional_blob32(expected_transaction_id)?,
            contains_route_secret: decode_bool(contains_route_secret)?,
            transaction_id: blob32(transaction_id)?,
            chain_id: optional_blob32(chain_id)?,
            evidence_digest: optional_blob32(evidence_digest)?,
            broadcast_count: from_i64(broadcast_count)?,
            delivery_attempts: from_i64(delivery_attempts)?,
        })
    })())
}

struct AuthorityStatsV1 {
    externalizations: Vec<SimulationExternalizationV1>,
    unique_externalizations: u64,
    economic_broadcasts: u64,
    consumed_attempts: u64,
    state_digest: Digest32,
}

impl AuthorityStatsV1 {
    fn from_records(
        records: Vec<ExternalizationRecordV1>,
        consumed_attempts: u64,
    ) -> Result<Self, SimulationErrorV1> {
        let mut economic_broadcasts = 0u64;
        let mut transaction_ids = BTreeSet::new();
        let mut state_hasher = Blake2b::<U32>::new();
        BlakeDigest::update(&mut state_hasher, AUTHORITY_STATE_DOMAIN);
        let mut public = Vec::with_capacity(records.len());
        for record in &records {
            if record.broadcast_count != 1
                || record.effect_id == ZERO_DIGEST
                || record.transaction_id == ZERO_DIGEST
            {
                return Err(SimulationErrorV1::InconsistentAuthorityState);
            }
            economic_broadcasts = economic_broadcasts
                .checked_add(record.broadcast_count)
                .ok_or(SimulationErrorV1::InconsistentAuthorityState)?;
            if !transaction_ids.insert(record.transaction_id) {
                return Err(SimulationErrorV1::InconsistentAuthorityState);
            }
            for bytes in [
                record.effect_id.as_slice(),
                record.route_id.as_slice(),
                record.transaction_id.as_slice(),
                record.semantic_digest.as_slice(),
                record.terms_digest.as_slice(),
                record.profile_digest.as_slice(),
                record.deployment_digest.as_slice(),
                record.dispatch_digest.as_slice(),
            ] {
                BlakeDigest::update(&mut state_hasher, (bytes.len() as u64).to_be_bytes());
                BlakeDigest::update(&mut state_hasher, bytes);
            }
            BlakeDigest::update(&mut state_hasher, [leg_tag(record.leg) as u8]);
            BlakeDigest::update(&mut state_hasher, [action_tag(record.action) as u8]);
            BlakeDigest::update(&mut state_hasher, record.fencing_epoch.to_be_bytes());
            match record.expected_transaction_id {
                Some(expected) => {
                    BlakeDigest::update(&mut state_hasher, [1]);
                    BlakeDigest::update(&mut state_hasher, expected);
                }
                None => BlakeDigest::update(&mut state_hasher, [0]),
            }
            BlakeDigest::update(&mut state_hasher, [u8::from(record.contains_route_secret)]);
            match (record.chain_id, record.evidence_digest) {
                (Some(chain), Some(evidence)) => {
                    BlakeDigest::update(&mut state_hasher, [1]);
                    BlakeDigest::update(&mut state_hasher, chain);
                    BlakeDigest::update(&mut state_hasher, evidence);
                }
                (None, None) => BlakeDigest::update(&mut state_hasher, [0]),
                _ => return Err(SimulationErrorV1::InconsistentAuthorityState),
            }
            BlakeDigest::update(&mut state_hasher, record.broadcast_count.to_be_bytes());
            BlakeDigest::update(&mut state_hasher, record.delivery_attempts.to_be_bytes());
            public.push(SimulationExternalizationV1 {
                effect_id: hex32(record.effect_id),
                transaction_id: hex32(record.transaction_id),
                leg: leg_name(record.leg),
                action: action_name(record.action),
                externally_custodied: record.contains_route_secret,
                broadcast_count: record.broadcast_count,
                delivery_attempts: record.delivery_attempts,
            });
        }
        let unique_externalizations = u64::try_from(records.len())
            .map_err(|_| SimulationErrorV1::InconsistentAuthorityState)?;
        if economic_broadcasts != unique_externalizations {
            return Err(SimulationErrorV1::InconsistentAuthorityState);
        }
        let state_digest = state_hasher.finalize().into();
        Ok(Self {
            externalizations: public,
            unique_externalizations,
            economic_broadcasts,
            consumed_attempts,
            state_digest,
        })
    }
}

fn funding_intent(leg: LegIdV1) -> ActionIntentV1 {
    let label = match leg {
        LegIdV1::Upstream => "upstream-funding",
        LegIdV1::Downstream => "downstream-funding",
    };
    let payload = format!("dom-interop-simulation:{label}:v1").into_bytes();
    ActionIntentV1 {
        leg,
        kind: ActionKindV1::Funding,
        semantic_digest: material(label),
        contains_route_secret: false,
        dispatch: EffectDispatchV1::RunnerPayload {
            payload_digest: digest_bytes_v1(&payload),
            payload,
        },
    }
}

fn claim_intent(leg: LegIdV1) -> ActionIntentV1 {
    let label = match leg {
        LegIdV1::Upstream => "upstream-claim",
        LegIdV1::Downstream => "downstream-claim",
    };
    ActionIntentV1 {
        leg,
        kind: ActionKindV1::Claim,
        semantic_digest: material(label),
        contains_route_secret: true,
        dispatch: EffectDispatchV1::ExternalCustody {
            custody_digest: material(&format!("{label}-custody")),
            transaction_id: material(&format!("{label}-transaction")),
        },
    }
}

fn refund_intent(leg: LegIdV1) -> ActionIntentV1 {
    let label = match leg {
        LegIdV1::Upstream => "upstream-refund",
        LegIdV1::Downstream => "downstream-refund",
    };
    let payload = format!("dom-interop-simulation:{label}:v1").into_bytes();
    ActionIntentV1 {
        leg,
        kind: ActionKindV1::Refund,
        semantic_digest: material(label),
        contains_route_secret: false,
        dispatch: EffectDispatchV1::RunnerPayload {
            payload_digest: digest_bytes_v1(&payload),
            payload,
        },
    }
}

fn material(label: &str) -> Digest32 {
    digest_parts(MATERIAL_DOMAIN, &[label.as_bytes()])
}

fn event_id(label: &str) -> Digest32 {
    digest_parts(EVENT_DOMAIN, &[label.as_bytes()])
}

fn action_event_id(leg: LegIdV1, action: ActionKindV1) -> Digest32 {
    let label = match (leg, action) {
        (LegIdV1::Upstream, ActionKindV1::Funding) => "authorize-upstream-funding",
        (LegIdV1::Downstream, ActionKindV1::Funding) => "authorize-downstream-funding",
        (LegIdV1::Upstream, ActionKindV1::Claim) => "authorize-upstream-claim",
        (LegIdV1::Downstream, ActionKindV1::Claim) => "authorize-downstream-claim",
        (LegIdV1::Upstream, ActionKindV1::Refund) => "authorize-upstream-refund",
        (LegIdV1::Downstream, ActionKindV1::Refund) => "authorize-downstream-refund",
    };
    event_id(label)
}

fn finality_event_id(leg: LegIdV1, action: ActionKindV1) -> Digest32 {
    let label = match (leg, action) {
        (LegIdV1::Upstream, ActionKindV1::Funding) => "finality-upstream-funding",
        (LegIdV1::Downstream, ActionKindV1::Funding) => "finality-downstream-funding",
        (LegIdV1::Upstream, ActionKindV1::Claim) => "finality-upstream-claim",
        (LegIdV1::Downstream, ActionKindV1::Claim) => "finality-downstream-claim",
        (LegIdV1::Upstream, ActionKindV1::Refund) => "finality-upstream-refund",
        (LegIdV1::Downstream, ActionKindV1::Refund) => "finality-downstream-refund",
    };
    event_id(label)
}

fn route_id(scenario: SimulationScenarioV1) -> Digest32 {
    digest_parts(ROUTE_DOMAIN, &[scenario.tag().as_bytes()])
}

fn owner_id(scenario: SimulationScenarioV1, invocation: u64) -> Digest32 {
    digest_parts(
        OWNER_DOMAIN,
        &[scenario.tag().as_bytes(), &invocation.to_be_bytes()],
    )
}

fn digest_parts(domain: &[u8], parts: &[&[u8]]) -> Digest32 {
    let mut hasher = Blake2b::<U32>::new();
    BlakeDigest::update(&mut hasher, domain);
    for part in parts {
        BlakeDigest::update(&mut hasher, (part.len() as u64).to_be_bytes());
        BlakeDigest::update(&mut hasher, part);
    }
    hasher.finalize().into()
}

fn leg_tag(leg: LegIdV1) -> i64 {
    match leg {
        LegIdV1::Upstream => 0,
        LegIdV1::Downstream => 1,
    }
}

fn action_tag(action: ActionKindV1) -> i64 {
    match action {
        ActionKindV1::Funding => 0,
        ActionKindV1::Claim => 1,
        ActionKindV1::Refund => 2,
    }
}

fn decode_leg(value: i64) -> Result<LegIdV1, SimulationErrorV1> {
    match value {
        0 => Ok(LegIdV1::Upstream),
        1 => Ok(LegIdV1::Downstream),
        _ => Err(SimulationErrorV1::InconsistentAuthorityState),
    }
}

fn decode_action(value: i64) -> Result<ActionKindV1, SimulationErrorV1> {
    match value {
        0 => Ok(ActionKindV1::Funding),
        1 => Ok(ActionKindV1::Claim),
        2 => Ok(ActionKindV1::Refund),
        _ => Err(SimulationErrorV1::InconsistentAuthorityState),
    }
}

fn decode_bool(value: i64) -> Result<bool, SimulationErrorV1> {
    match value {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(SimulationErrorV1::InconsistentAuthorityState),
    }
}

fn leg_name(leg: LegIdV1) -> &'static str {
    match leg {
        LegIdV1::Upstream => "upstream",
        LegIdV1::Downstream => "downstream",
    }
}

fn action_name(action: ActionKindV1) -> &'static str {
    match action {
        ActionKindV1::Funding => "funding",
        ActionKindV1::Claim => "claim",
        ActionKindV1::Refund => "refund",
    }
}

fn blob32(bytes: Vec<u8>) -> Result<Digest32, SimulationErrorV1> {
    bytes
        .try_into()
        .map_err(|_| SimulationErrorV1::InconsistentAuthorityState)
}

fn optional_blob32(bytes: Option<Vec<u8>>) -> Result<Option<Digest32>, SimulationErrorV1> {
    bytes.map(blob32).transpose()
}

fn to_i64(value: u64) -> Result<i64, SimulationErrorV1> {
    i64::try_from(value).map_err(|_| SimulationErrorV1::InconsistentAuthorityState)
}

fn from_i64(value: i64) -> Result<u64, SimulationErrorV1> {
    u64::try_from(value).map_err(|_| SimulationErrorV1::InconsistentAuthorityState)
}

fn to_u64(value: usize) -> Result<u64, SimulationErrorV1> {
    u64::try_from(value).map_err(|_| SimulationErrorV1::TerminalInvariant)
}

fn is_constraint(error: &rusqlite::Error) -> bool {
    matches!(
        error,
        rusqlite::Error::SqliteFailure(code, _)
            if code.code == rusqlite::ErrorCode::ConstraintViolation
    )
}

fn hex32(value: Digest32) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(64);
    for byte in value {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}
