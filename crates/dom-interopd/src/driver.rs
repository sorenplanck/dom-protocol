//! Incremental production route driver over the sealed supervisor boundaries.
//!
//! One call performs at most one orchestration class: admission, refund
//! arming, one action authorization, one bounded dispatch tick, one finality
//! observation, or takeover reconciliation.  Every economic effect remains
//! persist-before-dispatch inside [`crate::RouteSupervisorV1`].

use blake2::{
    digest::{Update, VariableOutput},
    Blake2bVar,
};
use route_executor::{
    ActionKindV1, ActionProgressV1, ActionStateV1, CoordinationPhaseV1, HealthStateV1, LegIdV1,
    RouteIdV1, SecretVisibilityV1,
};

use crate::{
    AuthenticatedRouteAdmissionV1, AuthorityRefusalV1, ChainObservationAuthority,
    ChainObservationQueryV1, Clock, ExternalCustodyAuthority, RefundArmingAuthority,
    RouteActionAuthority, RouteSupervisorErrorV1, RouteSupervisorV1, RunnerActionAuthority,
    TakeoverReconciliationAuthority, TimerAuthority,
};

const DRIVER_EVENT_DOMAIN: &[u8] = b"DOM-INTEROPD/ROUTE-DRIVER-EVENT/V1\0";

/// The exact orchestration class selected by one driver call.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RouteDriveStageV1 {
    /// Reconcile effects committed by an older fencing owner.
    Takeover,
    /// Freeze authenticated route terms.
    Admission,
    /// Persist both refund exits before funding.
    RefundArming,
    /// Commit and acknowledge due internal timer events before new work.
    Timer,
    /// Fund the upstream leg first.
    UpstreamFunding,
    /// Fund the downstream leg only after upstream finality.
    DownstreamFunding,
    /// Claim downstream, normally publishing the route scalar.
    DownstreamClaim,
    /// Claim upstream with priority after the scalar is public.
    UpstreamClaim,
    /// Refund downstream while the route is in recovery-only mode.
    DownstreamRefund,
    /// Refund upstream while the route is in recovery-only mode.
    UpstreamRefund,
    /// The route is deliberately stopped pending recovery or operator policy.
    Recovery,
    /// Both legs reached a terminal economic outcome.
    Terminal,
}

impl RouteDriveStageV1 {
    const fn tag(self) -> u8 {
        match self {
            Self::Takeover => 1,
            Self::Admission => 2,
            Self::RefundArming => 3,
            Self::UpstreamFunding => 4,
            Self::DownstreamFunding => 5,
            Self::DownstreamClaim => 6,
            Self::UpstreamClaim => 7,
            Self::DownstreamRefund => 8,
            Self::UpstreamRefund => 9,
            Self::Recovery => 10,
            Self::Terminal => 11,
            Self::Timer => 12,
        }
    }
}

/// Result class of one incremental driver call.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RouteDriveDispositionV1 {
    /// A durable transition or externalization completed.
    Progressed,
    /// The selected authority is temporarily unavailable or evidence is not
    /// yet sufficient. Retrying is safe and uses the same durable identity.
    Waiting,
    /// No new funding is permitted until recovery/operator state changes.
    RecoveryRequired,
    /// The route is terminal.
    Terminal,
}

/// Secret-free report from one driver call.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RouteDriveReportV1 {
    /// Orchestration class selected from the authenticated snapshot.
    pub stage: RouteDriveStageV1,
    /// Snapshot revision before the call.
    pub before_revision: u64,
    /// Snapshot revision after the call.
    pub after_revision: u64,
    /// Whether the call progressed, is waiting, or reached a terminal state.
    pub disposition: RouteDriveDispositionV1,
}

/// Fail-closed driver error. Authority errors remain redacted by the
/// supervisor and no transaction, key, scalar, endpoint, or payload is added.
#[derive(Debug, thiserror::Error)]
pub enum RouteDriverErrorV1 {
    /// The sealed supervisor rejected a transition or authority response.
    #[error("route driver supervisor: {0}")]
    Supervisor(#[from] RouteSupervisorErrorV1),
    /// The supplied admission capability does not reproduce retained terms.
    #[error("route driver admission does not match retained route bindings")]
    AdmissionMismatch,
    /// The route snapshot reached a state the closed driver cannot safely act on.
    #[error("route driver found inconsistent route progress")]
    InconsistentProgress,
    /// A deterministic event identity could not be constructed.
    #[error("route driver event identity construction failed")]
    EventIdentity,
}

/// Borrowed, capability-separated authority set for one bounded driver step.
///
/// The fields are explicit so callers cannot hide a generic signer or RPC
/// handle behind an untyped container.
pub struct RouteDriverAuthoritiesV1<'a, F, A, O, R, E, T, X> {
    pub refund: &'a mut F,
    pub action: &'a mut A,
    pub observer: &'a mut O,
    pub runner: &'a mut R,
    pub external_custody: &'a mut E,
    pub timers: &'a mut T,
    pub reconciler: &'a mut X,
}

/// Executes one restart-safe orchestration step for a single route.
///
/// The function owns no signer or RPC. Concrete production authorities are
/// sealed implementations assembled inside this crate; tests/simulation may
/// use deterministic authorities under their explicit feature graphs.
pub fn drive_route_once_v1<C, F, A, O, R, E, T, X>(
    supervisor: &mut RouteSupervisorV1<C>,
    admission: &AuthenticatedRouteAdmissionV1,
    authorities: &mut RouteDriverAuthoritiesV1<'_, F, A, O, R, E, T, X>,
) -> Result<RouteDriveReportV1, RouteDriverErrorV1>
where
    C: Clock,
    F: RefundArmingAuthority,
    A: RouteActionAuthority,
    O: ChainObservationAuthority,
    R: RunnerActionAuthority,
    E: ExternalCustodyAuthority,
    T: TimerAuthority,
    X: TakeoverReconciliationAuthority,
{
    let refund_authority = &mut *authorities.refund;
    let action_authority = &mut *authorities.action;
    let observer = &mut *authorities.observer;
    let runner = &mut *authorities.runner;
    let external_custody = &mut *authorities.external_custody;
    let timers = &mut *authorities.timers;
    let reconciler = &mut *authorities.reconciler;
    let before = supervisor.snapshot()?;
    let route_id = before.route_id;
    if admission.route_id() != route_id {
        return Err(RouteDriverErrorV1::AdmissionMismatch);
    }
    if before
        .bindings
        .as_ref()
        .is_some_and(|retained| retained != admission.frozen_bindings())
    {
        return Err(RouteDriverErrorV1::AdmissionMismatch);
    }

    match supervisor.reconcile_takeover(reconciler) {
        Ok(report) => {
            if report.externalized != 0
                || report.reauthorized != 0
                || report.partial_custody_resumed != 0
                || report.partial_secret_custody_resumed != 0
            {
                return report_after(
                    supervisor,
                    before.revision,
                    RouteDriveStageV1::Takeover,
                    RouteDriveDispositionV1::Progressed,
                );
            }
            if report.unknown != 0 {
                return report_after(
                    supervisor,
                    before.revision,
                    RouteDriveStageV1::Takeover,
                    RouteDriveDispositionV1::Waiting,
                );
            }
        }
        Err(error) if authority_unavailable(&error) => {
            return report_after(
                supervisor,
                before.revision,
                RouteDriveStageV1::Takeover,
                RouteDriveDispositionV1::Waiting,
            );
        }
        Err(error) => return Err(error.into()),
    }

    let snapshot = supervisor.snapshot()?;
    match snapshot.bindings.as_ref() {
        None => {
            if snapshot.coordination == CoordinationPhaseV1::Terminal {
                return report_after(
                    supervisor,
                    before.revision,
                    RouteDriveStageV1::Terminal,
                    RouteDriveDispositionV1::Terminal,
                );
            }
            if snapshot.health != HealthStateV1::Running {
                return report_after(
                    supervisor,
                    before.revision,
                    RouteDriveStageV1::Recovery,
                    RouteDriveDispositionV1::RecoveryRequired,
                );
            }
            let event_id = driver_event_id(route_id, RouteDriveStageV1::Admission, None, None)?;
            let result = supervisor.admit_route(event_id, admission);
            return authority_step(
                supervisor,
                before.revision,
                RouteDriveStageV1::Admission,
                result,
            );
        }
        Some(retained) if retained != admission.frozen_bindings() => {
            return Err(RouteDriverErrorV1::AdmissionMismatch)
        }
        Some(_) => {}
    }
    if snapshot.coordination == CoordinationPhaseV1::Terminal {
        return report_after(
            supervisor,
            before.revision,
            RouteDriveStageV1::Terminal,
            RouteDriveDispositionV1::Terminal,
        );
    }
    if matches!(
        snapshot.secret_visibility,
        SecretVisibilityV1::Public { .. }
    ) {
        if snapshot.refunds.is_none() {
            return report_after(
                supervisor,
                before.revision,
                RouteDriveStageV1::Recovery,
                RouteDriveDispositionV1::RecoveryRequired,
            );
        }
        // A refund already chosen for the upstream output is mutually
        // exclusive with its claim. Preserve that exact exit instead of
        // trying to authorize a competing secret path.
        if snapshot.upstream.refund.progress() != ActionProgressV1::NotPrepared {
            return drive_recovery_once(
                supervisor,
                RecoveryDriveContextV1 {
                    before_revision: before.revision,
                    snapshot: &snapshot,
                },
                action_authority,
                observer,
                runner,
                external_custody,
                timers,
            );
        }
        if snapshot.secret_public_but_upstream_unclaimed() {
            return match snapshot.upstream.funding {
                ActionStateV1::Externalized { .. } => drive_action_once(
                    supervisor,
                    ActionDriveContextV1 {
                        before_revision: before.revision,
                        stage: RouteDriveStageV1::UpstreamFunding,
                        leg: LegIdV1::Upstream,
                        action: ActionKindV1::Funding,
                    },
                    action_authority,
                    observer,
                    runner,
                    external_custody,
                    timers,
                ),
                ActionStateV1::Final { .. } | ActionStateV1::FinalityInvalidated { .. } => {
                    drive_action_once(
                        supervisor,
                        ActionDriveContextV1 {
                            before_revision: before.revision,
                            stage: RouteDriveStageV1::UpstreamClaim,
                            leg: LegIdV1::Upstream,
                            action: ActionKindV1::Claim,
                        },
                        action_authority,
                        observer,
                        runner,
                        external_custody,
                        timers,
                    )
                }
                ActionStateV1::NotPrepared | ActionStateV1::Committed(_) => report_after(
                    supervisor,
                    before.revision,
                    RouteDriveStageV1::Recovery,
                    RouteDriveDispositionV1::RecoveryRequired,
                ),
            };
        }
        if snapshot.upstream.claim.progress() == ActionProgressV1::Final {
            if matches!(
                snapshot.downstream.claim.progress(),
                ActionProgressV1::Committed | ActionProgressV1::Externalized
            ) {
                return drive_action_once(
                    supervisor,
                    ActionDriveContextV1 {
                        before_revision: before.revision,
                        stage: RouteDriveStageV1::DownstreamClaim,
                        leg: LegIdV1::Downstream,
                        action: ActionKindV1::Claim,
                    },
                    action_authority,
                    observer,
                    runner,
                    external_custody,
                    timers,
                );
            }
            if snapshot.downstream.refund.progress() != ActionProgressV1::NotPrepared
                || snapshot.health == HealthStateV1::RecoveryOnly
            {
                return drive_recovery_once(
                    supervisor,
                    RecoveryDriveContextV1 {
                        before_revision: before.revision,
                        snapshot: &snapshot,
                    },
                    action_authority,
                    observer,
                    runner,
                    external_custody,
                    timers,
                );
            }
        }
        return report_after(
            supervisor,
            before.revision,
            RouteDriveStageV1::Recovery,
            RouteDriveDispositionV1::RecoveryRequired,
        );
    }
    if snapshot.refunds.is_none() && snapshot.health != HealthStateV1::Running {
        return report_after(
            supervisor,
            before.revision,
            RouteDriveStageV1::Recovery,
            RouteDriveDispositionV1::RecoveryRequired,
        );
    }
    if snapshot.refunds.is_none() {
        let event_id = driver_event_id(route_id, RouteDriveStageV1::RefundArming, None, None)?;
        let result = supervisor.arm_refunds(event_id, refund_authority);
        return authority_step(
            supervisor,
            before.revision,
            RouteDriveStageV1::RefundArming,
            result,
        );
    }

    if snapshot.upstream.refund.progress() != ActionProgressV1::NotPrepared
        || snapshot.downstream.refund.progress() != ActionProgressV1::NotPrepared
    {
        return drive_recovery_once(
            supervisor,
            RecoveryDriveContextV1 {
                before_revision: before.revision,
                snapshot: &snapshot,
            },
            action_authority,
            observer,
            runner,
            external_custody,
            timers,
        );
    }

    match snapshot.health {
        HealthStateV1::Running => {}
        HealthStateV1::RecoveryOnly => {
            return drive_recovery_once(
                supervisor,
                RecoveryDriveContextV1 {
                    before_revision: before.revision,
                    snapshot: &snapshot,
                },
                action_authority,
                observer,
                runner,
                external_custody,
                timers,
            );
        }
        HealthStateV1::Degraded | HealthStateV1::ManualIntervention => {
            return report_after(
                supervisor,
                before.revision,
                RouteDriveStageV1::Recovery,
                RouteDriveDispositionV1::RecoveryRequired,
            );
        }
    }

    if snapshot.upstream.funding.progress() != ActionProgressV1::Final {
        return drive_action_once(
            supervisor,
            ActionDriveContextV1 {
                before_revision: before.revision,
                stage: RouteDriveStageV1::UpstreamFunding,
                leg: LegIdV1::Upstream,
                action: ActionKindV1::Funding,
            },
            action_authority,
            observer,
            runner,
            external_custody,
            timers,
        );
    }
    if snapshot.downstream.funding.progress() != ActionProgressV1::Final {
        return drive_action_once(
            supervisor,
            ActionDriveContextV1 {
                before_revision: before.revision,
                stage: RouteDriveStageV1::DownstreamFunding,
                leg: LegIdV1::Downstream,
                action: ActionKindV1::Funding,
            },
            action_authority,
            observer,
            runner,
            external_custody,
            timers,
        );
    }
    if snapshot.downstream.claim.progress() != ActionProgressV1::Final {
        return drive_action_once(
            supervisor,
            ActionDriveContextV1 {
                before_revision: before.revision,
                stage: RouteDriveStageV1::DownstreamClaim,
                leg: LegIdV1::Downstream,
                action: ActionKindV1::Claim,
            },
            action_authority,
            observer,
            runner,
            external_custody,
            timers,
        );
    }
    if snapshot.upstream.claim.progress() != ActionProgressV1::Final {
        return Err(RouteDriverErrorV1::InconsistentProgress);
    }
    report_after(
        supervisor,
        before.revision,
        RouteDriveStageV1::Terminal,
        RouteDriveDispositionV1::Terminal,
    )
}

struct RecoveryDriveContextV1<'a> {
    before_revision: u64,
    snapshot: &'a route_executor::RouteSnapshotV1,
}

fn drive_recovery_once<C, A, O, R, E, T>(
    supervisor: &mut RouteSupervisorV1<C>,
    context: RecoveryDriveContextV1<'_>,
    action_authority: &mut A,
    observer: &mut O,
    runner: &mut R,
    external_custody: &mut E,
    timers: &mut T,
) -> Result<RouteDriveReportV1, RouteDriverErrorV1>
where
    C: Clock,
    A: RouteActionAuthority,
    O: ChainObservationAuthority,
    R: RunnerActionAuthority,
    E: ExternalCustodyAuthority,
    T: TimerAuthority,
{
    let RecoveryDriveContextV1 {
        before_revision,
        snapshot,
    } = context;
    // Once a terminal path left custody, finish observing that exact path;
    // authorizing its competing refund would violate mutual exclusion.  A
    // downstream claim that is only committed cannot be externalized after
    // entering recovery, so it deliberately requires operator/reconciliation
    // rather than a competing action.
    match snapshot.downstream.claim.progress() {
        ActionProgressV1::Externalized => {
            return drive_action_once(
                supervisor,
                ActionDriveContextV1 {
                    before_revision,
                    stage: RouteDriveStageV1::DownstreamClaim,
                    leg: LegIdV1::Downstream,
                    action: ActionKindV1::Claim,
                },
                action_authority,
                observer,
                runner,
                external_custody,
                timers,
            );
        }
        ActionProgressV1::Committed => {
            return report_after(
                supervisor,
                before_revision,
                RouteDriveStageV1::Recovery,
                RouteDriveDispositionV1::RecoveryRequired,
            );
        }
        ActionProgressV1::NotPrepared | ActionProgressV1::Final => {}
    }

    for (leg, stage) in [
        (LegIdV1::Downstream, RouteDriveStageV1::DownstreamRefund),
        (LegIdV1::Upstream, RouteDriveStageV1::UpstreamRefund),
    ] {
        if snapshot.leg(leg).refund.progress() != ActionProgressV1::NotPrepared
            && snapshot.leg(leg).refund.progress() != ActionProgressV1::Final
        {
            return drive_action_once(
                supervisor,
                ActionDriveContextV1 {
                    before_revision,
                    stage,
                    leg,
                    action: ActionKindV1::Refund,
                },
                action_authority,
                observer,
                runner,
                external_custody,
                timers,
            );
        }
    }

    for (leg, stage) in [
        (LegIdV1::Downstream, RouteDriveStageV1::DownstreamRefund),
        (LegIdV1::Upstream, RouteDriveStageV1::UpstreamRefund),
    ] {
        let leg_snapshot = snapshot.leg(leg);
        if matches!(
            leg_snapshot.funding.progress(),
            ActionProgressV1::Externalized | ActionProgressV1::Final
        ) && leg_snapshot.claim.progress() == ActionProgressV1::NotPrepared
            && leg_snapshot.refund.progress() == ActionProgressV1::NotPrepared
        {
            return drive_action_once(
                supervisor,
                ActionDriveContextV1 {
                    before_revision,
                    stage,
                    leg,
                    action: ActionKindV1::Refund,
                },
                action_authority,
                observer,
                runner,
                external_custody,
                timers,
            );
        }
    }

    report_after(
        supervisor,
        before_revision,
        RouteDriveStageV1::Recovery,
        RouteDriveDispositionV1::RecoveryRequired,
    )
}

struct ActionDriveContextV1 {
    before_revision: u64,
    stage: RouteDriveStageV1,
    leg: LegIdV1,
    action: ActionKindV1,
}

fn drive_action_once<C, A, O, R, E, T>(
    supervisor: &mut RouteSupervisorV1<C>,
    context: ActionDriveContextV1,
    action_authority: &mut A,
    observer: &mut O,
    runner: &mut R,
    external_custody: &mut E,
    timers: &mut T,
) -> Result<RouteDriveReportV1, RouteDriverErrorV1>
where
    C: Clock,
    A: RouteActionAuthority,
    O: ChainObservationAuthority,
    R: RunnerActionAuthority,
    E: ExternalCustodyAuthority,
    T: TimerAuthority,
{
    let ActionDriveContextV1 {
        before_revision,
        stage,
        leg,
        action,
    } = context;
    let snapshot = supervisor.snapshot()?;
    let state = snapshot.leg(leg).action(action).clone();
    match state {
        ActionStateV1::NotPrepared => {
            // Timers are the durable deadline/recovery authority. They must
            // run before a new action is authorized; otherwise a due deadline
            // could remain invisible forever while every snapshot-selected
            // action is still NotPrepared. The sole exception is an upstream
            // claim after public exposure: even an unavailable timer must not
            // delay committing that urgent recovery capability.
            let urgent_unprepared_claim = stage == RouteDriveStageV1::UpstreamClaim
                && leg == LegIdV1::Upstream
                && action == ActionKindV1::Claim
                && snapshot.secret_public_but_upstream_unclaimed();
            if !urgent_unprepared_claim {
                match supervisor.dispatch_one_due_timer(timers) {
                    Ok(report) => {
                        if report.timers_completed != 0 {
                            return report_after(
                                supervisor,
                                before_revision,
                                RouteDriveStageV1::Timer,
                                RouteDriveDispositionV1::Progressed,
                            );
                        }
                        if report.urgent_externalized != 0
                            || report.runner_externalized != 0
                            || report.custody_externalized != 0
                            || report.custody_partial_progress != 0
                            || report.custody_progress_unchanged != 0
                            || report.custody_unknown != 0
                        {
                            return Err(RouteDriverErrorV1::InconsistentProgress);
                        }
                        if report.takeover_reconciliation_required || report.urgent_in_flight {
                            return report_after(
                                supervisor,
                                before_revision,
                                RouteDriveStageV1::Takeover,
                                RouteDriveDispositionV1::Waiting,
                            );
                        }
                    }
                    Err(RouteSupervisorErrorV1::TimerAuthority(
                        AuthorityRefusalV1::Unavailable,
                    )) => {
                        return report_after(
                            supervisor,
                            before_revision,
                            RouteDriveStageV1::Timer,
                            RouteDriveDispositionV1::Waiting,
                        );
                    }
                    Err(error) if authority_unavailable(&error) => {
                        return report_after(
                            supervisor,
                            before_revision,
                            stage,
                            RouteDriveDispositionV1::Waiting,
                        );
                    }
                    Err(error) => return Err(error.into()),
                }
            }
            let event_id = driver_event_id(snapshot.route_id, stage, Some((leg, action)), None)?;
            let result = supervisor.authorize_action(event_id, leg, action, action_authority);
            authority_step(supervisor, before_revision, stage, result)
        }
        ActionStateV1::Committed(reference) => {
            match supervisor.dispatch_one_due_timer(timers) {
                Ok(report) => {
                    if report.urgent_externalized != 0
                        || report.runner_externalized != 0
                        || report.custody_externalized != 0
                        || report.custody_partial_progress != 0
                        || report.custody_progress_unchanged != 0
                        || report.custody_unknown != 0
                    {
                        return Err(RouteDriverErrorV1::InconsistentProgress);
                    }
                    if report.timers_completed != 0 {
                        return report_after(
                            supervisor,
                            before_revision,
                            RouteDriveStageV1::Timer,
                            RouteDriveDispositionV1::Progressed,
                        );
                    }
                    if report.takeover_reconciliation_required {
                        return report_after(
                            supervisor,
                            before_revision,
                            RouteDriveStageV1::Takeover,
                            RouteDriveDispositionV1::Waiting,
                        );
                    }
                }
                Err(RouteSupervisorErrorV1::TimerAuthority(AuthorityRefusalV1::Unavailable)) => {
                    return report_after(
                        supervisor,
                        before_revision,
                        RouteDriveStageV1::Timer,
                        RouteDriveDispositionV1::Waiting,
                    );
                }
                Err(error) if authority_unavailable(&error) => {
                    return report_after(
                        supervisor,
                        before_revision,
                        stage,
                        RouteDriveDispositionV1::Waiting,
                    );
                }
                Err(error) => return Err(error.into()),
            }
            match supervisor.dispatch_one_effect(runner, external_custody) {
                Ok(report) => {
                    let after = supervisor.snapshot()?;
                    let (reported_stage, disposition) = match after.leg(leg).action(action) {
                        ActionStateV1::Externalized { effect, .. }
                            if effect.effect_id == reference.effect_id =>
                        {
                            if report.timers_completed != 0 {
                                return Err(RouteDriverErrorV1::InconsistentProgress);
                            }
                            (stage, RouteDriveDispositionV1::Progressed)
                        }
                        ActionStateV1::Committed(retained) if retained == &reference => {
                            if report.urgent_externalized != 0
                                || report.runner_externalized != 0
                                || report.custody_externalized != 0
                            {
                                return Err(RouteDriverErrorV1::InconsistentProgress);
                            }
                            if report.custody_partial_progress != 0 {
                                if report.custody_progress_unchanged != 0
                                    || report.custody_unknown != 0
                                {
                                    return Err(RouteDriverErrorV1::InconsistentProgress);
                                }
                                (stage, RouteDriveDispositionV1::Progressed)
                            } else {
                                (stage, RouteDriveDispositionV1::Waiting)
                            }
                        }
                        _ => return Err(RouteDriverErrorV1::InconsistentProgress),
                    };
                    Ok(RouteDriveReportV1 {
                        stage: reported_stage,
                        before_revision,
                        after_revision: after.revision,
                        disposition,
                    })
                }
                Err(error) if authority_unavailable(&error) => report_after(
                    supervisor,
                    before_revision,
                    stage,
                    RouteDriveDispositionV1::Waiting,
                ),
                Err(error) => Err(error.into()),
            }
        }
        ActionStateV1::Externalized { transaction_id, .. }
        | ActionStateV1::FinalityInvalidated { transaction_id, .. } => {
            let event_id = driver_event_id(
                snapshot.route_id,
                stage,
                Some((leg, action)),
                Some((transaction_id, snapshot.last_event_digest)),
            )?;
            let result = supervisor.record_chain_observation(
                event_id,
                ChainObservationQueryV1::Finality {
                    leg,
                    action,
                    transaction_id,
                },
                observer,
            );
            authority_step(supervisor, before_revision, stage, result)
        }
        ActionStateV1::Final { .. } => Err(RouteDriverErrorV1::InconsistentProgress),
    }
}

fn authority_step<C: Clock, T>(
    supervisor: &RouteSupervisorV1<C>,
    before_revision: u64,
    stage: RouteDriveStageV1,
    result: Result<T, RouteSupervisorErrorV1>,
) -> Result<RouteDriveReportV1, RouteDriverErrorV1> {
    match result {
        Ok(_) => report_after(
            supervisor,
            before_revision,
            stage,
            RouteDriveDispositionV1::Progressed,
        ),
        Err(error) if authority_unavailable(&error) => report_after(
            supervisor,
            before_revision,
            stage,
            RouteDriveDispositionV1::Waiting,
        ),
        Err(error) => Err(error.into()),
    }
}

fn report_after<C: Clock>(
    supervisor: &RouteSupervisorV1<C>,
    before_revision: u64,
    stage: RouteDriveStageV1,
    disposition: RouteDriveDispositionV1,
) -> Result<RouteDriveReportV1, RouteDriverErrorV1> {
    Ok(RouteDriveReportV1 {
        stage,
        before_revision,
        after_revision: supervisor.snapshot()?.revision,
        disposition,
    })
}

fn authority_unavailable(error: &RouteSupervisorErrorV1) -> bool {
    matches!(
        error,
        RouteSupervisorErrorV1::StoreAuthorityBusy
            | RouteSupervisorErrorV1::RefundAuthority(AuthorityRefusalV1::Unavailable)
            | RouteSupervisorErrorV1::RouteActionAuthority(AuthorityRefusalV1::Unavailable)
            | RouteSupervisorErrorV1::ChainObservationAuthority(AuthorityRefusalV1::Unavailable)
            | RouteSupervisorErrorV1::RunnerAuthority(AuthorityRefusalV1::Unavailable)
            | RouteSupervisorErrorV1::ExternalCustodyAuthority(AuthorityRefusalV1::Unavailable)
            | RouteSupervisorErrorV1::TimerAuthority(AuthorityRefusalV1::Unavailable)
            | RouteSupervisorErrorV1::ReconciliationAuthority(AuthorityRefusalV1::Unavailable)
    )
}

fn driver_event_id(
    route_id: RouteIdV1,
    stage: RouteDriveStageV1,
    action: Option<(LegIdV1, ActionKindV1)>,
    observation: Option<([u8; 32], [u8; 32])>,
) -> Result<[u8; 32], RouteDriverErrorV1> {
    let mut hasher = Blake2bVar::new(32).map_err(|_| RouteDriverErrorV1::EventIdentity)?;
    hasher.update(DRIVER_EVENT_DOMAIN);
    hasher.update(&route_id);
    hasher.update(&[stage.tag()]);
    match action {
        Some((leg, kind)) => {
            hasher.update(&[1, leg_tag(leg), action_tag(kind)]);
        }
        None => hasher.update(&[0, 0, 0]),
    }
    match observation {
        Some((transaction_id, predecessor)) => {
            hasher.update(&[1]);
            hasher.update(&transaction_id);
            hasher.update(&predecessor);
        }
        None => hasher.update(&[0]),
    }
    let mut digest = [0; 32];
    hasher
        .finalize_variable(&mut digest)
        .map_err(|_| RouteDriverErrorV1::EventIdentity)?;
    if digest == [0; 32] {
        return Err(RouteDriverErrorV1::EventIdentity);
    }
    Ok(digest)
}

const fn leg_tag(leg: LegIdV1) -> u8 {
    match leg {
        LegIdV1::Upstream => 1,
        LegIdV1::Downstream => 2,
    }
}

const fn action_tag(action: ActionKindV1) -> u8 {
    match action {
        ActionKindV1::Funding => 1,
        ActionKindV1::Claim => 2,
        ActionKindV1::Refund => 3,
    }
}
