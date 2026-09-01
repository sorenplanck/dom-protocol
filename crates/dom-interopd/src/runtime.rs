//! Long-lived, restart-safe execution loop for one production route.
//!
//! The incremental driver deliberately performs one authority call per step.
//! This module owns the repetition policy around it: bounded backoff, lease
//! renewal before sleeping, shutdown draining and a secret-free progress
//! callback. Chain-specific authority implementations remain in the
//! composition root and are still sealed by [`crate::supervisor`].

use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

use route_executor::{CoordinationPhaseV1, RouteSnapshotV1, SecretVisibilityV1};

use crate::{
    drive_route_once_v1, AuthenticatedRouteAdmissionV1, AuthorityRefusalV1,
    ChainObservationAuthority, Clock, ExternalCustodyAuthority, RefundArmingAuthority,
    RouteActionAuthority, RouteDriveDispositionV1, RouteDriveReportV1, RouteDriverAuthoritiesV1,
    RouteDriverErrorV1, RouteSecretRetirementAuthority, RouteSupervisorErrorV1, RouteSupervisorV1,
    RunnerActionAuthority, TakeoverReconciliationAuthority, TimerAuthority,
};

/// Longest blocking wait accepted by the production loop.
pub const MAX_ROUTE_RUNTIME_BACKOFF_MS_V1: u64 = 30_000;

/// Defensive cap for a single bounded invocation.
pub const MAX_ROUTE_RUNTIME_STEP_BUDGET_V1: u64 = 1_000_000;

/// Backoff policy for a single route runtime.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RouteRuntimeConfigV1 {
    waiting_backoff_ms: u64,
    recovery_backoff_ms: u64,
}

impl RouteRuntimeConfigV1 {
    /// Validates bounded waits against the supervisor's renewal window.
    pub fn new(
        waiting_backoff_ms: u64,
        recovery_backoff_ms: u64,
        supervisor: crate::RouteSupervisorConfigV1,
    ) -> Result<Self, RouteRuntimeErrorV1> {
        let safe_sleep_ceiling = supervisor
            .lease_duration_ms()
            .checked_sub(supervisor.renew_before_ms())
            .ok_or(RouteRuntimeErrorV1::InvalidConfiguration)?;
        if waiting_backoff_ms == 0
            || recovery_backoff_ms == 0
            || waiting_backoff_ms > MAX_ROUTE_RUNTIME_BACKOFF_MS_V1
            || recovery_backoff_ms > MAX_ROUTE_RUNTIME_BACKOFF_MS_V1
            || waiting_backoff_ms > safe_sleep_ceiling
            || recovery_backoff_ms > safe_sleep_ceiling
        {
            return Err(RouteRuntimeErrorV1::InvalidConfiguration);
        }
        Ok(Self {
            waiting_backoff_ms,
            recovery_backoff_ms,
        })
    }

    /// Delay after an unavailable authority or incomplete observation.
    pub const fn waiting_backoff_ms(self) -> u64 {
        self.waiting_backoff_ms
    }

    /// Delay while a funded route remains in recovery-only mode.
    pub const fn recovery_backoff_ms(self) -> u64 {
        self.recovery_backoff_ms
    }
}

/// Secret-free hook used for shutdown, waiting and operational reporting.
///
/// Production uses [`SystemRouteRunControlV1`]. Test graphs may provide a
/// deterministic implementation that advances their trusted manual clock.
pub trait RouteRunControlV1 {
    /// Whether the operator requested a coordinated shutdown.
    fn shutdown_requested(&mut self) -> Result<bool, RouteRunControlErrorV1>;

    /// Wait for a bounded interval. Implementations may return early after a
    /// shutdown request, but must not claim that time elapsed when it did not.
    fn wait(&mut self, duration: Duration) -> Result<(), RouteRunControlErrorV1>;

    /// Observe one secret-free driver report after its durable step.
    fn record_progress(
        &mut self,
        _report: RouteDriveReportV1,
    ) -> Result<(), RouteRunControlErrorV1> {
        Ok(())
    }
}

/// Control-plane error. It never includes endpoints, payloads or secrets.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum RouteRunControlErrorV1 {
    /// The shutdown/wakeup primitive was poisoned or unavailable.
    #[error("route runtime control unavailable")]
    Unavailable,
}

#[derive(Default)]
struct ShutdownStateV1 {
    requested: Mutex<bool>,
    wake: Condvar,
}

/// Cloneable handle that requests and wakes a coordinated shutdown.
#[derive(Clone, Default)]
pub struct RouteShutdownTokenV1 {
    state: Arc<ShutdownStateV1>,
}

impl core::fmt::Debug for RouteShutdownTokenV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("RouteShutdownTokenV1([redacted])")
    }
}

impl RouteShutdownTokenV1 {
    /// Creates an unset shutdown token.
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the request monotonically and wakes a sleeping runtime.
    pub fn request_shutdown(&self) -> Result<(), RouteRunControlErrorV1> {
        let mut requested = self
            .state
            .requested
            .lock()
            .map_err(|_| RouteRunControlErrorV1::Unavailable)?;
        *requested = true;
        self.state.wake.notify_all();
        Ok(())
    }

    /// Reads the monotonic shutdown request.
    pub fn is_shutdown_requested(&self) -> Result<bool, RouteRunControlErrorV1> {
        self.state
            .requested
            .lock()
            .map(|requested| *requested)
            .map_err(|_| RouteRunControlErrorV1::Unavailable)
    }
}

/// Standard blocking control for the Linux production process.
pub struct SystemRouteRunControlV1 {
    shutdown: RouteShutdownTokenV1,
}

impl core::fmt::Debug for SystemRouteRunControlV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("SystemRouteRunControlV1([redacted])")
    }
}

impl SystemRouteRunControlV1 {
    /// Creates a controller and the handle an OS-signal worker may hold.
    pub fn new() -> (Self, RouteShutdownTokenV1) {
        let shutdown = RouteShutdownTokenV1::new();
        (
            Self {
                shutdown: shutdown.clone(),
            },
            shutdown,
        )
    }
}

impl RouteRunControlV1 for SystemRouteRunControlV1 {
    fn shutdown_requested(&mut self) -> Result<bool, RouteRunControlErrorV1> {
        self.shutdown.is_shutdown_requested()
    }

    fn wait(&mut self, duration: Duration) -> Result<(), RouteRunControlErrorV1> {
        let requested = self
            .shutdown
            .state
            .requested
            .lock()
            .map_err(|_| RouteRunControlErrorV1::Unavailable)?;
        let (_guard, _timeout) = self
            .shutdown
            .state
            .wake
            .wait_timeout_while(requested, duration, |value| !*value)
            .map_err(|_| RouteRunControlErrorV1::Unavailable)?;
        Ok(())
    }
}

/// The eight sealed authority classes owned by one route process.
pub struct RouteRuntimeAuthoritiesV1<F, A, O, R, E, T, X, Y> {
    refund: F,
    action: A,
    observer: O,
    runner: R,
    custody: E,
    timers: T,
    reconciler: X,
    retirement: Y,
}

/// Authorities used while advancing the normal route path.
pub struct RouteRuntimeOperationalAuthoritiesV1<F, A, O, R> {
    pub refund: F,
    pub action: A,
    pub observer: O,
    pub runner: R,
}

/// Authorities that own external custody, deadlines and takeover recovery.
pub struct RouteRuntimeRecoveryAuthoritiesV1<E, T, X, Y> {
    pub custody: E,
    pub timers: T,
    pub reconciler: X,
    /// Consumes only a Store-minted public-terminal/no-open-funds capability.
    pub retirement: Y,
}

impl<F, A, O, R, E, T, X, Y> RouteRuntimeAuthoritiesV1<F, A, O, R, E, T, X, Y> {
    /// Assembles the exact authority set. No generic signer is accepted.
    pub fn new(
        operational: RouteRuntimeOperationalAuthoritiesV1<F, A, O, R>,
        recovery: RouteRuntimeRecoveryAuthoritiesV1<E, T, X, Y>,
    ) -> Self {
        let RouteRuntimeOperationalAuthoritiesV1 {
            refund,
            action,
            observer,
            runner,
        } = operational;
        let RouteRuntimeRecoveryAuthoritiesV1 {
            custody,
            timers,
            reconciler,
            retirement,
        } = recovery;
        Self {
            refund,
            action,
            observer,
            runner,
            custody,
            timers,
            reconciler,
            retirement,
        }
    }
}

impl<F, A, O, R, E, T, X, Y> core::fmt::Debug
    for RouteRuntimeAuthoritiesV1<F, A, O, R, E, T, X, Y>
{
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("RouteRuntimeAuthoritiesV1([redacted])")
    }
}

/// Why a bounded or continuous route loop returned to its caller.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RouteRuntimeExitV1 {
    /// Both route settlements are terminal.
    Terminal {
        /// Last durable route revision.
        revision: u64,
        /// Number of driver calls performed by this invocation.
        steps: u64,
    },
    /// Shutdown was requested before any route funds/effects remained open.
    SafeShutdown {
        /// Last durable route revision.
        revision: u64,
        /// Number of driver calls performed by this invocation.
        steps: u64,
    },
    /// A laboratory/operator-provided finite step budget was exhausted.
    StepBudgetExhausted {
        /// Last durable route revision.
        revision: u64,
        /// Number of driver calls performed by this invocation.
        steps: u64,
    },
}

/// Fail-closed runtime error.
#[derive(Debug, thiserror::Error)]
pub enum RouteRuntimeErrorV1 {
    /// Backoff or step bounds are invalid for the supervisor lease policy.
    #[error("invalid route runtime configuration")]
    InvalidConfiguration,
    /// The incremental driver rejected the current state or authority result.
    #[error("route runtime driver: {0}")]
    Driver(#[from] RouteDriverErrorV1),
    /// Lease renewal or snapshot verification failed.
    #[error("route runtime supervisor: {0}")]
    Supervisor(#[from] RouteSupervisorErrorV1),
    /// The shutdown/wakeup/reporting control failed.
    #[error("route runtime control: {0}")]
    Control(#[from] RouteRunControlErrorV1),
    /// Terminal journal replay succeeded but exact secret retirement did not.
    #[error("route runtime secret retirement: {0:?}")]
    SecretRetirement(AuthorityRefusalV1),
}

/// One long-lived production route process.
///
/// The runtime owns the route supervisor, authenticated pinned admission and
/// every sealed authority. It has no raw reducer-event or generic-signing API.
pub struct ProductionRouteRuntimeV1<C, F, A, O, R, E, T, X, Y>
where
    C: Clock,
{
    supervisor: RouteSupervisorV1<C>,
    admission: AuthenticatedRouteAdmissionV1,
    authorities: RouteRuntimeAuthoritiesV1<F, A, O, R, E, T, X, Y>,
    config: RouteRuntimeConfigV1,
}

impl<C, F, A, O, R, E, T, X, Y> core::fmt::Debug
    for ProductionRouteRuntimeV1<C, F, A, O, R, E, T, X, Y>
where
    C: Clock,
{
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("ProductionRouteRuntimeV1")
            .field("supervisor", &self.supervisor)
            .field("admission", &self.admission)
            .field("authorities", &self.authorities)
            .field("config", &self.config)
            .finish()
    }
}

impl<C, F, A, O, R, E, T, X, Y> ProductionRouteRuntimeV1<C, F, A, O, R, E, T, X, Y>
where
    C: Clock,
    F: RefundArmingAuthority,
    A: RouteActionAuthority,
    O: ChainObservationAuthority,
    R: RunnerActionAuthority,
    E: ExternalCustodyAuthority,
    T: TimerAuthority,
    X: TakeoverReconciliationAuthority,
    Y: RouteSecretRetirementAuthority,
{
    /// Takes ownership of one already-acquired supervisor and its authorities.
    pub fn new(
        supervisor: RouteSupervisorV1<C>,
        admission: AuthenticatedRouteAdmissionV1,
        authorities: RouteRuntimeAuthoritiesV1<F, A, O, R, E, T, X, Y>,
        config: RouteRuntimeConfigV1,
    ) -> Result<Self, RouteRuntimeErrorV1> {
        // Re-run validation against the actual supervisor. This rejects a
        // config constructed for a longer lease policy.
        let config = RouteRuntimeConfigV1::new(
            config.waiting_backoff_ms,
            config.recovery_backoff_ms,
            supervisor.config(),
        )?;
        if admission.route_id() != supervisor.lease_status().route_id() {
            return Err(RouteRuntimeErrorV1::InvalidConfiguration);
        }
        Ok(Self {
            supervisor,
            admission,
            authorities,
            config,
        })
    }

    /// Current verified public route snapshot.
    pub fn snapshot(&self) -> Result<RouteSnapshotV1, RouteRuntimeErrorV1> {
        Ok(self.supervisor.snapshot()?)
    }

    /// Performs exactly one incremental driver step.
    pub fn step(&mut self) -> Result<RouteDriveReportV1, RouteRuntimeErrorV1> {
        let report = self.drive_step()?;
        let after = self.supervisor.snapshot()?;
        if report.disposition == RouteDriveDispositionV1::Terminal
            || after.coordination == CoordinationPhaseV1::Terminal
        {
            self.retire_public_terminal(&after)?;
        }
        Ok(report)
    }

    /// Renews the route lease before a bounded blocking operation owned by the
    /// production composition root. The bound is checked against the same
    /// renewal window used by this runtime's internal waits, so an external
    /// Relay cycle cannot silently outlive the route operation lock.
    #[expect(
        dead_code,
        reason = "retained surface not yet wired by the stage-7 composition root"
    )]
    pub(crate) fn prepare_bounded_external_block(
        &mut self,
        bound: Duration,
    ) -> Result<(), RouteRuntimeErrorV1> {
        let bound_ms = u64::try_from(bound.as_millis())
            .map_err(|_| RouteRuntimeErrorV1::InvalidConfiguration)?;
        let safe_ceiling = self
            .supervisor
            .config()
            .lease_duration_ms()
            .checked_sub(self.supervisor.config().renew_before_ms())
            .ok_or(RouteRuntimeErrorV1::InvalidConfiguration)?;
        if bound_ms == 0 || bound_ms > safe_ceiling {
            return Err(RouteRuntimeErrorV1::InvalidConfiguration);
        }
        self.supervisor.renew()?;
        Ok(())
    }

    /// Returns the existing fail-closed shutdown decision without consuming a
    /// driver step. Composite loops must use this instead of treating an OS
    /// shutdown request as unconditional permission to abandon the route.
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "retained surface not yet wired by the stage-7 composition root"
        )
    )]
    pub(crate) fn composite_shutdown_is_safe(&self) -> Result<bool, RouteRuntimeErrorV1> {
        let snapshot = self.supervisor.snapshot()?;
        self.shutdown_is_safe(&snapshot)
    }

    fn drive_step(&mut self) -> Result<RouteDriveReportV1, RouteRuntimeErrorV1> {
        let authorities = &mut self.authorities;
        let mut driver_authorities = RouteDriverAuthoritiesV1 {
            refund: &mut authorities.refund,
            action: &mut authorities.action,
            observer: &mut authorities.observer,
            runner: &mut authorities.runner,
            external_custody: &mut authorities.custody,
            timers: &mut authorities.timers,
            reconciler: &mut authorities.reconciler,
        };
        Ok(drive_route_once_v1(
            &mut self.supervisor,
            &self.admission,
            &mut driver_authorities,
        )?)
    }

    /// Runs continuously until terminal state or a safe coordinated shutdown.
    pub fn run<Ctl: RouteRunControlV1>(
        &mut self,
        control: &mut Ctl,
    ) -> Result<RouteRuntimeExitV1, RouteRuntimeErrorV1> {
        self.run_inner(control, None)
    }

    /// Executes at most `step_budget` driver calls.
    ///
    /// This is useful for watchdogs and deterministic tests. Exhaustion does
    /// not change route state beyond the already completed durable steps.
    pub fn run_bounded<Ctl: RouteRunControlV1>(
        &mut self,
        control: &mut Ctl,
        step_budget: u64,
    ) -> Result<RouteRuntimeExitV1, RouteRuntimeErrorV1> {
        if step_budget == 0 || step_budget > MAX_ROUTE_RUNTIME_STEP_BUDGET_V1 {
            return Err(RouteRuntimeErrorV1::InvalidConfiguration);
        }
        self.run_inner(control, Some(step_budget))
    }

    fn run_inner<Ctl: RouteRunControlV1>(
        &mut self,
        control: &mut Ctl,
        step_budget: Option<u64>,
    ) -> Result<RouteRuntimeExitV1, RouteRuntimeErrorV1> {
        let mut steps = 0u64;
        loop {
            let before = self.supervisor.snapshot()?;
            if before.coordination == CoordinationPhaseV1::Terminal {
                return self.finish_terminal(before, steps);
            }
            if control.shutdown_requested()? && self.shutdown_is_safe(&before)? {
                return Ok(RouteRuntimeExitV1::SafeShutdown {
                    revision: before.revision,
                    steps,
                });
            }
            if step_budget.is_some_and(|budget| steps >= budget) {
                return Ok(RouteRuntimeExitV1::StepBudgetExhausted {
                    revision: before.revision,
                    steps,
                });
            }

            let report = self.drive_step()?;
            steps = steps
                .checked_add(1)
                .ok_or(RouteRuntimeErrorV1::InvalidConfiguration)?;
            control.record_progress(report)?;
            let after = self.supervisor.snapshot()?;
            if report.disposition == RouteDriveDispositionV1::Terminal
                || after.coordination == CoordinationPhaseV1::Terminal
            {
                return self.finish_terminal(after, steps);
            }
            if control.shutdown_requested()? && self.shutdown_is_safe(&after)? {
                return Ok(RouteRuntimeExitV1::SafeShutdown {
                    revision: after.revision,
                    steps,
                });
            }

            let wait_ms = match report.disposition {
                RouteDriveDispositionV1::Progressed => None,
                RouteDriveDispositionV1::Waiting => Some(self.config.waiting_backoff_ms),
                RouteDriveDispositionV1::RecoveryRequired => Some(self.config.recovery_backoff_ms),
                RouteDriveDispositionV1::Terminal => unreachable!("handled above"),
            };
            if let Some(wait_ms) = wait_ms {
                // A fresh full lease is committed before the process blocks.
                // Config validation guarantees the wait cannot consume its
                // safe renewal window.
                self.supervisor.renew()?;
                control.wait(Duration::from_millis(wait_ms))?;
            }
        }
    }

    fn finish_terminal(
        &mut self,
        snapshot: RouteSnapshotV1,
        steps: u64,
    ) -> Result<RouteRuntimeExitV1, RouteRuntimeErrorV1> {
        self.retire_public_terminal(&snapshot)?;
        Ok(RouteRuntimeExitV1::Terminal {
            revision: snapshot.revision,
            steps,
        })
    }

    fn retire_public_terminal(
        &mut self,
        snapshot: &RouteSnapshotV1,
    ) -> Result<(), RouteRuntimeErrorV1> {
        if matches!(
            &snapshot.secret_visibility,
            SecretVisibilityV1::Public { .. }
        ) {
            let capability = self.supervisor.mint_route_secret_retirement_capability()?;
            self.authorities
                .retirement
                .retire_route_secret(capability)
                .map_err(RouteRuntimeErrorV1::SecretRetirement)?;
        }
        Ok(())
    }

    fn shutdown_is_safe(&self, snapshot: &RouteSnapshotV1) -> Result<bool, RouteRuntimeErrorV1> {
        if snapshot.coordination == CoordinationPhaseV1::Terminal {
            return Ok(true);
        }
        if snapshot.secret_public_but_upstream_unclaimed() || snapshot.has_open_funds() {
            return Ok(false);
        }
        Ok(self.supervisor.pending_effect_count()? == 0)
    }
}
