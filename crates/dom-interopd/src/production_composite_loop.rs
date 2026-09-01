//! Bounded composition of the retained Stage-12 Relay graph and route runtime.
//!
//! One owner derives both Noise sessions from the exact Stage-12 wire, chain,
//! identity and Relay database bindings. Every Relay leg step is ordered as
//! durable outbound submission, authenticated bounded network exchange, then
//! inbound polling with fresh wall time. F6 activation and the route driver are
//! interleaved without reopening a Store, Relay, identity or network client.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use kaystra_core::types::TimelockSpec;
use route_executor::LegIdV1;

use crate::production_contracts::ProductionContractsPollErrorV1;
use crate::production_f6::terminal_release::ProductionRouteStoreRuntimeAuthorityV2;
use crate::production_f6_activation::ProductionF6PairRuntimeReceiverV2;
use crate::production_f6_lifecycle::{
    ProductionF6ActivationRefusalV2, ProductionF6LifecycleErrorV2,
};
use crate::production_noise_relay::{
    ProductionNoiseRelayDatabasePairV1, ProductionNoiseRelayErrorV1,
    ProductionNoiseRelayExchangeReportV1, ProductionNoiseRelayRouteContextV1,
    ProductionNoiseRelaySessionV1,
};
use crate::production_relay_network_config::{
    ProductionRelayLinkPositionV1, ProductionRelayNetworkConfigErrorV1,
    ProductionRelayNetworkConfigV1, ProductionRelayNetworkLinkV1,
};
use crate::production_relay_network_runtime::{
    ProductionRelayNetworkBoundsV1, ProductionRelayNetworkRuntimeErrorV1,
    ProductionRelayNetworkRuntimeV1,
};
use crate::production_relay_stage12::ProductionRelayStage12OwnerV1;
use crate::relay_worker::{
    RelayInboundPollReportV1, RelayOutboundStepV1, RelayWorkerInboundErrorV1,
    RelayWorkerOutboundErrorV1,
};
use crate::{
    ChainObservationAuthority, Clock, ExternalCustodyAuthority, ProductionRouteRuntimeV1,
    RefundArmingAuthority, RouteActionAuthority, RouteDriveDispositionV1, RouteDriveReportV1,
    RouteRunControlErrorV1, RouteRunControlV1, RouteRuntimeErrorV1, RouteSecretRetirementAuthority,
    RunnerActionAuthority, TakeoverReconciliationAuthority, TimerAuthority,
};

const MIN_SOCKET_BOUND_V1: Duration = Duration::from_millis(25);
const MIN_EXCHANGE_BOUND_V1: Duration = Duration::from_millis(100);
const MAX_COMPOSITE_BLOCKING_BOUND_V1: Duration = Duration::from_secs(30);
const MIN_BACKOFF_V1: Duration = Duration::from_millis(1);
const MAX_ACTIVATION_ROUNDS_V1: u64 = 1_000_000;
const MAX_INTERLEAVED_ROUNDS_V1: u64 = 1_000_000;

/// Fixed blocking and retry bounds for one composite owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ProductionCompositeLoopConfigV1 {
    network: ProductionRelayNetworkRuntimeV1,
    exchange_timeout: Duration,
    backoff: Duration,
    activation_round_budget: u64,
}

impl ProductionCompositeLoopConfigV1 {
    pub(crate) fn new(
        connect_timeout: Duration,
        accept_timeout: Duration,
        exchange_timeout: Duration,
        backoff: Duration,
        activation_round_budget: u64,
    ) -> Result<Self, ProductionCompositeLoopErrorV1> {
        if !(MIN_SOCKET_BOUND_V1..=MAX_COMPOSITE_BLOCKING_BOUND_V1).contains(&connect_timeout)
            || !(MIN_SOCKET_BOUND_V1..=MAX_COMPOSITE_BLOCKING_BOUND_V1).contains(&accept_timeout)
            || !(MIN_EXCHANGE_BOUND_V1..=MAX_COMPOSITE_BLOCKING_BOUND_V1)
                .contains(&exchange_timeout)
            || !(MIN_BACKOFF_V1..=MAX_COMPOSITE_BLOCKING_BOUND_V1).contains(&backoff)
            || activation_round_budget == 0
            || activation_round_budget > MAX_ACTIVATION_ROUNDS_V1
        {
            return Err(ProductionCompositeLoopErrorV1::InvalidConfiguration);
        }
        // The combined worst-case blocking window per leg must stay within the
        // composite bound even though the loop takes its per-call bounds from
        // the network runtime below.
        connect_timeout
            .max(accept_timeout)
            .checked_add(exchange_timeout)
            .filter(|bound| *bound <= MAX_COMPOSITE_BLOCKING_BOUND_V1)
            .ok_or(ProductionCompositeLoopErrorV1::InvalidConfiguration)?;
        let bounds = ProductionRelayNetworkBoundsV1::new(connect_timeout, accept_timeout)
            .map_err(|_| ProductionCompositeLoopErrorV1::InvalidConfiguration)?;
        Ok(Self {
            network: ProductionRelayNetworkRuntimeV1::new(bounds),
            exchange_timeout,
            backoff,
            activation_round_budget,
        })
    }
}

/// Redacted failure from composite activation or interleaved execution.
#[derive(Debug, thiserror::Error)]
pub(crate) enum ProductionCompositeLoopErrorV1 {
    #[error("production composite loop configuration is invalid")]
    InvalidConfiguration,
    #[error("production composite wall clock is unavailable")]
    ClockUnavailable,
    #[error("production composite outbound Relay step failed")]
    Outbound(#[source] RelayWorkerOutboundErrorV1),
    #[error("production composite authenticated Relay exchange failed")]
    Network(#[source] ProductionRelayNetworkRuntimeErrorV1),
    #[error("production composite inbound Relay step failed")]
    Inbound(#[source] ProductionContractsPollErrorV1<ProductionF6LifecycleErrorV2>),
    #[error("production composite F6 activation failed")]
    Activation(#[source] ProductionF6ActivationRefusalV2),
    #[error("production composite route runtime failed")]
    Route(#[source] RouteRuntimeErrorV1),
    #[error("production composite shutdown/backoff control failed")]
    Control(#[source] RouteRunControlErrorV1),
}

/// Secret-free report for one exact leg cycle.
pub(crate) struct ProductionCompositeRelayStepReportV1 {
    pub(crate) leg: LegIdV1,
    pub(crate) outbound: RelayOutboundStepV1,
    pub(crate) exchange: ProductionNoiseRelayExchangeReportV1,
    pub(crate) inbound: RelayInboundPollReportV1,
}

impl core::fmt::Debug for ProductionCompositeRelayStepReportV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("ProductionCompositeRelayStepReportV1")
            .field("leg", &self.leg)
            .field("outbound", &self.outbound)
            .field("exchange", &self.exchange)
            .field("inbound", &self.inbound)
            .finish()
    }
}

/// Sole retained Stage-12 owner plus its two exact Noise sessions.
pub(crate) struct ProductionCompositeRelayLoopV1 {
    owner: ProductionRelayStage12OwnerV1,
    network_config: ProductionRelayNetworkConfigV1,
    network: ProductionRelayNetworkRuntimeV1,
    sessions: [ProductionNoiseRelaySessionV1; 2],
    backoff: Duration,
    last_relay_time_seconds: u64,
}

impl core::fmt::Debug for ProductionCompositeRelayLoopV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("ProductionCompositeRelayLoopV1([authorities redacted])")
    }
}

impl ProductionCompositeRelayLoopV1 {
    fn compose(
        owner: ProductionRelayStage12OwnerV1,
        receiver: &ProductionF6PairRuntimeReceiverV2,
        network_config: ProductionRelayNetworkConfigV1,
        config: ProductionCompositeLoopConfigV1,
    ) -> Result<Self, ProductionCompositeLoopErrorV1> {
        if !owner.matches_f6_pair_receiver(receiver) {
            return Err(ProductionCompositeLoopErrorV1::InvalidConfiguration);
        }
        let local_database = owner.relay().database_id();
        network_config
            .validate_local_database_id(local_database)
            .map_err(map_network_config_error)?;
        let upstream = derive_noise_session(
            &owner,
            LegIdV1::Upstream,
            network_config.link(ProductionRelayLinkPositionV1::Upstream),
            local_database,
            config.exchange_timeout,
        )?;
        let downstream = derive_noise_session(
            &owner,
            LegIdV1::Downstream,
            network_config.link(ProductionRelayLinkPositionV1::Downstream),
            local_database,
            config.exchange_timeout,
        )?;
        let last_relay_time_seconds = owner
            .retained_relay_timestamp_floor()
            .map_err(|_| ProductionCompositeLoopErrorV1::ClockUnavailable)?;
        Ok(Self {
            owner,
            network_config,
            network: config.network,
            sessions: [upstream, downstream],
            backoff: config.backoff,

            last_relay_time_seconds,
        })
    }

    /// Executes exactly one submit/exchange/poll cycle for one named leg.
    pub(crate) fn step_leg(
        &mut self,
        leg: LegIdV1,
    ) -> Result<ProductionCompositeRelayStepReportV1, ProductionCompositeLoopErrorV1> {
        let outbound = match leg {
            LegIdV1::Upstream => {
                let (contracts, relay) = self.owner.upstream_and_relay_mut();
                contracts
                    .submit_outbound_once(relay)
                    .map_err(ProductionCompositeLoopErrorV1::Outbound)?
            }
            LegIdV1::Downstream => {
                let (contracts, relay) = self.owner.downstream_and_relay_mut();
                contracts
                    .submit_outbound_once(relay)
                    .map_err(ProductionCompositeLoopErrorV1::Outbound)?
            }
        };

        let position = relay_position(leg);
        let session_index = relay_index(leg);
        let exchange = {
            let link = self.network_config.link(position);
            let session = &self.sessions[session_index];
            let (identity, relay) = self.owner.identity_and_relay_mut();
            self.network
                .exchange_configured_link(link, session, identity, relay)
                .map_err(ProductionCompositeLoopErrorV1::Network)?
        };

        // Poll time is sampled only after the potentially blocking network
        // exchange; a stale timestamp can never be reused across legs.
        let now = self.fresh_relay_time()?;
        let inbound = match leg {
            LegIdV1::Upstream => {
                let (contracts, relay) = self.owner.upstream_and_relay_mut();
                contracts
                    .poll_inbound(relay, now)
                    .map_err(ProductionCompositeLoopErrorV1::Inbound)?
            }
            LegIdV1::Downstream => {
                let (contracts, relay) = self.owner.downstream_and_relay_mut();
                contracts
                    .poll_inbound(relay, now)
                    .map_err(ProductionCompositeLoopErrorV1::Inbound)?
            }
        };
        Ok(ProductionCompositeRelayStepReportV1 {
            leg,
            outbound,
            exchange,
            inbound,
        })
    }

    fn fresh_relay_time(&mut self) -> Result<TimelockSpec, ProductionCompositeLoopErrorV1> {
        let current = host_time_seconds()?;
        let durable_floor = self
            .owner
            .retained_relay_timestamp_floor()
            .map_err(|_| ProductionCompositeLoopErrorV1::ClockUnavailable)?;
        let accepted =
            validate_nonregressing_time(current, durable_floor, self.last_relay_time_seconds)?;
        self.last_relay_time_seconds = accepted;
        Ok(TimelockSpec::TimestampSeconds { value: accepted })
    }
}

/// Owner of the pre-runtime Relay/F6 activation phase.
pub(crate) struct ProductionCompositeActivationV1 {
    relay: ProductionCompositeRelayLoopV1,
    receiver: ProductionF6PairRuntimeReceiverV2,
    round_budget: u64,
}

impl core::fmt::Debug for ProductionCompositeActivationV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("ProductionCompositeActivationV1([authorities redacted])")
    }
}

/// Bounded activation outcome that never discards the retained Relay owner on
/// shutdown or budget exhaustion.
pub(crate) enum ProductionCompositeActivationExitV1 {
    Ready {
        relay: ProductionCompositeRelayLoopV1,
        route_store: ProductionRouteStoreRuntimeAuthorityV2,
    },
    #[expect(dead_code, reason = "retains the Relay owner across a non-ready exit")]
    Shutdown(ProductionCompositeActivationV1),
    RoundBudgetExhausted(ProductionCompositeActivationV1),
    Failed {
        #[expect(dead_code, reason = "retains the Relay owner across a non-ready exit")]
        activation: ProductionCompositeActivationV1,
        #[cfg_attr(
            not(test),
            expect(dead_code, reason = "retains the Relay owner across a non-ready exit")
        )]
        error: ProductionCompositeLoopErrorV1,
    },
}

impl core::fmt::Debug for ProductionCompositeActivationExitV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Ready { .. } => formatter.write_str("ProductionCompositeActivationExitV1::Ready"),
            Self::Shutdown(_) => {
                formatter.write_str("ProductionCompositeActivationExitV1::Shutdown")
            }
            Self::RoundBudgetExhausted(_) => {
                formatter.write_str("ProductionCompositeActivationExitV1::RoundBudgetExhausted")
            }
            Self::Failed { .. } => {
                formatter.write_str("ProductionCompositeActivationExitV1::Failed")
            }
        }
    }
}

trait CompositeActivationRelayV1 {
    type Error;

    fn step_activation_leg(&mut self, leg: LegIdV1) -> Result<(), Self::Error>;
    fn activation_backoff(&self) -> Duration;
}

impl CompositeActivationRelayV1 for ProductionCompositeRelayLoopV1 {
    type Error = ProductionCompositeLoopErrorV1;

    fn step_activation_leg(&mut self, leg: LegIdV1) -> Result<(), Self::Error> {
        match self.step_leg(leg) {
            Ok(_) => Ok(()),
            Err(error) if is_f6_activation_awaiting(&error) => Ok(()),
            Err(error) => Err(error),
        }
    }

    fn activation_backoff(&self) -> Duration {
        self.backoff
    }
}

trait CompositeActivationReceiverV1 {
    type Ready;
    type Error;

    fn take_activation_ready(&mut self) -> Result<Option<Self::Ready>, Self::Error>;
}

impl CompositeActivationReceiverV1 for ProductionF6PairRuntimeReceiverV2 {
    type Ready = ProductionRouteStoreRuntimeAuthorityV2;
    type Error = ProductionF6ActivationRefusalV2;

    fn take_activation_ready(&mut self) -> Result<Option<Self::Ready>, Self::Error> {
        match self.take_ready() {
            Ok(ready) => Ok(Some(ready)),
            Err(
                ProductionF6ActivationRefusalV2::Awaiting(_)
                | ProductionF6ActivationRefusalV2::Unavailable,
            ) => Ok(None),
            Err(error) => Err(error),
        }
    }
}

enum CompositeActivationCoreExitV1<Ready> {
    Ready(Ready),
    Shutdown,
    RoundBudgetExhausted,
}

#[derive(Debug)]
enum CompositeActivationCoreErrorV1<RelayError, ReceiverError> {
    Relay(RelayError),
    Receiver(ReceiverError),
    Control(RouteRunControlErrorV1),
    InvalidConfiguration,
}

type CompositeActivationCoreResultV1<Relay, Receiver> = Result<
    CompositeActivationCoreExitV1<<Receiver as CompositeActivationReceiverV1>::Ready>,
    CompositeActivationCoreErrorV1<
        <Relay as CompositeActivationRelayV1>::Error,
        <Receiver as CompositeActivationReceiverV1>::Error,
    >,
>;

fn run_activation_core_v1<Relay, Receiver, Ctl>(
    relay: &mut Relay,
    receiver: &mut Receiver,
    control: &mut Ctl,
    round_budget: u64,
) -> CompositeActivationCoreResultV1<Relay, Receiver>
where
    Relay: CompositeActivationRelayV1,
    Receiver: CompositeActivationReceiverV1,
    Ctl: RouteRunControlV1,
{
    if round_budget == 0 || round_budget > MAX_ACTIVATION_ROUNDS_V1 {
        return Err(CompositeActivationCoreErrorV1::InvalidConfiguration);
    }
    for _ in 0..round_budget {
        if control
            .shutdown_requested()
            .map_err(CompositeActivationCoreErrorV1::Control)?
        {
            return Ok(CompositeActivationCoreExitV1::Shutdown);
        }
        relay
            .step_activation_leg(LegIdV1::Upstream)
            .map_err(CompositeActivationCoreErrorV1::Relay)?;
        relay
            .step_activation_leg(LegIdV1::Downstream)
            .map_err(CompositeActivationCoreErrorV1::Relay)?;
        if let Some(ready) = receiver
            .take_activation_ready()
            .map_err(CompositeActivationCoreErrorV1::Receiver)?
        {
            return Ok(CompositeActivationCoreExitV1::Ready(ready));
        }
        control
            .wait(relay.activation_backoff())
            .map_err(CompositeActivationCoreErrorV1::Control)?;
    }
    Ok(CompositeActivationCoreExitV1::RoundBudgetExhausted)
}

impl ProductionCompositeActivationV1 {
    pub(crate) fn new(
        owner: ProductionRelayStage12OwnerV1,
        receiver: ProductionF6PairRuntimeReceiverV2,
        network_config: ProductionRelayNetworkConfigV1,
        config: ProductionCompositeLoopConfigV1,
    ) -> Result<Self, ProductionCompositeLoopErrorV1> {
        Ok(Self {
            relay: ProductionCompositeRelayLoopV1::compose(
                owner,
                &receiver,
                network_config,
                config,
            )?,
            receiver,
            round_budget: config.activation_round_budget,
        })
    }

    /// Drives both legs until the exact pair receiver releases the route Store.
    /// `Ready` is constructed only from a successful `take_ready()` call.
    pub(crate) fn activate_bounded<Ctl: RouteRunControlV1>(
        mut self,
        control: &mut Ctl,
    ) -> ProductionCompositeActivationExitV1 {
        let outcome = match run_activation_core_v1(
            &mut self.relay,
            &mut self.receiver,
            control,
            self.round_budget,
        )
        .map_err(|error| match error {
            CompositeActivationCoreErrorV1::Relay(error) => error,
            CompositeActivationCoreErrorV1::Receiver(error) => {
                ProductionCompositeLoopErrorV1::Activation(error)
            }
            CompositeActivationCoreErrorV1::Control(error) => {
                ProductionCompositeLoopErrorV1::Control(error)
            }
            CompositeActivationCoreErrorV1::InvalidConfiguration => {
                ProductionCompositeLoopErrorV1::InvalidConfiguration
            }
        }) {
            Ok(outcome) => outcome,
            Err(error) => {
                return ProductionCompositeActivationExitV1::Failed {
                    activation: self,
                    error,
                };
            }
        };
        match outcome {
            CompositeActivationCoreExitV1::Ready(route_store) => {
                ProductionCompositeActivationExitV1::Ready {
                    relay: self.relay,
                    route_store,
                }
            }
            CompositeActivationCoreExitV1::Shutdown => {
                ProductionCompositeActivationExitV1::Shutdown(self)
            }
            CompositeActivationCoreExitV1::RoundBudgetExhausted => {
                ProductionCompositeActivationExitV1::RoundBudgetExhausted(self)
            }
        }
    }
}

/// Secret-free exit of one bounded Relay/route interleaving invocation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ProductionCompositeRuntimeExitV1 {
    Shutdown {
        rounds: u64,
    },
    Terminal {
        rounds: u64,
        report: RouteDriveReportV1,
    },
    RoundBudgetExhausted {
        rounds: u64,
    },
}

trait CompositeRelayCycleV1 {
    type Error;

    fn step_relay_leg(&mut self, leg: LegIdV1) -> Result<(), Self::Error>;
    fn backoff(&self) -> Duration;
}

impl CompositeRelayCycleV1 for ProductionCompositeRelayLoopV1 {
    type Error = ProductionCompositeLoopErrorV1;

    fn step_relay_leg(&mut self, leg: LegIdV1) -> Result<(), Self::Error> {
        self.step_leg(leg).map(|_| ())
    }

    fn backoff(&self) -> Duration {
        self.backoff
    }
}

trait CompositeRouteCycleV1 {
    type Error;

    fn step_route(&mut self) -> Result<RouteDriveReportV1, Self::Error>;
}

impl<C, F, A, O, R, E, T, X, Y> CompositeRouteCycleV1
    for ProductionRouteRuntimeV1<C, F, A, O, R, E, T, X, Y>
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
    type Error = RouteRuntimeErrorV1;

    fn step_route(&mut self) -> Result<RouteDriveReportV1, Self::Error> {
        self.step()
    }
}

#[derive(Debug)]
enum CompositeCoreErrorV1<RelayError, RouteError> {
    Relay(RelayError),
    Route(RouteError),
    Control(RouteRunControlErrorV1),
    InvalidConfiguration,
}

fn run_interleaved_core_v1<Relay, Route, Ctl>(
    relay: &mut Relay,
    route: &mut Route,
    control: &mut Ctl,
    round_budget: u64,
) -> Result<ProductionCompositeRuntimeExitV1, CompositeCoreErrorV1<Relay::Error, Route::Error>>
where
    Relay: CompositeRelayCycleV1,
    Route: CompositeRouteCycleV1,
    Ctl: RouteRunControlV1,
{
    if round_budget == 0 || round_budget > MAX_INTERLEAVED_ROUNDS_V1 {
        return Err(CompositeCoreErrorV1::InvalidConfiguration);
    }
    let mut rounds = 0_u64;
    while rounds < round_budget {
        if control
            .shutdown_requested()
            .map_err(CompositeCoreErrorV1::Control)?
        {
            return Ok(ProductionCompositeRuntimeExitV1::Shutdown { rounds });
        }
        relay
            .step_relay_leg(LegIdV1::Upstream)
            .map_err(CompositeCoreErrorV1::Relay)?;
        relay
            .step_relay_leg(LegIdV1::Downstream)
            .map_err(CompositeCoreErrorV1::Relay)?;
        let report = route.step_route().map_err(CompositeCoreErrorV1::Route)?;
        rounds = rounds
            .checked_add(1)
            .ok_or(CompositeCoreErrorV1::InvalidConfiguration)?;
        control
            .record_progress(report)
            .map_err(CompositeCoreErrorV1::Control)?;
        if report.disposition == RouteDriveDispositionV1::Terminal {
            return Ok(ProductionCompositeRuntimeExitV1::Terminal { rounds, report });
        }
        if matches!(
            report.disposition,
            RouteDriveDispositionV1::Waiting | RouteDriveDispositionV1::RecoveryRequired
        ) {
            control
                .wait(relay.backoff())
                .map_err(CompositeCoreErrorV1::Control)?;
        }
    }
    Ok(ProductionCompositeRuntimeExitV1::RoundBudgetExhausted { rounds })
}

/// Interleaves exactly one upstream Relay step, one downstream Relay step and
/// one concrete route-runtime step per round.
pub(crate) fn run_production_composite_runtime_bounded_v1<C, F, A, O, R, E, T, X, Y, Ctl>(
    relay: &mut ProductionCompositeRelayLoopV1,
    route: &mut ProductionRouteRuntimeV1<C, F, A, O, R, E, T, X, Y>,
    control: &mut Ctl,
    round_budget: u64,
) -> Result<ProductionCompositeRuntimeExitV1, ProductionCompositeLoopErrorV1>
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
    Ctl: RouteRunControlV1,
{
    run_interleaved_core_v1(relay, route, control, round_budget).map_err(|error| match error {
        CompositeCoreErrorV1::Relay(error) => error,
        CompositeCoreErrorV1::Route(error) => ProductionCompositeLoopErrorV1::Route(error),
        CompositeCoreErrorV1::Control(error) => ProductionCompositeLoopErrorV1::Control(error),
        CompositeCoreErrorV1::InvalidConfiguration => {
            ProductionCompositeLoopErrorV1::InvalidConfiguration
        }
    })
}

fn derive_noise_session(
    owner: &ProductionRelayStage12OwnerV1,
    leg: LegIdV1,
    link: &ProductionRelayNetworkLinkV1,
    local_database: relay::production::RelayDatabaseIdV1,
    exchange_timeout: Duration,
) -> Result<ProductionNoiseRelaySessionV1, ProductionCompositeLoopErrorV1> {
    let retained = owner.leg(leg);
    let wire = retained.wire();
    let chain_id = *retained.trusted_chain_id().as_bytes();
    let context = ProductionNoiseRelayRouteContextV1::new(
        chain_id,
        wire.network_id,
        wire.route_id,
        wire.session_id,
    )
    .map_err(map_noise_error)?;
    let databases =
        ProductionNoiseRelayDatabasePairV1::new(local_database, link.remote_relay_database_id())
            .map_err(map_noise_error)?;
    ProductionNoiseRelaySessionV1::new(
        link.noise_role(),
        context,
        retained.noise_identity_references().clone(),
        databases,
        exchange_timeout,
    )
    .map_err(map_noise_error)
}

fn host_time_seconds() -> Result<u64, ProductionCompositeLoopErrorV1> {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| ProductionCompositeLoopErrorV1::ClockUnavailable)?
        .as_secs();
    if seconds == 0 {
        return Err(ProductionCompositeLoopErrorV1::ClockUnavailable);
    }
    Ok(seconds)
}

fn validate_nonregressing_time(
    current: u64,
    durable_floor: u64,
    process_floor: u64,
) -> Result<u64, ProductionCompositeLoopErrorV1> {
    if current == 0 || current < durable_floor || current < process_floor {
        return Err(ProductionCompositeLoopErrorV1::ClockUnavailable);
    }
    Ok(current)
}

const fn relay_position(leg: LegIdV1) -> ProductionRelayLinkPositionV1 {
    match leg {
        LegIdV1::Upstream => ProductionRelayLinkPositionV1::Upstream,
        LegIdV1::Downstream => ProductionRelayLinkPositionV1::Downstream,
    }
}

const fn relay_index(leg: LegIdV1) -> usize {
    match leg {
        LegIdV1::Upstream => 0,
        LegIdV1::Downstream => 1,
    }
}

fn map_network_config_error(
    _error: ProductionRelayNetworkConfigErrorV1,
) -> ProductionCompositeLoopErrorV1 {
    ProductionCompositeLoopErrorV1::InvalidConfiguration
}

fn map_noise_error(_error: ProductionNoiseRelayErrorV1) -> ProductionCompositeLoopErrorV1 {
    ProductionCompositeLoopErrorV1::InvalidConfiguration
}

fn is_f6_activation_awaiting(error: &ProductionCompositeLoopErrorV1) -> bool {
    matches!(
        error,
        ProductionCompositeLoopErrorV1::Inbound(ProductionContractsPollErrorV1::Worker(
            RelayWorkerInboundErrorV1::F6(route_transport::F6DispatchErrorV1::F6(
                ProductionF6LifecycleErrorV2::Awaiting(_),
            )),
        ))
    )
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::rc::Rc;

    use rfq::v2::SettlementPositionV2;

    use crate::production_f6_lifecycle::ProductionPendingAuthorityV1;
    use crate::{RouteDriveStageV1, RouteRunControlErrorV1};

    use super::*;

    #[derive(Default)]
    struct TestRelayV1 {
        log: Rc<RefCell<Vec<&'static str>>>,
        backoff: Duration,
    }

    impl CompositeRelayCycleV1 for TestRelayV1 {
        type Error = ();

        fn step_relay_leg(&mut self, leg: LegIdV1) -> Result<(), Self::Error> {
            self.log.borrow_mut().push(match leg {
                LegIdV1::Upstream => "upstream-relay",
                LegIdV1::Downstream => "downstream-relay",
            });
            Ok(())
        }

        fn backoff(&self) -> Duration {
            self.backoff
        }
    }

    impl CompositeActivationRelayV1 for TestRelayV1 {
        type Error = ();

        fn step_activation_leg(&mut self, leg: LegIdV1) -> Result<(), Self::Error> {
            self.step_relay_leg(leg)
        }

        fn activation_backoff(&self) -> Duration {
            self.backoff
        }
    }

    struct TestActivationReceiverV1 {
        calls: u64,
        ready_on_call: u64,
    }

    impl CompositeActivationReceiverV1 for TestActivationReceiverV1 {
        type Ready = u8;
        type Error = ();

        fn take_activation_ready(&mut self) -> Result<Option<Self::Ready>, Self::Error> {
            self.calls += 1;
            Ok((self.calls == self.ready_on_call).then_some(7))
        }
    }

    struct TestRouteV1 {
        log: Rc<RefCell<Vec<&'static str>>>,
        reports: Vec<RouteDriveReportV1>,
    }

    impl CompositeRouteCycleV1 for TestRouteV1 {
        type Error = ();

        fn step_route(&mut self) -> Result<RouteDriveReportV1, Self::Error> {
            self.log.borrow_mut().push("route-step");
            Ok(self.reports.remove(0))
        }
    }

    #[derive(Default)]
    struct TestControlV1 {
        shutdown: bool,
        waits: Vec<Duration>,
        progress: Vec<RouteDriveReportV1>,
    }

    impl RouteRunControlV1 for TestControlV1 {
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
            self.progress.push(report);
            Ok(())
        }
    }

    fn report(disposition: RouteDriveDispositionV1, revision: u64) -> RouteDriveReportV1 {
        RouteDriveReportV1 {
            stage: RouteDriveStageV1::Admission,
            before_revision: revision,
            after_revision: revision + 1,
            disposition,
        }
    }

    #[test]
    fn interleaving_is_upstream_downstream_then_exactly_one_route_step() {
        let log = Rc::new(RefCell::new(Vec::new()));
        let mut relay = TestRelayV1 {
            log: Rc::clone(&log),
            backoff: Duration::from_millis(7),
        };
        let mut route = TestRouteV1 {
            log: Rc::clone(&log),
            reports: vec![
                report(RouteDriveDispositionV1::Progressed, 1),
                report(RouteDriveDispositionV1::Progressed, 2),
            ],
        };
        let mut control = TestControlV1::default();
        assert_eq!(
            run_interleaved_core_v1(&mut relay, &mut route, &mut control, 2)
                .expect("bounded schedule"),
            ProductionCompositeRuntimeExitV1::RoundBudgetExhausted { rounds: 2 }
        );
        assert_eq!(
            log.borrow().as_slice(),
            [
                "upstream-relay",
                "downstream-relay",
                "route-step",
                "upstream-relay",
                "downstream-relay",
                "route-step"
            ]
        );
        assert_eq!(control.progress.len(), 2);
        assert!(control.waits.is_empty());
    }

    #[test]
    fn activation_releases_ready_only_after_both_legs_and_receiver_gate() {
        let log = Rc::new(RefCell::new(Vec::new()));
        let backoff = Duration::from_millis(11);
        let mut relay = TestRelayV1 {
            log: Rc::clone(&log),
            backoff,
        };
        let mut receiver = TestActivationReceiverV1 {
            calls: 0,
            ready_on_call: 2,
        };
        let mut control = TestControlV1::default();
        match run_activation_core_v1(&mut relay, &mut receiver, &mut control, 3)
            .expect("activation schedule")
        {
            CompositeActivationCoreExitV1::Ready(value) => assert_eq!(value, 7),
            CompositeActivationCoreExitV1::Shutdown
            | CompositeActivationCoreExitV1::RoundBudgetExhausted => panic!("not ready"),
        }
        assert_eq!(
            log.borrow().as_slice(),
            [
                "upstream-relay",
                "downstream-relay",
                "upstream-relay",
                "downstream-relay"
            ]
        );
        assert_eq!(receiver.calls, 2);
        assert_eq!(control.waits, vec![backoff]);
    }

    #[test]
    fn only_exact_f6_awaiting_error_is_retryable_during_pair_activation() {
        let awaiting = ProductionCompositeLoopErrorV1::Inbound(
            ProductionContractsPollErrorV1::Worker(RelayWorkerInboundErrorV1::F6(
                route_transport::F6DispatchErrorV1::F6(ProductionF6LifecycleErrorV2::Awaiting(
                    ProductionPendingAuthorityV1::AuthenticatedRfq {
                        position: SettlementPositionV2::Downstream,
                    },
                )),
            )),
        );
        assert!(is_f6_activation_awaiting(&awaiting));
        assert!(!is_f6_activation_awaiting(
            &ProductionCompositeLoopErrorV1::ClockUnavailable
        ));
    }

    #[test]
    fn shutdown_prevents_every_relay_and_route_call() {
        let log = Rc::new(RefCell::new(Vec::new()));
        let mut relay = TestRelayV1 {
            log: Rc::clone(&log),
            backoff: Duration::from_millis(7),
        };
        let mut route = TestRouteV1 {
            log: Rc::clone(&log),
            reports: vec![report(RouteDriveDispositionV1::Progressed, 1)],
        };
        let mut control = TestControlV1 {
            shutdown: true,
            ..TestControlV1::default()
        };
        assert_eq!(
            run_interleaved_core_v1(&mut relay, &mut route, &mut control, 1).expect("shutdown"),
            ProductionCompositeRuntimeExitV1::Shutdown { rounds: 0 }
        );
        assert!(log.borrow().is_empty());
    }

    #[test]
    fn waiting_uses_only_the_bounded_composite_backoff() {
        let log = Rc::new(RefCell::new(Vec::new()));
        let backoff = Duration::from_millis(17);
        let mut relay = TestRelayV1 {
            log: Rc::clone(&log),
            backoff,
        };
        let mut route = TestRouteV1 {
            log,
            reports: vec![report(RouteDriveDispositionV1::Waiting, 1)],
        };
        let mut control = TestControlV1::default();
        let _ = run_interleaved_core_v1(&mut relay, &mut route, &mut control, 1)
            .expect("bounded waiting");
        assert_eq!(control.waits, vec![backoff]);
    }

    #[test]
    fn composite_bounds_reject_zero_and_long_blocking_windows() {
        assert!(ProductionCompositeLoopConfigV1::new(
            Duration::ZERO,
            Duration::from_millis(25),
            Duration::from_millis(100),
            Duration::from_millis(1),
            1,
        )
        .is_err());
        assert!(ProductionCompositeLoopConfigV1::new(
            Duration::from_secs(31),
            Duration::from_millis(25),
            Duration::from_millis(100),
            Duration::from_millis(1),
            1,
        )
        .is_err());
    }

    #[test]
    fn relay_leg_mapping_is_exhaustive_and_stable() {
        assert_eq!(relay_index(LegIdV1::Upstream), 0);
        assert_eq!(relay_index(LegIdV1::Downstream), 1);
        assert_eq!(
            relay_position(LegIdV1::Upstream),
            ProductionRelayLinkPositionV1::Upstream
        );
        assert_eq!(
            relay_position(LegIdV1::Downstream),
            ProductionRelayLinkPositionV1::Downstream
        );
    }
}
