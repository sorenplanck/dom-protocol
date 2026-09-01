//! Durable composition root for DOM interoperability.
//!
//! This crate owns process-level assembly. Protocol reducers, chain adapters,
//! signers and stores remain separate authorities; the daemon coordinates them
//! without obtaining generic signing power or persisting the route scalar.

#![forbid(unsafe_code)]

mod admission;
mod driver;
#[cfg(feature = "production")]
mod production_chain_signers;
#[cfg(feature = "production")]
mod production_child_btc;
#[cfg(feature = "production")]
mod production_child_dom;
#[cfg(feature = "production")]
mod production_child_evidence;
#[cfg(feature = "production")]
mod production_child_evm;
#[cfg(feature = "production")]
mod production_child_router;
#[cfg(feature = "production")]
mod production_child_solana;
#[cfg(feature = "production")]
mod production_child_xmr;
#[cfg(feature = "production")]
mod production_children;
#[cfg(feature = "production")]
pub mod production_f6;
// `config-only` compiles this module for its own codec/golden tests without
// the production graph; it deliberately re-exports nothing (see below), so its
// public items are unused in that build alone.
#[cfg(any(feature = "production", feature = "config-only"))]
mod production_config;
#[cfg(feature = "production")]
pub(crate) mod production_contracts;
#[cfg(feature = "production")]
mod production_inputs;
#[cfg(feature = "production")]
mod production_materializer;
// Shares the `config-only` gate with `production_config`: the codec and its
// bounds compile and are tested without the production graph, while the client
// and credential boundary below stay behind `production`.
#[cfg(any(feature = "production", feature = "config-only"))]
mod production_node;
#[cfg(feature = "production")]
mod production_plan_authority;
#[cfg(feature = "production")]
mod production_plan_source;
#[cfg(feature = "production")]
mod production_provisioning;
#[cfg(feature = "production")]
pub mod production_refund_arming;
#[cfg(feature = "production")]
mod production_role_plan;
#[cfg(feature = "production")]
mod production_run;
#[cfg(feature = "production")]
mod production_service;
#[cfg(feature = "production")]
pub(crate) mod production_settlement;
#[cfg(feature = "production")]
mod production_settlement_runtime;
#[cfg(feature = "production")]
mod production_signal;
#[cfg(feature = "production")]
pub(crate) mod production_time_guard;
#[cfg(feature = "production")]
mod production_timer;
#[cfg(feature = "production")]
mod relay_worker;
mod runtime;
#[cfg(feature = "simulation")]
mod simulation;
mod supervisor;

// The production unit tests share one authenticated route-time fixture. It is
// declared exactly once at the crate root so Clippy's duplicate-module guard
// also guarantees that every consumer exercises the same Rust types/statics.
#[cfg(all(test, feature = "production"))]
#[path = "../../route-time-anchor/tests/common/mod.rs"]
mod route_time_test_common;

pub use admission::{
    AuthenticatedRouteAdmissionV1, AuthenticatedRouteTimeBindingV2,
    RegistryRouteAdmissionAuthorityV1, RouteAdmissionRefusalV1, RouteAdmissionRequestV1,
    RouteLegSelectionV1, RouteRosterSnapshotsV1,
};
pub use driver::{
    drive_route_once_v1, RouteDriveDispositionV1, RouteDriveReportV1, RouteDriveStageV1,
    RouteDriverAuthoritiesV1, RouteDriverErrorV1,
};
#[cfg(feature = "production")]
pub use production_config::{
    load_production_create_bootstrap_v1, load_production_create_bootstrap_v2,
    load_production_create_bootstrap_v3, load_production_reopen_bootstrap_v1,
    load_production_reopen_bootstrap_v2, load_production_reopen_bootstrap_v3,
    ProductionBootstrapConfigV1, ProductionBootstrapModeV1, ProductionConfigErrorV1,
    ProductionPathKindV1, ProductionPathReferencesV1, ProductionPathRoleV1, ProductionRoutePinsV1,
    ProductionRuntimeBoundsV1, ValidatedProductionBootstrapV1, ValidatedProductionLayoutV1,
    MAX_PRODUCTION_BOOTSTRAP_BYTES_V1, MAX_PRODUCTION_RELATIVE_PATH_BYTES_V1,
    PRODUCTION_CREATE_CONFIG_FILE_V1, PRODUCTION_CREATE_CONFIG_FILE_V2,
    PRODUCTION_CREATE_CONFIG_FILE_V3, PRODUCTION_NODE_CONFIG_FILE_V1,
    PRODUCTION_PATH_ROLE_COUNT_V1, PRODUCTION_PATH_ROLE_COUNT_V2, PRODUCTION_PATH_ROLE_COUNT_V3,
    PRODUCTION_REOPEN_CONFIG_FILE_V1, PRODUCTION_REOPEN_CONFIG_FILE_V2,
    PRODUCTION_REOPEN_CONFIG_FILE_V3,
};
#[cfg(feature = "production")]
pub use production_inputs::{
    load_authenticated_production_inputs_v1, AuthenticatedProductionInputsV1,
    ProductionAuthorityBundleV1, ProductionBitcoinLegKeyProofsV1,
    ProductionBitcoinParticipantKeyProofV1, ProductionBitcoinParticipantKeyStatementRequestV1,
    ProductionEvmLegProofsV1, ProductionInputErrorV1, ProductionParticipantBindingBundleV1,
    ProductionRelayRosterBundleV1, ProductionRosterLegV1, ProductionRosterMemberV1,
    ProductionRoutePositionV1, BITCOIN_PARTICIPANT_KEY_PROOF_BYTES_V1,
    MAX_PRODUCTION_AUTHORITY_BUNDLE_BYTES_V1, MAX_PRODUCTION_PARTICIPANT_BUNDLE_BYTES_V1,
    PRODUCTION_ROSTER_BUNDLE_BYTES_V1,
};
#[cfg(feature = "production")]
pub use production_node::{
    load_production_node_config_v1, read_production_secrets_from_stdin, DomNodeEndpointV1,
    ProductionNodeBoundsV1, ProductionNodeConfigV1, ProductionSecretsV1,
    MAX_DOM_NODE_BEARER_BYTES_V1, MAX_DOM_NODE_ENDPOINT_BYTES_V1, MAX_DOM_NODE_NETWORK_BYTES_V1,
    MAX_PRODUCTION_NODE_CONFIG_BYTES_V1,
};
#[cfg(feature = "production")]
pub use production_run::{
    run_production_v1, ProductionRunErrorV1, ProductionRunModeV1, ProductionRunOptionsV1,
    UnavailableRunnerAuthorityV1, MISSING_PRODUCTION_PARTS_V1,
};
#[cfg(feature = "production")]
pub use production_signal::{
    ProductionSignalBridgeErrorV1, ProductionSignalBridgeV1, PRODUCTION_SIGNAL_JOIN_TIMEOUT_V1,
};
#[cfg(feature = "production")]
pub use relay_worker::{
    ContractsRelayIngressErrorV1, ContractsSessionStatusV1, DurableRelayWorkerV1,
    PreparedContractsIngressV1, PreparedRelayOutboundV1, RelayF6MessageKindV1,
    RelayInboundDispatchReportV1, RelayInboundPollReportV1, RelayOutboundStepV1,
    RelayWorkerConfigV1, RelayWorkerInboundErrorV1, RelayWorkerOpenErrorV1,
    RelayWorkerOutboundErrorV1, RelayWorkerPathsV1, UnavailableF6AuthorityErrorV1,
    UnavailableF6AuthorityV1,
};
pub use runtime::{
    ProductionRouteRuntimeV1, RouteRunControlErrorV1, RouteRunControlV1, RouteRuntimeAuthoritiesV1,
    RouteRuntimeConfigV1, RouteRuntimeErrorV1, RouteRuntimeExitV1,
    RouteRuntimeOperationalAuthoritiesV1, RouteRuntimeRecoveryAuthoritiesV1, RouteShutdownTokenV1,
    SystemRouteRunControlV1, MAX_ROUTE_RUNTIME_BACKOFF_MS_V1, MAX_ROUTE_RUNTIME_STEP_BUDGET_V1,
};
#[cfg(feature = "simulation")]
pub use simulation::{
    run_simulation_v1, SimulationCrashPointV1, SimulationErrorV1, SimulationExternalizationV1,
    SimulationOptionsV1, SimulationReportV1, SimulationScenarioV1, SIMULATION_CRASH_EXIT_CODE_V1,
};
pub use supervisor::{
    AcknowledgedCustodyProgressV1, ActionExternalizationReceiptV1, AuthorityRefusalV1,
    ChainObservationAuthority, ChainObservationQueryV1, ChainObservationRequestV1, Clock,
    ClockErrorV1, CustodyDispatchOutcomeV1, ExternalCustodyActionRequestV1,
    ExternalCustodyAuthority, ReconciliationRequestV1, RefundArmingAuthority,
    RefundArmingRequestV1, RouteActionAuthority, RouteActionAuthorizationRequestV1,
    RouteLeaseStatusV1, RouteSecretRetirementAuthority, RouteSupervisorConfigV1,
    RouteSupervisorErrorV1, RouteSupervisorTickReportV1, RouteSupervisorV1, RunnerActionAuthority,
    RunnerActionRequestV1, SignerCapabilityV1, SystemClockV1, TakeoverReconciliationAuthority,
    TakeoverReconciliationOutcomeV1, TakeoverReconciliationReportV1, TimerAuthority,
    TimerDispatchV1, TimerEventCommitV1, VerifiedChainObservationV1,
};

#[cfg(any(feature = "development", feature = "simulation", test))]
pub use supervisor::ManualClockV1;

#[cfg(all(feature = "production", feature = "development"))]
compile_error!("the production and development feature sets are mutually exclusive");
#[cfg(all(feature = "production", feature = "simulation"))]
compile_error!("the production binary cannot contain simulation support");
#[cfg(all(feature = "development", feature = "simulation"))]
compile_error!("the development and simulation feature sets are mutually exclusive");
#[cfg(all(feature = "production", not(target_os = "linux")))]
compile_error!("the production DOM interop authority is currently Linux-only");

use serde::Serialize;

/// Runtime build mode visible in the self-check attestation.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeBuildModeV1 {
    /// Non-operational developer build.
    Development,
    /// Deterministic local simulation build.
    Simulation,
    /// Linux build with the complete production dependency graph.
    Production,
    /// No recognized mode feature was selected.
    Incomplete,
}

/// Machine-readable evidence about the exact daemon artifact.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct BuildAttestationV1 {
    /// Daemon crate version.
    pub version: &'static str,
    /// Source commit observed by the build script.
    pub git_commit: &'static str,
    /// Whether the build script observed any worktree difference.
    pub git_dirty: bool,
    /// BLAKE2b-256 of the exact workspace `Cargo.lock`.
    pub cargo_lock_blake2b256: &'static str,
    /// Rust compilation target triple.
    pub target: &'static str,
    /// Cargo compilation profile.
    pub profile: &'static str,
    /// Selected closed build mode.
    pub mode: RuntimeBuildModeV1,
    /// Whether this is a release-profile Linux production artifact.
    pub operational_artifact: bool,
    /// Whether the real DOM adaptor dependency is selected.
    pub real_dom_adaptor: bool,
    /// Whether EVM HTTP RPC support is selected.
    pub evm_rpc_http: bool,
    /// Whether the concrete Bitcoin Core authority is selected.
    pub bitcoin_core_live: bool,
    /// Whether production durable stores/relay are selected.
    pub durable_authorities: bool,
    /// Simulation/fault surfaces are absent from the production graph.
    pub laboratory_surfaces_absent: bool,
}

/// Startup refusal emitted before any store, signer or network is opened.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum StartupRefusalV1 {
    /// This artifact was not compiled as a release production build.
    #[error("dom-interopd artifact is not production-operational")]
    NonOperationalArtifact,
    /// The self-check JSON encoder failed.
    #[error("self-check serialization failed")]
    SelfCheckEncoding,
}

/// Returns the compile/build provenance of this exact artifact.
pub fn build_attestation_v1() -> BuildAttestationV1 {
    let mode = build_mode();
    let production = mode == RuntimeBuildModeV1::Production;
    let release = !cfg!(debug_assertions) && env!("DOM_INTEROP_BUILD_PROFILE") == "release";
    let linux = cfg!(target_os = "linux");
    BuildAttestationV1 {
        version: env!("CARGO_PKG_VERSION"),
        git_commit: env!("DOM_INTEROP_GIT_COMMIT"),
        git_dirty: env!("DOM_INTEROP_GIT_DIRTY") == "true",
        cargo_lock_blake2b256: env!("DOM_INTEROP_CARGO_LOCK_BLAKE2B256"),
        target: env!("DOM_INTEROP_BUILD_TARGET"),
        profile: env!("DOM_INTEROP_BUILD_PROFILE"),
        mode,
        operational_artifact: production && release && linux,
        real_dom_adaptor: production,
        evm_rpc_http: production,
        bitcoin_core_live: production,
        durable_authorities: production && linux,
        laboratory_surfaces_absent: production && !cfg!(feature = "simulation"),
    }
}

/// Serializes [`build_attestation_v1`] as one stable JSON object.
pub fn self_check_json_v1() -> Result<String, StartupRefusalV1> {
    serde_json::to_string_pretty(&build_attestation_v1())
        .map_err(|_| StartupRefusalV1::SelfCheckEncoding)
}

/// Refuses startup unless this exact artifact passes the compile-time closure.
pub fn require_operational_artifact_v1() -> Result<(), StartupRefusalV1> {
    if build_attestation_v1().operational_artifact {
        Ok(())
    } else {
        Err(StartupRefusalV1::NonOperationalArtifact)
    }
}

const fn build_mode() -> RuntimeBuildModeV1 {
    if cfg!(feature = "production") {
        RuntimeBuildModeV1::Production
    } else if cfg!(feature = "simulation") {
        RuntimeBuildModeV1::Simulation
    } else if cfg!(feature = "development") {
        RuntimeBuildModeV1::Development
    } else {
        RuntimeBuildModeV1::Incomplete
    }
}
