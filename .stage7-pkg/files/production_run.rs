//! Production composition root: the arm that `main` runs.
//!
//! **This does not yet run a route, and says so rather than pretending.** It
//! goes as far as the pieces that exist allow — it reads the out-of-band
//! secrets, loads and authenticates the canonical configuration, opens the
//! route, time, route-secret, settlement-coordinator, chain actuator/signer,
//! solver-inventory, RFQ-late F6, Relay/Contracts and refund authorities — and
//! then refuses, naming every production authority that is not composed yet. A
//! refusal that names what is missing is a result; a loop driven by test
//! doubles would not be.
//!
//! Nothing here is a stand-in. There is no mock, no laboratory value and no
//! `evidence-only` surface: where a piece is absent it is absent, and
//! [`PRODUCTION_KNOWN_LIMITS_V1`] names the fail-closed limits.

use std::fs::File;
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use adapter_dom_real::RealDomRpcRuntimeV1;
use btc_actuator::DurableBitcoinActuatorV1;
use cap_std::fs::Dir;
use deployment_registry::{ResolvedBitcoinDeploymentV1, ResolvedEvmDeploymentV1};
use dom_actuator::{
    AuthenticatedDomPayoutFaceV1, DomActuatorStoreV1, DomLeaseV1, DomPayoutFaceSelectionRequestV1,
};
use dom_scriptless_store::{
    BudgetPolicyProfileV1, BudgetPolicyV1, ContractsSessionStoreV1,
    PreparedContractsSessionStoreOpenV1, BUDGET_POLICY_LEN,
};
use evm_actuator::{DurableEvmActuatorV1, EvmSignerRoleV1};
use relay::production::RelayDatabaseIdV1;
use rfq::v2::SettlementPositionV2;
use route_executor::LegIdV1;
use route_secret_vault::{DurableRouteSecretVaultV1, RouteSecretSealKeyV1};
use settlement_coordinator::DurableSettlementCoordinatorV1;
use solver_inventory::DurableInventoryStoreV1;

use crate::production_bitcoin_prebroadcast::ProductionBitcoinPrebroadcastOwnerV7;
use crate::production_child_btc::{
    ProductionBitcoinChildPortV1, SystemProductionBitcoinChildClockV1,
};
use crate::production_child_router::ProductionSettlementChildRouterV1;
use crate::production_composite_loop::{
    run_production_composite_runtime_bounded_v1, ProductionCompositeActivationExitV1,
    ProductionCompositeActivationV1, ProductionCompositeLoopConfigV1,
    ProductionCompositeRuntimeExitV1,
};
use crate::production_materializer::{
    ProductionCustodiedFirstExposureClaimAuthorityV1,
    ProductionSettlementMaterializationOwnerV1,
};
use crate::production_plan_persistence::ProductionSettlementPlanPersistenceOwnerV1;
use crate::production_plan_source::{
    ProductionDomPublicSecretSourceScopeV1, ProductionDomPublicSecretSourceV1,
    ProductionLateBitcoinPublicSecretSourceV1, ProductionPublicSecretSourceRouterV1,
    VerifiedProductionSettlementPlanSourceV1,
};
use crate::production_runner::ProductionExternalCustodyOnlyRunnerV1;
use crate::production_settlement::{
    assemble_production_settlement_authorities_with_child_port_v1,
    ProductionSettlementBridgeConfigV1,
};
use crate::runtime::{
    ProductionRouteRuntimeV1, RouteRuntimeAuthoritiesV1, RouteRuntimeConfigV1,
    RouteRuntimeOperationalAuthoritiesV1, RouteRuntimeRecoveryAuthoritiesV1,
};
use crate::supervisor::{RouteSupervisorConfigV1, RouteSupervisorV1, SystemClockV1};
use crate::production_chain_services::{
    load_production_chain_services_v1, ProductionChainClientsV1,
};
use crate::production_chain_signers::{
    provision_production_chain_signers_v1, ProductionChainSignerAuthoritiesV1,
    ProductionChainSignerProvisioningRequestV1,
};
use crate::production_child_dom::{
    compose_production_dom_child_port_v1, ProductionDomChildBindingsV1,
    ProductionDomChildSessionBindingsV1, ProductionDomMaterializationScopeV1,
};
use crate::production_child_evm::{
    ProductionEvmChildPortV1, ProductionEvmMaterializationScopeV1,
    ProductionEvmMaterializingPortInputV1, SystemProductionEvmChildClockV1,
};
use crate::production_config::{
    load_production_create_or_resume_bootstrap_v10, load_production_reopen_bootstrap_v10,
    provisioning_binding_for_v10_bootstrap, read_owner_file_bounded, ProductionConfigErrorV1,
    ProductionF6PathRoleV4, ProductionF6PathRoleV8, ProductionOperationalPoliciesV10,
    ProductionPathRoleV1, ValidatedProductionBootstrapV1,
    MAX_PRODUCTION_F6_AUTHORITY_BUNDLE_BYTES_V8,
};
use crate::production_contracts_session_bootstrap::{
    bootstrap_production_contracts_sessions_v1, ProductionContractsSessionBootstrapRequestV1,
};
use crate::production_evm_remote_signer::{
    ProductionEvmRemoteSignerBindingV1, ProductionEvmRemoteSignerPinsV1,
};
use crate::production_evm_signer::{
    ProductionEvmLocalCredentialV1, ProductionEvmSignerBindingV1, ProductionEvmSignerPinsV1,
    ProductionScopedEip1559SignerV1,
};
use crate::production_f6::{ProductionF6PathsV2, ProductionF6PreparedBindingsV2};
use crate::production_f6_activation::{
    ProductionF6ActivationPathsV2, ProductionF6PairActivationRequestV2,
    ProductionF6PairLegMaterialsV2,
};
use crate::production_f6_factory::{
    AuthenticatedProductionF6AuthorityBundleV7, ProductionF6AuthenticatedRouteContextV7,
    ProductionF6BondSignerCredentialsV7, ProductionF6CounterpartyTermsOwnerV7,
    ProductionF6ExternalPathsV7, ProductionF6ExternalPreparedBindingsV7,
    ProductionF6PairAuthoritiesFactoryV7, ProductionF6PairFactoryRequestV7,
    ProductionF6TermsOwnersV7,
};
use crate::production_inputs::{
    load_authenticated_production_inputs_v1,
    load_authenticated_production_inputs_with_provisioning_v1, AuthenticatedProductionInputsV1,
};
use crate::production_node::{
    load_production_node_config_v1, read_production_secrets_v3_from_stdin,
};
use crate::production_plan_source::ProductionPublicSecretRetentionV1;
use crate::production_provisioning::{
    DurableProductionProvisioningJournalV1, ProductionProvisioningStageStateV1,
    ProductionProvisioningStageV1, ROUTE_SECRET_VAULT_ROOT_NAME_V1,
};
use crate::production_refund_arming::{
    ProductionCounterpartyRefundFaceV1, ProductionDomRefundFaceScopeV1,
    ProductionRefundArmingAuthorityV1, ProductionRefundArmingCredentialV1,
    ProductionRefundArmingSourcesV1, ProductionRefundLegV1,
};
use crate::production_relay_network_config::{
    load_production_relay_network_config_v1, ProductionRelayNetworkConfigV1,
};
use crate::production_relay_stage12::{
    construct_production_relay_stage12_v1, ProductionRelayStage12ModeV1,
    ProductionRelayStage12RequestV1,
};
use crate::production_signal::ProductionSignalBridgeV1;
use crate::production_timer::ProductionDeadlineTimerAuthorityV1;
use crate::{require_operational_artifact_v1, SystemRouteRunControlV1};

/// Whether this invocation provisions a new route or resumes an existing one.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ProductionRunModeV1 {
    /// Reads the V10 create manifest and its recovery companion, and requires
    /// every managed authority to be absent.
    Create,
    /// Reads only the V10 recovery manifest and requires every managed
    /// authority to exist. Never falls back to provisioning.
    ReopenExisting,
}

/// Exactly what `run` was asked to do.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ProductionRunOptionsV1 {
    /// Owner-only directory holding the manifests and every managed authority.
    pub state_dir: PathBuf,
    /// Provision or resume.
    pub mode: ProductionRunModeV1,
}

/// Redacted refusal from the composition root. No variant carries a path, a
/// credential, or any byte of either.
#[derive(Clone, PartialEq, Eq, Debug, thiserror::Error)]
pub enum ProductionRunErrorV1 {
    /// The library entrypoint was reached through an artifact that is not an
    /// exact Linux release build with the closed production feature graph.
    #[error("production artifact is not operational")]
    StartupArtifact,
    /// The sole SIGINT/SIGTERM consumer could not be installed before any
    /// other production worker was allowed to exist.
    #[error("production signal authority unavailable")]
    SignalBridge,
    /// The out-of-band secret stream was refused. Its own error names which of
    /// the nine fields was wrong; it is not repeated here, because this
    /// boundary must not widen a redacted refusal into a specific one.
    #[error("production secrets unavailable")]
    Secrets,
    /// The canonical configuration was refused.
    #[error("production configuration refused")]
    Configuration,
    /// The owner-only Relay sidecar disagrees with the directional peer
    /// identities authenticated by V10, or aliases this process's Relay.
    #[error("production Relay network configuration refused")]
    RelayNetworkConfiguration,
    /// A public route input failed to authenticate.
    #[error("production inputs refused")]
    Inputs,
    /// The authenticated route journal contains a runner-shaped effect, which
    /// this production composition must never dispatch or reconcile.
    #[error("production route journal violates external-custody-only policy")]
    RouteJournalPolicy,
    /// The state directory could not be opened as a capability.
    #[error("production state directory capability unavailable")]
    StateDirectoryCapability,
    /// The encrypted public-scalar recovery authority could not be created or
    /// reopened under the retained state-directory capability.
    #[error("production route-secret vault unavailable")]
    RouteSecretVault,
    /// The durable two-face settlement coordinator could not be created,
    /// resumed from its exact journaled prefix, or reopened and authenticated.
    #[error("production settlement coordinator unavailable")]
    CoordinatorStore,
    /// The DOM custody/control store could not be created, resumed from its
    /// exact journaled prefix, or reopened and fully audited.
    #[error("production DOM actuator store unavailable")]
    DomActuatorStore,
    /// The EVM nonce/allowance/transaction authority could not be created,
    /// resumed from its exact prefix, or reopened and fully audited.
    #[error("production EVM actuator store unavailable")]
    EvmActuatorStore,
    /// The Bitcoin signing/broadcast authority could not be created, resumed
    /// from its exact prefix, or reopened under the pinned process owner.
    #[error("production Bitcoin actuator store unavailable")]
    BitcoinActuatorStore,
    /// The route's DOM wallet/nonces and Bitcoin participant signer could not
    /// be provisioned or reopened under one exact authenticated participant.
    #[error("production chain signer authorities unavailable")]
    ChainSignerAuthorities,
    /// The single local EVM credential was invalid, matched zero or both
    /// admitted accounts, or could not be bound to its exact route role.
    #[error("production local EVM signer authority unavailable")]
    EvmSignerAuthority,
    /// The authenticated DOM node configuration or live adapter was refused.
    #[error("production DOM node authority unavailable")]
    DomNodeAuthority,
    /// EVM/Bitcoin endpoints, credentials, deadlines or deployment bindings
    /// were refused before any route worker started.
    #[error("production counterparty chain services unavailable")]
    ChainServices,
    /// The solver inventory/bond authority could not be created, resumed from
    /// its exact pristine prefix, or reopened under the authenticated binding.
    #[error("production solver inventory store unavailable")]
    SolverInventoryStore,
    /// The two raw Contracts Stores could not be created/resumed as one
    /// pristine Stage-10 unit or reopened under the ratified budget policy.
    #[error("production Contracts stores unavailable")]
    ContractsStores,
    /// The RFQ-late F6 pair could not authenticate its public bundle, prepare
    /// or resume its exact Stage-11 prefixes, or retain both activation owners.
    #[error("production F6 authorities unavailable")]
    F6Authorities,
    /// The central Relay and the two single-owner Contracts/F6 workers could
    /// not be constructed or resumed under the Stage-12 journal boundary.
    #[error("production Relay/Contracts authorities unavailable")]
    RelayAuthorities,
    /// The four exact refund faces or their durable Stage-13 owner could not
    /// be constructed, resumed or reopened under the authenticated V9 epoch.
    #[error("production refund-arming authority unavailable")]
    RefundArmingAuthority,
    /// The exact route/composition deadlines could not be reduced to one
    /// deterministic timer authority.
    #[error("production deadline timer authority unavailable")]
    TimerAuthority,
    /// One concrete settlement child could not be bound to the same admitted
    /// route, deployment, signer, actuator lease and Contracts owner.
    #[error("production settlement child authority unavailable")]
    SettlementChildAuthority,
    /// Ordered production authority creation could not be resumed exactly.
    #[error("production provisioning journal unavailable")]
    Provisioning,
    /// The host clock is before the Unix epoch, so no trusted second exists.
    #[error("production host clock is unusable")]
    HostClock,
    /// The Bitcoin funding child could not be composed from the sole armed
    /// prebroadcast owner, or a durably recovered claim was found that this
    /// build cannot rebind without the authenticated M.8 participant round.
    #[error("production Bitcoin child authority unavailable")]
    BitcoinChildAuthority,
    /// The public-secret sources, first-exposure custody or materialization
    /// owner refused the authenticated route scope.
    #[error("production settlement plan source unavailable")]
    PlanSource,
    /// The composite Relay/Noise loop could not be configured, activated or
    /// driven under the retained Stage-12 owner.
    #[error("production composite relay loop failed")]
    CompositeLoop,
    /// The activated route store could not be acquired under the production
    /// lease/fencing authority, or its journal contradicts the closed runner
    /// policy.
    #[error("production route supervisor unavailable")]
    RouteSupervisor,
    /// The concrete route runtime refused its authorities or configuration, or
    /// failed closed while driving the route.
    #[error("production route runtime failed")]
    RouteRuntime,
}

/// Known, deliberately fail-closed limits of this composition root.
///
/// Printed once by `main` at startup so an operator knows which paths refuse
/// by policy rather than by fault. Each entry names the exact refusal point;
/// none is a placeholder, mock or degraded substitute.
pub const PRODUCTION_KNOWN_LIMITS_V1: &[&str] = &[
    "BitcoinClaim: the Bitcoin child is composed funding/refund-only; every claim materialization is refused by `ProductionBitcoinChildPortV1` until the authenticated DSC1 M.8 participant round (pubnonce/partial/aggregate) exists, and a durably recovered claim refuses startup (`ClaimRecoveryNotComposable`)",
    "EvmPublicSecretSource: no EVM reextraction source is installed; `ProductionPublicSecretSourceRouterV1` refuses EVM-scoped reextraction, and recovery of an already-public `t` uses the sealed retention vault only",
];

/// Runs the production composition root as far as it can go today.
///
/// The order is the order the pieces depend on each other, and each step is
/// the one already-reviewed function that owns it:
///
/// 1. the nine out-of-band secrets, read once from standard input;
/// 2. the canonical manifest and its companion, through the V10 loaders;
/// 3. a trusted second (see below);
/// 4. every public route input, authenticated, which also creates or reopens
///    the durable route store and the V2 time authority;
/// 5. the state directory as a capability, which is what the two Contracts
///    stores will need;
/// 6. the route-secret retention authority, created or reopened using the
///    independent fourth credential;
/// 7. the durable settlement coordinator, bound to the two public authority
///    identities and the ordered provisioning journal;
/// 8. the durable DOM custody/control store, opened exactly once under the
///    next ordered provisioning stage;
/// 9. the durable EVM actuator store;
/// 10. the durable Bitcoin actuator store under the process-owner pin;
/// 11. the durable solver inventory/bond store under its authenticated
///     binding;
/// 12. the complete RFQ-late F6 pair, including wallet-authenticated payout
///     faces, exact prepared prefixes and the one-shot route-store handoff;
/// 13. the central Relay plus both Store-sharing Contracts/F6 workers;
/// 14. the funding/refund-only Bitcoin child, the exact child router, the
///     public-secret sources and the split materialization owner;
/// 15. the settlement bridge, the composite Relay/Noise activation of the F6
///     pair, the route supervisor lease and the concrete route runtime;
/// 16. the interleaved Relay/route loop until terminal or safe shutdown, then
///     teardown in reverse ownership order. The fail-closed limits are named
///     in [`PRODUCTION_KNOWN_LIMITS_V1`].
///
/// **On the trusted second, because the word is doing work.** Step 4 wants a
/// second the composition root vouches for, and this takes it from the host
/// clock. That is a decision and not an obvious wiring: a host clock is not an
/// authenticated time source, and what makes the route's timing safe is the
/// signed time policy and evidence that step 4 itself verifies, not this
/// number. It is used to *enter* that verification, never to satisfy it.
pub fn run_production_v1(options: &ProductionRunOptionsV1) -> Result<(), ProductionRunErrorV1> {
    // `main` performs this check before argument parsing, but this public
    // library entrypoint is also a trust boundary and must remain safe when
    // embedded directly. No secret, path, store or worker is touched first.
    require_operational_artifact_v1().map_err(|_| ProductionRunErrorV1::StartupArtifact)?;

    // Read before anything else touches the filesystem: standard input is
    // consumed in one pass and a supervisor that wrote it is waiting.
    let secrets =
        read_production_secrets_v3_from_stdin().map_err(|_| ProductionRunErrorV1::Secrets)?;
    let secrets = secrets.into_parts();
    let upstream_f6_hsm_credentials = secrets.upstream_f6_hsm_credentials;
    let downstream_f6_hsm_credentials = secrets.downstream_f6_hsm_credentials;
    let secrets = secrets.common;
    let local_evm_credential = ProductionEvmLocalCredentialV1::import(secrets.evm_signing_secret)
        .map_err(|_| ProductionRunErrorV1::EvmSignerAuthority)?;
    let secrets = secrets.common;
    let bearer = secrets.bearer;
    let upstream_relay_signing_secret = secrets.upstream_relay_signing_secret;
    let downstream_relay_signing_secret = secrets.downstream_relay_signing_secret;
    let identity_passphrase = secrets.identity_passphrase;
    let dom_wallet_passphrase = secrets.dom_wallet_passphrase;
    let bitcoin_participant_secret = secrets.bitcoin_participant_secret;
    let route_secret_seal_key = secrets.route_secret_seal_key;
    let refund_arming_credential = secrets.refund_arming_credential;

    // Install the sole process signal consumer after the one blocking secret
    // read, but before any future Relay/RPC or actuator worker can be spawned.
    // Installing it before stdin would suppress the default SIGTERM action
    // while no runtime loop yet existed to observe the shutdown token. The
    // guard remains on this thread and restores the prior mask on every typed
    // return path.
    let (mut _run_control, shutdown) = SystemRouteRunControlV1::new();
    let mut _signal_bridge = ProductionSignalBridgeV1::install(shutdown)
        .map_err(|_| ProductionRunErrorV1::SignalBridge)?;

    let bootstrap = load_bootstrap(options).map_err(|_| ProductionRunErrorV1::Configuration)?;
    let operational_policies = bootstrap
        .config()
        .operational_policies_v10()
        .ok_or(ProductionRunErrorV1::Configuration)?;
    let relay_network_config = bind_v10_relay_network_configuration(
        bootstrap.layout().state_dir(),
        bootstrap.config(),
        operational_policies,
    )?;
    let provisioning_binding = provisioning_binding_for_v10_bootstrap(&bootstrap)
        .map_err(|_| ProductionRunErrorV1::Provisioning)?;
    let mut provisioning = match options.mode {
        ProductionRunModeV1::Create => {
            DurableProductionProvisioningJournalV1::open_or_create_after_absence_check(
                bootstrap.layout().state_dir(),
                provisioning_binding,
            )
        }
        ProductionRunModeV1::ReopenExisting => DurableProductionProvisioningJournalV1::open(
            bootstrap.layout().state_dir(),
            provisioning_binding,
        ),
    }
    .map_err(|_| ProductionRunErrorV1::Provisioning)?;
    if options.mode == ProductionRunModeV1::ReopenExisting {
        require_reopen_provisioning_prefix(&provisioning)?;
    }
    let trusted_now_seconds = trusted_now_seconds_v1()?;
    let mut inputs = match options.mode {
        ProductionRunModeV1::Create => load_authenticated_production_inputs_with_provisioning_v1(
            &bootstrap,
            trusted_now_seconds,
            &mut provisioning,
        ),
        ProductionRunModeV1::ReopenExisting => {
            load_authenticated_production_inputs_v1(&bootstrap, trusted_now_seconds)
        }
    }
    .map_err(|_| ProductionRunErrorV1::Inputs)?;
    // The production entrypoint is V10-only. Older manifest families remain
    // decodable for recovery tooling and tests, but cannot enter a live route
    // without the authenticated bilateral Contracts bootstrap.
    inputs
        .contracts_bootstrap()
        .ok_or(ProductionRunErrorV1::Inputs)?;
    inputs
        .audit_external_custody_only()
        .map_err(|_| ProductionRunErrorV1::RouteJournalPolicy)?;
    let runtime_bounds = bootstrap.config().bounds();
    let dom_deployment = inputs
        .admission()
        .dom_deployment_capability()
        .map_err(|_| ProductionRunErrorV1::DomNodeAuthority)?;
    let dom_node = load_production_node_config_v1(bootstrap.layout().state_dir())
        .map_err(|_| ProductionRunErrorV1::DomNodeAuthority)?;
    let dom_history_limit = dom_node.history_limit();
    let dom_chain_adapter = dom_node
        .into_dom_chain_adapter(
            bearer,
            dom_deployment.deployment(),
            runtime_bounds.external_call_timeout_ms,
        )
        .map_err(|_| ProductionRunErrorV1::DomNodeAuthority)?;
    let (evm_deployment, bitcoin_deployment) = selected_counterparty_deployments(&inputs)?;
    let evm_fees = operational_policies
        .evm_fees(bootstrap.config(), &evm_deployment)
        .map_err(|_| ProductionRunErrorV1::Configuration)?;
    let chain_services = load_production_chain_services_v1(bootstrap.layout().state_dir())
        .map_err(|_| ProductionRunErrorV1::ChainServices)?;
    let chain_clients = chain_services
        .into_clients(
            evm_deployment,
            &bitcoin_deployment,
            runtime_bounds.external_call_timeout_ms,
        )
        .map_err(|_| ProductionRunErrorV1::ChainServices)?;
    let pending_evm_signer_pair = bind_single_local_evm_signer(
        &inputs,
        local_evm_credential,
        bootstrap.config().pins().process_owner_id,
    )?;
    let state_capability = state_dir_capability(bootstrap.layout().state_dir())?;
    let vault_stage_before_begin = provisioning
        .stage_state(ProductionProvisioningStageV1::RouteSecretVault)
        .map_err(|_| ProductionRunErrorV1::Provisioning)?;
    if options.mode == ProductionRunModeV1::Create
        && vault_stage_before_begin == ProductionProvisioningStageStateV1::Absent
    {
        require_vault_create_prefix_absent(&state_capability)?;
    }
    let vault_stage = match options.mode {
        ProductionRunModeV1::Create => provisioning
            .begin(ProductionProvisioningStageV1::RouteSecretVault)
            .map_err(|_| ProductionRunErrorV1::Provisioning)?,
        ProductionRunModeV1::ReopenExisting => vault_stage_before_begin,
    };
    let route_secret_retention = open_route_secret_retention(
        options.mode,
        vault_stage_before_begin,
        vault_stage,
        Arc::clone(&state_capability),
        route_secret_seal_key,
    )?;
    if options.mode == ProductionRunModeV1::Create
        && vault_stage != ProductionProvisioningStageStateV1::Complete
    {
        provisioning
            .complete(ProductionProvisioningStageV1::RouteSecretVault)
            .map_err(|_| ProductionRunErrorV1::Provisioning)?;
    } else if vault_stage != ProductionProvisioningStageStateV1::Complete {
        return Err(ProductionRunErrorV1::Provisioning);
    }

    let coordinator_stage_before_begin = provisioning
        .stage_state(ProductionProvisioningStageV1::CoordinatorStore)
        .map_err(|_| ProductionRunErrorV1::Provisioning)?;
    let coordinator_path = bootstrap
        .layout()
        .path(ProductionPathRoleV1::CoordinatorStore);
    if options.mode == ProductionRunModeV1::Create
        && coordinator_stage_before_begin == ProductionProvisioningStageStateV1::Absent
    {
        require_coordinator_create_prefix_absent(coordinator_path)?;
    }
    let coordinator_stage = match options.mode {
        ProductionRunModeV1::Create => provisioning
            .begin(ProductionProvisioningStageV1::CoordinatorStore)
            .map_err(|_| ProductionRunErrorV1::Provisioning)?,
        ProductionRunModeV1::ReopenExisting => coordinator_stage_before_begin,
    };
    let pins = bootstrap.config().pins();
    let now_unix_ms = trusted_now_seconds
        .checked_mul(1_000)
        .ok_or(ProductionRunErrorV1::CoordinatorStore)?;
    let coordinator = open_settlement_coordinator(
        options.mode,
        coordinator_stage_before_begin,
        coordinator_stage,
        coordinator_path,
        pins.coordinator_id,
        pins.coordinator_plan_authority_id,
        now_unix_ms,
    )?;
    if options.mode == ProductionRunModeV1::Create
        && coordinator_stage != ProductionProvisioningStageStateV1::Complete
    {
        provisioning
            .complete(ProductionProvisioningStageV1::CoordinatorStore)
            .map_err(|_| ProductionRunErrorV1::Provisioning)?;
    } else if coordinator_stage != ProductionProvisioningStageStateV1::Complete {
        return Err(ProductionRunErrorV1::Provisioning);
    }

    let dom_stage_before_begin = provisioning
        .stage_state(ProductionProvisioningStageV1::DomActuatorStore)
        .map_err(|_| ProductionRunErrorV1::Provisioning)?;
    let dom_path = bootstrap
        .layout()
        .path(ProductionPathRoleV1::DomActuatorStore);
    if options.mode == ProductionRunModeV1::Create
        && dom_stage_before_begin == ProductionProvisioningStageStateV1::Absent
    {
        require_dom_actuator_create_prefix_absent(dom_path)?;
    }
    let dom_stage = match options.mode {
        ProductionRunModeV1::Create => provisioning
            .begin(ProductionProvisioningStageV1::DomActuatorStore)
            .map_err(|_| ProductionRunErrorV1::Provisioning)?,
        ProductionRunModeV1::ReopenExisting => dom_stage_before_begin,
    };
    let mut dom_actuator_store =
        open_dom_actuator_store(options.mode, dom_stage_before_begin, dom_stage, dom_path)?;
    if options.mode == ProductionRunModeV1::Create
        && dom_stage != ProductionProvisioningStageStateV1::Complete
    {
        provisioning
            .complete(ProductionProvisioningStageV1::DomActuatorStore)
            .map_err(|_| ProductionRunErrorV1::Provisioning)?;
    } else if dom_stage != ProductionProvisioningStageStateV1::Complete {
        return Err(ProductionRunErrorV1::Provisioning);
    }

    let evm_stage_before_begin = provisioning
        .stage_state(ProductionProvisioningStageV1::EvmActuatorStore)
        .map_err(|_| ProductionRunErrorV1::Provisioning)?;
    let evm_path = bootstrap
        .layout()
        .path(ProductionPathRoleV1::EvmActuatorStore);
    if options.mode == ProductionRunModeV1::Create
        && evm_stage_before_begin == ProductionProvisioningStageStateV1::Absent
    {
        require_evm_actuator_create_prefix_absent(evm_path)?;
    }
    let evm_stage = match options.mode {
        ProductionRunModeV1::Create => provisioning
            .begin(ProductionProvisioningStageV1::EvmActuatorStore)
            .map_err(|_| ProductionRunErrorV1::Provisioning)?,
        ProductionRunModeV1::ReopenExisting => evm_stage_before_begin,
    };
    let mut evm_actuator_store =
        open_evm_actuator_store(options.mode, evm_stage_before_begin, evm_stage, evm_path)?;
    complete_provisioning_stage(
        options.mode,
        evm_stage,
        ProductionProvisioningStageV1::EvmActuatorStore,
        &mut provisioning,
    )?;

    let bitcoin_stage_before_begin = provisioning
        .stage_state(ProductionProvisioningStageV1::BitcoinActuatorStore)
        .map_err(|_| ProductionRunErrorV1::Provisioning)?;
    let bitcoin_path = bootstrap
        .layout()
        .path(ProductionPathRoleV1::BitcoinActuatorStore);
    if options.mode == ProductionRunModeV1::Create
        && bitcoin_stage_before_begin == ProductionProvisioningStageStateV1::Absent
    {
        require_bitcoin_actuator_create_prefix_absent(bitcoin_path)?;
    }
    let bitcoin_stage = match options.mode {
        ProductionRunModeV1::Create => provisioning
            .begin(ProductionProvisioningStageV1::BitcoinActuatorStore)
            .map_err(|_| ProductionRunErrorV1::Provisioning)?,
        ProductionRunModeV1::ReopenExisting => bitcoin_stage_before_begin,
    };
    let mut bitcoin_actuator_store = open_bitcoin_actuator_store(
        options.mode,
        bitcoin_stage_before_begin,
        bitcoin_stage,
        bitcoin_path,
        pins.process_owner_id,
    )?;
    complete_provisioning_stage(
        options.mode,
        bitcoin_stage,
        ProductionProvisioningStageV1::BitcoinActuatorStore,
        &mut provisioning,
    )?;

    let mut chain_signers =
        provision_production_chain_signers_v1(ProductionChainSignerProvisioningRequestV1 {
            bootstrap: &bootstrap,
            inputs: &inputs,
            journal: &mut provisioning,
            upstream_relay_signing_secret: &upstream_relay_signing_secret,
            downstream_relay_signing_secret: &downstream_relay_signing_secret,
            dom_wallet_passphrase,
            bitcoin_participant_secret,
        })
        .map_err(|_| ProductionRunErrorV1::ChainSignerAuthorities)?;

    let inventory_stage_before_begin = provisioning
        .stage_state(ProductionProvisioningStageV1::SolverInventoryStore)
        .map_err(|_| ProductionRunErrorV1::Provisioning)?;
    let inventory_path = bootstrap
        .layout()
        .path(ProductionPathRoleV1::SolverInventoryStore);
    if options.mode == ProductionRunModeV1::Create
        && inventory_stage_before_begin == ProductionProvisioningStageStateV1::Absent
    {
        require_solver_inventory_create_prefix_absent(inventory_path)?;
    }
    let inventory_stage = match options.mode {
        ProductionRunModeV1::Create => provisioning
            .begin(ProductionProvisioningStageV1::SolverInventoryStore)
            .map_err(|_| ProductionRunErrorV1::Provisioning)?,
        ProductionRunModeV1::ReopenExisting => inventory_stage_before_begin,
    };
    let solver_inventory = open_solver_inventory_store(
        options.mode,
        inventory_stage_before_begin,
        inventory_stage,
        inventory_path,
        pins.solver_inventory_binding_digest,
    )?;
    complete_provisioning_stage(
        options.mode,
        inventory_stage,
        ProductionProvisioningStageV1::SolverInventoryStore,
        &mut provisioning,
    )?;

    let contracts_policy = load_contracts_budget_policy(&bootstrap)?;
    let upstream_contracts_path = bootstrap
        .layout()
        .path(ProductionPathRoleV1::UpstreamContracts);
    let downstream_contracts_path = bootstrap
        .layout()
        .path(ProductionPathRoleV1::DownstreamContracts);
    let upstream_contracts_root =
        contracts_root_name(bootstrap.layout().state_dir(), upstream_contracts_path)?;
    let downstream_contracts_root =
        contracts_root_name(bootstrap.layout().state_dir(), downstream_contracts_path)?;
    let contracts_stage_before_begin = provisioning
        .stage_state(ProductionProvisioningStageV1::ContractsStores)
        .map_err(|_| ProductionRunErrorV1::Provisioning)?;
    if options.mode == ProductionRunModeV1::Create
        && contracts_stage_before_begin != ProductionProvisioningStageStateV1::Complete
    {
        preflight_contracts_store_pair(
            Arc::clone(&state_capability),
            upstream_contracts_root,
            downstream_contracts_root,
            &contracts_policy,
            provisioning_binding,
            contracts_stage_before_begin == ProductionProvisioningStageStateV1::Started,
        )?;
    }
    let contracts_stage = match options.mode {
        ProductionRunModeV1::Create => provisioning
            .begin(ProductionProvisioningStageV1::ContractsStores)
            .map_err(|_| ProductionRunErrorV1::Provisioning)?,
        ProductionRunModeV1::ReopenExisting => contracts_stage_before_begin,
    };
    let contracts_stores = open_contracts_store_pair(ContractsStorePairRequestV1 {
        mode: options.mode,
        stage_before_begin: contracts_stage_before_begin,
        stage: contracts_stage,
        parent: Arc::clone(&state_capability),
        upstream_root: upstream_contracts_root,
        downstream_root: downstream_contracts_root,
        policy: contracts_policy,
        creation_binding: provisioning_binding,
    })?;
    let identity_store_path = bootstrap
        .layout()
        .contracts_transport_identity_store()
        .ok_or(ProductionRunErrorV1::ContractsStores)?;
    let authenticated_contracts_bootstrap = inputs
        .contracts_bootstrap()
        .ok_or(ProductionRunErrorV1::ContractsStores)?;
    let contracts_stage10_owner =
        bootstrap_production_contracts_sessions_v1(ProductionContractsSessionBootstrapRequestV1 {
            state_capability: Arc::clone(&state_capability),
            state_dir: bootstrap.layout().state_dir(),
            identity_store_path,
            identity_passphrase,
            dom_chain_adapter,
            authenticated_bootstrap: authenticated_contracts_bootstrap,
            chain_signers: &chain_signers,
            upstream_store: contracts_stores.upstream,
            downstream_store: contracts_stores.downstream,
        })
        .map_err(|_| ProductionRunErrorV1::ContractsStores)?;
    complete_provisioning_stage(
        options.mode,
        contracts_stage,
        ProductionProvisioningStageV1::ContractsStores,
        &mut provisioning,
    )?;

    // Stage 11 authenticates every immutable F6 input before publishing a
    // prefix. The bundle file was already digest-pinned by the V8 loader; this
    // second boundary verifies its threshold signatures and exact route scope.
    let f6_bundle_path = bootstrap
        .layout()
        .f6_path_v8(ProductionF6PathRoleV8::AuthorityBundleV7)
        .ok_or(ProductionRunErrorV1::F6Authorities)?;
    let f6_bundle_bytes = read_owner_file_bounded(
        f6_bundle_path,
        MAX_PRODUCTION_F6_AUTHORITY_BUNDLE_BYTES_V8,
        ProductionConfigErrorV1::InputArtifactUnavailable,
    )
    .map_err(|_| ProductionRunErrorV1::F6Authorities)?;
    let f6_bundle = AuthenticatedProductionF6AuthorityBundleV7::decode_and_authenticate(
        &f6_bundle_bytes,
        &inputs,
    )
    .map_err(|_| ProductionRunErrorV1::F6Authorities)?;
    let f6_solver = f6_bundle.solver();
    let f6_route = ProductionF6AuthenticatedRouteContextV7::from_authenticated(&inputs);
    let composition_owner = inputs.composition_owner();
    let route_id = inputs.admission().route_id();
    let composition_digest = inputs.composition().binding_digest();
    let dom_chain_id = inputs.composition().upstream().dom_leg.chain_id;

    let f6_external_paths = ProductionF6ExternalPathsV7::new(
        bootstrap.layout().state_dir(),
        [
            required_f6_v8_path(&bootstrap, ProductionF6PathRoleV8::UpstreamStatusStore)?
                .to_path_buf(),
            required_f6_v8_path(&bootstrap, ProductionF6PathRoleV8::DownstreamStatusStore)?
                .to_path_buf(),
            required_f6_v8_path(&bootstrap, ProductionF6PathRoleV8::UpstreamTimeStore)?
                .to_path_buf(),
            required_f6_v8_path(&bootstrap, ProductionF6PathRoleV8::DownstreamTimeStore)?
                .to_path_buf(),
            required_f6_v8_path(&bootstrap, ProductionF6PathRoleV8::UpstreamCandidateStore)?
                .to_path_buf(),
            required_f6_v8_path(&bootstrap, ProductionF6PathRoleV8::DownstreamCandidateStore)?
                .to_path_buf(),
        ],
    )
    .map_err(|_| ProductionRunErrorV1::F6Authorities)?;
    let f6_external_prepared = ProductionF6ExternalPreparedBindingsV7::derive_stage11(
        provisioning_binding,
        route_id,
        composition_digest,
    )
    .map_err(|_| ProductionRunErrorV1::F6Authorities)?;
    let upstream_f6_prepared = ProductionF6PreparedBindingsV2::derive_stage11(
        provisioning_binding,
        route_id,
        composition_digest,
        SettlementPositionV2::Upstream,
    )
    .map_err(|_| ProductionRunErrorV1::F6Authorities)?;
    let downstream_f6_prepared = ProductionF6PreparedBindingsV2::derive_stage11(
        provisioning_binding,
        route_id,
        composition_digest,
        SettlementPositionV2::Downstream,
    )
    .map_err(|_| ProductionRunErrorV1::F6Authorities)?;
    let upstream_f6_paths = ProductionF6ActivationPathsV2::from_v4_layout(
        bootstrap.layout(),
        SettlementPositionV2::Upstream,
    )
    .map_err(|_| ProductionRunErrorV1::F6Authorities)?;
    let downstream_f6_paths = ProductionF6ActivationPathsV2::from_v4_layout(
        bootstrap.layout(),
        SettlementPositionV2::Downstream,
    )
    .map_err(|_| ProductionRunErrorV1::F6Authorities)?;

    // External Bitcoin custody is an existing V8 authority. Opening it is a
    // read/authentication step; creation or replacement is never permitted.
    let mut bitcoin_prebroadcast_owner = ProductionBitcoinPrebroadcastOwnerV7::open_existing(
        &bootstrap,
        &inputs,
        Rc::clone(&chain_clients.bitcoin_live),
    )
    .map_err(|_| ProductionRunErrorV1::F6Authorities)?;

    let f6_stage_before_begin = provisioning
        .stage_state(ProductionProvisioningStageV1::F6Authorities)
        .map_err(|_| ProductionRunErrorV1::Provisioning)?;
    let f6_stage = match options.mode {
        ProductionRunModeV1::Create => provisioning
            .begin(ProductionProvisioningStageV1::F6Authorities)
            .map_err(|_| ProductionRunErrorV1::Provisioning)?,
        ProductionRunModeV1::ReopenExisting => f6_stage_before_begin,
    };
    require_f6_stage_open_state(options.mode, f6_stage)?;

    // A Started stage is an authenticated, idempotent creation prefix. The
    // retained V4 journals and the six V8 RFQ-late owners are prepared in one
    // fixed order and are never touched before the global begin record.
    if f6_stage == ProductionProvisioningStageStateV1::Started {
        upstream_f6_prepared
            .prepare_stage11(ProductionF6PathsV2 {
                binding_log: required_f6_v4_path(
                    &bootstrap,
                    ProductionF6PathRoleV4::UpstreamBindingLog,
                )?,
                receipt_store: required_f6_v4_path(
                    &bootstrap,
                    ProductionF6PathRoleV4::UpstreamReceiptStore,
                )?,
                candidate_book: required_f6_v4_path(
                    &bootstrap,
                    ProductionF6PathRoleV4::UpstreamCandidateBook,
                )?,
            })
            .map_err(|_| ProductionRunErrorV1::F6Authorities)?;
        downstream_f6_prepared
            .prepare_stage11(ProductionF6PathsV2 {
                binding_log: required_f6_v4_path(
                    &bootstrap,
                    ProductionF6PathRoleV4::DownstreamBindingLog,
                )?,
                receipt_store: required_f6_v4_path(
                    &bootstrap,
                    ProductionF6PathRoleV4::DownstreamReceiptStore,
                )?,
                candidate_book: required_f6_v4_path(
                    &bootstrap,
                    ProductionF6PathRoleV4::DownstreamCandidateBook,
                )?,
            })
            .map_err(|_| ProductionRunErrorV1::F6Authorities)?;
        f6_external_prepared
            .prepare_stage11(&f6_external_paths)
            .map_err(|_| ProductionRunErrorV1::F6Authorities)?;
    }

    // The wallet, not this root, selects the unique commitments. Both session
    // bindings and their one physical participant lease are durable, making a
    // crash anywhere in this pair exactly resumable.
    let (upstream_dom_payout, downstream_dom_payout, dom_lease) = authenticate_dom_f6_payouts(
        &inputs,
        &mut chain_signers,
        &mut dom_actuator_store,
        pins.process_owner_id,
        now_unix_ms,
        runtime_bounds.lease_duration_ms,
    )?;
    let bitcoin_payout = bitcoin_prebroadcast_owner
        .take_payout_face()
        .map_err(|_| ProductionRunErrorV1::F6Authorities)?;
    let (upstream_counterparty, downstream_counterparty) = match chain_signers.bitcoin_leg() {
        LegIdV1::Upstream => (
            ProductionF6CounterpartyTermsOwnerV7::Bitcoin {
                payout: bitcoin_payout,
                deployment: bitcoin_deployment,
            },
            ProductionF6CounterpartyTermsOwnerV7::Evm(evm_deployment),
        ),
        LegIdV1::Downstream => (
            ProductionF6CounterpartyTermsOwnerV7::Evm(evm_deployment),
            ProductionF6CounterpartyTermsOwnerV7::Bitcoin {
                payout: bitcoin_payout,
                deployment: bitcoin_deployment,
            },
        ),
    };
    let mut f6_pair_factory =
        ProductionF6PairAuthoritiesFactoryV7::new(ProductionF6PairFactoryRequestV7 {
            bundle: f6_bundle,
            route: f6_route,
            composition: composition_owner,
            paths: f6_external_paths,
            prepared: f6_external_prepared,
            inventory: solver_inventory,
            inventory_owner_id: pins.process_owner_id,
            inventory_lease_duration_ms: runtime_bounds.lease_duration_ms,
            terms: ProductionF6TermsOwnersV7 {
                upstream_dom: upstream_dom_payout,
                downstream_dom: downstream_dom_payout,
                upstream_counterparty,
                downstream_counterparty,
            },
            credentials: ProductionF6BondSignerCredentialsV7 {
                upstream: upstream_f6_hsm_credentials,
                downstream: downstream_f6_hsm_credentials,
            },
        })
        .map_err(|_| ProductionRunErrorV1::F6Authorities)?;
    let f6_final_claim_plan = f6_pair_factory
        .take_final_claim_plan()
        .map_err(|_| ProductionRunErrorV1::F6Authorities)?;
    let route_store = inputs
        .take_route_store_for_f6()
        .map_err(|_| ProductionRunErrorV1::F6Authorities)?;
    let (upstream_f6_activation, downstream_f6_activation, f6_runtime_receiver) =
        ProductionF6PairActivationRequestV2 {
            route_store,
            route_id,
            composition_v2_digest: composition_digest,
            upstream: ProductionF6PairLegMaterialsV2::new(
                SettlementPositionV2::Upstream,
                f6_solver,
                dom_chain_id,
                upstream_f6_paths,
                upstream_f6_prepared,
            ),
            downstream: ProductionF6PairLegMaterialsV2::new(
                SettlementPositionV2::Downstream,
                f6_solver,
                dom_chain_id,
                downstream_f6_paths,
                downstream_f6_prepared,
            ),
            authority_factory: Box::new(f6_pair_factory),
        }
        .into_authorities()
        .map_err(|_| ProductionRunErrorV1::F6Authorities)?;

    // Completion certifies that every move-only Stage-11 owner exists in this
    // process. It is deliberately after the one-shot RouteStore transfer and
    // pair split; a crash before here leaves Started and resumes every prefix.
    complete_provisioning_stage(
        options.mode,
        f6_stage,
        ProductionProvisioningStageV1::F6Authorities,
        &mut provisioning,
    )?;

    let relay_stage_before_begin = provisioning
        .stage_state(ProductionProvisioningStageV1::RelayAuthorities)
        .map_err(|_| ProductionRunErrorV1::Provisioning)?;
    let relay_stage = match options.mode {
        ProductionRunModeV1::Create => provisioning
            .begin(ProductionProvisioningStageV1::RelayAuthorities)
            .map_err(|_| ProductionRunErrorV1::Provisioning)?,
        ProductionRunModeV1::ReopenExisting => relay_stage_before_begin,
    };
    let relay_stage12 = construct_production_relay_stage12_v1(ProductionRelayStage12RequestV1 {
        bootstrap: &bootstrap,
        inputs: &inputs,
        chain_signers: &chain_signers,
        contracts: contracts_stage10_owner,
        upstream_activation: upstream_f6_activation,
        downstream_activation: downstream_f6_activation,
        upstream_relay_signing_secret,
        downstream_relay_signing_secret,
        mode: match options.mode {
            ProductionRunModeV1::Create => ProductionRelayStage12ModeV1::CreateOrResume,
            ProductionRunModeV1::ReopenExisting => ProductionRelayStage12ModeV1::ReopenExisting,
        },
        stage_before_begin: relay_stage_before_begin,
        stage: relay_stage,
    })
    .map_err(|_| ProductionRunErrorV1::RelayAuthorities)?;
    let relay_stage12 = relay_stage12
        .recover_production_f6_applied_history()
        .map_err(|_| ProductionRunErrorV1::RelayAuthorities)?;
    complete_provisioning_stage(
        options.mode,
        relay_stage,
        ProductionProvisioningStageV1::RelayAuthorities,
        &mut provisioning,
    )?;
    let mut relay_stage12_owner = relay_stage12
        .finish(&provisioning)
        .map_err(|_| ProductionRunErrorV1::RelayAuthorities)?;

    // Stage 13 binds all four refund verifiers before any funding child can be
    // constructed. The authority epoch is the immutable V9 configuration pin;
    // it is deliberately distinct from the supervisor's dynamic route fence.
    let refund_authority_epoch = bootstrap
        .config()
        .refund_arming_authority_epoch_v9()
        .ok_or(ProductionRunErrorV1::Configuration)?;
    let deadline_timer =
        ProductionDeadlineTimerAuthorityV1::from_composition(route_id, inputs.composition())
            .map_err(|_| ProductionRunErrorV1::TimerAuthority)?;
    let refund_stage_before_begin = provisioning
        .stage_state(ProductionProvisioningStageV1::RefundArmingAuthority)
        .map_err(|_| ProductionRunErrorV1::Provisioning)?;
    let refund_stage = match options.mode {
        ProductionRunModeV1::Create => provisioning
            .begin(ProductionProvisioningStageV1::RefundArmingAuthority)
            .map_err(|_| ProductionRunErrorV1::Provisioning)?,
        ProductionRunModeV1::ReopenExisting => refund_stage_before_begin,
    };
    let upstream_dom_refund = relay_stage12_owner
        .leg_mut(LegIdV1::Upstream)
        .contracts_mut()
        .dom_refund_face(
            ProductionDomRefundFaceScopeV1::new(
                inputs.admission(),
                inputs.composition(),
                LegIdV1::Upstream,
                pins.process_owner_id,
                refund_authority_epoch,
            )
            .map_err(|_| ProductionRunErrorV1::RefundArmingAuthority)?,
            chain_signers.dom_binding(LegIdV1::Upstream),
        )
        .map_err(|_| ProductionRunErrorV1::RefundArmingAuthority)?;
    let downstream_dom_refund = relay_stage12_owner
        .leg_mut(LegIdV1::Downstream)
        .contracts_mut()
        .dom_refund_face(
            ProductionDomRefundFaceScopeV1::new(
                inputs.admission(),
                inputs.composition(),
                LegIdV1::Downstream,
                pins.process_owner_id,
                refund_authority_epoch,
            )
            .map_err(|_| ProductionRunErrorV1::RefundArmingAuthority)?,
            chain_signers.dom_binding(LegIdV1::Downstream),
        )
        .map_err(|_| ProductionRunErrorV1::RefundArmingAuthority)?;
    let bitcoin_refund = bitcoin_prebroadcast_owner
        .refund_face(&inputs)
        .map_err(|_| ProductionRunErrorV1::RefundArmingAuthority)?;
    let ProductionChainClientsV1 {
        evm: evm_chain_client,
        evm_refund,
        bitcoin: bitcoin_chain_client,
        bitcoin_live,
    } = chain_clients;
    let (upstream_counterparty_refund, downstream_counterparty_refund) =
        match chain_signers.bitcoin_leg() {
            LegIdV1::Upstream => (
                ProductionCounterpartyRefundFaceV1::Bitcoin(bitcoin_refund),
                ProductionCounterpartyRefundFaceV1::Evm(evm_refund),
            ),
            LegIdV1::Downstream => (
                ProductionCounterpartyRefundFaceV1::Evm(evm_refund),
                ProductionCounterpartyRefundFaceV1::Bitcoin(bitcoin_refund),
            ),
        };
    let refund_sources = ProductionRefundArmingSourcesV1::new(
        inputs.admission(),
        inputs.composition(),
        pins.process_owner_id,
        refund_authority_epoch,
        ProductionRefundLegV1::new(upstream_dom_refund, upstream_counterparty_refund),
        ProductionRefundLegV1::new(downstream_dom_refund, downstream_counterparty_refund),
    )
    .map_err(|_| ProductionRunErrorV1::RefundArmingAuthority)?;
    let refund_path = bootstrap
        .layout()
        .refund_arming_database()
        .ok_or(ProductionRunErrorV1::RefundArmingAuthority)?;
    let refund_arming_authority = open_refund_arming_authority(
        options.mode,
        refund_stage_before_begin,
        refund_stage,
        refund_path,
        refund_arming_credential,
        refund_sources,
    )?;
    complete_provisioning_stage(
        options.mode,
        refund_stage,
        ProductionProvisioningStageV1::RefundArmingAuthority,
        &mut provisioning,
    )?;
    let (role_plan, upstream_source_scope, downstream_source_scope) =
        f6_final_claim_plan.into_parts();
    let dom_materialization_scope = ProductionDomMaterializationScopeV1::authenticate(
        &inputs,
        &role_plan,
        upstream_source_scope.clone(),
        downstream_source_scope.clone(),
    )
    .map_err(|_| ProductionRunErrorV1::SettlementChildAuthority)?;
    let upstream_dom_binding = chain_signers.dom_binding(LegIdV1::Upstream);
    let downstream_dom_binding = chain_signers.dom_binding(LegIdV1::Downstream);
    let upstream_dom_contracts = relay_stage12_owner
        .leg_mut(LegIdV1::Upstream)
        .contracts_mut()
        .dom_child_store_authority(
            upstream_dom_binding,
            inputs.composition().upstream().dom_leg.deadline,
        )
        .map_err(|_| ProductionRunErrorV1::SettlementChildAuthority)?;
    let downstream_dom_contracts = relay_stage12_owner
        .leg_mut(LegIdV1::Downstream)
        .contracts_mut()
        .dom_child_store_authority(
            downstream_dom_binding,
            inputs.composition().downstream().dom_leg.deadline,
        )
        .map_err(|_| ProductionRunErrorV1::SettlementChildAuthority)?;
    let dom_runtime = RealDomRpcRuntimeV1::new(
        relay_stage12_owner
            .take_dom_chain_adapter()
            .map_err(|_| ProductionRunErrorV1::SettlementChildAuthority)?,
        dom_history_limit,
    )
    .map_err(|_| ProductionRunErrorV1::SettlementChildAuthority)?;
    let dom_child_composition = compose_production_dom_child_port_v1(
        dom_actuator_store,
        ProductionDomChildBindingsV1 {
            sessions: [
                ProductionDomChildSessionBindingsV1 {
                    leg: settlement_coordinator::SettlementLegV1::Upstream,
                    settlement_id: inputs.composition().upstream().settlement_id.0,
                    binding: upstream_dom_binding,
                    contracts: upstream_dom_contracts,
                },
                ProductionDomChildSessionBindingsV1 {
                    leg: settlement_coordinator::SettlementLegV1::Downstream,
                    settlement_id: inputs.composition().downstream().settlement_id.0,
                    binding: downstream_dom_binding,
                    contracts: downstream_dom_contracts,
                },
            ],
            lease: dom_lease,
            trusted_chain_id: relay_stage12_owner
                .leg(LegIdV1::Upstream)
                .trusted_chain_id(),
            runtime: dom_runtime,
            route_terms_digest: inputs.admission().frozen_bindings().terms_digest,
            materialization_scope: dom_materialization_scope,
        },
    )
    .map_err(|_| ProductionRunErrorV1::SettlementChildAuthority)?;
    let (dom_child, dom_public_secret_consumers, dom_f7_scanner) = dom_child_composition.split();
    let (local_evm_signer, evm_leg, remote_evm_signer) = pending_evm_signer_pair.into_parts();
    let evm_settlement = match evm_leg {
        LegIdV1::Upstream => inputs.composition().upstream(),
        LegIdV1::Downstream => inputs.composition().downstream(),
    };
    let evm_scope = ProductionEvmMaterializationScopeV1::authenticate(
        &inputs,
        &role_plan,
        &upstream_source_scope,
        &downstream_source_scope,
        evm_leg,
    )
    .map_err(|_| ProductionRunErrorV1::SettlementChildAuthority)?;
    let local_evm_role = local_evm_signer.binding().role();
    let local_evm_lease = evm_actuator_store
        .acquire_lease_for_role(
            &evm_deployment,
            local_evm_role,
            pins.process_owner_id,
            trusted_now_millis_v1()?,
            runtime_bounds.actuator_lease_ms,
        )
        .map_err(|_| ProductionRunErrorV1::SettlementChildAuthority)?
        .lease();
    let remote_evm_transport = relay_stage12_owner
        .leg_mut(evm_leg)
        .contracts_mut()
        .evm_remote_transport_authority(
            &remote_evm_signer,
            evm_settlement.counterparty_leg.deadline,
        )
        .map_err(|_| ProductionRunErrorV1::SettlementChildAuthority)?;
    let evm_child =
        ProductionEvmChildPortV1::new_materializing(ProductionEvmMaterializingPortInputV1 {
            actuator: evm_actuator_store,
            rpc: evm_chain_client,
            deployment: evm_deployment,
            local_lease: local_evm_lease,
            clock: SystemProductionEvmChildClockV1,
            settlement: evm_settlement,
            fees: evm_fees,
            observation_valid_for_ms: operational_policies.evm_observation_valid_for_ms(),
            local_signer: Box::new(local_evm_signer),
            remote_binding: remote_evm_signer,
            remote_transport: remote_evm_transport,
            remote_custody_lease_duration_ms: operational_policies
                .evm_remote_custody_lease_duration_ms(),
            scope: evm_scope,
        })
        .map_err(|_| ProductionRunErrorV1::SettlementChildAuthority)?;
    // ------------------------------------------------------------------
    // Stage 14 — the sole Bitcoin child (funding/refund real, claim closed).
    //
    // F6 already consumed the payout proof above, so the armed owner may now
    // become the one funding authority. There is no authenticated M.8
    // participant round in this build, so the child is composed with
    // `ProductionBitcoinChildPortV1::new`: funding and refund are driven by
    // the real actuator and Core client, and every claim materialization is
    // refused by the child itself (`claim: None`). A durably recovered claim
    // contradicts that policy and refuses startup rather than being rebound
    // from caller-shaped session facts. See `PRODUCTION_KNOWN_LIMITS_V1`.
    // ------------------------------------------------------------------
    let bitcoin_leg = chain_signers.bitcoin_leg();
    let bitcoin_funding = bitcoin_prebroadcast_owner
        .into_child_handoff(&inputs)
        .map_err(|_| ProductionRunErrorV1::BitcoinChildAuthority)?
        .into_funding_only()
        .map_err(|_| ProductionRunErrorV1::BitcoinChildAuthority)?;
    let bitcoin_lease = bitcoin_actuator_store
        .acquire_lease(trusted_now_millis_v1()?, runtime_bounds.actuator_lease_ms)
        .map_err(|_| ProductionRunErrorV1::BitcoinChildAuthority)?;
    let bitcoin_child = ProductionBitcoinChildPortV1::new(
        bitcoin_actuator_store,
        bitcoin_chain_client,
        bitcoin_lease,
        SystemProductionBitcoinChildClockV1,
        bitcoin_funding,
    )
    .map_err(|_| ProductionRunErrorV1::BitcoinChildAuthority)?;
    let bitcoin_chain_id = inputs
        .admission()
        .bitcoin_deployment_capability(bitcoin_leg)
        .map_err(|_| ProductionRunErrorV1::BitcoinChildAuthority)?
        .profile()
        .chain_id
        .0;

    // ------------------------------------------------------------------
    // Stage 15 — exact child router. The DOM port is already authenticated by
    // its own composition; the EVM and Bitcoin ports are sealed here. Both
    // counterparty faces are present, so the router cannot degrade to a
    // single-face route.
    // ------------------------------------------------------------------
    let child_router = ProductionSettlementChildRouterV1::new(
        dom_child,
        Some(ProductionSettlementChildRouterV1::authenticate_evm(evm_child)),
        Some(ProductionSettlementChildRouterV1::authenticate_bitcoin(
            bitcoin_child,
        )),
    )
    .map_err(|_| ProductionRunErrorV1::SettlementChildAuthority)?;

    // ------------------------------------------------------------------
    // Stages 16-17 — first-exposure custody and the public-secret sources.
    //
    // The route reveals on the downstream DOM leg first (`DomRevealsFirst`,
    // `LocalOrigin`), so the DOM downstream consumer minted by the DOM child
    // composition is the only first-exposure observer. The upstream DOM
    // consumer has no role in this reveal mode and is released here rather
    // than parked. The Bitcoin source is late-installable and is completed by
    // the materialization owner once an exact expected transaction exists. No
    // EVM source is installed (see `PRODUCTION_KNOWN_LIMITS_V1`); the router
    // refuses EVM-scoped reextraction instead of guessing a transaction id.
    // ------------------------------------------------------------------
    let first_exposure =
        ProductionCustodiedFirstExposureClaimAuthorityV1::bind(&inputs, &role_plan)
            .map_err(|_| ProductionRunErrorV1::PlanSource)?;
    let [upstream_dom_consumer, downstream_dom_consumer] = dom_public_secret_consumers;
    drop(upstream_dom_consumer);
    let dom_trusted_chain_id = relay_stage12_owner
        .leg(LegIdV1::Downstream)
        .trusted_chain_id();
    let dom_source_scope = ProductionDomPublicSecretSourceScopeV1::authenticate(
        composition_digest,
        settlement_coordinator::SettlementLegV1::Downstream,
        inputs.composition().downstream().settlement_id.0,
        downstream_dom_binding,
        dom_trusted_chain_id,
    )
    .map_err(|_| ProductionRunErrorV1::PlanSource)?;
    let (dom_secret_source, dom_secret_installer) = relay_stage12_owner
        .leg_mut(LegIdV1::Downstream)
        .contracts_mut()
        .dom_public_secret_source(dom_source_scope, downstream_dom_consumer)
        .map_err(|_| ProductionRunErrorV1::PlanSource)?;
    let (bitcoin_secret_source, bitcoin_secret_installer) =
        ProductionLateBitcoinPublicSecretSourceV1::new_installable(
            route_id,
            composition_digest,
            bitcoin_chain_id,
        )
        .map_err(|_| ProductionRunErrorV1::PlanSource)?;
    let secret_source_router = ProductionPublicSecretSourceRouterV1::new(
        dom_secret_source,
        // No EVM reextraction source exists in this build; the type parameter
        // is pinned to an existing source type only so the router's generic
        // resolves. See `PRODUCTION_KNOWN_LIMITS_V1`.
        Option::<ProductionDomPublicSecretSourceV1>::None,
        Some(bitcoin_secret_source),
    )
    .map_err(|_| ProductionRunErrorV1::PlanSource)?;

    // ------------------------------------------------------------------
    // Stages 18-21 — materialization owner, plan source, persistence and the
    // five settlement authorities. The owner is split exactly once into the
    // draft materializer (plan source), the child runtime handle (bridge
    // child port) and the authenticated plan authority (persistence). The
    // coordinator is moved into the bridge; no second handle to it exists.
    // ------------------------------------------------------------------
    let materialization_owner = ProductionSettlementMaterializationOwnerV1::authenticate(
        &inputs,
        &coordinator,
        role_plan,
        upstream_source_scope,
        downstream_source_scope,
        child_router,
        first_exposure,
        dom_secret_installer,
        Some(bitcoin_secret_installer),
    )
    .map_err(|_| ProductionRunErrorV1::PlanSource)?;
    let (draft_materializer, child_runtime_handle, plan_authority) =
        materialization_owner.split();
    let plan_source = VerifiedProductionSettlementPlanSourceV1::new(
        route_id,
        inputs.admission().frozen_bindings().clone(),
        inputs.composition_owner(),
        secret_source_router,
        route_secret_retention,
        draft_materializer,
    )
    .map_err(|_| ProductionRunErrorV1::PlanSource)?;
    let plan_persistence = ProductionSettlementPlanPersistenceOwnerV1::new(
        plan_authority,
        trusted_now_millis_v1()?,
    )
    .map_err(|_| ProductionRunErrorV1::PlanSource)?;
    let bridge_config = ProductionSettlementBridgeConfigV1::new(
        pins.process_owner_id,
        runtime_bounds.coordinator_lease_ms,
    )
    .map_err(|_| ProductionRunErrorV1::CoordinatorStore)?;
    let settlement = assemble_production_settlement_authorities_with_child_port_v1(
        coordinator,
        bridge_config,
        plan_source,
        plan_persistence,
        child_runtime_handle,
    );

    // ------------------------------------------------------------------
    // Stages 22-24 — composite Relay/Noise loop and F6 pair activation.
    //
    // The retained Stage-12 owner moves into the composite loop here; every
    // authority that needed `&mut` access to it was derived above. Socket and
    // exchange bounds come from the authenticated V10 external-call bound and
    // the Relay poll backoff, so no timing constant is invented. Activation is
    // bounded per invocation and re-entered until the exact pair receiver
    // releases the route Store, or shutdown is requested.
    // ------------------------------------------------------------------
    let external_call_bound = Duration::from_millis(runtime_bounds.external_call_timeout_ms);
    let relay_backoff = Duration::from_millis(runtime_bounds.relay_poll_backoff_ms);
    let composite_config = ProductionCompositeLoopConfigV1::new(
        external_call_bound,
        external_call_bound,
        external_call_bound,
        relay_backoff,
        PRODUCTION_ACTIVATION_ROUND_BUDGET_V1,
    )
    .map_err(|_| ProductionRunErrorV1::CompositeLoop)?;
    let mut activation = ProductionCompositeActivationV1::new(
        relay_stage12_owner,
        f6_runtime_receiver,
        relay_network_config,
        composite_config,
    )
    .map_err(|_| ProductionRunErrorV1::CompositeLoop)?;
    let (mut relay_loop, route_store) = loop {
        match activation.activate_bounded(&mut _run_control) {
            ProductionCompositeActivationExitV1::Ready { relay, route_store } => {
                break (relay, route_store);
            }
            ProductionCompositeActivationExitV1::RoundBudgetExhausted(again) => {
                activation = again;
            }
            ProductionCompositeActivationExitV1::Shutdown(_) => {
                // Shutdown before activation: no route lease was taken and no
                // effect was externalized by this process. The retained
                // stores are closed by drop in reverse construction order.
                return Ok(());
            }
            ProductionCompositeActivationExitV1::Failed { error: _, .. } => {
                return Err(ProductionRunErrorV1::CompositeLoop);
            }
        }
    };

    // ------------------------------------------------------------------
    // Stages 25-26 — runner policy audit and route supervisor acquisition.
    //
    // The production runner is the closed external-custody-only policy; it is
    // installed only after the full-history audit proves the retained journal
    // never committed a generic runner action. The supervisor then takes the
    // one route lease under the process owner id and the authenticated V10
    // lease/renewal/dispatch bounds.
    // ------------------------------------------------------------------
    route_store
        .audit_external_custody_only_v1()
        .map_err(|_| ProductionRunErrorV1::RouteSupervisor)?;
    let per_queue_batch_limit = usize::try_from(runtime_bounds.per_queue_batch_limit)
        .map_err(|_| ProductionRunErrorV1::Configuration)?;
    let supervisor_config = RouteSupervisorConfigV1::new(
        runtime_bounds.lease_duration_ms,
        runtime_bounds.renew_before_ms,
        runtime_bounds.dispatch_lease_ms,
        per_queue_batch_limit,
    )
    .map_err(|_| ProductionRunErrorV1::RouteSupervisor)?;
    let supervisor = RouteSupervisorV1::acquire_production_route_store(
        route_store,
        route_id,
        pins.process_owner_id,
        supervisor_config,
        SystemClockV1,
    )
    .map_err(|_| ProductionRunErrorV1::RouteSupervisor)?;

    // ------------------------------------------------------------------
    // Stages 27-29 — the exact authority set and the concrete route runtime.
    // ------------------------------------------------------------------
    let operational = RouteRuntimeOperationalAuthoritiesV1 {
        refund: refund_arming_authority,
        action: settlement.action,
        observer: settlement.observer,
        runner: ProductionExternalCustodyOnlyRunnerV1,
    };
    let recovery = RouteRuntimeRecoveryAuthoritiesV1 {
        custody: settlement.custody,
        timers: deadline_timer,
        reconciler: settlement.takeover,
        retirement: settlement.retirement,
    };
    let authorities = RouteRuntimeAuthoritiesV1::new(operational, recovery);
    let runtime_config = RouteRuntimeConfigV1::new(
        runtime_bounds.waiting_backoff_ms,
        runtime_bounds.recovery_backoff_ms,
        supervisor_config,
    )
    .map_err(|_| ProductionRunErrorV1::RouteRuntime)?;
    let mut route_runtime = ProductionRouteRuntimeV1::new(
        supervisor,
        inputs.admission().clone(),
        authorities,
        runtime_config,
    )
    .map_err(|_| ProductionRunErrorV1::RouteRuntime)?;

    // ------------------------------------------------------------------
    // Stages 30-31 — interleaved Relay/route execution until terminal or safe
    // shutdown. Each invocation is bounded; budget exhaustion re-enters the
    // same loop with the same owners, so the bound limits blocking, not the
    // route. Every route step is a durable driver call; nothing here reports
    // progress the Store has not recorded.
    // ------------------------------------------------------------------
    let _retained_for_f7_m8 = (chain_signers, dom_f7_scanner, bitcoin_live, operational_policies);
    loop {
        match run_production_composite_runtime_bounded_v1(
            &mut relay_loop,
            &mut route_runtime,
            &mut _run_control,
            PRODUCTION_INTERLEAVED_ROUND_BUDGET_V1,
        )
        .map_err(|_| ProductionRunErrorV1::RouteRuntime)?
        {
            ProductionCompositeRuntimeExitV1::Terminal { .. }
            | ProductionCompositeRuntimeExitV1::Shutdown { .. } => break,
            ProductionCompositeRuntimeExitV1::RoundBudgetExhausted { .. } => {}
        }
    }

    // ------------------------------------------------------------------
    // Stages 32-33 — teardown in reverse ownership order. The route runtime
    // (and its lease) goes first, then the Relay loop and its Noise sessions,
    // then every retained store by scope exit; the signal-bridge guard is the
    // last to drop and restores the prior mask on this return path.
    // ------------------------------------------------------------------
    drop(route_runtime);
    drop(relay_loop);
    Ok(())
}

/// Bounded Relay rounds per activation invocation. The composition root
/// re-enters activation on exhaustion, so this bounds blocking between
/// shutdown checks, not the activation itself.
const PRODUCTION_ACTIVATION_ROUND_BUDGET_V1: u64 = 4_096;

/// Bounded interleaved rounds per runtime invocation, re-entered on
/// exhaustion for the same reason.
const PRODUCTION_INTERLEAVED_ROUND_BUDGET_V1: u64 = 4_096;

fn required_f6_v4_path<'bootstrap>(
    bootstrap: &'bootstrap ValidatedProductionBootstrapV1,
    role: ProductionF6PathRoleV4,
) -> Result<&'bootstrap Path, ProductionRunErrorV1> {
    bootstrap
        .layout()
        .f6_path_v4(role)
        .ok_or(ProductionRunErrorV1::F6Authorities)
}

fn require_f6_stage_open_state(
    mode: ProductionRunModeV1,
    state: ProductionProvisioningStageStateV1,
) -> Result<(), ProductionRunErrorV1> {
    if matches!(
        (mode, state),
        (
            ProductionRunModeV1::Create,
            ProductionProvisioningStageStateV1::Started
                | ProductionProvisioningStageStateV1::Complete
        ) | (
            ProductionRunModeV1::ReopenExisting,
            ProductionProvisioningStageStateV1::Complete
        )
    ) {
        Ok(())
    } else {
        Err(ProductionRunErrorV1::Provisioning)
    }
}

fn required_f6_v8_path<'bootstrap>(
    bootstrap: &'bootstrap ValidatedProductionBootstrapV1,
    role: ProductionF6PathRoleV8,
) -> Result<&'bootstrap Path, ProductionRunErrorV1> {
    bootstrap
        .layout()
        .f6_path_v8(role)
        .ok_or(ProductionRunErrorV1::F6Authorities)
}

fn authenticate_dom_f6_payouts(
    inputs: &AuthenticatedProductionInputsV1,
    chain_signers: &mut ProductionChainSignerAuthoritiesV1,
    store: &mut DomActuatorStoreV1,
    owner_id: [u8; 32],
    now_unix_ms: u64,
    lease_duration_ms: u64,
) -> Result<
    (
        AuthenticatedDomPayoutFaceV1,
        AuthenticatedDomPayoutFaceV1,
        DomLeaseV1,
    ),
    ProductionRunErrorV1,
> {
    let participant = chain_signers.participant_id();
    let lease = store
        .acquire_lease(participant.0, owner_id, now_unix_ms, lease_duration_ms)
        .map_err(|_| ProductionRunErrorV1::F6Authorities)?;
    let upstream_binding = chain_signers.dom_binding(LegIdV1::Upstream);
    let downstream_binding = chain_signers.dom_binding(LegIdV1::Downstream);
    store
        .bind_session(lease, upstream_binding, now_unix_ms)
        .map_err(|_| ProductionRunErrorV1::F6Authorities)?;
    store
        .bind_session(lease, downstream_binding, now_unix_ms)
        .map_err(|_| ProductionRunErrorV1::F6Authorities)?;

    let upstream_value = u64::try_from(inputs.composition().upstream().dom_leg.amount)
        .map_err(|_| ProductionRunErrorV1::F6Authorities)?;
    let downstream_value = u64::try_from(inputs.composition().downstream().dom_leg.amount)
        .map_err(|_| ProductionRunErrorV1::F6Authorities)?;
    let upstream_request = DomPayoutFaceSelectionRequestV1::new(upstream_value, now_unix_ms)
        .map_err(|_| ProductionRunErrorV1::F6Authorities)?;
    let downstream_request = DomPayoutFaceSelectionRequestV1::new(downstream_value, now_unix_ms)
        .map_err(|_| ProductionRunErrorV1::F6Authorities)?;
    let upstream = {
        let mut authority = chain_signers
            .dom_authority(LegIdV1::Upstream)
            .map_err(|_| ProductionRunErrorV1::F6Authorities)?;
        authority
            .wallet()
            .authenticate_unique_payout_face(store, lease, upstream_request)
            .map_err(|_| ProductionRunErrorV1::F6Authorities)?
    };
    let downstream = {
        let mut authority = chain_signers
            .dom_authority(LegIdV1::Downstream)
            .map_err(|_| ProductionRunErrorV1::F6Authorities)?;
        authority
            .wallet()
            .authenticate_unique_payout_face(store, lease, downstream_request)
            .map_err(|_| ProductionRunErrorV1::F6Authorities)?
    };
    Ok((upstream, downstream, lease))
}

fn selected_counterparty_deployments(
    inputs: &AuthenticatedProductionInputsV1,
) -> Result<(ResolvedEvmDeploymentV1, ResolvedBitcoinDeploymentV1), ProductionRunErrorV1> {
    let mut evm = None;
    let mut bitcoin = None;
    for leg in [LegIdV1::Upstream, LegIdV1::Downstream] {
        match (inputs.evm_session(leg), inputs.bitcoin_session(leg)) {
            (Some(session), None) if evm.is_none() => {
                evm = Some(
                    inputs
                        .admission()
                        .evm_deployment_capability(leg, session)
                        .map_err(|_| ProductionRunErrorV1::ChainServices)?,
                );
            }
            (None, Some(_session)) if bitcoin.is_none() => {
                bitcoin = Some(
                    inputs
                        .admission()
                        .bitcoin_deployment_capability(leg)
                        .map_err(|_| ProductionRunErrorV1::ChainServices)?,
                );
            }
            (Some(_), Some(_)) | (Some(_), None) | (None, Some(_)) | (None, None) => {
                return Err(ProductionRunErrorV1::ChainServices);
            }
        }
    }
    evm.zip(bitcoin).ok_or(ProductionRunErrorV1::ChainServices)
}

/// One authenticated local signer plus the exact move-only handoff policy for
/// the complementary role owned by the counterparty daemon.
///
/// The remote side is deliberately not a `ScopedEip1559SignerV1`: its key
/// never enters this process.  The retained binding can mint only public 0x15
/// requests and can import a response only through the Contracts Store's
/// one-shot `PreparedEvmSignedActionImportV1` capability.
struct PendingEvmSignerPairV1 {
    local_signer: ProductionScopedEip1559SignerV1,
    local_leg: LegIdV1,
    remote_signer: ProductionEvmRemoteSignerBindingV1,
}

impl PendingEvmSignerPairV1 {
    /// Consumes the pre-runtime owner exactly once.  Keeping the leg beside
    /// both complementary signer authorities prevents the Stage-13 wiring
    /// from re-deriving a role from caller-shaped account bytes.
    fn into_parts(
        self,
    ) -> (
        ProductionScopedEip1559SignerV1,
        LegIdV1,
        ProductionEvmRemoteSignerBindingV1,
    ) {
        (self.local_signer, self.local_leg, self.remote_signer)
    }
}

fn bind_single_local_evm_signer(
    inputs: &AuthenticatedProductionInputsV1,
    credential: ProductionEvmLocalCredentialV1,
    owner_id: [u8; 32],
) -> Result<PendingEvmSignerPairV1, ProductionRunErrorV1> {
    let mut selected = None;
    for leg in [LegIdV1::Upstream, LegIdV1::Downstream] {
        let Some(session) = inputs.evm_session(leg) else {
            continue;
        };
        if selected.is_some() {
            return Err(ProductionRunErrorV1::EvmSignerAuthority);
        }
        let deployment = inputs
            .admission()
            .evm_deployment_capability(leg, session)
            .map_err(|_| ProductionRunErrorV1::EvmSignerAuthority)?;
        selected = Some((leg, session, deployment));
    }
    let Some((local_leg, session, deployment)) = selected else {
        return Err(ProductionRunErrorV1::EvmSignerAuthority);
    };
    let adapter = deployment.adapter_config();
    let account = credential.account();
    let (local_role, remote_role) =
        exact_local_evm_roles(account, adapter.funder, adapter.beneficiary)?;
    let binding = ProductionEvmSignerBindingV1::new(ProductionEvmSignerPinsV1 {
        route_id: inputs.admission().route_id(),
        registry_digest: deployment.registry_digest(),
        profile_digest: deployment.profile_digest(),
        asset_binding_digest: deployment.asset_binding_digest(),
        deployment_digest: deployment.deployment().deployment_digest,
        terms_digest: session.settlement_terms_digest(),
        chain_id: adapter.chain_id,
        contract: adapter.contract,
        account,
        role: local_role,
    })
    .map_err(|_| ProductionRunErrorV1::EvmSignerAuthority)?;
    let local_signer = credential
        .bind(binding)
        .map_err(|_| ProductionRunErrorV1::EvmSignerAuthority)?;
    let settlement = match local_leg {
        LegIdV1::Upstream => inputs.composition().upstream(),
        LegIdV1::Downstream => inputs.composition().downstream(),
    };
    let (requester_id, signer_id) = match local_role {
        EvmSignerRoleV1::Funder => (
            settlement.counterparty_leg.refund_to.0,
            settlement.counterparty_leg.beneficiary.0,
        ),
        EvmSignerRoleV1::Beneficiary => (
            settlement.counterparty_leg.beneficiary.0,
            settlement.counterparty_leg.refund_to.0,
        ),
    };
    let remote_account = match remote_role {
        EvmSignerRoleV1::Funder => adapter.funder,
        EvmSignerRoleV1::Beneficiary => adapter.beneficiary,
    };
    let remote_signer = ProductionEvmRemoteSignerBindingV1::new(ProductionEvmRemoteSignerPinsV1 {
        route_id: inputs.admission().route_id(),
        session_id: settlement.session_id.0,
        settlement_id: settlement.settlement_id.0,
        terms_digest: session.settlement_terms_digest(),
        registry_digest: deployment.registry_digest(),
        profile_digest: deployment.profile_digest(),
        deployment_digest: deployment.deployment().deployment_digest,
        composition_digest: inputs.composition().binding_digest(),
        chain_id: adapter.chain_id,
        contract: adapter.contract,
        signer_account: remote_account,
        role: remote_role,
        requester_id,
        signer_id,
        owner_id,
    })
    .map_err(|_| ProductionRunErrorV1::EvmSignerAuthority)?;
    Ok(PendingEvmSignerPairV1 {
        local_signer,
        local_leg,
        remote_signer,
    })
}

fn exact_local_evm_roles(
    local_account: [u8; 20],
    funder: [u8; 20],
    beneficiary: [u8; 20],
) -> Result<(EvmSignerRoleV1, EvmSignerRoleV1), ProductionRunErrorV1> {
    match (local_account == funder, local_account == beneficiary) {
        (true, false) => Ok((EvmSignerRoleV1::Funder, EvmSignerRoleV1::Beneficiary)),
        (false, true) => Ok((EvmSignerRoleV1::Beneficiary, EvmSignerRoleV1::Funder)),
        (false, false) | (true, true) => Err(ProductionRunErrorV1::EvmSignerAuthority),
    }
}

fn open_route_secret_retention(
    mode: ProductionRunModeV1,
    stage_before_begin: ProductionProvisioningStageStateV1,
    stage: ProductionProvisioningStageStateV1,
    state_capability: Arc<Dir>,
    key: RouteSecretSealKeyV1,
) -> Result<ProductionPublicSecretRetentionV1, ProductionRunErrorV1> {
    let vault = match (mode, stage) {
        (ProductionRunModeV1::Create, ProductionProvisioningStageStateV1::Started) => {
            if stage_before_begin == ProductionProvisioningStageStateV1::Absent {
                DurableRouteSecretVaultV1::create_production(
                    state_capability,
                    ROUTE_SECRET_VAULT_ROOT_NAME_V1,
                )
            } else if stage_before_begin == ProductionProvisioningStageStateV1::Started {
                match state_capability.symlink_metadata(ROUTE_SECRET_VAULT_ROOT_NAME_V1) {
                    Ok(_) => DurableRouteSecretVaultV1::resume_create_production(
                        state_capability,
                        ROUTE_SECRET_VAULT_ROOT_NAME_V1,
                    ),
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                        DurableRouteSecretVaultV1::create_production(
                            state_capability,
                            ROUTE_SECRET_VAULT_ROOT_NAME_V1,
                        )
                    }
                    Err(_) => return Err(ProductionRunErrorV1::RouteSecretVault),
                }
            } else {
                return Err(ProductionRunErrorV1::Provisioning);
            }
        }
        (ProductionRunModeV1::Create, ProductionProvisioningStageStateV1::Complete) => {
            DurableRouteSecretVaultV1::open_production(
                state_capability,
                ROUTE_SECRET_VAULT_ROOT_NAME_V1,
                &key,
            )
        }
        (ProductionRunModeV1::Create, _) => {
            return Err(ProductionRunErrorV1::Provisioning);
        }
        (ProductionRunModeV1::ReopenExisting, ProductionProvisioningStageStateV1::Complete) => {
            DurableRouteSecretVaultV1::open_production(
                state_capability,
                ROUTE_SECRET_VAULT_ROOT_NAME_V1,
                &key,
            )
        }
        (ProductionRunModeV1::ReopenExisting, _) => {
            return Err(ProductionRunErrorV1::Provisioning);
        }
    }
    .map_err(|_| ProductionRunErrorV1::RouteSecretVault)?;
    Ok(ProductionPublicSecretRetentionV1::new(vault, key))
}

struct ProductionContractsStoresV1 {
    upstream: ContractsSessionStoreV1,
    downstream: ContractsSessionStoreV1,
}

struct ContractsStorePairRequestV1<'a> {
    mode: ProductionRunModeV1,
    stage_before_begin: ProductionProvisioningStageStateV1,
    stage: ProductionProvisioningStageStateV1,
    parent: Arc<Dir>,
    upstream_root: &'a str,
    downstream_root: &'a str,
    policy: BudgetPolicyV1,
    creation_binding: [u8; 32],
}

enum PreparedContractsStoreProvisioningV1<'a> {
    Pristine {
        parent: Arc<Dir>,
        root_name: &'a str,
        policy: BudgetPolicyV1,
        creation_binding: [u8; 32],
    },
    CompleteBound(PreparedContractsSessionStoreOpenV1),
}

impl PreparedContractsStoreProvisioningV1<'_> {
    fn finish(self) -> Result<ContractsSessionStoreV1, ProductionRunErrorV1> {
        match self {
            Self::Pristine {
                parent,
                root_name,
                policy,
                creation_binding,
            } => ContractsSessionStoreV1::resume_create_production(
                parent,
                root_name,
                policy,
                creation_binding,
            ),
            Self::CompleteBound(prepared) => prepared.finish(),
        }
        .map_err(|_| ProductionRunErrorV1::ContractsStores)
    }
}

fn load_contracts_budget_policy(
    bootstrap: &ValidatedProductionBootstrapV1,
) -> Result<BudgetPolicyV1, ProductionRunErrorV1> {
    let path = bootstrap
        .layout()
        .contracts_budget_policy()
        .ok_or(ProductionRunErrorV1::ContractsStores)?;
    let bytes = read_owner_file_bounded(
        path,
        BUDGET_POLICY_LEN as u64,
        ProductionConfigErrorV1::InputArtifactUnavailable,
    )
    .map_err(|_| ProductionRunErrorV1::ContractsStores)?;
    let policy =
        BudgetPolicyV1::from_bytes(&bytes).map_err(|_| ProductionRunErrorV1::ContractsStores)?;
    if policy.profile() != BudgetPolicyProfileV1::ProductionRatified {
        return Err(ProductionRunErrorV1::ContractsStores);
    }
    Ok(policy)
}

fn contracts_root_name<'a>(
    state_dir: &Path,
    contracts_path: &'a Path,
) -> Result<&'a str, ProductionRunErrorV1> {
    if contracts_path.parent() != Some(state_dir) {
        return Err(ProductionRunErrorV1::ContractsStores);
    }
    contracts_path
        .file_name()
        .and_then(|name| name.to_str())
        .filter(|name| !name.is_empty())
        .ok_or(ProductionRunErrorV1::ContractsStores)
}

fn preflight_contracts_store_pair(
    parent: Arc<Dir>,
    upstream_root: &str,
    downstream_root: &str,
    policy: &BudgetPolicyV1,
    creation_binding: [u8; 32],
    allow_complete_bound: bool,
) -> Result<(), ProductionRunErrorV1> {
    let upstream = prepare_contracts_store_provisioning(
        Arc::clone(&parent),
        upstream_root,
        policy.clone(),
        creation_binding,
        allow_complete_bound,
    )?;
    let downstream = prepare_contracts_store_provisioning(
        parent,
        downstream_root,
        policy.clone(),
        creation_binding,
        allow_complete_bound,
    )?;
    drop((upstream, downstream));
    Ok(())
}

fn prepare_contracts_store_provisioning<'a>(
    parent: Arc<Dir>,
    root_name: &'a str,
    policy: BudgetPolicyV1,
    creation_binding: [u8; 32],
    allow_complete_bound: bool,
) -> Result<PreparedContractsStoreProvisioningV1<'a>, ProductionRunErrorV1> {
    match ContractsSessionStoreV1::preflight_resume_create_production(
        Arc::clone(&parent),
        root_name,
        &policy,
        creation_binding,
    ) {
        Ok(()) => Ok(PreparedContractsStoreProvisioningV1::Pristine {
            parent,
            root_name,
            policy,
            creation_binding,
        }),
        Err(_) if allow_complete_bound => {
            let prepared = ContractsSessionStoreV1::prepare_open_resumed_production(
                parent,
                root_name,
                policy,
                creation_binding,
            )
            .map_err(|_| ProductionRunErrorV1::ContractsStores)?;
            Ok(PreparedContractsStoreProvisioningV1::CompleteBound(
                prepared,
            ))
        }
        Err(_) => Err(ProductionRunErrorV1::ContractsStores),
    }
}

fn open_contracts_store_pair(
    request: ContractsStorePairRequestV1<'_>,
) -> Result<ProductionContractsStoresV1, ProductionRunErrorV1> {
    let ContractsStorePairRequestV1 {
        mode,
        stage_before_begin,
        stage,
        parent,
        upstream_root,
        downstream_root,
        policy,
        creation_binding,
    } = request;
    match (mode, stage) {
        (ProductionRunModeV1::Create, ProductionProvisioningStageStateV1::Started) => {
            if !matches!(
                stage_before_begin,
                ProductionProvisioningStageStateV1::Absent
                    | ProductionProvisioningStageStateV1::Started
            ) {
                return Err(ProductionRunErrorV1::Provisioning);
            }
            preflight_contracts_store_pair(
                Arc::clone(&parent),
                upstream_root,
                downstream_root,
                &policy,
                creation_binding,
                stage_before_begin == ProductionProvisioningStageStateV1::Started,
            )?;
            let upstream = prepare_contracts_store_provisioning(
                Arc::clone(&parent),
                upstream_root,
                policy.clone(),
                creation_binding,
                stage_before_begin == ProductionProvisioningStageStateV1::Started,
            )?;
            let downstream = prepare_contracts_store_provisioning(
                parent,
                downstream_root,
                policy,
                creation_binding,
                stage_before_begin == ProductionProvisioningStageStateV1::Started,
            )?;
            let upstream = upstream.finish()?;
            let downstream = downstream.finish()?;
            Ok(ProductionContractsStoresV1 {
                upstream,
                downstream,
            })
        }
        (ProductionRunModeV1::Create, ProductionProvisioningStageStateV1::Complete)
        | (ProductionRunModeV1::ReopenExisting, ProductionProvisioningStageStateV1::Complete) => {
            let upstream = ContractsSessionStoreV1::prepare_open_production(
                Arc::clone(&parent),
                upstream_root,
                policy.clone(),
            )
            .map_err(|_| ProductionRunErrorV1::ContractsStores)?;
            let downstream =
                ContractsSessionStoreV1::prepare_open_production(parent, downstream_root, policy)
                    .map_err(|_| ProductionRunErrorV1::ContractsStores)?;
            let upstream = upstream
                .finish()
                .map_err(|_| ProductionRunErrorV1::ContractsStores)?;
            let downstream = downstream
                .finish()
                .map_err(|_| ProductionRunErrorV1::ContractsStores)?;
            Ok(ProductionContractsStoresV1 {
                upstream,
                downstream,
            })
        }
        (ProductionRunModeV1::Create, _) | (ProductionRunModeV1::ReopenExisting, _) => {
            Err(ProductionRunErrorV1::Provisioning)
        }
    }
}

fn require_vault_create_prefix_absent(state_capability: &Dir) -> Result<(), ProductionRunErrorV1> {
    match state_capability.symlink_metadata(ROUTE_SECRET_VAULT_ROOT_NAME_V1) {
        Ok(_) => Err(ProductionRunErrorV1::RouteSecretVault),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(ProductionRunErrorV1::RouteSecretVault),
    }
}

fn require_reopen_provisioning_prefix(
    provisioning: &DurableProductionProvisioningJournalV1,
) -> Result<(), ProductionRunErrorV1> {
    for stage in [
        ProductionProvisioningStageV1::TimeAnchorStore,
        ProductionProvisioningStageV1::RouteStore,
        ProductionProvisioningStageV1::RouteSecretVault,
        ProductionProvisioningStageV1::CoordinatorStore,
        ProductionProvisioningStageV1::DomActuatorStore,
        ProductionProvisioningStageV1::EvmActuatorStore,
        ProductionProvisioningStageV1::BitcoinActuatorStore,
        ProductionProvisioningStageV1::ChainSignerAuthorities,
        ProductionProvisioningStageV1::SolverInventoryStore,
        ProductionProvisioningStageV1::ContractsStores,
        ProductionProvisioningStageV1::F6Authorities,
        ProductionProvisioningStageV1::RelayAuthorities,
        ProductionProvisioningStageV1::RefundArmingAuthority,
    ] {
        if provisioning
            .stage_state(stage)
            .map_err(|_| ProductionRunErrorV1::Provisioning)?
            != ProductionProvisioningStageStateV1::Complete
        {
            return Err(ProductionRunErrorV1::Provisioning);
        }
    }
    Ok(())
}

fn open_refund_arming_authority(
    mode: ProductionRunModeV1,
    stage_before_begin: ProductionProvisioningStageStateV1,
    stage: ProductionProvisioningStageStateV1,
    path: &Path,
    credential: ProductionRefundArmingCredentialV1,
    sources: ProductionRefundArmingSourcesV1<'_>,
) -> Result<ProductionRefundArmingAuthorityV1, ProductionRunErrorV1> {
    let lock_present = path_entry_present(&actuator_process_lock_path(path))
        .map_err(|_| ProductionRunErrorV1::RefundArmingAuthority)?;
    let database_present =
        path_entry_present(path).map_err(|_| ProductionRunErrorV1::RefundArmingAuthority)?;
    let opened = match refund_arming_open_mode(
        mode,
        stage_before_begin,
        stage,
        lock_present,
        database_present,
    )? {
        RefundArmingOpenModeV1::Create => {
            ProductionRefundArmingAuthorityV1::create(path, credential, sources)
        }
        RefundArmingOpenModeV1::ResumeCreate => {
            ProductionRefundArmingAuthorityV1::resume_create_production(path, credential, sources)
        }
        RefundArmingOpenModeV1::OpenExisting => {
            ProductionRefundArmingAuthorityV1::open_existing(path, credential, sources)
        }
    };
    opened.map_err(|_| ProductionRunErrorV1::RefundArmingAuthority)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RefundArmingOpenModeV1 {
    Create,
    ResumeCreate,
    OpenExisting,
}

fn refund_arming_open_mode(
    mode: ProductionRunModeV1,
    stage_before_begin: ProductionProvisioningStageStateV1,
    stage: ProductionProvisioningStageStateV1,
    lock_present: bool,
    database_present: bool,
) -> Result<RefundArmingOpenModeV1, ProductionRunErrorV1> {
    match (
        mode,
        stage_before_begin,
        stage,
        lock_present,
        database_present,
    ) {
        (
            ProductionRunModeV1::Create,
            ProductionProvisioningStageStateV1::Absent
            | ProductionProvisioningStageStateV1::Started,
            ProductionProvisioningStageStateV1::Started,
            false,
            false,
        ) => Ok(RefundArmingOpenModeV1::Create),
        (
            ProductionRunModeV1::Create,
            ProductionProvisioningStageStateV1::Started,
            ProductionProvisioningStageStateV1::Started,
            true,
            _,
        ) => Ok(RefundArmingOpenModeV1::ResumeCreate),
        (
            ProductionRunModeV1::Create | ProductionRunModeV1::ReopenExisting,
            ProductionProvisioningStageStateV1::Complete,
            ProductionProvisioningStageStateV1::Complete,
            true,
            true,
        ) => Ok(RefundArmingOpenModeV1::OpenExisting),
        _ => Err(ProductionRunErrorV1::RefundArmingAuthority),
    }
}

fn open_settlement_coordinator(
    mode: ProductionRunModeV1,
    stage_before_begin: ProductionProvisioningStageStateV1,
    stage: ProductionProvisioningStageStateV1,
    path: &Path,
    coordinator_id: [u8; 32],
    plan_authority_id: [u8; 32],
    now_unix_ms: u64,
) -> Result<DurableSettlementCoordinatorV1, ProductionRunErrorV1> {
    match (mode, stage) {
        (ProductionRunModeV1::Create, ProductionProvisioningStageStateV1::Started) => {
            if stage_before_begin == ProductionProvisioningStageStateV1::Absent {
                return DurableSettlementCoordinatorV1::create(
                    path,
                    coordinator_id,
                    plan_authority_id,
                    now_unix_ms,
                )
                .map_err(|_| ProductionRunErrorV1::CoordinatorStore);
            }
            if stage_before_begin != ProductionProvisioningStageStateV1::Started {
                return Err(ProductionRunErrorV1::Provisioning);
            }
            if path_entry_present(&coordinator_process_lock_path(path))
                .map_err(|_| ProductionRunErrorV1::CoordinatorStore)?
            {
                DurableSettlementCoordinatorV1::resume_create_production(
                    path,
                    coordinator_id,
                    plan_authority_id,
                    now_unix_ms,
                )
            } else if path_entry_present(path)
                .map_err(|_| ProductionRunErrorV1::CoordinatorStore)?
            {
                return Err(ProductionRunErrorV1::CoordinatorStore);
            } else {
                DurableSettlementCoordinatorV1::create(
                    path,
                    coordinator_id,
                    plan_authority_id,
                    now_unix_ms,
                )
            }
        }
        (
            ProductionRunModeV1::Create | ProductionRunModeV1::ReopenExisting,
            ProductionProvisioningStageStateV1::Complete,
        ) => DurableSettlementCoordinatorV1::open_existing(path, coordinator_id, plan_authority_id),
        _ => return Err(ProductionRunErrorV1::Provisioning),
    }
    .map_err(|_| ProductionRunErrorV1::CoordinatorStore)
}

fn require_coordinator_create_prefix_absent(path: &Path) -> Result<(), ProductionRunErrorV1> {
    if path_entry_present(path).map_err(|_| ProductionRunErrorV1::CoordinatorStore)?
        || path_entry_present(&coordinator_process_lock_path(path))
            .map_err(|_| ProductionRunErrorV1::CoordinatorStore)?
    {
        return Err(ProductionRunErrorV1::CoordinatorStore);
    }
    Ok(())
}

fn path_entry_present(path: &Path) -> std::io::Result<bool> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error),
    }
}

fn open_dom_actuator_store(
    mode: ProductionRunModeV1,
    stage_before_begin: ProductionProvisioningStageStateV1,
    stage: ProductionProvisioningStageStateV1,
    path: &Path,
) -> Result<DomActuatorStoreV1, ProductionRunErrorV1> {
    match (mode, stage) {
        (ProductionRunModeV1::Create, ProductionProvisioningStageStateV1::Started) => {
            if stage_before_begin == ProductionProvisioningStageStateV1::Absent {
                return DomActuatorStoreV1::create(path)
                    .map_err(|_| ProductionRunErrorV1::DomActuatorStore);
            }
            if stage_before_begin != ProductionProvisioningStageStateV1::Started {
                return Err(ProductionRunErrorV1::Provisioning);
            }
            if path_entry_present(&dom_actuator_process_lock_path(path))
                .map_err(|_| ProductionRunErrorV1::DomActuatorStore)?
            {
                DomActuatorStoreV1::resume_create_production(path)
            } else if path_entry_present(path)
                .map_err(|_| ProductionRunErrorV1::DomActuatorStore)?
            {
                return Err(ProductionRunErrorV1::DomActuatorStore);
            } else {
                DomActuatorStoreV1::create(path)
            }
        }
        (
            ProductionRunModeV1::Create | ProductionRunModeV1::ReopenExisting,
            ProductionProvisioningStageStateV1::Complete,
        ) => DomActuatorStoreV1::open_existing(path),
        _ => return Err(ProductionRunErrorV1::Provisioning),
    }
    .map_err(|_| ProductionRunErrorV1::DomActuatorStore)
}

fn require_dom_actuator_create_prefix_absent(path: &Path) -> Result<(), ProductionRunErrorV1> {
    if path_entry_present(path).map_err(|_| ProductionRunErrorV1::DomActuatorStore)?
        || path_entry_present(&dom_actuator_process_lock_path(path))
            .map_err(|_| ProductionRunErrorV1::DomActuatorStore)?
    {
        return Err(ProductionRunErrorV1::DomActuatorStore);
    }
    Ok(())
}

fn complete_provisioning_stage(
    mode: ProductionRunModeV1,
    state: ProductionProvisioningStageStateV1,
    stage: ProductionProvisioningStageV1,
    provisioning: &mut DurableProductionProvisioningJournalV1,
) -> Result<(), ProductionRunErrorV1> {
    if mode == ProductionRunModeV1::Create && state != ProductionProvisioningStageStateV1::Complete
    {
        provisioning
            .complete(stage)
            .map_err(|_| ProductionRunErrorV1::Provisioning)
    } else if state == ProductionProvisioningStageStateV1::Complete {
        Ok(())
    } else {
        Err(ProductionRunErrorV1::Provisioning)
    }
}

fn open_evm_actuator_store(
    mode: ProductionRunModeV1,
    stage_before_begin: ProductionProvisioningStageStateV1,
    stage: ProductionProvisioningStageStateV1,
    path: &Path,
) -> Result<DurableEvmActuatorV1, ProductionRunErrorV1> {
    match (mode, stage) {
        (ProductionRunModeV1::Create, ProductionProvisioningStageStateV1::Started) => {
            if stage_before_begin == ProductionProvisioningStageStateV1::Absent {
                return DurableEvmActuatorV1::create(path)
                    .map_err(|_| ProductionRunErrorV1::EvmActuatorStore);
            }
            if stage_before_begin != ProductionProvisioningStageStateV1::Started {
                return Err(ProductionRunErrorV1::Provisioning);
            }
            if path_entry_present(&actuator_process_lock_path(path))
                .map_err(|_| ProductionRunErrorV1::EvmActuatorStore)?
            {
                DurableEvmActuatorV1::resume_create_production(path)
            } else if path_entry_present(path)
                .map_err(|_| ProductionRunErrorV1::EvmActuatorStore)?
            {
                return Err(ProductionRunErrorV1::EvmActuatorStore);
            } else {
                DurableEvmActuatorV1::create(path)
            }
        }
        (
            ProductionRunModeV1::Create | ProductionRunModeV1::ReopenExisting,
            ProductionProvisioningStageStateV1::Complete,
        ) => DurableEvmActuatorV1::open_existing(path),
        _ => return Err(ProductionRunErrorV1::Provisioning),
    }
    .map_err(|_| ProductionRunErrorV1::EvmActuatorStore)
}

fn require_evm_actuator_create_prefix_absent(path: &Path) -> Result<(), ProductionRunErrorV1> {
    if path_entry_present(path).map_err(|_| ProductionRunErrorV1::EvmActuatorStore)?
        || path_entry_present(&actuator_process_lock_path(path))
            .map_err(|_| ProductionRunErrorV1::EvmActuatorStore)?
    {
        return Err(ProductionRunErrorV1::EvmActuatorStore);
    }
    Ok(())
}

fn open_bitcoin_actuator_store(
    mode: ProductionRunModeV1,
    stage_before_begin: ProductionProvisioningStageStateV1,
    stage: ProductionProvisioningStageStateV1,
    path: &Path,
    owner_id: [u8; 32],
) -> Result<DurableBitcoinActuatorV1, ProductionRunErrorV1> {
    match (mode, stage) {
        (ProductionRunModeV1::Create, ProductionProvisioningStageStateV1::Started) => {
            if stage_before_begin == ProductionProvisioningStageStateV1::Absent {
                return DurableBitcoinActuatorV1::create(path, owner_id)
                    .map_err(|_| ProductionRunErrorV1::BitcoinActuatorStore);
            }
            if stage_before_begin != ProductionProvisioningStageStateV1::Started {
                return Err(ProductionRunErrorV1::Provisioning);
            }
            if path_entry_present(&actuator_process_lock_path(path))
                .map_err(|_| ProductionRunErrorV1::BitcoinActuatorStore)?
            {
                DurableBitcoinActuatorV1::resume_create_production(path, owner_id)
            } else if path_entry_present(path)
                .map_err(|_| ProductionRunErrorV1::BitcoinActuatorStore)?
            {
                return Err(ProductionRunErrorV1::BitcoinActuatorStore);
            } else {
                DurableBitcoinActuatorV1::create(path, owner_id)
            }
        }
        (
            ProductionRunModeV1::Create | ProductionRunModeV1::ReopenExisting,
            ProductionProvisioningStageStateV1::Complete,
        ) => DurableBitcoinActuatorV1::open_existing(path, owner_id),
        _ => return Err(ProductionRunErrorV1::Provisioning),
    }
    .map_err(|_| ProductionRunErrorV1::BitcoinActuatorStore)
}

fn open_solver_inventory_store(
    mode: ProductionRunModeV1,
    stage_before_begin: ProductionProvisioningStageStateV1,
    stage: ProductionProvisioningStageStateV1,
    path: &Path,
    binding_digest: [u8; 32],
) -> Result<DurableInventoryStoreV1, ProductionRunErrorV1> {
    match (mode, stage) {
        (ProductionRunModeV1::Create, ProductionProvisioningStageStateV1::Started) => {
            if stage_before_begin == ProductionProvisioningStageStateV1::Absent {
                return DurableInventoryStoreV1::create(path, binding_digest)
                    .map_err(|_| ProductionRunErrorV1::SolverInventoryStore);
            }
            if stage_before_begin != ProductionProvisioningStageStateV1::Started {
                return Err(ProductionRunErrorV1::Provisioning);
            }
            if path_entry_present(&actuator_process_lock_path(path))
                .map_err(|_| ProductionRunErrorV1::SolverInventoryStore)?
            {
                DurableInventoryStoreV1::resume_create_production(path, binding_digest)
            } else if path_entry_present(path)
                .map_err(|_| ProductionRunErrorV1::SolverInventoryStore)?
            {
                return Err(ProductionRunErrorV1::SolverInventoryStore);
            } else {
                DurableInventoryStoreV1::create(path, binding_digest)
            }
        }
        (
            ProductionRunModeV1::Create | ProductionRunModeV1::ReopenExisting,
            ProductionProvisioningStageStateV1::Complete,
        ) => DurableInventoryStoreV1::open_existing(path, binding_digest),
        _ => return Err(ProductionRunErrorV1::Provisioning),
    }
    .map_err(|_| ProductionRunErrorV1::SolverInventoryStore)
}

fn require_solver_inventory_create_prefix_absent(path: &Path) -> Result<(), ProductionRunErrorV1> {
    if path_entry_present(path).map_err(|_| ProductionRunErrorV1::SolverInventoryStore)?
        || path_entry_present(&actuator_process_lock_path(path))
            .map_err(|_| ProductionRunErrorV1::SolverInventoryStore)?
    {
        return Err(ProductionRunErrorV1::SolverInventoryStore);
    }
    Ok(())
}

fn require_bitcoin_actuator_create_prefix_absent(path: &Path) -> Result<(), ProductionRunErrorV1> {
    if path_entry_present(path).map_err(|_| ProductionRunErrorV1::BitcoinActuatorStore)?
        || path_entry_present(&actuator_process_lock_path(path))
            .map_err(|_| ProductionRunErrorV1::BitcoinActuatorStore)?
    {
        return Err(ProductionRunErrorV1::BitcoinActuatorStore);
    }
    Ok(())
}

fn actuator_process_lock_path(path: &Path) -> PathBuf {
    let mut value = path.as_os_str().to_os_string();
    value.push(".lock");
    PathBuf::from(value)
}

fn dom_actuator_process_lock_path(path: &Path) -> PathBuf {
    actuator_process_lock_path(path)
}

fn coordinator_process_lock_path(path: &Path) -> PathBuf {
    let mut value = path.as_os_str().to_os_string();
    value.push(".lock");
    PathBuf::from(value)
}

fn load_bootstrap(
    options: &ProductionRunOptionsV1,
) -> Result<ValidatedProductionBootstrapV1, ProductionConfigErrorV1> {
    match options.mode {
        ProductionRunModeV1::Create => {
            load_production_create_or_resume_bootstrap_v10(&options.state_dir)
        }
        ProductionRunModeV1::ReopenExisting => {
            load_production_reopen_bootstrap_v10(&options.state_dir)
        }
    }
}

/// Loads the fixed network sidecar and binds both named peers to the V10
/// manifest before any durable authority or socket is opened.
fn bind_v10_relay_network_configuration(
    state_dir: &Path,
    config: &crate::production_config::ProductionBootstrapConfigV1,
    policies: ProductionOperationalPoliciesV10,
) -> Result<ProductionRelayNetworkConfigV1, ProductionRunErrorV1> {
    if config.operational_policies_v10() != Some(policies) {
        return Err(ProductionRunErrorV1::Configuration);
    }
    let relay_pins = config
        .relay_authority_pins_v6()
        .ok_or(ProductionRunErrorV1::Configuration)?;
    let network = load_production_relay_network_config_v1(state_dir)
        .map_err(|_| ProductionRunErrorV1::RelayNetworkConfiguration)?;
    validate_v10_relay_network_configuration(&network, relay_pins.relay_database_id, policies)?;
    Ok(network)
}

fn validate_v10_relay_network_configuration(
    network: &ProductionRelayNetworkConfigV1,
    local_relay_database_id: [u8; 32],
    policies: ProductionOperationalPoliciesV10,
) -> Result<(), ProductionRunErrorV1> {
    let local = RelayDatabaseIdV1::new(local_relay_database_id)
        .map_err(|_| ProductionRunErrorV1::Configuration)?;
    let upstream = RelayDatabaseIdV1::new(policies.upstream_remote_relay_database_id())
        .map_err(|_| ProductionRunErrorV1::Configuration)?;
    let downstream = RelayDatabaseIdV1::new(policies.downstream_remote_relay_database_id())
        .map_err(|_| ProductionRunErrorV1::Configuration)?;
    network
        .validate_remote_database_ids(upstream, downstream)
        .and_then(|()| network.validate_local_database_id(local))
        .map_err(|_| ProductionRunErrorV1::RelayNetworkConfiguration)?;
    Ok(())
}

/// Seconds since the Unix epoch, from the host clock. See the note on
/// [`run_production_v1`] about what this is and is not.
fn trusted_now_seconds_v1() -> Result<u64, ProductionRunErrorV1> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .map_err(|_| ProductionRunErrorV1::HostClock)
}

fn trusted_now_millis_v1() -> Result<u64, ProductionRunErrorV1> {
    let elapsed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| ProductionRunErrorV1::HostClock)?;
    u64::try_from(elapsed.as_millis()).map_err(|_| ProductionRunErrorV1::HostClock)
}

/// Opens the already-validated state directory as a capability.
///
/// The path is the one the loader canonicalised and validated for ownership
/// and mode; this only turns it into the handle the durable stores take.
fn state_dir_capability(state_dir: &Path) -> Result<Arc<Dir>, ProductionRunErrorV1> {
    let handle =
        File::open(state_dir).map_err(|_| ProductionRunErrorV1::StateDirectoryCapability)?;
    Ok(Arc::new(Dir::from_std_file(handle)))
}

#[cfg(test)]
mod tests {
    use std::error::Error;

    use counterparty_api::RevealedSecretBytes;
    use k256::{
        elliptic_curve::{sec1::ToEncodedPoint as _, PrimeField as _},
        ProjectivePoint, Scalar,
    };
    use route_secret_vault::{
        RouteSecretBindingsV2, RouteSecretExposureSourceV2, RouteSecretExposureV2,
    };

    use super::*;

    type TestResult<T = ()> = Result<T, Box<dyn Error>>;

    #[test]
    fn v10_relay_policy_is_bound_to_named_sidecar_peers_and_local_owner() -> TestResult {
        use crate::production_relay_network_config::{
            ProductionRelayEndpointModeV1, ProductionRelayNetworkLinkV1,
        };

        let upstream = [0xa1; 32];
        let downstream = [0xb2; 32];
        let local = [0xc3; 32];
        let policies =
            ProductionOperationalPoliciesV10::new(upstream, downstream, 100, 10, 1_000, 1_000)?;
        let network = ProductionRelayNetworkConfigV1::new(
            ProductionRelayNetworkLinkV1::new(
                ProductionRelayEndpointModeV1::Connect,
                "127.0.0.1:41001".parse()?,
                RelayDatabaseIdV1::new(upstream)?,
            )?,
            ProductionRelayNetworkLinkV1::new(
                ProductionRelayEndpointModeV1::Listen,
                "127.0.0.1:41002".parse()?,
                RelayDatabaseIdV1::new(downstream)?,
            )?,
        )?;
        assert_eq!(
            validate_v10_relay_network_configuration(&network, local, policies),
            Ok(())
        );
        assert_eq!(
            validate_v10_relay_network_configuration(&network, upstream, policies),
            Err(ProductionRunErrorV1::RelayNetworkConfiguration)
        );
        let swapped_policies =
            ProductionOperationalPoliciesV10::new(downstream, upstream, 100, 10, 1_000, 1_000)?;
        assert_eq!(
            validate_v10_relay_network_configuration(&network, local, swapped_policies),
            Err(ProductionRunErrorV1::RelayNetworkConfiguration)
        );
        Ok(())
    }

    #[test]
    fn refund_arming_open_mode_accepts_only_exact_journal_and_file_prefixes() {
        let modes = [
            ProductionRunModeV1::Create,
            ProductionRunModeV1::ReopenExisting,
        ];
        let states = [
            ProductionProvisioningStageStateV1::Absent,
            ProductionProvisioningStageStateV1::Started,
            ProductionProvisioningStageStateV1::Complete,
        ];
        for mode in modes {
            for before in states {
                for current in states {
                    for lock_present in [false, true] {
                        for database_present in [false, true] {
                            let expected =
                                match (mode, before, current, lock_present, database_present) {
                                    (
                                        ProductionRunModeV1::Create,
                                        ProductionProvisioningStageStateV1::Absent
                                        | ProductionProvisioningStageStateV1::Started,
                                        ProductionProvisioningStageStateV1::Started,
                                        false,
                                        false,
                                    ) => Some(RefundArmingOpenModeV1::Create),
                                    (
                                        ProductionRunModeV1::Create,
                                        ProductionProvisioningStageStateV1::Started,
                                        ProductionProvisioningStageStateV1::Started,
                                        true,
                                        _,
                                    ) => Some(RefundArmingOpenModeV1::ResumeCreate),
                                    (
                                        ProductionRunModeV1::Create
                                        | ProductionRunModeV1::ReopenExisting,
                                        ProductionProvisioningStageStateV1::Complete,
                                        ProductionProvisioningStageStateV1::Complete,
                                        true,
                                        true,
                                    ) => Some(RefundArmingOpenModeV1::OpenExisting),
                                    _ => None,
                                };
                            assert_eq!(
                                refund_arming_open_mode(
                                    mode,
                                    before,
                                    current,
                                    lock_present,
                                    database_present,
                                )
                                .ok(),
                                expected,
                                "unexpected refund authority prefix acceptance",
                            );
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn library_entrypoint_refuses_non_operational_artifact_before_inputs() {
        let result = run_production_v1(&ProductionRunOptionsV1 {
            state_dir: PathBuf::from("must-not-be-read-in-a-debug-test"),
            mode: ProductionRunModeV1::ReopenExisting,
        });
        assert_eq!(result, Err(ProductionRunErrorV1::StartupArtifact));
    }

    #[test]
    fn f6_stage11_recovery_accepts_only_started_create_or_complete_reopen() {
        assert_eq!(
            require_f6_stage_open_state(
                ProductionRunModeV1::Create,
                ProductionProvisioningStageStateV1::Started,
            ),
            Ok(())
        );
        assert_eq!(
            require_f6_stage_open_state(
                ProductionRunModeV1::Create,
                ProductionProvisioningStageStateV1::Complete,
            ),
            Ok(())
        );
        assert_eq!(
            require_f6_stage_open_state(
                ProductionRunModeV1::ReopenExisting,
                ProductionProvisioningStageStateV1::Complete,
            ),
            Ok(())
        );
        for (mode, state) in [
            (
                ProductionRunModeV1::Create,
                ProductionProvisioningStageStateV1::Absent,
            ),
            (
                ProductionRunModeV1::ReopenExisting,
                ProductionProvisioningStageStateV1::Absent,
            ),
            (
                ProductionRunModeV1::ReopenExisting,
                ProductionProvisioningStageStateV1::Started,
            ),
        ] {
            assert_eq!(
                require_f6_stage_open_state(mode, state),
                Err(ProductionRunErrorV1::Provisioning)
            );
        }
    }

    #[test]
    fn local_evm_key_must_match_exactly_one_admitted_role() {
        let funder = [0x11; 20];
        let beneficiary = [0x22; 20];
        assert_eq!(
            exact_local_evm_roles(funder, funder, beneficiary),
            Ok((EvmSignerRoleV1::Funder, EvmSignerRoleV1::Beneficiary))
        );
        assert_eq!(
            exact_local_evm_roles(beneficiary, funder, beneficiary),
            Ok((EvmSignerRoleV1::Beneficiary, EvmSignerRoleV1::Funder))
        );
        assert_eq!(
            exact_local_evm_roles([0x33; 20], funder, beneficiary),
            Err(ProductionRunErrorV1::EvmSignerAuthority)
        );
        assert_eq!(
            exact_local_evm_roles(funder, funder, funder),
            Err(ProductionRunErrorV1::EvmSignerAuthority)
        );
    }

    fn scalar_and_bindings() -> TestResult<(RevealedSecretBytes, RouteSecretBindingsV2)> {
        let mut scalar_bytes = [0_u8; 32];
        scalar_bytes[31] = 7;
        let scalar = Option::<Scalar>::from(Scalar::from_repr(scalar_bytes.into()))
            .ok_or("invalid test scalar")?;
        let encoded = (ProjectivePoint::GENERATOR * scalar)
            .to_affine()
            .to_encoded_point(true);
        let point: [u8; 33] = encoded.as_bytes().try_into()?;
        let bindings = RouteSecretBindingsV2::new(
            [1; 32],
            [2; 32],
            RouteSecretExposureV2::new(
                [3; 32],
                [4; 32],
                [5; 32],
                RouteSecretExposureSourceV2::Externalized,
                1,
            )?,
            point,
        )?;
        Ok((RevealedSecretBytes::new(scalar_bytes), bindings))
    }

    fn phase<T>(result: Result<T, ProductionRunErrorV1>, label: &'static str) -> TestResult<T> {
        result.map_err(|error| std::io::Error::other(format!("{label}: {error:?}")).into())
    }

    fn production_contracts_policy(marker: u8) -> TestResult<BudgetPolicyV1> {
        let mut bytes = [0; BUDGET_POLICY_LEN];
        bytes[..8].copy_from_slice(b"DOMNVBP1");
        bytes[8..10].copy_from_slice(&1_u16.to_le_bytes());
        bytes[10] = BudgetPolicyProfileV1::ProductionRatified as u8;
        bytes[11] = 1;
        bytes[16..48].fill(marker);
        bytes[48..56].copy_from_slice(&100_u64.to_le_bytes());
        bytes[56..64].copy_from_slice(&50_u64.to_le_bytes());
        bytes[64..68].copy_from_slice(&10_u32.to_le_bytes());
        bytes[72..80].copy_from_slice(&25_u64.to_le_bytes());
        bytes[80..88].copy_from_slice(&3_600_u64.to_le_bytes());
        bytes[88..96].copy_from_slice(&60_u64.to_le_bytes());
        bytes[96..104].copy_from_slice(&86_400_u64.to_le_bytes());
        bytes[104..112].copy_from_slice(&1_u64.to_le_bytes());
        let digest = dom_scriptless_crypto::authoritative_storage_hash_v1(
            dom_scriptless_crypto::StorageHashDomainV1::BudgetPolicy,
            &bytes[..112],
        );
        bytes[112..].copy_from_slice(&digest);
        Ok(BudgetPolicyV1::from_bytes(&bytes)?)
    }

    fn install_contracts_test_session(store: &ContractsSessionStoreV1, marker: u8) -> TestResult {
        use dom_scriptless_store::{
            SessionChainProjectionV1, SessionIrreversibleV1, SessionPhaseV1, SessionRecordFieldsV1,
            SessionRecordV1, SessionTxObservationV1,
        };

        let record = SessionRecordV1::new(
            SessionRecordFieldsV1 {
                session_id: [marker; 32],
                revision: 0,
                phase: SessionPhaseV1::Created,
                terms_hash: [marker.wrapping_add(1); 32],
                transcript_hash: [marker.wrapping_add(2); 32],
                irreversible: SessionIrreversibleV1 {
                    any_signing_share_sent: false,
                    funding_authorized: false,
                    adaptor_secret_exposed: false,
                    nonce_epoch: 0,
                },
                chain: SessionChainProjectionV1 {
                    tip_id: [marker.wrapping_add(3); 32],
                    tip_height: 0,
                    funding: SessionTxObservationV1::Unknown,
                    claim: SessionTxObservationV1::Unknown,
                    refund: SessionTxObservationV1::Unknown,
                },
            },
            &[],
        )?;
        let durable = store.create_session(&record)?;
        if durable.as_bytes() != record.as_bytes() {
            return Err("session bytes changed during fixture publication".into());
        }
        Ok(())
    }

    #[test]
    fn composition_root_creates_reopens_and_authenticates_route_secret_vault() -> TestResult {
        let temporary = tempfile::tempdir()?;
        let create_capability = state_dir_capability(temporary.path())?;
        let retention = open_route_secret_retention(
            ProductionRunModeV1::Create,
            ProductionProvisioningStageStateV1::Absent,
            ProductionProvisioningStageStateV1::Started,
            create_capability,
            RouteSecretSealKeyV1::import([0xA5; 32])?,
        )?;
        drop(retention);

        let resumed_prefix = open_route_secret_retention(
            ProductionRunModeV1::Create,
            ProductionProvisioningStageStateV1::Started,
            ProductionProvisioningStageStateV1::Started,
            state_dir_capability(temporary.path())?,
            RouteSecretSealKeyV1::import([0xA5; 32])?,
        )?;
        drop(resumed_prefix);

        // Install one real authenticated record so reopening proves the
        // supplied credential, rather than merely proving an empty root.
        let key = RouteSecretSealKeyV1::import([0xA5; 32])?;
        let vault = DurableRouteSecretVaultV1::open_production(
            state_dir_capability(temporary.path())?,
            ROUTE_SECRET_VAULT_ROOT_NAME_V1,
            &key,
        )?;
        let (scalar, bindings) = scalar_and_bindings()?;
        vault.put(&key, &bindings, scalar)?;
        drop(vault);

        let reopened = open_route_secret_retention(
            ProductionRunModeV1::Create,
            ProductionProvisioningStageStateV1::Complete,
            ProductionProvisioningStageStateV1::Complete,
            state_dir_capability(temporary.path())?,
            RouteSecretSealKeyV1::import([0xA5; 32])?,
        )?;
        drop(reopened);

        let reopened = open_route_secret_retention(
            ProductionRunModeV1::ReopenExisting,
            ProductionProvisioningStageStateV1::Complete,
            ProductionProvisioningStageStateV1::Complete,
            state_dir_capability(temporary.path())?,
            RouteSecretSealKeyV1::import([0xA5; 32])?,
        )?;
        drop(reopened);

        let wrong = open_route_secret_retention(
            ProductionRunModeV1::ReopenExisting,
            ProductionProvisioningStageStateV1::Complete,
            ProductionProvisioningStageStateV1::Complete,
            state_dir_capability(temporary.path())?,
            RouteSecretSealKeyV1::import([0x5A; 32])?,
        );
        assert!(matches!(wrong, Err(ProductionRunErrorV1::RouteSecretVault)));

        let planted_directory = tempfile::tempdir()?;
        drop(DurableRouteSecretVaultV1::create_production(
            state_dir_capability(planted_directory.path())?,
            ROUTE_SECRET_VAULT_ROOT_NAME_V1,
        )?);
        let planted = open_route_secret_retention(
            ProductionRunModeV1::Create,
            ProductionProvisioningStageStateV1::Absent,
            ProductionProvisioningStageStateV1::Started,
            state_dir_capability(planted_directory.path())?,
            RouteSecretSealKeyV1::import([0xA5; 32])?,
        );
        assert!(matches!(
            planted,
            Err(ProductionRunErrorV1::RouteSecretVault)
        ));
        Ok(())
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn contracts_pair_resumes_all_store_prefixes_and_refuses_wrong_bindings() -> TestResult {
        use std::os::unix::fs::PermissionsExt as _;

        const UPSTREAM: &str = "upstream-contracts";
        const DOWNSTREAM: &str = "downstream-contracts";
        let binding = [0x71; 32];
        for prefix in [
            "none",
            "upstream-pristine",
            "downstream-pristine",
            "both-pristine",
            "upstream-complete",
            "downstream-complete",
            "both-complete",
        ] {
            let temporary = tempfile::tempdir()?;
            std::fs::set_permissions(temporary.path(), std::fs::Permissions::from_mode(0o700))?;
            let policy = production_contracts_policy(0x41)?;
            if matches!(
                prefix,
                "upstream-pristine"
                    | "both-pristine"
                    | "upstream-complete"
                    | "downstream-complete"
                    | "both-complete"
            ) {
                let store = ContractsSessionStoreV1::resume_create_production(
                    state_dir_capability(temporary.path())?,
                    UPSTREAM,
                    policy.clone(),
                    binding,
                )?;
                if matches!(prefix, "upstream-complete" | "both-complete") {
                    install_contracts_test_session(&store, 0x51)?;
                }
                drop(store);
            }
            if matches!(
                prefix,
                "downstream-pristine"
                    | "both-pristine"
                    | "upstream-complete"
                    | "downstream-complete"
                    | "both-complete"
            ) {
                let store = ContractsSessionStoreV1::resume_create_production(
                    state_dir_capability(temporary.path())?,
                    DOWNSTREAM,
                    policy.clone(),
                    binding,
                )?;
                if matches!(prefix, "downstream-complete" | "both-complete") {
                    install_contracts_test_session(&store, 0x52)?;
                }
                drop(store);
            }
            let stores = open_contracts_store_pair(ContractsStorePairRequestV1 {
                mode: ProductionRunModeV1::Create,
                stage_before_begin: ProductionProvisioningStageStateV1::Started,
                stage: ProductionProvisioningStageStateV1::Started,
                parent: state_dir_capability(temporary.path())?,
                upstream_root: UPSTREAM,
                downstream_root: DOWNSTREAM,
                policy: policy.clone(),
                creation_binding: binding,
            })?;
            drop(stores);
            drop(open_contracts_store_pair(ContractsStorePairRequestV1 {
                mode: ProductionRunModeV1::ReopenExisting,
                stage_before_begin: ProductionProvisioningStageStateV1::Complete,
                stage: ProductionProvisioningStageStateV1::Complete,
                parent: state_dir_capability(temporary.path())?,
                upstream_root: UPSTREAM,
                downstream_root: DOWNSTREAM,
                policy,
                creation_binding: binding,
            })?);
        }

        let temporary = tempfile::tempdir()?;
        std::fs::set_permissions(temporary.path(), std::fs::Permissions::from_mode(0o700))?;
        let policy = production_contracts_policy(0x41)?;
        let upstream = ContractsSessionStoreV1::resume_create_production(
            state_dir_capability(temporary.path())?,
            UPSTREAM,
            policy.clone(),
            binding,
        )?;
        install_contracts_test_session(&upstream, 0x61)?;
        drop(upstream);
        assert!(matches!(
            open_contracts_store_pair(ContractsStorePairRequestV1 {
                mode: ProductionRunModeV1::Create,
                stage_before_begin: ProductionProvisioningStageStateV1::Started,
                stage: ProductionProvisioningStageStateV1::Started,
                parent: state_dir_capability(temporary.path())?,
                upstream_root: UPSTREAM,
                downstream_root: DOWNSTREAM,
                policy: policy.clone(),
                creation_binding: [0x72; 32],
            }),
            Err(ProductionRunErrorV1::ContractsStores)
        ));
        assert!(!temporary.path().join(DOWNSTREAM).exists());
        assert!(matches!(
            open_contracts_store_pair(ContractsStorePairRequestV1 {
                mode: ProductionRunModeV1::Create,
                stage_before_begin: ProductionProvisioningStageStateV1::Started,
                stage: ProductionProvisioningStageStateV1::Started,
                parent: state_dir_capability(temporary.path())?,
                upstream_root: UPSTREAM,
                downstream_root: DOWNSTREAM,
                policy: production_contracts_policy(0x42)?,
                creation_binding: binding,
            }),
            Err(ProductionRunErrorV1::ContractsStores)
        ));
        assert!(!temporary.path().join(DOWNSTREAM).exists());

        let planted = tempfile::tempdir()?;
        std::fs::set_permissions(planted.path(), std::fs::Permissions::from_mode(0o700))?;
        drop(ContractsSessionStoreV1::create_production(
            state_dir_capability(planted.path())?,
            UPSTREAM,
            policy.clone(),
        )?);
        assert!(matches!(
            open_contracts_store_pair(ContractsStorePairRequestV1 {
                mode: ProductionRunModeV1::Create,
                stage_before_begin: ProductionProvisioningStageStateV1::Absent,
                stage: ProductionProvisioningStageStateV1::Started,
                parent: state_dir_capability(planted.path())?,
                upstream_root: UPSTREAM,
                downstream_root: DOWNSTREAM,
                policy,
                creation_binding: binding,
            }),
            Err(ProductionRunErrorV1::ContractsStores)
        ));
        assert!(!planted.path().join(DOWNSTREAM).exists());

        let atomic = tempfile::tempdir()?;
        std::fs::set_permissions(atomic.path(), std::fs::Permissions::from_mode(0o700))?;
        let policy = production_contracts_policy(0x41)?;
        for root in [UPSTREAM, DOWNSTREAM] {
            drop(ContractsSessionStoreV1::resume_create_production(
                state_dir_capability(atomic.path())?,
                root,
                policy.clone(),
                binding,
            )?);
        }
        let upstream_staging = atomic
            .path()
            .join(UPSTREAM)
            .join("session-records")
            .join(format!(".{}-{:020}.session.staging", "00".repeat(32), 0));
        std::fs::write(&upstream_staging, b"recoverable-prefix")?;
        std::fs::set_permissions(&upstream_staging, std::fs::Permissions::from_mode(0o400))?;
        let downstream_foreign = atomic
            .path()
            .join(DOWNSTREAM)
            .join("session-artifacts")
            .join("caller-shaped");
        std::fs::write(&downstream_foreign, b"foreign")?;
        std::fs::set_permissions(&downstream_foreign, std::fs::Permissions::from_mode(0o400))?;
        assert!(matches!(
            open_contracts_store_pair(ContractsStorePairRequestV1 {
                mode: ProductionRunModeV1::ReopenExisting,
                stage_before_begin: ProductionProvisioningStageStateV1::Complete,
                stage: ProductionProvisioningStageStateV1::Complete,
                parent: state_dir_capability(atomic.path())?,
                upstream_root: UPSTREAM,
                downstream_root: DOWNSTREAM,
                policy,
                creation_binding: binding,
            }),
            Err(ProductionRunErrorV1::ContractsStores)
        ));
        assert_eq!(std::fs::read(&upstream_staging)?, b"recoverable-prefix");
        Ok(())
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn reopen_requires_the_complete_authenticated_provisioning_prefix() -> TestResult {
        use std::os::unix::fs::PermissionsExt as _;

        let temporary = tempfile::tempdir()?;
        std::fs::set_permissions(temporary.path(), std::fs::Permissions::from_mode(0o700))?;
        let authority_root = std::fs::canonicalize(temporary.path())?;
        let mut journal =
            DurableProductionProvisioningJournalV1::open_or_create_after_absence_check(
                &authority_root,
                [0x55; 32],
            )?;
        assert!(matches!(
            require_reopen_provisioning_prefix(&journal),
            Err(ProductionRunErrorV1::Provisioning)
        ));
        for stage in [
            ProductionProvisioningStageV1::TimeAnchorStore,
            ProductionProvisioningStageV1::RouteStore,
            ProductionProvisioningStageV1::RouteSecretVault,
        ] {
            journal.begin(stage)?;
            journal.complete(stage)?;
            assert!(matches!(
                require_reopen_provisioning_prefix(&journal),
                Err(ProductionRunErrorV1::Provisioning)
            ));
        }
        journal.begin(ProductionProvisioningStageV1::CoordinatorStore)?;
        assert!(matches!(
            require_reopen_provisioning_prefix(&journal),
            Err(ProductionRunErrorV1::Provisioning)
        ));
        journal.complete(ProductionProvisioningStageV1::CoordinatorStore)?;
        assert!(matches!(
            require_reopen_provisioning_prefix(&journal),
            Err(ProductionRunErrorV1::Provisioning)
        ));
        journal.begin(ProductionProvisioningStageV1::DomActuatorStore)?;
        assert!(matches!(
            require_reopen_provisioning_prefix(&journal),
            Err(ProductionRunErrorV1::Provisioning)
        ));
        journal.complete(ProductionProvisioningStageV1::DomActuatorStore)?;
        assert!(matches!(
            require_reopen_provisioning_prefix(&journal),
            Err(ProductionRunErrorV1::Provisioning)
        ));
        journal.begin(ProductionProvisioningStageV1::EvmActuatorStore)?;
        assert!(matches!(
            require_reopen_provisioning_prefix(&journal),
            Err(ProductionRunErrorV1::Provisioning)
        ));
        journal.complete(ProductionProvisioningStageV1::EvmActuatorStore)?;
        assert!(matches!(
            require_reopen_provisioning_prefix(&journal),
            Err(ProductionRunErrorV1::Provisioning)
        ));
        journal.begin(ProductionProvisioningStageV1::BitcoinActuatorStore)?;
        assert!(matches!(
            require_reopen_provisioning_prefix(&journal),
            Err(ProductionRunErrorV1::Provisioning)
        ));
        journal.complete(ProductionProvisioningStageV1::BitcoinActuatorStore)?;
        assert!(matches!(
            require_reopen_provisioning_prefix(&journal),
            Err(ProductionRunErrorV1::Provisioning)
        ));
        journal.begin(ProductionProvisioningStageV1::ChainSignerAuthorities)?;
        assert!(matches!(
            require_reopen_provisioning_prefix(&journal),
            Err(ProductionRunErrorV1::Provisioning)
        ));
        journal.complete(ProductionProvisioningStageV1::ChainSignerAuthorities)?;
        assert!(matches!(
            require_reopen_provisioning_prefix(&journal),
            Err(ProductionRunErrorV1::Provisioning)
        ));
        journal.begin(ProductionProvisioningStageV1::SolverInventoryStore)?;
        assert!(matches!(
            require_reopen_provisioning_prefix(&journal),
            Err(ProductionRunErrorV1::Provisioning)
        ));
        journal.complete(ProductionProvisioningStageV1::SolverInventoryStore)?;
        assert!(matches!(
            require_reopen_provisioning_prefix(&journal),
            Err(ProductionRunErrorV1::Provisioning)
        ));
        journal.begin(ProductionProvisioningStageV1::ContractsStores)?;
        assert!(matches!(
            require_reopen_provisioning_prefix(&journal),
            Err(ProductionRunErrorV1::Provisioning)
        ));
        journal.complete(ProductionProvisioningStageV1::ContractsStores)?;
        assert!(matches!(
            require_reopen_provisioning_prefix(&journal),
            Err(ProductionRunErrorV1::Provisioning)
        ));
        for stage in [
            ProductionProvisioningStageV1::F6Authorities,
            ProductionProvisioningStageV1::RelayAuthorities,
            ProductionProvisioningStageV1::RefundArmingAuthority,
        ] {
            journal.begin(stage)?;
            assert!(matches!(
                require_reopen_provisioning_prefix(&journal),
                Err(ProductionRunErrorV1::Provisioning)
            ));
            journal.complete(stage)?;
            if stage != ProductionProvisioningStageV1::RefundArmingAuthority {
                assert!(matches!(
                    require_reopen_provisioning_prefix(&journal),
                    Err(ProductionRunErrorV1::Provisioning)
                ));
            }
        }
        require_reopen_provisioning_prefix(&journal)?;
        Ok(())
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn solver_inventory_create_resume_and_complete_reopen_are_strict() -> TestResult {
        use std::fs::OpenOptions;
        use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};

        let temporary = tempfile::tempdir()?;
        std::fs::set_permissions(temporary.path(), std::fs::Permissions::from_mode(0o700))?;
        let authority_root = std::fs::canonicalize(temporary.path())?;
        let path = authority_root.join("solver-inventory.sqlite3");
        let binding = [0x81; 32];

        drop(phase(
            open_solver_inventory_store(
                ProductionRunModeV1::Create,
                ProductionProvisioningStageStateV1::Absent,
                ProductionProvisioningStageStateV1::Started,
                &path,
                binding,
            ),
            "fresh solver inventory create failed",
        )?);
        drop(phase(
            open_solver_inventory_store(
                ProductionRunModeV1::Create,
                ProductionProvisioningStageStateV1::Started,
                ProductionProvisioningStageStateV1::Started,
                &path,
                binding,
            ),
            "solver inventory checkpoint resume failed",
        )?);
        drop(phase(
            open_solver_inventory_store(
                ProductionRunModeV1::Create,
                ProductionProvisioningStageStateV1::Complete,
                ProductionProvisioningStageStateV1::Complete,
                &path,
                binding,
            ),
            "completed solver inventory reopen failed",
        )?);
        assert!(matches!(
            open_solver_inventory_store(
                ProductionRunModeV1::ReopenExisting,
                ProductionProvisioningStageStateV1::Complete,
                ProductionProvisioningStageStateV1::Complete,
                &path,
                [0x82; 32],
            ),
            Err(ProductionRunErrorV1::SolverInventoryStore)
        ));

        let absent_after_journal = authority_root.join("absent-after-journal.sqlite3");
        drop(phase(
            open_solver_inventory_store(
                ProductionRunModeV1::Create,
                ProductionProvisioningStageStateV1::Started,
                ProductionProvisioningStageStateV1::Started,
                &absent_after_journal,
                binding,
            ),
            "solver inventory journal-only resume failed",
        )?);

        let lock_only = authority_root.join("lock-only-solver-inventory.sqlite3");
        drop(
            OpenOptions::new()
                .read(true)
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(actuator_process_lock_path(&lock_only))?,
        );
        drop(phase(
            open_solver_inventory_store(
                ProductionRunModeV1::Create,
                ProductionProvisioningStageStateV1::Started,
                ProductionProvisioningStageStateV1::Started,
                &lock_only,
                binding,
            ),
            "solver inventory lock-only resume failed",
        )?);

        let database_only = authority_root.join("database-only-solver-inventory.sqlite3");
        drop(
            OpenOptions::new()
                .read(true)
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&database_only)?,
        );
        assert!(matches!(
            open_solver_inventory_store(
                ProductionRunModeV1::Create,
                ProductionProvisioningStageStateV1::Started,
                ProductionProvisioningStageStateV1::Started,
                &database_only,
                binding,
            ),
            Err(ProductionRunErrorV1::SolverInventoryStore)
        ));

        let planted = authority_root.join("planted-solver-inventory.sqlite3");
        drop(DurableInventoryStoreV1::create(&planted, binding)?);
        assert!(matches!(
            require_solver_inventory_create_prefix_absent(&planted),
            Err(ProductionRunErrorV1::SolverInventoryStore)
        ));
        Ok(())
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn dom_actuator_create_resume_and_complete_reopen_are_strict() -> TestResult {
        use std::fs::OpenOptions;
        use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};

        let temporary = tempfile::tempdir()?;
        std::fs::set_permissions(temporary.path(), std::fs::Permissions::from_mode(0o700))?;
        let authority_root = std::fs::canonicalize(temporary.path())?;
        let path = authority_root.join("dom-actuator.sqlite3");

        let created = phase(
            open_dom_actuator_store(
                ProductionRunModeV1::Create,
                ProductionProvisioningStageStateV1::Absent,
                ProductionProvisioningStageStateV1::Started,
                &path,
            ),
            "fresh DOM actuator create failed",
        )?;
        drop(created);
        let resumed = phase(
            open_dom_actuator_store(
                ProductionRunModeV1::Create,
                ProductionProvisioningStageStateV1::Started,
                ProductionProvisioningStageStateV1::Started,
                &path,
            ),
            "DOM actuator checkpoint resume failed",
        )?;
        drop(resumed);
        let reopened = phase(
            open_dom_actuator_store(
                ProductionRunModeV1::Create,
                ProductionProvisioningStageStateV1::Complete,
                ProductionProvisioningStageStateV1::Complete,
                &path,
            ),
            "completed DOM actuator reopen failed",
        )?;
        drop(reopened);

        let planted = authority_root.join("planted-dom-actuator.sqlite3");
        drop(DomActuatorStoreV1::create(&planted)?);
        assert!(matches!(
            open_dom_actuator_store(
                ProductionRunModeV1::Create,
                ProductionProvisioningStageStateV1::Absent,
                ProductionProvisioningStageStateV1::Started,
                &planted,
            ),
            Err(ProductionRunErrorV1::DomActuatorStore)
        ));

        let lock_only = authority_root.join("lock-only-dom-actuator.sqlite3");
        drop(
            OpenOptions::new()
                .read(true)
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(dom_actuator_process_lock_path(&lock_only))?,
        );
        drop(phase(
            open_dom_actuator_store(
                ProductionRunModeV1::Create,
                ProductionProvisioningStageStateV1::Started,
                ProductionProvisioningStageStateV1::Started,
                &lock_only,
            ),
            "DOM actuator lock-only resume failed",
        )?);

        let database_only = authority_root.join("database-only-dom-actuator.sqlite3");
        drop(
            OpenOptions::new()
                .read(true)
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&database_only)?,
        );
        assert!(matches!(
            open_dom_actuator_store(
                ProductionRunModeV1::Create,
                ProductionProvisioningStageStateV1::Started,
                ProductionProvisioningStageStateV1::Started,
                &database_only,
            ),
            Err(ProductionRunErrorV1::DomActuatorStore)
        ));
        Ok(())
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn evm_actuator_create_resume_and_complete_reopen_are_strict() -> TestResult {
        use std::fs::OpenOptions;
        use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};

        let temporary = tempfile::tempdir()?;
        std::fs::set_permissions(temporary.path(), std::fs::Permissions::from_mode(0o700))?;
        let authority_root = std::fs::canonicalize(temporary.path())?;
        let path = authority_root.join("evm-actuator.sqlite3");

        drop(phase(
            open_evm_actuator_store(
                ProductionRunModeV1::Create,
                ProductionProvisioningStageStateV1::Absent,
                ProductionProvisioningStageStateV1::Started,
                &path,
            ),
            "fresh EVM actuator create failed",
        )?);
        drop(phase(
            open_evm_actuator_store(
                ProductionRunModeV1::Create,
                ProductionProvisioningStageStateV1::Started,
                ProductionProvisioningStageStateV1::Started,
                &path,
            ),
            "EVM actuator checkpoint resume failed",
        )?);
        drop(phase(
            open_evm_actuator_store(
                ProductionRunModeV1::Create,
                ProductionProvisioningStageStateV1::Complete,
                ProductionProvisioningStageStateV1::Complete,
                &path,
            ),
            "completed EVM actuator reopen failed",
        )?);

        let planted = authority_root.join("planted-evm-actuator.sqlite3");
        drop(DurableEvmActuatorV1::create(&planted)?);
        assert!(matches!(
            open_evm_actuator_store(
                ProductionRunModeV1::Create,
                ProductionProvisioningStageStateV1::Absent,
                ProductionProvisioningStageStateV1::Started,
                &planted,
            ),
            Err(ProductionRunErrorV1::EvmActuatorStore)
        ));

        let lock_only = authority_root.join("lock-only-evm-actuator.sqlite3");
        drop(
            OpenOptions::new()
                .read(true)
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(actuator_process_lock_path(&lock_only))?,
        );
        drop(phase(
            open_evm_actuator_store(
                ProductionRunModeV1::Create,
                ProductionProvisioningStageStateV1::Started,
                ProductionProvisioningStageStateV1::Started,
                &lock_only,
            ),
            "EVM actuator lock-only resume failed",
        )?);

        let database_only = authority_root.join("database-only-evm-actuator.sqlite3");
        drop(
            OpenOptions::new()
                .read(true)
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&database_only)?,
        );
        assert!(matches!(
            open_evm_actuator_store(
                ProductionRunModeV1::Create,
                ProductionProvisioningStageStateV1::Started,
                ProductionProvisioningStageStateV1::Started,
                &database_only,
            ),
            Err(ProductionRunErrorV1::EvmActuatorStore)
        ));
        Ok(())
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn bitcoin_actuator_create_resume_and_complete_reopen_are_strict() -> TestResult {
        use std::fs::OpenOptions;
        use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};

        let temporary = tempfile::tempdir()?;
        std::fs::set_permissions(temporary.path(), std::fs::Permissions::from_mode(0o700))?;
        let authority_root = std::fs::canonicalize(temporary.path())?;
        let path = authority_root.join("bitcoin-actuator.sqlite3");
        let owner = [0x71; 32];

        drop(phase(
            open_bitcoin_actuator_store(
                ProductionRunModeV1::Create,
                ProductionProvisioningStageStateV1::Absent,
                ProductionProvisioningStageStateV1::Started,
                &path,
                owner,
            ),
            "fresh Bitcoin actuator create failed",
        )?);
        drop(phase(
            open_bitcoin_actuator_store(
                ProductionRunModeV1::Create,
                ProductionProvisioningStageStateV1::Started,
                ProductionProvisioningStageStateV1::Started,
                &path,
                owner,
            ),
            "Bitcoin actuator checkpoint resume failed",
        )?);
        drop(phase(
            open_bitcoin_actuator_store(
                ProductionRunModeV1::Create,
                ProductionProvisioningStageStateV1::Complete,
                ProductionProvisioningStageStateV1::Complete,
                &path,
                owner,
            ),
            "completed Bitcoin actuator reopen failed",
        )?);
        drop(phase(
            open_bitcoin_actuator_store(
                ProductionRunModeV1::ReopenExisting,
                ProductionProvisioningStageStateV1::Complete,
                ProductionProvisioningStageStateV1::Complete,
                &path,
                [0x72; 32],
            ),
            "Bitcoin actuator takeover owner reopen failed",
        )?);
        assert!(matches!(
            open_bitcoin_actuator_store(
                ProductionRunModeV1::ReopenExisting,
                ProductionProvisioningStageStateV1::Complete,
                ProductionProvisioningStageStateV1::Complete,
                &path,
                [0; 32],
            ),
            Err(ProductionRunErrorV1::BitcoinActuatorStore)
        ));

        let planted = authority_root.join("planted-bitcoin-actuator.sqlite3");
        drop(DurableBitcoinActuatorV1::create(&planted, owner)?);
        assert!(matches!(
            open_bitcoin_actuator_store(
                ProductionRunModeV1::Create,
                ProductionProvisioningStageStateV1::Absent,
                ProductionProvisioningStageStateV1::Started,
                &planted,
                owner,
            ),
            Err(ProductionRunErrorV1::BitcoinActuatorStore)
        ));

        let lock_only = authority_root.join("lock-only-bitcoin-actuator.sqlite3");
        drop(
            OpenOptions::new()
                .read(true)
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(actuator_process_lock_path(&lock_only))?,
        );
        drop(phase(
            open_bitcoin_actuator_store(
                ProductionRunModeV1::Create,
                ProductionProvisioningStageStateV1::Started,
                ProductionProvisioningStageStateV1::Started,
                &lock_only,
                owner,
            ),
            "Bitcoin actuator lock-only resume failed",
        )?);

        let database_only = authority_root.join("database-only-bitcoin-actuator.sqlite3");
        drop(
            OpenOptions::new()
                .read(true)
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&database_only)?,
        );
        assert!(matches!(
            open_bitcoin_actuator_store(
                ProductionRunModeV1::Create,
                ProductionProvisioningStageStateV1::Started,
                ProductionProvisioningStageStateV1::Started,
                &database_only,
                owner,
            ),
            Err(ProductionRunErrorV1::BitcoinActuatorStore)
        ));
        Ok(())
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn coordinator_create_resume_and_complete_reopen_are_strict() -> TestResult {
        use std::fs::OpenOptions;
        use std::os::unix::fs::OpenOptionsExt as _;
        use std::os::unix::fs::PermissionsExt as _;

        let temporary = tempfile::tempdir()?;
        std::fs::set_permissions(temporary.path(), std::fs::Permissions::from_mode(0o700))?;
        let authority_root = std::fs::canonicalize(temporary.path())?;
        let coordinator_id = [0x31; 32];
        let plan_authority_id = [0x32; 32];
        let path = authority_root.join("coordinator.sqlite3");

        let created = phase(
            open_settlement_coordinator(
                ProductionRunModeV1::Create,
                ProductionProvisioningStageStateV1::Absent,
                ProductionProvisioningStageStateV1::Started,
                &path,
                coordinator_id,
                plan_authority_id,
                1_000,
            ),
            "fresh coordinator create failed",
        )?;
        drop(created);

        let resumed_after_checkpoint = phase(
            open_settlement_coordinator(
                ProductionRunModeV1::Create,
                ProductionProvisioningStageStateV1::Started,
                ProductionProvisioningStageStateV1::Started,
                &path,
                coordinator_id,
                plan_authority_id,
                2_000,
            ),
            "coordinator checkpoint resume failed",
        )?;
        drop(resumed_after_checkpoint);

        let reopened_complete = phase(
            open_settlement_coordinator(
                ProductionRunModeV1::Create,
                ProductionProvisioningStageStateV1::Complete,
                ProductionProvisioningStageStateV1::Complete,
                &path,
                coordinator_id,
                plan_authority_id,
                3_000,
            ),
            "completed coordinator reopen failed",
        )?;
        drop(reopened_complete);

        let planted = authority_root.join("planted.sqlite3");
        drop(DurableSettlementCoordinatorV1::create(
            &planted,
            coordinator_id,
            plan_authority_id,
            1_000,
        )?);
        let refused = open_settlement_coordinator(
            ProductionRunModeV1::Create,
            ProductionProvisioningStageStateV1::Absent,
            ProductionProvisioningStageStateV1::Started,
            &planted,
            coordinator_id,
            plan_authority_id,
            2_000,
        );
        assert!(matches!(
            refused,
            Err(ProductionRunErrorV1::CoordinatorStore)
        ));

        let lock_only = authority_root.join("lock-only.sqlite3");
        let lock_path = coordinator_process_lock_path(&lock_only);
        drop(
            OpenOptions::new()
                .read(true)
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(lock_path)?,
        );
        let resumed_lock_prefix = phase(
            open_settlement_coordinator(
                ProductionRunModeV1::Create,
                ProductionProvisioningStageStateV1::Started,
                ProductionProvisioningStageStateV1::Started,
                &lock_only,
                coordinator_id,
                plan_authority_id,
                4_000,
            ),
            "coordinator lock-only resume failed",
        )?;
        drop(resumed_lock_prefix);

        let wrong_binding = open_settlement_coordinator(
            ProductionRunModeV1::ReopenExisting,
            ProductionProvisioningStageStateV1::Complete,
            ProductionProvisioningStageStateV1::Complete,
            &path,
            [0x41; 32],
            plan_authority_id,
            5_000,
        );
        assert!(matches!(
            wrong_binding,
            Err(ProductionRunErrorV1::CoordinatorStore)
        ));
        Ok(())
    }
}
