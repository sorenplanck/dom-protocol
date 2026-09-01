//! Production composition root: the arm that `main` runs.
//!
//! **This does not yet run a route, and says so rather than pretending.** It
//! goes as far as the pieces that exist allow — it reads the out-of-band
//! secrets, loads and authenticates the canonical configuration, opens the
//! route, time, route-secret, settlement-coordinator, chain actuator/signer and
//! solver-inventory authorities — and then
//! refuses, naming every production authority that is not composed yet. A
//! refusal that names what is missing is a result; a loop driven by test
//! doubles would not be.
//!
//! Nothing here is a stand-in. There is no mock, no laboratory value and no
//! `evidence-only` surface: where a piece is absent it is absent, and
//! [`ProductionRunErrorV1::NotComposable`] carries the list.

use std::fs::File;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use btc_actuator::DurableBitcoinActuatorV1;
use cap_std::fs::Dir;
use dom_actuator::DomActuatorStoreV1;
use dom_scriptless_store::{
    BudgetPolicyProfileV1, BudgetPolicyV1, ContractsSessionStoreV1, BUDGET_POLICY_LEN,
};
use evm_actuator::DurableEvmActuatorV1;
use route_secret_vault::{DurableRouteSecretVaultV1, RouteSecretSealKeyV1};
use settlement_coordinator::DurableSettlementCoordinatorV1;
use solver_inventory::DurableInventoryStoreV1;

use crate::production_chain_signers::{
    provision_production_chain_signers_v1, ProductionChainSignerProvisioningRequestV1,
};
use crate::production_children::{
    compose_production_counterparty_children_v1, load_production_chain_endpoints,
    ProductionCounterpartyCompositionRequestV1,
};
use crate::production_config::{
    load_production_create_or_resume_bootstrap_v3, load_production_create_or_resume_bootstrap_v4,
    load_production_reopen_bootstrap_v3, load_production_reopen_bootstrap_v4,
    provisioning_binding_for_bootstrap, read_owner_file_bounded, ProductionConfigErrorV1,
    ProductionPathRoleV1, ValidatedProductionBootstrapV1,
};
use crate::production_inputs::{
    load_authenticated_production_inputs_v1,
    load_authenticated_production_inputs_with_provisioning_v1, AuthenticatedProductionInputsV1,
};
use crate::production_node::read_production_secrets_from_stdin;
use crate::production_plan_source::ProductionPublicSecretRetentionV1;
use crate::production_provisioning::{
    DurableProductionProvisioningJournalV1, ProductionProvisioningStageStateV1,
    ProductionProvisioningStageV1, ROUTE_SECRET_VAULT_ROOT_NAME_V1,
};
use crate::production_service::{
    compose_production_route_service_v1, ProductionRouteServiceRequestV1,
};
use crate::production_timer::{
    deadline_context_digest_v1, ProductionDeadlineBindingV1, ProductionDeadlineTimerAuthorityV1,
};
use crate::supervisor::{
    ActionExternalizationReceiptV1, AuthorityRefusalV1, RunnerActionAuthority,
    RunnerActionRequestV1,
};
use kaystra_core::types::TimelockSpec;
use route_executor::LegIdV1;

// This fixed name contains the forbidden manifest-path label `secret`, so no
// operator-controlled V1/V2/V3 path role can alias it. The composition root,
// rather than a manifest string, is the only authority that can select it.
// This `cfg` is load-bearing and must match the one on the `authority_seal::Sealed`
// impl below, which is the symbol's only use.  That impl exists only outside
// laboratory builds, and `cargo test` sets `test` even when `production` is the
// selected feature, so a wider import is an orphan in the lib-test target of a
// legitimate production profile -- which is exactly what `clippy -D warnings`
// refuses.  Deleting the import instead of gating it would drop the explicit
// seal and leave the authority unsealed in the real production build.
#[cfg(not(any(feature = "development", feature = "simulation", test)))]
use crate::supervisor::authority_seal;

/// Whether this invocation provisions a new route or resumes an existing one.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ProductionRunModeV1 {
    /// Reads the V3 create manifest and its recovery companion, and requires
    /// every managed authority to be absent.
    Create,
    /// Reads only the V3 recovery manifest and requires every managed
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
    /// The out-of-band secret stream was refused. Its own error names which of
    /// the eight fields was wrong; it is not repeated here, because this
    /// boundary must not widen a redacted refusal into a specific one.
    #[error("production secrets unavailable")]
    Secrets,
    /// The canonical configuration was refused.
    #[error("production configuration refused")]
    Configuration,
    /// A public route input failed to authenticate.
    #[error("production inputs refused")]
    Inputs,
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
    /// The phase-1 service plane (transport identity, Relay queue and the two
    /// Relay-backed Contracts owners over the fail-closed F6 authority) could
    /// not be composed or its two provisioning stages refused.
    #[error("production relay/F6 service plane unavailable")]
    RelayAuthorities,
    /// The solver inventory/bond authority could not be created, resumed from
    /// its exact pristine prefix, or reopened under the authenticated binding.
    #[error("production solver inventory store unavailable")]
    SolverInventoryStore,
    /// The two raw Contracts Stores could not be created/resumed as one
    /// pristine Stage-10 unit or reopened under the ratified budget policy.
    #[error("production Contracts stores unavailable")]
    ContractsStores,
    /// Ordered production authority creation could not be resumed exactly.
    #[error("production provisioning journal unavailable")]
    Provisioning,
    /// The host clock is before the Unix epoch, so no trusted second exists.
    #[error("production host clock is unusable")]
    HostClock,
    /// The counterparty settlement children could not be composed from the
    /// V4 chain-endpoints artifact and the provisioned durable stores.
    #[error("production counterparty children unavailable")]
    CounterpartyChildren,
    /// Everything above succeeded and the route still cannot be composed,
    /// because parts of the composition have no production implementation.
    ///
    /// This is the honest terminal state of this binary today. The parts are
    /// named in [`MISSING_PRODUCTION_PARTS_V1`] and printed by `main`, so an
    /// operator learns exactly what is absent instead of reading "failed".
    #[error("production route is not composable yet")]
    NotComposable,
}

/// Every part the composition root still lacks, in the order it would need
/// them. Printed verbatim on refusal.
///
/// This list is the specification of the remaining work and is deliberately
/// concrete: each line names a trait or a type and where a production
/// implementation would have to exist. It is not a wish list — every entry was
/// measured, and the absence of each was confirmed across the workspace rather
/// than assumed.
pub const MISSING_PRODUCTION_PARTS_V1: &[&str] = &[
    "RefundArmingAuthority: all four counterparty refund faces (EVM, Bitcoin, Solana, Monero) are now constructed by `compose_production_counterparty_children_v1` and returned in `ProductionCounterpartyChildrenV1::refund_faces`; what remains is retaining the Stage-10 Contracts stores as the DOM faces and calling `ProductionRefundArmingAuthorityV1::create`/`open_existing` with the refund-arming credential — bounded glue, no missing authority",
    "RunnerActionAuthority: only the declared fail-closed `UnavailableRunnerAuthorityV1` exists; composed interop routes settle through the chain child authorities and emit no `RunnerPayload` effects, so this refusal is only reachable by a route shape this composition does not produce — it is retained deliberately, not as a hole",
    "PublicSecretSource (upstream reveal extraction): DONE for every extractable chain — `ProductionPublicSecretSourceRouterV1` now routes DOM, EVM, Bitcoin and Solana (`ProductionSolanaPublicSecretSourceV1` re-reads the finalized escrow state PDA through the quorum pool and re-verifies the revealed scalar against BOTH DLEQ-certified curve points). Monero deliberately has no source and never will: a CLSAG ring signature keeps the spend scalar off the Monero chain, so the XMR leg's reveal is the DOM adaptor completion served by the DOM source, and `authenticate_leg` refuses any role plan that pins `VerifiedCounterpartyClaim` to a Monero counterparty leg.",
    "SettlementPlanAuthorityV1 (base): DONE — `ProductionRoutePlanAuthorityV1` re-authenticates every plan against the frozen route pins and issues the coordinator-pinned authorization; unit-tested.",
    "TimerAuthority: `ProductionDeadlineTimerAuthorityV1` and its canonical `deadline_context_digest_v1` derivation exist; the composition root has only to build its admitted-deadline map from the two authenticated counterparty deadlines — bounded glue, no missing authority",
    "SettlementChildAuthorityV1: the four counterparty children are composed by this root from a V4 bootstrap; the router still awaits the DOM child, which needs the Relay worker plus a Contracts opening — composable today over `UnavailableF6AuthorityV1` (F6 negotiation fail-closed) with the DOM node RPC endpoint added to the V4 chain-endpoints artifact and the Relay authorities provisioned",
    "SettlementChildObserverV1: same seam as the authority above — counterparty children composed, router awaiting the DOM child",
    "F6TransportPortV1: two distinct things. (a) The DURABLE F6 PORT `ProductionSolverF6AuthorityV2` is a complete `F6TransportPortV1` engine, and `UnavailableF6AuthorityV1` is the fail-closed alternative that lets the runtime compose and drive real chain settlements while F6 negotiation is refused. (b) The REAL F6 NEGOTIATION still needs one authority that does not exist: `ProductionF6TermsAuthorityV2` has only a test `UnreachableTermsV2` impl. Building it is new cross-object cryptographic authority code (RFQ/quote/terms authentication against a real evidence source), not composition glue, and is the one genuine gap between the engine and served RFQ negotiation",
];

/// Explicit fail-closed runner boundary for a composition that has installed
/// no real dispatch authority.
///
/// It refuses every action rather than dispatching one, and it exists so the
/// absence is a named type with a written reason instead of a hole. A route
/// composed with this makes no external dispatch at all, which is the correct
/// behaviour while there is nothing to dispatch through: the alternative is a
/// runner that reports success it did not achieve.
///
/// **This is not the test double.** `production_settlement`'s own test module
/// has a `RefusingRunnerV1` that also returns an error, and it is deliberately
/// not promoted here: it carries no documentation, no reason and a bare
/// generic refusal, so moving it out would dress a test stub as a policy. The
/// two look alike and mean different things.
///
/// **On the refusal variant, because the choice is behavioural and not
/// cosmetic.** [`AuthorityRefusalV1`] has no variant meaning "not installed".
/// `Unavailable` reads closest, and is wrong: `driver.rs`'s
/// `authority_unavailable` classifies it as a temporary condition and backs off
/// to retry, so a route would spin forever waiting for an authority that will
/// never appear. `Refused` stops the route, which is what should happen, and
/// its own wording — "rejected the exact scoped request" — is narrower than
/// what happens here, since every request is refused and not one. The taxonomy
/// has a gap; this picks correct behaviour over a closer name and says so
/// rather than leaving the next reader to wonder which was meant.
pub struct UnavailableRunnerAuthorityV1;

impl core::fmt::Debug for UnavailableRunnerAuthorityV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("UnavailableRunnerAuthorityV1")
            .finish()
    }
}

// The blanket seal impl exists only in laboratory builds, so a production
// authority declares it explicitly, exactly as the four in
// `production_settlement` do.
#[cfg(not(any(feature = "development", feature = "simulation", test)))]
impl authority_seal::Sealed for UnavailableRunnerAuthorityV1 {}

impl RunnerActionAuthority for UnavailableRunnerAuthorityV1 {
    fn externalize_runner_action(
        &mut self,
        _request: RunnerActionRequestV1<'_>,
    ) -> Result<ActionExternalizationReceiptV1, AuthorityRefusalV1> {
        Err(AuthorityRefusalV1::Refused)
    }
}

/// Runs the production composition root as far as it can go today.
///
/// The order is the order the pieces depend on each other, and each step is
/// the one already-reviewed function that owns it:
///
/// 1. the eight out-of-band secrets, read once from standard input;
/// 2. the canonical manifest and its companion, through the V3 loaders;
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
/// 12. the refusal, because the parts named in
///     [`MISSING_PRODUCTION_PARTS_V1`] do not exist.
///
/// **On the trusted second, because the word is doing work.** Step 4 wants a
/// second the composition root vouches for, and this takes it from the host
/// clock. That is a decision and not an obvious wiring: a host clock is not an
/// authenticated time source, and what makes the route's timing safe is the
/// signed time policy and evidence that step 4 itself verifies, not this
/// number. It is used to *enter* that verification, never to satisfy it.
pub fn run_production_v1(options: &ProductionRunOptionsV1) -> Result<(), ProductionRunErrorV1> {
    // Read before anything else touches the filesystem: standard input is
    // consumed in one pass and a supervisor that wrote it is waiting.
    let secrets =
        read_production_secrets_from_stdin().map_err(|_| ProductionRunErrorV1::Secrets)?;
    let secrets = secrets.into_parts();
    let _bearer = secrets.bearer;
    let upstream_relay_signing_secret = secrets.upstream_relay_signing_secret;
    let downstream_relay_signing_secret = secrets.downstream_relay_signing_secret;
    let identity_passphrase = secrets.identity_passphrase;
    let dom_wallet_passphrase = secrets.dom_wallet_passphrase;
    let bitcoin_participant_secret = secrets.bitcoin_participant_secret;
    let route_secret_seal_key = secrets.route_secret_seal_key;
    let _refund_arming_credential = secrets.refund_arming_credential;

    let bootstrap = load_bootstrap(options).map_err(|_| ProductionRunErrorV1::Configuration)?;
    let provisioning_binding = provisioning_binding_for_bootstrap(&bootstrap)
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
    let inputs = match options.mode {
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
    let _route_secret_retention = open_route_secret_retention(
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
    let _coordinator = open_settlement_coordinator(
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
    let _dom_actuator_store =
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
    let evm_actuator_store =
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
    let bitcoin_actuator_store = open_bitcoin_actuator_store(
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

    let chain_signers =
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
    let _solver_inventory = open_solver_inventory_store(
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
    complete_provisioning_stage(
        options.mode,
        contracts_stage,
        ProductionProvisioningStageV1::ContractsStores,
        &mut provisioning,
    )?;

    // The deterministic deadline timer authority. Both counterparty legs
    // freeze an absolute-timestamp deadline; the authority admits exactly
    // those two contexts, derived canonically, and turns a due timer into
    // the recovery-only health event. Self-contained: it needs no endpoint,
    // store or signer, only the two authenticated deadlines.
    let route_id = inputs.admission().route_id();
    let _deadline_timer = compose_production_deadline_timer_v1(&inputs, route_id)?;

    // The counterparty settlement children. With a V4 bootstrap the four
    // chain faces the route admitted are composed here in drive form, from
    // the retained actuator stores, the authenticated sessions and the
    // operator's chain-endpoints artifact — exactly one child per admitted
    // leg, or a named refusal. A V3 bootstrap has no endpoints artifact and
    // composes nothing, which is the old behaviour unchanged.
    let _counterparty_children = match bootstrap.layout().chain_endpoints() {
        Some(endpoints_path) => {
            let endpoints = load_production_chain_endpoints(endpoints_path)
                .map_err(|_| ProductionRunErrorV1::CounterpartyChildren)?;
            let now_unix_ms = u64::try_from(
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map_err(|_| ProductionRunErrorV1::HostClock)?
                    .as_millis(),
            )
            .map_err(|_| ProductionRunErrorV1::HostClock)?;
            Some(
                compose_production_counterparty_children_v1(
                    ProductionCounterpartyCompositionRequestV1 {
                        inputs: &inputs,
                        endpoints: &endpoints,
                        evm_actuator: Some(evm_actuator_store),
                        bitcoin_actuator: Some(bitcoin_actuator_store),
                        bitcoin_prebroadcast_path: bootstrap.layout().bitcoin_prebroadcast_store(),
                        solana_store_path: bootstrap.layout().solana_actuator_store(),
                        xmr_store_path: bootstrap.layout().xmr_actuator_store(),
                        owner_id: pins.process_owner_id,
                        now_unix_ms,
                        actuator_lease_ms: bootstrap.config().bounds().actuator_lease_ms,
                        external_call_timeout_ms: bootstrap
                            .config()
                            .bounds()
                            .external_call_timeout_ms,
                    },
                )
                .map_err(|_| ProductionRunErrorV1::CounterpartyChildren)?,
            )
        }
        None => {
            drop(evm_actuator_store);
            drop(bitcoin_actuator_store);
            None
        }
    };

    // Stages 11 and 12: the phase-1 service plane. The transport identity
    // store, the durable Relay queue and the two Relay-backed Contracts
    // owners compose over the sanctioned fail-closed F6 authority; the two
    // remaining provisioning stages complete inside, in journal order.
    let _route_service = compose_production_route_service_v1(
        ProductionRouteServiceRequestV1 {
            mode: options.mode,
            bootstrap: &bootstrap,
            inputs: &inputs,
            signers: &chain_signers,
            state_capability: Arc::clone(&state_capability),
            upstream_store: contracts_stores.upstream,
            downstream_store: contracts_stores.downstream,
            identity_passphrase,
            upstream_relay_signing_secret,
            downstream_relay_signing_secret,
        },
        &mut provisioning,
    )
    .map_err(|_| ProductionRunErrorV1::RelayAuthorities)?;

    // The composition point. Stages 1 through 12 above exist and have run,
    // and with a V4 bootstrap the counterparty settlement children exist
    // beside them; everything below is named in
    // `MISSING_PRODUCTION_PARTS_V1`. The two raw Contracts store owners are
    // retained above; the relay worker, the DOM child and the route runtime
    // are composed here once those parts exist, and deliberately not before:
    // a route driven by anything other than its real authorities would
    // report progress it did not make.
    Err(ProductionRunErrorV1::NotComposable)
}

fn compose_production_deadline_timer_v1(
    inputs: &AuthenticatedProductionInputsV1,
    route_id: [u8; 32],
) -> Result<ProductionDeadlineTimerAuthorityV1, ProductionRunErrorV1> {
    let composition = inputs.composition();
    let mut bindings = Vec::with_capacity(2);
    for (leg, terms) in [
        (LegIdV1::Upstream, composition.upstream()),
        (LegIdV1::Downstream, composition.downstream()),
    ] {
        let deadline_seconds = match terms.counterparty_leg.deadline {
            TimelockSpec::TimestampSeconds { value } if value != 0 => value,
            // A non-timestamp counterparty deadline has no wall-clock context
            // to schedule against; the timer authority never admits one.
            _ => return Err(ProductionRunErrorV1::CounterpartyChildren),
        };
        let terms_digest = terms
            .terms_hash()
            .map_err(|_| ProductionRunErrorV1::CounterpartyChildren)?;
        let deadline_unix_ms = deadline_seconds
            .checked_mul(1000)
            .ok_or(ProductionRunErrorV1::CounterpartyChildren)?;
        let leg_tag = match leg {
            LegIdV1::Upstream => 1u8,
            LegIdV1::Downstream => 2u8,
        };
        let context_digest =
            deadline_context_digest_v1(route_id, leg_tag, 0, terms_digest, deadline_unix_ms)
                .map_err(|_| ProductionRunErrorV1::CounterpartyChildren)?;
        bindings.push(
            ProductionDeadlineBindingV1::new(context_digest, deadline_unix_ms)
                .map_err(|_| ProductionRunErrorV1::CounterpartyChildren)?,
        );
    }
    ProductionDeadlineTimerAuthorityV1::new(route_id, bindings)
        .map_err(|_| ProductionRunErrorV1::CounterpartyChildren)
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
) -> Result<(), ProductionRunErrorV1> {
    ContractsSessionStoreV1::preflight_resume_create_production(
        Arc::clone(&parent),
        upstream_root,
        policy,
        creation_binding,
    )
    .map_err(|_| ProductionRunErrorV1::ContractsStores)?;
    ContractsSessionStoreV1::preflight_resume_create_production(
        parent,
        downstream_root,
        policy,
        creation_binding,
    )
    .map_err(|_| ProductionRunErrorV1::ContractsStores)
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
            )?;
            let upstream = ContractsSessionStoreV1::resume_create_production(
                Arc::clone(&parent),
                upstream_root,
                policy.clone(),
                creation_binding,
            )
            .map_err(|_| ProductionRunErrorV1::ContractsStores)?;
            let downstream = ContractsSessionStoreV1::resume_create_production(
                parent,
                downstream_root,
                policy,
                creation_binding,
            )
            .map_err(|_| ProductionRunErrorV1::ContractsStores)?;
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
    // The V4 manifest pair wins when present; a state directory without it
    // stays on the V3 family and everything V3 could do keeps working. The
    // fallback is on the exact absent-manifest refusal only, so a corrupt V4
    // manifest is an error, never silently a V3 deployment.
    match options.mode {
        ProductionRunModeV1::Create => {
            match load_production_create_or_resume_bootstrap_v4(&options.state_dir) {
                Ok(bootstrap) => Ok(bootstrap),
                Err(ProductionConfigErrorV1::ConfigUnavailable) => {
                    load_production_create_or_resume_bootstrap_v3(&options.state_dir)
                }
                Err(error) => Err(error),
            }
        }
        ProductionRunModeV1::ReopenExisting => {
            match load_production_reopen_bootstrap_v4(&options.state_dir) {
                Ok(bootstrap) => Ok(bootstrap),
                Err(ProductionConfigErrorV1::ConfigUnavailable) => {
                    load_production_reopen_bootstrap_v3(&options.state_dir)
                }
                Err(error) => Err(error),
            }
        }
    }
}

/// Seconds since the Unix epoch, from the host clock. See the note on
/// [`run_production_v1`] about what this is and is not.
fn trusted_now_seconds_v1() -> Result<u64, ProductionRunErrorV1> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .map_err(|_| ProductionRunErrorV1::HostClock)
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
        for prefix in ["none", "upstream", "downstream", "both"] {
            let temporary = tempfile::tempdir()?;
            std::fs::set_permissions(temporary.path(), std::fs::Permissions::from_mode(0o700))?;
            let policy = production_contracts_policy(0x41)?;
            if matches!(prefix, "upstream" | "both") {
                drop(ContractsSessionStoreV1::resume_create_production(
                    state_dir_capability(temporary.path())?,
                    UPSTREAM,
                    policy.clone(),
                    binding,
                )?);
            }
            if matches!(prefix, "downstream" | "both") {
                drop(ContractsSessionStoreV1::resume_create_production(
                    state_dir_capability(temporary.path())?,
                    DOWNSTREAM,
                    policy.clone(),
                    binding,
                )?);
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
        drop(ContractsSessionStoreV1::resume_create_production(
            state_dir_capability(temporary.path())?,
            UPSTREAM,
            policy.clone(),
            binding,
        )?);
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
