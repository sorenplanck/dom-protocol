//! Strict, secret-free bootstrap configuration for one production route.
//!
//! This module is deliberately independent from the process composition code.
//! It authenticates no chain fact and mints no protocol capability. Instead,
//! it freezes public identities, commitments, runtime bounds and relative path
//! references, then verifies the physical state layout before any authority is
//! opened. The registry, route-time, participant-binding, Relay, coordinator
//! and actuator authorities remain responsible for authenticating their own
//! retained bytes.

use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::fs::{self, File};
use std::io::Read;
#[cfg(target_os = "linux")]
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};

use blake2::{
    digest::{Update, VariableOutput},
    Blake2bVar,
};

#[cfg(feature = "production")]
use crate::production_provisioning::{
    provisioning_binding_v1, DurableProductionProvisioningJournalV1, ProductionProvisioningErrorV1,
    ProductionProvisioningStageStateV1, ProductionProvisioningStageV1,
    ROUTE_SECRET_VAULT_ROOT_NAME_V1,
};

/// Fixed provisioning manifest name. It is never used for recovery.
pub const PRODUCTION_CREATE_CONFIG_FILE_V1: &str = "bootstrap-create-v1.conf";
/// Fixed recovery manifest name. Recovery never falls back to the create file.
pub const PRODUCTION_REOPEN_CONFIG_FILE_V1: &str = "bootstrap-reopen-v1.conf";
/// Maximum accepted bootstrap manifest size, checked before allocation.
pub const MAX_PRODUCTION_BOOTSTRAP_BYTES_V1: u64 = 16 * 1024;
/// Maximum length of one relative state reference.
pub const MAX_PRODUCTION_RELATIVE_PATH_BYTES_V1: usize = 192;
/// Exact number of public path references in the V1 layout.
pub const PRODUCTION_PATH_ROLE_COUNT_V1: usize = 28;
/// Fixed V2 provisioning manifest name. The V1 loader never accepts it.
pub const PRODUCTION_CREATE_CONFIG_FILE_V2: &str = "bootstrap-create-v2.conf";
/// Fixed V2 recovery manifest name. The V1 loader never accepts it.
pub const PRODUCTION_REOPEN_CONFIG_FILE_V2: &str = "bootstrap-reopen-v2.conf";
/// Fixed node-global configuration name, resolved only under the same trusted
/// state directory. It is never referenced by a manifest path role.
pub const PRODUCTION_NODE_CONFIG_FILE_V1: &str = "node.v1";
/// Exact number of public path references in the V2 layout: the V1 set plus
/// the externally provisioned Contracts transport identity authority.
pub const PRODUCTION_PATH_ROLE_COUNT_V2: usize = 29;
/// Fixed V3 provisioning manifest name. No earlier loader accepts it.
pub const PRODUCTION_CREATE_CONFIG_FILE_V3: &str = "bootstrap-create-v3.conf";
/// Fixed V3 recovery manifest name. No earlier loader accepts it.
pub const PRODUCTION_REOPEN_CONFIG_FILE_V3: &str = "bootstrap-reopen-v3.conf";
/// Exact number of public path references in the V3 layout: the V2 set plus
/// the externally provisioned Contracts budget policy artifact.
///
/// The count grows per family and the V1 constant never moves, which is what
/// keeps every already-provisioned manifest of every earlier family readable:
/// the line count a decoder expects is a function of the family it was asked
/// for, never of the newest one.
pub const PRODUCTION_PATH_ROLE_COUNT_V3: usize = 30;
/// Fixed V4 provisioning manifest name. No earlier loader accepts it.
pub const PRODUCTION_CREATE_CONFIG_FILE_V4: &str = "bootstrap-create-v4.conf";
/// Fixed V4 recovery manifest name. No earlier loader accepts it.
pub const PRODUCTION_REOPEN_CONFIG_FILE_V4: &str = "bootstrap-reopen-v4.conf";
/// Exact number of public path references in the V4 layout: the V3 set plus
/// the chain-endpoints artifact, the Solana and Monero actuator stores, and
/// the Bitcoin prebroadcast store the external arming flow writes into.
pub const PRODUCTION_PATH_ROLE_COUNT_V4: usize = 34;

const HEADER_V1: &str = "DOM-INTEROPD-BOOTSTRAP-V1";
const HEADER_V2: &str = "DOM-INTEROPD-BOOTSTRAP-V2";
const HEADER_V3: &str = "DOM-INTEROPD-BOOTSTRAP-V3";
const HEADER_V4: &str = "DOM-INTEROPD-BOOTSTRAP-V4";
const IDENTITY_STORE_KEY_V2: &str = "path_contracts_transport_identity_store";
const BUDGET_POLICY_KEY_V3: &str = "path_contracts_budget_policy";
const CHAIN_ENDPOINTS_KEY_V4: &str = "path_chain_endpoints";
const SOLANA_ACTUATOR_STORE_KEY_V4: &str = "path_solana_actuator_store";
const XMR_ACTUATOR_STORE_KEY_V4: &str = "path_xmr_actuator_store";
const BITCOIN_PREBROADCAST_STORE_KEY_V4: &str = "path_bitcoin_prebroadcast_store";
const END_V1: &str = "end=1";
const CONFIG_DIGEST_DOMAIN_V1: &[u8] = b"DOM-INTEROPD/BOOTSTRAP-CONFIG/V1\0";
const DIRECTORY_MODE_V1: u32 = 0o700;
const FILE_MODE_V1: u32 = 0o600;
const MIN_LEASE_DURATION_MS_V1: u64 = 60_000;
const MAX_LEASE_DURATION_MS_V1: u64 = 600_000;
const MIN_EXTERNAL_CALL_TIMEOUT_MS_V1: u64 = 1_000;
const MAX_EXTERNAL_CALL_TIMEOUT_MS_V1: u64 = 60_000;
const MIN_BACKOFF_MS_V1: u64 = 10;
const MAX_BACKOFF_MS_V1: u64 = 30_000;
const MAX_PATH_SEGMENTS_V1: usize = 6;
const MAX_PATH_SEGMENT_BYTES_V1: usize = 48;
const MAX_INPUT_ARTIFACT_BYTES_V1: u64 = 512 * 1024 * 1024;
const ZERO_DIGEST: [u8; 32] = [0; 32];
// Must stay byte-identical to the journal module's fixed root. This local copy
// also keeps the config-only codec build independent from the production graph.
const PRODUCTION_PROVISIONING_ROOT_RESERVED_V1: &str = "production-provisioning-v1";
const PRODUCTION_PROVISIONING_STAGING_RESERVED_V1: &str = "production-provisioning-v1.new";

/// Whether this invocation is provisioning new stores or reopening all of
/// them after a process restart.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProductionBootstrapModeV1 {
    /// Every managed store leaf must be absent. All immutable input artifacts
    /// and a byte-equivalent reopen companion manifest must already exist.
    Create,
    /// Every managed store must already exist with the expected physical type.
    /// No missing state is created or repaired.
    ReopenExisting,
}

/// Which frozen manifest family a document belongs to.
///
/// V1 is the 28-role golden layout and is preserved byte for byte. V2 is the
/// same document plus exactly one externally provisioned identity authority,
/// under its own header and its own file names, so neither loader can ever
/// accept the other family's bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ProductionBootstrapFamilyV1 {
    V1,
    V2,
    V3,
    V4,
}

impl ProductionBootstrapFamilyV1 {
    const fn header(self) -> &'static str {
        match self {
            Self::V1 => HEADER_V1,
            Self::V2 => HEADER_V2,
            Self::V3 => HEADER_V3,
            Self::V4 => HEADER_V4,
        }
    }

    const fn path_role_count(self) -> usize {
        match self {
            Self::V1 => PRODUCTION_PATH_ROLE_COUNT_V1,
            Self::V2 => PRODUCTION_PATH_ROLE_COUNT_V2,
            Self::V3 => PRODUCTION_PATH_ROLE_COUNT_V3,
            Self::V4 => PRODUCTION_PATH_ROLE_COUNT_V4,
        }
    }
}

impl ProductionBootstrapModeV1 {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Create => "create",
            Self::ReopenExisting => "reopen_existing",
        }
    }

    fn parse(value: &str) -> Result<Self, ProductionConfigErrorV1> {
        match value {
            "create" => Ok(Self::Create),
            "reopen_existing" => Ok(Self::ReopenExisting),
            _ => Err(ProductionConfigErrorV1::InvalidCanonicalEncoding),
        }
    }
}

/// Physical expectation for one path role.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProductionPathKindV1 {
    /// Immutable or externally managed regular file that must already exist in
    /// both modes. Its owning authority performs semantic authentication.
    InputFile,
    /// Daemon-managed regular-file store, absent on create and present on
    /// reopen.
    ManagedFile,
    /// Daemon-managed directory-root authority, absent on create and present
    /// on reopen.
    ManagedDirectory,
    /// Directory authority provisioned outside the daemon. It must already
    /// exist in both modes; the daemon never creates it and never replaces a
    /// missing identity authority with fresh material.
    ExistingAuthorityDirectory,
}

/// Complete fixed set of input and durable-state references for one composed
/// route. The list intentionally has no endpoint, credential or generic file
/// escape hatch.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
#[repr(u8)]
pub enum ProductionPathRoleV1 {
    /// Threshold-authenticated deployment registry database.
    RegistryStore = 0,
    /// Public bundle of distinct registry, time-policy and time-evidence sets.
    RegistryAuthorities = 1,
    /// Canonical upstream settlement terms artifact.
    UpstreamTerms = 2,
    /// Canonical downstream settlement terms artifact.
    DownstreamTerms = 3,
    /// Dual-signed participant/account binding bundle.
    ParticipantBindings = 4,
    /// Public Relay roster snapshot bundle.
    RelayRoster = 5,
    /// Threshold-signed route-time policy artifact.
    TimePolicy = 6,
    /// Threshold-signed route-time evidence artifact.
    TimeEvidence = 7,
    /// Existing encrypted DOM participant wallet. No password is stored here.
    DomWallet = 8,
    /// Durable route journal/outbox/timer store.
    RouteStore = 9,
    /// Durable V2 cross-chain time authority.
    TimeAnchorStore = 10,
    /// Durable two-face settlement coordinator.
    CoordinatorStore = 11,
    /// DOM actuator control/custody store.
    DomActuatorStore = 12,
    /// EVM actuator operation/nonce/receipt store.
    EvmActuatorStore = 13,
    /// Bitcoin actuator operation store.
    BitcoinActuatorStore = 14,
    /// Bitcoin participant signing-session durable state.
    BitcoinParticipantState = 15,
    /// Upstream DOM collaborative-session durable state.
    DomUpstreamParticipantState = 16,
    /// Downstream DOM collaborative-session durable state.
    DomDownstreamParticipantState = 17,
    /// Solver inventory and bond reservation store.
    SolverInventoryStore = 18,
    /// Local durable Relay store-and-forward queue.
    RelayQueue = 19,
    /// Upstream Relay sender/outbox authority root.
    UpstreamRelaySender = 20,
    /// Upstream Relay inbox authority root.
    UpstreamRelayInbox = 21,
    /// Upstream Relay frame-reassembly authority root.
    UpstreamRelayFrames = 22,
    /// Upstream Contracts Store authority root.
    UpstreamContracts = 23,
    /// Downstream Relay sender/outbox authority root.
    DownstreamRelaySender = 24,
    /// Downstream Relay inbox authority root.
    DownstreamRelayInbox = 25,
    /// Downstream Relay frame-reassembly authority root.
    DownstreamRelayFrames = 26,
    /// Downstream Contracts Store authority root.
    DownstreamContracts = 27,
}

impl ProductionPathRoleV1 {
    /// Roles in their only canonical V1 encoding order.
    pub const ALL: [Self; PRODUCTION_PATH_ROLE_COUNT_V1] = [
        Self::RegistryStore,
        Self::RegistryAuthorities,
        Self::UpstreamTerms,
        Self::DownstreamTerms,
        Self::ParticipantBindings,
        Self::RelayRoster,
        Self::TimePolicy,
        Self::TimeEvidence,
        Self::DomWallet,
        Self::RouteStore,
        Self::TimeAnchorStore,
        Self::CoordinatorStore,
        Self::DomActuatorStore,
        Self::EvmActuatorStore,
        Self::BitcoinActuatorStore,
        Self::BitcoinParticipantState,
        Self::DomUpstreamParticipantState,
        Self::DomDownstreamParticipantState,
        Self::SolverInventoryStore,
        Self::RelayQueue,
        Self::UpstreamRelaySender,
        Self::UpstreamRelayInbox,
        Self::UpstreamRelayFrames,
        Self::UpstreamContracts,
        Self::DownstreamRelaySender,
        Self::DownstreamRelayInbox,
        Self::DownstreamRelayFrames,
        Self::DownstreamContracts,
    ];

    /// Canonical configuration key.
    pub const fn key(self) -> &'static str {
        match self {
            Self::RegistryStore => "path_registry_store",
            Self::RegistryAuthorities => "path_registry_authorities",
            Self::UpstreamTerms => "path_upstream_terms",
            Self::DownstreamTerms => "path_downstream_terms",
            Self::ParticipantBindings => "path_participant_bindings",
            Self::RelayRoster => "path_relay_roster",
            Self::TimePolicy => "path_time_policy",
            Self::TimeEvidence => "path_time_evidence",
            Self::DomWallet => "path_dom_wallet",
            Self::RouteStore => "path_route_store",
            Self::TimeAnchorStore => "path_time_anchor_store",
            Self::CoordinatorStore => "path_coordinator_store",
            Self::DomActuatorStore => "path_dom_actuator_store",
            Self::EvmActuatorStore => "path_evm_actuator_store",
            Self::BitcoinActuatorStore => "path_bitcoin_actuator_store",
            Self::BitcoinParticipantState => "path_bitcoin_participant_state",
            Self::DomUpstreamParticipantState => "path_dom_upstream_participant_state",
            Self::DomDownstreamParticipantState => "path_dom_downstream_participant_state",
            Self::SolverInventoryStore => "path_solver_inventory_store",
            Self::RelayQueue => "path_relay_queue",
            Self::UpstreamRelaySender => "path_upstream_relay_sender",
            Self::UpstreamRelayInbox => "path_upstream_relay_inbox",
            Self::UpstreamRelayFrames => "path_upstream_relay_frames",
            Self::UpstreamContracts => "path_upstream_contracts",
            Self::DownstreamRelaySender => "path_downstream_relay_sender",
            Self::DownstreamRelayInbox => "path_downstream_relay_inbox",
            Self::DownstreamRelayFrames => "path_downstream_relay_frames",
            Self::DownstreamContracts => "path_downstream_contracts",
        }
    }

    /// Required physical type and create/reopen semantics.
    pub const fn kind(self) -> ProductionPathKindV1 {
        match self {
            Self::RegistryStore
            | Self::RegistryAuthorities
            | Self::UpstreamTerms
            | Self::DownstreamTerms
            | Self::ParticipantBindings
            | Self::RelayRoster
            | Self::TimePolicy
            | Self::TimeEvidence
            | Self::DomWallet => ProductionPathKindV1::InputFile,
            Self::RouteStore
            | Self::TimeAnchorStore
            | Self::CoordinatorStore
            | Self::DomActuatorStore
            | Self::EvmActuatorStore
            | Self::BitcoinActuatorStore
            | Self::BitcoinParticipantState
            | Self::DomUpstreamParticipantState
            | Self::DomDownstreamParticipantState
            | Self::SolverInventoryStore => ProductionPathKindV1::ManagedFile,
            Self::RelayQueue
            | Self::UpstreamRelaySender
            | Self::UpstreamRelayInbox
            | Self::UpstreamRelayFrames
            | Self::UpstreamContracts
            | Self::DownstreamRelaySender
            | Self::DownstreamRelayInbox
            | Self::DownstreamRelayFrames
            | Self::DownstreamContracts => ProductionPathKindV1::ManagedDirectory,
        }
    }

    const fn index(self) -> usize {
        self as usize
    }
}

/// Public, non-secret commitments needed to bind recovery to the same route.
///
/// These values are compared by the composition root with the outputs of the
/// authenticated authorities. A digest in this structure is not itself proof.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct ProductionRoutePinsV1 {
    /// DOM interoperability network identity.
    pub network_id: [u8; 32],
    /// Composed route identity.
    pub route_id: [u8; 32],
    /// Threshold-authenticated registry manifest digest.
    pub registry_manifest_digest: [u8; 32],
    /// External rollback floor for the registry.
    pub registry_minimum_epoch: u64,
    /// Digest of the public registry authority set.
    pub registry_authority_set_digest: [u8; 32],
    /// Digest of the independent route-time policy authority set.
    pub time_policy_authority_set_digest: [u8; 32],
    /// Digest of the independent route-time evidence authority set.
    pub time_evidence_authority_set_digest: [u8; 32],
    /// Canonical upstream terms digest.
    pub upstream_terms_digest: [u8; 32],
    /// Canonical downstream terms digest.
    pub downstream_terms_digest: [u8; 32],
    /// Ordered terms scope used by the V2 time authority.
    pub route_scope_digest: [u8; 32],
    /// Digest of the participant/account binding bundle.
    pub participant_bindings_digest: [u8; 32],
    /// Digest of both Relay wire contexts and roster snapshots.
    pub relay_binding_digest: [u8; 32],
    /// Threshold-signed route-time policy digest.
    pub time_policy_digest: [u8; 32],
    /// Threshold-signed current route-time evidence digest.
    pub time_evidence_digest: [u8; 32],
    /// Stable public process owner identity used by fenced stores.
    pub process_owner_id: [u8; 32],
    /// Settlement coordinator identity pinned by its store.
    pub coordinator_id: [u8; 32],
    /// Settlement plan-authority identity pinned by the coordinator.
    pub coordinator_plan_authority_id: [u8; 32],
    /// Digest binding the concrete DOM/EVM/Bitcoin actuator authorities.
    pub actuator_bindings_digest: [u8; 32],
    /// Digest binding the solver inventory/bond authority.
    pub solver_inventory_binding_digest: [u8; 32],
}

impl core::fmt::Debug for ProductionRoutePinsV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("ProductionRoutePinsV1([redacted])")
    }
}

impl ProductionRoutePinsV1 {
    fn validate(self) -> Result<Self, ProductionConfigErrorV1> {
        if self.registry_minimum_epoch == 0 {
            return Err(ProductionConfigErrorV1::InvalidPublicBinding);
        }
        let digests = [
            self.network_id,
            self.route_id,
            self.registry_manifest_digest,
            self.registry_authority_set_digest,
            self.time_policy_authority_set_digest,
            self.time_evidence_authority_set_digest,
            self.upstream_terms_digest,
            self.downstream_terms_digest,
            self.route_scope_digest,
            self.participant_bindings_digest,
            self.relay_binding_digest,
            self.time_policy_digest,
            self.time_evidence_digest,
            self.process_owner_id,
            self.coordinator_id,
            self.coordinator_plan_authority_id,
            self.actuator_bindings_digest,
            self.solver_inventory_binding_digest,
        ];
        let mut distinct = BTreeSet::new();
        for digest in digests {
            if digest == ZERO_DIGEST || !distinct.insert(digest) {
                return Err(ProductionConfigErrorV1::InvalidPublicBinding);
            }
        }
        Ok(self)
    }
}

/// Bounded orchestration timings. Chain clients may use stricter fixed limits,
/// but must never exceed `external_call_timeout_ms` at this boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProductionRuntimeBoundsV1 {
    /// Route supervisor lease lifetime.
    pub lease_duration_ms: u64,
    /// Remaining lifetime at which the route lease is renewed.
    pub renew_before_ms: u64,
    /// Exact outbox/custody dispatch lease.
    pub dispatch_lease_ms: u64,
    /// Settlement coordinator lease lifetime.
    pub coordinator_lease_ms: u64,
    /// DOM/EVM/Bitcoin actuator lease lifetime.
    pub actuator_lease_ms: u64,
    /// Maximum one external authority call may block.
    pub external_call_timeout_ms: u64,
    /// Backoff for unavailable but healthy authorities.
    pub waiting_backoff_ms: u64,
    /// Backoff while funded state is in recovery.
    pub recovery_backoff_ms: u64,
    /// Relay mailbox polling backoff.
    pub relay_poll_backoff_ms: u64,
    /// The driver is structurally single-action; V1 requires exactly one.
    pub per_queue_batch_limit: u64,
}

impl ProductionRuntimeBoundsV1 {
    fn validate(self) -> Result<Self, ProductionConfigErrorV1> {
        let safe_sleep = self
            .lease_duration_ms
            .checked_sub(self.renew_before_ms)
            .ok_or(ProductionConfigErrorV1::InvalidRuntimeBounds)?;
        let backoffs = [
            self.waiting_backoff_ms,
            self.recovery_backoff_ms,
            self.relay_poll_backoff_ms,
        ];
        if self.lease_duration_ms < MIN_LEASE_DURATION_MS_V1
            || self.lease_duration_ms > MAX_LEASE_DURATION_MS_V1
            || self.renew_before_ms == 0
            || self.renew_before_ms >= self.lease_duration_ms
            || self.dispatch_lease_ms == 0
            || self.dispatch_lease_ms > self.renew_before_ms
            || self.coordinator_lease_ms < self.dispatch_lease_ms
            || self.coordinator_lease_ms > MAX_LEASE_DURATION_MS_V1
            || self.actuator_lease_ms < self.dispatch_lease_ms
            || self.actuator_lease_ms > MAX_LEASE_DURATION_MS_V1
            || self.external_call_timeout_ms < MIN_EXTERNAL_CALL_TIMEOUT_MS_V1
            || self.external_call_timeout_ms > MAX_EXTERNAL_CALL_TIMEOUT_MS_V1
            || self.external_call_timeout_ms > self.dispatch_lease_ms
            || self.recovery_backoff_ms > self.waiting_backoff_ms
            || self.relay_poll_backoff_ms > self.waiting_backoff_ms
            || self.per_queue_batch_limit != 1
            || backoffs.iter().any(|value| {
                *value < MIN_BACKOFF_MS_V1 || *value > MAX_BACKOFF_MS_V1 || *value > safe_sleep
            })
        {
            return Err(ProductionConfigErrorV1::InvalidRuntimeBounds);
        }
        Ok(self)
    }
}

/// Canonical relative references. Values are validated lexically before any
/// state path is joined to the trusted root.
#[derive(Clone, Eq, PartialEq)]
pub struct ProductionPathReferencesV1 {
    paths: [String; PRODUCTION_PATH_ROLE_COUNT_V1],
}

impl core::fmt::Debug for ProductionPathReferencesV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("ProductionPathReferencesV1([redacted])")
    }
}

impl ProductionPathReferencesV1 {
    /// Validates an ordered array corresponding exactly to
    /// [`ProductionPathRoleV1::ALL`].
    pub fn from_ordered(
        paths: [String; PRODUCTION_PATH_ROLE_COUNT_V1],
    ) -> Result<Self, ProductionConfigErrorV1> {
        validate_path_set(paths.as_slice())?;
        Ok(Self { paths })
    }

    /// Relative path for one fixed role.
    pub fn get(&self, role: ProductionPathRoleV1) -> &Path {
        Path::new(&self.paths[role.index()])
    }
}

/// Parsed canonical configuration. It contains public commitments and path
/// references only. Debug output remains redacted to prevent operational path
/// disclosure.
#[derive(Clone, Eq, PartialEq)]
pub struct ProductionBootstrapConfigV1 {
    mode: ProductionBootstrapModeV1,
    pins: ProductionRoutePinsV1,
    bounds: ProductionRuntimeBoundsV1,
    paths: ProductionPathReferencesV1,
    /// The references a family adds beyond the 28 V1 roles.
    ///
    /// One field with three states rather than one `Option` per extra, and the
    /// difference is not cosmetic: with separate options the space is a power
    /// of two and at least one combination — a later family's reference
    /// present while an earlier one is absent — would be representable and
    /// held off only by convention. As a single enum the family is a total
    /// function of the value, `family()` cannot fail, and the illegal state
    /// has nowhere to exist.
    ///
    /// [`ProductionFamilyExtrasV1::None`] reproduces the V1 golden exactly,
    /// and `V2` reproduces the V2 golden exactly: the encoder emits from this
    /// field and from nothing else.
    extras: ProductionFamilyExtrasV1,
}

/// References a bootstrap family adds beyond the 28 V1 path roles.
///
/// These are deliberately **not** variants of [`ProductionPathRoleV1`]: that
/// enum is the spine of the V1 line count and of `ALL`, and extending it would
/// move every already-provisioned manifest of every family. Extras live beside
/// it, one variant per family, which is how V2 was added and how V3 will be.
/// No `Debug`, deliberately: the variants hold operational path references,
/// and the configuration that owns them redacts its own `Debug` for exactly
/// that reason. A derived formatter here would be a way around that redaction
/// that nobody chose.
#[derive(Clone, PartialEq, Eq)]
enum ProductionFamilyExtrasV1 {
    /// The V1 family adds nothing.
    None,
    /// The V2 family adds the externally provisioned Contracts transport
    /// identity authority.
    V2 { identity_store: String },
    /// The V3 family adds the externally provisioned Contracts budget policy
    /// artifact, alongside everything V2 carries.
    ///
    /// Both references are named in one variant rather than in two options,
    /// which is what makes "a budget policy without an identity store"
    /// unrepresentable instead of merely undocumented.
    V3 {
        identity_store: String,
        budget_policy: String,
    },
    /// The V4 family adds what the counterparty settlement children need:
    /// the chain-endpoints artifact and the durable stores of the Solana and
    /// Monero actuators, plus the Bitcoin prebroadcast store the external
    /// funding-arming flow writes into. One variant, six references — a
    /// configuration carrying the endpoints without the stores they feed is
    /// unrepresentable, not merely discouraged.
    V4 {
        identity_store: String,
        budget_policy: String,
        chain_endpoints: String,
        solana_actuator_store: String,
        xmr_actuator_store: String,
        bitcoin_prebroadcast_store: String,
    },
}

impl core::fmt::Debug for ProductionBootstrapConfigV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("ProductionBootstrapConfigV1([redacted])")
    }
}

impl ProductionBootstrapConfigV1 {
    /// Builds a canonical public configuration for deployment tooling.
    pub fn from_parts(
        mode: ProductionBootstrapModeV1,
        pins: ProductionRoutePinsV1,
        bounds: ProductionRuntimeBoundsV1,
        paths: ProductionPathReferencesV1,
    ) -> Result<Self, ProductionConfigErrorV1> {
        Ok(Self {
            mode,
            pins: pins.validate()?,
            bounds: bounds.validate()?,
            paths,
            extras: ProductionFamilyExtrasV1::None,
        })
    }

    /// Builds a canonical V2 configuration: the exact V1 document plus the one
    /// externally provisioned Contracts transport identity authority.
    ///
    /// The extra reference is validated lexically and cross-checked against all
    /// 28 V1 references, so it can never alias, contain or be contained by an
    /// existing authority root.
    pub fn from_parts_v2(
        mode: ProductionBootstrapModeV1,
        pins: ProductionRoutePinsV1,
        bounds: ProductionRuntimeBoundsV1,
        paths: ProductionPathReferencesV1,
        contracts_transport_identity_store: String,
    ) -> Result<Self, ProductionConfigErrorV1> {
        let mut extended = Vec::with_capacity(PRODUCTION_PATH_ROLE_COUNT_V2);
        extended.extend_from_slice(&paths.paths);
        extended.push(contracts_transport_identity_store.clone());
        validate_path_set(&extended)?;
        Ok(Self {
            mode,
            pins: pins.validate()?,
            bounds: bounds.validate()?,
            paths,
            extras: ProductionFamilyExtrasV1::V2 {
                identity_store: contracts_transport_identity_store,
            },
        })
    }

    /// Builds a V3 configuration: the V2 set plus the budget policy artifact.
    ///
    /// Both extra references are required together, which is the whole reason
    /// the extras are one enum: there is no way to reach a state carrying a
    /// budget policy without an identity store, so no later reader has to ask
    /// whether it is looking at a half-built V3.
    ///
    /// The full reference set is validated as one, so the two new references
    /// can no more alias, contain or be contained by an existing authority
    /// root than the 28 V1 ones can.
    pub fn from_parts_v3(
        mode: ProductionBootstrapModeV1,
        pins: ProductionRoutePinsV1,
        bounds: ProductionRuntimeBoundsV1,
        paths: ProductionPathReferencesV1,
        contracts_transport_identity_store: String,
        contracts_budget_policy: String,
    ) -> Result<Self, ProductionConfigErrorV1> {
        let mut extended = Vec::with_capacity(PRODUCTION_PATH_ROLE_COUNT_V3);
        extended.extend_from_slice(&paths.paths);
        extended.push(contracts_transport_identity_store.clone());
        extended.push(contracts_budget_policy.clone());
        validate_path_set(&extended)?;
        Ok(Self {
            mode,
            pins: pins.validate()?,
            bounds: bounds.validate()?,
            paths,
            extras: ProductionFamilyExtrasV1::V3 {
                identity_store: contracts_transport_identity_store,
                budget_policy: contracts_budget_policy,
            },
        })
    }

    /// Builds a V4 configuration: the V3 set plus the chain-endpoints
    /// artifact, the Solana and Monero actuator stores and the Bitcoin
    /// prebroadcast store.
    ///
    /// All four new references arrive together, for the same reason V3's two
    /// did: the counterparty children consume them as one unit, and a partial
    /// set is a state nobody should be able to write down.
    #[allow(clippy::too_many_arguments)]
    pub fn from_parts_v4(
        mode: ProductionBootstrapModeV1,
        pins: ProductionRoutePinsV1,
        bounds: ProductionRuntimeBoundsV1,
        paths: ProductionPathReferencesV1,
        contracts_transport_identity_store: String,
        contracts_budget_policy: String,
        chain_endpoints: String,
        solana_actuator_store: String,
        xmr_actuator_store: String,
        bitcoin_prebroadcast_store: String,
    ) -> Result<Self, ProductionConfigErrorV1> {
        let mut extended = Vec::with_capacity(PRODUCTION_PATH_ROLE_COUNT_V4);
        extended.extend_from_slice(&paths.paths);
        extended.push(contracts_transport_identity_store.clone());
        extended.push(contracts_budget_policy.clone());
        extended.push(chain_endpoints.clone());
        extended.push(solana_actuator_store.clone());
        extended.push(xmr_actuator_store.clone());
        extended.push(bitcoin_prebroadcast_store.clone());
        validate_path_set(&extended)?;
        Ok(Self {
            mode,
            pins: pins.validate()?,
            bounds: bounds.validate()?,
            paths,
            extras: ProductionFamilyExtrasV1::V4 {
                identity_store: contracts_transport_identity_store,
                budget_policy: contracts_budget_policy,
                chain_endpoints,
                solana_actuator_store,
                xmr_actuator_store,
                bitcoin_prebroadcast_store,
            },
        })
    }

    /// Externally provisioned Contracts transport identity authority, present
    /// only in the V2 family.
    pub fn contracts_transport_identity_store(&self) -> Option<&Path> {
        match &self.extras {
            ProductionFamilyExtrasV1::None => None,
            ProductionFamilyExtrasV1::V2 { identity_store }
            | ProductionFamilyExtrasV1::V3 { identity_store, .. }
            | ProductionFamilyExtrasV1::V4 { identity_store, .. } => {
                Some(Path::new(identity_store))
            }
        }
    }

    /// Externally provisioned Contracts budget policy artifact, present only
    /// in the V3 family.
    ///
    /// The policy is a provisioned input like the registry authorities, not
    /// something the composition root may invent: the Contracts session store
    /// refuses any profile that is not `ProductionRatified` and cross-checks
    /// the caller's policy byte for byte against the one it persisted, so a
    /// policy chosen at startup would be refused by the store on the second
    /// run even if it were accepted on the first.
    pub fn contracts_budget_policy(&self) -> Option<&Path> {
        match &self.extras {
            ProductionFamilyExtrasV1::None | ProductionFamilyExtrasV1::V2 { .. } => None,
            ProductionFamilyExtrasV1::V3 { budget_policy, .. }
            | ProductionFamilyExtrasV1::V4 { budget_policy, .. } => Some(Path::new(budget_policy)),
        }
    }

    /// Chain-endpoints artifact reference, present only in the V4 family.
    pub fn chain_endpoints(&self) -> Option<&Path> {
        match &self.extras {
            ProductionFamilyExtrasV1::V4 {
                chain_endpoints, ..
            } => Some(Path::new(chain_endpoints)),
            _ => None,
        }
    }

    /// Solana actuator store reference, present only in the V4 family.
    pub fn solana_actuator_store(&self) -> Option<&Path> {
        match &self.extras {
            ProductionFamilyExtrasV1::V4 {
                solana_actuator_store,
                ..
            } => Some(Path::new(solana_actuator_store)),
            _ => None,
        }
    }

    /// Monero actuator store reference, present only in the V4 family.
    pub fn xmr_actuator_store(&self) -> Option<&Path> {
        match &self.extras {
            ProductionFamilyExtrasV1::V4 {
                xmr_actuator_store, ..
            } => Some(Path::new(xmr_actuator_store)),
            _ => None,
        }
    }

    /// Bitcoin prebroadcast store reference, present only in the V4 family.
    pub fn bitcoin_prebroadcast_store(&self) -> Option<&Path> {
        match &self.extras {
            ProductionFamilyExtrasV1::V4 {
                bitcoin_prebroadcast_store,
                ..
            } => Some(Path::new(bitcoin_prebroadcast_store)),
            _ => None,
        }
    }

    /// The family is read off the extras, and the match is total.
    ///
    /// There is no `else` arm and no default: every state of the extras names
    /// exactly one family, so a family can never be inferred from the absence
    /// of something.
    const fn family(&self) -> ProductionBootstrapFamilyV1 {
        match &self.extras {
            ProductionFamilyExtrasV1::None => ProductionBootstrapFamilyV1::V1,
            ProductionFamilyExtrasV1::V2 { .. } => ProductionBootstrapFamilyV1::V2,
            ProductionFamilyExtrasV1::V3 { .. } => ProductionBootstrapFamilyV1::V3,
            ProductionFamilyExtrasV1::V4 { .. } => ProductionBootstrapFamilyV1::V4,
        }
    }

    /// Decodes only the exact canonical V1 bytes for the requested mode.
    /// Duplicate keys, unknown keys, alternate order, non-canonical numbers,
    /// trailing whitespace/bytes and checksum drift are all rejected.
    pub fn decode_canonical_for_mode(
        bytes: &[u8],
        expected_mode: ProductionBootstrapModeV1,
    ) -> Result<Self, ProductionConfigErrorV1> {
        decode_config(bytes, expected_mode, ProductionBootstrapFamilyV1::V1)
    }

    /// Decodes only the exact canonical V2 bytes for the requested mode. A V1
    /// document is refused here, and a V2 document is refused by
    /// [`Self::decode_canonical_for_mode`].
    pub fn decode_canonical_v2_for_mode(
        bytes: &[u8],
        expected_mode: ProductionBootstrapModeV1,
    ) -> Result<Self, ProductionConfigErrorV1> {
        decode_config(bytes, expected_mode, ProductionBootstrapFamilyV1::V2)
    }

    /// Decodes only the exact canonical V3 bytes for the requested mode.
    ///
    /// The family is an argument and never a guess: a V1 or V2 document
    /// reaches this function and is refused at the header and at the line
    /// count, both, before any field is read.
    pub fn decode_canonical_v3_for_mode(
        bytes: &[u8],
        expected_mode: ProductionBootstrapModeV1,
    ) -> Result<Self, ProductionConfigErrorV1> {
        decode_config(bytes, expected_mode, ProductionBootstrapFamilyV1::V3)
    }

    /// Decodes only the exact canonical V4 bytes for the requested mode. As
    /// with every earlier family, the family is an argument and never a
    /// guess.
    pub fn decode_canonical_v4_for_mode(
        bytes: &[u8],
        expected_mode: ProductionBootstrapModeV1,
    ) -> Result<Self, ProductionConfigErrorV1> {
        decode_config(bytes, expected_mode, ProductionBootstrapFamilyV1::V4)
    }

    /// Returns exact canonical bytes, including the integrity digest.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, ProductionConfigErrorV1> {
        let body = self.canonical_body();
        let digest = config_digest(body.as_bytes())?;
        let mut encoded = body;
        writeln!(&mut encoded, "config_digest={}", encode_hex(&digest))
            .map_err(|_| ProductionConfigErrorV1::InvalidCanonicalEncoding)?;
        writeln!(&mut encoded, "{END_V1}")
            .map_err(|_| ProductionConfigErrorV1::InvalidCanonicalEncoding)?;
        if encoded.len() as u64 > MAX_PRODUCTION_BOOTSTRAP_BYTES_V1 {
            return Err(ProductionConfigErrorV1::OversizeConfig);
        }
        Ok(encoded.into_bytes())
    }

    /// Frozen startup mode.
    pub const fn mode(&self) -> ProductionBootstrapModeV1 {
        self.mode
    }

    /// Public route and authority commitments.
    pub const fn pins(&self) -> ProductionRoutePinsV1 {
        self.pins
    }

    /// Validated runtime bounds.
    pub const fn bounds(&self) -> ProductionRuntimeBoundsV1 {
        self.bounds
    }

    /// Relative reference for a fixed authority role.
    pub fn relative_path(&self, role: ProductionPathRoleV1) -> &Path {
        self.paths.get(role)
    }

    fn canonical_body(&self) -> String {
        let mut body = String::new();
        // The V1 line is kept verbatim so the reviewed I14 inventory does not
        // move; every header added since uses infallible `push_str`, which adds
        // no new `expect` site to that inventory.
        //
        // No wildcard arm, deliberately. This match is the reason the V3 family
        // could not be added without a compiler error here: a `_` would have
        // written a V2 header onto a V3 document and nothing would have said so.
        match self.family() {
            ProductionBootstrapFamilyV1::V1 => {
                writeln!(&mut body, "{HEADER_V1}").expect("string write cannot fail");
            }
            ProductionBootstrapFamilyV1::V2 => {
                body.push_str(HEADER_V2);
                body.push('\n');
            }
            ProductionBootstrapFamilyV1::V3 => {
                body.push_str(HEADER_V3);
                body.push('\n');
            }
            ProductionBootstrapFamilyV1::V4 => {
                body.push_str(HEADER_V4);
                body.push('\n');
            }
        }
        writeln!(&mut body, "mode={}", self.mode.as_str()).expect("string write cannot fail");
        write_digest(&mut body, "network_id", self.pins.network_id);
        write_digest(&mut body, "route_id", self.pins.route_id);
        write_digest(
            &mut body,
            "registry_manifest_digest",
            self.pins.registry_manifest_digest,
        );
        write_u64(
            &mut body,
            "registry_minimum_epoch",
            self.pins.registry_minimum_epoch,
        );
        write_digest(
            &mut body,
            "registry_authority_set_digest",
            self.pins.registry_authority_set_digest,
        );
        write_digest(
            &mut body,
            "time_policy_authority_set_digest",
            self.pins.time_policy_authority_set_digest,
        );
        write_digest(
            &mut body,
            "time_evidence_authority_set_digest",
            self.pins.time_evidence_authority_set_digest,
        );
        write_digest(
            &mut body,
            "upstream_terms_digest",
            self.pins.upstream_terms_digest,
        );
        write_digest(
            &mut body,
            "downstream_terms_digest",
            self.pins.downstream_terms_digest,
        );
        write_digest(
            &mut body,
            "route_scope_digest",
            self.pins.route_scope_digest,
        );
        write_digest(
            &mut body,
            "participant_bindings_digest",
            self.pins.participant_bindings_digest,
        );
        write_digest(
            &mut body,
            "relay_binding_digest",
            self.pins.relay_binding_digest,
        );
        write_digest(
            &mut body,
            "time_policy_digest",
            self.pins.time_policy_digest,
        );
        write_digest(
            &mut body,
            "time_evidence_digest",
            self.pins.time_evidence_digest,
        );
        write_digest(&mut body, "process_owner_id", self.pins.process_owner_id);
        write_digest(&mut body, "coordinator_id", self.pins.coordinator_id);
        write_digest(
            &mut body,
            "coordinator_plan_authority_id",
            self.pins.coordinator_plan_authority_id,
        );
        write_digest(
            &mut body,
            "actuator_bindings_digest",
            self.pins.actuator_bindings_digest,
        );
        write_digest(
            &mut body,
            "solver_inventory_binding_digest",
            self.pins.solver_inventory_binding_digest,
        );
        write_u64(
            &mut body,
            "lease_duration_ms",
            self.bounds.lease_duration_ms,
        );
        write_u64(&mut body, "renew_before_ms", self.bounds.renew_before_ms);
        write_u64(
            &mut body,
            "dispatch_lease_ms",
            self.bounds.dispatch_lease_ms,
        );
        write_u64(
            &mut body,
            "coordinator_lease_ms",
            self.bounds.coordinator_lease_ms,
        );
        write_u64(
            &mut body,
            "actuator_lease_ms",
            self.bounds.actuator_lease_ms,
        );
        write_u64(
            &mut body,
            "external_call_timeout_ms",
            self.bounds.external_call_timeout_ms,
        );
        write_u64(
            &mut body,
            "waiting_backoff_ms",
            self.bounds.waiting_backoff_ms,
        );
        write_u64(
            &mut body,
            "recovery_backoff_ms",
            self.bounds.recovery_backoff_ms,
        );
        write_u64(
            &mut body,
            "relay_poll_backoff_ms",
            self.bounds.relay_poll_backoff_ms,
        );
        write_u64(
            &mut body,
            "per_queue_batch_limit",
            self.bounds.per_queue_batch_limit,
        );
        for role in ProductionPathRoleV1::ALL {
            writeln!(
                &mut body,
                "{}={}",
                role.key(),
                self.paths.paths[role.index()]
            )
            .expect("string write cannot fail");
        }
        match &self.extras {
            ProductionFamilyExtrasV1::None => {}
            ProductionFamilyExtrasV1::V2 { identity_store } => {
                push_reference(&mut body, IDENTITY_STORE_KEY_V2, identity_store);
            }
            // Order is part of the format: the V2 reference keeps the position
            // it has always had and the V3 one follows it, so a V3 document is
            // a V2 document plus one line and never a reordering of it.
            ProductionFamilyExtrasV1::V3 {
                identity_store,
                budget_policy,
            } => {
                push_reference(&mut body, IDENTITY_STORE_KEY_V2, identity_store);
                push_reference(&mut body, BUDGET_POLICY_KEY_V3, budget_policy);
            }
            // Same discipline as V3: a V4 document is a V3 document plus four
            // lines in one fixed order, never a reordering of it.
            ProductionFamilyExtrasV1::V4 {
                identity_store,
                budget_policy,
                chain_endpoints,
                solana_actuator_store,
                xmr_actuator_store,
                bitcoin_prebroadcast_store,
            } => {
                push_reference(&mut body, IDENTITY_STORE_KEY_V2, identity_store);
                push_reference(&mut body, BUDGET_POLICY_KEY_V3, budget_policy);
                push_reference(&mut body, CHAIN_ENDPOINTS_KEY_V4, chain_endpoints);
                push_reference(
                    &mut body,
                    SOLANA_ACTUATOR_STORE_KEY_V4,
                    solana_actuator_store,
                );
                push_reference(&mut body, XMR_ACTUATOR_STORE_KEY_V4, xmr_actuator_store);
                push_reference(
                    &mut body,
                    BITCOIN_PREBROADCAST_STORE_KEY_V4,
                    bitcoin_prebroadcast_store,
                );
            }
        }
        body
    }

    fn equivalent_except_mode(&self, other: &Self) -> bool {
        self.pins == other.pins
            && self.bounds == other.bounds
            && self.paths == other.paths
            && self.extras == other.extras
    }
}

/// Canonical absolute paths validated under one owner-only state directory.
pub struct ValidatedProductionLayoutV1 {
    state_dir: PathBuf,
    paths: [PathBuf; PRODUCTION_PATH_ROLE_COUNT_V1],
    contracts_transport_identity_store: Option<PathBuf>,
    contracts_budget_policy: Option<PathBuf>,
    chain_endpoints: Option<PathBuf>,
    solana_actuator_store: Option<PathBuf>,
    xmr_actuator_store: Option<PathBuf>,
    bitcoin_prebroadcast_store: Option<PathBuf>,
}

impl core::fmt::Debug for ValidatedProductionLayoutV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("ValidatedProductionLayoutV1([redacted])")
    }
}

impl ValidatedProductionLayoutV1 {
    /// Canonical owner-only state directory.
    pub fn state_dir(&self) -> &Path {
        &self.state_dir
    }

    /// Canonical absolute path for one authority role.
    pub fn path(&self, role: ProductionPathRoleV1) -> &Path {
        &self.paths[role.index()]
    }

    /// Canonical absolute path of the externally provisioned Contracts
    /// transport identity authority, present in the V2 and V3 layouts.
    pub fn contracts_transport_identity_store(&self) -> Option<&Path> {
        self.contracts_transport_identity_store.as_deref()
    }

    /// Absolute path of the externally provisioned Contracts budget policy,
    /// present only in the V3 family.
    pub fn contracts_budget_policy(&self) -> Option<&Path> {
        self.contracts_budget_policy.as_deref()
    }

    /// Absolute path of the chain-endpoints artifact, V4 only.
    pub fn chain_endpoints(&self) -> Option<&Path> {
        self.chain_endpoints.as_deref()
    }

    /// Absolute path of the Solana actuator store, V4 only.
    pub fn solana_actuator_store(&self) -> Option<&Path> {
        self.solana_actuator_store.as_deref()
    }

    /// Absolute path of the Monero actuator store, V4 only.
    pub fn xmr_actuator_store(&self) -> Option<&Path> {
        self.xmr_actuator_store.as_deref()
    }

    /// Absolute path of the Bitcoin prebroadcast store, V4 only. Written by
    /// the external funding-arming flow; validated here only when present.
    pub fn bitcoin_prebroadcast_store(&self) -> Option<&Path> {
        self.bitcoin_prebroadcast_store.as_deref()
    }
}

/// Fully validated bootstrap handoff. Opening an authority is still the
/// responsibility of its own concrete `create` or `open_existing` API.
pub struct ValidatedProductionBootstrapV1 {
    config: ProductionBootstrapConfigV1,
    layout: ValidatedProductionLayoutV1,
}

impl core::fmt::Debug for ValidatedProductionBootstrapV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("ValidatedProductionBootstrapV1([redacted])")
    }
}

impl ValidatedProductionBootstrapV1 {
    /// Validated public configuration.
    pub const fn config(&self) -> &ProductionBootstrapConfigV1 {
        &self.config
    }

    /// Validated absolute state layout.
    pub const fn layout(&self) -> &ValidatedProductionLayoutV1 {
        &self.layout
    }
}

/// Redacted startup refusal. No variant contains a path, endpoint, input byte
/// or nested error string.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProductionConfigErrorV1 {
    /// This boundary is currently hardened only for Linux.
    UnsupportedPlatform,
    /// The state directory is not one canonical owner-only authority.
    InvalidStateAuthority,
    /// The fixed bootstrap manifest is absent or physically unsafe.
    ConfigUnavailable,
    /// The manifest exceeded its pre-allocation bound.
    OversizeConfig,
    /// Encoding, ordering, field set or trailing bytes were non-canonical.
    InvalidCanonicalEncoding,
    /// The retained integrity digest did not match the canonical body.
    IntegrityMismatch,
    /// A public identity/digest/epoch binding was null or ambiguous.
    InvalidPublicBinding,
    /// Runtime timeout, lease or backoff bounds were unsafe.
    InvalidRuntimeBounds,
    /// A relative state reference was not canonical or was sensitive-looking.
    InvalidPathReference,
    /// Two path roles alias or overlap.
    AmbiguousPathReference,
    /// An immutable input artifact was missing or physically unsafe.
    InputArtifactUnavailable,
    /// Create mode found a managed state leaf already present.
    StateAlreadyPresent,
    /// Recovery found a missing or wrong-type managed state authority.
    RecoveryStateUnavailable,
    /// A partial-create journal was absent when needed, physically unsafe,
    /// bound to another manifest pair, or inconsistent with managed state.
    ProvisioningJournalRefused,
    /// Create and reopen companion manifests did not bind identical facts.
    CompanionMismatch,
    /// The externally provisioned identity authority directory is missing or is
    /// not one canonical owner-only directory. It is never created here.
    IdentityAuthorityUnavailable,
    /// The node-global manifest is absent, oversize or not owner-only.
    NodeConfigUnavailable,
    /// The DOM endpoint is syntactically unusable before any network access.
    InvalidNodeEndpoint,
    /// The frozen DOM node identity is not one accepted laboratory identity.
    InvalidNodeIdentity,
    /// A node-global bound is zero, non-canonical or outside its fixed range.
    InvalidNodeBounds,
    /// The out-of-band secret stream is a terminal, so no supervisor wrote it.
    SecretStreamIsTerminal,
    /// The secret stream did not reach end of input within its fixed bound.
    SecretStreamOversized,
    /// The secret stream is empty or could not be read in one bounded pass.
    SecretStreamUnavailable,
    /// The secret stream does not carry exactly eight newline-separated
    /// fields. A missing field, an extra field and a trailing newline are all
    /// this error: the count is exact and no shape is tolerated.
    SecretStreamFieldCount,
    /// The bearer field is not one exact token: it is empty, past its own
    /// bound, or carries an ASCII control byte. Historically the commonest
    /// cause is `echo` instead of `printf '%s'`.
    BearerMaterialMalformed,
    /// The relay signing secret field is not exactly sixty-four lowercase hex
    /// characters. Uppercase is refused rather than accepted: one spelling of
    /// one secret, so an operator's stream is reproducible byte for byte.
    RelaySigningSecretMalformed,
    /// The Contracts identity passphrase field is empty, past its own bound,
    /// or carries an ASCII control byte.
    IdentityPassphraseMalformed,
    /// The encrypted DOM wallet passphrase is empty, invalid UTF-8, past its
    /// bound, contains a control byte, or reuses the Contracts passphrase.
    DomWalletPassphraseMalformed,
    /// The Bitcoin participant signing key is not one independent non-zero
    /// 256-bit scalar encoded as exactly sixty-four lowercase hex characters.
    BitcoinParticipantSecretMalformed,
    /// The route-secret vault seal key is not one non-zero 256-bit key in
    /// exactly sixty-four lowercase hexadecimal characters.
    RouteSecretSealKeyMalformed,
    /// The refund-arming journal credential is not one non-zero, independent
    /// 256-bit key in exactly sixty-four lowercase hexadecimal characters.
    RefundArmingCredentialMalformed,
    /// The authenticated DOM client could not be constructed from an otherwise
    /// valid node configuration.
    NodeClientUnavailable,
    /// A bounded filesystem operation failed without exposing details.
    StorageUnavailable,
}

impl core::fmt::Display for ProductionConfigErrorV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let message = match self {
            Self::UnsupportedPlatform => "production bootstrap platform is unsupported",
            Self::InvalidStateAuthority => "invalid production state authority",
            Self::ConfigUnavailable => "production bootstrap manifest unavailable",
            Self::OversizeConfig => "production bootstrap manifest exceeds bound",
            Self::InvalidCanonicalEncoding => "invalid production bootstrap encoding",
            Self::IntegrityMismatch => "production bootstrap integrity mismatch",
            Self::InvalidPublicBinding => "invalid production bootstrap binding",
            Self::InvalidRuntimeBounds => "invalid production runtime bounds",
            Self::InvalidPathReference => "invalid production state reference",
            Self::AmbiguousPathReference => "ambiguous production state references",
            Self::InputArtifactUnavailable => "production input artifact unavailable",
            Self::StateAlreadyPresent => "production create state already exists",
            Self::RecoveryStateUnavailable => "production recovery state unavailable",
            Self::ProvisioningJournalRefused => "production provisioning journal refused",
            Self::CompanionMismatch => "production bootstrap companion mismatch",
            Self::IdentityAuthorityUnavailable => {
                "production identity authority directory unavailable"
            }
            Self::NodeConfigUnavailable => "production node configuration unavailable",
            Self::InvalidNodeEndpoint => "production DOM endpoint is invalid",
            Self::InvalidNodeIdentity => "production DOM node identity is invalid",
            Self::InvalidNodeBounds => "production node bounds are invalid",
            Self::SecretStreamIsTerminal => "production secret stream is a terminal",
            Self::SecretStreamOversized => "production secret stream is oversized",
            Self::SecretStreamUnavailable => "production secret stream unavailable",
            Self::SecretStreamFieldCount => "production secret stream field count is not eight",
            Self::BearerMaterialMalformed => "production bearer material is malformed",
            Self::RelaySigningSecretMalformed => "production relay signing secret is malformed",
            Self::IdentityPassphraseMalformed => "production identity passphrase is malformed",
            Self::DomWalletPassphraseMalformed => "production DOM wallet passphrase is malformed",
            Self::BitcoinParticipantSecretMalformed => {
                "production Bitcoin participant secret is malformed"
            }
            Self::RouteSecretSealKeyMalformed => {
                "production route-secret vault seal key is malformed"
            }
            Self::RefundArmingCredentialMalformed => {
                "production refund-arming credential is malformed"
            }
            Self::NodeClientUnavailable => "production DOM client unavailable",
            Self::StorageUnavailable => "production bootstrap storage unavailable",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for ProductionConfigErrorV1 {}

/// Loads the provisioning manifest and its pre-existing recovery companion.
/// All immutable inputs must exist and every managed store leaf must be absent.
/// This function creates nothing.
pub fn load_production_create_bootstrap_v1(
    state_dir: &Path,
) -> Result<ValidatedProductionBootstrapV1, ProductionConfigErrorV1> {
    let canonical_state = validate_state_dir(state_dir)?;
    let create = load_manifest(
        &canonical_state,
        PRODUCTION_CREATE_CONFIG_FILE_V1,
        ProductionBootstrapModeV1::Create,
        ProductionBootstrapFamilyV1::V1,
    )?;
    let reopen = load_manifest(
        &canonical_state,
        PRODUCTION_REOPEN_CONFIG_FILE_V1,
        ProductionBootstrapModeV1::ReopenExisting,
        ProductionBootstrapFamilyV1::V1,
    )?;
    if !create.equivalent_except_mode(&reopen) {
        return Err(ProductionConfigErrorV1::CompanionMismatch);
    }
    let layout = resolve_and_validate_layout(&canonical_state, &create, true)?;
    Ok(ValidatedProductionBootstrapV1 {
        config: create,
        layout,
    })
}

/// Loads only the recovery manifest and requires every managed authority to
/// exist. It never falls back to provisioning and never creates missing state.
pub fn load_production_reopen_bootstrap_v1(
    state_dir: &Path,
) -> Result<ValidatedProductionBootstrapV1, ProductionConfigErrorV1> {
    let canonical_state = validate_state_dir(state_dir)?;
    let config = load_manifest(
        &canonical_state,
        PRODUCTION_REOPEN_CONFIG_FILE_V1,
        ProductionBootstrapModeV1::ReopenExisting,
        ProductionBootstrapFamilyV1::V1,
    )?;
    let layout = resolve_and_validate_layout(&canonical_state, &config, false)?;
    Ok(ValidatedProductionBootstrapV1 { config, layout })
}

/// Loads the V2 provisioning manifest and its pre-existing recovery companion.
///
/// It behaves exactly like [`load_production_create_bootstrap_v1`] and adds one
/// rule: the externally provisioned Contracts transport identity authority must
/// already exist as an owner-only directory. It is never created here.
pub fn load_production_create_bootstrap_v2(
    state_dir: &Path,
) -> Result<ValidatedProductionBootstrapV1, ProductionConfigErrorV1> {
    let canonical_state = validate_state_dir(state_dir)?;
    let create = load_manifest(
        &canonical_state,
        PRODUCTION_CREATE_CONFIG_FILE_V2,
        ProductionBootstrapModeV1::Create,
        ProductionBootstrapFamilyV1::V2,
    )?;
    let reopen = load_manifest(
        &canonical_state,
        PRODUCTION_REOPEN_CONFIG_FILE_V2,
        ProductionBootstrapModeV1::ReopenExisting,
        ProductionBootstrapFamilyV1::V2,
    )?;
    if !create.equivalent_except_mode(&reopen) {
        return Err(ProductionConfigErrorV1::CompanionMismatch);
    }
    let layout = resolve_and_validate_layout(&canonical_state, &create, true)?;
    Ok(ValidatedProductionBootstrapV1 {
        config: create,
        layout,
    })
}

/// Loads only the V2 recovery manifest and requires every managed authority to
/// exist, plus the externally provisioned identity authority directory.
/// Loads the V3 provisioning manifest and its pre-existing recovery companion.
///
/// The V3 family adds the Contracts budget policy artifact. Like the V2
/// identity authority, it is **provisioned outside the daemon** and required
/// in create and in reopen alike: the loader validates it and never writes it.
pub fn load_production_create_bootstrap_v3(
    state_dir: &Path,
) -> Result<ValidatedProductionBootstrapV1, ProductionConfigErrorV1> {
    let canonical_state = validate_state_dir(state_dir)?;
    let create = load_manifest(
        &canonical_state,
        PRODUCTION_CREATE_CONFIG_FILE_V3,
        ProductionBootstrapModeV1::Create,
        ProductionBootstrapFamilyV1::V3,
    )?;
    let reopen = load_manifest(
        &canonical_state,
        PRODUCTION_REOPEN_CONFIG_FILE_V3,
        ProductionBootstrapModeV1::ReopenExisting,
        ProductionBootstrapFamilyV1::V3,
    )?;
    if !create.equivalent_except_mode(&reopen) {
        return Err(ProductionConfigErrorV1::CompanionMismatch);
    }
    let layout = resolve_and_validate_layout(&canonical_state, &create, true)?;
    Ok(ValidatedProductionBootstrapV1 {
        config: create,
        layout,
    })
}

/// Loads a V3 create invocation and resumes only a journal-authenticated
/// prefix left by an interrupted production provisioning run.
///
/// With no published journal this is byte-for-byte the strict create check:
/// every managed authority must be absent.  Once the journal exists, a path is
/// accepted only when its own ordered stage is `started` or `complete`; future
/// paths must remain absent.  The authority itself must still be reopened and
/// semantically authenticated by its owning module before the stage can be
/// completed.
#[cfg(feature = "production")]
pub(crate) fn load_production_create_or_resume_bootstrap_v3(
    state_dir: &Path,
) -> Result<ValidatedProductionBootstrapV1, ProductionConfigErrorV1> {
    let canonical_state = validate_state_dir(state_dir)?;
    let create = load_manifest(
        &canonical_state,
        PRODUCTION_CREATE_CONFIG_FILE_V3,
        ProductionBootstrapModeV1::Create,
        ProductionBootstrapFamilyV1::V3,
    )?;
    let reopen = load_manifest(
        &canonical_state,
        PRODUCTION_REOPEN_CONFIG_FILE_V3,
        ProductionBootstrapModeV1::ReopenExisting,
        ProductionBootstrapFamilyV1::V3,
    )?;
    if !create.equivalent_except_mode(&reopen) {
        return Err(ProductionConfigErrorV1::CompanionMismatch);
    }
    let binding = provisioning_binding_for_configs(&create, &reopen)?;
    let layout = match DurableProductionProvisioningJournalV1::open(&canonical_state, binding) {
        Ok(journal) => {
            resolve_and_validate_layout_for_provisioning(&canonical_state, &create, &journal)?
        }
        Err(ProductionProvisioningErrorV1::NotFound) => {
            let layout = resolve_and_validate_layout(&canonical_state, &create, true)?;
            require_absent(
                &canonical_state.join(ROUTE_SECRET_VAULT_ROOT_NAME_V1),
                ProductionConfigErrorV1::StateAlreadyPresent,
            )?;
            layout
        }
        Err(_) => return Err(ProductionConfigErrorV1::ProvisioningJournalRefused),
    };
    Ok(ValidatedProductionBootstrapV1 {
        config: create,
        layout,
    })
}

/// V4 twin of [`load_production_create_or_resume_bootstrap_v3`], reading only
/// the fixed V4 manifest pair.
pub(crate) fn load_production_create_or_resume_bootstrap_v4(
    state_dir: &Path,
) -> Result<ValidatedProductionBootstrapV1, ProductionConfigErrorV1> {
    let canonical_state = validate_state_dir(state_dir)?;
    let create = load_manifest(
        &canonical_state,
        PRODUCTION_CREATE_CONFIG_FILE_V4,
        ProductionBootstrapModeV1::Create,
        ProductionBootstrapFamilyV1::V4,
    )?;
    let reopen = load_manifest(
        &canonical_state,
        PRODUCTION_REOPEN_CONFIG_FILE_V4,
        ProductionBootstrapModeV1::ReopenExisting,
        ProductionBootstrapFamilyV1::V4,
    )?;
    if !create.equivalent_except_mode(&reopen) {
        return Err(ProductionConfigErrorV1::CompanionMismatch);
    }
    let binding = provisioning_binding_for_configs(&create, &reopen)?;
    let layout = match DurableProductionProvisioningJournalV1::open(&canonical_state, binding) {
        Ok(journal) => {
            resolve_and_validate_layout_for_provisioning(&canonical_state, &create, &journal)?
        }
        Err(ProductionProvisioningErrorV1::NotFound) => {
            let layout = resolve_and_validate_layout(&canonical_state, &create, true)?;
            require_absent(
                &canonical_state.join(ROUTE_SECRET_VAULT_ROOT_NAME_V1),
                ProductionConfigErrorV1::StateAlreadyPresent,
            )?;
            layout
        }
        Err(_) => return Err(ProductionConfigErrorV1::ProvisioningJournalRefused),
    };
    Ok(ValidatedProductionBootstrapV1 {
        config: create,
        layout,
    })
}

/// V4 twin of [`load_production_reopen_bootstrap_v3`].
pub fn load_production_reopen_bootstrap_v4(
    state_dir: &Path,
) -> Result<ValidatedProductionBootstrapV1, ProductionConfigErrorV1> {
    let canonical_state = validate_state_dir(state_dir)?;
    let config = load_manifest(
        &canonical_state,
        PRODUCTION_REOPEN_CONFIG_FILE_V4,
        ProductionBootstrapModeV1::ReopenExisting,
        ProductionBootstrapFamilyV1::V4,
    )?;
    let layout = resolve_and_validate_layout(&canonical_state, &config, false)?;
    Ok(ValidatedProductionBootstrapV1 { config, layout })
}

/// Provisioning binding for a V3 **or** V4 bootstrap: the companion manifest
/// is loaded with the same family and the binding covers both documents. Any
/// other family is refused, exactly as the V3-only predecessor refused
/// non-V3.
#[cfg(feature = "production")]
pub(crate) fn provisioning_binding_for_bootstrap(
    bootstrap: &ValidatedProductionBootstrapV1,
) -> Result<[u8; 32], ProductionConfigErrorV1> {
    let family = bootstrap.config.family();
    let (create_file, reopen_file) = match family {
        ProductionBootstrapFamilyV1::V3 => (
            PRODUCTION_CREATE_CONFIG_FILE_V3,
            PRODUCTION_REOPEN_CONFIG_FILE_V3,
        ),
        ProductionBootstrapFamilyV1::V4 => (
            PRODUCTION_CREATE_CONFIG_FILE_V4,
            PRODUCTION_REOPEN_CONFIG_FILE_V4,
        ),
        _ => return Err(ProductionConfigErrorV1::ProvisioningJournalRefused),
    };
    let (create, reopen) = match bootstrap.config.mode() {
        ProductionBootstrapModeV1::Create => (
            bootstrap.config.clone(),
            load_manifest(
                bootstrap.layout.state_dir(),
                reopen_file,
                ProductionBootstrapModeV1::ReopenExisting,
                family,
            )?,
        ),
        ProductionBootstrapModeV1::ReopenExisting => (
            load_manifest(
                bootstrap.layout.state_dir(),
                create_file,
                ProductionBootstrapModeV1::Create,
                family,
            )?,
            bootstrap.config.clone(),
        ),
    };
    if !create.equivalent_except_mode(&reopen) {
        return Err(ProductionConfigErrorV1::CompanionMismatch);
    }
    provisioning_binding_for_configs(&create, &reopen)
}

#[cfg(feature = "production")]
pub(crate) fn provisioning_binding_for_v3_bootstrap(
    bootstrap: &ValidatedProductionBootstrapV1,
) -> Result<[u8; 32], ProductionConfigErrorV1> {
    if bootstrap.config.family() != ProductionBootstrapFamilyV1::V3 {
        return Err(ProductionConfigErrorV1::ProvisioningJournalRefused);
    }
    let (create, reopen) = match bootstrap.config.mode() {
        ProductionBootstrapModeV1::Create => (
            bootstrap.config.clone(),
            load_manifest(
                bootstrap.layout.state_dir(),
                PRODUCTION_REOPEN_CONFIG_FILE_V3,
                ProductionBootstrapModeV1::ReopenExisting,
                ProductionBootstrapFamilyV1::V3,
            )?,
        ),
        ProductionBootstrapModeV1::ReopenExisting => (
            load_manifest(
                bootstrap.layout.state_dir(),
                PRODUCTION_CREATE_CONFIG_FILE_V3,
                ProductionBootstrapModeV1::Create,
                ProductionBootstrapFamilyV1::V3,
            )?,
            bootstrap.config.clone(),
        ),
    };
    if !create.equivalent_except_mode(&reopen) {
        return Err(ProductionConfigErrorV1::CompanionMismatch);
    }
    provisioning_binding_for_configs(&create, &reopen)
}

#[cfg(feature = "production")]
fn provisioning_binding_for_configs(
    create: &ProductionBootstrapConfigV1,
    reopen: &ProductionBootstrapConfigV1,
) -> Result<[u8; 32], ProductionConfigErrorV1> {
    provisioning_binding_v1(
        &create.canonical_bytes()?,
        &reopen.canonical_bytes()?,
        create.pins().route_id,
    )
    .map_err(|_| ProductionConfigErrorV1::ProvisioningJournalRefused)
}

/// Loads only the V3 recovery manifest and requires every managed authority to
/// exist. It never falls back to provisioning and never creates missing state.
pub fn load_production_reopen_bootstrap_v3(
    state_dir: &Path,
) -> Result<ValidatedProductionBootstrapV1, ProductionConfigErrorV1> {
    let canonical_state = validate_state_dir(state_dir)?;
    let config = load_manifest(
        &canonical_state,
        PRODUCTION_REOPEN_CONFIG_FILE_V3,
        ProductionBootstrapModeV1::ReopenExisting,
        ProductionBootstrapFamilyV1::V3,
    )?;
    let layout = resolve_and_validate_layout(&canonical_state, &config, false)?;
    Ok(ValidatedProductionBootstrapV1 { config, layout })
}

pub fn load_production_reopen_bootstrap_v2(
    state_dir: &Path,
) -> Result<ValidatedProductionBootstrapV1, ProductionConfigErrorV1> {
    let canonical_state = validate_state_dir(state_dir)?;
    let config = load_manifest(
        &canonical_state,
        PRODUCTION_REOPEN_CONFIG_FILE_V2,
        ProductionBootstrapModeV1::ReopenExisting,
        ProductionBootstrapFamilyV1::V2,
    )?;
    let layout = resolve_and_validate_layout(&canonical_state, &config, false)?;
    Ok(ValidatedProductionBootstrapV1 { config, layout })
}

fn decode_config(
    bytes: &[u8],
    expected_mode: ProductionBootstrapModeV1,
    family: ProductionBootstrapFamilyV1,
) -> Result<ProductionBootstrapConfigV1, ProductionConfigErrorV1> {
    if bytes.is_empty() || bytes.len() as u64 > MAX_PRODUCTION_BOOTSTRAP_BYTES_V1 {
        return Err(ProductionConfigErrorV1::OversizeConfig);
    }
    if !bytes.is_ascii() || bytes.last() != Some(&b'\n') || bytes.contains(&b'\r') {
        return Err(ProductionConfigErrorV1::InvalidCanonicalEncoding);
    }
    let text = std::str::from_utf8(bytes)
        .map_err(|_| ProductionConfigErrorV1::InvalidCanonicalEncoding)?;
    let lines: Vec<&str> = text[..text.len() - 1].split('\n').collect();
    let expected_lines = 1 + 1 + 18 + 1 + 10 + family.path_role_count() + 2;
    if lines.len() != expected_lines || lines.first() != Some(&family.header()) {
        return Err(ProductionConfigErrorV1::InvalidCanonicalEncoding);
    }
    let mut cursor = 1;
    let mode = ProductionBootstrapModeV1::parse(take_value(&lines, &mut cursor, "mode")?)?;
    if mode != expected_mode {
        return Err(ProductionConfigErrorV1::InvalidCanonicalEncoding);
    }
    let network_id = take_digest(&lines, &mut cursor, "network_id")?;
    let route_id = take_digest(&lines, &mut cursor, "route_id")?;
    let registry_manifest_digest = take_digest(&lines, &mut cursor, "registry_manifest_digest")?;
    let registry_minimum_epoch = take_u64(&lines, &mut cursor, "registry_minimum_epoch")?;
    let registry_authority_set_digest =
        take_digest(&lines, &mut cursor, "registry_authority_set_digest")?;
    let time_policy_authority_set_digest =
        take_digest(&lines, &mut cursor, "time_policy_authority_set_digest")?;
    let time_evidence_authority_set_digest =
        take_digest(&lines, &mut cursor, "time_evidence_authority_set_digest")?;
    let upstream_terms_digest = take_digest(&lines, &mut cursor, "upstream_terms_digest")?;
    let downstream_terms_digest = take_digest(&lines, &mut cursor, "downstream_terms_digest")?;
    let route_scope_digest = take_digest(&lines, &mut cursor, "route_scope_digest")?;
    let participant_bindings_digest =
        take_digest(&lines, &mut cursor, "participant_bindings_digest")?;
    let relay_binding_digest = take_digest(&lines, &mut cursor, "relay_binding_digest")?;
    let time_policy_digest = take_digest(&lines, &mut cursor, "time_policy_digest")?;
    let time_evidence_digest = take_digest(&lines, &mut cursor, "time_evidence_digest")?;
    let process_owner_id = take_digest(&lines, &mut cursor, "process_owner_id")?;
    let coordinator_id = take_digest(&lines, &mut cursor, "coordinator_id")?;
    let coordinator_plan_authority_id =
        take_digest(&lines, &mut cursor, "coordinator_plan_authority_id")?;
    let actuator_bindings_digest = take_digest(&lines, &mut cursor, "actuator_bindings_digest")?;
    let solver_inventory_binding_digest =
        take_digest(&lines, &mut cursor, "solver_inventory_binding_digest")?;
    let lease_duration_ms = take_u64(&lines, &mut cursor, "lease_duration_ms")?;
    let renew_before_ms = take_u64(&lines, &mut cursor, "renew_before_ms")?;
    let dispatch_lease_ms = take_u64(&lines, &mut cursor, "dispatch_lease_ms")?;
    let coordinator_lease_ms = take_u64(&lines, &mut cursor, "coordinator_lease_ms")?;
    let actuator_lease_ms = take_u64(&lines, &mut cursor, "actuator_lease_ms")?;
    let external_call_timeout_ms = take_u64(&lines, &mut cursor, "external_call_timeout_ms")?;
    let waiting_backoff_ms = take_u64(&lines, &mut cursor, "waiting_backoff_ms")?;
    let recovery_backoff_ms = take_u64(&lines, &mut cursor, "recovery_backoff_ms")?;
    let relay_poll_backoff_ms = take_u64(&lines, &mut cursor, "relay_poll_backoff_ms")?;
    let per_queue_batch_limit = take_u64(&lines, &mut cursor, "per_queue_batch_limit")?;
    let mut path_values = Vec::with_capacity(PRODUCTION_PATH_ROLE_COUNT_V1);
    for role in ProductionPathRoleV1::ALL {
        path_values.push(take_value(&lines, &mut cursor, role.key())?.to_owned());
    }
    let paths: [String; PRODUCTION_PATH_ROLE_COUNT_V1] = path_values
        .try_into()
        .map_err(|_| ProductionConfigErrorV1::InvalidCanonicalEncoding)?;
    // Read in the order the encoder writes them, which is the only order the
    // format has. A family that adds a reference adds it after the ones it
    // inherits, so an earlier family's document is a prefix of a later one's
    // reference block and never a permutation.
    enum DecodedExtrasV1 {
        None,
        V2(String),
        V3(String, String),
        V4(String, String, String, String, String, String),
    }
    let extras = match family {
        ProductionBootstrapFamilyV1::V1 => DecodedExtrasV1::None,
        ProductionBootstrapFamilyV1::V2 => {
            DecodedExtrasV1::V2(take_value(&lines, &mut cursor, IDENTITY_STORE_KEY_V2)?.to_owned())
        }
        ProductionBootstrapFamilyV1::V3 => DecodedExtrasV1::V3(
            take_value(&lines, &mut cursor, IDENTITY_STORE_KEY_V2)?.to_owned(),
            take_value(&lines, &mut cursor, BUDGET_POLICY_KEY_V3)?.to_owned(),
        ),
        ProductionBootstrapFamilyV1::V4 => DecodedExtrasV1::V4(
            take_value(&lines, &mut cursor, IDENTITY_STORE_KEY_V2)?.to_owned(),
            take_value(&lines, &mut cursor, BUDGET_POLICY_KEY_V3)?.to_owned(),
            take_value(&lines, &mut cursor, CHAIN_ENDPOINTS_KEY_V4)?.to_owned(),
            take_value(&lines, &mut cursor, SOLANA_ACTUATOR_STORE_KEY_V4)?.to_owned(),
            take_value(&lines, &mut cursor, XMR_ACTUATOR_STORE_KEY_V4)?.to_owned(),
            take_value(&lines, &mut cursor, BITCOIN_PREBROADCAST_STORE_KEY_V4)?.to_owned(),
        ),
    };
    let supplied_digest = decode_digest(take_value(&lines, &mut cursor, "config_digest")?)?;
    if lines.get(cursor) != Some(&END_V1) || cursor + 1 != lines.len() {
        return Err(ProductionConfigErrorV1::InvalidCanonicalEncoding);
    }
    let config = ProductionBootstrapConfigV1::from_parts(
        mode,
        ProductionRoutePinsV1 {
            network_id,
            route_id,
            registry_manifest_digest,
            registry_minimum_epoch,
            registry_authority_set_digest,
            time_policy_authority_set_digest,
            time_evidence_authority_set_digest,
            upstream_terms_digest,
            downstream_terms_digest,
            route_scope_digest,
            participant_bindings_digest,
            relay_binding_digest,
            time_policy_digest,
            time_evidence_digest,
            process_owner_id,
            coordinator_id,
            coordinator_plan_authority_id,
            actuator_bindings_digest,
            solver_inventory_binding_digest,
        },
        ProductionRuntimeBoundsV1 {
            lease_duration_ms,
            renew_before_ms,
            dispatch_lease_ms,
            coordinator_lease_ms,
            actuator_lease_ms,
            external_call_timeout_ms,
            waiting_backoff_ms,
            recovery_backoff_ms,
            relay_poll_backoff_ms,
            per_queue_batch_limit,
        },
        ProductionPathReferencesV1::from_ordered(paths)?,
    )?;
    let config = match extras {
        DecodedExtrasV1::None => config,
        DecodedExtrasV1::V2(identity_store) => ProductionBootstrapConfigV1::from_parts_v2(
            config.mode,
            config.pins,
            config.bounds,
            config.paths,
            identity_store,
        )?,
        DecodedExtrasV1::V3(identity_store, budget_policy) => {
            ProductionBootstrapConfigV1::from_parts_v3(
                config.mode,
                config.pins,
                config.bounds,
                config.paths,
                identity_store,
                budget_policy,
            )?
        }
        DecodedExtrasV1::V4(
            identity_store,
            budget_policy,
            chain_endpoints,
            solana_actuator_store,
            xmr_actuator_store,
            bitcoin_prebroadcast_store,
        ) => ProductionBootstrapConfigV1::from_parts_v4(
            config.mode,
            config.pins,
            config.bounds,
            config.paths,
            identity_store,
            budget_policy,
            chain_endpoints,
            solana_actuator_store,
            xmr_actuator_store,
            bitcoin_prebroadcast_store,
        )?,
    };
    let body = config.canonical_body();
    if config_digest(body.as_bytes())? != supplied_digest
        || config.canonical_bytes()?.as_slice() != bytes
    {
        return Err(ProductionConfigErrorV1::IntegrityMismatch);
    }
    Ok(config)
}

pub(crate) fn take_value<'a>(
    lines: &[&'a str],
    cursor: &mut usize,
    expected_key: &str,
) -> Result<&'a str, ProductionConfigErrorV1> {
    let line = lines
        .get(*cursor)
        .ok_or(ProductionConfigErrorV1::InvalidCanonicalEncoding)?;
    *cursor += 1;
    let (key, value) = line
        .split_once('=')
        .ok_or(ProductionConfigErrorV1::InvalidCanonicalEncoding)?;
    if key != expected_key || value.is_empty() || value.contains('=') {
        return Err(ProductionConfigErrorV1::InvalidCanonicalEncoding);
    }
    Ok(value)
}

fn take_digest(
    lines: &[&str],
    cursor: &mut usize,
    key: &str,
) -> Result<[u8; 32], ProductionConfigErrorV1> {
    decode_digest(take_value(lines, cursor, key)?)
}

fn take_u64(lines: &[&str], cursor: &mut usize, key: &str) -> Result<u64, ProductionConfigErrorV1> {
    let value = take_value(lines, cursor, key)?;
    if value == "0" || value.starts_with('0') || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(ProductionConfigErrorV1::InvalidCanonicalEncoding);
    }
    value
        .parse()
        .map_err(|_| ProductionConfigErrorV1::InvalidCanonicalEncoding)
}

fn write_digest(target: &mut String, key: &str, value: [u8; 32]) {
    writeln!(target, "{key}={}", encode_hex(&value)).expect("string write cannot fail");
}

fn write_u64(target: &mut String, key: &str, value: u64) {
    writeln!(target, "{key}={value}").expect("string write cannot fail");
}

pub(crate) fn config_digest(bytes: &[u8]) -> Result<[u8; 32], ProductionConfigErrorV1> {
    let mut hash =
        Blake2bVar::new(32).map_err(|_| ProductionConfigErrorV1::InvalidCanonicalEncoding)?;
    hash.update(CONFIG_DIGEST_DOMAIN_V1);
    hash.update(bytes);
    let mut output = [0; 32];
    hash.finalize_variable(&mut output)
        .map_err(|_| ProductionConfigErrorV1::InvalidCanonicalEncoding)?;
    Ok(output)
}

/// Appends one `key=value` reference line with infallible pushes.
///
/// Deliberately not `writeln!`: the V1 line is kept as it was so the reviewed
/// I14 `expect` inventory does not move, and every reference added since is
/// written with pushes that cannot fail and so add no new site to it.
fn push_reference(body: &mut String, key: &str, value: &str) {
    body.push_str(key);
    body.push('=');
    body.push_str(value);
    body.push('\n');
}

pub(crate) fn encode_hex(bytes: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(64);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

pub(crate) fn decode_digest(value: &str) -> Result<[u8; 32], ProductionConfigErrorV1> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(ProductionConfigErrorV1::InvalidCanonicalEncoding);
    }
    if value.bytes().any(|byte| byte.is_ascii_uppercase()) {
        return Err(ProductionConfigErrorV1::InvalidCanonicalEncoding);
    }
    let mut output = [0; 32];
    for (index, byte) in output.iter_mut().enumerate() {
        let offset = index * 2;
        *byte = (hex_nibble(value.as_bytes()[offset])? << 4)
            | hex_nibble(value.as_bytes()[offset + 1])?;
    }
    Ok(output)
}

fn hex_nibble(byte: u8) -> Result<u8, ProductionConfigErrorV1> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        _ => Err(ProductionConfigErrorV1::InvalidCanonicalEncoding),
    }
}

fn validate_path_set(paths: &[String]) -> Result<(), ProductionConfigErrorV1> {
    for path in paths {
        validate_relative_path(path)?;
    }
    for left in 0..paths.len() {
        for right in (left + 1)..paths.len() {
            let left_path = Path::new(&paths[left]);
            let right_path = Path::new(&paths[right]);
            if left_path == right_path
                || left_path.starts_with(right_path)
                || right_path.starts_with(left_path)
                || paths_are_auxiliary_aliases(&paths[left], &paths[right])
            {
                return Err(ProductionConfigErrorV1::AmbiguousPathReference);
            }
        }
    }
    Ok(())
}

fn paths_are_auxiliary_aliases(left: &str, right: &str) -> bool {
    ["-wal", "-shm", "-journal", ".lock", ".tmp", ".new"]
        .iter()
        .any(|suffix| left == format!("{right}{suffix}") || right == format!("{left}{suffix}"))
}

fn validate_relative_path(value: &str) -> Result<(), ProductionConfigErrorV1> {
    if value.is_empty()
        || value.len() > MAX_PRODUCTION_RELATIVE_PATH_BYTES_V1
        || !value.is_ascii()
        || value.starts_with('/')
        || value.ends_with('/')
        || value.contains("//")
        || value.contains('\\')
    {
        return Err(ProductionConfigErrorV1::InvalidPathReference);
    }
    let path = Path::new(value);
    let components: Vec<_> = path.components().collect();
    if components.is_empty()
        || components.len() > MAX_PATH_SEGMENTS_V1
        || components
            .iter()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(ProductionConfigErrorV1::InvalidPathReference);
    }
    let mut reconstructed = String::new();
    for (index, component) in components.iter().enumerate() {
        let segment = component
            .as_os_str()
            .to_str()
            .ok_or(ProductionConfigErrorV1::InvalidPathReference)?;
        if segment.is_empty()
            || segment.len() > MAX_PATH_SEGMENT_BYTES_V1
            || segment.starts_with('.')
            || segment.ends_with('.')
            || !segment.bytes().all(|byte| {
                byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"._-".contains(&byte)
            })
            || !segment
                .as_bytes()
                .first()
                .is_some_and(u8::is_ascii_lowercase)
            || !segment
                .as_bytes()
                .last()
                .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
            || contains_sensitive_label(segment)
        {
            return Err(ProductionConfigErrorV1::InvalidPathReference);
        }
        if index != 0 {
            reconstructed.push('/');
        }
        reconstructed.push_str(segment);
    }
    if reconstructed != value
        || Path::new(value) == Path::new(PRODUCTION_PROVISIONING_ROOT_RESERVED_V1)
        || Path::new(value).starts_with(PRODUCTION_PROVISIONING_ROOT_RESERVED_V1)
        || Path::new(value) == Path::new(PRODUCTION_PROVISIONING_STAGING_RESERVED_V1)
        || matches!(
            value,
            PRODUCTION_CREATE_CONFIG_FILE_V1
                | PRODUCTION_REOPEN_CONFIG_FILE_V1
                | PRODUCTION_CREATE_CONFIG_FILE_V2
                | PRODUCTION_REOPEN_CONFIG_FILE_V2
                | PRODUCTION_CREATE_CONFIG_FILE_V3
                | PRODUCTION_REOPEN_CONFIG_FILE_V3
                | PRODUCTION_NODE_CONFIG_FILE_V1
        )
    {
        return Err(ProductionConfigErrorV1::InvalidPathReference);
    }
    Ok(())
}

fn contains_sensitive_label(segment: &str) -> bool {
    const FORBIDDEN: [&str; 19] = [
        "secret",
        "seed",
        "private",
        "key",
        "share",
        "nonce",
        "passwd",
        "password",
        "cookie",
        "bearer",
        "token",
        "scalar",
        "credential",
        "apikey",
        "segredo",
        "semente",
        "chave",
        "senha",
        "credencial",
    ];
    FORBIDDEN.iter().any(|label| segment.contains(label))
}

fn load_manifest(
    state_dir: &Path,
    file_name: &str,
    expected_mode: ProductionBootstrapModeV1,
    family: ProductionBootstrapFamilyV1,
) -> Result<ProductionBootstrapConfigV1, ProductionConfigErrorV1> {
    let path = state_dir.join(file_name);
    let bytes = read_owner_file_bounded(
        &path,
        MAX_PRODUCTION_BOOTSTRAP_BYTES_V1,
        ProductionConfigErrorV1::ConfigUnavailable,
    )?;
    decode_config(&bytes, expected_mode, family)
}

/// Resolves and validates the V4 extras for either layout path.
///
/// The chain-endpoints artifact is a provisioned input; the two actuator
/// stores are managed files whose lifecycle the run's provisioning stages
/// own, so here they are only required to be an owner file when present.
/// The Bitcoin prebroadcast store is written by the external arming flow and
/// may legitimately be absent until that flow runs.
fn resolve_v4_extras(
    state_dir: &Path,
    config: &ProductionBootstrapConfigV1,
) -> Result<
    (
        Option<PathBuf>,
        Option<PathBuf>,
        Option<PathBuf>,
        Option<PathBuf>,
    ),
    ProductionConfigErrorV1,
> {
    let chain_endpoints = match config.chain_endpoints() {
        None => None,
        Some(relative) => {
            let path = state_dir.join(relative);
            validate_parent_chain(state_dir, &path)?;
            validate_input_file(&path)?;
            Some(path)
        }
    };
    let managed = |relative: Option<&Path>| -> Result<Option<PathBuf>, ProductionConfigErrorV1> {
        match relative {
            None => Ok(None),
            Some(relative) => {
                let path = state_dir.join(relative);
                validate_parent_chain(state_dir, &path)?;
                match fs::symlink_metadata(&path) {
                    Ok(_) => validate_owner_file(
                        &path,
                        ProductionConfigErrorV1::RecoveryStateUnavailable,
                    )?,
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                    Err(_) => return Err(ProductionConfigErrorV1::StorageUnavailable),
                }
                Ok(Some(path))
            }
        }
    };
    let solana_actuator_store = managed(config.solana_actuator_store())?;
    let xmr_actuator_store = managed(config.xmr_actuator_store())?;
    let bitcoin_prebroadcast_store = managed(config.bitcoin_prebroadcast_store())?;
    Ok((
        chain_endpoints,
        solana_actuator_store,
        xmr_actuator_store,
        bitcoin_prebroadcast_store,
    ))
}

fn resolve_and_validate_layout(
    state_dir: &Path,
    config: &ProductionBootstrapConfigV1,
    creating: bool,
) -> Result<ValidatedProductionLayoutV1, ProductionConfigErrorV1> {
    let paths = std::array::from_fn(|index| state_dir.join(config.paths.paths[index].as_str()));
    for role in ProductionPathRoleV1::ALL {
        let path = &paths[role.index()];
        validate_parent_chain(state_dir, path)?;
        match role.kind() {
            ProductionPathKindV1::InputFile => {
                validate_input_file(path)?;
            }
            ProductionPathKindV1::ManagedFile if creating => {
                require_managed_file_absent(path)?;
            }
            ProductionPathKindV1::ManagedDirectory if creating => {
                require_absent(path, ProductionConfigErrorV1::StateAlreadyPresent)?;
            }
            ProductionPathKindV1::ManagedFile => {
                validate_owner_file(path, ProductionConfigErrorV1::RecoveryStateUnavailable)?;
            }
            ProductionPathKindV1::ManagedDirectory => {
                validate_owner_directory(path, ProductionConfigErrorV1::RecoveryStateUnavailable)?;
            }
            // No V1 role carries this kind today, so this arm is unreachable in
            // the V1 layout. It is written out rather than folded into a
            // wildcard so that adding a role of this kind is a compile-time
            // decision here instead of a silent fall-through.
            ProductionPathKindV1::ExistingAuthorityDirectory => {
                validate_owner_directory(
                    path,
                    ProductionConfigErrorV1::IdentityAuthorityUnavailable,
                )?;
            }
        }
    }
    // Provisioned outside the daemon: required in create and in reopen alike,
    // never created and never repaired here.
    let contracts_transport_identity_store = match config.contracts_transport_identity_store() {
        None => None,
        Some(relative) => {
            let path = state_dir.join(relative);
            validate_parent_chain(state_dir, &path)?;
            validate_owner_directory(&path, ProductionConfigErrorV1::IdentityAuthorityUnavailable)?;
            Some(path)
        }
    };
    // Provisioned outside the daemon like the identity authority above, and
    // validated as an input artifact rather than a directory: it is the bytes
    // of one budget policy, not a store root.
    let contracts_budget_policy = match config.contracts_budget_policy() {
        None => None,
        Some(relative) => {
            let path = state_dir.join(relative);
            validate_parent_chain(state_dir, &path)?;
            validate_input_file(&path)?;
            Some(path)
        }
    };
    let (chain_endpoints, solana_actuator_store, xmr_actuator_store, bitcoin_prebroadcast_store) =
        resolve_v4_extras(state_dir, config)?;
    Ok(ValidatedProductionLayoutV1 {
        state_dir: state_dir.to_path_buf(),
        paths,
        contracts_transport_identity_store,
        contracts_budget_policy,
        chain_endpoints,
        solana_actuator_store,
        xmr_actuator_store,
        bitcoin_prebroadcast_store,
    })
}

#[cfg(feature = "production")]
fn resolve_and_validate_layout_for_provisioning(
    state_dir: &Path,
    config: &ProductionBootstrapConfigV1,
    journal: &DurableProductionProvisioningJournalV1,
) -> Result<ValidatedProductionLayoutV1, ProductionConfigErrorV1> {
    let paths = std::array::from_fn(|index| state_dir.join(config.paths.paths[index].as_str()));
    for role in ProductionPathRoleV1::ALL {
        let path = &paths[role.index()];
        validate_parent_chain(state_dir, path)?;
        match role.kind() {
            ProductionPathKindV1::InputFile => validate_input_file(path)?,
            ProductionPathKindV1::ExistingAuthorityDirectory => validate_owner_directory(
                path,
                ProductionConfigErrorV1::IdentityAuthorityUnavailable,
            )?,
            ProductionPathKindV1::ManagedFile | ProductionPathKindV1::ManagedDirectory => {
                validate_managed_path_for_provisioning(
                    path,
                    role.kind(),
                    journal
                        .stage_state(
                            provisioning_stage_for_role(role)
                                .ok_or(ProductionConfigErrorV1::ProvisioningJournalRefused)?,
                        )
                        .map_err(|_| ProductionConfigErrorV1::ProvisioningJournalRefused)?,
                )?;
            }
        }
    }

    let vault_path = state_dir.join(ROUTE_SECRET_VAULT_ROOT_NAME_V1);
    validate_managed_path_for_provisioning(
        &vault_path,
        ProductionPathKindV1::ManagedDirectory,
        journal
            .stage_state(ProductionProvisioningStageV1::RouteSecretVault)
            .map_err(|_| ProductionConfigErrorV1::ProvisioningJournalRefused)?,
    )?;

    let contracts_transport_identity_store = match config.contracts_transport_identity_store() {
        None => None,
        Some(relative) => {
            let path = state_dir.join(relative);
            validate_parent_chain(state_dir, &path)?;
            validate_owner_directory(&path, ProductionConfigErrorV1::IdentityAuthorityUnavailable)?;
            Some(path)
        }
    };
    let contracts_budget_policy = match config.contracts_budget_policy() {
        None => None,
        Some(relative) => {
            let path = state_dir.join(relative);
            validate_parent_chain(state_dir, &path)?;
            validate_input_file(&path)?;
            Some(path)
        }
    };
    let (chain_endpoints, solana_actuator_store, xmr_actuator_store, bitcoin_prebroadcast_store) =
        resolve_v4_extras(state_dir, config)?;
    Ok(ValidatedProductionLayoutV1 {
        state_dir: state_dir.to_path_buf(),
        paths,
        contracts_transport_identity_store,
        contracts_budget_policy,
        chain_endpoints,
        solana_actuator_store,
        xmr_actuator_store,
        bitcoin_prebroadcast_store,
    })
}

#[cfg(feature = "production")]
fn validate_managed_path_for_provisioning(
    path: &Path,
    kind: ProductionPathKindV1,
    state: ProductionProvisioningStageStateV1,
) -> Result<(), ProductionConfigErrorV1> {
    let present = match fs::symlink_metadata(path) {
        Ok(_) => true,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
        Err(_) => return Err(ProductionConfigErrorV1::StorageUnavailable),
    };
    match (state, present, kind) {
        (ProductionProvisioningStageStateV1::Absent, _, ProductionPathKindV1::ManagedFile) => {
            require_managed_file_absent(path)
        }
        (ProductionProvisioningStageStateV1::Absent, _, ProductionPathKindV1::ManagedDirectory) => {
            require_absent(path, ProductionConfigErrorV1::StateAlreadyPresent)
        }
        (ProductionProvisioningStageStateV1::Started, false, ProductionPathKindV1::ManagedFile) => {
            validate_started_managed_file_prefix(path)
        }
        (
            ProductionProvisioningStageStateV1::Started,
            false,
            ProductionPathKindV1::ManagedDirectory,
        ) => Ok(()),
        (
            ProductionProvisioningStageStateV1::Started
            | ProductionProvisioningStageStateV1::Complete,
            true,
            ProductionPathKindV1::ManagedFile,
        ) => validate_owner_file(path, ProductionConfigErrorV1::ProvisioningJournalRefused),
        (
            ProductionProvisioningStageStateV1::Started
            | ProductionProvisioningStageStateV1::Complete,
            true,
            ProductionPathKindV1::ManagedDirectory,
        ) => validate_owner_directory(path, ProductionConfigErrorV1::ProvisioningJournalRefused),
        (ProductionProvisioningStageStateV1::Complete, false, _) => {
            Err(ProductionConfigErrorV1::ProvisioningJournalRefused)
        }
        (
            _,
            _,
            ProductionPathKindV1::InputFile | ProductionPathKindV1::ExistingAuthorityDirectory,
        ) => Err(ProductionConfigErrorV1::ProvisioningJournalRefused),
    }
}

#[cfg(feature = "production")]
fn validate_started_managed_file_prefix(path: &Path) -> Result<(), ProductionConfigErrorV1> {
    require_absent(path, ProductionConfigErrorV1::StateAlreadyPresent)?;
    let path_text = path
        .as_os_str()
        .to_str()
        .ok_or(ProductionConfigErrorV1::InvalidPathReference)?;
    for suffix in ["-wal", "-shm", "-journal", ".tmp", ".new"] {
        require_absent(
            Path::new(&format!("{path_text}{suffix}")),
            ProductionConfigErrorV1::ProvisioningJournalRefused,
        )?;
    }
    let lock_path = Path::new(&format!("{path_text}.lock")).to_path_buf();
    match fs::symlink_metadata(&lock_path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(ProductionConfigErrorV1::StorageUnavailable),
        Ok(metadata) => {
            validate_owner_file(
                &lock_path,
                ProductionConfigErrorV1::ProvisioningJournalRefused,
            )?;
            if metadata.len() != 0 {
                return Err(ProductionConfigErrorV1::ProvisioningJournalRefused);
            }
            Ok(())
        }
    }
}

#[cfg(feature = "production")]
const fn provisioning_stage_for_role(
    role: ProductionPathRoleV1,
) -> Option<ProductionProvisioningStageV1> {
    match role {
        ProductionPathRoleV1::RouteStore => Some(ProductionProvisioningStageV1::RouteStore),
        ProductionPathRoleV1::TimeAnchorStore => {
            Some(ProductionProvisioningStageV1::TimeAnchorStore)
        }
        ProductionPathRoleV1::CoordinatorStore => {
            Some(ProductionProvisioningStageV1::CoordinatorStore)
        }
        ProductionPathRoleV1::DomActuatorStore => {
            Some(ProductionProvisioningStageV1::DomActuatorStore)
        }
        ProductionPathRoleV1::EvmActuatorStore => {
            Some(ProductionProvisioningStageV1::EvmActuatorStore)
        }
        ProductionPathRoleV1::BitcoinActuatorStore => {
            Some(ProductionProvisioningStageV1::BitcoinActuatorStore)
        }
        ProductionPathRoleV1::BitcoinParticipantState
        | ProductionPathRoleV1::DomUpstreamParticipantState
        | ProductionPathRoleV1::DomDownstreamParticipantState => {
            Some(ProductionProvisioningStageV1::ChainSignerAuthorities)
        }
        ProductionPathRoleV1::SolverInventoryStore => {
            Some(ProductionProvisioningStageV1::SolverInventoryStore)
        }
        ProductionPathRoleV1::RelayQueue
        | ProductionPathRoleV1::UpstreamRelaySender
        | ProductionPathRoleV1::UpstreamRelayInbox
        | ProductionPathRoleV1::UpstreamRelayFrames
        | ProductionPathRoleV1::DownstreamRelaySender
        | ProductionPathRoleV1::DownstreamRelayInbox
        | ProductionPathRoleV1::DownstreamRelayFrames => {
            Some(ProductionProvisioningStageV1::RelayAuthorities)
        }
        ProductionPathRoleV1::UpstreamContracts | ProductionPathRoleV1::DownstreamContracts => {
            Some(ProductionProvisioningStageV1::ContractsStores)
        }
        ProductionPathRoleV1::RegistryStore
        | ProductionPathRoleV1::RegistryAuthorities
        | ProductionPathRoleV1::UpstreamTerms
        | ProductionPathRoleV1::DownstreamTerms
        | ProductionPathRoleV1::ParticipantBindings
        | ProductionPathRoleV1::RelayRoster
        | ProductionPathRoleV1::TimePolicy
        | ProductionPathRoleV1::TimeEvidence
        | ProductionPathRoleV1::DomWallet => None,
    }
}

fn validate_input_file(path: &Path) -> Result<(), ProductionConfigErrorV1> {
    validate_owner_file(path, ProductionConfigErrorV1::InputArtifactUnavailable)?;
    let metadata = fs::symlink_metadata(path)
        .map_err(|_| ProductionConfigErrorV1::InputArtifactUnavailable)?;
    if metadata.len() == 0 || metadata.len() > MAX_INPUT_ARTIFACT_BYTES_V1 {
        return Err(ProductionConfigErrorV1::InputArtifactUnavailable);
    }
    Ok(())
}

fn require_managed_file_absent(path: &Path) -> Result<(), ProductionConfigErrorV1> {
    require_absent(path, ProductionConfigErrorV1::StateAlreadyPresent)?;
    let path_text = path
        .as_os_str()
        .to_str()
        .ok_or(ProductionConfigErrorV1::InvalidPathReference)?;
    for suffix in ["-wal", "-shm", "-journal", ".lock", ".tmp", ".new"] {
        require_absent(
            Path::new(&format!("{path_text}{suffix}")),
            ProductionConfigErrorV1::StateAlreadyPresent,
        )?;
    }
    Ok(())
}

pub(crate) fn validate_state_dir(state_dir: &Path) -> Result<PathBuf, ProductionConfigErrorV1> {
    #[cfg(not(target_os = "linux"))]
    {
        let _ = state_dir;
        return Err(ProductionConfigErrorV1::UnsupportedPlatform);
    }
    #[cfg(target_os = "linux")]
    {
        if !state_dir.is_absolute() {
            return Err(ProductionConfigErrorV1::InvalidStateAuthority);
        }
        let canonical = fs::canonicalize(state_dir)
            .map_err(|_| ProductionConfigErrorV1::InvalidStateAuthority)?;
        if canonical != state_dir {
            return Err(ProductionConfigErrorV1::InvalidStateAuthority);
        }
        validate_owner_directory(&canonical, ProductionConfigErrorV1::InvalidStateAuthority)?;
        Ok(canonical)
    }
}

fn validate_parent_chain(state_dir: &Path, child: &Path) -> Result<(), ProductionConfigErrorV1> {
    if !child.starts_with(state_dir) || child == state_dir {
        return Err(ProductionConfigErrorV1::InvalidPathReference);
    }
    let parent = child
        .parent()
        .ok_or(ProductionConfigErrorV1::InvalidPathReference)?;
    if parent == state_dir {
        return Ok(());
    }
    let relative = parent
        .strip_prefix(state_dir)
        .map_err(|_| ProductionConfigErrorV1::InvalidPathReference)?;
    let mut current = state_dir.to_path_buf();
    for component in relative.components() {
        current.push(component);
        validate_owner_directory(&current, ProductionConfigErrorV1::InvalidStateAuthority)?;
    }
    Ok(())
}

fn require_absent(
    path: &Path,
    present_error: ProductionConfigErrorV1,
) -> Result<(), ProductionConfigErrorV1> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Ok(_) => Err(present_error),
        Err(_) => Err(ProductionConfigErrorV1::StorageUnavailable),
    }
}

pub(crate) fn read_owner_file_bounded(
    path: &Path,
    max_bytes: u64,
    physical_error: ProductionConfigErrorV1,
) -> Result<Vec<u8>, ProductionConfigErrorV1> {
    validate_owner_file(path, physical_error)?;
    let before = fs::symlink_metadata(path).map_err(|_| physical_error)?;
    if before.len() == 0 || before.len() > max_bytes {
        return Err(if before.len() > max_bytes {
            ProductionConfigErrorV1::OversizeConfig
        } else {
            physical_error
        });
    }
    let mut file = File::open(path).map_err(|_| physical_error)?;
    let opened = file.metadata().map_err(|_| physical_error)?;
    #[cfg(target_os = "linux")]
    if before.dev() != opened.dev() || before.ino() != opened.ino() {
        return Err(physical_error);
    }
    let mut bytes = Vec::with_capacity(before.len() as usize);
    file.by_ref()
        .take(max_bytes + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| physical_error)?;
    if bytes.len() as u64 > max_bytes {
        return Err(ProductionConfigErrorV1::OversizeConfig);
    }
    let after = file.metadata().map_err(|_| physical_error)?;
    #[cfg(target_os = "linux")]
    if opened.dev() != after.dev()
        || opened.ino() != after.ino()
        || opened.len() != after.len()
        || opened.mtime() != after.mtime()
        || opened.mtime_nsec() != after.mtime_nsec()
        || after.nlink() != 1
    {
        return Err(physical_error);
    }
    #[cfg(target_os = "linux")]
    {
        let retained = fs::symlink_metadata(path).map_err(|_| physical_error)?;
        if !retained.file_type().is_file()
            || retained.file_type().is_symlink()
            || retained.dev() != after.dev()
            || retained.ino() != after.ino()
        {
            return Err(physical_error);
        }
    }
    Ok(bytes)
}

fn validate_owner_file(
    path: &Path,
    error: ProductionConfigErrorV1,
) -> Result<(), ProductionConfigErrorV1> {
    #[cfg(not(target_os = "linux"))]
    {
        let _ = path;
        return Err(ProductionConfigErrorV1::UnsupportedPlatform);
    }
    #[cfg(target_os = "linux")]
    {
        let metadata = fs::symlink_metadata(path).map_err(|_| error)?;
        if !metadata.file_type().is_file()
            || metadata.file_type().is_symlink()
            || metadata.permissions().mode() & 0o7777 != FILE_MODE_V1
            || metadata.nlink() != 1
            || metadata.uid() != effective_uid()?
        {
            return Err(error);
        }
        Ok(())
    }
}

fn validate_owner_directory(
    path: &Path,
    error: ProductionConfigErrorV1,
) -> Result<(), ProductionConfigErrorV1> {
    #[cfg(not(target_os = "linux"))]
    {
        let _ = path;
        return Err(ProductionConfigErrorV1::UnsupportedPlatform);
    }
    #[cfg(target_os = "linux")]
    {
        let metadata = fs::symlink_metadata(path).map_err(|_| error)?;
        if !metadata.file_type().is_dir()
            || metadata.file_type().is_symlink()
            || metadata.permissions().mode() & 0o7777 != DIRECTORY_MODE_V1
            || metadata.uid() != effective_uid()?
        {
            return Err(error);
        }
        Ok(())
    }
}

#[cfg(target_os = "linux")]
fn effective_uid() -> Result<u32, ProductionConfigErrorV1> {
    let mut file =
        File::open("/proc/self/status").map_err(|_| ProductionConfigErrorV1::StorageUnavailable)?;
    let mut bytes = Vec::with_capacity(4096);
    file.by_ref()
        .take(64 * 1024)
        .read_to_end(&mut bytes)
        .map_err(|_| ProductionConfigErrorV1::StorageUnavailable)?;
    let text =
        std::str::from_utf8(&bytes).map_err(|_| ProductionConfigErrorV1::StorageUnavailable)?;
    let line = text
        .lines()
        .find(|line| line.starts_with("Uid:"))
        .ok_or(ProductionConfigErrorV1::StorageUnavailable)?;
    let mut fields = line[4..].split_ascii_whitespace();
    let _real = fields
        .next()
        .ok_or(ProductionConfigErrorV1::StorageUnavailable)?;
    fields
        .next()
        .ok_or(ProductionConfigErrorV1::StorageUnavailable)?
        .parse()
        .map_err(|_| ProductionConfigErrorV1::StorageUnavailable)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::{DirBuilder, OpenOptions};
    use std::io::Write;
    use std::os::unix::fs::{symlink, DirBuilderExt, OpenOptionsExt};
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(1);

    /// Externally provisioned identity authority used by the V2 fixtures.
    const IDENTITY_STORE_PATH_V2: &str = "inputs/contracts-transport-identity";

    struct Fixture {
        root: PathBuf,
    }

    impl Fixture {
        fn new() -> Self {
            let ordinal = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
            let root = std::env::temp_dir().join(format!(
                "dom-interop-production-config-{}-{ordinal}",
                std::process::id()
            ));
            assert!(!root.exists());
            create_owner_dir(&root);
            create_owner_dir(&root.join("inputs"));
            create_owner_dir(&root.join("state"));
            let fixture = Self { root };
            for role in ProductionPathRoleV1::ALL {
                if role.kind() == ProductionPathKindV1::InputFile {
                    write_owner_file(
                        &fixture.root.join(standard_paths()[role.index()].as_str()),
                        role.key().as_bytes(),
                    );
                }
            }
            fixture
        }

        fn config(&self, mode: ProductionBootstrapModeV1) -> ProductionBootstrapConfigV1 {
            ProductionBootstrapConfigV1::from_parts(
                mode,
                pins(),
                bounds(),
                ProductionPathReferencesV1::from_ordered(standard_paths()).unwrap(),
            )
            .unwrap()
        }

        fn config_v2(&self, mode: ProductionBootstrapModeV1) -> ProductionBootstrapConfigV1 {
            ProductionBootstrapConfigV1::from_parts_v2(
                mode,
                pins(),
                bounds(),
                ProductionPathReferencesV1::from_ordered(standard_paths()).unwrap(),
                IDENTITY_STORE_PATH_V2.to_owned(),
            )
            .unwrap()
        }

        fn install_manifests_v2(&self) {
            write_owner_file(
                &self.root.join(PRODUCTION_CREATE_CONFIG_FILE_V2),
                &self
                    .config_v2(ProductionBootstrapModeV1::Create)
                    .canonical_bytes()
                    .unwrap(),
            );
            write_owner_file(
                &self.root.join(PRODUCTION_REOPEN_CONFIG_FILE_V2),
                &self
                    .config_v2(ProductionBootstrapModeV1::ReopenExisting)
                    .canonical_bytes()
                    .unwrap(),
            );
        }

        fn create_identity_authority(&self) {
            create_owner_dir(&self.root.join(IDENTITY_STORE_PATH_V2));
        }

        fn install_manifests(&self) {
            write_owner_file(
                &self.root.join(PRODUCTION_CREATE_CONFIG_FILE_V1),
                &self
                    .config(ProductionBootstrapModeV1::Create)
                    .canonical_bytes()
                    .unwrap(),
            );
            write_owner_file(
                &self.root.join(PRODUCTION_REOPEN_CONFIG_FILE_V1),
                &self
                    .config(ProductionBootstrapModeV1::ReopenExisting)
                    .canonical_bytes()
                    .unwrap(),
            );
        }

        fn create_managed_state(&self) {
            for role in ProductionPathRoleV1::ALL {
                let path = self.root.join(standard_paths()[role.index()].as_str());
                match role.kind() {
                    ProductionPathKindV1::InputFile
                    | ProductionPathKindV1::ExistingAuthorityDirectory => {}
                    ProductionPathKindV1::ManagedFile => write_owner_file(&path, b"state-v1"),
                    ProductionPathKindV1::ManagedDirectory => create_owner_dir(&path),
                }
            }
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            if self.root.starts_with(std::env::temp_dir())
                && self
                    .root
                    .file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| name.starts_with("dom-interop-production-config-"))
            {
                let _ = fs::remove_dir_all(&self.root);
            }
        }
    }

    fn create_owner_dir(path: &Path) {
        let mut builder = DirBuilder::new();
        builder.mode(DIRECTORY_MODE_V1);
        builder.create(path).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(DIRECTORY_MODE_V1)).unwrap();
    }

    fn write_owner_file(path: &Path, bytes: &[u8]) {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true).mode(FILE_MODE_V1);
        let mut file = options.open(path).unwrap();
        file.write_all(bytes).unwrap();
        file.sync_all().unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(FILE_MODE_V1)).unwrap();
    }

    fn standard_paths() -> [String; PRODUCTION_PATH_ROLE_COUNT_V1] {
        [
            "inputs/registry.sqlite3",
            "inputs/registry-authorities.v1",
            "inputs/upstream-terms.v1",
            "inputs/downstream-terms.v1",
            "inputs/participant-bindings.v1",
            "inputs/relay-roster.v1",
            "inputs/time-policy.v2",
            "inputs/time-evidence.v2",
            "inputs/dom-wallet.enc",
            "state/route.sqlite3",
            "state/time-anchor.sqlite3",
            "state/coordinator.sqlite3",
            "state/dom-actuator.sqlite3",
            "state/evm-actuator.sqlite3",
            "state/bitcoin-actuator.sqlite3",
            "state/bitcoin-participant.v1",
            "state/dom-upstream-participant.v1",
            "state/dom-downstream-participant.v1",
            "state/solver-inventory.sqlite3",
            "state/relay-queue",
            "state/upstream-sender",
            "state/upstream-inbox",
            "state/upstream-frames",
            "state/upstream-contracts",
            "state/downstream-sender",
            "state/downstream-inbox",
            "state/downstream-frames",
            "state/downstream-contracts",
        ]
        .map(str::to_owned)
    }

    fn pins() -> ProductionRoutePinsV1 {
        let mut next = 1_u8;
        let mut digest = || {
            let value = [next; 32];
            next += 1;
            value
        };
        ProductionRoutePinsV1 {
            network_id: digest(),
            route_id: digest(),
            registry_manifest_digest: digest(),
            registry_minimum_epoch: 7,
            registry_authority_set_digest: digest(),
            time_policy_authority_set_digest: digest(),
            time_evidence_authority_set_digest: digest(),
            upstream_terms_digest: digest(),
            downstream_terms_digest: digest(),
            route_scope_digest: digest(),
            participant_bindings_digest: digest(),
            relay_binding_digest: digest(),
            time_policy_digest: digest(),
            time_evidence_digest: digest(),
            process_owner_id: digest(),
            coordinator_id: digest(),
            coordinator_plan_authority_id: digest(),
            actuator_bindings_digest: digest(),
            solver_inventory_binding_digest: digest(),
        }
    }

    const fn bounds() -> ProductionRuntimeBoundsV1 {
        ProductionRuntimeBoundsV1 {
            lease_duration_ms: 120_000,
            renew_before_ms: 60_000,
            dispatch_lease_ms: 45_000,
            coordinator_lease_ms: 120_000,
            actuator_lease_ms: 120_000,
            external_call_timeout_ms: 30_000,
            waiting_backoff_ms: 1_000,
            recovery_backoff_ms: 100,
            relay_poll_backoff_ms: 500,
            per_queue_batch_limit: 1,
        }
    }

    fn rechecksum(mut bytes: Vec<u8>) -> Vec<u8> {
        let marker = b"config_digest=";
        let start = bytes
            .windows(marker.len())
            .position(|window| window == marker)
            .unwrap();
        let body = bytes[..start].to_vec();
        let digest = encode_hex(&config_digest(&body).unwrap());
        let digest_start = start + marker.len();
        bytes[digest_start..digest_start + 64].copy_from_slice(digest.as_bytes());
        bytes
    }

    fn replace_once(bytes: Vec<u8>, from: &str, to: &str) -> Vec<u8> {
        assert_eq!(from.len(), to.len());
        let mut text = String::from_utf8(bytes).unwrap();
        let position = text.find(from).unwrap();
        text.replace_range(position..position + from.len(), to);
        text.into_bytes()
    }

    /// Frozen canonical V1 encoding of the deterministic fixture input.
    ///
    /// Every newline is written explicitly so no editor, formatter or invisible
    /// character can silently alter the frozen bytes. Adding, removing, renaming
    /// or reordering any role, pin, bound or key changes this literal, which is
    /// precisely what the golden exists to catch.
    const GOLDEN_CREATE_V1: &str = concat!(
        "DOM-INTEROPD-BOOTSTRAP-V1\n",
        "mode=create\n",
        "network_id=0101010101010101010101010101010101010101010101010101010101010101\n",
        "route_id=0202020202020202020202020202020202020202020202020202020202020202\n",
        "registry_manifest_digest=0303030303030303030303030303030303030303030303030303030303030303\n",
        "registry_minimum_epoch=7\n",
        "registry_authority_set_digest=0404040404040404040404040404040404040404040404040404040404040404\n",
        "time_policy_authority_set_digest=0505050505050505050505050505050505050505050505050505050505050505\n",
        "time_evidence_authority_set_digest=0606060606060606060606060606060606060606060606060606060606060606\n",
        "upstream_terms_digest=0707070707070707070707070707070707070707070707070707070707070707\n",
        "downstream_terms_digest=0808080808080808080808080808080808080808080808080808080808080808\n",
        "route_scope_digest=0909090909090909090909090909090909090909090909090909090909090909\n",
        "participant_bindings_digest=0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a\n",
        "relay_binding_digest=0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b\n",
        "time_policy_digest=0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c\n",
        "time_evidence_digest=0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d\n",
        "process_owner_id=0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e\n",
        "coordinator_id=0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f\n",
        "coordinator_plan_authority_id=1010101010101010101010101010101010101010101010101010101010101010\n",
        "actuator_bindings_digest=1111111111111111111111111111111111111111111111111111111111111111\n",
        "solver_inventory_binding_digest=1212121212121212121212121212121212121212121212121212121212121212\n",
        "lease_duration_ms=120000\n",
        "renew_before_ms=60000\n",
        "dispatch_lease_ms=45000\n",
        "coordinator_lease_ms=120000\n",
        "actuator_lease_ms=120000\n",
        "external_call_timeout_ms=30000\n",
        "waiting_backoff_ms=1000\n",
        "recovery_backoff_ms=100\n",
        "relay_poll_backoff_ms=500\n",
        "per_queue_batch_limit=1\n",
        "path_registry_store=inputs/registry.sqlite3\n",
        "path_registry_authorities=inputs/registry-authorities.v1\n",
        "path_upstream_terms=inputs/upstream-terms.v1\n",
        "path_downstream_terms=inputs/downstream-terms.v1\n",
        "path_participant_bindings=inputs/participant-bindings.v1\n",
        "path_relay_roster=inputs/relay-roster.v1\n",
        "path_time_policy=inputs/time-policy.v2\n",
        "path_time_evidence=inputs/time-evidence.v2\n",
        "path_dom_wallet=inputs/dom-wallet.enc\n",
        "path_route_store=state/route.sqlite3\n",
        "path_time_anchor_store=state/time-anchor.sqlite3\n",
        "path_coordinator_store=state/coordinator.sqlite3\n",
        "path_dom_actuator_store=state/dom-actuator.sqlite3\n",
        "path_evm_actuator_store=state/evm-actuator.sqlite3\n",
        "path_bitcoin_actuator_store=state/bitcoin-actuator.sqlite3\n",
        "path_bitcoin_participant_state=state/bitcoin-participant.v1\n",
        "path_dom_upstream_participant_state=state/dom-upstream-participant.v1\n",
        "path_dom_downstream_participant_state=state/dom-downstream-participant.v1\n",
        "path_solver_inventory_store=state/solver-inventory.sqlite3\n",
        "path_relay_queue=state/relay-queue\n",
        "path_upstream_relay_sender=state/upstream-sender\n",
        "path_upstream_relay_inbox=state/upstream-inbox\n",
        "path_upstream_relay_frames=state/upstream-frames\n",
        "path_upstream_contracts=state/upstream-contracts\n",
        "path_downstream_relay_sender=state/downstream-sender\n",
        "path_downstream_relay_inbox=state/downstream-inbox\n",
        "path_downstream_relay_frames=state/downstream-frames\n",
        "path_downstream_contracts=state/downstream-contracts\n",
        "config_digest=93822c2ddaf2e13adcce70e1243c454a9013e20ba0e22a1c8b4de25954f32960\n",
        "end=1\n",
    );

    /// BLAKE2b-256 of the complete frozen encoding above.
    const GOLDEN_CREATE_V1_BLAKE2B256: &str =
        "8484c930344caa284460afa6ee35fca50a518f22a4d1145a02311ad312b158f1";

    /// Frozen canonical V2 create manifest, byte for byte.
    ///
    /// The V2 family shipped without one. This literal is the V1 golden with
    /// its header replaced and one reference line added, and its digests were
    /// derived by an implementation independent of this crate rather than
    /// printed by the encoder — the same derivation was first checked against
    /// the V1 golden's two frozen values and reproduced both exactly, which is
    /// what makes it evidence instead of an echo.
    const GOLDEN_CREATE_V2: &str = concat!(
        "DOM-INTEROPD-BOOTSTRAP-V2\n",
        "mode=create\n",
        "network_id=0101010101010101010101010101010101010101010101010101010101010101\n",
        "route_id=0202020202020202020202020202020202020202020202020202020202020202\n",
        "registry_manifest_digest=0303030303030303030303030303030303030303030303030303030303030303\n",
        "registry_minimum_epoch=7\n",
        "registry_authority_set_digest=0404040404040404040404040404040404040404040404040404040404040404\n",
        "time_policy_authority_set_digest=0505050505050505050505050505050505050505050505050505050505050505\n",
        "time_evidence_authority_set_digest=0606060606060606060606060606060606060606060606060606060606060606\n",
        "upstream_terms_digest=0707070707070707070707070707070707070707070707070707070707070707\n",
        "downstream_terms_digest=0808080808080808080808080808080808080808080808080808080808080808\n",
        "route_scope_digest=0909090909090909090909090909090909090909090909090909090909090909\n",
        "participant_bindings_digest=0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a\n",
        "relay_binding_digest=0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b\n",
        "time_policy_digest=0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c\n",
        "time_evidence_digest=0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d\n",
        "process_owner_id=0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e\n",
        "coordinator_id=0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f\n",
        "coordinator_plan_authority_id=1010101010101010101010101010101010101010101010101010101010101010\n",
        "actuator_bindings_digest=1111111111111111111111111111111111111111111111111111111111111111\n",
        "solver_inventory_binding_digest=1212121212121212121212121212121212121212121212121212121212121212\n",
        "lease_duration_ms=120000\n",
        "renew_before_ms=60000\n",
        "dispatch_lease_ms=45000\n",
        "coordinator_lease_ms=120000\n",
        "actuator_lease_ms=120000\n",
        "external_call_timeout_ms=30000\n",
        "waiting_backoff_ms=1000\n",
        "recovery_backoff_ms=100\n",
        "relay_poll_backoff_ms=500\n",
        "per_queue_batch_limit=1\n",
        "path_registry_store=inputs/registry.sqlite3\n",
        "path_registry_authorities=inputs/registry-authorities.v1\n",
        "path_upstream_terms=inputs/upstream-terms.v1\n",
        "path_downstream_terms=inputs/downstream-terms.v1\n",
        "path_participant_bindings=inputs/participant-bindings.v1\n",
        "path_relay_roster=inputs/relay-roster.v1\n",
        "path_time_policy=inputs/time-policy.v2\n",
        "path_time_evidence=inputs/time-evidence.v2\n",
        "path_dom_wallet=inputs/dom-wallet.enc\n",
        "path_route_store=state/route.sqlite3\n",
        "path_time_anchor_store=state/time-anchor.sqlite3\n",
        "path_coordinator_store=state/coordinator.sqlite3\n",
        "path_dom_actuator_store=state/dom-actuator.sqlite3\n",
        "path_evm_actuator_store=state/evm-actuator.sqlite3\n",
        "path_bitcoin_actuator_store=state/bitcoin-actuator.sqlite3\n",
        "path_bitcoin_participant_state=state/bitcoin-participant.v1\n",
        "path_dom_upstream_participant_state=state/dom-upstream-participant.v1\n",
        "path_dom_downstream_participant_state=state/dom-downstream-participant.v1\n",
        "path_solver_inventory_store=state/solver-inventory.sqlite3\n",
        "path_relay_queue=state/relay-queue\n",
        "path_upstream_relay_sender=state/upstream-sender\n",
        "path_upstream_relay_inbox=state/upstream-inbox\n",
        "path_upstream_relay_frames=state/upstream-frames\n",
        "path_upstream_contracts=state/upstream-contracts\n",
        "path_downstream_relay_sender=state/downstream-sender\n",
        "path_downstream_relay_inbox=state/downstream-inbox\n",
        "path_downstream_relay_frames=state/downstream-frames\n",
        "path_downstream_contracts=state/downstream-contracts\n",
        "path_contracts_transport_identity_store=inputs/contracts-transport-identity\n",
        "config_digest=7b60e96c7d50ffbd56745738d577c2ccbc01d7673670d2ca95c96acb6b6341ed\n",
        "end=1\n",
    );

    /// BLAKE2b-256 of the complete frozen V2 encoding above.
    const GOLDEN_CREATE_V2_BLAKE2B256: &str =
        "fd6bb20bfe5d29101095e0fa788547c4c4c093417164eb990c4d07a73bddd8d3";

    /// Frozen canonical V3 create manifest, byte for byte.
    ///
    /// Derived the same way as the V2 golden and by the same independent
    /// implementation, whose two digests were re-checked against **both**
    /// already-frozen goldens before this one was written. A golden printed by
    /// the encoder would prove the encoder equals itself; this one is written
    /// by something that shares no line with the crate it freezes.
    const GOLDEN_CREATE_V3: &str = concat!(
        "DOM-INTEROPD-BOOTSTRAP-V3\n",
        "mode=create\n",
        "network_id=0101010101010101010101010101010101010101010101010101010101010101\n",
        "route_id=0202020202020202020202020202020202020202020202020202020202020202\n",
        "registry_manifest_digest=0303030303030303030303030303030303030303030303030303030303030303\n",
        "registry_minimum_epoch=7\n",
        "registry_authority_set_digest=0404040404040404040404040404040404040404040404040404040404040404\n",
        "time_policy_authority_set_digest=0505050505050505050505050505050505050505050505050505050505050505\n",
        "time_evidence_authority_set_digest=0606060606060606060606060606060606060606060606060606060606060606\n",
        "upstream_terms_digest=0707070707070707070707070707070707070707070707070707070707070707\n",
        "downstream_terms_digest=0808080808080808080808080808080808080808080808080808080808080808\n",
        "route_scope_digest=0909090909090909090909090909090909090909090909090909090909090909\n",
        "participant_bindings_digest=0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a\n",
        "relay_binding_digest=0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b\n",
        "time_policy_digest=0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c\n",
        "time_evidence_digest=0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d\n",
        "process_owner_id=0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e\n",
        "coordinator_id=0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f\n",
        "coordinator_plan_authority_id=1010101010101010101010101010101010101010101010101010101010101010\n",
        "actuator_bindings_digest=1111111111111111111111111111111111111111111111111111111111111111\n",
        "solver_inventory_binding_digest=1212121212121212121212121212121212121212121212121212121212121212\n",
        "lease_duration_ms=120000\n",
        "renew_before_ms=60000\n",
        "dispatch_lease_ms=45000\n",
        "coordinator_lease_ms=120000\n",
        "actuator_lease_ms=120000\n",
        "external_call_timeout_ms=30000\n",
        "waiting_backoff_ms=1000\n",
        "recovery_backoff_ms=100\n",
        "relay_poll_backoff_ms=500\n",
        "per_queue_batch_limit=1\n",
        "path_registry_store=inputs/registry.sqlite3\n",
        "path_registry_authorities=inputs/registry-authorities.v1\n",
        "path_upstream_terms=inputs/upstream-terms.v1\n",
        "path_downstream_terms=inputs/downstream-terms.v1\n",
        "path_participant_bindings=inputs/participant-bindings.v1\n",
        "path_relay_roster=inputs/relay-roster.v1\n",
        "path_time_policy=inputs/time-policy.v2\n",
        "path_time_evidence=inputs/time-evidence.v2\n",
        "path_dom_wallet=inputs/dom-wallet.enc\n",
        "path_route_store=state/route.sqlite3\n",
        "path_time_anchor_store=state/time-anchor.sqlite3\n",
        "path_coordinator_store=state/coordinator.sqlite3\n",
        "path_dom_actuator_store=state/dom-actuator.sqlite3\n",
        "path_evm_actuator_store=state/evm-actuator.sqlite3\n",
        "path_bitcoin_actuator_store=state/bitcoin-actuator.sqlite3\n",
        "path_bitcoin_participant_state=state/bitcoin-participant.v1\n",
        "path_dom_upstream_participant_state=state/dom-upstream-participant.v1\n",
        "path_dom_downstream_participant_state=state/dom-downstream-participant.v1\n",
        "path_solver_inventory_store=state/solver-inventory.sqlite3\n",
        "path_relay_queue=state/relay-queue\n",
        "path_upstream_relay_sender=state/upstream-sender\n",
        "path_upstream_relay_inbox=state/upstream-inbox\n",
        "path_upstream_relay_frames=state/upstream-frames\n",
        "path_upstream_contracts=state/upstream-contracts\n",
        "path_downstream_relay_sender=state/downstream-sender\n",
        "path_downstream_relay_inbox=state/downstream-inbox\n",
        "path_downstream_relay_frames=state/downstream-frames\n",
        "path_downstream_contracts=state/downstream-contracts\n",
        "path_contracts_transport_identity_store=inputs/contracts-transport-identity\n",
        "path_contracts_budget_policy=inputs/contracts-budget-policy\n",
        "config_digest=e5b436dc3c3a0d2ead9219a9f063d0cd2156f798d316c52658bc500c46488176\n",
        "end=1\n",
    );

    /// BLAKE2b-256 of the complete frozen V3 encoding above.
    const GOLDEN_CREATE_V3_BLAKE2B256: &str =
        "029fd42a37da48f2eeddd995a8216ba5116d95aef82f224dfb6058b3d1991ec2";

    /// Frozen V1 role keys, in their only canonical order.
    const GOLDEN_ROLE_KEYS_V1: [&str; PRODUCTION_PATH_ROLE_COUNT_V1] = [
        "path_registry_store",
        "path_registry_authorities",
        "path_upstream_terms",
        "path_downstream_terms",
        "path_participant_bindings",
        "path_relay_roster",
        "path_time_policy",
        "path_time_evidence",
        "path_dom_wallet",
        "path_route_store",
        "path_time_anchor_store",
        "path_coordinator_store",
        "path_dom_actuator_store",
        "path_evm_actuator_store",
        "path_bitcoin_actuator_store",
        "path_bitcoin_participant_state",
        "path_dom_upstream_participant_state",
        "path_dom_downstream_participant_state",
        "path_solver_inventory_store",
        "path_relay_queue",
        "path_upstream_relay_sender",
        "path_upstream_relay_inbox",
        "path_upstream_relay_frames",
        "path_upstream_contracts",
        "path_downstream_relay_sender",
        "path_downstream_relay_inbox",
        "path_downstream_relay_frames",
        "path_downstream_contracts",
    ];

    fn golden_blake2b256(bytes: &[u8]) -> String {
        let mut hash = Blake2bVar::new(32).expect("32-byte BLAKE2b is available");
        hash.update(bytes);
        let mut output = [0; 32];
        hash.finalize_variable(&mut output)
            .expect("32-byte BLAKE2b output");
        encode_hex(&output)
    }

    const BUDGET_POLICY_PATH_V3: &str = "inputs/contracts-budget-policy";

    fn golden_create_config_v3() -> ProductionBootstrapConfigV1 {
        ProductionBootstrapConfigV1::from_parts_v3(
            ProductionBootstrapModeV1::Create,
            pins(),
            bounds(),
            ProductionPathReferencesV1::from_ordered(standard_paths())
                .expect("the fixture path set is canonical"),
            IDENTITY_STORE_PATH_V2.to_owned(),
            BUDGET_POLICY_PATH_V3.to_owned(),
        )
        .expect("the V3 fixture config is canonical")
    }

    fn golden_create_config_v4() -> ProductionBootstrapConfigV1 {
        ProductionBootstrapConfigV1::from_parts_v4(
            ProductionBootstrapModeV1::Create,
            pins(),
            bounds(),
            ProductionPathReferencesV1::from_ordered(standard_paths())
                .expect("the fixture path set is canonical"),
            IDENTITY_STORE_PATH_V2.to_owned(),
            BUDGET_POLICY_PATH_V3.to_owned(),
            "inputs/chain-endpoints".to_owned(),
            "solana-actuator-store".to_owned(),
            "xmr-actuator-store".to_owned(),
            "bitcoin-prebroadcast-store".to_owned(),
        )
        .expect("the V4 fixture config is canonical")
    }

    #[test]
    fn v4_config_round_trips_canonically_and_no_other_family_accepts_it() {
        let config = golden_create_config_v4();
        let bytes = config.canonical_bytes().expect("encode V4");
        let decoded = ProductionBootstrapConfigV1::decode_canonical_v4_for_mode(
            &bytes,
            ProductionBootstrapModeV1::Create,
        )
        .expect("decode V4");
        assert_eq!(decoded, config);
        assert_eq!(decoded.canonical_bytes().expect("re-encode"), bytes);
        assert!(ProductionBootstrapConfigV1::decode_canonical_v3_for_mode(
            &bytes,
            ProductionBootstrapModeV1::Create,
        )
        .is_err());
        assert!(ProductionBootstrapConfigV1::decode_canonical_for_mode(
            &bytes,
            ProductionBootstrapModeV1::Create,
        )
        .is_err());
        // And the V4 decoder refuses the V3 document.
        let v3_bytes = golden_create_config_v3()
            .canonical_bytes()
            .expect("encode V3");
        assert!(ProductionBootstrapConfigV1::decode_canonical_v4_for_mode(
            &v3_bytes,
            ProductionBootstrapModeV1::Create,
        )
        .is_err());
    }

    #[test]
    fn v4_accessors_expose_exactly_the_new_references() {
        let config = golden_create_config_v4();
        assert!(config.chain_endpoints().is_some());
        assert!(config.solana_actuator_store().is_some());
        assert!(config.xmr_actuator_store().is_some());
        assert!(config.bitcoin_prebroadcast_store().is_some());
        assert!(config.contracts_budget_policy().is_some());
        assert!(config.contracts_transport_identity_store().is_some());
        let v3 = golden_create_config_v3();
        assert!(v3.chain_endpoints().is_none());
        assert!(v3.solana_actuator_store().is_none());
        assert!(v3.xmr_actuator_store().is_none());
        assert!(v3.bitcoin_prebroadcast_store().is_none());
    }

    #[test]
    fn v4_refuses_aliased_new_references() {
        assert!(ProductionBootstrapConfigV1::from_parts_v4(
            ProductionBootstrapModeV1::Create,
            pins(),
            bounds(),
            ProductionPathReferencesV1::from_ordered(standard_paths())
                .expect("the fixture path set is canonical"),
            IDENTITY_STORE_PATH_V2.to_owned(),
            BUDGET_POLICY_PATH_V3.to_owned(),
            "inputs/chain-endpoints".to_owned(),
            // Aliases the V1 EVM actuator store reference.
            "state/evm-actuator.sqlite3".to_owned(),
            "xmr-actuator-store".to_owned(),
            "bitcoin-prebroadcast-store".to_owned(),
        )
        .is_err());
    }

    fn golden_create_config_v2() -> ProductionBootstrapConfigV1 {
        ProductionBootstrapConfigV1::from_parts_v2(
            ProductionBootstrapModeV1::Create,
            pins(),
            bounds(),
            ProductionPathReferencesV1::from_ordered(standard_paths())
                .expect("the fixture path set is canonical"),
            IDENTITY_STORE_PATH_V2.to_owned(),
        )
        .expect("the V2 fixture config is canonical")
    }

    fn golden_create_config() -> ProductionBootstrapConfigV1 {
        ProductionBootstrapConfigV1::from_parts(
            ProductionBootstrapModeV1::Create,
            pins(),
            bounds(),
            ProductionPathReferencesV1::from_ordered(standard_paths())
                .expect("the deterministic fixture path set is canonical"),
        )
        .expect("the deterministic fixture config is canonical")
    }

    #[test]
    fn production_config_v1_golden_bytes_are_frozen() {
        // (c) The V1 shape itself: exactly 28 roles, one frozen order, one
        // frozen key each, and `index()` agreeing with the position in `ALL`.
        assert_eq!(PRODUCTION_PATH_ROLE_COUNT_V1, 28);
        assert_eq!(
            ProductionPathRoleV1::ALL.len(),
            PRODUCTION_PATH_ROLE_COUNT_V1
        );
        for (position, role) in ProductionPathRoleV1::ALL.into_iter().enumerate() {
            assert_eq!(role.index(), position);
            assert_eq!(role.key(), GOLDEN_ROLE_KEYS_V1[position]);
        }

        // (a) The encoder still produces the exact frozen bytes.
        let config = golden_create_config();
        let encoded = config
            .canonical_bytes()
            .expect("the deterministic fixture config encodes");
        assert_eq!(
            encoded,
            GOLDEN_CREATE_V1.as_bytes(),
            "the V1 bootstrap encoding drifted from its frozen golden"
        );
        assert_eq!(golden_blake2b256(&encoded), GOLDEN_CREATE_V1_BLAKE2B256);

        // (b) The frozen bytes still decode back to the exact same input.
        let decoded = ProductionBootstrapConfigV1::decode_canonical_for_mode(
            GOLDEN_CREATE_V1.as_bytes(),
            ProductionBootstrapModeV1::Create,
        )
        .expect("the frozen golden must decode");
        assert!(
            decoded == config,
            "the frozen golden decoded to a different configuration"
        );
        assert_eq!(decoded.mode(), ProductionBootstrapModeV1::Create);
        assert_eq!(decoded.pins(), pins());
        assert_eq!(decoded.bounds(), bounds());
        let expected_paths = standard_paths();
        for (position, role) in ProductionPathRoleV1::ALL.into_iter().enumerate() {
            assert_eq!(
                decoded.relative_path(role),
                Path::new(&expected_paths[position])
            );
        }

        // (d) One tampered byte, same length and everything else intact, is
        // refused with the exact integrity error and never reinterpreted.
        let tampered = replace_once(
            GOLDEN_CREATE_V1.as_bytes().to_vec(),
            "state/downstream-contracts",
            "state/downstream-contractz",
        );
        assert_eq!(tampered.len(), GOLDEN_CREATE_V1.len());
        assert_eq!(
            ProductionBootstrapConfigV1::decode_canonical_for_mode(
                &tampered,
                ProductionBootstrapModeV1::Create,
            )
            .unwrap_err(),
            ProductionConfigErrorV1::IntegrityMismatch
        );
    }

    /// Repair aid for the golden above: prints the exact current encoding and
    /// its digest.
    ///
    /// It is ignored by default and asserts nothing. It exists only so that a
    /// deliberate, reviewed change to the V1 shape can be re-frozen without
    /// hand-transcribing 3398 bytes.
    #[test]
    #[ignore = "prints the golden; run explicitly when re-freezing V1 on purpose"]
    fn print_production_config_v1_golden() {
        let encoded = golden_create_config()
            .canonical_bytes()
            .expect("the deterministic fixture config encodes");
        println!(
            "{}",
            std::str::from_utf8(&encoded).expect("the canonical encoding is ASCII")
        );
        println!("blake2b256={}", golden_blake2b256(&encoded));
    }

    #[test]
    fn reserved_manifest_names_are_never_path_references() {
        for reserved in [
            PRODUCTION_CREATE_CONFIG_FILE_V1,
            PRODUCTION_REOPEN_CONFIG_FILE_V1,
            PRODUCTION_CREATE_CONFIG_FILE_V2,
            PRODUCTION_REOPEN_CONFIG_FILE_V2,
            PRODUCTION_NODE_CONFIG_FILE_V1,
        ] {
            assert_eq!(
                validate_relative_path(reserved).unwrap_err(),
                ProductionConfigErrorV1::InvalidPathReference,
                "{reserved} must never be usable as a path role reference"
            );
            let mut paths = standard_paths();
            paths[0] = reserved.to_owned();
            assert_eq!(
                ProductionPathReferencesV1::from_ordered(paths).unwrap_err(),
                ProductionConfigErrorV1::InvalidPathReference
            );
            let mut extended = standard_paths().to_vec();
            extended.push(reserved.to_owned());
            assert_eq!(
                validate_path_set(&extended).unwrap_err(),
                ProductionConfigErrorV1::InvalidPathReference
            );
        }
    }

    /// The V3 family is frozen from the day it exists, unlike V2.
    ///
    /// One side is the encoder and the other a literal derived outside this
    /// crate. It also asserts the shape the family promises: a V3 document is
    /// a V2 document plus exactly one reference line, in that position — so a
    /// future edit that reordered the extras would fail here and not silently
    /// produce a document no earlier decoder can read.
    #[test]
    fn production_config_v3_golden_bytes_are_frozen() {
        let config = golden_create_config_v3();
        let encoded = config
            .canonical_bytes()
            .expect("the deterministic V3 fixture config encodes");
        assert_eq!(
            encoded,
            GOLDEN_CREATE_V3.as_bytes(),
            "the V3 bootstrap encoding drifted from its frozen golden"
        );
        assert_eq!(golden_blake2b256(&encoded), GOLDEN_CREATE_V3_BLAKE2B256);

        let decoded = ProductionBootstrapConfigV1::decode_canonical_v3_for_mode(
            GOLDEN_CREATE_V3.as_bytes(),
            ProductionBootstrapModeV1::Create,
        )
        .expect("the frozen V3 golden must decode");
        assert!(
            decoded == config,
            "the frozen V3 golden decoded to a different configuration"
        );
        assert_eq!(
            decoded.contracts_budget_policy(),
            Some(Path::new(BUDGET_POLICY_PATH_V3))
        );

        // V3 is V2 plus one line, and the added line is the last reference.
        let frozen_v2: Vec<&str> = GOLDEN_CREATE_V2.lines().collect();
        let produced: Vec<&str> = GOLDEN_CREATE_V3.lines().collect();
        assert_eq!(produced.len(), frozen_v2.len() + 1);
        assert_eq!(produced[0], HEADER_V3);
        let digest_at = produced
            .iter()
            .position(|line| line.starts_with("config_digest="))
            .expect("the V3 golden carries a digest line");
        assert_eq!(
            produced[digest_at - 1],
            format!("{BUDGET_POLICY_KEY_V3}={BUDGET_POLICY_PATH_V3}")
        );
        assert_eq!(
            produced[digest_at - 2],
            format!("{IDENTITY_STORE_KEY_V2}={IDENTITY_STORE_PATH_V2}")
        );
    }

    /// Prints the V3 golden. Run explicitly when re-freezing V3 on purpose.
    #[test]
    #[ignore = "prints the golden; run explicitly when re-freezing V3 on purpose"]
    fn print_production_config_v3_golden() {
        let encoded = golden_create_config_v3()
            .canonical_bytes()
            .expect("the deterministic V3 fixture config encodes");
        println!(
            "{}",
            std::str::from_utf8(&encoded).expect("the canonical encoding is ASCII")
        );
        println!("blake2b256={}", golden_blake2b256(&encoded));
    }

    /// No family decodes another family's bytes, in either direction.
    #[test]
    fn v3_documents_are_refused_by_the_v1_and_v2_decoders_and_the_reverse() {
        for (bytes, name) in [
            (GOLDEN_CREATE_V1.as_bytes(), "V1"),
            (GOLDEN_CREATE_V2.as_bytes(), "V2"),
        ] {
            assert!(
                ProductionBootstrapConfigV1::decode_canonical_v3_for_mode(
                    bytes,
                    ProductionBootstrapModeV1::Create,
                )
                .is_err(),
                "the V3 decoder accepted a {name} document"
            );
        }
        assert!(ProductionBootstrapConfigV1::decode_canonical_for_mode(
            GOLDEN_CREATE_V3.as_bytes(),
            ProductionBootstrapModeV1::Create,
        )
        .is_err());
        assert!(ProductionBootstrapConfigV1::decode_canonical_v2_for_mode(
            GOLDEN_CREATE_V3.as_bytes(),
            ProductionBootstrapModeV1::Create,
        )
        .is_err());
    }

    /// The V2 family now has frozen bytes, and this is what checks them.
    ///
    /// Built the same way as the V1 golden test and for the same reason: one
    /// side is the encoder, the other is a literal nobody can regenerate by
    /// accident. `print_production_config_v2_golden` exists to re-freeze it
    /// deliberately, exactly as V1 does.
    #[test]
    fn production_config_v2_golden_bytes_are_frozen() {
        let config = golden_create_config_v2();
        let encoded = config
            .canonical_bytes()
            .expect("the deterministic V2 fixture config encodes");
        assert_eq!(
            encoded,
            GOLDEN_CREATE_V2.as_bytes(),
            "the V2 bootstrap encoding drifted from its frozen golden"
        );
        assert_eq!(golden_blake2b256(&encoded), GOLDEN_CREATE_V2_BLAKE2B256);

        let decoded = ProductionBootstrapConfigV1::decode_canonical_v2_for_mode(
            GOLDEN_CREATE_V2.as_bytes(),
            ProductionBootstrapModeV1::Create,
        )
        .expect("the frozen V2 golden must decode");
        assert!(
            decoded == config,
            "the frozen V2 golden decoded to a different configuration"
        );
    }

    /// Prints the V2 golden. Run explicitly when re-freezing V2 on purpose.
    #[test]
    #[ignore = "prints the golden; run explicitly when re-freezing V2 on purpose"]
    fn print_production_config_v2_golden() {
        let encoded = golden_create_config_v2()
            .canonical_bytes()
            .expect("the deterministic V2 fixture config encodes");
        println!(
            "{}",
            std::str::from_utf8(&encoded).expect("the canonical encoding is ASCII")
        );
        println!("blake2b256={}", golden_blake2b256(&encoded));
    }

    /// The extras refactor moved no byte of either family.
    ///
    /// V1 is covered by the frozen golden above — `GOLDEN_CREATE_V1` and its
    /// frozen digest — and this test does not restate it. **V2 has no frozen
    /// golden in this repository**, which is a gap worth naming rather than
    /// papering over: it shipped with behavioural tests only. So the strongest
    /// available check is structural, and it is written so that one side comes
    /// from the frozen V1 literal and the other from the encoder — never the
    /// encoder against itself, which would pass whatever the encoder did.
    ///
    /// The `config_digest` line is excluded by name and not by accident: it
    /// covers the body, so it *must* differ between two documents that differ.
    /// Excluding anything else would be hiding drift.
    #[test]
    fn the_v2_document_is_the_frozen_v1_document_plus_exactly_one_line() {
        let v2 = ProductionBootstrapConfigV1::from_parts_v2(
            ProductionBootstrapModeV1::Create,
            pins(),
            bounds(),
            ProductionPathReferencesV1::from_ordered(standard_paths())
                .expect("the fixture path set is canonical"),
            IDENTITY_STORE_PATH_V2.to_owned(),
        )
        .expect("the V2 fixture config is canonical");
        let encoded = v2.canonical_bytes().expect("the V2 document encodes");
        let encoded = std::str::from_utf8(&encoded).expect("the document is UTF-8");

        let frozen: Vec<&str> = GOLDEN_CREATE_V1.lines().collect();
        let produced: Vec<&str> = encoded.lines().collect();
        assert_eq!(
            produced.len(),
            frozen.len() + 1,
            "V2 must be the V1 document plus exactly one reference line"
        );

        // The headers are the two family headers and nothing else.
        assert_eq!(frozen[0], HEADER_V1);
        assert_eq!(produced[0], HEADER_V2);

        // Every other line of the frozen V1 document appears in the produced
        // V2 document, unchanged, except the digest that must differ.
        let extra = format!("{IDENTITY_STORE_KEY_V2}={IDENTITY_STORE_PATH_V2}");
        let mut expected: Vec<&str> = Vec::with_capacity(produced.len());
        expected.push(HEADER_V2);
        for line in &frozen[1..] {
            if line.starts_with("config_digest=") {
                expected.push(extra.as_str());
            }
            expected.push(line);
        }
        for (index, (produced, expected)) in produced.iter().zip(expected.iter()).enumerate() {
            if expected.starts_with("config_digest=") {
                assert!(
                    produced.starts_with("config_digest="),
                    "line {index} should still be the digest"
                );
                continue;
            }
            assert_eq!(
                produced, expected,
                "line {index} drifted from the V1 golden"
            );
        }
    }

    #[test]
    fn v1_and_v2_manifest_families_never_decode_each_other() {
        let v1 = golden_create_config();
        let v1_bytes = v1.canonical_bytes().expect("the V1 document encodes");
        let v2 = ProductionBootstrapConfigV1::from_parts_v2(
            ProductionBootstrapModeV1::Create,
            pins(),
            bounds(),
            ProductionPathReferencesV1::from_ordered(standard_paths())
                .expect("the fixture path set is canonical"),
            IDENTITY_STORE_PATH_V2.to_owned(),
        )
        .expect("the V2 fixture config is canonical");
        let v2_bytes = v2.canonical_bytes().expect("the V2 document encodes");

        // The two families differ in header, line count and content, and each
        // one round-trips only through its own decoder.
        assert_ne!(v1_bytes, v2_bytes);
        assert_eq!(v1.contracts_transport_identity_store(), None);
        assert_eq!(
            v2.contracts_transport_identity_store(),
            Some(Path::new(IDENTITY_STORE_PATH_V2))
        );
        let decoded_v1 = ProductionBootstrapConfigV1::decode_canonical_for_mode(
            &v1_bytes,
            ProductionBootstrapModeV1::Create,
        )
        .expect("the V1 document decodes in the V1 family");
        assert!(decoded_v1 == v1);
        let decoded_v2 = ProductionBootstrapConfigV1::decode_canonical_v2_for_mode(
            &v2_bytes,
            ProductionBootstrapModeV1::Create,
        )
        .expect("the V2 document decodes in the V2 family");
        assert!(decoded_v2 == v2);

        // Neither loader ever accepts the other family's bytes, and there is no
        // silent migration in either direction.
        assert_eq!(
            ProductionBootstrapConfigV1::decode_canonical_for_mode(
                &v2_bytes,
                ProductionBootstrapModeV1::Create,
            )
            .unwrap_err(),
            ProductionConfigErrorV1::InvalidCanonicalEncoding
        );
        assert_eq!(
            ProductionBootstrapConfigV1::decode_canonical_v2_for_mode(
                &v1_bytes,
                ProductionBootstrapModeV1::Create,
            )
            .unwrap_err(),
            ProductionConfigErrorV1::InvalidCanonicalEncoding
        );
    }

    #[test]
    fn v2_identity_authority_is_required_in_both_modes_and_never_created() {
        let fixture = Fixture::new();
        fixture.install_manifests_v2();
        let identity = fixture.root.join(IDENTITY_STORE_PATH_V2);

        // Create refuses while the externally provisioned authority is absent,
        // and provisions nothing on its way out.
        assert_eq!(
            load_production_create_bootstrap_v2(&fixture.root).unwrap_err(),
            ProductionConfigErrorV1::IdentityAuthorityUnavailable
        );
        assert!(
            !identity.exists(),
            "a refused create must never provision the identity authority"
        );

        fixture.create_identity_authority();
        let created = load_production_create_bootstrap_v2(&fixture.root)
            .expect("create accepts the provisioned identity authority");
        assert_eq!(
            created.layout().contracts_transport_identity_store(),
            Some(identity.as_path())
        );

        // Reopen applies the same rule: the authority must already be there.
        fixture.create_managed_state();
        fs::remove_dir_all(&identity).unwrap();
        assert_eq!(
            load_production_reopen_bootstrap_v2(&fixture.root).unwrap_err(),
            ProductionConfigErrorV1::IdentityAuthorityUnavailable
        );
        assert!(
            !identity.exists(),
            "a refused reopen must never provision the identity authority"
        );
        fixture.create_identity_authority();
        let reopened = load_production_reopen_bootstrap_v2(&fixture.root)
            .expect("reopen accepts the provisioned identity authority");
        assert_eq!(
            reopened.config().contracts_transport_identity_store(),
            Some(Path::new(IDENTITY_STORE_PATH_V2))
        );
    }

    #[test]
    fn canonical_codec_rejects_tamper_duplicate_unknown_trailing_and_wrong_mode() {
        let fixture = Fixture::new();
        let config = fixture.config(ProductionBootstrapModeV1::Create);
        let bytes = config.canonical_bytes().unwrap();
        assert_eq!(
            ProductionBootstrapConfigV1::decode_canonical_for_mode(
                &bytes,
                ProductionBootstrapModeV1::Create
            )
            .unwrap(),
            config
        );

        let tampered = replace_once(bytes.clone(), "route_id=02", "route_id=03");
        assert_eq!(
            ProductionBootstrapConfigV1::decode_canonical_for_mode(
                &tampered,
                ProductionBootstrapModeV1::Create
            )
            .unwrap_err(),
            ProductionConfigErrorV1::IntegrityMismatch
        );

        let mut duplicate = bytes.clone();
        let insertion = duplicate
            .windows(b"route_id=".len())
            .position(|window| window == b"route_id=")
            .unwrap();
        duplicate.splice(
            insertion..insertion,
            b"network_id=0101010101010101010101010101010101010101010101010101010101010101\n"
                .iter()
                .copied(),
        );
        assert_eq!(
            ProductionBootstrapConfigV1::decode_canonical_for_mode(
                &duplicate,
                ProductionBootstrapModeV1::Create
            )
            .unwrap_err(),
            ProductionConfigErrorV1::InvalidCanonicalEncoding
        );
        let canonical_text = std::str::from_utf8(&bytes).unwrap();
        for forbidden in [
            "secret",
            "seed",
            "private",
            "key",
            "share",
            "nonce",
            "password",
            "cookie",
            "bearer",
            "token",
            "scalar",
            "credential",
            "apikey",
        ] {
            assert!(!canonical_text.contains(forbidden));
        }

        let unknown = replace_once(bytes.clone(), "network_id", "unknown___");
        assert_eq!(
            ProductionBootstrapConfigV1::decode_canonical_for_mode(
                &unknown,
                ProductionBootstrapModeV1::Create
            )
            .unwrap_err(),
            ProductionConfigErrorV1::InvalidCanonicalEncoding
        );

        let mut trailing = bytes.clone();
        trailing.push(b' ');
        assert_eq!(
            ProductionBootstrapConfigV1::decode_canonical_for_mode(
                &trailing,
                ProductionBootstrapModeV1::Create
            )
            .unwrap_err(),
            ProductionConfigErrorV1::InvalidCanonicalEncoding
        );
        assert_eq!(
            ProductionBootstrapConfigV1::decode_canonical_for_mode(
                &bytes,
                ProductionBootstrapModeV1::ReopenExisting
            )
            .unwrap_err(),
            ProductionConfigErrorV1::InvalidCanonicalEncoding
        );
    }

    #[test]
    fn traversal_sensitive_alias_and_oversize_are_rejected() {
        let fixture = Fixture::new();
        let bytes = fixture
            .config(ProductionBootstrapModeV1::Create)
            .canonical_bytes()
            .unwrap();
        let traversal = replace_once(
            bytes.clone(),
            "inputs/registry.sqlite3",
            "../out/registry.sqlite3",
        );
        let traversal = rechecksum(traversal);
        assert_eq!(
            ProductionBootstrapConfigV1::decode_canonical_for_mode(
                &traversal,
                ProductionBootstrapModeV1::Create
            )
            .unwrap_err(),
            ProductionConfigErrorV1::InvalidPathReference
        );

        let mut paths = standard_paths();
        paths[ProductionPathRoleV1::RegistryStore.index()] = "inputs/bearer-token.v1".to_owned();
        assert_eq!(
            ProductionPathReferencesV1::from_ordered(paths).unwrap_err(),
            ProductionConfigErrorV1::InvalidPathReference
        );
        let mut paths = standard_paths();
        paths[ProductionPathRoleV1::RouteStore.index()] =
            paths[ProductionPathRoleV1::TimeAnchorStore.index()].clone();
        assert_eq!(
            ProductionPathReferencesV1::from_ordered(paths).unwrap_err(),
            ProductionConfigErrorV1::AmbiguousPathReference
        );
        let mut paths = standard_paths();
        paths[ProductionPathRoleV1::TimeAnchorStore.index()] = "state/route.sqlite3-wal".to_owned();
        assert_eq!(
            ProductionPathReferencesV1::from_ordered(paths).unwrap_err(),
            ProductionConfigErrorV1::AmbiguousPathReference
        );
        assert_eq!(
            ProductionBootstrapConfigV1::decode_canonical_for_mode(
                &vec![b'a'; MAX_PRODUCTION_BOOTSTRAP_BYTES_V1 as usize + 1],
                ProductionBootstrapModeV1::Create
            )
            .unwrap_err(),
            ProductionConfigErrorV1::OversizeConfig
        );
    }

    #[test]
    fn create_and_reopen_are_disjoint_and_recovery_never_creates() {
        let fixture = Fixture::new();
        fixture.install_manifests();
        let create = load_production_create_bootstrap_v1(&fixture.root).unwrap();
        assert_eq!(create.config().mode(), ProductionBootstrapModeV1::Create);
        assert!(create
            .layout()
            .path(ProductionPathRoleV1::RouteStore)
            .starts_with(&fixture.root));
        assert_eq!(
            load_production_reopen_bootstrap_v1(&fixture.root).unwrap_err(),
            ProductionConfigErrorV1::RecoveryStateUnavailable
        );
        assert!(!fixture
            .root
            .join(standard_paths()[ProductionPathRoleV1::RouteStore.index()].as_str())
            .exists());

        fixture.create_managed_state();
        assert_eq!(
            load_production_create_bootstrap_v1(&fixture.root).unwrap_err(),
            ProductionConfigErrorV1::StateAlreadyPresent
        );
        let reopened = load_production_reopen_bootstrap_v1(&fixture.root).unwrap();
        assert_eq!(
            reopened.config().mode(),
            ProductionBootstrapModeV1::ReopenExisting
        );

        let missing = fixture
            .root
            .join(standard_paths()[ProductionPathRoleV1::CoordinatorStore.index()].as_str());
        fs::remove_file(&missing).unwrap();
        assert_eq!(
            load_production_reopen_bootstrap_v1(&fixture.root).unwrap_err(),
            ProductionConfigErrorV1::RecoveryStateUnavailable
        );
        assert!(!missing.exists());
    }

    #[test]
    fn residual_sidecar_blocks_create() {
        let fixture = Fixture::new();
        fixture.install_manifests();
        let route = fixture
            .root
            .join(standard_paths()[ProductionPathRoleV1::RouteStore.index()].as_str());
        write_owner_file(Path::new(&format!("{}-wal", route.display())), b"residual");
        assert_eq!(
            load_production_create_bootstrap_v1(&fixture.root).unwrap_err(),
            ProductionConfigErrorV1::StateAlreadyPresent
        );
    }

    #[cfg(feature = "production")]
    #[test]
    fn started_managed_file_accepts_only_the_exact_lock_prefix() {
        let fixture = Fixture::new();
        let route = fixture
            .root
            .join(standard_paths()[ProductionPathRoleV1::RouteStore.index()].as_str());
        assert_eq!(validate_started_managed_file_prefix(&route), Ok(()));

        let lock = PathBuf::from(format!("{}.lock", route.display()));
        write_owner_file(&lock, b"");
        assert_eq!(validate_started_managed_file_prefix(&route), Ok(()));

        let wal = PathBuf::from(format!("{}-wal", route.display()));
        write_owner_file(&wal, b"residual");
        assert_eq!(
            validate_started_managed_file_prefix(&route),
            Err(ProductionConfigErrorV1::ProvisioningJournalRefused)
        );
        fs::remove_file(&wal).unwrap();

        fs::remove_file(&lock).unwrap();
        write_owner_file(&lock, b"not-empty");
        assert_eq!(
            validate_started_managed_file_prefix(&route),
            Err(ProductionConfigErrorV1::ProvisioningJournalRefused)
        );
        fs::remove_file(&lock).unwrap();
        write_owner_file(&lock, b"");
        fs::set_permissions(&lock, fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(
            validate_started_managed_file_prefix(&route),
            Err(ProductionConfigErrorV1::ProvisioningJournalRefused)
        );
    }

    #[test]
    fn symlink_hardlink_and_weak_modes_fail_closed() {
        let fixture = Fixture::new();
        fixture.install_manifests();
        let registry = fixture
            .root
            .join(standard_paths()[ProductionPathRoleV1::RegistryStore.index()].as_str());
        let upstream = fixture
            .root
            .join(standard_paths()[ProductionPathRoleV1::UpstreamTerms.index()].as_str());
        fs::remove_file(&registry).unwrap();
        symlink(&upstream, &registry).unwrap();
        assert_eq!(
            load_production_create_bootstrap_v1(&fixture.root).unwrap_err(),
            ProductionConfigErrorV1::InputArtifactUnavailable
        );

        fs::remove_file(&registry).unwrap();
        fs::hard_link(&upstream, &registry).unwrap();
        assert_eq!(
            load_production_create_bootstrap_v1(&fixture.root).unwrap_err(),
            ProductionConfigErrorV1::InputArtifactUnavailable
        );
        fs::remove_file(&registry).unwrap();
        write_owner_file(&registry, b"registry");
        fs::set_permissions(&registry, fs::Permissions::from_mode(0o640)).unwrap();
        assert_eq!(
            load_production_create_bootstrap_v1(&fixture.root).unwrap_err(),
            ProductionConfigErrorV1::InputArtifactUnavailable
        );
    }

    #[test]
    fn companion_mismatch_and_redaction_are_enforced() {
        let fixture = Fixture::new();
        fixture.install_manifests();
        let reopen_path = fixture.root.join(PRODUCTION_REOPEN_CONFIG_FILE_V1);
        fs::remove_file(&reopen_path).unwrap();
        let mut reopen = fixture.config(ProductionBootstrapModeV1::ReopenExisting);
        reopen.bounds.waiting_backoff_ms = 2_000;
        write_owner_file(&reopen_path, &reopen.canonical_bytes().unwrap());
        assert_eq!(
            load_production_create_bootstrap_v1(&fixture.root).unwrap_err(),
            ProductionConfigErrorV1::CompanionMismatch
        );
        assert_eq!(
            format!("{:?}", reopen),
            "ProductionBootstrapConfigV1([redacted])"
        );
        assert!(!format!("{:?}", ProductionConfigErrorV1::ConfigUnavailable)
            .contains(fixture.root.to_str().unwrap()));
    }
}
