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
use route_executor::LegIdV1;

#[cfg(feature = "production")]
use deployment_registry::ResolvedEvmDeploymentV1;
#[cfg(feature = "production")]
use evm_actuator::EvmFeesV1;

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
/// Fixed owner-only Relay network sidecar; never accepted as a manifest role.
pub const PRODUCTION_RELAY_NETWORK_CONFIG_FILE_V1: &str = "production-relay-network.v1";
/// Fixed durable refund journal leaf owned by Stage 13.
pub const REFUND_ARMING_DATABASE_FILE_V1: &str = "refund-arming.v1.sqlite3";
/// Fixed durable Solana actuator store, created only by a route whose
/// admitted shape carries a Solana leg. Its create/reopen audit is the
/// actuator crate's own; the layout pins the name and the parent chain.
pub const SOLANA_ACTUATOR_DATABASE_FILE_V1: &str = "solana-actuator.v1.sqlite3";
/// Fixed durable Monero actuator store, created only by a route whose
/// admitted shape carries a Monero leg. Same discipline as the Solana store.
pub const XMR_ACTUATOR_DATABASE_FILE_V1: &str = "xmr-actuator.v1.sqlite3";
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
/// Exact path-reference count in V4: V3 plus eleven explicit F6 authorities.
pub const PRODUCTION_PATH_ROLE_COUNT_V4: usize = 41;
/// Number of position-aware F6 authorities added by the V4 family.
pub const PRODUCTION_F6_PATH_ROLE_COUNT_V4: usize = 11;
/// Fixed V5 provisioning manifest name. No earlier loader accepts it.
pub const PRODUCTION_CREATE_CONFIG_FILE_V5: &str = "bootstrap-create-v5.conf";
/// Fixed V5 recovery manifest name. No earlier loader accepts it.
pub const PRODUCTION_REOPEN_CONFIG_FILE_V5: &str = "bootstrap-reopen-v5.conf";
/// Exact path-reference count in V5: V4 plus the signed Contracts bootstrap.
pub const PRODUCTION_PATH_ROLE_COUNT_V5: usize = 42;
/// Fixed V6 provisioning manifest name. No earlier loader accepts it.
pub const PRODUCTION_CREATE_CONFIG_FILE_V6: &str = "bootstrap-create-v6.conf";
/// Fixed V6 recovery manifest name. No earlier loader accepts it.
pub const PRODUCTION_REOPEN_CONFIG_FILE_V6: &str = "bootstrap-reopen-v6.conf";
/// V6 retains exactly the same 42 physical references as V5.
pub const PRODUCTION_PATH_ROLE_COUNT_V6: usize = PRODUCTION_PATH_ROLE_COUNT_V5;
/// Fixed V7 provisioning manifest name. No earlier loader accepts it.
pub const PRODUCTION_CREATE_CONFIG_FILE_V7: &str = "bootstrap-create-v7.conf";
/// Fixed V7 recovery manifest name. No earlier loader accepts it.
pub const PRODUCTION_REOPEN_CONFIG_FILE_V7: &str = "bootstrap-reopen-v7.conf";
/// V7 adds one externally provisioned Bitcoin prebroadcast authority root.
pub const PRODUCTION_PATH_ROLE_COUNT_V7: usize = PRODUCTION_PATH_ROLE_COUNT_V6 + 1;
/// Fixed V8 provisioning manifest name. No earlier loader accepts it.
pub const PRODUCTION_CREATE_CONFIG_FILE_V8: &str = "bootstrap-create-v8.conf";
/// Fixed V8 recovery manifest name. No earlier loader accepts it.
pub const PRODUCTION_REOPEN_CONFIG_FILE_V8: &str = "bootstrap-reopen-v8.conf";
/// Six RFQ-late F6 stores plus the threshold-authenticated V7 bundle.
pub const PRODUCTION_F6_PATH_ROLE_COUNT_V8: usize = 7;
/// V8 retains V7 and adds the seven exact F6 V7 references.
pub const PRODUCTION_PATH_ROLE_COUNT_V8: usize =
    PRODUCTION_PATH_ROLE_COUNT_V7 + PRODUCTION_F6_PATH_ROLE_COUNT_V8;
/// Fixed V9 provisioning manifest name. No earlier loader accepts it.
pub const PRODUCTION_CREATE_CONFIG_FILE_V9: &str = "bootstrap-create-v9.conf";
/// Fixed V9 recovery manifest name. No earlier loader accepts it.
pub const PRODUCTION_REOPEN_CONFIG_FILE_V9: &str = "bootstrap-reopen-v9.conf";
/// V9 adds no path authority: it pins the refund authority generation.
pub const PRODUCTION_PATH_ROLE_COUNT_V9: usize = PRODUCTION_PATH_ROLE_COUNT_V8;
/// Fixed V10 provisioning manifest name. No earlier loader accepts it.
pub const PRODUCTION_CREATE_CONFIG_FILE_V10: &str = "bootstrap-create-v10.conf";
/// Fixed V10 recovery manifest name. No earlier loader accepts it.
pub const PRODUCTION_REOPEN_CONFIG_FILE_V10: &str = "bootstrap-reopen-v10.conf";
/// V10 authenticates operational policies without adding a path authority.
pub const PRODUCTION_PATH_ROLE_COUNT_V10: usize = PRODUCTION_PATH_ROLE_COUNT_V9;

const HEADER_V1: &str = "DOM-INTEROPD-BOOTSTRAP-V1";
const HEADER_V2: &str = "DOM-INTEROPD-BOOTSTRAP-V2";
const HEADER_V3: &str = "DOM-INTEROPD-BOOTSTRAP-V3";
const HEADER_V4: &str = "DOM-INTEROPD-BOOTSTRAP-V4";
const HEADER_V5: &str = "DOM-INTEROPD-BOOTSTRAP-V5";
const HEADER_V6: &str = "DOM-INTEROPD-BOOTSTRAP-V6";
const HEADER_V7: &str = "DOM-INTEROPD-BOOTSTRAP-V7";
const HEADER_V8: &str = "DOM-INTEROPD-BOOTSTRAP-V8";
const HEADER_V9: &str = "DOM-INTEROPD-BOOTSTRAP-V9";
const HEADER_V10: &str = "DOM-INTEROPD-BOOTSTRAP-V10";
const IDENTITY_STORE_KEY_V2: &str = "path_contracts_transport_identity_store";
const BUDGET_POLICY_KEY_V3: &str = "path_contracts_budget_policy";
const CONTRACTS_BOOTSTRAP_KEY_V5: &str = "path_contracts_bootstrap";
const CONTRACTS_BOOTSTRAP_COMMIT_DIGEST_KEY_V5: &str = "contracts_bootstrap_commit_digest";
const CONTRACTS_BOOTSTRAP_REVEAL_DIGEST_KEY_V5: &str = "contracts_bootstrap_reveal_digest";
const RELAY_DATABASE_ID_KEY_V6: &str = "relay_database_id";
const UPSTREAM_RELAY_SENDER_ID_KEY_V6: &str = "upstream_relay_sender_store_id";
const UPSTREAM_RELAY_INBOX_ID_KEY_V6: &str = "upstream_relay_inbox_id";
const UPSTREAM_RELAY_FRAME_ID_KEY_V6: &str = "upstream_relay_reassembler_id";
const DOWNSTREAM_RELAY_SENDER_ID_KEY_V6: &str = "downstream_relay_sender_store_id";
const DOWNSTREAM_RELAY_INBOX_ID_KEY_V6: &str = "downstream_relay_inbox_id";
const DOWNSTREAM_RELAY_FRAME_ID_KEY_V6: &str = "downstream_relay_reassembler_id";
const RELAY_MAX_ENVELOPES_KEY_V6: &str = "relay_max_envelopes";
const SENDER_MAX_ENVELOPES_KEY_V6: &str = "sender_max_envelopes";
const INBOX_MAX_ENTRIES_KEY_V6: &str = "inbox_max_entries";
const FRAME_MAX_MESSAGES_KEY_V6: &str = "frame_max_messages";
const FRAME_MAX_ACTIVE_BYTES_KEY_V6: &str = "frame_max_active_bytes";
const FRAME_MAX_ACTIVE_CHUNKS_KEY_V6: &str = "frame_max_active_chunks";
const BITCOIN_PREBROADCAST_STORE_KEY_V7: &str = "path_bitcoin_prebroadcast_store";
const BITCOIN_LEG_KEY_V7: &str = "bitcoin_prebroadcast_leg";
const BITCOIN_SETTLEMENT_ID_KEY_V7: &str = "bitcoin_prebroadcast_settlement_id";
const BITCOIN_SESSION_ID_KEY_V7: &str = "bitcoin_prebroadcast_session_id";
const BITCOIN_TERMS_DIGEST_KEY_V7: &str = "bitcoin_prebroadcast_terms_digest";
const BITCOIN_DEPLOYMENT_DIGEST_KEY_V7: &str = "bitcoin_prebroadcast_deployment_digest";
const BITCOIN_ROUTE_BINDING_KEY_V7: &str = "bitcoin_prebroadcast_route_binding";
const BITCOIN_PLAN_DIGEST_KEY_V7: &str = "bitcoin_prebroadcast_plan_digest";
const BITCOIN_RECEIPT_DIGEST_KEY_V7: &str = "bitcoin_prebroadcast_receipt_digest";
const BITCOIN_CONTRACT_SCRIPT_DIGEST_KEY_V7: &str = "bitcoin_prebroadcast_contract_script_digest";
const BITCOIN_CLAIM_SCRIPT_DIGEST_KEY_V7: &str = "bitcoin_prebroadcast_claim_script_digest";
const BITCOIN_REFUND_SCRIPT_DIGEST_KEY_V7: &str = "bitcoin_prebroadcast_refund_script_digest";
const BITCOIN_REFUND_KEY_KEY_V7: &str = "bitcoin_prebroadcast_refund_key_xonly";
const BITCOIN_FUNDING_TEMPLATE_KEY_V7: &str = "bitcoin_prebroadcast_funding_template_hash";
const BITCOIN_CLAIM_TEMPLATE_KEY_V7: &str = "bitcoin_prebroadcast_claim_template_hash";
const BITCOIN_REFUND_TEMPLATE_KEY_V7: &str = "bitcoin_prebroadcast_refund_template_hash";
const F6_AUTHORITY_BUNDLE_DIGEST_KEY_V8: &str = "f6_authority_bundle_digest_v7";
const REFUND_ARMING_AUTHORITY_EPOCH_KEY_V9: &str = "refund_arming_authority_epoch";
const UPSTREAM_REMOTE_RELAY_DATABASE_ID_KEY_V10: &str = "upstream_remote_relay_database_id";
const DOWNSTREAM_REMOTE_RELAY_DATABASE_ID_KEY_V10: &str = "downstream_remote_relay_database_id";
const EVM_INITIAL_MAX_FEE_PER_GAS_KEY_V10: &str = "evm_initial_max_fee_per_gas";
const EVM_INITIAL_MAX_PRIORITY_FEE_PER_GAS_KEY_V10: &str = "evm_initial_max_priority_fee_per_gas";
const EVM_OBSERVATION_VALID_FOR_MS_KEY_V10: &str = "evm_observation_valid_for_ms";
const EVM_REMOTE_CUSTODY_LEASE_DURATION_MS_KEY_V10: &str = "evm_remote_custody_lease_duration_ms";
const END_V1: &str = "end=1";
const CONFIG_DIGEST_DOMAIN_V1: &[u8] = b"DOM-INTEROPD/BOOTSTRAP-CONFIG/V1\0";
const BITCOIN_PREBROADCAST_SCRIPT_DIGEST_DOMAIN_V7: &[u8] =
    b"DOM-INTEROPD/PRODUCTION/BITCOIN-PREBROADCAST/SCRIPT/V7\0";
const F6_AUTHORITY_BUNDLE_DIGEST_DOMAIN_V8: &[u8] =
    b"DOM-INTEROPD/PRODUCTION/F6-AUTHORITY-BUNDLE/V8\0";
const MAX_BITCOIN_PREBROADCAST_SCRIPT_BYTES_V7: usize = 10_000;
/// Must stay equal to the strict bound in `production_f6_factory`.
pub const MAX_PRODUCTION_F6_AUTHORITY_BUNDLE_BYTES_V8: u64 = 32_768;
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
// Must stay equal to evm-actuator's strict observation TTL and lease bounds.
const MAX_EVM_OBSERVATION_VALID_FOR_MS_V10: u64 = 60 * 60 * 1_000;
const MAX_EVM_REMOTE_CUSTODY_LEASE_DURATION_MS_V10: u64 = 24 * 60 * 60 * 1_000;
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
    V5,
    V6,
    V7,
    V8,
    V9,
    V10,
}

impl ProductionBootstrapFamilyV1 {
    const fn header(self) -> &'static str {
        match self {
            Self::V1 => HEADER_V1,
            Self::V2 => HEADER_V2,
            Self::V3 => HEADER_V3,
            Self::V4 => HEADER_V4,
            Self::V5 => HEADER_V5,
            Self::V6 => HEADER_V6,
            Self::V7 => HEADER_V7,
            Self::V8 => HEADER_V8,
            Self::V9 => HEADER_V9,
            Self::V10 => HEADER_V10,
        }
    }

    const fn path_role_count(self) -> usize {
        match self {
            Self::V1 => PRODUCTION_PATH_ROLE_COUNT_V1,
            Self::V2 => PRODUCTION_PATH_ROLE_COUNT_V2,
            Self::V3 => PRODUCTION_PATH_ROLE_COUNT_V3,
            Self::V4 => PRODUCTION_PATH_ROLE_COUNT_V4,
            Self::V5 => PRODUCTION_PATH_ROLE_COUNT_V5,
            Self::V6 => PRODUCTION_PATH_ROLE_COUNT_V6,
            Self::V7 => PRODUCTION_PATH_ROLE_COUNT_V7,
            Self::V8 => PRODUCTION_PATH_ROLE_COUNT_V8,
            Self::V9 => PRODUCTION_PATH_ROLE_COUNT_V9,
            Self::V10 => PRODUCTION_PATH_ROLE_COUNT_V10,
        }
    }

    const fn extra_binding_line_count(self) -> usize {
        match self {
            Self::V1 | Self::V2 | Self::V3 | Self::V4 => 0,
            Self::V5 => 2,
            Self::V6 => 15,
            Self::V7 => 30,
            // V7's thirty public binding lines plus the exact F6 bundle digest.
            Self::V8 => 31,
            // V8's thirty-one public binding lines plus the static refund
            // authority generation. The dynamic route fence is never encoded.
            Self::V9 => 32,
            // V9's thirty-two binding lines plus two remote Relay identities
            // and four exact EVM operational-policy values.
            Self::V10 => 38,
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

/// Eleven durable F6 leaves introduced together by the V4 family.
///
/// They remain separate from [`ProductionPathRoleV1`] so the frozen V1–V3
/// role order and discriminants cannot move.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
#[repr(u8)]
pub enum ProductionF6PathRoleV4 {
    SolverStatusStore = 0,
    UpstreamPreF6TimeStore = 1,
    DownstreamPreF6TimeStore = 2,
    UpstreamBindingLog = 3,
    UpstreamReceiptStore = 4,
    UpstreamCandidateBook = 5,
    UpstreamCandidateAttestation = 6,
    DownstreamBindingLog = 7,
    DownstreamReceiptStore = 8,
    DownstreamCandidateBook = 9,
    DownstreamCandidateAttestation = 10,
}

impl ProductionF6PathRoleV4 {
    pub const ALL: [Self; PRODUCTION_F6_PATH_ROLE_COUNT_V4] = [
        Self::SolverStatusStore,
        Self::UpstreamPreF6TimeStore,
        Self::DownstreamPreF6TimeStore,
        Self::UpstreamBindingLog,
        Self::UpstreamReceiptStore,
        Self::UpstreamCandidateBook,
        Self::UpstreamCandidateAttestation,
        Self::DownstreamBindingLog,
        Self::DownstreamReceiptStore,
        Self::DownstreamCandidateBook,
        Self::DownstreamCandidateAttestation,
    ];

    pub const fn key(self) -> &'static str {
        match self {
            Self::SolverStatusStore => "path_solver_status_store",
            Self::UpstreamPreF6TimeStore => "path_upstream_pre_f6_time_store",
            Self::DownstreamPreF6TimeStore => "path_downstream_pre_f6_time_store",
            Self::UpstreamBindingLog => "path_upstream_f6_binding_log",
            Self::UpstreamReceiptStore => "path_upstream_f6_receipt_store",
            Self::UpstreamCandidateBook => "path_upstream_f6_candidate_book",
            Self::UpstreamCandidateAttestation => "path_upstream_f6_candidate_attestation",
            Self::DownstreamBindingLog => "path_downstream_f6_binding_log",
            Self::DownstreamReceiptStore => "path_downstream_f6_receipt_store",
            Self::DownstreamCandidateBook => "path_downstream_f6_candidate_book",
            Self::DownstreamCandidateAttestation => "path_downstream_f6_candidate_attestation",
        }
    }

    const fn index(self) -> usize {
        self as usize
    }

    /// V8 retains only the six route/RFQ journals from the V4 graph. Solver
    /// status, pre-F6 time, and candidate attestation each have distinct V8
    /// physical owners and must not coexist with their superseded V4 files.
    const fn retained_by_v8(self) -> bool {
        matches!(
            self,
            Self::UpstreamBindingLog
                | Self::UpstreamReceiptStore
                | Self::UpstreamCandidateBook
                | Self::DownstreamBindingLog
                | Self::DownstreamReceiptStore
                | Self::DownstreamCandidateBook
        )
    }
}

/// Exact RFQ-late F6 V7 inputs introduced by V8 and retained by V9.
///
/// The first six roles are independent managed stores. The seventh is one
/// immutable, threshold-authenticated public bundle; the HSM socket endpoints
/// and their expected owner UIDs live only inside that signed bundle.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
#[repr(u8)]
pub enum ProductionF6PathRoleV8 {
    UpstreamStatusStore = 0,
    DownstreamStatusStore = 1,
    UpstreamTimeStore = 2,
    DownstreamTimeStore = 3,
    UpstreamCandidateStore = 4,
    DownstreamCandidateStore = 5,
    AuthorityBundleV7 = 6,
}

impl ProductionF6PathRoleV8 {
    pub const ALL: [Self; PRODUCTION_F6_PATH_ROLE_COUNT_V8] = [
        Self::UpstreamStatusStore,
        Self::DownstreamStatusStore,
        Self::UpstreamTimeStore,
        Self::DownstreamTimeStore,
        Self::UpstreamCandidateStore,
        Self::DownstreamCandidateStore,
        Self::AuthorityBundleV7,
    ];

    pub const fn key(self) -> &'static str {
        match self {
            Self::UpstreamStatusStore => "path_upstream_f6_v7_status_store",
            Self::DownstreamStatusStore => "path_downstream_f6_v7_status_store",
            Self::UpstreamTimeStore => "path_upstream_f6_v7_time_store",
            Self::DownstreamTimeStore => "path_downstream_f6_v7_time_store",
            Self::UpstreamCandidateStore => "path_upstream_f6_v7_candidate_store",
            Self::DownstreamCandidateStore => "path_downstream_f6_v7_candidate_store",
            Self::AuthorityBundleV7 => "path_f6_authority_bundle_v7",
        }
    }

    pub const fn kind(self) -> ProductionPathKindV1 {
        match self {
            Self::UpstreamStatusStore
            | Self::DownstreamStatusStore
            | Self::UpstreamTimeStore
            | Self::DownstreamTimeStore
            | Self::UpstreamCandidateStore
            | Self::DownstreamCandidateStore => ProductionPathKindV1::ManagedFile,
            Self::AuthorityBundleV7 => ProductionPathKindV1::InputFile,
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

/// Canonical ordered references for the eleven V4 F6 authorities.
#[derive(Clone, Eq, PartialEq)]
pub struct ProductionF6PathReferencesV4 {
    paths: [String; PRODUCTION_F6_PATH_ROLE_COUNT_V4],
}

impl core::fmt::Debug for ProductionF6PathReferencesV4 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("ProductionF6PathReferencesV4([redacted])")
    }
}

impl ProductionF6PathReferencesV4 {
    /// Validates one exact ordered reference for every V4 F6 role.
    pub fn from_ordered(
        paths: [String; PRODUCTION_F6_PATH_ROLE_COUNT_V4],
    ) -> Result<Self, ProductionConfigErrorV1> {
        validate_path_set(paths.as_slice())?;
        Ok(Self { paths })
    }

    /// Relative path for one exact F6 authority role.
    pub fn get(&self, role: ProductionF6PathRoleV4) -> &Path {
        Path::new(&self.paths[role.index()])
    }
}

/// Canonical ordered references for the strict F6 V7 authority graph.
#[derive(Clone, Eq, PartialEq)]
pub struct ProductionF6PathReferencesV8 {
    paths: [String; PRODUCTION_F6_PATH_ROLE_COUNT_V8],
}

impl core::fmt::Debug for ProductionF6PathReferencesV8 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("ProductionF6PathReferencesV8([redacted])")
    }
}

impl ProductionF6PathReferencesV8 {
    /// Validates the six physical stores and immutable bundle as one set.
    pub fn from_ordered(
        paths: [String; PRODUCTION_F6_PATH_ROLE_COUNT_V8],
    ) -> Result<Self, ProductionConfigErrorV1> {
        validate_path_set(paths.as_slice())?;
        Ok(Self { paths })
    }

    /// Relative path for one strict F6 V7 authority role.
    pub fn get(&self, role: ProductionF6PathRoleV8) -> &Path {
        Path::new(&self.paths[role.index()])
    }
}

/// Exact semantic commitments of the two-stage Contracts bootstrap artifact.
///
/// These pins are V5-only so adding them cannot change a V1–V4 manifest. The
/// commit stage is pinned independently from the reveal stage even though the
/// latter binds the former; this keeps pre-reveal authorization explicit at
/// the production configuration boundary.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct ProductionContractsBootstrapPinsV5 {
    commit_stage_digest: [u8; 32],
    reveal_stage_digest: [u8; 32],
}

impl core::fmt::Debug for ProductionContractsBootstrapPinsV5 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("ProductionContractsBootstrapPinsV5([redacted])")
    }
}

impl ProductionContractsBootstrapPinsV5 {
    /// Constructs two nonzero, distinct stage commitments.
    pub fn new(
        commit_stage_digest: [u8; 32],
        reveal_stage_digest: [u8; 32],
    ) -> Result<Self, ProductionConfigErrorV1> {
        if commit_stage_digest == ZERO_DIGEST
            || reveal_stage_digest == ZERO_DIGEST
            || commit_stage_digest == reveal_stage_digest
        {
            return Err(ProductionConfigErrorV1::InvalidPublicBinding);
        }
        Ok(Self {
            commit_stage_digest,
            reveal_stage_digest,
        })
    }

    /// Semantic digest of the signed pre-reveal commitment stage.
    pub const fn commit_stage_digest(self) -> [u8; 32] {
        self.commit_stage_digest
    }

    /// Semantic digest of the signed reveal stage that binds the commit.
    pub const fn reveal_stage_digest(self) -> [u8; 32] {
        self.reveal_stage_digest
    }

    fn validate_against_route_pins(
        self,
        route_pins: ProductionRoutePinsV1,
    ) -> Result<Self, ProductionConfigErrorV1> {
        let route_digests = route_pin_digests(route_pins);
        if route_digests.contains(&self.commit_stage_digest)
            || route_digests.contains(&self.reveal_stage_digest)
        {
            return Err(ProductionConfigErrorV1::InvalidPublicBinding);
        }
        Ok(self)
    }
}

/// Stable identities and hard retention bounds for the seven live Relay
/// authorities opened by the V6 composition root.
///
/// The fields are public provisioning facts, like [`ProductionRoutePinsV1`].
/// They do not authenticate retained state by themselves: each owning Relay
/// store still rechecks the same identity and quota when it opens.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct ProductionRelayAuthorityPinsV6 {
    /// Stable identity persisted by the production Relay database.
    pub relay_database_id: [u8; 32],
    /// Stable upstream outbound sender-store identity.
    pub upstream_sender_store_id: [u8; 32],
    /// Stable upstream durable inbox identity.
    pub upstream_inbox_id: [u8; 32],
    /// Stable upstream frame-reassembler identity.
    pub upstream_reassembler_id: [u8; 32],
    /// Stable downstream outbound sender-store identity.
    pub downstream_sender_store_id: [u8; 32],
    /// Stable downstream durable inbox identity.
    pub downstream_inbox_id: [u8; 32],
    /// Stable downstream frame-reassembler identity.
    pub downstream_reassembler_id: [u8; 32],
    /// Maximum envelopes retained by the central Relay database.
    pub relay_max_envelopes: u32,
    /// Maximum completed envelopes retained by each sender store.
    pub sender_max_envelopes: u32,
    /// Maximum accepted entries retained by each inbox.
    pub inbox_max_entries: u32,
    /// Maximum message identities retained by each reassembler.
    pub frame_max_messages: u16,
    /// Maximum bytes reserved by active framed messages per reassembler.
    pub frame_max_active_bytes: u64,
    /// Maximum chunks retained across active messages per reassembler.
    pub frame_max_active_chunks: u32,
}

impl core::fmt::Debug for ProductionRelayAuthorityPinsV6 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("ProductionRelayAuthorityPinsV6([redacted])")
    }
}

impl ProductionRelayAuthorityPinsV6 {
    fn authority_ids(self) -> [[u8; 32]; 7] {
        [
            self.relay_database_id,
            self.upstream_sender_store_id,
            self.upstream_inbox_id,
            self.upstream_reassembler_id,
            self.downstream_sender_store_id,
            self.downstream_inbox_id,
            self.downstream_reassembler_id,
        ]
    }

    fn validate_against_prior_pins(
        self,
        route_pins: ProductionRoutePinsV1,
        contracts_pins: ProductionContractsBootstrapPinsV5,
    ) -> Result<Self, ProductionConfigErrorV1> {
        let mut distinct = BTreeSet::new();
        let prior = route_pin_digests(route_pins);
        for id in self.authority_ids() {
            if id == ZERO_DIGEST
                || prior.contains(&id)
                || id == contracts_pins.commit_stage_digest()
                || id == contracts_pins.reveal_stage_digest()
                || !distinct.insert(id)
            {
                return Err(ProductionConfigErrorV1::InvalidPublicBinding);
            }
        }
        if !(1..=65_536).contains(&self.relay_max_envelopes)
            || !(1..=65_536).contains(&self.sender_max_envelopes)
            || !(1..=65_536).contains(&self.inbox_max_entries)
            || !(1..=256).contains(&self.frame_max_messages)
            || !(16_385..=67_108_864).contains(&self.frame_max_active_bytes)
            || !(1..=8_448).contains(&self.frame_max_active_chunks)
        {
            return Err(ProductionConfigErrorV1::InvalidRuntimeBounds);
        }
        Ok(self)
    }
}

/// Complete set of references and stage pins added by the V5 family.
///
/// Grouping the fields makes half-configured V5 values unrepresentable and
/// keeps the public constructor narrow without suppressing lint policy.
#[derive(Clone, Eq, PartialEq)]
pub struct ProductionFamilyInputsV5 {
    identity_store: String,
    budget_policy: String,
    f6: ProductionF6PathReferencesV4,
    contracts_bootstrap: String,
    contracts_bootstrap_pins: ProductionContractsBootstrapPinsV5,
}

impl core::fmt::Debug for ProductionFamilyInputsV5 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("ProductionFamilyInputsV5([redacted])")
    }
}

impl ProductionFamilyInputsV5 {
    /// Groups the complete V5-only input surface for validation against the
    /// base route paths and pins in [`ProductionBootstrapConfigV1::from_parts_v5`].
    pub fn new(
        contracts_transport_identity_store: String,
        contracts_budget_policy: String,
        f6: ProductionF6PathReferencesV4,
        contracts_bootstrap: String,
        contracts_bootstrap_pins: ProductionContractsBootstrapPinsV5,
    ) -> Self {
        Self {
            identity_store: contracts_transport_identity_store,
            budget_policy: contracts_budget_policy,
            f6,
            contracts_bootstrap,
            contracts_bootstrap_pins,
        }
    }
}

/// Complete V6 input surface: the byte-exact V5 family plus real Relay store
/// identities and quotas. Keeping this grouped makes partial V6 values
/// unrepresentable without widening the already-shipped V5 constructor.
#[derive(Clone, Eq, PartialEq)]
pub struct ProductionFamilyInputsV6 {
    v5: ProductionFamilyInputsV5,
    relay_authority_pins: ProductionRelayAuthorityPinsV6,
}

impl core::fmt::Debug for ProductionFamilyInputsV6 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("ProductionFamilyInputsV6([redacted])")
    }
}

impl ProductionFamilyInputsV6 {
    /// Extends one complete V5 input set with all Relay identities and quotas.
    pub fn new(
        v5: ProductionFamilyInputsV5,
        relay_authority_pins: ProductionRelayAuthorityPinsV6,
    ) -> Self {
        Self {
            v5,
            relay_authority_pins,
        }
    }
}

/// Exact public facts of the pre-existing Bitcoin funding/refund authority.
///
/// The V7 daemon does not create this authority.  A pre-bootstrap producer
/// obtains real wallet inputs, arms the exact CSV refund, and publishes its
/// receipt first; these pins then make a different route, session, deployment,
/// Taproot contract or receipt unacceptable at composition time.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct ProductionBitcoinPrebroadcastPinsV7 {
    /// Route position occupied by Bitcoin.
    pub leg: LegIdV1,
    /// Exact composed settlement identity.
    pub settlement_id: [u8; 32],
    /// Exact Bitcoin signing-session identity.
    pub session_id: [u8; 32],
    /// Canonical settlement terms digest for `leg`.
    pub terms_digest: [u8; 32],
    /// Digest of the complete resolved registry deployment capability.
    pub deployment_digest: [u8; 32],
    /// Pre-bootstrap route binding accepted by `btc-live`.
    pub route_binding: [u8; 32],
    /// Digest of the exact public prebroadcast plan.
    pub plan_digest: [u8; 32],
    /// Digest of the complete real-wallet fresh-route receipt.
    pub receipt_digest: [u8; 32],
    /// Digest of the exact P2TR contract scriptPubKey.
    pub contract_script_pubkey_digest: [u8; 32],
    /// Digest of the wallet-owned cooperative-claim destination script.
    pub claim_destination_script_pubkey_digest: [u8; 32],
    /// Digest of the wallet-owned CSV-refund destination script.
    pub refund_destination_script_pubkey_digest: [u8; 32],
    /// BIP340 key committed by the CSV refund leaf.
    pub refund_key_xonly: [u8; 32],
    /// Signature-independent funding template commitment.
    pub funding_template_hash: [u8; 32],
    /// Signature-independent cooperative-claim template commitment.
    pub claim_template_hash: [u8; 32],
    /// Signature-independent CSV-refund template commitment.
    pub refund_template_hash: [u8; 32],
}

impl core::fmt::Debug for ProductionBitcoinPrebroadcastPinsV7 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("ProductionBitcoinPrebroadcastPinsV7([redacted])")
    }
}

impl ProductionBitcoinPrebroadcastPinsV7 {
    fn validate_against_route_pins(
        self,
        route: ProductionRoutePinsV1,
    ) -> Result<Self, ProductionConfigErrorV1> {
        let expected_terms = match self.leg {
            LegIdV1::Upstream => route.upstream_terms_digest,
            LegIdV1::Downstream => route.downstream_terms_digest,
        };
        let required = [
            self.settlement_id,
            self.session_id,
            self.terms_digest,
            self.deployment_digest,
            self.route_binding,
            self.plan_digest,
            self.receipt_digest,
            self.contract_script_pubkey_digest,
            self.claim_destination_script_pubkey_digest,
            self.refund_destination_script_pubkey_digest,
            self.refund_key_xonly,
            self.funding_template_hash,
            self.claim_template_hash,
            self.refund_template_hash,
        ];
        let script_digests = [
            self.contract_script_pubkey_digest,
            self.claim_destination_script_pubkey_digest,
            self.refund_destination_script_pubkey_digest,
        ];
        let template_hashes = [
            self.funding_template_hash,
            self.claim_template_hash,
            self.refund_template_hash,
        ];
        if required.contains(&ZERO_DIGEST)
            || self.settlement_id == self.session_id
            || self.terms_digest != expected_terms
            || !all_distinct(script_digests)
            || !all_distinct(template_hashes)
        {
            return Err(ProductionConfigErrorV1::InvalidPublicBinding);
        }
        Ok(self)
    }
}

/// Complete V7 input surface: the exact V6 family plus the sole external
/// Bitcoin prebroadcast root and its authenticated public pins.
#[derive(Clone, Eq, PartialEq)]
pub struct ProductionFamilyInputsV7 {
    v6: ProductionFamilyInputsV6,
    bitcoin_prebroadcast_store: String,
    bitcoin_prebroadcast_pins: ProductionBitcoinPrebroadcastPinsV7,
}

impl core::fmt::Debug for ProductionFamilyInputsV7 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("ProductionFamilyInputsV7([redacted])")
    }
}

impl ProductionFamilyInputsV7 {
    /// Extends one complete V6 input set with already armed Bitcoin custody.
    pub fn new(
        v6: ProductionFamilyInputsV6,
        bitcoin_prebroadcast_store: String,
        bitcoin_prebroadcast_pins: ProductionBitcoinPrebroadcastPinsV7,
    ) -> Self {
        Self {
            v6,
            bitcoin_prebroadcast_store,
            bitcoin_prebroadcast_pins,
        }
    }
}

/// Complete live-run surface: V7 Bitcoin custody plus the strict F6 V7 graph.
///
/// There is deliberately no conversion from V4 F6 references. Production must
/// name two status stores, two time stores and two candidate stores explicitly,
/// and must pin the exact immutable authority-bundle bytes.
#[derive(Clone, Eq, PartialEq)]
pub struct ProductionFamilyInputsV8 {
    v7: ProductionFamilyInputsV7,
    f6: ProductionF6PathReferencesV8,
    f6_authority_bundle_digest: [u8; 32],
}

impl core::fmt::Debug for ProductionFamilyInputsV8 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("ProductionFamilyInputsV8([redacted])")
    }
}

impl ProductionFamilyInputsV8 {
    /// Adds the exact F6 V7 graph to one complete V7 configuration.
    pub fn new(
        v7: ProductionFamilyInputsV7,
        f6: ProductionF6PathReferencesV8,
        f6_authority_bundle_digest: [u8; 32],
    ) -> Self {
        Self {
            v7,
            f6,
            f6_authority_bundle_digest,
        }
    }
}

/// Complete V9 live-run surface with one explicit, static refund-authority
/// generation layered on the byte-frozen V8 authority graph.
///
/// This epoch identifies the provisioned refund authority configuration. It is
/// deliberately not the RouteStore lease fencing epoch, which remains dynamic
/// across restart and takeover.
#[derive(Clone, Eq, PartialEq)]
pub struct ProductionFamilyInputsV9 {
    v8: ProductionFamilyInputsV8,
    refund_arming_authority_epoch: u64,
}

impl core::fmt::Debug for ProductionFamilyInputsV9 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("ProductionFamilyInputsV9([redacted])")
    }
}

impl ProductionFamilyInputsV9 {
    /// Adds the nonzero, deployment-pinned refund authority generation.
    pub fn new(v8: ProductionFamilyInputsV8, refund_arming_authority_epoch: u64) -> Self {
        Self {
            v8,
            refund_arming_authority_epoch,
        }
    }
}

/// Operational identities and EVM policy authenticated by the V10 manifest.
///
/// The remote Relay identities are directional facts, not endpoint-discovered
/// hints. The fee tuple and time windows are exact initial runtime inputs and
/// cannot be synthesized by the composition root.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct ProductionOperationalPoliciesV10 {
    upstream_remote_relay_database_id: [u8; 32],
    downstream_remote_relay_database_id: [u8; 32],
    evm_initial_max_fee_per_gas: u128,
    evm_initial_max_priority_fee_per_gas: u128,
    evm_observation_valid_for_ms: u64,
    evm_remote_custody_lease_duration_ms: u64,
}

impl core::fmt::Debug for ProductionOperationalPoliciesV10 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("ProductionOperationalPoliciesV10([redacted])")
    }
}

impl ProductionOperationalPoliciesV10 {
    /// Constructs the complete V10 policy surface. Cross-authority identity
    /// validation is performed when it is bound to the complete V10
    /// configuration and its inherited authenticated pins.
    pub fn new(
        upstream_remote_relay_database_id: [u8; 32],
        downstream_remote_relay_database_id: [u8; 32],
        evm_initial_max_fee_per_gas: u128,
        evm_initial_max_priority_fee_per_gas: u128,
        evm_observation_valid_for_ms: u64,
        evm_remote_custody_lease_duration_ms: u64,
    ) -> Result<Self, ProductionConfigErrorV1> {
        if upstream_remote_relay_database_id == ZERO_DIGEST
            || downstream_remote_relay_database_id == ZERO_DIGEST
            || upstream_remote_relay_database_id == downstream_remote_relay_database_id
        {
            return Err(ProductionConfigErrorV1::InvalidPublicBinding);
        }
        if evm_initial_max_fee_per_gas == 0
            || evm_initial_max_priority_fee_per_gas == 0
            || evm_initial_max_priority_fee_per_gas > evm_initial_max_fee_per_gas
            || evm_observation_valid_for_ms == 0
            || evm_observation_valid_for_ms > MAX_EVM_OBSERVATION_VALID_FOR_MS_V10
            || evm_remote_custody_lease_duration_ms == 0
            || evm_remote_custody_lease_duration_ms > MAX_EVM_REMOTE_CUSTODY_LEASE_DURATION_MS_V10
        {
            return Err(ProductionConfigErrorV1::InvalidRuntimeBounds);
        }
        Ok(Self {
            upstream_remote_relay_database_id,
            downstream_remote_relay_database_id,
            evm_initial_max_fee_per_gas,
            evm_initial_max_priority_fee_per_gas,
            evm_observation_valid_for_ms,
            evm_remote_custody_lease_duration_ms,
        })
    }

    /// Remote Relay database expected on the upstream link.
    pub const fn upstream_remote_relay_database_id(self) -> [u8; 32] {
        self.upstream_remote_relay_database_id
    }

    /// Remote Relay database expected on the downstream link.
    pub const fn downstream_remote_relay_database_id(self) -> [u8; 32] {
        self.downstream_remote_relay_database_id
    }

    /// Initial maximum EIP-1559 total fee per gas.
    pub const fn evm_initial_max_fee_per_gas(self) -> u128 {
        self.evm_initial_max_fee_per_gas
    }

    /// Initial maximum EIP-1559 priority fee per gas.
    pub const fn evm_initial_max_priority_fee_per_gas(self) -> u128 {
        self.evm_initial_max_priority_fee_per_gas
    }

    /// Validity window supplied to every EVM observation mutation.
    pub const fn evm_observation_valid_for_ms(self) -> u64 {
        self.evm_observation_valid_for_ms
    }

    /// Lease duration supplied to remote EVM action custody.
    pub const fn evm_remote_custody_lease_duration_ms(self) -> u64 {
        self.evm_remote_custody_lease_duration_ms
    }

    /// Constructs the actuator fee value only after binding this exact policy
    /// to the V10 config and an authenticated deployment from the same registry.
    ///
    /// The bootstrap config carries only a registry digest/minimum epoch, not
    /// deployment fee caps. Requiring the resolved capability here is the first
    /// boundary where those caps exist without accepting caller-invented data.
    #[cfg(feature = "production")]
    pub fn evm_fees(
        self,
        config: &ProductionBootstrapConfigV1,
        deployment: &ResolvedEvmDeploymentV1,
    ) -> Result<EvmFeesV1, ProductionConfigErrorV1> {
        if config.operational_policies_v10() != Some(self)
            || deployment.registry_digest() != config.pins.registry_manifest_digest
            || deployment.registry_epoch() < config.pins.registry_minimum_epoch
        {
            return Err(ProductionConfigErrorV1::InvalidPublicBinding);
        }
        let caps = deployment.deployment();
        self.evm_fees_with_caps(caps.max_fee_per_gas, caps.max_priority_fee_per_gas)
    }

    #[cfg(feature = "production")]
    fn evm_fees_with_caps(
        self,
        max_fee_per_gas_cap: u128,
        max_priority_fee_per_gas_cap: u128,
    ) -> Result<EvmFeesV1, ProductionConfigErrorV1> {
        if self.evm_initial_max_fee_per_gas > max_fee_per_gas_cap
            || self.evm_initial_max_priority_fee_per_gas > max_priority_fee_per_gas_cap
        {
            return Err(ProductionConfigErrorV1::InvalidRuntimeBounds);
        }
        EvmFeesV1::new(
            self.evm_initial_max_fee_per_gas,
            self.evm_initial_max_priority_fee_per_gas,
        )
        .map_err(|_| ProductionConfigErrorV1::InvalidRuntimeBounds)
    }

    fn validate_against_existing_pins(
        self,
        route_pins: ProductionRoutePinsV1,
        contracts_pins: ProductionContractsBootstrapPinsV5,
        relay_pins: ProductionRelayAuthorityPinsV6,
        bitcoin_pins: ProductionBitcoinPrebroadcastPinsV7,
        f6_authority_bundle_digest: [u8; 32],
    ) -> Result<Self, ProductionConfigErrorV1> {
        let remote_ids = [
            self.upstream_remote_relay_database_id,
            self.downstream_remote_relay_database_id,
        ];
        let conflicts = |id: &[u8; 32]| {
            route_pin_digests(route_pins).contains(id)
                || [
                    contracts_pins.commit_stage_digest(),
                    contracts_pins.reveal_stage_digest(),
                ]
                .contains(id)
                || relay_pins.authority_ids().contains(id)
                || bitcoin_prebroadcast_pin_digests(bitcoin_pins).contains(id)
                || *id == f6_authority_bundle_digest
        };
        if remote_ids.iter().any(conflicts) {
            return Err(ProductionConfigErrorV1::InvalidPublicBinding);
        }
        Ok(self)
    }
}

/// Complete V10 surface: byte-frozen V9 plus authenticated operational policy.
#[derive(Clone, Eq, PartialEq)]
pub struct ProductionFamilyInputsV10 {
    v9: ProductionFamilyInputsV9,
    operational_policies: ProductionOperationalPoliciesV10,
}

impl core::fmt::Debug for ProductionFamilyInputsV10 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("ProductionFamilyInputsV10([redacted])")
    }
}

impl ProductionFamilyInputsV10 {
    /// Extends one complete V9 input set with all V10 operational policies.
    pub fn new(
        v9: ProductionFamilyInputsV9,
        operational_policies: ProductionOperationalPoliciesV10,
    ) -> Self {
        Self {
            v9,
            operational_policies,
        }
    }
}

fn all_distinct<const N: usize>(values: [[u8; 32]; N]) -> bool {
    let mut set = BTreeSet::new();
    values.into_iter().all(|value| set.insert(value))
}

const fn route_pin_digests(pins: ProductionRoutePinsV1) -> [[u8; 32]; 18] {
    [
        pins.network_id,
        pins.route_id,
        pins.registry_manifest_digest,
        pins.registry_authority_set_digest,
        pins.time_policy_authority_set_digest,
        pins.time_evidence_authority_set_digest,
        pins.upstream_terms_digest,
        pins.downstream_terms_digest,
        pins.route_scope_digest,
        pins.participant_bindings_digest,
        pins.relay_binding_digest,
        pins.time_policy_digest,
        pins.time_evidence_digest,
        pins.process_owner_id,
        pins.coordinator_id,
        pins.coordinator_plan_authority_id,
        pins.actuator_bindings_digest,
        pins.solver_inventory_binding_digest,
    ]
}

const fn bitcoin_prebroadcast_pin_digests(
    pins: ProductionBitcoinPrebroadcastPinsV7,
) -> [[u8; 32]; 14] {
    [
        pins.settlement_id,
        pins.session_id,
        pins.terms_digest,
        pins.deployment_digest,
        pins.route_binding,
        pins.plan_digest,
        pins.receipt_digest,
        pins.contract_script_pubkey_digest,
        pins.claim_destination_script_pubkey_digest,
        pins.refund_destination_script_pubkey_digest,
        pins.refund_key_xonly,
        pins.funding_template_hash,
        pins.claim_template_hash,
        pins.refund_template_hash,
    ]
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
/// it, one variant per family, which is how V2, V3 and V4 were added.
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
    /// V4 makes every durable F6 authority explicit and retains all V3
    /// provisioned authorities.
    V4 {
        identity_store: String,
        budget_policy: String,
        f6: ProductionF6PathReferencesV4,
    },
    /// V5 retains the complete V4 surface and adds exactly one externally
    /// provisioned, two-stage authenticated Contracts bootstrap artifact.
    V5 {
        identity_store: String,
        budget_policy: String,
        f6: ProductionF6PathReferencesV4,
        contracts_bootstrap: String,
        contracts_bootstrap_pins: ProductionContractsBootstrapPinsV5,
    },
    /// V6 retains every V5 input and binds the identities and quotas of all
    /// seven live Relay authorities without adding another physical path.
    V6 {
        identity_store: String,
        budget_policy: String,
        f6: ProductionF6PathReferencesV4,
        contracts_bootstrap: String,
        contracts_bootstrap_pins: ProductionContractsBootstrapPinsV5,
        relay_authority_pins: ProductionRelayAuthorityPinsV6,
    },
    /// V7 retains all V6 facts and adds one already armed, externally
    /// provisioned Bitcoin prebroadcast authority. It is never daemon-created.
    V7 {
        identity_store: String,
        budget_policy: String,
        f6: ProductionF6PathReferencesV4,
        contracts_bootstrap: String,
        contracts_bootstrap_pins: ProductionContractsBootstrapPinsV5,
        relay_authority_pins: ProductionRelayAuthorityPinsV6,
        bitcoin_prebroadcast_store: String,
        bitcoin_prebroadcast_pins: ProductionBitcoinPrebroadcastPinsV7,
    },
    /// V8 retains all V7 authorities and adds the non-adaptable F6 V7 graph.
    V8 {
        identity_store: String,
        budget_policy: String,
        f6_v4: ProductionF6PathReferencesV4,
        contracts_bootstrap: String,
        contracts_bootstrap_pins: ProductionContractsBootstrapPinsV5,
        relay_authority_pins: ProductionRelayAuthorityPinsV6,
        bitcoin_prebroadcast_store: String,
        bitcoin_prebroadcast_pins: ProductionBitcoinPrebroadcastPinsV7,
        f6_v8: ProductionF6PathReferencesV8,
        f6_authority_bundle_digest: [u8; 32],
    },
    /// V9 retains V8 byte semantics and adds the static refund authority
    /// generation required to reconstruct both DOM faces after restart.
    V9 {
        identity_store: String,
        budget_policy: String,
        f6_v4: ProductionF6PathReferencesV4,
        contracts_bootstrap: String,
        contracts_bootstrap_pins: ProductionContractsBootstrapPinsV5,
        relay_authority_pins: ProductionRelayAuthorityPinsV6,
        bitcoin_prebroadcast_store: String,
        bitcoin_prebroadcast_pins: ProductionBitcoinPrebroadcastPinsV7,
        f6_v8: ProductionF6PathReferencesV8,
        f6_authority_bundle_digest: [u8; 32],
        refund_arming_authority_epoch: u64,
    },
    /// V10 retains the byte-frozen V9 graph and authenticates both remote
    /// Relay database identities plus the exact initial EVM policy.
    V10 {
        identity_store: String,
        budget_policy: String,
        f6_v4: ProductionF6PathReferencesV4,
        contracts_bootstrap: String,
        contracts_bootstrap_pins: ProductionContractsBootstrapPinsV5,
        relay_authority_pins: ProductionRelayAuthorityPinsV6,
        bitcoin_prebroadcast_store: String,
        bitcoin_prebroadcast_pins: ProductionBitcoinPrebroadcastPinsV7,
        f6_v8: ProductionF6PathReferencesV8,
        f6_authority_bundle_digest: [u8; 32],
        refund_arming_authority_epoch: u64,
        operational_policies: ProductionOperationalPoliciesV10,
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

    /// Builds a V4 configuration with all eleven F6 leaves explicitly named.
    pub fn from_parts_v4(
        mode: ProductionBootstrapModeV1,
        pins: ProductionRoutePinsV1,
        bounds: ProductionRuntimeBoundsV1,
        paths: ProductionPathReferencesV1,
        contracts_transport_identity_store: String,
        contracts_budget_policy: String,
        f6: ProductionF6PathReferencesV4,
    ) -> Result<Self, ProductionConfigErrorV1> {
        let mut extended = Vec::with_capacity(PRODUCTION_PATH_ROLE_COUNT_V4);
        extended.extend_from_slice(&paths.paths);
        extended.push(contracts_transport_identity_store.clone());
        extended.push(contracts_budget_policy.clone());
        extended.extend_from_slice(&f6.paths);
        validate_path_set(&extended)?;
        Ok(Self {
            mode,
            pins: pins.validate()?,
            bounds: bounds.validate()?,
            paths,
            extras: ProductionFamilyExtrasV1::V4 {
                identity_store: contracts_transport_identity_store,
                budget_policy: contracts_budget_policy,
                f6,
            },
        })
    }

    /// Builds a V5 configuration with one exact Contracts bootstrap artifact
    /// and independent semantic pins for its commit and reveal stages.
    pub fn from_parts_v5(
        mode: ProductionBootstrapModeV1,
        pins: ProductionRoutePinsV1,
        bounds: ProductionRuntimeBoundsV1,
        paths: ProductionPathReferencesV1,
        inputs: ProductionFamilyInputsV5,
    ) -> Result<Self, ProductionConfigErrorV1> {
        let ProductionFamilyInputsV5 {
            identity_store,
            budget_policy,
            f6,
            contracts_bootstrap,
            contracts_bootstrap_pins,
        } = inputs;
        let pins = pins.validate()?;
        let contracts_bootstrap_pins =
            contracts_bootstrap_pins.validate_against_route_pins(pins)?;
        let mut extended = Vec::with_capacity(PRODUCTION_PATH_ROLE_COUNT_V5);
        extended.extend_from_slice(&paths.paths);
        extended.push(identity_store.clone());
        extended.push(budget_policy.clone());
        extended.extend_from_slice(&f6.paths);
        extended.push(contracts_bootstrap.clone());
        validate_path_set(&extended)?;
        Ok(Self {
            mode,
            pins,
            bounds: bounds.validate()?,
            paths,
            extras: ProductionFamilyExtrasV1::V5 {
                identity_store,
                budget_policy,
                f6,
                contracts_bootstrap,
                contracts_bootstrap_pins,
            },
        })
    }

    /// Builds a V6 configuration over the exact V5 path surface and adds the
    /// seven real Relay authority identities plus their hard quotas.
    pub fn from_parts_v6(
        mode: ProductionBootstrapModeV1,
        pins: ProductionRoutePinsV1,
        bounds: ProductionRuntimeBoundsV1,
        paths: ProductionPathReferencesV1,
        inputs: ProductionFamilyInputsV6,
    ) -> Result<Self, ProductionConfigErrorV1> {
        let ProductionFamilyInputsV6 {
            v5:
                ProductionFamilyInputsV5 {
                    identity_store,
                    budget_policy,
                    f6,
                    contracts_bootstrap,
                    contracts_bootstrap_pins,
                },
            relay_authority_pins,
        } = inputs;
        let pins = pins.validate()?;
        let contracts_bootstrap_pins =
            contracts_bootstrap_pins.validate_against_route_pins(pins)?;
        let relay_authority_pins =
            relay_authority_pins.validate_against_prior_pins(pins, contracts_bootstrap_pins)?;
        let mut extended = Vec::with_capacity(PRODUCTION_PATH_ROLE_COUNT_V6);
        extended.extend_from_slice(&paths.paths);
        extended.push(identity_store.clone());
        extended.push(budget_policy.clone());
        extended.extend_from_slice(&f6.paths);
        extended.push(contracts_bootstrap.clone());
        validate_path_set(&extended)?;
        Ok(Self {
            mode,
            pins,
            bounds: bounds.validate()?,
            paths,
            extras: ProductionFamilyExtrasV1::V6 {
                identity_store,
                budget_policy,
                f6,
                contracts_bootstrap,
                contracts_bootstrap_pins,
                relay_authority_pins,
            },
        })
    }

    /// Builds a V7 configuration that can only consume one externally
    /// provisioned, already refund-armed Bitcoin prebroadcast authority.
    pub fn from_parts_v7(
        mode: ProductionBootstrapModeV1,
        pins: ProductionRoutePinsV1,
        bounds: ProductionRuntimeBoundsV1,
        paths: ProductionPathReferencesV1,
        inputs: ProductionFamilyInputsV7,
    ) -> Result<Self, ProductionConfigErrorV1> {
        let ProductionFamilyInputsV7 {
            v6:
                ProductionFamilyInputsV6 {
                    v5:
                        ProductionFamilyInputsV5 {
                            identity_store,
                            budget_policy,
                            f6,
                            contracts_bootstrap,
                            contracts_bootstrap_pins,
                        },
                    relay_authority_pins,
                },
            bitcoin_prebroadcast_store,
            bitcoin_prebroadcast_pins,
        } = inputs;
        let pins = pins.validate()?;
        let contracts_bootstrap_pins =
            contracts_bootstrap_pins.validate_against_route_pins(pins)?;
        let relay_authority_pins =
            relay_authority_pins.validate_against_prior_pins(pins, contracts_bootstrap_pins)?;
        let bitcoin_prebroadcast_pins =
            bitcoin_prebroadcast_pins.validate_against_route_pins(pins)?;
        let mut extended = Vec::with_capacity(PRODUCTION_PATH_ROLE_COUNT_V7);
        extended.extend_from_slice(&paths.paths);
        extended.push(identity_store.clone());
        extended.push(budget_policy.clone());
        extended.extend_from_slice(&f6.paths);
        extended.push(contracts_bootstrap.clone());
        extended.push(bitcoin_prebroadcast_store.clone());
        validate_path_set(&extended)?;
        Ok(Self {
            mode,
            pins,
            bounds: bounds.validate()?,
            paths,
            extras: ProductionFamilyExtrasV1::V7 {
                identity_store,
                budget_policy,
                f6,
                contracts_bootstrap,
                contracts_bootstrap_pins,
                relay_authority_pins,
                bitcoin_prebroadcast_store,
                bitcoin_prebroadcast_pins,
            },
        })
    }

    /// Builds the strict V8 live-run configuration.
    ///
    /// V8 cannot be built from V4/V6 alone: it requires the complete V7
    /// Bitcoin authority and all seven F6 V7 references as independent paths.
    pub fn from_parts_v8(
        mode: ProductionBootstrapModeV1,
        pins: ProductionRoutePinsV1,
        bounds: ProductionRuntimeBoundsV1,
        paths: ProductionPathReferencesV1,
        inputs: ProductionFamilyInputsV8,
    ) -> Result<Self, ProductionConfigErrorV1> {
        let ProductionFamilyInputsV8 {
            v7:
                ProductionFamilyInputsV7 {
                    v6:
                        ProductionFamilyInputsV6 {
                            v5:
                                ProductionFamilyInputsV5 {
                                    identity_store,
                                    budget_policy,
                                    f6: f6_v4,
                                    contracts_bootstrap,
                                    contracts_bootstrap_pins,
                                },
                            relay_authority_pins,
                        },
                    bitcoin_prebroadcast_store,
                    bitcoin_prebroadcast_pins,
                },
            f6: f6_v8,
            f6_authority_bundle_digest,
        } = inputs;
        let pins = pins.validate()?;
        let contracts_bootstrap_pins =
            contracts_bootstrap_pins.validate_against_route_pins(pins)?;
        let relay_authority_pins =
            relay_authority_pins.validate_against_prior_pins(pins, contracts_bootstrap_pins)?;
        let bitcoin_prebroadcast_pins =
            bitcoin_prebroadcast_pins.validate_against_route_pins(pins)?;
        if f6_authority_bundle_digest == ZERO_DIGEST
            || route_pin_digests(pins).contains(&f6_authority_bundle_digest)
            || bitcoin_prebroadcast_pin_digests(bitcoin_prebroadcast_pins)
                .contains(&f6_authority_bundle_digest)
        {
            return Err(ProductionConfigErrorV1::InvalidPublicBinding);
        }
        let mut extended = Vec::with_capacity(PRODUCTION_PATH_ROLE_COUNT_V8);
        extended.extend_from_slice(&paths.paths);
        extended.push(identity_store.clone());
        extended.push(budget_policy.clone());
        extended.extend_from_slice(&f6_v4.paths);
        extended.push(contracts_bootstrap.clone());
        extended.push(bitcoin_prebroadcast_store.clone());
        extended.extend_from_slice(&f6_v8.paths);
        validate_path_set(&extended)?;
        Ok(Self {
            mode,
            pins,
            bounds: bounds.validate()?,
            paths,
            extras: ProductionFamilyExtrasV1::V8 {
                identity_store,
                budget_policy,
                f6_v4,
                contracts_bootstrap,
                contracts_bootstrap_pins,
                relay_authority_pins,
                bitcoin_prebroadcast_store,
                bitcoin_prebroadcast_pins,
                f6_v8,
                f6_authority_bundle_digest,
            },
        })
    }

    /// Builds the strict V9 live-run configuration.
    ///
    /// V9 retains the complete V8 authority graph and adds one explicit,
    /// nonzero refund-authority generation. The value is immutable bootstrap
    /// state and must not be populated from a live RouteStore lease fence.
    pub fn from_parts_v9(
        mode: ProductionBootstrapModeV1,
        pins: ProductionRoutePinsV1,
        bounds: ProductionRuntimeBoundsV1,
        paths: ProductionPathReferencesV1,
        inputs: ProductionFamilyInputsV9,
    ) -> Result<Self, ProductionConfigErrorV1> {
        let ProductionFamilyInputsV9 {
            v8:
                ProductionFamilyInputsV8 {
                    v7:
                        ProductionFamilyInputsV7 {
                            v6:
                                ProductionFamilyInputsV6 {
                                    v5:
                                        ProductionFamilyInputsV5 {
                                            identity_store,
                                            budget_policy,
                                            f6: f6_v4,
                                            contracts_bootstrap,
                                            contracts_bootstrap_pins,
                                        },
                                    relay_authority_pins,
                                },
                            bitcoin_prebroadcast_store,
                            bitcoin_prebroadcast_pins,
                        },
                    f6: f6_v8,
                    f6_authority_bundle_digest,
                },
            refund_arming_authority_epoch,
        } = inputs;
        let pins = pins.validate()?;
        let contracts_bootstrap_pins =
            contracts_bootstrap_pins.validate_against_route_pins(pins)?;
        let relay_authority_pins =
            relay_authority_pins.validate_against_prior_pins(pins, contracts_bootstrap_pins)?;
        let bitcoin_prebroadcast_pins =
            bitcoin_prebroadcast_pins.validate_against_route_pins(pins)?;
        if refund_arming_authority_epoch == 0
            || f6_authority_bundle_digest == ZERO_DIGEST
            || route_pin_digests(pins).contains(&f6_authority_bundle_digest)
            || bitcoin_prebroadcast_pin_digests(bitcoin_prebroadcast_pins)
                .contains(&f6_authority_bundle_digest)
        {
            return Err(ProductionConfigErrorV1::InvalidPublicBinding);
        }
        let mut extended = Vec::with_capacity(PRODUCTION_PATH_ROLE_COUNT_V9);
        extended.extend_from_slice(&paths.paths);
        extended.push(identity_store.clone());
        extended.push(budget_policy.clone());
        extended.extend_from_slice(&f6_v4.paths);
        extended.push(contracts_bootstrap.clone());
        extended.push(bitcoin_prebroadcast_store.clone());
        extended.extend_from_slice(&f6_v8.paths);
        validate_path_set(&extended)?;
        Ok(Self {
            mode,
            pins,
            bounds: bounds.validate()?,
            paths,
            extras: ProductionFamilyExtrasV1::V9 {
                identity_store,
                budget_policy,
                f6_v4,
                contracts_bootstrap,
                contracts_bootstrap_pins,
                relay_authority_pins,
                bitcoin_prebroadcast_store,
                bitcoin_prebroadcast_pins,
                f6_v8,
                f6_authority_bundle_digest,
                refund_arming_authority_epoch,
            },
        })
    }

    /// Builds the strict V10 configuration by retaining the complete V9 graph
    /// and binding the directional remote Relay identities and EVM policy.
    pub fn from_parts_v10(
        mode: ProductionBootstrapModeV1,
        pins: ProductionRoutePinsV1,
        bounds: ProductionRuntimeBoundsV1,
        paths: ProductionPathReferencesV1,
        inputs: ProductionFamilyInputsV10,
    ) -> Result<Self, ProductionConfigErrorV1> {
        let ProductionFamilyInputsV10 {
            v9,
            operational_policies,
        } = inputs;
        Self::from_parts_v9(mode, pins, bounds, paths, v9)?.promote_v9_to_v10(operational_policies)
    }

    fn promote_v9_to_v10(
        self,
        operational_policies: ProductionOperationalPoliciesV10,
    ) -> Result<Self, ProductionConfigErrorV1> {
        let Self {
            mode,
            pins,
            bounds,
            paths,
            extras,
        } = self;
        let extras = match extras {
            ProductionFamilyExtrasV1::V9 {
                identity_store,
                budget_policy,
                f6_v4,
                contracts_bootstrap,
                contracts_bootstrap_pins,
                relay_authority_pins,
                bitcoin_prebroadcast_store,
                bitcoin_prebroadcast_pins,
                f6_v8,
                f6_authority_bundle_digest,
                refund_arming_authority_epoch,
            } => {
                let operational_policies = operational_policies.validate_against_existing_pins(
                    pins,
                    contracts_bootstrap_pins,
                    relay_authority_pins,
                    bitcoin_prebroadcast_pins,
                    f6_authority_bundle_digest,
                )?;
                ProductionFamilyExtrasV1::V10 {
                    identity_store,
                    budget_policy,
                    f6_v4,
                    contracts_bootstrap,
                    contracts_bootstrap_pins,
                    relay_authority_pins,
                    bitcoin_prebroadcast_store,
                    bitcoin_prebroadcast_pins,
                    f6_v8,
                    f6_authority_bundle_digest,
                    refund_arming_authority_epoch,
                    operational_policies,
                }
            }
            _ => return Err(ProductionConfigErrorV1::InvalidCanonicalEncoding),
        };
        Ok(Self {
            mode,
            pins,
            bounds,
            paths,
            extras,
        })
    }

    fn promote_v8_to_v9(
        self,
        refund_arming_authority_epoch: u64,
    ) -> Result<Self, ProductionConfigErrorV1> {
        if refund_arming_authority_epoch == 0 {
            return Err(ProductionConfigErrorV1::InvalidPublicBinding);
        }
        let Self {
            mode,
            pins,
            bounds,
            paths,
            extras,
        } = self;
        let extras = match extras {
            ProductionFamilyExtrasV1::V8 {
                identity_store,
                budget_policy,
                f6_v4,
                contracts_bootstrap,
                contracts_bootstrap_pins,
                relay_authority_pins,
                bitcoin_prebroadcast_store,
                bitcoin_prebroadcast_pins,
                f6_v8,
                f6_authority_bundle_digest,
            } => ProductionFamilyExtrasV1::V9 {
                identity_store,
                budget_policy,
                f6_v4,
                contracts_bootstrap,
                contracts_bootstrap_pins,
                relay_authority_pins,
                bitcoin_prebroadcast_store,
                bitcoin_prebroadcast_pins,
                f6_v8,
                f6_authority_bundle_digest,
                refund_arming_authority_epoch,
            },
            _ => return Err(ProductionConfigErrorV1::InvalidCanonicalEncoding),
        };
        Ok(Self {
            mode,
            pins,
            bounds,
            paths,
            extras,
        })
    }

    /// Externally provisioned Contracts transport identity authority, present
    /// in every family from V2 onward.
    pub fn contracts_transport_identity_store(&self) -> Option<&Path> {
        match &self.extras {
            ProductionFamilyExtrasV1::None => None,
            ProductionFamilyExtrasV1::V2 { identity_store }
            | ProductionFamilyExtrasV1::V3 { identity_store, .. }
            | ProductionFamilyExtrasV1::V4 { identity_store, .. }
            | ProductionFamilyExtrasV1::V5 { identity_store, .. }
            | ProductionFamilyExtrasV1::V6 { identity_store, .. }
            | ProductionFamilyExtrasV1::V7 { identity_store, .. }
            | ProductionFamilyExtrasV1::V8 { identity_store, .. }
            | ProductionFamilyExtrasV1::V9 { identity_store, .. }
            | ProductionFamilyExtrasV1::V10 { identity_store, .. } => {
                Some(Path::new(identity_store))
            }
        }
    }

    /// Externally provisioned Contracts budget policy artifact, present in
    /// every family from V3 onward.
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
            | ProductionFamilyExtrasV1::V4 { budget_policy, .. }
            | ProductionFamilyExtrasV1::V5 { budget_policy, .. }
            | ProductionFamilyExtrasV1::V6 { budget_policy, .. }
            | ProductionFamilyExtrasV1::V7 { budget_policy, .. }
            | ProductionFamilyExtrasV1::V8 { budget_policy, .. }
            | ProductionFamilyExtrasV1::V9 { budget_policy, .. }
            | ProductionFamilyExtrasV1::V10 { budget_policy, .. } => Some(Path::new(budget_policy)),
        }
    }

    /// Explicit F6 references, present in V4 and every later family.
    pub const fn f6_paths_v4(&self) -> Option<&ProductionF6PathReferencesV4> {
        match &self.extras {
            ProductionFamilyExtrasV1::V4 { f6, .. }
            | ProductionFamilyExtrasV1::V5 { f6, .. }
            | ProductionFamilyExtrasV1::V6 { f6, .. }
            | ProductionFamilyExtrasV1::V7 { f6, .. } => Some(f6),
            ProductionFamilyExtrasV1::V8 { f6_v4, .. }
            | ProductionFamilyExtrasV1::V9 { f6_v4, .. }
            | ProductionFamilyExtrasV1::V10 { f6_v4, .. } => Some(f6_v4),
            ProductionFamilyExtrasV1::None
            | ProductionFamilyExtrasV1::V2 { .. }
            | ProductionFamilyExtrasV1::V3 { .. } => None,
        }
    }

    /// Externally provisioned exact Contracts bootstrap artifact from V5 onward.
    pub fn contracts_bootstrap(&self) -> Option<&Path> {
        match &self.extras {
            ProductionFamilyExtrasV1::V5 {
                contracts_bootstrap,
                ..
            }
            | ProductionFamilyExtrasV1::V6 {
                contracts_bootstrap,
                ..
            }
            | ProductionFamilyExtrasV1::V7 {
                contracts_bootstrap,
                ..
            }
            | ProductionFamilyExtrasV1::V8 {
                contracts_bootstrap,
                ..
            }
            | ProductionFamilyExtrasV1::V9 {
                contracts_bootstrap,
                ..
            }
            | ProductionFamilyExtrasV1::V10 {
                contracts_bootstrap,
                ..
            } => Some(Path::new(contracts_bootstrap)),
            ProductionFamilyExtrasV1::None
            | ProductionFamilyExtrasV1::V2 { .. }
            | ProductionFamilyExtrasV1::V3 { .. }
            | ProductionFamilyExtrasV1::V4 { .. } => None,
        }
    }

    /// Semantic commit/reveal pins introduced in V5 and inherited thereafter.
    pub const fn contracts_bootstrap_pins_v5(&self) -> Option<ProductionContractsBootstrapPinsV5> {
        match &self.extras {
            ProductionFamilyExtrasV1::V5 {
                contracts_bootstrap_pins,
                ..
            }
            | ProductionFamilyExtrasV1::V6 {
                contracts_bootstrap_pins,
                ..
            }
            | ProductionFamilyExtrasV1::V7 {
                contracts_bootstrap_pins,
                ..
            }
            | ProductionFamilyExtrasV1::V8 {
                contracts_bootstrap_pins,
                ..
            }
            | ProductionFamilyExtrasV1::V9 {
                contracts_bootstrap_pins,
                ..
            }
            | ProductionFamilyExtrasV1::V10 {
                contracts_bootstrap_pins,
                ..
            } => Some(*contracts_bootstrap_pins),
            ProductionFamilyExtrasV1::None
            | ProductionFamilyExtrasV1::V2 { .. }
            | ProductionFamilyExtrasV1::V3 { .. }
            | ProductionFamilyExtrasV1::V4 { .. } => None,
        }
    }

    /// Real Relay identities and quotas introduced in V6 and inherited thereafter.
    pub const fn relay_authority_pins_v6(&self) -> Option<ProductionRelayAuthorityPinsV6> {
        match &self.extras {
            ProductionFamilyExtrasV1::V6 {
                relay_authority_pins,
                ..
            }
            | ProductionFamilyExtrasV1::V7 {
                relay_authority_pins,
                ..
            }
            | ProductionFamilyExtrasV1::V8 {
                relay_authority_pins,
                ..
            }
            | ProductionFamilyExtrasV1::V9 {
                relay_authority_pins,
                ..
            }
            | ProductionFamilyExtrasV1::V10 {
                relay_authority_pins,
                ..
            } => Some(*relay_authority_pins),
            ProductionFamilyExtrasV1::None
            | ProductionFamilyExtrasV1::V2 { .. }
            | ProductionFamilyExtrasV1::V3 { .. }
            | ProductionFamilyExtrasV1::V4 { .. }
            | ProductionFamilyExtrasV1::V5 { .. } => None,
        }
    }

    /// Externally provisioned Bitcoin prebroadcast authority from V7 onward.
    pub fn bitcoin_prebroadcast_store_v7(&self) -> Option<&Path> {
        match &self.extras {
            ProductionFamilyExtrasV1::V7 {
                bitcoin_prebroadcast_store,
                ..
            }
            | ProductionFamilyExtrasV1::V8 {
                bitcoin_prebroadcast_store,
                ..
            }
            | ProductionFamilyExtrasV1::V9 {
                bitcoin_prebroadcast_store,
                ..
            }
            | ProductionFamilyExtrasV1::V10 {
                bitcoin_prebroadcast_store,
                ..
            } => Some(Path::new(bitcoin_prebroadcast_store)),
            ProductionFamilyExtrasV1::None
            | ProductionFamilyExtrasV1::V2 { .. }
            | ProductionFamilyExtrasV1::V3 { .. }
            | ProductionFamilyExtrasV1::V4 { .. }
            | ProductionFamilyExtrasV1::V5 { .. }
            | ProductionFamilyExtrasV1::V6 { .. } => None,
        }
    }

    /// Exact route/session/deployment/Taproot/receipt pins for V7 Bitcoin custody.
    pub const fn bitcoin_prebroadcast_pins_v7(
        &self,
    ) -> Option<ProductionBitcoinPrebroadcastPinsV7> {
        match &self.extras {
            ProductionFamilyExtrasV1::V7 {
                bitcoin_prebroadcast_pins,
                ..
            }
            | ProductionFamilyExtrasV1::V8 {
                bitcoin_prebroadcast_pins,
                ..
            }
            | ProductionFamilyExtrasV1::V9 {
                bitcoin_prebroadcast_pins,
                ..
            }
            | ProductionFamilyExtrasV1::V10 {
                bitcoin_prebroadcast_pins,
                ..
            } => Some(*bitcoin_prebroadcast_pins),
            ProductionFamilyExtrasV1::None
            | ProductionFamilyExtrasV1::V2 { .. }
            | ProductionFamilyExtrasV1::V3 { .. }
            | ProductionFamilyExtrasV1::V4 { .. }
            | ProductionFamilyExtrasV1::V5 { .. }
            | ProductionFamilyExtrasV1::V6 { .. } => None,
        }
    }

    /// Strict F6 V7 paths, present in V8 and inherited by V9 and V10.
    pub const fn f6_paths_v8(&self) -> Option<&ProductionF6PathReferencesV8> {
        match &self.extras {
            ProductionFamilyExtrasV1::V8 { f6_v8, .. }
            | ProductionFamilyExtrasV1::V9 { f6_v8, .. }
            | ProductionFamilyExtrasV1::V10 { f6_v8, .. } => Some(f6_v8),
            ProductionFamilyExtrasV1::None
            | ProductionFamilyExtrasV1::V2 { .. }
            | ProductionFamilyExtrasV1::V3 { .. }
            | ProductionFamilyExtrasV1::V4 { .. }
            | ProductionFamilyExtrasV1::V5 { .. }
            | ProductionFamilyExtrasV1::V6 { .. }
            | ProductionFamilyExtrasV1::V7 { .. } => None,
        }
    }

    /// Domain-separated digest of the exact threshold-authenticated V7 bundle.
    pub const fn f6_authority_bundle_digest_v8(&self) -> Option<[u8; 32]> {
        match &self.extras {
            ProductionFamilyExtrasV1::V8 {
                f6_authority_bundle_digest,
                ..
            }
            | ProductionFamilyExtrasV1::V9 {
                f6_authority_bundle_digest,
                ..
            }
            | ProductionFamilyExtrasV1::V10 {
                f6_authority_bundle_digest,
                ..
            } => Some(*f6_authority_bundle_digest),
            ProductionFamilyExtrasV1::None
            | ProductionFamilyExtrasV1::V2 { .. }
            | ProductionFamilyExtrasV1::V3 { .. }
            | ProductionFamilyExtrasV1::V4 { .. }
            | ProductionFamilyExtrasV1::V5 { .. }
            | ProductionFamilyExtrasV1::V6 { .. }
            | ProductionFamilyExtrasV1::V7 { .. } => None,
        }
    }

    /// Static refund-authority generation. V9 introduces it and V10 retains it.
    /// It is not a RouteStore lease fencing epoch.
    pub const fn refund_arming_authority_epoch_v9(&self) -> Option<u64> {
        match &self.extras {
            ProductionFamilyExtrasV1::V9 {
                refund_arming_authority_epoch,
                ..
            }
            | ProductionFamilyExtrasV1::V10 {
                refund_arming_authority_epoch,
                ..
            } => Some(*refund_arming_authority_epoch),
            ProductionFamilyExtrasV1::None
            | ProductionFamilyExtrasV1::V2 { .. }
            | ProductionFamilyExtrasV1::V3 { .. }
            | ProductionFamilyExtrasV1::V4 { .. }
            | ProductionFamilyExtrasV1::V5 { .. }
            | ProductionFamilyExtrasV1::V6 { .. }
            | ProductionFamilyExtrasV1::V7 { .. }
            | ProductionFamilyExtrasV1::V8 { .. } => None,
        }
    }

    /// Directional Relay identities and exact EVM policy introduced in V10.
    pub const fn operational_policies_v10(&self) -> Option<ProductionOperationalPoliciesV10> {
        match &self.extras {
            ProductionFamilyExtrasV1::V10 {
                operational_policies,
                ..
            } => Some(*operational_policies),
            ProductionFamilyExtrasV1::None
            | ProductionFamilyExtrasV1::V2 { .. }
            | ProductionFamilyExtrasV1::V3 { .. }
            | ProductionFamilyExtrasV1::V4 { .. }
            | ProductionFamilyExtrasV1::V5 { .. }
            | ProductionFamilyExtrasV1::V6 { .. }
            | ProductionFamilyExtrasV1::V7 { .. }
            | ProductionFamilyExtrasV1::V8 { .. }
            | ProductionFamilyExtrasV1::V9 { .. } => None,
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
            ProductionFamilyExtrasV1::V5 { .. } => ProductionBootstrapFamilyV1::V5,
            ProductionFamilyExtrasV1::V6 { .. } => ProductionBootstrapFamilyV1::V6,
            ProductionFamilyExtrasV1::V7 { .. } => ProductionBootstrapFamilyV1::V7,
            ProductionFamilyExtrasV1::V8 { .. } => ProductionBootstrapFamilyV1::V8,
            ProductionFamilyExtrasV1::V9 { .. } => ProductionBootstrapFamilyV1::V9,
            ProductionFamilyExtrasV1::V10 { .. } => ProductionBootstrapFamilyV1::V10,
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

    /// Decodes only the exact canonical V4 bytes for the requested mode.
    pub fn decode_canonical_v4_for_mode(
        bytes: &[u8],
        expected_mode: ProductionBootstrapModeV1,
    ) -> Result<Self, ProductionConfigErrorV1> {
        decode_config(bytes, expected_mode, ProductionBootstrapFamilyV1::V4)
    }

    /// Decodes only the exact canonical V5 bytes for the requested mode.
    pub fn decode_canonical_v5_for_mode(
        bytes: &[u8],
        expected_mode: ProductionBootstrapModeV1,
    ) -> Result<Self, ProductionConfigErrorV1> {
        decode_config(bytes, expected_mode, ProductionBootstrapFamilyV1::V5)
    }

    /// Decodes only the exact canonical V6 bytes for the requested mode.
    pub fn decode_canonical_v6_for_mode(
        bytes: &[u8],
        expected_mode: ProductionBootstrapModeV1,
    ) -> Result<Self, ProductionConfigErrorV1> {
        decode_config(bytes, expected_mode, ProductionBootstrapFamilyV1::V6)
    }

    /// Decodes only the exact canonical V7 bytes for the requested mode.
    pub fn decode_canonical_v7_for_mode(
        bytes: &[u8],
        expected_mode: ProductionBootstrapModeV1,
    ) -> Result<Self, ProductionConfigErrorV1> {
        decode_config(bytes, expected_mode, ProductionBootstrapFamilyV1::V7)
    }

    /// Decodes only the strict V8 live-run document. It never accepts V1–V7.
    pub fn decode_canonical_v8_for_mode(
        bytes: &[u8],
        expected_mode: ProductionBootstrapModeV1,
    ) -> Result<Self, ProductionConfigErrorV1> {
        decode_config(bytes, expected_mode, ProductionBootstrapFamilyV1::V8)
    }

    /// Decodes only the strict V9 live-run document. It never accepts V1–V8.
    pub fn decode_canonical_v9_for_mode(
        bytes: &[u8],
        expected_mode: ProductionBootstrapModeV1,
    ) -> Result<Self, ProductionConfigErrorV1> {
        decode_config(bytes, expected_mode, ProductionBootstrapFamilyV1::V9)
    }

    /// Decodes only the strict V10 operational-policy document.
    pub fn decode_canonical_v10_for_mode(
        bytes: &[u8],
        expected_mode: ProductionBootstrapModeV1,
    ) -> Result<Self, ProductionConfigErrorV1> {
        decode_config(bytes, expected_mode, ProductionBootstrapFamilyV1::V10)
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
            ProductionBootstrapFamilyV1::V5 => {
                body.push_str(HEADER_V5);
                body.push('\n');
            }
            ProductionBootstrapFamilyV1::V6 => {
                body.push_str(HEADER_V6);
                body.push('\n');
            }
            ProductionBootstrapFamilyV1::V7 => {
                body.push_str(HEADER_V7);
                body.push('\n');
            }
            ProductionBootstrapFamilyV1::V8 => {
                body.push_str(HEADER_V8);
                body.push('\n');
            }
            ProductionBootstrapFamilyV1::V9 => {
                body.push_str(HEADER_V9);
                body.push('\n');
            }
            ProductionBootstrapFamilyV1::V10 => {
                body.push_str(HEADER_V10);
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
            ProductionFamilyExtrasV1::V4 {
                identity_store,
                budget_policy,
                f6,
            } => {
                push_reference(&mut body, IDENTITY_STORE_KEY_V2, identity_store);
                push_reference(&mut body, BUDGET_POLICY_KEY_V3, budget_policy);
                for role in ProductionF6PathRoleV4::ALL {
                    push_reference(&mut body, role.key(), &f6.paths[role.index()]);
                }
            }
            ProductionFamilyExtrasV1::V5 {
                identity_store,
                budget_policy,
                f6,
                contracts_bootstrap,
                contracts_bootstrap_pins,
            } => {
                push_reference(&mut body, IDENTITY_STORE_KEY_V2, identity_store);
                push_reference(&mut body, BUDGET_POLICY_KEY_V3, budget_policy);
                for role in ProductionF6PathRoleV4::ALL {
                    push_reference(&mut body, role.key(), &f6.paths[role.index()]);
                }
                push_reference(&mut body, CONTRACTS_BOOTSTRAP_KEY_V5, contracts_bootstrap);
                write_digest(
                    &mut body,
                    CONTRACTS_BOOTSTRAP_COMMIT_DIGEST_KEY_V5,
                    contracts_bootstrap_pins.commit_stage_digest,
                );
                write_digest(
                    &mut body,
                    CONTRACTS_BOOTSTRAP_REVEAL_DIGEST_KEY_V5,
                    contracts_bootstrap_pins.reveal_stage_digest,
                );
            }
            ProductionFamilyExtrasV1::V6 {
                identity_store,
                budget_policy,
                f6,
                contracts_bootstrap,
                contracts_bootstrap_pins,
                relay_authority_pins,
            } => {
                push_reference(&mut body, IDENTITY_STORE_KEY_V2, identity_store);
                push_reference(&mut body, BUDGET_POLICY_KEY_V3, budget_policy);
                for role in ProductionF6PathRoleV4::ALL {
                    push_reference(&mut body, role.key(), &f6.paths[role.index()]);
                }
                push_reference(&mut body, CONTRACTS_BOOTSTRAP_KEY_V5, contracts_bootstrap);
                write_digest(
                    &mut body,
                    CONTRACTS_BOOTSTRAP_COMMIT_DIGEST_KEY_V5,
                    contracts_bootstrap_pins.commit_stage_digest,
                );
                write_digest(
                    &mut body,
                    CONTRACTS_BOOTSTRAP_REVEAL_DIGEST_KEY_V5,
                    contracts_bootstrap_pins.reveal_stage_digest,
                );
                write_digest(
                    &mut body,
                    RELAY_DATABASE_ID_KEY_V6,
                    relay_authority_pins.relay_database_id,
                );
                write_digest(
                    &mut body,
                    UPSTREAM_RELAY_SENDER_ID_KEY_V6,
                    relay_authority_pins.upstream_sender_store_id,
                );
                write_digest(
                    &mut body,
                    UPSTREAM_RELAY_INBOX_ID_KEY_V6,
                    relay_authority_pins.upstream_inbox_id,
                );
                write_digest(
                    &mut body,
                    UPSTREAM_RELAY_FRAME_ID_KEY_V6,
                    relay_authority_pins.upstream_reassembler_id,
                );
                write_digest(
                    &mut body,
                    DOWNSTREAM_RELAY_SENDER_ID_KEY_V6,
                    relay_authority_pins.downstream_sender_store_id,
                );
                write_digest(
                    &mut body,
                    DOWNSTREAM_RELAY_INBOX_ID_KEY_V6,
                    relay_authority_pins.downstream_inbox_id,
                );
                write_digest(
                    &mut body,
                    DOWNSTREAM_RELAY_FRAME_ID_KEY_V6,
                    relay_authority_pins.downstream_reassembler_id,
                );
                write_u64(
                    &mut body,
                    RELAY_MAX_ENVELOPES_KEY_V6,
                    u64::from(relay_authority_pins.relay_max_envelopes),
                );
                write_u64(
                    &mut body,
                    SENDER_MAX_ENVELOPES_KEY_V6,
                    u64::from(relay_authority_pins.sender_max_envelopes),
                );
                write_u64(
                    &mut body,
                    INBOX_MAX_ENTRIES_KEY_V6,
                    u64::from(relay_authority_pins.inbox_max_entries),
                );
                write_u64(
                    &mut body,
                    FRAME_MAX_MESSAGES_KEY_V6,
                    u64::from(relay_authority_pins.frame_max_messages),
                );
                write_u64(
                    &mut body,
                    FRAME_MAX_ACTIVE_BYTES_KEY_V6,
                    relay_authority_pins.frame_max_active_bytes,
                );
                write_u64(
                    &mut body,
                    FRAME_MAX_ACTIVE_CHUNKS_KEY_V6,
                    u64::from(relay_authority_pins.frame_max_active_chunks),
                );
            }
            ProductionFamilyExtrasV1::V7 {
                identity_store,
                budget_policy,
                f6,
                contracts_bootstrap,
                contracts_bootstrap_pins,
                relay_authority_pins,
                bitcoin_prebroadcast_store,
                bitcoin_prebroadcast_pins,
            } => {
                write_v7_family_body(
                    &mut body,
                    ProductionV7BodyPartsV1 {
                        identity_store,
                        budget_policy,
                        f6,
                        contracts_bootstrap,
                        contracts_bootstrap_pins: *contracts_bootstrap_pins,
                        relay_authority_pins: *relay_authority_pins,
                        bitcoin_prebroadcast_store,
                        bitcoin_prebroadcast_pins: *bitcoin_prebroadcast_pins,
                    },
                );
            }
            ProductionFamilyExtrasV1::V8 {
                identity_store,
                budget_policy,
                f6_v4,
                contracts_bootstrap,
                contracts_bootstrap_pins,
                relay_authority_pins,
                bitcoin_prebroadcast_store,
                bitcoin_prebroadcast_pins,
                f6_v8,
                f6_authority_bundle_digest,
            } => {
                write_v7_family_body(
                    &mut body,
                    ProductionV7BodyPartsV1 {
                        identity_store,
                        budget_policy,
                        f6: f6_v4,
                        contracts_bootstrap,
                        contracts_bootstrap_pins: *contracts_bootstrap_pins,
                        relay_authority_pins: *relay_authority_pins,
                        bitcoin_prebroadcast_store,
                        bitcoin_prebroadcast_pins: *bitcoin_prebroadcast_pins,
                    },
                );
                for role in ProductionF6PathRoleV8::ALL {
                    push_reference(&mut body, role.key(), &f6_v8.paths[role.index()]);
                }
                write_digest(
                    &mut body,
                    F6_AUTHORITY_BUNDLE_DIGEST_KEY_V8,
                    *f6_authority_bundle_digest,
                );
            }
            ProductionFamilyExtrasV1::V9 {
                identity_store,
                budget_policy,
                f6_v4,
                contracts_bootstrap,
                contracts_bootstrap_pins,
                relay_authority_pins,
                bitcoin_prebroadcast_store,
                bitcoin_prebroadcast_pins,
                f6_v8,
                f6_authority_bundle_digest,
                refund_arming_authority_epoch,
            } => {
                write_v7_family_body(
                    &mut body,
                    ProductionV7BodyPartsV1 {
                        identity_store,
                        budget_policy,
                        f6: f6_v4,
                        contracts_bootstrap,
                        contracts_bootstrap_pins: *contracts_bootstrap_pins,
                        relay_authority_pins: *relay_authority_pins,
                        bitcoin_prebroadcast_store,
                        bitcoin_prebroadcast_pins: *bitcoin_prebroadcast_pins,
                    },
                );
                for role in ProductionF6PathRoleV8::ALL {
                    push_reference(&mut body, role.key(), &f6_v8.paths[role.index()]);
                }
                write_digest(
                    &mut body,
                    F6_AUTHORITY_BUNDLE_DIGEST_KEY_V8,
                    *f6_authority_bundle_digest,
                );
                write_u64(
                    &mut body,
                    REFUND_ARMING_AUTHORITY_EPOCH_KEY_V9,
                    *refund_arming_authority_epoch,
                );
            }
            ProductionFamilyExtrasV1::V10 {
                identity_store,
                budget_policy,
                f6_v4,
                contracts_bootstrap,
                contracts_bootstrap_pins,
                relay_authority_pins,
                bitcoin_prebroadcast_store,
                bitcoin_prebroadcast_pins,
                f6_v8,
                f6_authority_bundle_digest,
                refund_arming_authority_epoch,
                operational_policies,
            } => {
                write_v7_family_body(
                    &mut body,
                    ProductionV7BodyPartsV1 {
                        identity_store,
                        budget_policy,
                        f6: f6_v4,
                        contracts_bootstrap,
                        contracts_bootstrap_pins: *contracts_bootstrap_pins,
                        relay_authority_pins: *relay_authority_pins,
                        bitcoin_prebroadcast_store,
                        bitcoin_prebroadcast_pins: *bitcoin_prebroadcast_pins,
                    },
                );
                for role in ProductionF6PathRoleV8::ALL {
                    push_reference(&mut body, role.key(), &f6_v8.paths[role.index()]);
                }
                write_digest(
                    &mut body,
                    F6_AUTHORITY_BUNDLE_DIGEST_KEY_V8,
                    *f6_authority_bundle_digest,
                );
                write_u64(
                    &mut body,
                    REFUND_ARMING_AUTHORITY_EPOCH_KEY_V9,
                    *refund_arming_authority_epoch,
                );
                write_digest(
                    &mut body,
                    UPSTREAM_REMOTE_RELAY_DATABASE_ID_KEY_V10,
                    operational_policies.upstream_remote_relay_database_id,
                );
                write_digest(
                    &mut body,
                    DOWNSTREAM_REMOTE_RELAY_DATABASE_ID_KEY_V10,
                    operational_policies.downstream_remote_relay_database_id,
                );
                write_u128(
                    &mut body,
                    EVM_INITIAL_MAX_FEE_PER_GAS_KEY_V10,
                    operational_policies.evm_initial_max_fee_per_gas,
                );
                write_u128(
                    &mut body,
                    EVM_INITIAL_MAX_PRIORITY_FEE_PER_GAS_KEY_V10,
                    operational_policies.evm_initial_max_priority_fee_per_gas,
                );
                write_u64(
                    &mut body,
                    EVM_OBSERVATION_VALID_FOR_MS_KEY_V10,
                    operational_policies.evm_observation_valid_for_ms,
                );
                write_u64(
                    &mut body,
                    EVM_REMOTE_CUSTODY_LEASE_DURATION_MS_KEY_V10,
                    operational_policies.evm_remote_custody_lease_duration_ms,
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

struct ProductionV7BodyPartsV1<'a> {
    identity_store: &'a str,
    budget_policy: &'a str,
    f6: &'a ProductionF6PathReferencesV4,
    contracts_bootstrap: &'a str,
    contracts_bootstrap_pins: ProductionContractsBootstrapPinsV5,
    relay_authority_pins: ProductionRelayAuthorityPinsV6,
    bitcoin_prebroadcast_store: &'a str,
    bitcoin_prebroadcast_pins: ProductionBitcoinPrebroadcastPinsV7,
}

fn write_v7_family_body(body: &mut String, parts: ProductionV7BodyPartsV1<'_>) {
    push_reference(body, IDENTITY_STORE_KEY_V2, parts.identity_store);
    push_reference(body, BUDGET_POLICY_KEY_V3, parts.budget_policy);
    for role in ProductionF6PathRoleV4::ALL {
        push_reference(body, role.key(), &parts.f6.paths[role.index()]);
    }
    push_reference(body, CONTRACTS_BOOTSTRAP_KEY_V5, parts.contracts_bootstrap);
    write_digest(
        body,
        CONTRACTS_BOOTSTRAP_COMMIT_DIGEST_KEY_V5,
        parts.contracts_bootstrap_pins.commit_stage_digest,
    );
    write_digest(
        body,
        CONTRACTS_BOOTSTRAP_REVEAL_DIGEST_KEY_V5,
        parts.contracts_bootstrap_pins.reveal_stage_digest,
    );
    write_digest(
        body,
        RELAY_DATABASE_ID_KEY_V6,
        parts.relay_authority_pins.relay_database_id,
    );
    write_digest(
        body,
        UPSTREAM_RELAY_SENDER_ID_KEY_V6,
        parts.relay_authority_pins.upstream_sender_store_id,
    );
    write_digest(
        body,
        UPSTREAM_RELAY_INBOX_ID_KEY_V6,
        parts.relay_authority_pins.upstream_inbox_id,
    );
    write_digest(
        body,
        UPSTREAM_RELAY_FRAME_ID_KEY_V6,
        parts.relay_authority_pins.upstream_reassembler_id,
    );
    write_digest(
        body,
        DOWNSTREAM_RELAY_SENDER_ID_KEY_V6,
        parts.relay_authority_pins.downstream_sender_store_id,
    );
    write_digest(
        body,
        DOWNSTREAM_RELAY_INBOX_ID_KEY_V6,
        parts.relay_authority_pins.downstream_inbox_id,
    );
    write_digest(
        body,
        DOWNSTREAM_RELAY_FRAME_ID_KEY_V6,
        parts.relay_authority_pins.downstream_reassembler_id,
    );
    write_u64(
        body,
        RELAY_MAX_ENVELOPES_KEY_V6,
        u64::from(parts.relay_authority_pins.relay_max_envelopes),
    );
    write_u64(
        body,
        SENDER_MAX_ENVELOPES_KEY_V6,
        u64::from(parts.relay_authority_pins.sender_max_envelopes),
    );
    write_u64(
        body,
        INBOX_MAX_ENTRIES_KEY_V6,
        u64::from(parts.relay_authority_pins.inbox_max_entries),
    );
    write_u64(
        body,
        FRAME_MAX_MESSAGES_KEY_V6,
        u64::from(parts.relay_authority_pins.frame_max_messages),
    );
    write_u64(
        body,
        FRAME_MAX_ACTIVE_BYTES_KEY_V6,
        parts.relay_authority_pins.frame_max_active_bytes,
    );
    write_u64(
        body,
        FRAME_MAX_ACTIVE_CHUNKS_KEY_V6,
        u64::from(parts.relay_authority_pins.frame_max_active_chunks),
    );
    push_reference(
        body,
        BITCOIN_PREBROADCAST_STORE_KEY_V7,
        parts.bitcoin_prebroadcast_store,
    );
    let leg = match parts.bitcoin_prebroadcast_pins.leg {
        LegIdV1::Upstream => "upstream",
        LegIdV1::Downstream => "downstream",
    };
    push_reference(body, BITCOIN_LEG_KEY_V7, leg);
    write_bitcoin_prebroadcast_pins_v7(body, parts.bitcoin_prebroadcast_pins);
}

fn write_bitcoin_prebroadcast_pins_v7(
    body: &mut String,
    pins: ProductionBitcoinPrebroadcastPinsV7,
) {
    write_digest(body, BITCOIN_SETTLEMENT_ID_KEY_V7, pins.settlement_id);
    write_digest(body, BITCOIN_SESSION_ID_KEY_V7, pins.session_id);
    write_digest(body, BITCOIN_TERMS_DIGEST_KEY_V7, pins.terms_digest);
    write_digest(
        body,
        BITCOIN_DEPLOYMENT_DIGEST_KEY_V7,
        pins.deployment_digest,
    );
    write_digest(body, BITCOIN_ROUTE_BINDING_KEY_V7, pins.route_binding);
    write_digest(body, BITCOIN_PLAN_DIGEST_KEY_V7, pins.plan_digest);
    write_digest(body, BITCOIN_RECEIPT_DIGEST_KEY_V7, pins.receipt_digest);
    write_digest(
        body,
        BITCOIN_CONTRACT_SCRIPT_DIGEST_KEY_V7,
        pins.contract_script_pubkey_digest,
    );
    write_digest(
        body,
        BITCOIN_CLAIM_SCRIPT_DIGEST_KEY_V7,
        pins.claim_destination_script_pubkey_digest,
    );
    write_digest(
        body,
        BITCOIN_REFUND_SCRIPT_DIGEST_KEY_V7,
        pins.refund_destination_script_pubkey_digest,
    );
    write_digest(body, BITCOIN_REFUND_KEY_KEY_V7, pins.refund_key_xonly);
    write_digest(
        body,
        BITCOIN_FUNDING_TEMPLATE_KEY_V7,
        pins.funding_template_hash,
    );
    write_digest(
        body,
        BITCOIN_CLAIM_TEMPLATE_KEY_V7,
        pins.claim_template_hash,
    );
    write_digest(
        body,
        BITCOIN_REFUND_TEMPLATE_KEY_V7,
        pins.refund_template_hash,
    );
}

/// Canonical absolute paths validated under one owner-only state directory.
pub struct ValidatedProductionLayoutV1 {
    state_dir: PathBuf,
    paths: [PathBuf; PRODUCTION_PATH_ROLE_COUNT_V1],
    contracts_transport_identity_store: Option<PathBuf>,
    contracts_budget_policy: Option<PathBuf>,
    f6_paths_v4: Option<[PathBuf; PRODUCTION_F6_PATH_ROLE_COUNT_V4]>,
    contracts_bootstrap: Option<PathBuf>,
    bitcoin_prebroadcast_store_v7: Option<PathBuf>,
    f6_paths_v8: Option<[PathBuf; PRODUCTION_F6_PATH_ROLE_COUNT_V8]>,
    refund_arming_database: Option<PathBuf>,
    solana_actuator_database: Option<PathBuf>,
    xmr_actuator_database: Option<PathBuf>,
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
    /// transport identity authority, present in every layout from V2 onward.
    pub fn contracts_transport_identity_store(&self) -> Option<&Path> {
        self.contracts_transport_identity_store.as_deref()
    }

    /// Absolute path of the externally provisioned Contracts budget policy,
    /// present in every layout from V3 onward.
    pub fn contracts_budget_policy(&self) -> Option<&Path> {
        self.contracts_budget_policy.as_deref()
    }

    /// Canonical absolute path for one V4 F6 authority.
    pub fn f6_path_v4(&self, role: ProductionF6PathRoleV4) -> Option<&Path> {
        self.f6_paths_v4
            .as_ref()
            .map(|paths| paths[role.index()].as_path())
    }

    /// Exact owner-only Contracts bootstrap input, present from V5 onward.
    pub fn contracts_bootstrap(&self) -> Option<&Path> {
        self.contracts_bootstrap.as_deref()
    }

    /// Existing owner-only Bitcoin prebroadcast authority root in V7.
    pub fn bitcoin_prebroadcast_store_v7(&self) -> Option<&Path> {
        self.bitcoin_prebroadcast_store_v7.as_deref()
    }

    /// Canonical absolute path for one strict F6 V7 authority.
    pub fn f6_path_v8(&self, role: ProductionF6PathRoleV8) -> Option<&Path> {
        self.f6_paths_v8
            .as_ref()
            .map(|paths| paths[role.index()].as_path())
    }

    /// Fixed Stage-13 refund journal, present in the live V8/V9/V10 layouts.
    pub fn refund_arming_database(&self) -> Option<&Path> {
        self.refund_arming_database.as_deref()
    }

    /// Fixed Solana actuator store name, pinned in the live layouts.
    pub fn solana_actuator_database(&self) -> Option<&Path> {
        self.solana_actuator_database.as_deref()
    }

    /// Fixed Monero actuator store name, pinned in the live layouts.
    pub fn xmr_actuator_database(&self) -> Option<&Path> {
        self.xmr_actuator_database.as_deref()
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
    /// The externally provisioned, refund-armed Bitcoin custody directory is
    /// missing or physically unsafe. It is never created or repaired here.
    BitcoinPrebroadcastAuthorityUnavailable,
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
            Self::BitcoinPrebroadcastAuthorityUnavailable => {
                "production Bitcoin prebroadcast authority directory unavailable"
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

/// Loads the V4 provisioning manifest and its byte-equivalent recovery
/// companion, including all eleven explicit F6 leaves.
pub fn load_production_create_bootstrap_v4(
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
    let layout = resolve_and_validate_layout(&canonical_state, &create, true)?;
    Ok(ValidatedProductionBootstrapV1 {
        config: create,
        layout,
    })
}

/// Loads the V5 provisioning manifest and its byte-equivalent recovery
/// companion, including the exact externally provisioned Contracts bootstrap.
pub fn load_production_create_bootstrap_v5(
    state_dir: &Path,
) -> Result<ValidatedProductionBootstrapV1, ProductionConfigErrorV1> {
    let canonical_state = validate_state_dir(state_dir)?;
    let create = load_manifest(
        &canonical_state,
        PRODUCTION_CREATE_CONFIG_FILE_V5,
        ProductionBootstrapModeV1::Create,
        ProductionBootstrapFamilyV1::V5,
    )?;
    let reopen = load_manifest(
        &canonical_state,
        PRODUCTION_REOPEN_CONFIG_FILE_V5,
        ProductionBootstrapModeV1::ReopenExisting,
        ProductionBootstrapFamilyV1::V5,
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

/// Loads the V6 provisioning manifest and byte-equivalent recovery companion,
/// including all real Relay authority identities and quotas.
pub fn load_production_create_bootstrap_v6(
    state_dir: &Path,
) -> Result<ValidatedProductionBootstrapV1, ProductionConfigErrorV1> {
    let canonical_state = validate_state_dir(state_dir)?;
    let create = load_manifest(
        &canonical_state,
        PRODUCTION_CREATE_CONFIG_FILE_V6,
        ProductionBootstrapModeV1::Create,
        ProductionBootstrapFamilyV1::V6,
    )?;
    let reopen = load_manifest(
        &canonical_state,
        PRODUCTION_REOPEN_CONFIG_FILE_V6,
        ProductionBootstrapModeV1::ReopenExisting,
        ProductionBootstrapFamilyV1::V6,
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

/// Loads the V7 provisioning manifest and companion, requiring the external
/// Bitcoin prebroadcast authority in both modes without creating it.
pub fn load_production_create_bootstrap_v7(
    state_dir: &Path,
) -> Result<ValidatedProductionBootstrapV1, ProductionConfigErrorV1> {
    let canonical_state = validate_state_dir(state_dir)?;
    let create = load_manifest(
        &canonical_state,
        PRODUCTION_CREATE_CONFIG_FILE_V7,
        ProductionBootstrapModeV1::Create,
        ProductionBootstrapFamilyV1::V7,
    )?;
    let reopen = load_manifest(
        &canonical_state,
        PRODUCTION_REOPEN_CONFIG_FILE_V7,
        ProductionBootstrapModeV1::ReopenExisting,
        ProductionBootstrapFamilyV1::V7,
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

/// Loads only the strict V8 live-run family. It requires the complete V7
/// Bitcoin authority, the immutable F6 bundle and six independent F6 stores.
pub fn load_production_create_bootstrap_v8(
    state_dir: &Path,
) -> Result<ValidatedProductionBootstrapV1, ProductionConfigErrorV1> {
    let canonical_state = validate_state_dir(state_dir)?;
    let create = load_manifest(
        &canonical_state,
        PRODUCTION_CREATE_CONFIG_FILE_V8,
        ProductionBootstrapModeV1::Create,
        ProductionBootstrapFamilyV1::V8,
    )?;
    let reopen = load_manifest(
        &canonical_state,
        PRODUCTION_REOPEN_CONFIG_FILE_V8,
        ProductionBootstrapModeV1::ReopenExisting,
        ProductionBootstrapFamilyV1::V8,
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

/// Loads only the strict V9 live-run family and requires the immutable refund
/// authority generation to agree across create and recovery companions.
pub fn load_production_create_bootstrap_v9(
    state_dir: &Path,
) -> Result<ValidatedProductionBootstrapV1, ProductionConfigErrorV1> {
    let canonical_state = validate_state_dir(state_dir)?;
    let create = load_manifest(
        &canonical_state,
        PRODUCTION_CREATE_CONFIG_FILE_V9,
        ProductionBootstrapModeV1::Create,
        ProductionBootstrapFamilyV1::V9,
    )?;
    let reopen = load_manifest(
        &canonical_state,
        PRODUCTION_REOPEN_CONFIG_FILE_V9,
        ProductionBootstrapModeV1::ReopenExisting,
        ProductionBootstrapFamilyV1::V9,
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

/// Loads only V10 and requires byte-equivalent operational policies in the
/// pre-existing recovery companion.
pub fn load_production_create_bootstrap_v10(
    state_dir: &Path,
) -> Result<ValidatedProductionBootstrapV1, ProductionConfigErrorV1> {
    let canonical_state = validate_state_dir(state_dir)?;
    let create = load_manifest(
        &canonical_state,
        PRODUCTION_CREATE_CONFIG_FILE_V10,
        ProductionBootstrapModeV1::Create,
        ProductionBootstrapFamilyV1::V10,
    )?;
    let reopen = load_manifest(
        &canonical_state,
        PRODUCTION_REOPEN_CONFIG_FILE_V10,
        ProductionBootstrapModeV1::ReopenExisting,
        ProductionBootstrapFamilyV1::V10,
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
#[expect(
    dead_code,
    reason = "superseded bootstrap lineage retained for configuration migration history"
)]
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

#[cfg(feature = "production")]
#[expect(
    dead_code,
    reason = "superseded bootstrap lineage retained for configuration migration history"
)]
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

#[cfg(feature = "production")]
#[expect(
    dead_code,
    reason = "superseded bootstrap lineage retained for configuration migration history"
)]
pub(crate) fn load_production_create_or_resume_bootstrap_v5(
    state_dir: &Path,
) -> Result<ValidatedProductionBootstrapV1, ProductionConfigErrorV1> {
    let canonical_state = validate_state_dir(state_dir)?;
    let create = load_manifest(
        &canonical_state,
        PRODUCTION_CREATE_CONFIG_FILE_V5,
        ProductionBootstrapModeV1::Create,
        ProductionBootstrapFamilyV1::V5,
    )?;
    let reopen = load_manifest(
        &canonical_state,
        PRODUCTION_REOPEN_CONFIG_FILE_V5,
        ProductionBootstrapModeV1::ReopenExisting,
        ProductionBootstrapFamilyV1::V5,
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

#[cfg(feature = "production")]
#[expect(
    dead_code,
    reason = "superseded bootstrap lineage retained for configuration migration history"
)]
pub(crate) fn load_production_create_or_resume_bootstrap_v6(
    state_dir: &Path,
) -> Result<ValidatedProductionBootstrapV1, ProductionConfigErrorV1> {
    let canonical_state = validate_state_dir(state_dir)?;
    let create = load_manifest(
        &canonical_state,
        PRODUCTION_CREATE_CONFIG_FILE_V6,
        ProductionBootstrapModeV1::Create,
        ProductionBootstrapFamilyV1::V6,
    )?;
    let reopen = load_manifest(
        &canonical_state,
        PRODUCTION_REOPEN_CONFIG_FILE_V6,
        ProductionBootstrapModeV1::ReopenExisting,
        ProductionBootstrapFamilyV1::V6,
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

#[cfg(feature = "production")]
#[expect(
    dead_code,
    reason = "superseded bootstrap lineage retained for configuration migration history"
)]
pub(crate) fn load_production_create_or_resume_bootstrap_v7(
    state_dir: &Path,
) -> Result<ValidatedProductionBootstrapV1, ProductionConfigErrorV1> {
    let canonical_state = validate_state_dir(state_dir)?;
    let create = load_manifest(
        &canonical_state,
        PRODUCTION_CREATE_CONFIG_FILE_V7,
        ProductionBootstrapModeV1::Create,
        ProductionBootstrapFamilyV1::V7,
    )?;
    let reopen = load_manifest(
        &canonical_state,
        PRODUCTION_REOPEN_CONFIG_FILE_V7,
        ProductionBootstrapModeV1::ReopenExisting,
        ProductionBootstrapFamilyV1::V7,
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

#[cfg(feature = "production")]
#[expect(
    dead_code,
    reason = "superseded bootstrap lineage retained for configuration migration history"
)]
pub(crate) fn load_production_create_or_resume_bootstrap_v8(
    state_dir: &Path,
) -> Result<ValidatedProductionBootstrapV1, ProductionConfigErrorV1> {
    let canonical_state = validate_state_dir(state_dir)?;
    let create = load_manifest(
        &canonical_state,
        PRODUCTION_CREATE_CONFIG_FILE_V8,
        ProductionBootstrapModeV1::Create,
        ProductionBootstrapFamilyV1::V8,
    )?;
    let reopen = load_manifest(
        &canonical_state,
        PRODUCTION_REOPEN_CONFIG_FILE_V8,
        ProductionBootstrapModeV1::ReopenExisting,
        ProductionBootstrapFamilyV1::V8,
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

#[cfg(feature = "production")]
#[expect(
    dead_code,
    reason = "superseded bootstrap lineage retained for configuration migration history"
)]
pub(crate) fn load_production_create_or_resume_bootstrap_v9(
    state_dir: &Path,
) -> Result<ValidatedProductionBootstrapV1, ProductionConfigErrorV1> {
    let canonical_state = validate_state_dir(state_dir)?;
    let create = load_manifest(
        &canonical_state,
        PRODUCTION_CREATE_CONFIG_FILE_V9,
        ProductionBootstrapModeV1::Create,
        ProductionBootstrapFamilyV1::V9,
    )?;
    let reopen = load_manifest(
        &canonical_state,
        PRODUCTION_REOPEN_CONFIG_FILE_V9,
        ProductionBootstrapModeV1::ReopenExisting,
        ProductionBootstrapFamilyV1::V9,
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

#[cfg(feature = "production")]
pub(crate) fn load_production_create_or_resume_bootstrap_v10(
    state_dir: &Path,
) -> Result<ValidatedProductionBootstrapV1, ProductionConfigErrorV1> {
    let canonical_state = validate_state_dir(state_dir)?;
    let create = load_manifest(
        &canonical_state,
        PRODUCTION_CREATE_CONFIG_FILE_V10,
        ProductionBootstrapModeV1::Create,
        ProductionBootstrapFamilyV1::V10,
    )?;
    let reopen = load_manifest(
        &canonical_state,
        PRODUCTION_REOPEN_CONFIG_FILE_V10,
        ProductionBootstrapModeV1::ReopenExisting,
        ProductionBootstrapFamilyV1::V10,
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

#[cfg(feature = "production")]
#[expect(
    dead_code,
    reason = "superseded bootstrap lineage retained for configuration migration history"
)]
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
#[expect(
    dead_code,
    reason = "superseded bootstrap lineage retained for configuration migration history"
)]
pub(crate) fn provisioning_binding_for_v4_bootstrap(
    bootstrap: &ValidatedProductionBootstrapV1,
) -> Result<[u8; 32], ProductionConfigErrorV1> {
    if bootstrap.config.family() != ProductionBootstrapFamilyV1::V4 {
        return Err(ProductionConfigErrorV1::ProvisioningJournalRefused);
    }
    let (create, reopen) = match bootstrap.config.mode() {
        ProductionBootstrapModeV1::Create => (
            bootstrap.config.clone(),
            load_manifest(
                bootstrap.layout.state_dir(),
                PRODUCTION_REOPEN_CONFIG_FILE_V4,
                ProductionBootstrapModeV1::ReopenExisting,
                ProductionBootstrapFamilyV1::V4,
            )?,
        ),
        ProductionBootstrapModeV1::ReopenExisting => (
            load_manifest(
                bootstrap.layout.state_dir(),
                PRODUCTION_CREATE_CONFIG_FILE_V4,
                ProductionBootstrapModeV1::Create,
                ProductionBootstrapFamilyV1::V4,
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
#[expect(
    dead_code,
    reason = "superseded bootstrap lineage retained for configuration migration history"
)]
pub(crate) fn provisioning_binding_for_v5_bootstrap(
    bootstrap: &ValidatedProductionBootstrapV1,
) -> Result<[u8; 32], ProductionConfigErrorV1> {
    if bootstrap.config.family() != ProductionBootstrapFamilyV1::V5 {
        return Err(ProductionConfigErrorV1::ProvisioningJournalRefused);
    }
    let (create, reopen) = match bootstrap.config.mode() {
        ProductionBootstrapModeV1::Create => (
            bootstrap.config.clone(),
            load_manifest(
                bootstrap.layout.state_dir(),
                PRODUCTION_REOPEN_CONFIG_FILE_V5,
                ProductionBootstrapModeV1::ReopenExisting,
                ProductionBootstrapFamilyV1::V5,
            )?,
        ),
        ProductionBootstrapModeV1::ReopenExisting => (
            load_manifest(
                bootstrap.layout.state_dir(),
                PRODUCTION_CREATE_CONFIG_FILE_V5,
                ProductionBootstrapModeV1::Create,
                ProductionBootstrapFamilyV1::V5,
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
#[expect(
    dead_code,
    reason = "superseded bootstrap lineage retained for configuration migration history"
)]
pub(crate) fn provisioning_binding_for_v6_bootstrap(
    bootstrap: &ValidatedProductionBootstrapV1,
) -> Result<[u8; 32], ProductionConfigErrorV1> {
    if bootstrap.config.family() != ProductionBootstrapFamilyV1::V6 {
        return Err(ProductionConfigErrorV1::ProvisioningJournalRefused);
    }
    let (create, reopen) = match bootstrap.config.mode() {
        ProductionBootstrapModeV1::Create => (
            bootstrap.config.clone(),
            load_manifest(
                bootstrap.layout.state_dir(),
                PRODUCTION_REOPEN_CONFIG_FILE_V6,
                ProductionBootstrapModeV1::ReopenExisting,
                ProductionBootstrapFamilyV1::V6,
            )?,
        ),
        ProductionBootstrapModeV1::ReopenExisting => (
            load_manifest(
                bootstrap.layout.state_dir(),
                PRODUCTION_CREATE_CONFIG_FILE_V6,
                ProductionBootstrapModeV1::Create,
                ProductionBootstrapFamilyV1::V6,
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
#[expect(
    dead_code,
    reason = "superseded bootstrap lineage retained for configuration migration history"
)]
pub(crate) fn provisioning_binding_for_v7_bootstrap(
    bootstrap: &ValidatedProductionBootstrapV1,
) -> Result<[u8; 32], ProductionConfigErrorV1> {
    if bootstrap.config.family() != ProductionBootstrapFamilyV1::V7 {
        return Err(ProductionConfigErrorV1::ProvisioningJournalRefused);
    }
    let (create, reopen) = match bootstrap.config.mode() {
        ProductionBootstrapModeV1::Create => (
            bootstrap.config.clone(),
            load_manifest(
                bootstrap.layout.state_dir(),
                PRODUCTION_REOPEN_CONFIG_FILE_V7,
                ProductionBootstrapModeV1::ReopenExisting,
                ProductionBootstrapFamilyV1::V7,
            )?,
        ),
        ProductionBootstrapModeV1::ReopenExisting => (
            load_manifest(
                bootstrap.layout.state_dir(),
                PRODUCTION_CREATE_CONFIG_FILE_V7,
                ProductionBootstrapModeV1::Create,
                ProductionBootstrapFamilyV1::V7,
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
#[expect(
    dead_code,
    reason = "superseded bootstrap lineage retained for configuration migration history"
)]
pub(crate) fn provisioning_binding_for_v8_bootstrap(
    bootstrap: &ValidatedProductionBootstrapV1,
) -> Result<[u8; 32], ProductionConfigErrorV1> {
    if bootstrap.config.family() != ProductionBootstrapFamilyV1::V8 {
        return Err(ProductionConfigErrorV1::ProvisioningJournalRefused);
    }
    let (create, reopen) = match bootstrap.config.mode() {
        ProductionBootstrapModeV1::Create => (
            bootstrap.config.clone(),
            load_manifest(
                bootstrap.layout.state_dir(),
                PRODUCTION_REOPEN_CONFIG_FILE_V8,
                ProductionBootstrapModeV1::ReopenExisting,
                ProductionBootstrapFamilyV1::V8,
            )?,
        ),
        ProductionBootstrapModeV1::ReopenExisting => (
            load_manifest(
                bootstrap.layout.state_dir(),
                PRODUCTION_CREATE_CONFIG_FILE_V8,
                ProductionBootstrapModeV1::Create,
                ProductionBootstrapFamilyV1::V8,
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
#[expect(
    dead_code,
    reason = "superseded bootstrap lineage retained for configuration migration history"
)]
pub(crate) fn provisioning_binding_for_v9_bootstrap(
    bootstrap: &ValidatedProductionBootstrapV1,
) -> Result<[u8; 32], ProductionConfigErrorV1> {
    if bootstrap.config.family() != ProductionBootstrapFamilyV1::V9 {
        return Err(ProductionConfigErrorV1::ProvisioningJournalRefused);
    }
    let (create, reopen) = match bootstrap.config.mode() {
        ProductionBootstrapModeV1::Create => (
            bootstrap.config.clone(),
            load_manifest(
                bootstrap.layout.state_dir(),
                PRODUCTION_REOPEN_CONFIG_FILE_V9,
                ProductionBootstrapModeV1::ReopenExisting,
                ProductionBootstrapFamilyV1::V9,
            )?,
        ),
        ProductionBootstrapModeV1::ReopenExisting => (
            load_manifest(
                bootstrap.layout.state_dir(),
                PRODUCTION_CREATE_CONFIG_FILE_V9,
                ProductionBootstrapModeV1::Create,
                ProductionBootstrapFamilyV1::V9,
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
pub(crate) fn provisioning_binding_for_v10_bootstrap(
    bootstrap: &ValidatedProductionBootstrapV1,
) -> Result<[u8; 32], ProductionConfigErrorV1> {
    if bootstrap.config.family() != ProductionBootstrapFamilyV1::V10 {
        return Err(ProductionConfigErrorV1::ProvisioningJournalRefused);
    }
    let (create, reopen) = match bootstrap.config.mode() {
        ProductionBootstrapModeV1::Create => (
            bootstrap.config.clone(),
            load_manifest(
                bootstrap.layout.state_dir(),
                PRODUCTION_REOPEN_CONFIG_FILE_V10,
                ProductionBootstrapModeV1::ReopenExisting,
                ProductionBootstrapFamilyV1::V10,
            )?,
        ),
        ProductionBootstrapModeV1::ReopenExisting => (
            load_manifest(
                bootstrap.layout.state_dir(),
                PRODUCTION_CREATE_CONFIG_FILE_V10,
                ProductionBootstrapModeV1::Create,
                ProductionBootstrapFamilyV1::V10,
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

/// Loads only the V4 recovery manifest and requires all managed authorities.
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

/// Loads only the V5 recovery manifest and requires every managed authority
/// plus the externally provisioned Contracts bootstrap to exist.
pub fn load_production_reopen_bootstrap_v5(
    state_dir: &Path,
) -> Result<ValidatedProductionBootstrapV1, ProductionConfigErrorV1> {
    let canonical_state = validate_state_dir(state_dir)?;
    let config = load_manifest(
        &canonical_state,
        PRODUCTION_REOPEN_CONFIG_FILE_V5,
        ProductionBootstrapModeV1::ReopenExisting,
        ProductionBootstrapFamilyV1::V5,
    )?;
    let layout = resolve_and_validate_layout(&canonical_state, &config, false)?;
    Ok(ValidatedProductionBootstrapV1 { config, layout })
}

/// Loads only the V6 recovery manifest and requires the complete V5 physical
/// layout under the V6 Relay identity and quota bindings.
pub fn load_production_reopen_bootstrap_v6(
    state_dir: &Path,
) -> Result<ValidatedProductionBootstrapV1, ProductionConfigErrorV1> {
    let canonical_state = validate_state_dir(state_dir)?;
    let config = load_manifest(
        &canonical_state,
        PRODUCTION_REOPEN_CONFIG_FILE_V6,
        ProductionBootstrapModeV1::ReopenExisting,
        ProductionBootstrapFamilyV1::V6,
    )?;
    let layout = resolve_and_validate_layout(&canonical_state, &config, false)?;
    Ok(ValidatedProductionBootstrapV1 { config, layout })
}

/// Loads only the V7 recovery manifest and requires the pre-existing Bitcoin
/// prebroadcast authority together with every managed V6 authority.
pub fn load_production_reopen_bootstrap_v7(
    state_dir: &Path,
) -> Result<ValidatedProductionBootstrapV1, ProductionConfigErrorV1> {
    let canonical_state = validate_state_dir(state_dir)?;
    let config = load_manifest(
        &canonical_state,
        PRODUCTION_REOPEN_CONFIG_FILE_V7,
        ProductionBootstrapModeV1::ReopenExisting,
        ProductionBootstrapFamilyV1::V7,
    )?;
    let layout = resolve_and_validate_layout(&canonical_state, &config, false)?;
    Ok(ValidatedProductionBootstrapV1 { config, layout })
}

/// Loads only the V8 recovery manifest. It never falls back to V7 or creates
/// any missing F6/Bitcoin authority.
pub fn load_production_reopen_bootstrap_v8(
    state_dir: &Path,
) -> Result<ValidatedProductionBootstrapV1, ProductionConfigErrorV1> {
    let canonical_state = validate_state_dir(state_dir)?;
    let config = load_manifest(
        &canonical_state,
        PRODUCTION_REOPEN_CONFIG_FILE_V8,
        ProductionBootstrapModeV1::ReopenExisting,
        ProductionBootstrapFamilyV1::V8,
    )?;
    let layout = resolve_and_validate_layout(&canonical_state, &config, false)?;
    Ok(ValidatedProductionBootstrapV1 { config, layout })
}

/// Loads only the V9 recovery manifest. The static refund authority epoch is
/// authenticated by the canonical config and never read from a live lease.
pub fn load_production_reopen_bootstrap_v9(
    state_dir: &Path,
) -> Result<ValidatedProductionBootstrapV1, ProductionConfigErrorV1> {
    let canonical_state = validate_state_dir(state_dir)?;
    let config = load_manifest(
        &canonical_state,
        PRODUCTION_REOPEN_CONFIG_FILE_V9,
        ProductionBootstrapModeV1::ReopenExisting,
        ProductionBootstrapFamilyV1::V9,
    )?;
    let layout = resolve_and_validate_layout(&canonical_state, &config, false)?;
    Ok(ValidatedProductionBootstrapV1 { config, layout })
}

/// Loads only V10 recovery, requires its create companion to bind identical
/// facts, and never falls back to an earlier family or creates missing state.
pub fn load_production_reopen_bootstrap_v10(
    state_dir: &Path,
) -> Result<ValidatedProductionBootstrapV1, ProductionConfigErrorV1> {
    let canonical_state = validate_state_dir(state_dir)?;
    let reopen = load_manifest(
        &canonical_state,
        PRODUCTION_REOPEN_CONFIG_FILE_V10,
        ProductionBootstrapModeV1::ReopenExisting,
        ProductionBootstrapFamilyV1::V10,
    )?;
    let create = load_manifest(
        &canonical_state,
        PRODUCTION_CREATE_CONFIG_FILE_V10,
        ProductionBootstrapModeV1::Create,
        ProductionBootstrapFamilyV1::V10,
    )?;
    if !create.equivalent_except_mode(&reopen) {
        return Err(ProductionConfigErrorV1::CompanionMismatch);
    }
    let layout = resolve_and_validate_layout(&canonical_state, &reopen, false)?;
    Ok(ValidatedProductionBootstrapV1 {
        config: reopen,
        layout,
    })
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

struct DecodedV6ExtrasV1 {
    identity: String,
    budget: String,
    f6: ProductionF6PathReferencesV4,
    contracts_bootstrap: String,
    contracts_pins: ProductionContractsBootstrapPinsV5,
    relay_pins: ProductionRelayAuthorityPinsV6,
}

fn decode_v6_extras(
    lines: &[&str],
    cursor: &mut usize,
) -> Result<DecodedV6ExtrasV1, ProductionConfigErrorV1> {
    let identity = take_value(lines, cursor, IDENTITY_STORE_KEY_V2)?.to_owned();
    let budget = take_value(lines, cursor, BUDGET_POLICY_KEY_V3)?.to_owned();
    let mut values = Vec::with_capacity(PRODUCTION_F6_PATH_ROLE_COUNT_V4);
    for role in ProductionF6PathRoleV4::ALL {
        values.push(take_value(lines, cursor, role.key())?.to_owned());
    }
    let paths: [String; PRODUCTION_F6_PATH_ROLE_COUNT_V4] = values
        .try_into()
        .map_err(|_| ProductionConfigErrorV1::InvalidCanonicalEncoding)?;
    let contracts_bootstrap = take_value(lines, cursor, CONTRACTS_BOOTSTRAP_KEY_V5)?.to_owned();
    let contracts_pins = ProductionContractsBootstrapPinsV5::new(
        take_digest(lines, cursor, CONTRACTS_BOOTSTRAP_COMMIT_DIGEST_KEY_V5)?,
        take_digest(lines, cursor, CONTRACTS_BOOTSTRAP_REVEAL_DIGEST_KEY_V5)?,
    )?;
    let relay_pins = ProductionRelayAuthorityPinsV6 {
        relay_database_id: take_digest(lines, cursor, RELAY_DATABASE_ID_KEY_V6)?,
        upstream_sender_store_id: take_digest(lines, cursor, UPSTREAM_RELAY_SENDER_ID_KEY_V6)?,
        upstream_inbox_id: take_digest(lines, cursor, UPSTREAM_RELAY_INBOX_ID_KEY_V6)?,
        upstream_reassembler_id: take_digest(lines, cursor, UPSTREAM_RELAY_FRAME_ID_KEY_V6)?,
        downstream_sender_store_id: take_digest(lines, cursor, DOWNSTREAM_RELAY_SENDER_ID_KEY_V6)?,
        downstream_inbox_id: take_digest(lines, cursor, DOWNSTREAM_RELAY_INBOX_ID_KEY_V6)?,
        downstream_reassembler_id: take_digest(lines, cursor, DOWNSTREAM_RELAY_FRAME_ID_KEY_V6)?,
        relay_max_envelopes: take_u32(lines, cursor, RELAY_MAX_ENVELOPES_KEY_V6)?,
        sender_max_envelopes: take_u32(lines, cursor, SENDER_MAX_ENVELOPES_KEY_V6)?,
        inbox_max_entries: take_u32(lines, cursor, INBOX_MAX_ENTRIES_KEY_V6)?,
        frame_max_messages: take_u16(lines, cursor, FRAME_MAX_MESSAGES_KEY_V6)?,
        frame_max_active_bytes: take_u64(lines, cursor, FRAME_MAX_ACTIVE_BYTES_KEY_V6)?,
        frame_max_active_chunks: take_u32(lines, cursor, FRAME_MAX_ACTIVE_CHUNKS_KEY_V6)?,
    };
    Ok(DecodedV6ExtrasV1 {
        identity,
        budget,
        f6: ProductionF6PathReferencesV4::from_ordered(paths)?,
        contracts_bootstrap,
        contracts_pins,
        relay_pins,
    })
}

fn decode_bitcoin_v7(
    lines: &[&str],
    cursor: &mut usize,
) -> Result<(String, ProductionBitcoinPrebroadcastPinsV7), ProductionConfigErrorV1> {
    let store = take_value(lines, cursor, BITCOIN_PREBROADCAST_STORE_KEY_V7)?.to_owned();
    let leg = match take_value(lines, cursor, BITCOIN_LEG_KEY_V7)? {
        "upstream" => LegIdV1::Upstream,
        "downstream" => LegIdV1::Downstream,
        _ => return Err(ProductionConfigErrorV1::InvalidCanonicalEncoding),
    };
    let pins = ProductionBitcoinPrebroadcastPinsV7 {
        leg,
        settlement_id: take_digest(lines, cursor, BITCOIN_SETTLEMENT_ID_KEY_V7)?,
        session_id: take_digest(lines, cursor, BITCOIN_SESSION_ID_KEY_V7)?,
        terms_digest: take_digest(lines, cursor, BITCOIN_TERMS_DIGEST_KEY_V7)?,
        deployment_digest: take_digest(lines, cursor, BITCOIN_DEPLOYMENT_DIGEST_KEY_V7)?,
        route_binding: take_digest(lines, cursor, BITCOIN_ROUTE_BINDING_KEY_V7)?,
        plan_digest: take_digest(lines, cursor, BITCOIN_PLAN_DIGEST_KEY_V7)?,
        receipt_digest: take_digest(lines, cursor, BITCOIN_RECEIPT_DIGEST_KEY_V7)?,
        contract_script_pubkey_digest: take_digest(
            lines,
            cursor,
            BITCOIN_CONTRACT_SCRIPT_DIGEST_KEY_V7,
        )?,
        claim_destination_script_pubkey_digest: take_digest(
            lines,
            cursor,
            BITCOIN_CLAIM_SCRIPT_DIGEST_KEY_V7,
        )?,
        refund_destination_script_pubkey_digest: take_digest(
            lines,
            cursor,
            BITCOIN_REFUND_SCRIPT_DIGEST_KEY_V7,
        )?,
        refund_key_xonly: take_digest(lines, cursor, BITCOIN_REFUND_KEY_KEY_V7)?,
        funding_template_hash: take_digest(lines, cursor, BITCOIN_FUNDING_TEMPLATE_KEY_V7)?,
        claim_template_hash: take_digest(lines, cursor, BITCOIN_CLAIM_TEMPLATE_KEY_V7)?,
        refund_template_hash: take_digest(lines, cursor, BITCOIN_REFUND_TEMPLATE_KEY_V7)?,
    };
    Ok((store, pins))
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
    let expected_lines =
        1 + 1 + 18 + 1 + 10 + family.path_role_count() + family.extra_binding_line_count() + 2;
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
    let mut decoded_bitcoin_v7 = None;
    let mut decoded_f6_v8 = None;
    let mut decoded_refund_epoch_v9 = None;
    let mut decoded_operational_policies_v10 = None;
    let extras = match family {
        ProductionBootstrapFamilyV1::V1 => None,
        ProductionBootstrapFamilyV1::V2 => Some((
            take_value(&lines, &mut cursor, IDENTITY_STORE_KEY_V2)?.to_owned(),
            None,
            None,
            None,
            None,
            None,
        )),
        ProductionBootstrapFamilyV1::V3 => Some((
            take_value(&lines, &mut cursor, IDENTITY_STORE_KEY_V2)?.to_owned(),
            Some(take_value(&lines, &mut cursor, BUDGET_POLICY_KEY_V3)?.to_owned()),
            None,
            None,
            None,
            None,
        )),
        ProductionBootstrapFamilyV1::V4 => {
            let identity = take_value(&lines, &mut cursor, IDENTITY_STORE_KEY_V2)?.to_owned();
            let budget = take_value(&lines, &mut cursor, BUDGET_POLICY_KEY_V3)?.to_owned();
            let mut values = Vec::with_capacity(PRODUCTION_F6_PATH_ROLE_COUNT_V4);
            for role in ProductionF6PathRoleV4::ALL {
                values.push(take_value(&lines, &mut cursor, role.key())?.to_owned());
            }
            let paths: [String; PRODUCTION_F6_PATH_ROLE_COUNT_V4] = values
                .try_into()
                .map_err(|_| ProductionConfigErrorV1::InvalidCanonicalEncoding)?;
            Some((
                identity,
                Some(budget),
                Some(ProductionF6PathReferencesV4::from_ordered(paths)?),
                None,
                None,
                None,
            ))
        }
        ProductionBootstrapFamilyV1::V5 => {
            let identity = take_value(&lines, &mut cursor, IDENTITY_STORE_KEY_V2)?.to_owned();
            let budget = take_value(&lines, &mut cursor, BUDGET_POLICY_KEY_V3)?.to_owned();
            let mut values = Vec::with_capacity(PRODUCTION_F6_PATH_ROLE_COUNT_V4);
            for role in ProductionF6PathRoleV4::ALL {
                values.push(take_value(&lines, &mut cursor, role.key())?.to_owned());
            }
            let paths: [String; PRODUCTION_F6_PATH_ROLE_COUNT_V4] = values
                .try_into()
                .map_err(|_| ProductionConfigErrorV1::InvalidCanonicalEncoding)?;
            let contracts_bootstrap =
                take_value(&lines, &mut cursor, CONTRACTS_BOOTSTRAP_KEY_V5)?.to_owned();
            let contracts_bootstrap_pins = ProductionContractsBootstrapPinsV5::new(
                take_digest(
                    &lines,
                    &mut cursor,
                    CONTRACTS_BOOTSTRAP_COMMIT_DIGEST_KEY_V5,
                )?,
                take_digest(
                    &lines,
                    &mut cursor,
                    CONTRACTS_BOOTSTRAP_REVEAL_DIGEST_KEY_V5,
                )?,
            )?;
            Some((
                identity,
                Some(budget),
                Some(ProductionF6PathReferencesV4::from_ordered(paths)?),
                Some(contracts_bootstrap),
                Some(contracts_bootstrap_pins),
                None,
            ))
        }
        ProductionBootstrapFamilyV1::V6 => {
            let decoded = decode_v6_extras(&lines, &mut cursor)?;
            Some((
                decoded.identity,
                Some(decoded.budget),
                Some(decoded.f6),
                Some(decoded.contracts_bootstrap),
                Some(decoded.contracts_pins),
                Some(decoded.relay_pins),
            ))
        }
        ProductionBootstrapFamilyV1::V7 => {
            let decoded = decode_v6_extras(&lines, &mut cursor)?;
            decoded_bitcoin_v7 = Some(decode_bitcoin_v7(&lines, &mut cursor)?);
            Some((
                decoded.identity,
                Some(decoded.budget),
                Some(decoded.f6),
                Some(decoded.contracts_bootstrap),
                Some(decoded.contracts_pins),
                Some(decoded.relay_pins),
            ))
        }
        ProductionBootstrapFamilyV1::V8 => {
            let decoded = decode_v6_extras(&lines, &mut cursor)?;
            decoded_bitcoin_v7 = Some(decode_bitcoin_v7(&lines, &mut cursor)?);
            let mut values = Vec::with_capacity(PRODUCTION_F6_PATH_ROLE_COUNT_V8);
            for role in ProductionF6PathRoleV8::ALL {
                values.push(take_value(&lines, &mut cursor, role.key())?.to_owned());
            }
            let paths: [String; PRODUCTION_F6_PATH_ROLE_COUNT_V8] = values
                .try_into()
                .map_err(|_| ProductionConfigErrorV1::InvalidCanonicalEncoding)?;
            let bundle_digest =
                take_digest(&lines, &mut cursor, F6_AUTHORITY_BUNDLE_DIGEST_KEY_V8)?;
            decoded_f6_v8 = Some((
                ProductionF6PathReferencesV8::from_ordered(paths)?,
                bundle_digest,
            ));
            Some((
                decoded.identity,
                Some(decoded.budget),
                Some(decoded.f6),
                Some(decoded.contracts_bootstrap),
                Some(decoded.contracts_pins),
                Some(decoded.relay_pins),
            ))
        }
        ProductionBootstrapFamilyV1::V9 => {
            let decoded = decode_v6_extras(&lines, &mut cursor)?;
            decoded_bitcoin_v7 = Some(decode_bitcoin_v7(&lines, &mut cursor)?);
            let mut values = Vec::with_capacity(PRODUCTION_F6_PATH_ROLE_COUNT_V8);
            for role in ProductionF6PathRoleV8::ALL {
                values.push(take_value(&lines, &mut cursor, role.key())?.to_owned());
            }
            let paths: [String; PRODUCTION_F6_PATH_ROLE_COUNT_V8] = values
                .try_into()
                .map_err(|_| ProductionConfigErrorV1::InvalidCanonicalEncoding)?;
            let bundle_digest =
                take_digest(&lines, &mut cursor, F6_AUTHORITY_BUNDLE_DIGEST_KEY_V8)?;
            decoded_f6_v8 = Some((
                ProductionF6PathReferencesV8::from_ordered(paths)?,
                bundle_digest,
            ));
            decoded_refund_epoch_v9 = Some(take_u64(
                &lines,
                &mut cursor,
                REFUND_ARMING_AUTHORITY_EPOCH_KEY_V9,
            )?);
            Some((
                decoded.identity,
                Some(decoded.budget),
                Some(decoded.f6),
                Some(decoded.contracts_bootstrap),
                Some(decoded.contracts_pins),
                Some(decoded.relay_pins),
            ))
        }
        ProductionBootstrapFamilyV1::V10 => {
            let decoded = decode_v6_extras(&lines, &mut cursor)?;
            decoded_bitcoin_v7 = Some(decode_bitcoin_v7(&lines, &mut cursor)?);
            let mut values = Vec::with_capacity(PRODUCTION_F6_PATH_ROLE_COUNT_V8);
            for role in ProductionF6PathRoleV8::ALL {
                values.push(take_value(&lines, &mut cursor, role.key())?.to_owned());
            }
            let paths: [String; PRODUCTION_F6_PATH_ROLE_COUNT_V8] = values
                .try_into()
                .map_err(|_| ProductionConfigErrorV1::InvalidCanonicalEncoding)?;
            let bundle_digest =
                take_digest(&lines, &mut cursor, F6_AUTHORITY_BUNDLE_DIGEST_KEY_V8)?;
            decoded_f6_v8 = Some((
                ProductionF6PathReferencesV8::from_ordered(paths)?,
                bundle_digest,
            ));
            decoded_refund_epoch_v9 = Some(take_u64(
                &lines,
                &mut cursor,
                REFUND_ARMING_AUTHORITY_EPOCH_KEY_V9,
            )?);
            decoded_operational_policies_v10 = Some(ProductionOperationalPoliciesV10::new(
                take_digest(
                    &lines,
                    &mut cursor,
                    UPSTREAM_REMOTE_RELAY_DATABASE_ID_KEY_V10,
                )?,
                take_digest(
                    &lines,
                    &mut cursor,
                    DOWNSTREAM_REMOTE_RELAY_DATABASE_ID_KEY_V10,
                )?,
                take_u128(&lines, &mut cursor, EVM_INITIAL_MAX_FEE_PER_GAS_KEY_V10)?,
                take_u128(
                    &lines,
                    &mut cursor,
                    EVM_INITIAL_MAX_PRIORITY_FEE_PER_GAS_KEY_V10,
                )?,
                take_u64(&lines, &mut cursor, EVM_OBSERVATION_VALID_FOR_MS_KEY_V10)?,
                take_u64(
                    &lines,
                    &mut cursor,
                    EVM_REMOTE_CUSTODY_LEASE_DURATION_MS_KEY_V10,
                )?,
            )?);
            Some((
                decoded.identity,
                Some(decoded.budget),
                Some(decoded.f6),
                Some(decoded.contracts_bootstrap),
                Some(decoded.contracts_pins),
                Some(decoded.relay_pins),
            ))
        }
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
    let config = match (extras, decoded_bitcoin_v7, decoded_f6_v8) {
        (None, None, None) => config,
        (Some((identity_store, None, None, None, None, None)), None, None) => {
            ProductionBootstrapConfigV1::from_parts_v2(
                config.mode,
                config.pins,
                config.bounds,
                config.paths,
                identity_store,
            )?
        }
        (Some((identity_store, Some(budget_policy), None, None, None, None)), None, None) => {
            ProductionBootstrapConfigV1::from_parts_v3(
                config.mode,
                config.pins,
                config.bounds,
                config.paths,
                identity_store,
                budget_policy,
            )?
        }
        (Some((identity_store, Some(budget_policy), Some(f6), None, None, None)), None, None) => {
            ProductionBootstrapConfigV1::from_parts_v4(
                config.mode,
                config.pins,
                config.bounds,
                config.paths,
                identity_store,
                budget_policy,
                f6,
            )?
        }
        (
            Some((
                identity_store,
                Some(budget_policy),
                Some(f6),
                Some(contracts_bootstrap),
                Some(contracts_bootstrap_pins),
                None,
            )),
            None,
            None,
        ) => ProductionBootstrapConfigV1::from_parts_v5(
            config.mode,
            config.pins,
            config.bounds,
            config.paths,
            ProductionFamilyInputsV5::new(
                identity_store,
                budget_policy,
                f6,
                contracts_bootstrap,
                contracts_bootstrap_pins,
            ),
        )?,
        (
            Some((
                identity_store,
                Some(budget_policy),
                Some(f6),
                Some(contracts_bootstrap),
                Some(contracts_bootstrap_pins),
                Some(relay_authority_pins),
            )),
            None,
            None,
        ) => ProductionBootstrapConfigV1::from_parts_v6(
            config.mode,
            config.pins,
            config.bounds,
            config.paths,
            ProductionFamilyInputsV6::new(
                ProductionFamilyInputsV5::new(
                    identity_store,
                    budget_policy,
                    f6,
                    contracts_bootstrap,
                    contracts_bootstrap_pins,
                ),
                relay_authority_pins,
            ),
        )?,
        (
            Some((
                identity_store,
                Some(budget_policy),
                Some(f6),
                Some(contracts_bootstrap),
                Some(contracts_bootstrap_pins),
                Some(relay_authority_pins),
            )),
            Some((bitcoin_prebroadcast_store, bitcoin_prebroadcast_pins)),
            None,
        ) => ProductionBootstrapConfigV1::from_parts_v7(
            config.mode,
            config.pins,
            config.bounds,
            config.paths,
            ProductionFamilyInputsV7::new(
                ProductionFamilyInputsV6::new(
                    ProductionFamilyInputsV5::new(
                        identity_store,
                        budget_policy,
                        f6,
                        contracts_bootstrap,
                        contracts_bootstrap_pins,
                    ),
                    relay_authority_pins,
                ),
                bitcoin_prebroadcast_store,
                bitcoin_prebroadcast_pins,
            ),
        )?,
        (
            Some((
                identity_store,
                Some(budget_policy),
                Some(f6_v4),
                Some(contracts_bootstrap),
                Some(contracts_bootstrap_pins),
                Some(relay_authority_pins),
            )),
            Some((bitcoin_prebroadcast_store, bitcoin_prebroadcast_pins)),
            Some((f6_v8, f6_authority_bundle_digest)),
        ) => ProductionBootstrapConfigV1::from_parts_v8(
            config.mode,
            config.pins,
            config.bounds,
            config.paths,
            ProductionFamilyInputsV8::new(
                ProductionFamilyInputsV7::new(
                    ProductionFamilyInputsV6::new(
                        ProductionFamilyInputsV5::new(
                            identity_store,
                            budget_policy,
                            f6_v4,
                            contracts_bootstrap,
                            contracts_bootstrap_pins,
                        ),
                        relay_authority_pins,
                    ),
                    bitcoin_prebroadcast_store,
                    bitcoin_prebroadcast_pins,
                ),
                f6_v8,
                f6_authority_bundle_digest,
            ),
        )?,
        _ => {
            return Err(ProductionConfigErrorV1::InvalidCanonicalEncoding);
        }
    };
    let config = match decoded_refund_epoch_v9 {
        None => config,
        Some(epoch) => config.promote_v8_to_v9(epoch)?,
    };
    let config = match decoded_operational_policies_v10 {
        None => config,
        Some(policies) => config.promote_v9_to_v10(policies)?,
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

fn take_u128(
    lines: &[&str],
    cursor: &mut usize,
    key: &str,
) -> Result<u128, ProductionConfigErrorV1> {
    let value = take_value(lines, cursor, key)?;
    if value == "0" || value.starts_with('0') || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(ProductionConfigErrorV1::InvalidCanonicalEncoding);
    }
    value
        .parse()
        .map_err(|_| ProductionConfigErrorV1::InvalidCanonicalEncoding)
}

fn take_u32(lines: &[&str], cursor: &mut usize, key: &str) -> Result<u32, ProductionConfigErrorV1> {
    u32::try_from(take_u64(lines, cursor, key)?)
        .map_err(|_| ProductionConfigErrorV1::InvalidCanonicalEncoding)
}

fn take_u16(lines: &[&str], cursor: &mut usize, key: &str) -> Result<u16, ProductionConfigErrorV1> {
    u16::try_from(take_u64(lines, cursor, key)?)
        .map_err(|_| ProductionConfigErrorV1::InvalidCanonicalEncoding)
}

fn write_digest(target: &mut String, key: &str, value: [u8; 32]) {
    writeln!(target, "{key}={}", encode_hex(&value)).expect("string write cannot fail");
}

fn write_u64(target: &mut String, key: &str, value: u64) {
    writeln!(target, "{key}={value}").expect("string write cannot fail");
}

fn write_u128(target: &mut String, key: &str, value: u128) {
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

/// Canonical V7 commitment for one exact Bitcoin scriptPubKey.
///
/// Provisioning uses the same bounded, length-prefixed domain as the runtime
/// owner, so a manifest cannot silently substitute an empty, oversized or
/// differently framed contract, claim-destination or refund-destination
/// script.
pub fn bitcoin_prebroadcast_script_digest_v7(
    script: &[u8],
) -> Result<[u8; 32], ProductionConfigErrorV1> {
    if script.is_empty() || script.len() > MAX_BITCOIN_PREBROADCAST_SCRIPT_BYTES_V7 {
        return Err(ProductionConfigErrorV1::InvalidPublicBinding);
    }
    let length =
        u32::try_from(script.len()).map_err(|_| ProductionConfigErrorV1::InvalidPublicBinding)?;
    let mut hasher =
        Blake2bVar::new(32).map_err(|_| ProductionConfigErrorV1::InvalidPublicBinding)?;
    hasher.update(BITCOIN_PREBROADCAST_SCRIPT_DIGEST_DOMAIN_V7);
    hasher.update(&length.to_be_bytes());
    hasher.update(script);
    let mut digest = [0; 32];
    hasher
        .finalize_variable(&mut digest)
        .map_err(|_| ProductionConfigErrorV1::InvalidPublicBinding)?;
    if digest == ZERO_DIGEST {
        return Err(ProductionConfigErrorV1::InvalidPublicBinding);
    }
    Ok(digest)
}

/// Domain-separated commitment to the exact bounded F6 V7 authority bundle.
pub fn production_f6_authority_bundle_digest_v8(
    bundle: &[u8],
) -> Result<[u8; 32], ProductionConfigErrorV1> {
    if bundle.is_empty() || bundle.len() as u64 > MAX_PRODUCTION_F6_AUTHORITY_BUNDLE_BYTES_V8 {
        return Err(ProductionConfigErrorV1::InvalidPublicBinding);
    }
    let length =
        u32::try_from(bundle.len()).map_err(|_| ProductionConfigErrorV1::InvalidPublicBinding)?;
    let mut hasher =
        Blake2bVar::new(32).map_err(|_| ProductionConfigErrorV1::InvalidPublicBinding)?;
    hasher.update(F6_AUTHORITY_BUNDLE_DIGEST_DOMAIN_V8);
    hasher.update(&length.to_be_bytes());
    hasher.update(bundle);
    let mut digest = [0; 32];
    hasher
        .finalize_variable(&mut digest)
        .map_err(|_| ProductionConfigErrorV1::InvalidPublicBinding)?;
    if digest == ZERO_DIGEST {
        return Err(ProductionConfigErrorV1::InvalidPublicBinding);
    }
    Ok(digest)
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
                | PRODUCTION_CREATE_CONFIG_FILE_V4
                | PRODUCTION_REOPEN_CONFIG_FILE_V4
                | PRODUCTION_CREATE_CONFIG_FILE_V5
                | PRODUCTION_REOPEN_CONFIG_FILE_V5
                | PRODUCTION_CREATE_CONFIG_FILE_V6
                | PRODUCTION_REOPEN_CONFIG_FILE_V6
                | PRODUCTION_CREATE_CONFIG_FILE_V7
                | PRODUCTION_REOPEN_CONFIG_FILE_V7
                | PRODUCTION_CREATE_CONFIG_FILE_V8
                | PRODUCTION_REOPEN_CONFIG_FILE_V8
                | PRODUCTION_CREATE_CONFIG_FILE_V9
                | PRODUCTION_REOPEN_CONFIG_FILE_V9
                | PRODUCTION_CREATE_CONFIG_FILE_V10
                | PRODUCTION_REOPEN_CONFIG_FILE_V10
                | PRODUCTION_NODE_CONFIG_FILE_V1
                | PRODUCTION_RELAY_NETWORK_CONFIG_FILE_V1
                | REFUND_ARMING_DATABASE_FILE_V1
                | SOLANA_ACTUATOR_DATABASE_FILE_V1
                | XMR_ACTUATOR_DATABASE_FILE_V1
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
    let f6_paths_v4 = match config.f6_paths_v4() {
        None => None,
        Some(references) => {
            let live_v8_or_later = config.f6_paths_v8().is_some();
            let paths =
                std::array::from_fn(|index| state_dir.join(references.paths[index].as_str()));
            for role in ProductionF6PathRoleV4::ALL {
                let path = &paths[role.index()];
                validate_parent_chain(state_dir, path)?;
                if live_v8_or_later && !role.retained_by_v8() {
                    require_absent(
                        path,
                        if creating {
                            ProductionConfigErrorV1::StateAlreadyPresent
                        } else {
                            ProductionConfigErrorV1::RecoveryStateUnavailable
                        },
                    )?;
                } else if creating {
                    require_managed_file_absent(path)?;
                } else {
                    validate_owner_file(path, ProductionConfigErrorV1::RecoveryStateUnavailable)?;
                }
            }
            Some(paths)
        }
    };
    let contracts_bootstrap = match config.contracts_bootstrap() {
        None => None,
        Some(relative) => {
            let path = state_dir.join(relative);
            validate_parent_chain(state_dir, &path)?;
            validate_input_file(&path)?;
            Some(path)
        }
    };
    let bitcoin_prebroadcast_store_v7 = match config.bitcoin_prebroadcast_store_v7() {
        None => None,
        Some(relative) => {
            let path = state_dir.join(relative);
            validate_parent_chain(state_dir, &path)?;
            validate_owner_directory(
                &path,
                ProductionConfigErrorV1::BitcoinPrebroadcastAuthorityUnavailable,
            )?;
            Some(path)
        }
    };
    let f6_paths_v8 = match config.f6_paths_v8() {
        None => None,
        Some(references) => {
            let paths =
                std::array::from_fn(|index| state_dir.join(references.paths[index].as_str()));
            for role in ProductionF6PathRoleV8::ALL {
                let path = &paths[role.index()];
                validate_parent_chain(state_dir, path)?;
                match role.kind() {
                    ProductionPathKindV1::ManagedFile if creating => {
                        require_managed_file_absent(path)?;
                    }
                    ProductionPathKindV1::ManagedFile => {
                        validate_owner_file(
                            path,
                            ProductionConfigErrorV1::RecoveryStateUnavailable,
                        )?;
                    }
                    ProductionPathKindV1::InputFile => validate_input_file(path)?,
                    ProductionPathKindV1::ManagedDirectory
                    | ProductionPathKindV1::ExistingAuthorityDirectory => {
                        return Err(ProductionConfigErrorV1::InvalidPathReference);
                    }
                }
            }
            authenticate_f6_bundle_file_v8(config, &paths)?;
            Some(paths)
        }
    };
    let refund_arming_database = if f6_paths_v8.is_some() {
        let path = state_dir.join(REFUND_ARMING_DATABASE_FILE_V1);
        validate_parent_chain(state_dir, &path)?;
        if creating {
            require_managed_file_absent(&path)?;
        } else {
            validate_owner_file(&path, ProductionConfigErrorV1::RecoveryStateUnavailable)?;
        }
        Some(path)
    } else {
        None
    };
    let solana_actuator_database = derive_optional_chain_actuator_database(
        state_dir,
        SOLANA_ACTUATOR_DATABASE_FILE_V1,
        creating,
        f6_paths_v8.is_some(),
    )?;
    let xmr_actuator_database = derive_optional_chain_actuator_database(
        state_dir,
        XMR_ACTUATOR_DATABASE_FILE_V1,
        creating,
        f6_paths_v8.is_some(),
    )?;
    Ok(ValidatedProductionLayoutV1 {
        state_dir: state_dir.to_path_buf(),
        paths,
        contracts_transport_identity_store,
        contracts_budget_policy,
        f6_paths_v4,
        contracts_bootstrap,
        bitcoin_prebroadcast_store_v7,
        f6_paths_v8,
        refund_arming_database,
        solana_actuator_database,
        xmr_actuator_database,
    })
}

/// Pins one optional per-chain actuator store: fixed name, validated parent
/// chain, and — unlike the journaled stores — presence that follows the
/// route's admitted shape, not the layout version. Creation requires the
/// leaf absent; a reopen accepts the honest absent state (the route never
/// composed that leg) or one canonical owner-only file.
fn derive_optional_chain_actuator_database(
    state_dir: &Path,
    file_name: &str,
    creating: bool,
    live_layout: bool,
) -> Result<Option<PathBuf>, ProductionConfigErrorV1> {
    if !live_layout {
        return Ok(None);
    }
    let path = state_dir.join(file_name);
    validate_parent_chain(state_dir, &path)?;
    if creating {
        require_managed_file_absent(&path)?;
    } else if path.exists() {
        validate_owner_file(&path, ProductionConfigErrorV1::RecoveryStateUnavailable)?;
    }
    Ok(Some(path))
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
    let f6_paths_v4 = match config.f6_paths_v4() {
        None => None,
        Some(references) => {
            let live_v8_or_later = config.f6_paths_v8().is_some();
            let paths =
                std::array::from_fn(|index| state_dir.join(references.paths[index].as_str()));
            let state = journal
                .stage_state(ProductionProvisioningStageV1::F6Authorities)
                .map_err(|_| ProductionConfigErrorV1::ProvisioningJournalRefused)?;
            for role in ProductionF6PathRoleV4::ALL {
                let path = &paths[role.index()];
                validate_parent_chain(state_dir, path)?;
                if live_v8_or_later && !role.retained_by_v8() {
                    require_absent(path, ProductionConfigErrorV1::RecoveryStateUnavailable)?;
                } else {
                    validate_managed_path_for_provisioning(
                        path,
                        ProductionPathKindV1::ManagedFile,
                        state,
                    )?;
                }
            }
            Some(paths)
        }
    };
    let contracts_bootstrap = match config.contracts_bootstrap() {
        None => None,
        Some(relative) => {
            let path = state_dir.join(relative);
            validate_parent_chain(state_dir, &path)?;
            validate_input_file(&path)?;
            Some(path)
        }
    };
    let bitcoin_prebroadcast_store_v7 = match config.bitcoin_prebroadcast_store_v7() {
        None => None,
        Some(relative) => {
            let path = state_dir.join(relative);
            validate_parent_chain(state_dir, &path)?;
            validate_owner_directory(
                &path,
                ProductionConfigErrorV1::BitcoinPrebroadcastAuthorityUnavailable,
            )?;
            Some(path)
        }
    };
    let f6_paths_v8 = match config.f6_paths_v8() {
        None => None,
        Some(references) => {
            let paths =
                std::array::from_fn(|index| state_dir.join(references.paths[index].as_str()));
            let state = journal
                .stage_state(ProductionProvisioningStageV1::F6Authorities)
                .map_err(|_| ProductionConfigErrorV1::ProvisioningJournalRefused)?;
            for role in ProductionF6PathRoleV8::ALL {
                let path = &paths[role.index()];
                validate_parent_chain(state_dir, path)?;
                match role.kind() {
                    ProductionPathKindV1::ManagedFile => validate_managed_path_for_provisioning(
                        path,
                        ProductionPathKindV1::ManagedFile,
                        state,
                    )?,
                    ProductionPathKindV1::InputFile => validate_input_file(path)?,
                    ProductionPathKindV1::ManagedDirectory
                    | ProductionPathKindV1::ExistingAuthorityDirectory => {
                        return Err(ProductionConfigErrorV1::InvalidPathReference);
                    }
                }
            }
            authenticate_f6_bundle_file_v8(config, &paths)?;
            Some(paths)
        }
    };
    let refund_arming_database = if f6_paths_v8.is_some() {
        let path = state_dir.join(REFUND_ARMING_DATABASE_FILE_V1);
        validate_parent_chain(state_dir, &path)?;
        validate_managed_path_for_provisioning(
            &path,
            ProductionPathKindV1::ManagedFile,
            journal
                .stage_state(ProductionProvisioningStageV1::RefundArmingAuthority)
                .map_err(|_| ProductionConfigErrorV1::ProvisioningJournalRefused)?,
        )?;
        Some(path)
    } else {
        None
    };
    // The per-chain actuator stores are deliberately unjournaled: their
    // presence follows the route's admitted shape, and their own create/
    // reopen audits are the actuator crates' contract. Provisioning resume
    // only pins the name and the parent chain and accepts absent-or-owner.
    let solana_actuator_database = derive_optional_chain_actuator_database(
        state_dir,
        SOLANA_ACTUATOR_DATABASE_FILE_V1,
        false,
        f6_paths_v8.is_some(),
    )?;
    let xmr_actuator_database = derive_optional_chain_actuator_database(
        state_dir,
        XMR_ACTUATOR_DATABASE_FILE_V1,
        false,
        f6_paths_v8.is_some(),
    )?;
    Ok(ValidatedProductionLayoutV1 {
        state_dir: state_dir.to_path_buf(),
        paths,
        contracts_transport_identity_store,
        contracts_budget_policy,
        f6_paths_v4,
        contracts_bootstrap,
        bitcoin_prebroadcast_store_v7,
        f6_paths_v8,
        refund_arming_database,
        solana_actuator_database,
        xmr_actuator_database,
    })
}

fn authenticate_f6_bundle_file_v8(
    config: &ProductionBootstrapConfigV1,
    paths: &[PathBuf; PRODUCTION_F6_PATH_ROLE_COUNT_V8],
) -> Result<(), ProductionConfigErrorV1> {
    let expected = config
        .f6_authority_bundle_digest_v8()
        .ok_or(ProductionConfigErrorV1::InvalidPublicBinding)?;
    let bytes = read_owner_file_bounded(
        &paths[ProductionF6PathRoleV8::AuthorityBundleV7.index()],
        MAX_PRODUCTION_F6_AUTHORITY_BUNDLE_BYTES_V8,
        ProductionConfigErrorV1::InputArtifactUnavailable,
    )?;
    if production_f6_authority_bundle_digest_v8(&bytes)? != expected {
        return Err(ProductionConfigErrorV1::IntegrityMismatch);
    }
    Ok(())
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
    const CONTRACTS_BOOTSTRAP_PATH_V5: &str = "inputs/contracts-bootstrap.v1";
    const BITCOIN_PREBROADCAST_STORE_PATH_V7: &str = "inputs/bitcoin-prebroadcast";
    const F6_AUTHORITY_BUNDLE_PATH_V8: &str = "inputs/f6-authority-bundle.v7";
    const F6_AUTHORITY_BUNDLE_BYTES_V8: &[u8] = b"threshold-authenticated-f6-bundle-v7";
    const REFUND_ARMING_AUTHORITY_EPOCH_V9: u64 = 17;
    const EVM_INITIAL_MAX_FEE_PER_GAS_V10: u128 = 30_000_000_000;
    const EVM_INITIAL_MAX_PRIORITY_FEE_PER_GAS_V10: u128 = 2_000_000_000;
    const EVM_OBSERVATION_VALID_FOR_MS_V10: u64 = 60_000;
    const EVM_REMOTE_CUSTODY_LEASE_DURATION_MS_V10: u64 = 300_000;
    const GOLDEN_CREATE_V9_BLAKE2B256: &str =
        "7d48f1c0b50ec3499fbd57ba811bf27324b54c68057e08b9a05e157478d28c71";

    fn contracts_bootstrap_pins_v5() -> ProductionContractsBootstrapPinsV5 {
        ProductionContractsBootstrapPinsV5::new([0x81; 32], [0x82; 32]).unwrap()
    }

    const fn relay_authority_pins_v6() -> ProductionRelayAuthorityPinsV6 {
        ProductionRelayAuthorityPinsV6 {
            relay_database_id: [0x91; 32],
            upstream_sender_store_id: [0x92; 32],
            upstream_inbox_id: [0x93; 32],
            upstream_reassembler_id: [0x94; 32],
            downstream_sender_store_id: [0x95; 32],
            downstream_inbox_id: [0x96; 32],
            downstream_reassembler_id: [0x97; 32],
            relay_max_envelopes: 65_536,
            sender_max_envelopes: 32_768,
            inbox_max_entries: 16_384,
            frame_max_messages: 256,
            frame_max_active_bytes: 67_108_864,
            frame_max_active_chunks: 8_448,
        }
    }

    fn bitcoin_prebroadcast_pins_v7() -> ProductionBitcoinPrebroadcastPinsV7 {
        ProductionBitcoinPrebroadcastPinsV7 {
            leg: LegIdV1::Downstream,
            settlement_id: [0xa1; 32],
            session_id: [0xa2; 32],
            terms_digest: pins().downstream_terms_digest,
            deployment_digest: [0xa3; 32],
            route_binding: [0xa4; 32],
            plan_digest: [0xa5; 32],
            receipt_digest: [0xa6; 32],
            contract_script_pubkey_digest: [0xa7; 32],
            claim_destination_script_pubkey_digest: [0xa8; 32],
            refund_destination_script_pubkey_digest: [0xa9; 32],
            refund_key_xonly: [0xaa; 32],
            funding_template_hash: [0xab; 32],
            claim_template_hash: [0xac; 32],
            refund_template_hash: [0xad; 32],
        }
    }

    fn operational_policies_v10() -> ProductionOperationalPoliciesV10 {
        ProductionOperationalPoliciesV10::new(
            [0xb1; 32],
            [0xb2; 32],
            EVM_INITIAL_MAX_FEE_PER_GAS_V10,
            EVM_INITIAL_MAX_PRIORITY_FEE_PER_GAS_V10,
            EVM_OBSERVATION_VALID_FOR_MS_V10,
            EVM_REMOTE_CUSTODY_LEASE_DURATION_MS_V10,
        )
        .expect("canonical V10 operational policies")
    }

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

        fn config_v4(&self, mode: ProductionBootstrapModeV1) -> ProductionBootstrapConfigV1 {
            ProductionBootstrapConfigV1::from_parts_v4(
                mode,
                pins(),
                bounds(),
                ProductionPathReferencesV1::from_ordered(standard_paths()).unwrap(),
                IDENTITY_STORE_PATH_V2.to_owned(),
                BUDGET_POLICY_PATH_V3.to_owned(),
                ProductionF6PathReferencesV4::from_ordered(standard_f6_paths_v4()).unwrap(),
            )
            .unwrap()
        }

        fn config_v5(&self, mode: ProductionBootstrapModeV1) -> ProductionBootstrapConfigV1 {
            ProductionBootstrapConfigV1::from_parts_v5(
                mode,
                pins(),
                bounds(),
                ProductionPathReferencesV1::from_ordered(standard_paths()).unwrap(),
                ProductionFamilyInputsV5::new(
                    IDENTITY_STORE_PATH_V2.to_owned(),
                    BUDGET_POLICY_PATH_V3.to_owned(),
                    ProductionF6PathReferencesV4::from_ordered(standard_f6_paths_v4()).unwrap(),
                    CONTRACTS_BOOTSTRAP_PATH_V5.to_owned(),
                    contracts_bootstrap_pins_v5(),
                ),
            )
            .unwrap()
        }

        fn config_v6(&self, mode: ProductionBootstrapModeV1) -> ProductionBootstrapConfigV1 {
            config_v6_with(mode, relay_authority_pins_v6())
        }

        fn config_v7(&self, mode: ProductionBootstrapModeV1) -> ProductionBootstrapConfigV1 {
            config_v7_with(mode, bitcoin_prebroadcast_pins_v7())
        }

        fn config_v8(&self, mode: ProductionBootstrapModeV1) -> ProductionBootstrapConfigV1 {
            config_v8(mode, standard_f6_paths_v8()).expect("canonical V8 fixture")
        }

        fn config_v9(&self, mode: ProductionBootstrapModeV1) -> ProductionBootstrapConfigV1 {
            config_v9(
                mode,
                standard_f6_paths_v8(),
                REFUND_ARMING_AUTHORITY_EPOCH_V9,
            )
            .expect("canonical V9 fixture")
        }

        fn config_v10(&self, mode: ProductionBootstrapModeV1) -> ProductionBootstrapConfigV1 {
            config_v10(mode, operational_policies_v10()).expect("canonical V10 fixture")
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

        fn install_manifests_v4(&self) {
            write_owner_file(
                &self.root.join(PRODUCTION_CREATE_CONFIG_FILE_V4),
                &self
                    .config_v4(ProductionBootstrapModeV1::Create)
                    .canonical_bytes()
                    .unwrap(),
            );
            write_owner_file(
                &self.root.join(PRODUCTION_REOPEN_CONFIG_FILE_V4),
                &self
                    .config_v4(ProductionBootstrapModeV1::ReopenExisting)
                    .canonical_bytes()
                    .unwrap(),
            );
        }

        fn install_manifests_v5(&self) {
            write_owner_file(
                &self.root.join(PRODUCTION_CREATE_CONFIG_FILE_V5),
                &self
                    .config_v5(ProductionBootstrapModeV1::Create)
                    .canonical_bytes()
                    .unwrap(),
            );
            write_owner_file(
                &self.root.join(PRODUCTION_REOPEN_CONFIG_FILE_V5),
                &self
                    .config_v5(ProductionBootstrapModeV1::ReopenExisting)
                    .canonical_bytes()
                    .unwrap(),
            );
        }

        fn install_manifests_v6(&self) {
            write_owner_file(
                &self.root.join(PRODUCTION_CREATE_CONFIG_FILE_V6),
                &self
                    .config_v6(ProductionBootstrapModeV1::Create)
                    .canonical_bytes()
                    .unwrap(),
            );
            write_owner_file(
                &self.root.join(PRODUCTION_REOPEN_CONFIG_FILE_V6),
                &self
                    .config_v6(ProductionBootstrapModeV1::ReopenExisting)
                    .canonical_bytes()
                    .unwrap(),
            );
        }

        fn install_manifests_v7(&self) {
            write_owner_file(
                &self.root.join(PRODUCTION_CREATE_CONFIG_FILE_V7),
                &self
                    .config_v7(ProductionBootstrapModeV1::Create)
                    .canonical_bytes()
                    .unwrap(),
            );
            write_owner_file(
                &self.root.join(PRODUCTION_REOPEN_CONFIG_FILE_V7),
                &self
                    .config_v7(ProductionBootstrapModeV1::ReopenExisting)
                    .canonical_bytes()
                    .unwrap(),
            );
        }

        fn install_manifests_v8(&self) {
            write_owner_file(
                &self.root.join(PRODUCTION_CREATE_CONFIG_FILE_V8),
                &self
                    .config_v8(ProductionBootstrapModeV1::Create)
                    .canonical_bytes()
                    .unwrap(),
            );
            write_owner_file(
                &self.root.join(PRODUCTION_REOPEN_CONFIG_FILE_V8),
                &self
                    .config_v8(ProductionBootstrapModeV1::ReopenExisting)
                    .canonical_bytes()
                    .unwrap(),
            );
        }

        fn install_manifests_v9(&self) {
            write_owner_file(
                &self.root.join(PRODUCTION_CREATE_CONFIG_FILE_V9),
                &self
                    .config_v9(ProductionBootstrapModeV1::Create)
                    .canonical_bytes()
                    .unwrap(),
            );
            write_owner_file(
                &self.root.join(PRODUCTION_REOPEN_CONFIG_FILE_V9),
                &self
                    .config_v9(ProductionBootstrapModeV1::ReopenExisting)
                    .canonical_bytes()
                    .unwrap(),
            );
        }

        fn install_manifests_v10(&self) {
            write_owner_file(
                &self.root.join(PRODUCTION_CREATE_CONFIG_FILE_V10),
                &self
                    .config_v10(ProductionBootstrapModeV1::Create)
                    .canonical_bytes()
                    .unwrap(),
            );
            write_owner_file(
                &self.root.join(PRODUCTION_REOPEN_CONFIG_FILE_V10),
                &self
                    .config_v10(ProductionBootstrapModeV1::ReopenExisting)
                    .canonical_bytes()
                    .unwrap(),
            );
        }

        fn create_identity_authority(&self) {
            create_owner_dir(&self.root.join(IDENTITY_STORE_PATH_V2));
        }

        fn create_v4_inputs(&self) {
            self.create_identity_authority();
            write_owner_file(&self.root.join(BUDGET_POLICY_PATH_V3), b"budget-v4");
        }

        fn create_v5_inputs(&self) {
            self.create_v4_inputs();
            write_owner_file(
                &self.root.join(CONTRACTS_BOOTSTRAP_PATH_V5),
                b"contracts-bootstrap-v5",
            );
        }

        fn create_v7_inputs(&self) {
            self.create_v5_inputs();
            create_owner_dir(&self.root.join(BITCOIN_PREBROADCAST_STORE_PATH_V7));
        }

        fn create_v8_inputs(&self) {
            self.create_v7_inputs();
            write_owner_file(
                &self.root.join(F6_AUTHORITY_BUNDLE_PATH_V8),
                F6_AUTHORITY_BUNDLE_BYTES_V8,
            );
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

        fn create_f6_state_v4(&self) {
            for path in standard_f6_paths_v4() {
                write_owner_file(&self.root.join(path), b"f6-state-v4");
            }
        }

        fn create_retained_f6_state_v4_for_v8(&self) {
            let paths = standard_f6_paths_v4();
            for role in ProductionF6PathRoleV4::ALL {
                if role.retained_by_v8() {
                    write_owner_file(
                        &self.root.join(paths[role.index()].as_str()),
                        b"f6-state-v4-retained-by-v8",
                    );
                }
            }
        }

        fn create_f6_state_v8(&self) {
            for role in ProductionF6PathRoleV8::ALL {
                if role.kind() == ProductionPathKindV1::ManagedFile {
                    write_owner_file(
                        &self
                            .root
                            .join(standard_f6_paths_v8()[role.index()].as_str()),
                        b"f6-state-v8",
                    );
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

    fn standard_f6_paths_v4() -> [String; PRODUCTION_F6_PATH_ROLE_COUNT_V4] {
        [
            "state/solver-status.sqlite3",
            "state/upstream-pre-f6-time.sqlite3",
            "state/downstream-pre-f6-time.sqlite3",
            "state/upstream-f6-binding.log",
            "state/upstream-f6-receipts.sqlite3",
            "state/upstream-f6-candidates.log",
            "state/upstream-f6-attestation.sqlite3",
            "state/downstream-f6-binding.log",
            "state/downstream-f6-receipts.sqlite3",
            "state/downstream-f6-candidates.log",
            "state/downstream-f6-attestation.sqlite3",
        ]
        .map(str::to_owned)
    }

    fn standard_f6_paths_v8() -> [String; PRODUCTION_F6_PATH_ROLE_COUNT_V8] {
        [
            "state/upstream-f6-v7-status.sqlite3",
            "state/downstream-f6-v7-status.sqlite3",
            "state/upstream-f6-v7-time.sqlite3",
            "state/downstream-f6-v7-time.sqlite3",
            "state/upstream-f6-v7-candidate.sqlite3",
            "state/downstream-f6-v7-candidate.sqlite3",
            F6_AUTHORITY_BUNDLE_PATH_V8,
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

    /// Frozen canonical V4 encoding derived independently from the encoder.
    ///
    /// The body is the already-frozen V3 fixture with only the reviewed family
    /// header change and the eleven ordered F6 references appended. Its
    /// `config_digest` and whole-document BLAKE2b-256 were calculated from
    /// those literal bytes, not by calling `canonical_bytes`.
    const GOLDEN_CREATE_V4: &str = concat!(
        "DOM-INTEROPD-BOOTSTRAP-V4\n",
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
        "path_solver_status_store=state/solver-status.sqlite3\n",
        "path_upstream_pre_f6_time_store=state/upstream-pre-f6-time.sqlite3\n",
        "path_downstream_pre_f6_time_store=state/downstream-pre-f6-time.sqlite3\n",
        "path_upstream_f6_binding_log=state/upstream-f6-binding.log\n",
        "path_upstream_f6_receipt_store=state/upstream-f6-receipts.sqlite3\n",
        "path_upstream_f6_candidate_book=state/upstream-f6-candidates.log\n",
        "path_upstream_f6_candidate_attestation=state/upstream-f6-attestation.sqlite3\n",
        "path_downstream_f6_binding_log=state/downstream-f6-binding.log\n",
        "path_downstream_f6_receipt_store=state/downstream-f6-receipts.sqlite3\n",
        "path_downstream_f6_candidate_book=state/downstream-f6-candidates.log\n",
        "path_downstream_f6_candidate_attestation=state/downstream-f6-attestation.sqlite3\n",
        "config_digest=1d479b9f113c9ccebe4630aadee1094dc2accb2c1a80da62a1e285262c39a1e6\n",
        "end=1\n",
    );

    /// BLAKE2b-256 of the complete frozen V4 encoding above.
    const GOLDEN_CREATE_V4_BLAKE2B256: &str =
        "dd73439a7e165ff8c868d3d171e47ba1914334a222b6ebc60637bba8c8c4c495";

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

    fn redigest_canonical_body(body: &str) -> Vec<u8> {
        assert!(body.ends_with('\n'));
        assert!(!body.contains("config_digest="));
        assert!(!body.contains("end=1\n"));
        let digest = config_digest(body.as_bytes()).expect("test body digest");
        format!("{body}config_digest={}\n{END_V1}\n", encode_hex(&digest)).into_bytes()
    }

    fn v10_canonical_body() -> String {
        let encoded = config_v10(
            ProductionBootstrapModeV1::Create,
            operational_policies_v10(),
        )
        .expect("canonical V10 fixture")
        .canonical_bytes()
        .expect("V10 encodes");
        let text = String::from_utf8(encoded).expect("V10 is ASCII");
        text[..text.find("config_digest=").expect("V10 digest line")].to_owned()
    }

    fn frozen_v5_bytes_from_v4_golden() -> Vec<u8> {
        let v4_body_end = GOLDEN_CREATE_V4
            .find("config_digest=")
            .expect("V4 golden digest line");
        let v4_body = &GOLDEN_CREATE_V4[..v4_body_end];
        let inherited = v4_body.strip_prefix(HEADER_V4).expect("V4 golden header");
        let mut body = String::new();
        body.push_str(HEADER_V5);
        body.push_str(inherited);
        push_reference(
            &mut body,
            CONTRACTS_BOOTSTRAP_KEY_V5,
            CONTRACTS_BOOTSTRAP_PATH_V5,
        );
        write_digest(
            &mut body,
            CONTRACTS_BOOTSTRAP_COMMIT_DIGEST_KEY_V5,
            contracts_bootstrap_pins_v5().commit_stage_digest(),
        );
        write_digest(
            &mut body,
            CONTRACTS_BOOTSTRAP_REVEAL_DIGEST_KEY_V5,
            contracts_bootstrap_pins_v5().reveal_stage_digest(),
        );
        let digest = config_digest(body.as_bytes()).expect("V5 frozen body digest");
        write_digest(&mut body, "config_digest", digest);
        body.push_str(END_V1);
        body.push('\n');
        body.into_bytes()
    }

    const BUDGET_POLICY_PATH_V3: &str = "inputs/contracts-budget-policy";

    fn config_v6_with(
        mode: ProductionBootstrapModeV1,
        relay_authority_pins: ProductionRelayAuthorityPinsV6,
    ) -> ProductionBootstrapConfigV1 {
        try_config_v6(mode, relay_authority_pins).expect("the V6 fixture config is canonical")
    }

    fn try_config_v6(
        mode: ProductionBootstrapModeV1,
        relay_authority_pins: ProductionRelayAuthorityPinsV6,
    ) -> Result<ProductionBootstrapConfigV1, ProductionConfigErrorV1> {
        ProductionBootstrapConfigV1::from_parts_v6(
            mode,
            pins(),
            bounds(),
            ProductionPathReferencesV1::from_ordered(standard_paths())
                .expect("the fixture path set is canonical"),
            ProductionFamilyInputsV6::new(
                ProductionFamilyInputsV5::new(
                    IDENTITY_STORE_PATH_V2.to_owned(),
                    BUDGET_POLICY_PATH_V3.to_owned(),
                    ProductionF6PathReferencesV4::from_ordered(standard_f6_paths_v4())
                        .expect("the F6 fixture path set is canonical"),
                    CONTRACTS_BOOTSTRAP_PATH_V5.to_owned(),
                    contracts_bootstrap_pins_v5(),
                ),
                relay_authority_pins,
            ),
        )
    }

    fn config_v7_with(
        mode: ProductionBootstrapModeV1,
        bitcoin_prebroadcast_pins: ProductionBitcoinPrebroadcastPinsV7,
    ) -> ProductionBootstrapConfigV1 {
        try_config_v7(mode, bitcoin_prebroadcast_pins).expect("the V7 fixture config is canonical")
    }

    fn try_config_v7(
        mode: ProductionBootstrapModeV1,
        bitcoin_prebroadcast_pins: ProductionBitcoinPrebroadcastPinsV7,
    ) -> Result<ProductionBootstrapConfigV1, ProductionConfigErrorV1> {
        try_config_v7_at(
            mode,
            bitcoin_prebroadcast_pins,
            BITCOIN_PREBROADCAST_STORE_PATH_V7,
        )
    }

    fn try_config_v7_at(
        mode: ProductionBootstrapModeV1,
        bitcoin_prebroadcast_pins: ProductionBitcoinPrebroadcastPinsV7,
        bitcoin_prebroadcast_store: &str,
    ) -> Result<ProductionBootstrapConfigV1, ProductionConfigErrorV1> {
        ProductionBootstrapConfigV1::from_parts_v7(
            mode,
            pins(),
            bounds(),
            ProductionPathReferencesV1::from_ordered(standard_paths())
                .expect("the fixture path set is canonical"),
            ProductionFamilyInputsV7::new(
                ProductionFamilyInputsV6::new(
                    ProductionFamilyInputsV5::new(
                        IDENTITY_STORE_PATH_V2.to_owned(),
                        BUDGET_POLICY_PATH_V3.to_owned(),
                        ProductionF6PathReferencesV4::from_ordered(standard_f6_paths_v4())
                            .expect("the F6 fixture path set is canonical"),
                        CONTRACTS_BOOTSTRAP_PATH_V5.to_owned(),
                        contracts_bootstrap_pins_v5(),
                    ),
                    relay_authority_pins_v6(),
                ),
                bitcoin_prebroadcast_store.to_owned(),
                bitcoin_prebroadcast_pins,
            ),
        )
    }

    fn config_v8(
        mode: ProductionBootstrapModeV1,
        f6_paths: [String; PRODUCTION_F6_PATH_ROLE_COUNT_V8],
    ) -> Result<ProductionBootstrapConfigV1, ProductionConfigErrorV1> {
        ProductionBootstrapConfigV1::from_parts_v8(
            mode,
            pins(),
            bounds(),
            ProductionPathReferencesV1::from_ordered(standard_paths())?,
            ProductionFamilyInputsV8::new(
                ProductionFamilyInputsV7::new(
                    ProductionFamilyInputsV6::new(
                        ProductionFamilyInputsV5::new(
                            IDENTITY_STORE_PATH_V2.to_owned(),
                            BUDGET_POLICY_PATH_V3.to_owned(),
                            ProductionF6PathReferencesV4::from_ordered(standard_f6_paths_v4())?,
                            CONTRACTS_BOOTSTRAP_PATH_V5.to_owned(),
                            contracts_bootstrap_pins_v5(),
                        ),
                        relay_authority_pins_v6(),
                    ),
                    BITCOIN_PREBROADCAST_STORE_PATH_V7.to_owned(),
                    bitcoin_prebroadcast_pins_v7(),
                ),
                ProductionF6PathReferencesV8::from_ordered(f6_paths)?,
                production_f6_authority_bundle_digest_v8(F6_AUTHORITY_BUNDLE_BYTES_V8)?,
            ),
        )
    }

    fn config_v9(
        mode: ProductionBootstrapModeV1,
        f6_paths: [String; PRODUCTION_F6_PATH_ROLE_COUNT_V8],
        refund_arming_authority_epoch: u64,
    ) -> Result<ProductionBootstrapConfigV1, ProductionConfigErrorV1> {
        ProductionBootstrapConfigV1::from_parts_v9(
            mode,
            pins(),
            bounds(),
            ProductionPathReferencesV1::from_ordered(standard_paths())?,
            ProductionFamilyInputsV9::new(
                ProductionFamilyInputsV8::new(
                    ProductionFamilyInputsV7::new(
                        ProductionFamilyInputsV6::new(
                            ProductionFamilyInputsV5::new(
                                IDENTITY_STORE_PATH_V2.to_owned(),
                                BUDGET_POLICY_PATH_V3.to_owned(),
                                ProductionF6PathReferencesV4::from_ordered(standard_f6_paths_v4())?,
                                CONTRACTS_BOOTSTRAP_PATH_V5.to_owned(),
                                contracts_bootstrap_pins_v5(),
                            ),
                            relay_authority_pins_v6(),
                        ),
                        BITCOIN_PREBROADCAST_STORE_PATH_V7.to_owned(),
                        bitcoin_prebroadcast_pins_v7(),
                    ),
                    ProductionF6PathReferencesV8::from_ordered(f6_paths)?,
                    production_f6_authority_bundle_digest_v8(F6_AUTHORITY_BUNDLE_BYTES_V8)?,
                ),
                refund_arming_authority_epoch,
            ),
        )
    }

    fn config_v10(
        mode: ProductionBootstrapModeV1,
        operational_policies: ProductionOperationalPoliciesV10,
    ) -> Result<ProductionBootstrapConfigV1, ProductionConfigErrorV1> {
        ProductionBootstrapConfigV1::from_parts_v10(
            mode,
            pins(),
            bounds(),
            ProductionPathReferencesV1::from_ordered(standard_paths())?,
            ProductionFamilyInputsV10::new(
                ProductionFamilyInputsV9::new(
                    ProductionFamilyInputsV8::new(
                        ProductionFamilyInputsV7::new(
                            ProductionFamilyInputsV6::new(
                                ProductionFamilyInputsV5::new(
                                    IDENTITY_STORE_PATH_V2.to_owned(),
                                    BUDGET_POLICY_PATH_V3.to_owned(),
                                    ProductionF6PathReferencesV4::from_ordered(
                                        standard_f6_paths_v4(),
                                    )?,
                                    CONTRACTS_BOOTSTRAP_PATH_V5.to_owned(),
                                    contracts_bootstrap_pins_v5(),
                                ),
                                relay_authority_pins_v6(),
                            ),
                            BITCOIN_PREBROADCAST_STORE_PATH_V7.to_owned(),
                            bitcoin_prebroadcast_pins_v7(),
                        ),
                        ProductionF6PathReferencesV8::from_ordered(standard_f6_paths_v8())?,
                        production_f6_authority_bundle_digest_v8(F6_AUTHORITY_BUNDLE_BYTES_V8)?,
                    ),
                    REFUND_ARMING_AUTHORITY_EPOCH_V9,
                ),
                operational_policies,
            ),
        )
    }

    fn set_relay_authority_id(
        pins: &mut ProductionRelayAuthorityPinsV6,
        index: usize,
        value: [u8; 32],
    ) {
        match index {
            0 => pins.relay_database_id = value,
            1 => pins.upstream_sender_store_id = value,
            2 => pins.upstream_inbox_id = value,
            3 => pins.upstream_reassembler_id = value,
            4 => pins.downstream_sender_store_id = value,
            5 => pins.downstream_inbox_id = value,
            6 => pins.downstream_reassembler_id = value,
            _ => panic!("invalid Relay authority index"),
        }
    }

    fn golden_create_config_v6() -> ProductionBootstrapConfigV1 {
        config_v6_with(ProductionBootstrapModeV1::Create, relay_authority_pins_v6())
    }

    fn golden_create_config_v7() -> ProductionBootstrapConfigV1 {
        config_v7_with(
            ProductionBootstrapModeV1::Create,
            bitcoin_prebroadcast_pins_v7(),
        )
    }

    fn golden_create_config_v8() -> ProductionBootstrapConfigV1 {
        config_v8(ProductionBootstrapModeV1::Create, standard_f6_paths_v8())
            .expect("the V8 fixture config is canonical")
    }

    fn golden_create_config_v9() -> ProductionBootstrapConfigV1 {
        config_v9(
            ProductionBootstrapModeV1::Create,
            standard_f6_paths_v8(),
            REFUND_ARMING_AUTHORITY_EPOCH_V9,
        )
        .expect("the V9 fixture config is canonical")
    }

    fn golden_create_config_v5() -> ProductionBootstrapConfigV1 {
        ProductionBootstrapConfigV1::from_parts_v5(
            ProductionBootstrapModeV1::Create,
            pins(),
            bounds(),
            ProductionPathReferencesV1::from_ordered(standard_paths())
                .expect("the fixture path set is canonical"),
            ProductionFamilyInputsV5::new(
                IDENTITY_STORE_PATH_V2.to_owned(),
                BUDGET_POLICY_PATH_V3.to_owned(),
                ProductionF6PathReferencesV4::from_ordered(standard_f6_paths_v4())
                    .expect("the F6 fixture path set is canonical"),
                CONTRACTS_BOOTSTRAP_PATH_V5.to_owned(),
                contracts_bootstrap_pins_v5(),
            ),
        )
        .expect("the V5 fixture config is canonical")
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
            ProductionF6PathReferencesV4::from_ordered(standard_f6_paths_v4())
                .expect("the F6 fixture path set is canonical"),
        )
        .expect("the V4 fixture config is canonical")
    }

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
    fn v8_f6_bundle_digest_has_a_fixed_kat_and_strict_bounds() {
        assert_eq!(
            encode_hex(
                &production_f6_authority_bundle_digest_v8(F6_AUTHORITY_BUNDLE_BYTES_V8)
                    .expect("fixture bundle is bounded")
            ),
            "861bd513c266d76a014584eb823f8acd04c8f22e06e98d1b784b664eb2e9f208"
        );
        assert_eq!(
            production_f6_authority_bundle_digest_v8(&[]),
            Err(ProductionConfigErrorV1::InvalidPublicBinding)
        );
        assert_eq!(
            production_f6_authority_bundle_digest_v8(&vec![
                0x41;
                MAX_PRODUCTION_F6_AUTHORITY_BUNDLE_BYTES_V8
                    as usize
                    + 1
            ]),
            Err(ProductionConfigErrorV1::InvalidPublicBinding)
        );
    }

    #[test]
    fn v9_round_trip_pins_only_the_static_refund_authority_epoch() {
        let config = golden_create_config_v9();
        let encoded = config.canonical_bytes().expect("V9 encodes");
        let decoded = ProductionBootstrapConfigV1::decode_canonical_v9_for_mode(
            &encoded,
            ProductionBootstrapModeV1::Create,
        )
        .expect("exact V9 decodes");
        assert_eq!(decoded, config);
        assert_eq!(PRODUCTION_PATH_ROLE_COUNT_V9, PRODUCTION_PATH_ROLE_COUNT_V8);
        assert_eq!(encoded.split(|byte| *byte == b'\n').count() - 1, 115);
        assert_eq!(
            decoded.refund_arming_authority_epoch_v9(),
            Some(REFUND_ARMING_AUTHORITY_EPOCH_V9)
        );
        assert_eq!(
            golden_create_config_v8().refund_arming_authority_epoch_v9(),
            None
        );
        let text = std::str::from_utf8(&encoded).expect("V9 is ASCII");
        assert_eq!(
            text.matches("refund_arming_authority_epoch=17\n").count(),
            1
        );
        assert!(!text.contains("fencing_epoch"));

        let changed_epoch = config_v9(
            ProductionBootstrapModeV1::Create,
            standard_f6_paths_v8(),
            REFUND_ARMING_AUTHORITY_EPOCH_V9 + 1,
        )
        .expect("the alternate V9 epoch is canonical")
        .canonical_bytes()
        .expect("the alternate V9 config encodes");
        let changed_text = std::str::from_utf8(&changed_epoch).expect("V9 is ASCII");
        let digest = text
            .lines()
            .find(|line| line.starts_with("config_digest="))
            .expect("V9 has a config digest");
        let changed_digest = changed_text
            .lines()
            .find(|line| line.starts_with("config_digest="))
            .expect("V9 has a config digest");
        assert_ne!(digest, changed_digest);
    }

    #[test]
    fn production_config_v9_hash_golden_is_frozen() {
        let encoded = golden_create_config_v9()
            .canonical_bytes()
            .expect("V9 encodes");
        assert_eq!(golden_blake2b256(&encoded), GOLDEN_CREATE_V9_BLAKE2B256);
    }

    #[test]
    fn v10_round_trip_authenticates_directional_relay_and_evm_policies() {
        let config = config_v10(
            ProductionBootstrapModeV1::Create,
            operational_policies_v10(),
        )
        .expect("canonical V10 fixture");
        let encoded = config.canonical_bytes().expect("V10 encodes");
        let decoded = ProductionBootstrapConfigV1::decode_canonical_v10_for_mode(
            &encoded,
            ProductionBootstrapModeV1::Create,
        )
        .expect("exact V10 decodes");
        assert_eq!(decoded, config);
        assert_eq!(
            PRODUCTION_PATH_ROLE_COUNT_V10,
            PRODUCTION_PATH_ROLE_COUNT_V9
        );
        assert_eq!(encoded.split(|byte| *byte == b'\n').count() - 1, 121);
        assert_eq!(
            decoded.operational_policies_v10(),
            Some(operational_policies_v10())
        );
        let policies = decoded.operational_policies_v10().unwrap();
        assert_eq!(policies.upstream_remote_relay_database_id(), [0xb1; 32]);
        assert_eq!(policies.downstream_remote_relay_database_id(), [0xb2; 32]);
        assert_eq!(
            policies.evm_initial_max_fee_per_gas(),
            EVM_INITIAL_MAX_FEE_PER_GAS_V10
        );
        assert_eq!(
            policies.evm_initial_max_priority_fee_per_gas(),
            EVM_INITIAL_MAX_PRIORITY_FEE_PER_GAS_V10
        );
        assert_eq!(
            policies.evm_observation_valid_for_ms(),
            EVM_OBSERVATION_VALID_FOR_MS_V10
        );
        assert_eq!(
            policies.evm_remote_custody_lease_duration_ms(),
            EVM_REMOTE_CUSTODY_LEASE_DURATION_MS_V10
        );
        assert!(ProductionBootstrapConfigV1::decode_canonical_v9_for_mode(
            &encoded,
            ProductionBootstrapModeV1::Create,
        )
        .is_err());
        assert!(ProductionBootstrapConfigV1::decode_canonical_v10_for_mode(
            &golden_create_config_v9().canonical_bytes().unwrap(),
            ProductionBootstrapModeV1::Create,
        )
        .is_err());
    }

    #[test]
    fn v10_refuses_missing_zero_transplanted_and_cross_companion_swapped_relay_ids() {
        assert_eq!(
            ProductionOperationalPoliciesV10::new(
                ZERO_DIGEST,
                [0xb2; 32],
                EVM_INITIAL_MAX_FEE_PER_GAS_V10,
                EVM_INITIAL_MAX_PRIORITY_FEE_PER_GAS_V10,
                EVM_OBSERVATION_VALID_FOR_MS_V10,
                EVM_REMOTE_CUSTODY_LEASE_DURATION_MS_V10,
            ),
            Err(ProductionConfigErrorV1::InvalidPublicBinding)
        );
        assert_eq!(
            ProductionOperationalPoliciesV10::new(
                [0xb1; 32],
                [0xb1; 32],
                EVM_INITIAL_MAX_FEE_PER_GAS_V10,
                EVM_INITIAL_MAX_PRIORITY_FEE_PER_GAS_V10,
                EVM_OBSERVATION_VALID_FOR_MS_V10,
                EVM_REMOTE_CUSTODY_LEASE_DURATION_MS_V10,
            ),
            Err(ProductionConfigErrorV1::InvalidPublicBinding)
        );

        for transplanted in [
            pins().route_id,
            contracts_bootstrap_pins_v5().commit_stage_digest(),
            relay_authority_pins_v6().relay_database_id,
            bitcoin_prebroadcast_pins_v7().receipt_digest,
            production_f6_authority_bundle_digest_v8(F6_AUTHORITY_BUNDLE_BYTES_V8).unwrap(),
        ] {
            let policies = ProductionOperationalPoliciesV10::new(
                transplanted,
                [0xb2; 32],
                EVM_INITIAL_MAX_FEE_PER_GAS_V10,
                EVM_INITIAL_MAX_PRIORITY_FEE_PER_GAS_V10,
                EVM_OBSERVATION_VALID_FOR_MS_V10,
                EVM_REMOTE_CUSTODY_LEASE_DURATION_MS_V10,
            )
            .unwrap();
            assert_eq!(
                config_v10(ProductionBootstrapModeV1::Create, policies),
                Err(ProductionConfigErrorV1::InvalidPublicBinding)
            );
        }

        let encoded = config_v10(
            ProductionBootstrapModeV1::Create,
            operational_policies_v10(),
        )
        .unwrap()
        .canonical_bytes()
        .unwrap();
        let missing = String::from_utf8(encoded)
            .unwrap()
            .replacen(
                "upstream_remote_relay_database_id=b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1\n",
                "",
                1,
            );
        assert!(ProductionBootstrapConfigV1::decode_canonical_v10_for_mode(
            missing.as_bytes(),
            ProductionBootstrapModeV1::Create,
        )
        .is_err());

        let fixture = Fixture::new();
        fixture.create_v8_inputs();
        let swapped = ProductionOperationalPoliciesV10::new(
            [0xb2; 32],
            [0xb1; 32],
            EVM_INITIAL_MAX_FEE_PER_GAS_V10,
            EVM_INITIAL_MAX_PRIORITY_FEE_PER_GAS_V10,
            EVM_OBSERVATION_VALID_FOR_MS_V10,
            EVM_REMOTE_CUSTODY_LEASE_DURATION_MS_V10,
        )
        .unwrap();
        write_owner_file(
            &fixture.root.join(PRODUCTION_CREATE_CONFIG_FILE_V10),
            &fixture
                .config_v10(ProductionBootstrapModeV1::Create)
                .canonical_bytes()
                .unwrap(),
        );
        write_owner_file(
            &fixture.root.join(PRODUCTION_REOPEN_CONFIG_FILE_V10),
            &config_v10(ProductionBootstrapModeV1::ReopenExisting, swapped)
                .unwrap()
                .canonical_bytes()
                .unwrap(),
        );
        assert_eq!(
            load_production_create_bootstrap_v10(&fixture.root).unwrap_err(),
            ProductionConfigErrorV1::CompanionMismatch
        );
        assert_eq!(
            load_production_reopen_bootstrap_v10(&fixture.root).unwrap_err(),
            ProductionConfigErrorV1::CompanionMismatch
        );
    }

    #[test]
    fn v10_refuses_invalid_fees_and_actuator_incompatible_durations() {
        let policy = |max_fee, priority_fee, observation, custody| {
            ProductionOperationalPoliciesV10::new(
                [0xb1; 32],
                [0xb2; 32],
                max_fee,
                priority_fee,
                observation,
                custody,
            )
        };
        for refused in [
            policy(0, 1, 1, 1),
            policy(1, 0, 1, 1),
            policy(1, 2, 1, 1),
            policy(1, 1, 0, 1),
            policy(1, 1, MAX_EVM_OBSERVATION_VALID_FOR_MS_V10 + 1, 1),
            policy(1, 1, 1, 0),
            policy(1, 1, 1, MAX_EVM_REMOTE_CUSTODY_LEASE_DURATION_MS_V10 + 1),
        ] {
            assert_eq!(refused, Err(ProductionConfigErrorV1::InvalidRuntimeBounds));
        }
        let maximum_u128_policy = policy(
            u128::MAX,
            u128::MAX,
            MAX_EVM_OBSERVATION_VALID_FOR_MS_V10,
            MAX_EVM_REMOTE_CUSTODY_LEASE_DURATION_MS_V10,
        )
        .expect("the config boundary has no deployment caps to invent");
        assert_eq!(maximum_u128_policy.evm_initial_max_fee_per_gas(), u128::MAX);
        #[cfg(feature = "production")]
        {
            assert_eq!(
                maximum_u128_policy.evm_fees_with_caps(
                    EVM_INITIAL_MAX_FEE_PER_GAS_V10,
                    EVM_INITIAL_MAX_PRIORITY_FEE_PER_GAS_V10,
                ),
                Err(ProductionConfigErrorV1::InvalidRuntimeBounds)
            );
            assert_eq!(
                operational_policies_v10().evm_fees_with_caps(
                    EVM_INITIAL_MAX_FEE_PER_GAS_V10 - 1,
                    EVM_INITIAL_MAX_PRIORITY_FEE_PER_GAS_V10,
                ),
                Err(ProductionConfigErrorV1::InvalidRuntimeBounds)
            );
            assert_eq!(
                operational_policies_v10().evm_fees_with_caps(
                    EVM_INITIAL_MAX_FEE_PER_GAS_V10,
                    EVM_INITIAL_MAX_PRIORITY_FEE_PER_GAS_V10 - 1,
                ),
                Err(ProductionConfigErrorV1::InvalidRuntimeBounds)
            );
            let fees = operational_policies_v10()
                .evm_fees_with_caps(
                    EVM_INITIAL_MAX_FEE_PER_GAS_V10,
                    EVM_INITIAL_MAX_PRIORITY_FEE_PER_GAS_V10,
                )
                .expect("fees at exact authenticated caps");
            assert_eq!(fees.max_fee_per_gas(), EVM_INITIAL_MAX_FEE_PER_GAS_V10);
            assert_eq!(
                fees.max_priority_fee_per_gas(),
                EVM_INITIAL_MAX_PRIORITY_FEE_PER_GAS_V10
            );
        }
    }

    #[test]
    fn v10_decoder_refuses_noncanonical_u128_duplicates_reordering_and_field_swaps() {
        let canonical = v10_canonical_body();
        let decode = |body: String| {
            ProductionBootstrapConfigV1::decode_canonical_v10_for_mode(
                &redigest_canonical_body(&body),
                ProductionBootstrapModeV1::Create,
            )
        };
        for malformed_value in [
            "030000000000",
            "+30000000000",
            "340282366920938463463374607431768211456",
        ] {
            let malformed = canonical.replacen(
                "evm_initial_max_fee_per_gas=30000000000\n",
                &format!("evm_initial_max_fee_per_gas={malformed_value}\n"),
                1,
            );
            assert_ne!(malformed, canonical);
            assert_eq!(
                decode(malformed).unwrap_err(),
                ProductionConfigErrorV1::InvalidCanonicalEncoding
            );
        }

        let duplicate = canonical.replacen(
            "evm_initial_max_fee_per_gas=30000000000\n",
            concat!(
                "evm_initial_max_fee_per_gas=30000000000\n",
                "evm_initial_max_fee_per_gas=30000000000\n"
            ),
            1,
        );
        assert_eq!(
            decode(duplicate).unwrap_err(),
            ProductionConfigErrorV1::InvalidCanonicalEncoding
        );

        let reordered = canonical.replacen(
            concat!(
                "evm_initial_max_fee_per_gas=30000000000\n",
                "evm_initial_max_priority_fee_per_gas=2000000000\n"
            ),
            concat!(
                "evm_initial_max_priority_fee_per_gas=2000000000\n",
                "evm_initial_max_fee_per_gas=30000000000\n"
            ),
            1,
        );
        assert_ne!(reordered, canonical);
        assert_eq!(
            decode(reordered).unwrap_err(),
            ProductionConfigErrorV1::InvalidCanonicalEncoding
        );

        let swapped_fields = canonical.replacen(
            concat!(
                "upstream_remote_relay_database_id=b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1\n",
                "downstream_remote_relay_database_id=b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2\n"
            ),
            concat!(
                "downstream_remote_relay_database_id=b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2\n",
                "upstream_remote_relay_database_id=b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1\n"
            ),
            1,
        );
        assert_ne!(swapped_fields, canonical);
        assert_eq!(
            decode(swapped_fields).unwrap_err(),
            ProductionConfigErrorV1::InvalidCanonicalEncoding
        );
    }

    #[test]
    fn v10_create_and_reopen_loaders_bind_the_same_companion() {
        let fixture = Fixture::new();
        fixture.create_v8_inputs();
        fixture.install_manifests_v10();
        let create =
            load_production_create_bootstrap_v10(&fixture.root).expect("strict V10 create layout");
        assert_eq!(
            create.config().operational_policies_v10(),
            Some(operational_policies_v10())
        );
        #[cfg(feature = "production")]
        assert_ne!(
            provisioning_binding_for_v10_bootstrap(&create).expect("V10 provisioning binding"),
            ZERO_DIGEST
        );

        fixture.create_managed_state();
        fixture.create_retained_f6_state_v4_for_v8();
        fixture.create_f6_state_v8();
        write_owner_file(
            &fixture.root.join(REFUND_ARMING_DATABASE_FILE_V1),
            b"refund-arming-state-v1",
        );
        let reopen =
            load_production_reopen_bootstrap_v10(&fixture.root).expect("strict V10 reopen layout");
        assert_eq!(
            reopen.config().operational_policies_v10(),
            Some(operational_policies_v10())
        );
    }

    #[test]
    fn v9_refuses_missing_zero_and_cross_companion_epoch_transplants() {
        assert_eq!(
            config_v9(ProductionBootstrapModeV1::Create, standard_f6_paths_v8(), 0,).unwrap_err(),
            ProductionConfigErrorV1::InvalidPublicBinding
        );

        let encoded = golden_create_config_v9().canonical_bytes().unwrap();
        let text = String::from_utf8(encoded).expect("V9 is ASCII");
        let missing = text.replacen("refund_arming_authority_epoch=17\n", "", 1);
        assert!(ProductionBootstrapConfigV1::decode_canonical_v9_for_mode(
            missing.as_bytes(),
            ProductionBootstrapModeV1::Create,
        )
        .is_err());
        assert!(ProductionBootstrapConfigV1::decode_canonical_v8_for_mode(
            text.as_bytes(),
            ProductionBootstrapModeV1::Create,
        )
        .is_err());
        assert!(ProductionBootstrapConfigV1::decode_canonical_v9_for_mode(
            &golden_create_config_v8().canonical_bytes().unwrap(),
            ProductionBootstrapModeV1::Create,
        )
        .is_err());

        let fixture = Fixture::new();
        fixture.create_v8_inputs();
        write_owner_file(
            &fixture.root.join(PRODUCTION_CREATE_CONFIG_FILE_V9),
            &config_v9(
                ProductionBootstrapModeV1::Create,
                standard_f6_paths_v8(),
                REFUND_ARMING_AUTHORITY_EPOCH_V9,
            )
            .unwrap()
            .canonical_bytes()
            .unwrap(),
        );
        write_owner_file(
            &fixture.root.join(PRODUCTION_REOPEN_CONFIG_FILE_V9),
            &config_v9(
                ProductionBootstrapModeV1::ReopenExisting,
                standard_f6_paths_v8(),
                REFUND_ARMING_AUTHORITY_EPOCH_V9 + 1,
            )
            .unwrap()
            .canonical_bytes()
            .unwrap(),
        );
        assert_eq!(
            load_production_create_bootstrap_v9(&fixture.root).unwrap_err(),
            ProductionConfigErrorV1::CompanionMismatch
        );
    }

    #[test]
    fn v1_through_v8_remain_exactly_decodable_by_their_frozen_family() {
        let v1 = golden_create_config();
        assert_eq!(
            ProductionBootstrapConfigV1::decode_canonical_for_mode(
                &v1.canonical_bytes().unwrap(),
                ProductionBootstrapModeV1::Create,
            )
            .unwrap(),
            v1
        );
        let v2 = golden_create_config_v2();
        assert_eq!(
            ProductionBootstrapConfigV1::decode_canonical_v2_for_mode(
                &v2.canonical_bytes().unwrap(),
                ProductionBootstrapModeV1::Create,
            )
            .unwrap(),
            v2
        );
        let v3 = golden_create_config_v3();
        assert_eq!(
            ProductionBootstrapConfigV1::decode_canonical_v3_for_mode(
                &v3.canonical_bytes().unwrap(),
                ProductionBootstrapModeV1::Create,
            )
            .unwrap(),
            v3
        );
        let v4 = golden_create_config_v4();
        assert_eq!(
            ProductionBootstrapConfigV1::decode_canonical_v4_for_mode(
                &v4.canonical_bytes().unwrap(),
                ProductionBootstrapModeV1::Create,
            )
            .unwrap(),
            v4
        );
        let v5 = golden_create_config_v5();
        assert_eq!(
            ProductionBootstrapConfigV1::decode_canonical_v5_for_mode(
                &v5.canonical_bytes().unwrap(),
                ProductionBootstrapModeV1::Create,
            )
            .unwrap(),
            v5
        );
        let v6 = golden_create_config_v6();
        assert_eq!(
            ProductionBootstrapConfigV1::decode_canonical_v6_for_mode(
                &v6.canonical_bytes().unwrap(),
                ProductionBootstrapModeV1::Create,
            )
            .unwrap(),
            v6
        );
        let v7 = golden_create_config_v7();
        assert_eq!(
            ProductionBootstrapConfigV1::decode_canonical_v7_for_mode(
                &v7.canonical_bytes().unwrap(),
                ProductionBootstrapModeV1::Create,
            )
            .unwrap(),
            v7
        );
        let v8 = golden_create_config_v8();
        assert_eq!(
            ProductionBootstrapConfigV1::decode_canonical_v8_for_mode(
                &v8.canonical_bytes().unwrap(),
                ProductionBootstrapModeV1::Create,
            )
            .unwrap(),
            v8
        );
    }

    #[test]
    fn v9_recovery_layout_retains_the_exact_v8_graph_and_refund_database() {
        let fixture = Fixture::new();
        fixture.create_v8_inputs();
        fixture.install_manifests_v9();
        let created =
            load_production_create_bootstrap_v9(&fixture.root).expect("strict V9 create layout");
        assert_eq!(
            created.config().refund_arming_authority_epoch_v9(),
            Some(REFUND_ARMING_AUTHORITY_EPOCH_V9)
        );
        fixture.create_managed_state();
        fixture.create_retained_f6_state_v4_for_v8();
        fixture.create_f6_state_v8();
        write_owner_file(
            &fixture.root.join(REFUND_ARMING_DATABASE_FILE_V1),
            b"refund-arming-state-v1",
        );
        let recovered =
            load_production_reopen_bootstrap_v9(&fixture.root).expect("strict V9 recovery layout");
        assert_eq!(
            recovered.config().refund_arming_authority_epoch_v9(),
            Some(REFUND_ARMING_AUTHORITY_EPOCH_V9)
        );
        assert_eq!(
            recovered.layout().refund_arming_database(),
            Some(fixture.root.join(REFUND_ARMING_DATABASE_FILE_V1).as_path())
        );
        for role in ProductionF6PathRoleV8::ALL {
            let expected = fixture
                .root
                .join(standard_f6_paths_v8()[role.index()].as_str());
            assert_eq!(
                recovered.layout().f6_path_v8(role),
                Some(expected.as_path())
            );
        }
    }

    #[test]
    fn v8_round_trip_is_v7_plus_exactly_six_stores_and_one_bundle() {
        let config = golden_create_config_v8();
        let encoded = config.canonical_bytes().expect("V8 encodes");
        let decoded = ProductionBootstrapConfigV1::decode_canonical_v8_for_mode(
            &encoded,
            ProductionBootstrapModeV1::Create,
        )
        .expect("exact V8 decodes");
        assert!(decoded == config);
        assert_eq!(PRODUCTION_PATH_ROLE_COUNT_V8, 50);
        assert_eq!(encoded.split(|byte| *byte == b'\n').count() - 1, 114);
        for role in ProductionF6PathRoleV8::ALL {
            assert_eq!(
                decoded.f6_paths_v8().map(|paths| paths.get(role)),
                Some(Path::new(&standard_f6_paths_v8()[role.index()]))
            );
        }
        assert_eq!(
            decoded.f6_authority_bundle_digest_v8(),
            Some(
                production_f6_authority_bundle_digest_v8(F6_AUTHORITY_BUNDLE_BYTES_V8)
                    .expect("fixture digest")
            )
        );
        let text = std::str::from_utf8(&encoded).expect("V8 is ASCII");
        assert!(!text.contains("socket"));
        assert!(!text.contains("endpoint"));
        assert!(!text.contains("credential"));
        assert!(!text.contains("allow"));
    }

    #[test]
    fn v8_has_no_family_fallback_and_refuses_missing_or_trailing_fields() {
        let v8 = golden_create_config_v8().canonical_bytes().unwrap();
        for older in [
            ProductionBootstrapConfigV1::decode_canonical_for_mode(
                &v8,
                ProductionBootstrapModeV1::Create,
            ),
            ProductionBootstrapConfigV1::decode_canonical_v4_for_mode(
                &v8,
                ProductionBootstrapModeV1::Create,
            ),
            ProductionBootstrapConfigV1::decode_canonical_v6_for_mode(
                &v8,
                ProductionBootstrapModeV1::Create,
            ),
            ProductionBootstrapConfigV1::decode_canonical_v7_for_mode(
                &v8,
                ProductionBootstrapModeV1::Create,
            ),
        ] {
            assert!(older.is_err());
        }
        assert!(ProductionBootstrapConfigV1::decode_canonical_v8_for_mode(
            &golden_create_config_v7().canonical_bytes().unwrap(),
            ProductionBootstrapModeV1::Create,
        )
        .is_err());

        let text = String::from_utf8(v8).expect("V8 is ASCII");
        let missing = text.replacen(
            "path_upstream_f6_v7_status_store=state/upstream-f6-v7-status.sqlite3\n",
            "",
            1,
        );
        assert!(ProductionBootstrapConfigV1::decode_canonical_v8_for_mode(
            missing.as_bytes(),
            ProductionBootstrapModeV1::Create,
        )
        .is_err());
        let trailing = format!("{text}unexpected=1\n");
        assert!(ProductionBootstrapConfigV1::decode_canonical_v8_for_mode(
            trailing.as_bytes(),
            ProductionBootstrapModeV1::Create,
        )
        .is_err());
    }

    #[test]
    fn v8_refuses_path_aliases_and_bundle_transplants_before_authority_open() {
        let mut aliases = standard_f6_paths_v8();
        aliases[1] = aliases[0].clone();
        assert_eq!(
            ProductionF6PathReferencesV8::from_ordered(aliases).unwrap_err(),
            ProductionConfigErrorV1::AmbiguousPathReference
        );

        let mut aliases_prior = standard_f6_paths_v8();
        aliases_prior[0] = standard_f6_paths_v4()[1].clone();
        assert_eq!(
            config_v8(ProductionBootstrapModeV1::Create, aliases_prior).unwrap_err(),
            ProductionConfigErrorV1::AmbiguousPathReference
        );

        let fixture = Fixture::new();
        fixture.create_v8_inputs();
        fixture.install_manifests_v8();
        load_production_create_bootstrap_v8(&fixture.root)
            .expect("the pinned bundle and absent managed stores are accepted");
        fs::write(
            fixture.root.join(F6_AUTHORITY_BUNDLE_PATH_V8),
            b"threshold-authenticated-f6-bundle-transplant",
        )
        .expect("replace fixture bundle bytes");
        assert_eq!(
            load_production_create_bootstrap_v8(&fixture.root).unwrap_err(),
            ProductionConfigErrorV1::IntegrityMismatch
        );
    }

    #[test]
    fn v8_layout_requires_bundle_and_all_six_stores_on_recovery() {
        let missing_bundle = Fixture::new();
        missing_bundle.create_v7_inputs();
        missing_bundle.install_manifests_v8();
        assert_eq!(
            load_production_create_bootstrap_v8(&missing_bundle.root).unwrap_err(),
            ProductionConfigErrorV1::InputArtifactUnavailable
        );

        let fixture = Fixture::new();
        fixture.create_v8_inputs();
        fixture.install_manifests_v8();
        load_production_create_bootstrap_v8(&fixture.root).expect("strict V8 create layout");
        fixture.create_managed_state();
        fixture.create_retained_f6_state_v4_for_v8();
        assert_eq!(
            load_production_reopen_bootstrap_v8(&fixture.root).unwrap_err(),
            ProductionConfigErrorV1::RecoveryStateUnavailable
        );
        fixture.create_f6_state_v8();
        assert_eq!(
            load_production_reopen_bootstrap_v8(&fixture.root).unwrap_err(),
            ProductionConfigErrorV1::RecoveryStateUnavailable
        );
        write_owner_file(
            &fixture.root.join(REFUND_ARMING_DATABASE_FILE_V1),
            b"refund-arming-state-v1",
        );
        let recovered =
            load_production_reopen_bootstrap_v8(&fixture.root).expect("strict V8 recovery layout");
        assert_eq!(
            recovered.layout().refund_arming_database(),
            Some(fixture.root.join(REFUND_ARMING_DATABASE_FILE_V1).as_path())
        );
        for role in ProductionF6PathRoleV8::ALL {
            let expected = fixture
                .root
                .join(standard_f6_paths_v8()[role.index()].as_str());
            assert_eq!(
                recovered.layout().f6_path_v8(role),
                Some(expected.as_path())
            );
        }

        write_owner_file(
            &fixture.root.join(
                standard_f6_paths_v4()[ProductionF6PathRoleV4::SolverStatusStore.index()].as_str(),
            ),
            b"superseded-v4-owner",
        );
        assert_eq!(
            load_production_reopen_bootstrap_v8(&fixture.root).unwrap_err(),
            ProductionConfigErrorV1::RecoveryStateUnavailable
        );
    }

    #[test]
    fn v7_script_digest_is_domain_separated_bounded_and_exact() {
        let first = bitcoin_prebroadcast_script_digest_v7(&[0x51]).expect("one-byte script");
        let second = bitcoin_prebroadcast_script_digest_v7(&[0x51, 0x00]).expect("two-byte script");
        assert_ne!(first, second);
        assert_eq!(
            bitcoin_prebroadcast_script_digest_v7(&[]),
            Err(ProductionConfigErrorV1::InvalidPublicBinding)
        );
        assert_eq!(
            bitcoin_prebroadcast_script_digest_v7(&vec![
                0;
                MAX_BITCOIN_PREBROADCAST_SCRIPT_BYTES_V7
                    + 1
            ]),
            Err(ProductionConfigErrorV1::InvalidPublicBinding)
        );
    }

    #[test]
    fn v7_round_trip_is_exact_and_pins_every_prebroadcast_scope() {
        let config = golden_create_config_v7();
        let encoded = config.canonical_bytes().expect("V7 encodes");
        let decoded = ProductionBootstrapConfigV1::decode_canonical_v7_for_mode(
            &encoded,
            ProductionBootstrapModeV1::Create,
        )
        .expect("exact V7 decodes");
        assert!(decoded == config);
        assert_eq!(PRODUCTION_PATH_ROLE_COUNT_V7, 43);
        assert_eq!(
            decoded.bitcoin_prebroadcast_store_v7(),
            Some(Path::new(BITCOIN_PREBROADCAST_STORE_PATH_V7))
        );
        assert_eq!(
            decoded.bitcoin_prebroadcast_pins_v7(),
            Some(bitcoin_prebroadcast_pins_v7())
        );
        let lines: Vec<&str> = std::str::from_utf8(&encoded)
            .expect("V7 is ASCII")
            .lines()
            .collect();
        assert_eq!(lines.len(), 106);
        let digest_at = lines
            .iter()
            .position(|line| line.starts_with("config_digest="))
            .expect("V7 config digest");
        assert_eq!(
            lines[digest_at - 15],
            format!("{BITCOIN_LEG_KEY_V7}=downstream")
        );
        assert_eq!(
            lines[digest_at - 1],
            format!(
                "{BITCOIN_REFUND_TEMPLATE_KEY_V7}={}",
                encode_hex(&bitcoin_prebroadcast_pins_v7().refund_template_hash)
            )
        );
    }

    #[test]
    fn v7_is_strictly_separated_from_every_earlier_family() {
        let v7 = golden_create_config_v7().canonical_bytes().unwrap();
        for decoded in [
            ProductionBootstrapConfigV1::decode_canonical_for_mode(
                &v7,
                ProductionBootstrapModeV1::Create,
            ),
            ProductionBootstrapConfigV1::decode_canonical_v2_for_mode(
                &v7,
                ProductionBootstrapModeV1::Create,
            ),
            ProductionBootstrapConfigV1::decode_canonical_v3_for_mode(
                &v7,
                ProductionBootstrapModeV1::Create,
            ),
            ProductionBootstrapConfigV1::decode_canonical_v4_for_mode(
                &v7,
                ProductionBootstrapModeV1::Create,
            ),
            ProductionBootstrapConfigV1::decode_canonical_v5_for_mode(
                &v7,
                ProductionBootstrapModeV1::Create,
            ),
            ProductionBootstrapConfigV1::decode_canonical_v6_for_mode(
                &v7,
                ProductionBootstrapModeV1::Create,
            ),
        ] {
            assert!(decoded.is_err());
        }
        for earlier in [
            golden_create_config().canonical_bytes().unwrap(),
            golden_create_config_v2().canonical_bytes().unwrap(),
            golden_create_config_v3().canonical_bytes().unwrap(),
            golden_create_config_v4().canonical_bytes().unwrap(),
            golden_create_config_v5().canonical_bytes().unwrap(),
            golden_create_config_v6().canonical_bytes().unwrap(),
        ] {
            assert!(ProductionBootstrapConfigV1::decode_canonical_v7_for_mode(
                &earlier,
                ProductionBootstrapModeV1::Create,
            )
            .is_err());
        }
    }

    #[test]
    fn v7_rejects_scope_transplants_and_ambiguous_taproot_pins() {
        let baseline = bitcoin_prebroadcast_pins_v7();
        let mut candidate = baseline;
        candidate.terms_digest = pins().upstream_terms_digest;
        assert_eq!(
            try_config_v7(ProductionBootstrapModeV1::Create, candidate).unwrap_err(),
            ProductionConfigErrorV1::InvalidPublicBinding
        );

        let mut candidate = baseline;
        candidate.receipt_digest = ZERO_DIGEST;
        assert_eq!(
            try_config_v7(ProductionBootstrapModeV1::Create, candidate).unwrap_err(),
            ProductionConfigErrorV1::InvalidPublicBinding
        );

        let mut candidate = baseline;
        candidate.claim_destination_script_pubkey_digest = candidate.contract_script_pubkey_digest;
        assert_eq!(
            try_config_v7(ProductionBootstrapModeV1::Create, candidate).unwrap_err(),
            ProductionConfigErrorV1::InvalidPublicBinding
        );

        let mut candidate = baseline;
        candidate.refund_template_hash = candidate.funding_template_hash;
        assert_eq!(
            try_config_v7(ProductionBootstrapModeV1::Create, candidate).unwrap_err(),
            ProductionConfigErrorV1::InvalidPublicBinding
        );

        assert_eq!(
            try_config_v7_at(
                ProductionBootstrapModeV1::Create,
                baseline,
                IDENTITY_STORE_PATH_V2,
            )
            .unwrap_err(),
            ProductionConfigErrorV1::AmbiguousPathReference
        );
    }

    #[test]
    fn v7_requires_existing_prebroadcast_authority_directory_and_never_creates_it() {
        let fixture = Fixture::new();
        fixture.create_v5_inputs();
        fixture.install_manifests_v7();
        let authority = fixture.root.join(BITCOIN_PREBROADCAST_STORE_PATH_V7);
        assert!(!authority.exists());
        assert_eq!(
            load_production_create_bootstrap_v7(&fixture.root).unwrap_err(),
            ProductionConfigErrorV1::BitcoinPrebroadcastAuthorityUnavailable
        );
        assert!(!authority.exists());

        create_owner_dir(&authority);
        let loaded =
            load_production_create_bootstrap_v7(&fixture.root).expect("complete V7 create layout");
        assert_eq!(
            loaded.layout().bitcoin_prebroadcast_store_v7(),
            Some(authority.as_path())
        );
        fixture.create_managed_state();
        fixture.create_f6_state_v4();
        let reopened = load_production_reopen_bootstrap_v7(&fixture.root)
            .expect("V7 recovery retains the same external authority path");
        assert_eq!(
            reopened.layout().bitcoin_prebroadcast_store_v7(),
            Some(authority.as_path())
        );
    }

    #[test]
    fn v7_companion_binds_the_exact_prebroadcast_receipt() {
        let fixture = Fixture::new();
        fixture.create_v7_inputs();
        let create = fixture.config_v7(ProductionBootstrapModeV1::Create);
        let mut substituted = bitcoin_prebroadcast_pins_v7();
        substituted.receipt_digest = [0xae; 32];
        let reopen = config_v7_with(ProductionBootstrapModeV1::ReopenExisting, substituted);
        write_owner_file(
            &fixture.root.join(PRODUCTION_CREATE_CONFIG_FILE_V7),
            &create.canonical_bytes().unwrap(),
        );
        write_owner_file(
            &fixture.root.join(PRODUCTION_REOPEN_CONFIG_FILE_V7),
            &reopen.canonical_bytes().unwrap(),
        );
        assert_eq!(
            load_production_create_bootstrap_v7(&fixture.root).unwrap_err(),
            ProductionConfigErrorV1::CompanionMismatch
        );
    }

    #[test]
    fn adding_v7_preserves_the_exact_v6_encoding() {
        let encoded = golden_create_config_v6().canonical_bytes().unwrap();
        let decoded = ProductionBootstrapConfigV1::decode_canonical_v6_for_mode(
            &encoded,
            ProductionBootstrapModeV1::Create,
        )
        .unwrap();
        assert_eq!(decoded.canonical_bytes().unwrap(), encoded);
        let text = std::str::from_utf8(&encoded).unwrap();
        assert!(!text.contains(BITCOIN_PREBROADCAST_STORE_KEY_V7));
        assert!(!text.contains(BITCOIN_RECEIPT_DIGEST_KEY_V7));
    }

    #[test]
    fn v6_round_trip_is_exact_and_has_ninety_lines() {
        let config = golden_create_config_v6();
        let encoded = config.canonical_bytes().expect("V6 encodes");
        let decoded = ProductionBootstrapConfigV1::decode_canonical_v6_for_mode(
            &encoded,
            ProductionBootstrapModeV1::Create,
        )
        .expect("exact V6 decodes");
        assert!(decoded == config);
        assert_eq!(PRODUCTION_PATH_ROLE_COUNT_V6, 42);
        assert_eq!(
            decoded.relay_authority_pins_v6(),
            Some(relay_authority_pins_v6())
        );
        assert_eq!(
            decoded.contracts_bootstrap_pins_v5(),
            Some(contracts_bootstrap_pins_v5())
        );
        let lines: Vec<&str> = std::str::from_utf8(&encoded)
            .expect("V6 is ASCII")
            .lines()
            .collect();
        assert_eq!(lines.len(), 90);
        let digest_at = lines
            .iter()
            .position(|line| line.starts_with("config_digest="))
            .expect("V6 config digest");
        assert_eq!(
            lines[digest_at - 13],
            format!(
                "{RELAY_DATABASE_ID_KEY_V6}={}",
                encode_hex(&relay_authority_pins_v6().relay_database_id)
            )
        );
        assert_eq!(
            lines[digest_at - 1],
            format!(
                "{FRAME_MAX_ACTIVE_CHUNKS_KEY_V6}={}",
                relay_authority_pins_v6().frame_max_active_chunks
            )
        );

        let oversized_u32 = rechecksum(
            String::from_utf8(encoded)
                .unwrap()
                .replacen(
                    "relay_max_envelopes=65536",
                    "relay_max_envelopes=4294967296",
                    1,
                )
                .into_bytes(),
        );
        assert_eq!(
            ProductionBootstrapConfigV1::decode_canonical_v6_for_mode(
                &oversized_u32,
                ProductionBootstrapModeV1::Create,
            )
            .unwrap_err(),
            ProductionConfigErrorV1::InvalidCanonicalEncoding
        );
    }

    #[test]
    fn v6_is_strictly_separated_from_every_earlier_family() {
        let v6 = golden_create_config_v6().canonical_bytes().unwrap();
        for decoded in [
            ProductionBootstrapConfigV1::decode_canonical_for_mode(
                &v6,
                ProductionBootstrapModeV1::Create,
            ),
            ProductionBootstrapConfigV1::decode_canonical_v2_for_mode(
                &v6,
                ProductionBootstrapModeV1::Create,
            ),
            ProductionBootstrapConfigV1::decode_canonical_v3_for_mode(
                &v6,
                ProductionBootstrapModeV1::Create,
            ),
            ProductionBootstrapConfigV1::decode_canonical_v4_for_mode(
                &v6,
                ProductionBootstrapModeV1::Create,
            ),
            ProductionBootstrapConfigV1::decode_canonical_v5_for_mode(
                &v6,
                ProductionBootstrapModeV1::Create,
            ),
        ] {
            assert!(decoded.is_err());
        }
        for earlier in [
            golden_create_config().canonical_bytes().unwrap(),
            golden_create_config_v2().canonical_bytes().unwrap(),
            golden_create_config_v3().canonical_bytes().unwrap(),
            golden_create_config_v4().canonical_bytes().unwrap(),
            golden_create_config_v5().canonical_bytes().unwrap(),
        ] {
            assert!(ProductionBootstrapConfigV1::decode_canonical_v6_for_mode(
                &earlier,
                ProductionBootstrapModeV1::Create,
            )
            .is_err());
        }
    }

    #[test]
    fn v6_rejects_every_authority_collision_and_bound_edge() {
        let baseline = relay_authority_pins_v6();
        let minimums = ProductionRelayAuthorityPinsV6 {
            relay_max_envelopes: 1,
            sender_max_envelopes: 1,
            inbox_max_entries: 1,
            frame_max_messages: 1,
            frame_max_active_bytes: 16_385,
            frame_max_active_chunks: 1,
            ..baseline
        };
        assert!(try_config_v6(ProductionBootstrapModeV1::Create, minimums).is_ok());
        let prior = route_pin_digests(pins()).into_iter().chain([
            contracts_bootstrap_pins_v5().commit_stage_digest(),
            contracts_bootstrap_pins_v5().reveal_stage_digest(),
        ]);
        for index in 0..7 {
            let mut candidate = baseline;
            set_relay_authority_id(&mut candidate, index, ZERO_DIGEST);
            assert_eq!(
                try_config_v6(ProductionBootstrapModeV1::Create, candidate).unwrap_err(),
                ProductionConfigErrorV1::InvalidPublicBinding
            );
            for prior_id in prior.clone() {
                let mut candidate = baseline;
                set_relay_authority_id(&mut candidate, index, prior_id);
                assert_eq!(
                    try_config_v6(ProductionBootstrapModeV1::Create, candidate).unwrap_err(),
                    ProductionConfigErrorV1::InvalidPublicBinding
                );
            }
        }
        let ids = baseline.authority_ids();
        for left in 0..ids.len() {
            for right in (left + 1)..ids.len() {
                let mut candidate = baseline;
                set_relay_authority_id(&mut candidate, right, ids[left]);
                assert_eq!(
                    try_config_v6(ProductionBootstrapModeV1::Create, candidate).unwrap_err(),
                    ProductionConfigErrorV1::InvalidPublicBinding
                );
            }
        }

        let mut invalid_bounds = Vec::new();
        for value in [0, 65_537] {
            let mut candidate = baseline;
            candidate.relay_max_envelopes = value;
            invalid_bounds.push(candidate);
            let mut candidate = baseline;
            candidate.sender_max_envelopes = value;
            invalid_bounds.push(candidate);
            let mut candidate = baseline;
            candidate.inbox_max_entries = value;
            invalid_bounds.push(candidate);
        }
        for value in [0, 257] {
            let mut candidate = baseline;
            candidate.frame_max_messages = value;
            invalid_bounds.push(candidate);
        }
        for value in [16_384, 67_108_865] {
            let mut candidate = baseline;
            candidate.frame_max_active_bytes = value;
            invalid_bounds.push(candidate);
        }
        for value in [0, 8_449] {
            let mut candidate = baseline;
            candidate.frame_max_active_chunks = value;
            invalid_bounds.push(candidate);
        }
        for candidate in invalid_bounds {
            assert_eq!(
                try_config_v6(ProductionBootstrapModeV1::Create, candidate).unwrap_err(),
                ProductionConfigErrorV1::InvalidRuntimeBounds
            );
        }
    }

    #[test]
    fn adding_v6_preserves_every_v1_through_v5_encoding() {
        let earlier = [
            golden_create_config().canonical_bytes().unwrap(),
            golden_create_config_v2().canonical_bytes().unwrap(),
            golden_create_config_v3().canonical_bytes().unwrap(),
            golden_create_config_v4().canonical_bytes().unwrap(),
            golden_create_config_v5().canonical_bytes().unwrap(),
        ];
        assert_eq!(earlier[0].as_slice(), GOLDEN_CREATE_V1.as_bytes());
        assert_eq!(earlier[1].as_slice(), GOLDEN_CREATE_V2.as_bytes());
        assert_eq!(earlier[2].as_slice(), GOLDEN_CREATE_V3.as_bytes());
        assert_eq!(earlier[3].as_slice(), GOLDEN_CREATE_V4.as_bytes());
        assert_eq!(earlier[4], frozen_v5_bytes_from_v4_golden());
        for encoded in earlier {
            let text = std::str::from_utf8(&encoded).unwrap();
            assert!(!text.contains(RELAY_DATABASE_ID_KEY_V6));
            assert!(!text.contains(FRAME_MAX_ACTIVE_CHUNKS_KEY_V6));
        }
    }

    #[test]
    fn v6_companion_and_layout_bind_the_exact_relay_configuration() {
        let fixture = Fixture::new();
        fixture.create_v5_inputs();
        let create = fixture.config_v6(ProductionBootstrapModeV1::Create);
        let mut substituted = relay_authority_pins_v6();
        substituted.downstream_reassembler_id = [0x98; 32];
        let reopen = config_v6_with(ProductionBootstrapModeV1::ReopenExisting, substituted);
        write_owner_file(
            &fixture.root.join(PRODUCTION_CREATE_CONFIG_FILE_V6),
            &create.canonical_bytes().unwrap(),
        );
        write_owner_file(
            &fixture.root.join(PRODUCTION_REOPEN_CONFIG_FILE_V6),
            &reopen.canonical_bytes().unwrap(),
        );
        assert_eq!(
            load_production_create_bootstrap_v6(&fixture.root).unwrap_err(),
            ProductionConfigErrorV1::CompanionMismatch
        );

        fs::remove_file(fixture.root.join(PRODUCTION_CREATE_CONFIG_FILE_V6)).unwrap();
        fs::remove_file(fixture.root.join(PRODUCTION_REOPEN_CONFIG_FILE_V6)).unwrap();
        fixture.install_manifests_v6();
        let loaded =
            load_production_create_bootstrap_v6(&fixture.root).expect("complete V6 create layout");
        assert_eq!(
            loaded.config().relay_authority_pins_v6(),
            Some(relay_authority_pins_v6())
        );
        assert_eq!(
            loaded.layout().contracts_bootstrap(),
            Some(fixture.root.join(CONTRACTS_BOOTSTRAP_PATH_V5).as_path())
        );
        fixture.create_managed_state();
        fixture.create_f6_state_v4();
        assert!(load_production_reopen_bootstrap_v6(&fixture.root).is_ok());
    }

    #[cfg(feature = "production")]
    #[test]
    fn v6_provisioning_journal_refuses_relay_quota_substitution() {
        let fixture = Fixture::new();
        fixture.create_v5_inputs();
        fixture.install_manifests_v6();
        let initial = load_production_create_or_resume_bootstrap_v6(&fixture.root)
            .expect("strict V6 create layout");
        let binding = provisioning_binding_for_v6_bootstrap(&initial)
            .expect("V6 companion-bound provisioning identity");
        let journal = DurableProductionProvisioningJournalV1::create(&fixture.root, binding)
            .expect("publish exact V6 provisioning journal");
        drop(journal);

        fs::remove_file(fixture.root.join(PRODUCTION_CREATE_CONFIG_FILE_V6)).unwrap();
        fs::remove_file(fixture.root.join(PRODUCTION_REOPEN_CONFIG_FILE_V6)).unwrap();
        let mut substituted = relay_authority_pins_v6();
        substituted.sender_max_envelopes -= 1;
        for (file, mode) in [
            (
                PRODUCTION_CREATE_CONFIG_FILE_V6,
                ProductionBootstrapModeV1::Create,
            ),
            (
                PRODUCTION_REOPEN_CONFIG_FILE_V6,
                ProductionBootstrapModeV1::ReopenExisting,
            ),
        ] {
            write_owner_file(
                &fixture.root.join(file),
                &config_v6_with(mode, substituted).canonical_bytes().unwrap(),
            );
        }
        assert_eq!(
            load_production_create_or_resume_bootstrap_v6(&fixture.root).unwrap_err(),
            ProductionConfigErrorV1::ProvisioningJournalRefused
        );
    }

    #[test]
    fn v5_round_trip_is_exact_bounded_and_stage_pinned() {
        let config = golden_create_config_v5();
        let encoded = config.canonical_bytes().expect("V5 encodes");
        let decoded = ProductionBootstrapConfigV1::decode_canonical_v5_for_mode(
            &encoded,
            ProductionBootstrapModeV1::Create,
        )
        .expect("exact V5 decodes");
        assert!(decoded == config);
        assert_eq!(PRODUCTION_PATH_ROLE_COUNT_V5, 42);
        assert_eq!(
            decoded.contracts_bootstrap(),
            Some(Path::new(CONTRACTS_BOOTSTRAP_PATH_V5))
        );
        assert_eq!(
            decoded.contracts_bootstrap_pins_v5(),
            Some(contracts_bootstrap_pins_v5())
        );

        let lines: Vec<&str> = std::str::from_utf8(&encoded)
            .expect("V5 is ASCII")
            .lines()
            .collect();
        let digest_at = lines
            .iter()
            .position(|line| line.starts_with("config_digest="))
            .expect("V5 config digest");
        assert_eq!(
            lines[digest_at - 3],
            format!("{CONTRACTS_BOOTSTRAP_KEY_V5}={CONTRACTS_BOOTSTRAP_PATH_V5}")
        );
        assert_eq!(
            lines[digest_at - 2],
            format!(
                "{CONTRACTS_BOOTSTRAP_COMMIT_DIGEST_KEY_V5}={}",
                encode_hex(&contracts_bootstrap_pins_v5().commit_stage_digest())
            )
        );
        assert_eq!(
            lines[digest_at - 1],
            format!(
                "{CONTRACTS_BOOTSTRAP_REVEAL_DIGEST_KEY_V5}={}",
                encode_hex(&contracts_bootstrap_pins_v5().reveal_stage_digest())
            )
        );

        let mut trailing = encoded.clone();
        trailing.extend_from_slice(b"x");
        assert!(ProductionBootstrapConfigV1::decode_canonical_v5_for_mode(
            &trailing,
            ProductionBootstrapModeV1::Create
        )
        .is_err());
        let mutated = replace_once(
            encoded,
            &encode_hex(&contracts_bootstrap_pins_v5().commit_stage_digest()),
            &encode_hex(&[0x83; 32]),
        );
        assert_eq!(
            ProductionBootstrapConfigV1::decode_canonical_v5_for_mode(
                &mutated,
                ProductionBootstrapModeV1::Create,
            )
            .unwrap_err(),
            ProductionConfigErrorV1::IntegrityMismatch
        );
    }

    #[test]
    fn v5_refuses_cross_family_documents_and_path_aliases() {
        let v5 = golden_create_config_v5()
            .canonical_bytes()
            .expect("V5 encodes");
        assert!(ProductionBootstrapConfigV1::decode_canonical_for_mode(
            &v5,
            ProductionBootstrapModeV1::Create
        )
        .is_err());
        assert!(ProductionBootstrapConfigV1::decode_canonical_v2_for_mode(
            &v5,
            ProductionBootstrapModeV1::Create
        )
        .is_err());
        assert!(ProductionBootstrapConfigV1::decode_canonical_v3_for_mode(
            &v5,
            ProductionBootstrapModeV1::Create
        )
        .is_err());
        assert!(ProductionBootstrapConfigV1::decode_canonical_v4_for_mode(
            &v5,
            ProductionBootstrapModeV1::Create
        )
        .is_err());
        for earlier in [
            golden_create_config().canonical_bytes().unwrap(),
            golden_create_config_v2().canonical_bytes().unwrap(),
            golden_create_config_v3().canonical_bytes().unwrap(),
            golden_create_config_v4().canonical_bytes().unwrap(),
        ] {
            assert!(ProductionBootstrapConfigV1::decode_canonical_v5_for_mode(
                &earlier,
                ProductionBootstrapModeV1::Create
            )
            .is_err());
        }

        assert_eq!(
            ProductionBootstrapConfigV1::from_parts_v5(
                ProductionBootstrapModeV1::Create,
                pins(),
                bounds(),
                ProductionPathReferencesV1::from_ordered(standard_paths()).unwrap(),
                ProductionFamilyInputsV5::new(
                    IDENTITY_STORE_PATH_V2.to_owned(),
                    BUDGET_POLICY_PATH_V3.to_owned(),
                    ProductionF6PathReferencesV4::from_ordered(standard_f6_paths_v4()).unwrap(),
                    standard_f6_paths_v4()[0].clone(),
                    contracts_bootstrap_pins_v5(),
                ),
            )
            .unwrap_err(),
            ProductionConfigErrorV1::AmbiguousPathReference
        );
    }

    #[test]
    fn v5_stage_pins_cannot_collapse_or_alias_any_route_pin() {
        assert_eq!(
            ProductionContractsBootstrapPinsV5::new([0; 32], [0x82; 32]).unwrap_err(),
            ProductionConfigErrorV1::InvalidPublicBinding
        );
        assert_eq!(
            ProductionContractsBootstrapPinsV5::new([0x81; 32], [0x81; 32]).unwrap_err(),
            ProductionConfigErrorV1::InvalidPublicBinding
        );
        let route_pins = pins();
        for prior_digest in route_pin_digests(route_pins) {
            for stage_pins in [
                ProductionContractsBootstrapPinsV5::new(prior_digest, [0x82; 32]).unwrap(),
                ProductionContractsBootstrapPinsV5::new([0x81; 32], prior_digest).unwrap(),
            ] {
                assert_eq!(
                    ProductionBootstrapConfigV1::from_parts_v5(
                        ProductionBootstrapModeV1::Create,
                        route_pins,
                        bounds(),
                        ProductionPathReferencesV1::from_ordered(standard_paths()).unwrap(),
                        ProductionFamilyInputsV5::new(
                            IDENTITY_STORE_PATH_V2.to_owned(),
                            BUDGET_POLICY_PATH_V3.to_owned(),
                            ProductionF6PathReferencesV4::from_ordered(standard_f6_paths_v4())
                                .unwrap(),
                            CONTRACTS_BOOTSTRAP_PATH_V5.to_owned(),
                            stage_pins,
                        ),
                    )
                    .unwrap_err(),
                    ProductionConfigErrorV1::InvalidPublicBinding
                );
            }
        }
    }

    #[test]
    fn v5_companion_refuses_a_semantically_valid_pin_substitution() {
        let fixture = Fixture::new();
        fixture.create_v5_inputs();
        let create = fixture.config_v5(ProductionBootstrapModeV1::Create);
        let substituted_reopen = ProductionBootstrapConfigV1::from_parts_v5(
            ProductionBootstrapModeV1::ReopenExisting,
            pins(),
            bounds(),
            ProductionPathReferencesV1::from_ordered(standard_paths()).unwrap(),
            ProductionFamilyInputsV5::new(
                IDENTITY_STORE_PATH_V2.to_owned(),
                BUDGET_POLICY_PATH_V3.to_owned(),
                ProductionF6PathReferencesV4::from_ordered(standard_f6_paths_v4()).unwrap(),
                CONTRACTS_BOOTSTRAP_PATH_V5.to_owned(),
                ProductionContractsBootstrapPinsV5::new([0x83; 32], [0x84; 32]).unwrap(),
            ),
        )
        .unwrap();
        write_owner_file(
            &fixture.root.join(PRODUCTION_CREATE_CONFIG_FILE_V5),
            &create.canonical_bytes().unwrap(),
        );
        write_owner_file(
            &fixture.root.join(PRODUCTION_REOPEN_CONFIG_FILE_V5),
            &substituted_reopen.canonical_bytes().unwrap(),
        );
        assert_eq!(
            load_production_create_bootstrap_v5(&fixture.root).unwrap_err(),
            ProductionConfigErrorV1::CompanionMismatch
        );
    }

    #[test]
    fn v5_layout_requires_the_external_bootstrap_in_create_and_reopen() {
        let fixture = Fixture::new();
        fixture.create_v4_inputs();
        fixture.install_manifests_v5();
        assert_eq!(
            load_production_create_bootstrap_v5(&fixture.root).unwrap_err(),
            ProductionConfigErrorV1::InputArtifactUnavailable
        );
        write_owner_file(
            &fixture.root.join(CONTRACTS_BOOTSTRAP_PATH_V5),
            b"contracts-bootstrap-v5",
        );
        let create =
            load_production_create_bootstrap_v5(&fixture.root).expect("complete V5 create layout");
        assert_eq!(
            create.layout().contracts_bootstrap(),
            Some(fixture.root.join(CONTRACTS_BOOTSTRAP_PATH_V5).as_path())
        );
        fixture.create_managed_state();
        fixture.create_f6_state_v4();
        assert!(load_production_reopen_bootstrap_v5(&fixture.root).is_ok());
    }

    #[cfg(feature = "production")]
    #[test]
    fn v5_provisioning_resume_requires_the_same_owner_only_external_bootstrap() {
        let fixture = Fixture::new();
        fixture.create_v5_inputs();
        fixture.install_manifests_v5();

        let initial = load_production_create_or_resume_bootstrap_v5(&fixture.root)
            .expect("strict V5 create layout");
        let binding = provisioning_binding_for_v5_bootstrap(&initial)
            .expect("V5 companion-bound provisioning identity");
        let journal = DurableProductionProvisioningJournalV1::create(&fixture.root, binding)
            .expect("publish exact V5 provisioning journal");
        drop(journal);

        let resumed = load_production_create_or_resume_bootstrap_v5(&fixture.root)
            .expect("journal-authenticated V5 provisioning resume");
        assert_eq!(
            resumed.layout().contracts_bootstrap(),
            Some(fixture.root.join(CONTRACTS_BOOTSTRAP_PATH_V5).as_path())
        );

        fs::set_permissions(
            fixture.root.join(CONTRACTS_BOOTSTRAP_PATH_V5),
            fs::Permissions::from_mode(0o640),
        )
        .expect("make the external artifact physically unsafe");
        assert_eq!(
            load_production_create_or_resume_bootstrap_v5(&fixture.root).unwrap_err(),
            ProductionConfigErrorV1::InputArtifactUnavailable
        );
    }

    #[test]
    fn adding_v5_does_not_add_any_line_to_v1_through_v4() {
        let earlier = [
            golden_create_config().canonical_bytes().unwrap(),
            golden_create_config_v2().canonical_bytes().unwrap(),
            golden_create_config_v3().canonical_bytes().unwrap(),
            golden_create_config_v4().canonical_bytes().unwrap(),
        ];
        for (index, encoded) in earlier.iter().enumerate() {
            let text = std::str::from_utf8(encoded).unwrap();
            assert!(
                !text.contains(CONTRACTS_BOOTSTRAP_KEY_V5),
                "family {}",
                index + 1
            );
            assert!(!text.contains(CONTRACTS_BOOTSTRAP_COMMIT_DIGEST_KEY_V5));
            assert!(!text.contains(CONTRACTS_BOOTSTRAP_REVEAL_DIGEST_KEY_V5));
        }
        assert_eq!(earlier[0].as_slice(), GOLDEN_CREATE_V1.as_bytes());
        assert_eq!(earlier[1].as_slice(), GOLDEN_CREATE_V2.as_bytes());
        assert_eq!(earlier[2].as_slice(), GOLDEN_CREATE_V3.as_bytes());
        assert_eq!(earlier[3].as_slice(), GOLDEN_CREATE_V4.as_bytes());
    }

    #[test]
    fn production_config_v4_golden_bytes_are_frozen() {
        let config = golden_create_config_v4();
        let encoded = config
            .canonical_bytes()
            .expect("the deterministic V4 fixture config encodes");
        assert_eq!(
            encoded,
            GOLDEN_CREATE_V4.as_bytes(),
            "the V4 bootstrap encoding drifted from its frozen golden"
        );
        assert_eq!(golden_blake2b256(&encoded), GOLDEN_CREATE_V4_BLAKE2B256);

        let decoded = ProductionBootstrapConfigV1::decode_canonical_v4_for_mode(
            GOLDEN_CREATE_V4.as_bytes(),
            ProductionBootstrapModeV1::Create,
        )
        .expect("the frozen V4 golden must decode");
        assert!(decoded == config);
    }

    #[test]
    fn v4_round_trip_is_v3_plus_exactly_eleven_ordered_f6_references() {
        let config = golden_create_config_v4();
        let encoded = config
            .canonical_bytes()
            .expect("the deterministic V4 config encodes");
        let decoded = ProductionBootstrapConfigV1::decode_canonical_v4_for_mode(
            &encoded,
            ProductionBootstrapModeV1::Create,
        )
        .expect("the exact V4 bytes decode");
        assert!(decoded == config);
        assert_eq!(PRODUCTION_PATH_ROLE_COUNT_V4, 41);
        assert_eq!(
            ProductionF6PathRoleV4::ALL.len(),
            PRODUCTION_F6_PATH_ROLE_COUNT_V4
        );
        let v3 = golden_create_config_v3()
            .canonical_bytes()
            .expect("the frozen V3 fixture encodes");
        let v3_lines: Vec<&str> = std::str::from_utf8(&v3)
            .expect("V3 is ASCII")
            .lines()
            .collect();
        let v4_lines: Vec<&str> = std::str::from_utf8(&encoded)
            .expect("V4 is ASCII")
            .lines()
            .collect();
        assert_eq!(v4_lines.len(), v3_lines.len() + 11);
        assert_eq!(v4_lines[0], HEADER_V4);
        let digest_at = v4_lines
            .iter()
            .position(|line| line.starts_with("config_digest="))
            .expect("V4 carries a digest");
        for (offset, role) in ProductionF6PathRoleV4::ALL.into_iter().enumerate() {
            assert_eq!(
                v4_lines[digest_at - PRODUCTION_F6_PATH_ROLE_COUNT_V4 + offset],
                format!("{}={}", role.key(), standard_f6_paths_v4()[offset])
            );
            assert_eq!(
                decoded.f6_paths_v4().map(|paths| paths.get(role)),
                Some(Path::new(&standard_f6_paths_v4()[offset]))
            );
        }
    }

    #[test]
    fn v4_refuses_cross_family_decode_and_any_path_alias() {
        let v4 = golden_create_config_v4()
            .canonical_bytes()
            .expect("V4 encodes");
        assert!(ProductionBootstrapConfigV1::decode_canonical_for_mode(
            &v4,
            ProductionBootstrapModeV1::Create
        )
        .is_err());
        assert!(ProductionBootstrapConfigV1::decode_canonical_v2_for_mode(
            &v4,
            ProductionBootstrapModeV1::Create
        )
        .is_err());
        assert!(ProductionBootstrapConfigV1::decode_canonical_v3_for_mode(
            &v4,
            ProductionBootstrapModeV1::Create
        )
        .is_err());
        for earlier in [GOLDEN_CREATE_V1, GOLDEN_CREATE_V2, GOLDEN_CREATE_V3] {
            assert!(ProductionBootstrapConfigV1::decode_canonical_v4_for_mode(
                earlier.as_bytes(),
                ProductionBootstrapModeV1::Create
            )
            .is_err());
        }

        let mut aliases_base = standard_f6_paths_v4();
        aliases_base[0] = standard_paths()[0].clone();
        assert_eq!(
            ProductionBootstrapConfigV1::from_parts_v4(
                ProductionBootstrapModeV1::Create,
                pins(),
                bounds(),
                ProductionPathReferencesV1::from_ordered(standard_paths()).unwrap(),
                IDENTITY_STORE_PATH_V2.to_owned(),
                BUDGET_POLICY_PATH_V3.to_owned(),
                ProductionF6PathReferencesV4::from_ordered(aliases_base).unwrap(),
            )
            .unwrap_err(),
            ProductionConfigErrorV1::AmbiguousPathReference
        );
        let mut aliases_f6 = standard_f6_paths_v4();
        aliases_f6[10] = aliases_f6[9].clone();
        assert_eq!(
            ProductionF6PathReferencesV4::from_ordered(aliases_f6).unwrap_err(),
            ProductionConfigErrorV1::AmbiguousPathReference
        );
    }

    #[test]
    fn v4_create_and_reopen_validate_all_eleven_physical_leaves() {
        let fixture = Fixture::new();
        fixture.create_v4_inputs();
        fixture.install_manifests_v4();
        let create = load_production_create_bootstrap_v4(&fixture.root)
            .expect("pristine V4 create layout is accepted");
        for role in ProductionF6PathRoleV4::ALL {
            let expected = fixture
                .root
                .join(standard_f6_paths_v4()[role.index()].as_str());
            assert_eq!(create.layout().f6_path_v4(role), Some(expected.as_path()));
        }
        fixture.create_managed_state();
        fixture.create_f6_state_v4();
        assert!(load_production_reopen_bootstrap_v4(&fixture.root).is_ok());
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
            PRODUCTION_CREATE_CONFIG_FILE_V3,
            PRODUCTION_REOPEN_CONFIG_FILE_V3,
            PRODUCTION_CREATE_CONFIG_FILE_V4,
            PRODUCTION_REOPEN_CONFIG_FILE_V4,
            PRODUCTION_CREATE_CONFIG_FILE_V5,
            PRODUCTION_REOPEN_CONFIG_FILE_V5,
            PRODUCTION_CREATE_CONFIG_FILE_V6,
            PRODUCTION_REOPEN_CONFIG_FILE_V6,
            PRODUCTION_CREATE_CONFIG_FILE_V7,
            PRODUCTION_REOPEN_CONFIG_FILE_V7,
            PRODUCTION_NODE_CONFIG_FILE_V1,
            PRODUCTION_RELAY_NETWORK_CONFIG_FILE_V1,
            REFUND_ARMING_DATABASE_FILE_V1,
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
