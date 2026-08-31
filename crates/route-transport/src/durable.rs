//! Linux durable recipient inbox for the shared Relay V1 transcript.
//!
//! The Relay is deliberately at-least-once and cannot acknowledge Contracts
//! acceptance.  This authority therefore persists every envelope accepted by
//! the recipient pipeline *before* dispatching its opaque payload.  A crash at
//! that boundary leaves a pending row which is delivered again after reopen;
//! the downstream port must commit idempotently before returning a receipt.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, DirBuilder, File, OpenOptions};
use std::os::fd::AsFd;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use blake2::{
    digest::{Update, VariableOutput},
    Blake2bVar,
};
use kaystra_core::types::Digest32;
use relay::auth::{
    accept_envelope, message_type, AuthRefusal, RecipientContextV1, RosterRegistryV1,
    TranscriptStateV1,
};
use relay::server::IdempotencyKeyV1;
use relay::{ParticipantId, RelayEnvelopeV1, TimelockSpec};
use rusqlite::{params, Connection, OpenFlags, OptionalExtension, TransactionBehavior};
use rustix::fs::{flock, FlockOperation};
use rustix::process::geteuid;

use crate::{BridgeRefusal, DurableProductionCreationStateV1, RelayQueueV1, RouteWireContextV1};

const DATABASE_FILE_NAME: &str = "route-inbox-v1.sqlite3";
const LOCK_FILE_NAME: &str = ".route-inbox.lock";
const ROOT_MODE: u32 = 0o700;
const FILE_MODE: u32 = 0o600;
const SCHEMA_VERSION: i64 = 1;
const APPLICATION_ID: i64 = 0x444f_4d49; // "DOMI"
const ZERO_DIGEST: Digest32 = [0; 32];
const MAX_INBOX_ENTRIES: u32 = 65_536;
const ENTRY_DOMAIN: &[u8] = b"DOM-INTEROP/ROUTE-INBOX/ENTRY/V1\0";
const DELIVERY_DOMAIN: &[u8] = b"DOM-INTEROP/ROUTE-INBOX/DELIVERY/V1\0";

const SCHEMA_SQL: &str = r#"
CREATE TABLE inbox_meta (
    singleton         INTEGER PRIMARY KEY CHECK (singleton = 1),
    schema_version    INTEGER NOT NULL CHECK (schema_version = 1),
    inbox_id          BLOB NOT NULL CHECK (length(inbox_id) = 32),
    network_id        BLOB NOT NULL CHECK (length(network_id) = 32),
    session_id        BLOB NOT NULL CHECK (length(session_id) = 32),
    route_id          BLOB NOT NULL CHECK (length(route_id) = 32),
    roster_snapshot   BLOB NOT NULL CHECK (length(roster_snapshot) = 32),
    recipient_id      BLOB NOT NULL CHECK (length(recipient_id) = 32),
    policy_version    INTEGER NOT NULL CHECK (policy_version > 0),
    max_entries       INTEGER NOT NULL CHECK (max_entries > 0 AND max_entries <= 65536),
    accepted_count    INTEGER NOT NULL CHECK (accepted_count >= 0 AND accepted_count <= max_entries)
) STRICT;

CREATE TABLE inbox_entries (
    ordinal             INTEGER PRIMARY KEY CHECK (ordinal > 0 AND ordinal <= 65536),
    sender_id           BLOB NOT NULL CHECK (length(sender_id) = 32),
    recipient_id        BLOB NOT NULL CHECK (length(recipient_id) = 32),
    sequence_be         BLOB NOT NULL CHECK (length(sequence_be) = 8),
    message_type        INTEGER NOT NULL CHECK (message_type BETWEEN 1 AND 5),
    envelope_digest     BLOB NOT NULL CHECK (length(envelope_digest) = 32),
    canonical_bytes     BLOB NOT NULL CHECK (length(canonical_bytes) <= 16742),
    accepted_now_domain INTEGER NOT NULL CHECK (accepted_now_domain BETWEEN 1 AND 3),
    accepted_now_be     BLOB NOT NULL CHECK (length(accepted_now_be) = 8),
    delivery_state      INTEGER NOT NULL CHECK (delivery_state BETWEEN 0 AND 2),
    delivery_receipt    BLOB NOT NULL CHECK (length(delivery_receipt) = 32),
    row_digest          BLOB NOT NULL CHECK (length(row_digest) = 32),
    delivery_digest     BLOB NOT NULL CHECK (length(delivery_digest) = 32),
    UNIQUE (sender_id, recipient_id, sequence_be),
    CHECK (
        (delivery_state = 0 AND delivery_receipt = zeroblob(32)) OR
        (delivery_state IN (1, 2) AND delivery_receipt != zeroblob(32))
    )
) STRICT;
"#;

/// Immutable identity and wire binding of one durable inbox.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DurableInboxConfigV1 {
    inbox_id: Digest32,
    wire: RouteWireContextV1,
    recipient_id: ParticipantId,
    max_entries: u32,
}

impl DurableInboxConfigV1 {
    /// Creates a non-null, bounded inbox configuration.
    pub fn new(
        inbox_id: Digest32,
        wire: RouteWireContextV1,
        recipient_id: ParticipantId,
        max_entries: u32,
    ) -> Result<Self, DurableInboxError> {
        if inbox_id == ZERO_DIGEST
            || wire.network_id == ZERO_DIGEST
            || wire.session_id == ZERO_DIGEST
            || wire.route_id == ZERO_DIGEST
            || wire.roster_snapshot == ZERO_DIGEST
            || recipient_id.0 == ZERO_DIGEST
            || wire.policy_version == 0
            || max_entries == 0
            || max_entries > MAX_INBOX_ENTRIES
        {
            return Err(DurableInboxError::InvalidConfiguration);
        }
        Ok(Self {
            inbox_id,
            wire,
            recipient_id,
            max_entries,
        })
    }

    /// Stable public inbox identity.
    pub const fn inbox_id(&self) -> &Digest32 {
        &self.inbox_id
    }

    /// Frozen route wire context.
    pub const fn wire_context(&self) -> RouteWireContextV1 {
        self.wire
    }

    /// Participant whose mailbox this authority consumes.
    pub const fn recipient_id(&self) -> ParticipantId {
        self.recipient_id
    }

    /// Maximum accepted envelopes retained by this inbox.
    pub const fn max_entries(&self) -> u32 {
        self.max_entries
    }

    fn recipient_context(&self) -> RecipientContextV1 {
        RecipientContextV1 {
            recipient_id: self.recipient_id,
            network_id: self.wire.network_id,
            session_id: self.wire.session_id,
            route_id: self.wire.route_id,
        }
    }
}

/// Durable inbox failures.  Filesystem and SQLite details are redacted so a
/// caller cannot accidentally log paths, query fragments, or payload bytes.
#[derive(Debug, thiserror::Error)]
pub enum DurableInboxError {
    /// A zero identity, relative/aliased path, unsafe mode, or invalid bound.
    #[error("invalid durable inbox configuration")]
    InvalidConfiguration,
    /// Explicit creation found an existing root.
    #[error("durable inbox root already exists")]
    AlreadyExists,
    /// Reopen found no durable database.
    #[error("durable inbox database is missing")]
    DatabaseMissing,
    /// Retained metadata does not match the expected inbox identity/context.
    #[error("wrong durable inbox identity")]
    WrongIdentity,
    /// A second process already owns this inbox, or storage access failed.
    #[error("durable inbox storage unavailable")]
    StorageUnavailable,
    /// Schema/backend version is not the frozen V1 format.
    #[error("unsupported durable inbox format")]
    UnsupportedFormat,
    /// Retained rows, digests, or transcript do not authenticate.
    #[error("corrupt durable inbox state")]
    CorruptState,
    /// The configured bounded inbox is full.
    #[error("durable inbox capacity exhausted")]
    CapacityExceeded,
    /// The Relay queue could not return its mailbox.
    #[error("relay queue unavailable: {0}")]
    Queue(BridgeRefusal),
    /// A consumer returned a zero/non-durable receipt.
    #[error("consumer returned an invalid durable receipt")]
    InvalidConsumerCommit,
}

impl From<rusqlite::Error> for DurableInboxError {
    fn from(_: rusqlite::Error) -> Self {
        Self::StorageUnavailable
    }
}

/// Per-envelope refusal retained in an ingest report.  Refused envelopes do
/// not move the durable transcript and their opaque payload is never exposed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DurableInboxEnvelopeRefusalV1 {
    /// The canonical Relay recipient pipeline refused the envelope.
    Pipeline(AuthRefusal),
    /// The envelope selected a different frozen roster snapshot.
    WrongRosterSnapshot,
    /// The envelope selected a different frozen protocol policy version.
    WrongPolicyVersion,
    /// A different canonical envelope reused an already durable flow key.
    DurableEquivocation,
}

/// Result of pulling and durably authenticating one at-least-once mailbox.
#[derive(Debug, Default)]
pub struct DurableInboxIngestReportV1 {
    /// Newly authenticated envelopes committed before this call returned.
    pub accepted: usize,
    /// Exact already-durable envelopes observed again.
    pub duplicates: usize,
    /// Individually named refusals; other mailbox entries were still tried.
    pub refused: Vec<DurableInboxEnvelopeRefusalV1>,
}

/// Current durable inbox counters, split so route and F6 backlogs cannot hide
/// each other.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct DurableInboxStatsV1 {
    /// Route/DSC1 envelopes awaiting Contracts acceptance.
    pub pending_route: usize,
    /// F6 envelopes awaiting the F6 consumer.
    pub pending_f6: usize,
    /// Payloads committed by their downstream authority.
    pub delivered: usize,
    /// Payloads whose downstream authority durably failed closed.
    pub failed_closed: usize,
}

/// Downstream durable disposition.  Both variants are terminal for the inbox:
/// either the state-machine transition is durable or that authority durably
/// quarantined/failed closed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DurablePayloadDispositionV1 {
    /// The downstream state-machine transition is durable.
    Applied,
    /// The downstream authority durably failed closed.
    FailedClosed,
}

/// Opaque proof returned only after a downstream authority made its result
/// durable.  The nonzero receipt is persisted by the inbox before the row is
/// removed from the pending set.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DurablePayloadCommitV1 {
    disposition: DurablePayloadDispositionV1,
    durable_receipt: Digest32,
    duplicate: bool,
}

impl DurablePayloadCommitV1 {
    /// Creates a downstream durable commit.  A zero receipt is refused because
    /// it cannot bind a redelivery to any durable result.
    pub fn new(
        disposition: DurablePayloadDispositionV1,
        durable_receipt: Digest32,
        duplicate: bool,
    ) -> Result<Self, DurableInboxError> {
        if durable_receipt == ZERO_DIGEST {
            return Err(DurableInboxError::InvalidConsumerCommit);
        }
        Ok(Self {
            disposition,
            durable_receipt,
            duplicate,
        })
    }

    /// Durable downstream disposition.
    pub const fn disposition(&self) -> DurablePayloadDispositionV1 {
        self.disposition
    }

    /// Opaque nonzero downstream receipt.
    pub const fn durable_receipt(&self) -> &Digest32 {
        &self.durable_receipt
    }

    /// Whether the downstream authority recognized an exact prior commit.
    pub const fn duplicate(&self) -> bool {
        self.duplicate
    }
}

/// Borrowed, already Relay-authenticated route payload delivered to Contracts.
/// No constructor is public; only [`DurableRelayInboxV1`] can issue it.
pub struct ContractsRouteDeliveryV1<'a> {
    sender_id: ParticipantId,
    sequence: u64,
    envelope_digest: Digest32,
    evidence: ContractsRouteDeliveryEvidenceV2,
    payload: &'a [u8],
}

/// Authentication evidence represented by a Contracts delivery.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ContractsRouteDeliveryEvidenceV2 {
    /// One direct V1 payload authenticated by its single outer Relay envelope.
    DirectRelayEnvelopeV1,
    /// One complete DSC1 object authenticated by every V2 frame and represented
    /// by their shared frame-set binding digest.
    ReassembledRouteFramesV2,
}

impl ContractsRouteDeliveryV1<'_> {
    #[cfg(test)]
    pub(crate) const fn from_authenticated_parts(
        sender_id: ParticipantId,
        sequence: u64,
        delivery_digest: Digest32,
        payload: &[u8],
    ) -> ContractsRouteDeliveryV1<'_> {
        ContractsRouteDeliveryV1 {
            sender_id,
            sequence,
            envelope_digest: delivery_digest,
            evidence: ContractsRouteDeliveryEvidenceV2::DirectRelayEnvelopeV1,
            payload,
        }
    }

    pub(crate) const fn from_reassembled_parts(
        sender_id: ParticipantId,
        first_sequence: u64,
        binding_digest: Digest32,
        payload: &[u8],
    ) -> ContractsRouteDeliveryV1<'_> {
        ContractsRouteDeliveryV1 {
            sender_id,
            sequence: first_sequence,
            envelope_digest: binding_digest,
            evidence: ContractsRouteDeliveryEvidenceV2::ReassembledRouteFramesV2,
            payload,
        }
    }

    /// Relay-roster-authenticated sender.
    pub const fn sender_id(&self) -> ParticipantId {
        self.sender_id
    }

    /// Shared-flow sequence accepted by the single inbox transcript.
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    /// Delivery evidence digest. For direct V1 this is the exact outer Relay
    /// envelope digest; after authenticated V2 reassembly it is the frame-set
    /// binding digest committed by every contributing outer envelope.
    pub const fn envelope_digest(&self) -> &Digest32 {
        &self.envelope_digest
    }

    /// Whether the evidence is one direct Relay envelope or a complete,
    /// authenticated V2 frame set.
    pub const fn delivery_evidence(&self) -> ContractsRouteDeliveryEvidenceV2 {
        self.evidence
    }

    /// Exact opaque DSC1 bytes carried by the envelope.
    pub const fn signed_dsc1(&self) -> &[u8] {
        self.payload
    }
}

/// Strict Contracts boundary used by the relay worker.
///
/// This API intentionally has no `SessionRecordV1` successor argument.  A
/// composition root must adapt an authority that derives and validates its
/// own successor (for example a phase-specific Contracts Store method); the
/// relay worker cannot manufacture a session transition from untrusted input.
pub trait ContractsTransportPortV1 {
    /// Redacted Contracts authority error.
    type Error: std::error::Error + Send + Sync + 'static;

    /// Authenticates and durably commits the exact DSC1 payload before
    /// returning.  Exact redelivery must return a duplicate durable commit.
    fn accept_signed_dsc1(
        &mut self,
        delivery: ContractsRouteDeliveryV1<'_>,
    ) -> Result<DurablePayloadCommitV1, Self::Error>;
}

/// Borrowed, already Relay-authenticated F6 payload delivered from the same
/// durable transcript as route traffic.
pub struct F6PayloadDeliveryV1<'a> {
    sender_id: ParticipantId,
    sequence: u64,
    message_type: u16,
    envelope_digest: Digest32,
    payload: &'a [u8],
}

impl F6PayloadDeliveryV1<'_> {
    /// Relay-roster-authenticated sender.
    pub const fn sender_id(&self) -> ParticipantId {
        self.sender_id
    }

    /// Shared-flow sequence accepted by the single inbox transcript.
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    /// One of the closed F6 kinds `RFQ`, `QUOTE`, `ACCEPTANCE`, or
    /// `SELECTION`.
    pub const fn message_type(&self) -> u16 {
        self.message_type
    }

    /// Digest of the exact outer Relay envelope.
    pub const fn envelope_digest(&self) -> &Digest32 {
        &self.envelope_digest
    }

    /// Exact opaque F6 object bytes.
    pub const fn payload(&self) -> &[u8] {
        self.payload
    }
}

/// Strict F6 consumer boundary owned by the same inbox as Contracts traffic.
/// A separate worker cannot construct or advance a second transcript.
pub trait F6TransportPortV1 {
    /// Redacted F6 engine error.
    type Error: std::error::Error + Send + Sync + 'static;

    /// Durably consumes one authenticated F6 object before returning.  Exact
    /// redelivery must return a duplicate durable commit.
    fn accept_f6(
        &mut self,
        delivery: F6PayloadDeliveryV1<'_>,
    ) -> Result<DurablePayloadCommitV1, Self::Error>;
}

/// Summary of one route-payload drain.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RouteDispatchReportV1 {
    /// Newly or idempotently applied Contracts payloads.
    pub applied: usize,
    /// Contracts payloads that durably failed the session closed.
    pub failed_closed: usize,
    /// Calls recognized by Contracts as exact prior commits after redelivery.
    pub duplicate_commits: usize,
    /// Route rows held because an earlier F6 row in the same flow is pending.
    pub blocked_by_f6: usize,
}

/// Route drain failure.  A failed row remains pending and is retried after
/// recovery; already marked rows are never sent again.
#[derive(Debug, thiserror::Error)]
pub enum RouteDispatchErrorV1<E: std::error::Error + Send + Sync + 'static> {
    /// Inbox storage failed before the delivery outcome became durable.
    #[error("durable inbox: {0}")]
    Inbox(#[source] DurableInboxError),
    /// The Contracts authority refused or was unavailable.
    #[error("contracts transport port: {0}")]
    Contracts(#[source] E),
}

/// Summary of one F6-payload drain.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct F6DispatchReportV1 {
    /// Newly or idempotently applied F6 payloads.
    pub applied: usize,
    /// F6 payloads that durably failed the route negotiation closed.
    pub failed_closed: usize,
    /// Calls recognized by the F6 authority as exact prior commits.
    pub duplicate_commits: usize,
    /// F6 rows held because an earlier route row in the same flow is pending.
    pub blocked_by_route: usize,
}

/// F6 drain failure.  The exact row remains pending for restart-safe retry.
#[derive(Debug, thiserror::Error)]
pub enum F6DispatchErrorV1<E: std::error::Error + Send + Sync + 'static> {
    /// Inbox storage failed before the delivery outcome became durable.
    #[error("durable inbox: {0}")]
    Inbox(#[source] DurableInboxError),
    /// The F6 authority refused or was unavailable.
    #[error("F6 transport port: {0}")]
    F6(#[source] E),
}

#[derive(Clone)]
struct StoredEntryV1 {
    ordinal: i64,
    sender_id: ParticipantId,
    recipient_id: ParticipantId,
    sequence: u64,
    message_type: u16,
    envelope_digest: Digest32,
    canonical_bytes: Vec<u8>,
    accepted_now: TimelockSpec,
    row_digest: Digest32,
}

/// Retained single-writer inbox and the sole recipient transcript authority
/// for F6 plus route messages of one session.
pub struct DurableRelayInboxV1 {
    connection: Connection,
    root: PathBuf,
    config: DurableInboxConfigV1,
    _database_authority: File,
    _sqlite_database_authority: File,
    _lock: File,
}

impl core::fmt::Debug for DurableRelayInboxV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("DurableRelayInboxV1")
            .field("inbox_id", &self.config.inbox_id)
            .field("session_id", &self.config.wire.session_id)
            .field("root", &"[redacted]")
            .finish()
    }
}

impl DurableRelayInboxV1 {
    /// Creates a brand-new owner-only inbox and audits its empty transcript.
    pub fn create(
        root: &Path,
        config: DurableInboxConfigV1,
        rosters: &RosterRegistryV1,
    ) -> Result<Self, DurableInboxError> {
        create_root(root)?;
        let lock = acquire_lock(root, true)?;
        let database_path = root.join(DATABASE_FILE_NAME);
        let database_authority = create_database_authority(&database_path)?;
        let (connection, sqlite_database_authority) = open_connection_via_authority(
            &database_authority,
            &database_path,
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;
        validate_connection_authority(
            &database_authority,
            &sqlite_database_authority,
            &database_path,
        )?;
        configure_connection(&connection)?;
        initialize_pristine_store(&connection, config)?;
        connection
            .execute_batch("PRAGMA wal_checkpoint(FULL);")
            .map_err(|_| DurableInboxError::StorageUnavailable)?;
        sync_directory(root)?;
        let inbox = Self {
            connection,
            root: root.to_path_buf(),
            config,
            _database_authority: database_authority,
            _sqlite_database_authority: sqlite_database_authority,
            _lock: lock,
        };
        inbox.validate_storage()?;
        inbox.audit_transcript(rosters)?;
        Ok(inbox)
    }

    /// Resumes only a pristine prefix of an explicitly journaled production
    /// create. Missing/empty roots and empty SQLite files are completed;
    /// initialized authorities are accepted only while their transcript is
    /// still empty. Foreign schema/identity, extra files, hard-link
    /// transplants and every accepted economic envelope are refused.
    pub fn resume_create_production(
        root: &Path,
        config: DurableInboxConfigV1,
        rosters: &RosterRegistryV1,
    ) -> Result<Self, DurableInboxError> {
        let lock = acquire_resume_lock(root)?;
        let database_path = root.join(DATABASE_FILE_NAME);
        let database_exists = database_path
            .try_exists()
            .map_err(|_| DurableInboxError::StorageUnavailable)?;
        validate_resumable_database_files(root, database_exists)?;
        let database_authority = if database_exists {
            open_database_authority(&database_path)?
        } else {
            create_database_authority(&database_path)?
        };
        let state = preflight_resumable_database(&database_path, &database_authority, &config)?;
        let (connection, sqlite_database_authority) = open_connection_via_authority(
            &database_authority,
            &database_path,
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;
        validate_connection_authority(
            &database_authority,
            &sqlite_database_authority,
            &database_path,
        )?;
        validate_database_path(&connection, &database_path)?;
        let revalidated = classify_resumable_connection(&connection, &config)?;
        if revalidated != state {
            return Err(DurableInboxError::InvalidConfiguration);
        }
        configure_connection(&connection)?;
        validate_connection_authority(
            &database_authority,
            &sqlite_database_authority,
            &database_path,
        )?;
        match state {
            DurableProductionCreationStateV1::Incomplete => {
                initialize_pristine_store(&connection, config)?;
            }
            DurableProductionCreationStateV1::InitializedPristine => {
                require_pristine_connection(&connection, &config)?;
            }
            DurableProductionCreationStateV1::Missing => {
                return Err(DurableInboxError::CorruptState)
            }
        }
        let inbox = Self {
            connection,
            root: root.to_path_buf(),
            config,
            _database_authority: database_authority,
            _sqlite_database_authority: sqlite_database_authority,
            _lock: lock,
        };
        inbox.validate_storage()?;
        inbox.audit_transcript(rosters)?;
        inbox.require_pristine_creation_state()?;
        inbox
            .connection
            .execute_batch("PRAGMA wal_checkpoint(FULL);")
            .map_err(|_| DurableInboxError::StorageUnavailable)?;
        sync_directory(root)?;
        Ok(inbox)
    }

    /// Performs the non-mutating half of production resume planning.
    pub fn production_creation_state(
        root: &Path,
        config: DurableInboxConfigV1,
    ) -> Result<DurableProductionCreationStateV1, DurableInboxError> {
        inspect_creation_state(root, &config)
    }

    /// Reopens the exact existing inbox, validates every retained row and
    /// reconstructs the shared transcript from recorded acceptance times.
    pub fn open(
        root: &Path,
        expected: DurableInboxConfigV1,
        rosters: &RosterRegistryV1,
    ) -> Result<Self, DurableInboxError> {
        validate_root(root)?;
        validate_root_entries(root)?;
        let lock = acquire_lock(root, false)?;
        let database_path = root.join(DATABASE_FILE_NAME);
        if !database_path
            .try_exists()
            .map_err(|_| DurableInboxError::StorageUnavailable)?
        {
            return Err(DurableInboxError::DatabaseMissing);
        }
        validate_owner_file(&database_path)?;
        let database_authority = open_database_authority(&database_path)?;
        let (connection, sqlite_database_authority) = open_connection_via_authority(
            &database_authority,
            &database_path,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;
        validate_connection_authority(
            &database_authority,
            &sqlite_database_authority,
            &database_path,
        )?;
        validate_database_path(&connection, &database_path)?;
        let inbox = Self {
            connection,
            root: root.to_path_buf(),
            config: expected,
            _database_authority: database_authority,
            _sqlite_database_authority: sqlite_database_authority,
            _lock: lock,
        };
        inbox.validate_storage()?;
        inbox.audit_transcript(rosters)?;
        let Self {
            connection,
            root,
            config,
            _database_authority: database_authority,
            _sqlite_database_authority: sqlite_database_authority,
            _lock: lock,
        } = inbox;
        drop(connection);
        drop(sqlite_database_authority);
        validate_database_authority(&database_authority, &database_path)?;
        let (connection, sqlite_database_authority) = open_connection_via_authority(
            &database_authority,
            &database_path,
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;
        validate_connection_authority(
            &database_authority,
            &sqlite_database_authority,
            &database_path,
        )?;
        validate_database_path(&connection, &database_path)?;
        let rw_preflight = Self {
            connection,
            root,
            config,
            _database_authority: database_authority,
            _sqlite_database_authority: sqlite_database_authority,
            _lock: lock,
        };
        rw_preflight.validate_storage()?;
        rw_preflight.audit_transcript(rosters)?;
        let Self {
            connection,
            root,
            config,
            _database_authority: database_authority,
            _sqlite_database_authority: sqlite_database_authority,
            _lock: lock,
        } = rw_preflight;
        configure_connection(&connection)?;
        let inbox = Self {
            connection,
            root,
            config,
            _database_authority: database_authority,
            _sqlite_database_authority: sqlite_database_authority,
            _lock: lock,
        };
        inbox.validate_storage()?;
        inbox.audit_transcript(rosters)?;
        Ok(inbox)
    }

    /// Pulls the queue mailbox, authenticates all known kinds through one
    /// shared transcript, and commits each accepted envelope before counting
    /// it as accepted.  Exact Relay redelivery is a no-op.
    pub fn ingest<Q: RelayQueueV1>(
        &mut self,
        queue: &Q,
        rosters: &RosterRegistryV1,
        now: TimelockSpec,
    ) -> Result<DurableInboxIngestReportV1, DurableInboxError> {
        let mut state = self.reconstruct_transcript(rosters)?;
        let mailbox = queue
            .queue_deliver(&self.config.recipient_id)
            .map_err(DurableInboxError::Queue)?;
        let mut report = DurableInboxIngestReportV1::default();
        for raw in mailbox {
            let envelope = match RelayEnvelopeV1::decode(&raw) {
                Ok(envelope) => envelope,
                Err(error) => {
                    report.refused.push(DurableInboxEnvelopeRefusalV1::Pipeline(
                        AuthRefusal::Codec(error),
                    ));
                    continue;
                }
            };
            if envelope.roster_snapshot != self.config.wire.roster_snapshot {
                report
                    .refused
                    .push(DurableInboxEnvelopeRefusalV1::WrongRosterSnapshot);
                continue;
            }
            if envelope.policy_version != self.config.wire.policy_version {
                report
                    .refused
                    .push(DurableInboxEnvelopeRefusalV1::WrongPolicyVersion);
                continue;
            }
            let key = IdempotencyKeyV1::of(&envelope);
            if let Some(existing) = self.entry_by_key(&key)? {
                if existing.canonical_bytes == raw {
                    report.duplicates += 1;
                } else {
                    report
                        .refused
                        .push(DurableInboxEnvelopeRefusalV1::DurableEquivocation);
                }
                continue;
            }
            let accepted = match accept_envelope(
                &raw,
                &self.config.recipient_context(),
                rosters,
                &mut state,
                now,
            ) {
                Ok(accepted) => accepted,
                Err(refusal) => {
                    report
                        .refused
                        .push(DurableInboxEnvelopeRefusalV1::Pipeline(refusal));
                    continue;
                }
            };
            self.persist_accepted(&accepted.envelope, accepted.digest, &raw, now)?;
            report.accepted += 1;
        }
        Ok(report)
    }

    /// Drains pending route payloads into a Contracts-owned, idempotent
    /// authority.  The row is marked only after the returned receipt is
    /// durable.  Crashing between those steps causes exact redelivery.
    pub fn dispatch_routes<P: ContractsTransportPortV1>(
        &mut self,
        port: &mut P,
    ) -> Result<RouteDispatchReportV1, RouteDispatchErrorV1<P::Error>> {
        let entries = self
            .entries_with_state_and_kind(0, None)
            .map_err(RouteDispatchErrorV1::Inbox)?;
        let mut report = RouteDispatchReportV1::default();
        let mut blocked_flows = BTreeSet::new();
        for entry in entries {
            let flow = (entry.sender_id.0, entry.recipient_id.0);
            if entry.message_type != message_type::ROUTE_TRANSPORT {
                blocked_flows.insert(flow);
                continue;
            }
            if blocked_flows.contains(&flow) {
                report.blocked_by_f6 += 1;
                continue;
            }
            let envelope = RelayEnvelopeV1::decode(&entry.canonical_bytes)
                .map_err(|_| RouteDispatchErrorV1::Inbox(DurableInboxError::CorruptState))?;
            let commit = port
                .accept_signed_dsc1(ContractsRouteDeliveryV1 {
                    sender_id: entry.sender_id,
                    sequence: entry.sequence,
                    envelope_digest: entry.envelope_digest,
                    evidence: ContractsRouteDeliveryEvidenceV2::DirectRelayEnvelopeV1,
                    payload: &envelope.payload,
                })
                .map_err(RouteDispatchErrorV1::Contracts)?;
            self.mark_delivered(&entry, commit)
                .map_err(RouteDispatchErrorV1::Inbox)?;
            if commit.duplicate {
                report.duplicate_commits += 1;
            }
            match commit.disposition {
                DurablePayloadDispositionV1::Applied => report.applied += 1,
                DurablePayloadDispositionV1::FailedClosed => report.failed_closed += 1,
            }
        }
        Ok(report)
    }

    /// Drains pending F6 payloads through the same durable inbox that accepted
    /// route envelopes.  This is the only F6 delivery API, making it
    /// impossible for an F6 worker to advance an independent transcript.
    pub fn dispatch_f6<P: F6TransportPortV1>(
        &mut self,
        port: &mut P,
    ) -> Result<F6DispatchReportV1, F6DispatchErrorV1<P::Error>> {
        let entries = self
            .entries_with_state_and_kind(0, None)
            .map_err(F6DispatchErrorV1::Inbox)?;
        let mut report = F6DispatchReportV1::default();
        let mut blocked_flows = BTreeSet::new();
        for entry in entries {
            let flow = (entry.sender_id.0, entry.recipient_id.0);
            if entry.message_type == message_type::ROUTE_TRANSPORT {
                blocked_flows.insert(flow);
                continue;
            }
            if blocked_flows.contains(&flow) {
                report.blocked_by_route += 1;
                continue;
            }
            let envelope = RelayEnvelopeV1::decode(&entry.canonical_bytes)
                .map_err(|_| F6DispatchErrorV1::Inbox(DurableInboxError::CorruptState))?;
            let commit = port
                .accept_f6(F6PayloadDeliveryV1 {
                    sender_id: entry.sender_id,
                    sequence: entry.sequence,
                    message_type: entry.message_type,
                    envelope_digest: entry.envelope_digest,
                    payload: &envelope.payload,
                })
                .map_err(F6DispatchErrorV1::F6)?;
            self.mark_delivered(&entry, commit)
                .map_err(F6DispatchErrorV1::Inbox)?;
            if commit.duplicate {
                report.duplicate_commits += 1;
            }
            match commit.disposition {
                DurablePayloadDispositionV1::Applied => report.applied += 1,
                DurablePayloadDispositionV1::FailedClosed => report.failed_closed += 1,
            }
        }
        Ok(report)
    }

    /// Returns bounded backlog counters without exposing payload bytes.
    pub fn stats(&self) -> Result<DurableInboxStatsV1, DurableInboxError> {
        let mut stats = DurableInboxStatsV1::default();
        let mut statement = self.connection.prepare(
            "SELECT message_type, delivery_state, COUNT(*)
             FROM inbox_entries GROUP BY message_type, delivery_state",
        )?;
        let rows = statement.query_map([], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, i64>(2)?,
            ))
        })?;
        for row in rows {
            let (kind, state, count) = row?;
            let count = usize::try_from(count).map_err(|_| DurableInboxError::CorruptState)?;
            match state {
                0 if kind == i64::from(message_type::ROUTE_TRANSPORT) => {
                    stats.pending_route += count
                }
                0 => stats.pending_f6 += count,
                1 => stats.delivered += count,
                2 => stats.failed_closed += count,
                _ => return Err(DurableInboxError::CorruptState),
            }
        }
        Ok(stats)
    }

    fn persist_accepted(
        &mut self,
        envelope: &RelayEnvelopeV1,
        envelope_digest: Digest32,
        raw: &[u8],
        now: TimelockSpec,
    ) -> Result<(), DurableInboxError> {
        let (now_domain, now_value) = timelock_parts(now);
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let count: i64 = transaction.query_row(
            "SELECT accepted_count FROM inbox_meta WHERE singleton = 1",
            [],
            |row| row.get(0),
        )?;
        if count < 0 || count as u64 >= u64::from(self.config.max_entries) {
            return Err(DurableInboxError::CapacityExceeded);
        }
        let ordinal = count
            .checked_add(1)
            .ok_or(DurableInboxError::CorruptState)?;
        let row_digest = entry_digest(
            &self.config,
            ordinal,
            envelope,
            &envelope_digest,
            raw,
            now_domain,
            now_value,
        )?;
        let delivery_digest = delivery_digest(&self.config, &row_digest, 0, &ZERO_DIGEST)?;
        transaction.execute(
            "INSERT INTO inbox_entries
             (ordinal, sender_id, recipient_id, sequence_be, message_type,
              envelope_digest, canonical_bytes, accepted_now_domain,
              accepted_now_be, delivery_state, delivery_receipt, row_digest,
              delivery_digest)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, 0, ?10, ?11, ?12)",
            params![
                ordinal,
                envelope.sender_id.0.as_slice(),
                envelope.recipient_id.0.as_slice(),
                envelope.sequence.to_be_bytes().as_slice(),
                i64::from(envelope.message_type),
                envelope_digest.as_slice(),
                raw,
                i64::from(now_domain),
                now_value.to_be_bytes().as_slice(),
                ZERO_DIGEST.as_slice(),
                row_digest.as_slice(),
                delivery_digest.as_slice(),
            ],
        )?;
        let meta_changed = transaction.execute(
            "UPDATE inbox_meta SET accepted_count = ?1
             WHERE singleton = 1 AND accepted_count = ?2",
            params![ordinal, count],
        )?;
        if meta_changed != 1 {
            return Err(DurableInboxError::CorruptState);
        }
        transaction.commit()?;
        Ok(())
    }

    fn mark_delivered(
        &mut self,
        entry: &StoredEntryV1,
        commit: DurablePayloadCommitV1,
    ) -> Result<(), DurableInboxError> {
        if commit.durable_receipt == ZERO_DIGEST {
            return Err(DurableInboxError::InvalidConsumerCommit);
        }
        let state = match commit.disposition {
            DurablePayloadDispositionV1::Applied => 1_u8,
            DurablePayloadDispositionV1::FailedClosed => 2_u8,
        };
        let next_digest = delivery_digest(
            &self.config,
            &entry.row_digest,
            state,
            &commit.durable_receipt,
        )?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let changed = transaction.execute(
            "UPDATE inbox_entries
             SET delivery_state = ?1, delivery_receipt = ?2, delivery_digest = ?3
             WHERE ordinal = ?4 AND delivery_state = 0 AND row_digest = ?5",
            params![
                i64::from(state),
                commit.durable_receipt.as_slice(),
                next_digest.as_slice(),
                entry.ordinal,
                entry.row_digest.as_slice(),
            ],
        )?;
        if changed != 1 {
            return Err(DurableInboxError::CorruptState);
        }
        transaction.commit()?;
        Ok(())
    }

    fn audit_transcript(&self, rosters: &RosterRegistryV1) -> Result<(), DurableInboxError> {
        self.reconstruct_transcript(rosters).map(|_| ())
    }

    fn reconstruct_transcript(
        &self,
        rosters: &RosterRegistryV1,
    ) -> Result<TranscriptStateV1, DurableInboxError> {
        let entries = self.entries_with_state_and_kind_all()?;
        let mut state = TranscriptStateV1::new();
        for entry in entries {
            let accepted = accept_envelope(
                &entry.canonical_bytes,
                &self.config.recipient_context(),
                rosters,
                &mut state,
                entry.accepted_now,
            )
            .map_err(|_| DurableInboxError::CorruptState)?;
            if accepted.digest != entry.envelope_digest
                || accepted.envelope.sender_id != entry.sender_id
                || accepted.envelope.recipient_id != entry.recipient_id
                || accepted.envelope.sequence != entry.sequence
                || accepted.envelope.message_type != entry.message_type
                || accepted.envelope.roster_snapshot != self.config.wire.roster_snapshot
                || accepted.envelope.policy_version != self.config.wire.policy_version
            {
                return Err(DurableInboxError::CorruptState);
            }
        }
        Ok(state)
    }

    fn entries_with_state_and_kind_all(&self) -> Result<Vec<StoredEntryV1>, DurableInboxError> {
        let entries = self.query_entries("SELECT ordinal, sender_id, recipient_id, sequence_be, message_type, envelope_digest, canonical_bytes, accepted_now_domain, accepted_now_be, delivery_state, delivery_receipt, row_digest, delivery_digest FROM inbox_entries ORDER BY ordinal ASC", [])?;
        for (index, entry) in entries.iter().enumerate() {
            let expected = i64::try_from(index + 1).map_err(|_| DurableInboxError::CorruptState)?;
            if entry.ordinal != expected {
                return Err(DurableInboxError::CorruptState);
            }
        }
        Ok(entries)
    }

    fn entries_with_state_and_kind(
        &self,
        state: u8,
        kind: Option<u16>,
    ) -> Result<Vec<StoredEntryV1>, DurableInboxError> {
        match kind {
            Some(kind) => {
                let mut statement = self.connection.prepare(
                    "SELECT ordinal, sender_id, recipient_id, sequence_be, message_type,
                            envelope_digest, canonical_bytes, accepted_now_domain,
                            accepted_now_be, delivery_state, delivery_receipt, row_digest,
                            delivery_digest
                     FROM inbox_entries
                     WHERE delivery_state = ?1 AND message_type = ?2
                     ORDER BY ordinal ASC",
                )?;
                load_entries(
                    &mut statement,
                    params![i64::from(state), i64::from(kind)],
                    &self.config,
                )
            }
            None => {
                let mut statement = self.connection.prepare(
                    "SELECT ordinal, sender_id, recipient_id, sequence_be, message_type,
                            envelope_digest, canonical_bytes, accepted_now_domain,
                            accepted_now_be, delivery_state, delivery_receipt, row_digest,
                            delivery_digest
                     FROM inbox_entries WHERE delivery_state = ?1 ORDER BY ordinal ASC",
                )?;
                load_entries(&mut statement, params![i64::from(state)], &self.config)
            }
        }
    }

    fn query_entries<P: rusqlite::Params>(
        &self,
        sql: &str,
        params: P,
    ) -> Result<Vec<StoredEntryV1>, DurableInboxError> {
        let mut statement = self.connection.prepare(sql)?;
        load_entries(&mut statement, params, &self.config)
    }

    fn entry_by_key(
        &self,
        key: &IdempotencyKeyV1,
    ) -> Result<Option<StoredEntryV1>, DurableInboxError> {
        let mut statement = self.connection.prepare(
            "SELECT ordinal, sender_id, recipient_id, sequence_be, message_type,
                    envelope_digest, canonical_bytes, accepted_now_domain,
                    accepted_now_be, delivery_state, delivery_receipt, row_digest,
                    delivery_digest
             FROM inbox_entries
             WHERE sender_id = ?1 AND recipient_id = ?2 AND sequence_be = ?3",
        )?;
        let raw = statement
            .query_row(
                params![
                    key.sender_id.0.as_slice(),
                    key.recipient_id.0.as_slice(),
                    key.sequence.to_be_bytes().as_slice(),
                ],
                raw_entry_from_row,
            )
            .optional()?;
        raw.map(|raw| validate_raw_entry(raw, &self.config))
            .transpose()
    }

    fn validate_storage(&self) -> Result<(), DurableInboxError> {
        validate_root(&self.root)?;
        validate_root_entries(&self.root)?;
        validate_connection_authority(
            &self._database_authority,
            &self._sqlite_database_authority,
            &self.root.join(DATABASE_FILE_NAME),
        )?;
        for suffix in ["", "-wal", "-shm"] {
            let path = self.root.join(format!("{DATABASE_FILE_NAME}{suffix}"));
            if path
                .try_exists()
                .map_err(|_| DurableInboxError::StorageUnavailable)?
            {
                validate_owner_file(&path)?;
            }
        }
        let app_id: i64 = self
            .connection
            .pragma_query_value(None, "application_id", |row| row.get(0))?;
        let version: i64 = self
            .connection
            .pragma_query_value(None, "user_version", |row| row.get(0))?;
        if app_id != APPLICATION_ID || version != SCHEMA_VERSION {
            return Err(DurableInboxError::UnsupportedFormat);
        }
        validate_database_path(&self.connection, &self.root.join(DATABASE_FILE_NAME))?;
        let quick: String = self
            .connection
            .query_row("PRAGMA quick_check", [], |row| row.get(0))?;
        if quick != "ok" {
            return Err(DurableInboxError::CorruptState);
        }
        if schema_objects(&self.connection)? != reference_schema_objects()? {
            return Err(DurableInboxError::UnsupportedFormat);
        }
        self.require_meta()?;
        self.entries_with_state_and_kind_all()?;
        Ok(())
    }

    fn require_pristine_creation_state(&self) -> Result<(), DurableInboxError> {
        let stats = self.stats()?;
        let accepted: i64 = self.connection.query_row(
            "SELECT accepted_count FROM inbox_meta WHERE singleton = 1",
            [],
            |row| row.get(0),
        )?;
        if accepted != 0 || stats != DurableInboxStatsV1::default() {
            return Err(DurableInboxError::UnsupportedFormat);
        }
        Ok(())
    }

    fn require_meta(&self) -> Result<(), DurableInboxError> {
        let retained = self
            .connection
            .query_row(
                "SELECT schema_version, inbox_id, network_id, session_id, route_id,
                        roster_snapshot, recipient_id, policy_version, max_entries,
                        accepted_count
                 FROM inbox_meta WHERE singleton = 1",
                [],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, Vec<u8>>(1)?,
                        row.get::<_, Vec<u8>>(2)?,
                        row.get::<_, Vec<u8>>(3)?,
                        row.get::<_, Vec<u8>>(4)?,
                        row.get::<_, Vec<u8>>(5)?,
                        row.get::<_, Vec<u8>>(6)?,
                        row.get::<_, i64>(7)?,
                        row.get::<_, i64>(8)?,
                        row.get::<_, i64>(9)?,
                    ))
                },
            )
            .optional()?;
        let Some((
            version,
            inbox,
            network,
            session,
            route,
            roster,
            recipient,
            policy,
            max,
            accepted_count,
        )) = retained
        else {
            return Err(DurableInboxError::WrongIdentity);
        };
        if version != SCHEMA_VERSION
            || as_digest(&inbox)? != self.config.inbox_id
            || as_digest(&network)? != self.config.wire.network_id
            || as_digest(&session)? != self.config.wire.session_id
            || as_digest(&route)? != self.config.wire.route_id
            || as_digest(&roster)? != self.config.wire.roster_snapshot
            || as_digest(&recipient)? != self.config.recipient_id.0
            || policy != i64::from(self.config.wire.policy_version)
            || max != i64::from(self.config.max_entries)
            || accepted_count < 0
            || accepted_count > max
        {
            return Err(DurableInboxError::WrongIdentity);
        }
        let (actual_count, maximum_ordinal): (i64, i64) = self.connection.query_row(
            "SELECT COUNT(*), COALESCE(MAX(ordinal), 0) FROM inbox_entries",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        if actual_count != accepted_count || maximum_ordinal != accepted_count {
            return Err(DurableInboxError::CorruptState);
        }
        Ok(())
    }
}

type RawEntry = (
    i64,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    i64,
    Vec<u8>,
    Vec<u8>,
    i64,
    Vec<u8>,
    i64,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
);

fn raw_entry_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<RawEntry> {
    Ok((
        row.get(0)?,
        row.get(1)?,
        row.get(2)?,
        row.get(3)?,
        row.get(4)?,
        row.get(5)?,
        row.get(6)?,
        row.get(7)?,
        row.get(8)?,
        row.get(9)?,
        row.get(10)?,
        row.get(11)?,
        row.get(12)?,
    ))
}

fn load_entries<P: rusqlite::Params>(
    statement: &mut rusqlite::Statement<'_>,
    params: P,
    config: &DurableInboxConfigV1,
) -> Result<Vec<StoredEntryV1>, DurableInboxError> {
    let rows = statement.query_map(params, raw_entry_from_row)?;
    let mut entries = Vec::new();
    for row in rows {
        entries.push(validate_raw_entry(row?, config)?);
    }
    Ok(entries)
}

fn validate_raw_entry(
    raw: RawEntry,
    config: &DurableInboxConfigV1,
) -> Result<StoredEntryV1, DurableInboxError> {
    let (
        ordinal,
        sender,
        recipient,
        sequence,
        message_type_raw,
        envelope_digest_raw,
        canonical_bytes,
        now_domain_raw,
        now_value_raw,
        delivery_state_raw,
        delivery_receipt_raw,
        row_digest_raw,
        delivery_digest_raw,
    ) = raw;
    if ordinal <= 0 || ordinal > i64::from(config.max_entries) {
        return Err(DurableInboxError::CorruptState);
    }
    let sender_id = ParticipantId(as_digest(&sender)?);
    let recipient_id = ParticipantId(as_digest(&recipient)?);
    let sequence = as_u64_be(&sequence)?;
    let message_type =
        u16::try_from(message_type_raw).map_err(|_| DurableInboxError::CorruptState)?;
    let envelope_digest = as_digest(&envelope_digest_raw)?;
    let now_domain = u8::try_from(now_domain_raw).map_err(|_| DurableInboxError::CorruptState)?;
    let now_value = as_u64_be(&now_value_raw)?;
    let accepted_now = timelock_from_parts(now_domain, now_value)?;
    let delivery_state =
        u8::try_from(delivery_state_raw).map_err(|_| DurableInboxError::CorruptState)?;
    let delivery_receipt = as_digest(&delivery_receipt_raw)?;
    let row_digest = as_digest(&row_digest_raw)?;
    let retained_delivery_digest = as_digest(&delivery_digest_raw)?;
    let envelope =
        RelayEnvelopeV1::decode(&canonical_bytes).map_err(|_| DurableInboxError::CorruptState)?;
    if envelope.sender_id != sender_id
        || envelope.recipient_id != recipient_id
        || envelope.sequence != sequence
        || envelope.message_type != message_type
        || envelope.recipient_id != config.recipient_id
        || envelope.network_id != config.wire.network_id
        || envelope.session_id != config.wire.session_id
        || envelope.route_id != config.wire.route_id
        || envelope.roster_snapshot != config.wire.roster_snapshot
        || envelope.policy_version != config.wire.policy_version
        || envelope
            .envelope_digest()
            .map_err(|_| DurableInboxError::CorruptState)?
            != envelope_digest
        || entry_digest(
            config,
            ordinal,
            &envelope,
            &envelope_digest,
            &canonical_bytes,
            now_domain,
            now_value,
        )? != row_digest
        || delivery_digest(config, &row_digest, delivery_state, &delivery_receipt)?
            != retained_delivery_digest
        || (delivery_state == 0 && delivery_receipt != ZERO_DIGEST)
        || (delivery_state != 0 && delivery_receipt == ZERO_DIGEST)
        || delivery_state > 2
    {
        return Err(DurableInboxError::CorruptState);
    }
    Ok(StoredEntryV1 {
        ordinal,
        sender_id,
        recipient_id,
        sequence,
        message_type,
        envelope_digest,
        canonical_bytes,
        accepted_now,
        row_digest,
    })
}

fn entry_digest(
    config: &DurableInboxConfigV1,
    ordinal: i64,
    envelope: &RelayEnvelopeV1,
    envelope_digest: &Digest32,
    raw: &[u8],
    now_domain: u8,
    now_value: u64,
) -> Result<Digest32, DurableInboxError> {
    digest_parts(
        ENTRY_DOMAIN,
        &[
            config.inbox_id.as_slice(),
            &ordinal.to_be_bytes(),
            envelope.sender_id.0.as_slice(),
            envelope.recipient_id.0.as_slice(),
            &envelope.sequence.to_be_bytes(),
            &envelope.message_type.to_be_bytes(),
            envelope_digest.as_slice(),
            &[now_domain],
            &now_value.to_be_bytes(),
            &(raw.len() as u32).to_be_bytes(),
            raw,
        ],
    )
}

fn delivery_digest(
    config: &DurableInboxConfigV1,
    row_digest: &Digest32,
    state: u8,
    receipt: &Digest32,
) -> Result<Digest32, DurableInboxError> {
    digest_parts(
        DELIVERY_DOMAIN,
        &[
            config.inbox_id.as_slice(),
            row_digest.as_slice(),
            &[state],
            receipt.as_slice(),
        ],
    )
}

fn digest_parts(domain: &[u8], parts: &[&[u8]]) -> Result<Digest32, DurableInboxError> {
    let mut hasher = Blake2bVar::new(32).map_err(|_| DurableInboxError::CorruptState)?;
    hasher.update(domain);
    for part in parts {
        hasher.update(part);
    }
    let mut digest = [0; 32];
    hasher
        .finalize_variable(&mut digest)
        .map_err(|_| DurableInboxError::CorruptState)?;
    Ok(digest)
}

fn timelock_parts(spec: TimelockSpec) -> (u8, u64) {
    match spec {
        TimelockSpec::BlockHeight { value } => (1, value),
        TimelockSpec::TimestampSeconds { value } => (2, value),
        TimelockSpec::BtcTime512s { value } => (3, value),
    }
}

fn timelock_from_parts(domain: u8, value: u64) -> Result<TimelockSpec, DurableInboxError> {
    match domain {
        1 => Ok(TimelockSpec::BlockHeight { value }),
        2 => Ok(TimelockSpec::TimestampSeconds { value }),
        3 => Ok(TimelockSpec::BtcTime512s { value }),
        _ => Err(DurableInboxError::CorruptState),
    }
}

fn as_digest(bytes: &[u8]) -> Result<Digest32, DurableInboxError> {
    bytes
        .try_into()
        .map_err(|_| DurableInboxError::CorruptState)
}

fn as_u64_be(bytes: &[u8]) -> Result<u64, DurableInboxError> {
    let exact: [u8; 8] = bytes
        .try_into()
        .map_err(|_| DurableInboxError::CorruptState)?;
    Ok(u64::from_be_bytes(exact))
}

fn configure_connection(connection: &Connection) -> Result<(), DurableInboxError> {
    connection.busy_timeout(std::time::Duration::from_secs(5))?;
    connection.execute_batch(
        "PRAGMA journal_mode=WAL;
         PRAGMA synchronous=FULL;
         PRAGMA foreign_keys=ON;
         PRAGMA read_uncommitted=OFF;
         PRAGMA trusted_schema=OFF;
         PRAGMA secure_delete=ON;
         PRAGMA temp_store=MEMORY;",
    )?;
    let defensive = rusqlite::config::DbConfig::SQLITE_DBCONFIG_DEFENSIVE;
    if !connection.set_db_config(defensive, true)? || !connection.db_config(defensive)? {
        return Err(DurableInboxError::UnsupportedFormat);
    }
    let journal: String = connection.query_row("PRAGMA journal_mode", [], |row| row.get(0))?;
    let synchronous: i64 = connection.query_row("PRAGMA synchronous", [], |row| row.get(0))?;
    let foreign_keys: i64 = connection.query_row("PRAGMA foreign_keys", [], |row| row.get(0))?;
    let read_uncommitted: i64 =
        connection.query_row("PRAGMA read_uncommitted", [], |row| row.get(0))?;
    let trusted_schema: i64 =
        connection.query_row("PRAGMA trusted_schema", [], |row| row.get(0))?;
    let secure_delete: i64 = connection.query_row("PRAGMA secure_delete", [], |row| row.get(0))?;
    let temp_store: i64 = connection.query_row("PRAGMA temp_store", [], |row| row.get(0))?;
    let busy_timeout: i64 = connection.query_row("PRAGMA busy_timeout", [], |row| row.get(0))?;
    if !journal.eq_ignore_ascii_case("wal")
        || synchronous != 2
        || foreign_keys != 1
        || read_uncommitted != 0
        || trusted_schema != 0
        || secure_delete != 1
        || temp_store != 2
        || busy_timeout != 5_000
    {
        return Err(DurableInboxError::UnsupportedFormat);
    }
    Ok(())
}

fn insert_meta(
    connection: &Connection,
    config: DurableInboxConfigV1,
) -> Result<(), DurableInboxError> {
    connection.execute(
        "INSERT INTO inbox_meta
         (singleton, schema_version, inbox_id, network_id, session_id, route_id,
          roster_snapshot, recipient_id, policy_version, max_entries, accepted_count)
         VALUES (1, ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, 0)",
        params![
            SCHEMA_VERSION,
            config.inbox_id.as_slice(),
            config.wire.network_id.as_slice(),
            config.wire.session_id.as_slice(),
            config.wire.route_id.as_slice(),
            config.wire.roster_snapshot.as_slice(),
            config.recipient_id.0.as_slice(),
            i64::from(config.wire.policy_version),
            i64::from(config.max_entries),
        ],
    )?;
    Ok(())
}

fn initialize_pristine_store(
    connection: &Connection,
    config: DurableInboxConfigV1,
) -> Result<(), DurableInboxError> {
    connection.execute_batch("BEGIN IMMEDIATE;")?;
    let initialized = (|| {
        connection.execute_batch(SCHEMA_SQL)?;
        connection.pragma_update(None, "application_id", APPLICATION_ID)?;
        connection.pragma_update(None, "user_version", SCHEMA_VERSION)?;
        insert_meta(connection, config)
    })();
    match initialized {
        Ok(()) => connection.execute_batch("COMMIT;")?,
        Err(error) => {
            let _rollback = connection.execute_batch("ROLLBACK;");
            return Err(error);
        }
    }
    Ok(())
}

type SchemaObjectV1 = (String, String, String, String);

fn schema_objects(connection: &Connection) -> Result<BTreeSet<SchemaObjectV1>, DurableInboxError> {
    const MAX_SCHEMA_OBJECTS: i64 = 8;
    const MAX_SCHEMA_SQL_BYTES: i64 = 131_072;
    let (count, maximum, total): (i64, Option<i64>, Option<i64>) = connection.query_row(
        "SELECT COUNT(*), MAX(length(sql)), SUM(length(sql))
         FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%'",
        [],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    )?;
    if !(0..=MAX_SCHEMA_OBJECTS).contains(&count)
        || maximum.is_some_and(|value| !(0..=MAX_SCHEMA_SQL_BYTES).contains(&value))
        || total.is_some_and(|value| !(0..=MAX_SCHEMA_SQL_BYTES).contains(&value))
    {
        return Err(DurableInboxError::UnsupportedFormat);
    }
    let mut statement = connection.prepare(
        "SELECT type, name, tbl_name, sql FROM sqlite_schema
         WHERE name NOT LIKE 'sqlite_%'",
    )?;
    let rows = statement.query_map([], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, String>(3)?,
        ))
    })?;
    let mut objects = BTreeSet::new();
    for row in rows {
        if !objects.insert(row?) {
            return Err(DurableInboxError::CorruptState);
        }
    }
    if i64::try_from(objects.len()).map_err(|_| DurableInboxError::CorruptState)? != count {
        return Err(DurableInboxError::UnsupportedFormat);
    }
    Ok(objects)
}

fn reference_schema_objects() -> Result<BTreeSet<SchemaObjectV1>, DurableInboxError> {
    let reference = Connection::open_in_memory()?;
    reference.execute_batch(SCHEMA_SQL)?;
    schema_objects(&reference)
}

fn require_pristine_connection(
    connection: &Connection,
    config: &DurableInboxConfigV1,
) -> Result<(), DurableInboxError> {
    let retained = connection
        .query_row(
            "SELECT schema_version, inbox_id, network_id, session_id, route_id,
                    roster_snapshot, recipient_id, policy_version, max_entries,
                    accepted_count
             FROM inbox_meta WHERE singleton = 1",
            [],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, Vec<u8>>(3)?,
                    row.get::<_, Vec<u8>>(4)?,
                    row.get::<_, Vec<u8>>(5)?,
                    row.get::<_, Vec<u8>>(6)?,
                    row.get::<_, i64>(7)?,
                    row.get::<_, i64>(8)?,
                    row.get::<_, i64>(9)?,
                ))
            },
        )
        .optional()?;
    let Some((version, inbox, network, session, route, roster, recipient, policy, max, accepted)) =
        retained
    else {
        return Err(DurableInboxError::WrongIdentity);
    };
    let rows: i64 =
        connection.query_row("SELECT COUNT(*) FROM inbox_entries", [], |row| row.get(0))?;
    if version != SCHEMA_VERSION
        || as_digest(&inbox)? != config.inbox_id
        || as_digest(&network)? != config.wire.network_id
        || as_digest(&session)? != config.wire.session_id
        || as_digest(&route)? != config.wire.route_id
        || as_digest(&roster)? != config.wire.roster_snapshot
        || as_digest(&recipient)? != config.recipient_id.0
        || policy != i64::from(config.wire.policy_version)
        || max != i64::from(config.max_entries)
        || accepted != 0
        || rows != 0
    {
        return Err(DurableInboxError::UnsupportedFormat);
    }
    Ok(())
}

fn preflight_resumable_database(
    database_path: &Path,
    authority: &File,
    config: &DurableInboxConfigV1,
) -> Result<DurableProductionCreationStateV1, DurableInboxError> {
    validate_database_authority(authority, database_path)?;
    if authority
        .metadata()
        .map_err(|_| DurableInboxError::StorageUnavailable)?
        .len()
        == 0
    {
        return Ok(DurableProductionCreationStateV1::Incomplete);
    }
    let (connection, sqlite_database_authority) = open_connection_via_authority(
        authority,
        database_path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?;
    validate_connection_authority(authority, &sqlite_database_authority, database_path)?;
    validate_database_path(&connection, database_path)?;
    let state = classify_resumable_connection(&connection, config)?;
    validate_connection_authority(authority, &sqlite_database_authority, database_path)?;
    Ok(state)
}

fn classify_resumable_connection(
    connection: &Connection,
    config: &DurableInboxConfigV1,
) -> Result<DurableProductionCreationStateV1, DurableInboxError> {
    let schema = schema_objects(connection)?;
    let app_id: i64 = connection.pragma_query_value(None, "application_id", |row| row.get(0))?;
    let version: i64 = connection.pragma_query_value(None, "user_version", |row| row.get(0))?;
    let state = if schema.is_empty() && app_id == 0 && version == 0 {
        DurableProductionCreationStateV1::Incomplete
    } else if schema == reference_schema_objects()?
        && app_id == APPLICATION_ID
        && version == SCHEMA_VERSION
    {
        require_pristine_connection(connection, config)?;
        DurableProductionCreationStateV1::InitializedPristine
    } else {
        return Err(DurableInboxError::UnsupportedFormat);
    };
    Ok(state)
}

fn validate_database_path(
    connection: &Connection,
    expected_path: &Path,
) -> Result<(), DurableInboxError> {
    let expected =
        fs::canonicalize(expected_path).map_err(|_| DurableInboxError::InvalidConfiguration)?;
    if expected != expected_path {
        return Err(DurableInboxError::InvalidConfiguration);
    }
    let mut statement = connection.prepare("PRAGMA database_list")?;
    let rows = statement.query_map([], |row| {
        Ok((row.get::<_, String>(1)?, row.get::<_, String>(2)?))
    })?;
    let mut saw_main = false;
    for row in rows {
        let (name, path) = row?;
        match name.as_str() {
            "main" if Path::new(&path) == expected => saw_main = true,
            "temp" if path.is_empty() => {}
            _ => return Err(DurableInboxError::InvalidConfiguration),
        }
    }
    if !saw_main {
        return Err(DurableInboxError::InvalidConfiguration);
    }
    Ok(())
}

fn create_root(root: &Path) -> Result<(), DurableInboxError> {
    validate_new_path(root)?;
    match DirBuilder::new().mode(ROOT_MODE).create(root) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            return Err(DurableInboxError::AlreadyExists)
        }
        Err(_) => return Err(DurableInboxError::StorageUnavailable),
    }
    sync_directory(root)?;
    let parent = root
        .parent()
        .ok_or(DurableInboxError::InvalidConfiguration)?;
    sync_directory(parent)?;
    validate_root(root)
}

fn validate_new_path(root: &Path) -> Result<(), DurableInboxError> {
    if !root.is_absolute() || root.file_name().is_none() {
        return Err(DurableInboxError::InvalidConfiguration);
    }
    let parent = root
        .parent()
        .ok_or(DurableInboxError::InvalidConfiguration)?;
    let canonical_parent =
        fs::canonicalize(parent).map_err(|_| DurableInboxError::InvalidConfiguration)?;
    if canonical_parent != parent {
        return Err(DurableInboxError::InvalidConfiguration);
    }
    validate_owner_directory(parent)
}

fn validate_root(root: &Path) -> Result<(), DurableInboxError> {
    if !root.is_absolute()
        || fs::canonicalize(root).map_err(|_| DurableInboxError::StorageUnavailable)? != root
    {
        return Err(DurableInboxError::InvalidConfiguration);
    }
    validate_owner_directory(root)
}

fn validate_root_entries(root: &Path) -> Result<(), DurableInboxError> {
    let allowed = [
        LOCK_FILE_NAME,
        DATABASE_FILE_NAME,
        "route-inbox-v1.sqlite3-wal",
        "route-inbox-v1.sqlite3-shm",
    ];
    let entries = fs::read_dir(root).map_err(|_| DurableInboxError::StorageUnavailable)?;
    for entry in entries {
        let name = entry
            .map_err(|_| DurableInboxError::StorageUnavailable)?
            .file_name()
            .into_string()
            .map_err(|_| DurableInboxError::InvalidConfiguration)?;
        if !allowed.contains(&name.as_str()) {
            return Err(DurableInboxError::InvalidConfiguration);
        }
    }
    Ok(())
}

fn inspect_creation_state(
    root: &Path,
    config: &DurableInboxConfigV1,
) -> Result<DurableProductionCreationStateV1, DurableInboxError> {
    match fs::symlink_metadata(root) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            validate_new_path(root)?;
            return Ok(DurableProductionCreationStateV1::Missing);
        }
        Err(_) => return Err(DurableInboxError::StorageUnavailable),
        Ok(_) => validate_root(root)?,
    }
    validate_root_entries(root)?;
    let lock_path = root.join(LOCK_FILE_NAME);
    let database_path = root.join(DATABASE_FILE_NAME);
    let lock_exists = lock_path
        .try_exists()
        .map_err(|_| DurableInboxError::StorageUnavailable)?;
    let database_exists = database_path
        .try_exists()
        .map_err(|_| DurableInboxError::StorageUnavailable)?;
    if !lock_exists {
        if fs::read_dir(root)
            .map_err(|_| DurableInboxError::StorageUnavailable)?
            .next()
            .is_none()
        {
            return Ok(DurableProductionCreationStateV1::Incomplete);
        }
        return Err(DurableInboxError::InvalidConfiguration);
    }
    validate_owner_file(&lock_path)?;
    validate_resumable_database_files(root, database_exists)?;
    if !database_exists {
        return Ok(DurableProductionCreationStateV1::Incomplete);
    }
    let authority = open_database_authority(&database_path)?;
    preflight_resumable_database(&database_path, &authority, config)
}

fn create_database_authority(path: &Path) -> Result<File, DurableInboxError> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(FILE_MODE)
        .open(path)
        .map_err(|_| DurableInboxError::StorageUnavailable)?;
    validate_database_authority(&file, path)?;
    file.sync_all()
        .map_err(|_| DurableInboxError::StorageUnavailable)?;
    sync_directory(
        path.parent()
            .ok_or(DurableInboxError::InvalidConfiguration)?,
    )?;
    Ok(file)
}

fn open_database_authority(path: &Path) -> Result<File, DurableInboxError> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .map_err(|_| DurableInboxError::StorageUnavailable)?;
    validate_database_authority(&file, path)?;
    Ok(file)
}

fn open_connection_via_authority(
    authority: &File,
    database_path: &Path,
    flags: OpenFlags,
) -> Result<(Connection, File), DurableInboxError> {
    open_connection_via_authority_with_hooks(authority, database_path, flags, || Ok(()), || Ok(()))
}

fn open_connection_via_authority_with_hooks<BeforeOpen, AfterOpen>(
    authority: &File,
    database_path: &Path,
    flags: OpenFlags,
    before_open: BeforeOpen,
    after_open: AfterOpen,
) -> Result<(Connection, File), DurableInboxError>
where
    BeforeOpen: FnOnce() -> Result<(), DurableInboxError>,
    AfterOpen: FnOnce() -> Result<(), DurableInboxError>,
{
    validate_database_authority(authority, database_path)?;
    let before = process_descriptor_snapshot()?;
    before_open()?;
    let connection = Connection::open_with_flags(database_path, flags)?;
    after_open()?;
    let sqlite_authority = capture_new_sqlite_database_authority(authority, &before)?;
    validate_connection_authority(authority, &sqlite_authority, database_path)?;
    Ok((connection, sqlite_authority))
}

fn validate_database_authority(authority: &File, path: &Path) -> Result<(), DurableInboxError> {
    validate_owner_file(path)?;
    let retained = authority
        .metadata()
        .map_err(|_| DurableInboxError::StorageUnavailable)?;
    let named = fs::symlink_metadata(path).map_err(|_| DurableInboxError::StorageUnavailable)?;
    if retained.dev() != named.dev() || retained.ino() != named.ino() {
        return Err(DurableInboxError::InvalidConfiguration);
    }
    Ok(())
}

fn validate_connection_authority(
    authority: &File,
    sqlite_authority: &File,
    path: &Path,
) -> Result<(), DurableInboxError> {
    validate_database_authority(authority, path)?;
    let retained = authority
        .metadata()
        .map_err(|_| DurableInboxError::StorageUnavailable)?;
    let sqlite = sqlite_authority
        .metadata()
        .map_err(|_| DurableInboxError::StorageUnavailable)?;
    if retained.dev() != sqlite.dev() || retained.ino() != sqlite.ino() {
        return Err(DurableInboxError::InvalidConfiguration);
    }
    Ok(())
}

fn process_descriptor_snapshot() -> Result<BTreeMap<i32, (u64, u64)>, DurableInboxError> {
    let mut snapshot = BTreeMap::new();
    for entry in fs::read_dir("/proc/self/fd").map_err(|_| DurableInboxError::StorageUnavailable)? {
        let entry = entry.map_err(|_| DurableInboxError::StorageUnavailable)?;
        let Ok(fd) = entry.file_name().to_string_lossy().parse::<i32>() else {
            continue;
        };
        match fs::metadata(entry.path()) {
            Ok(metadata) => {
                snapshot.insert(fd, (metadata.dev(), metadata.ino()));
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err(DurableInboxError::StorageUnavailable),
        }
    }
    Ok(snapshot)
}

fn capture_new_sqlite_database_authority(
    authority: &File,
    before: &BTreeMap<i32, (u64, u64)>,
) -> Result<File, DurableInboxError> {
    let retained = authority
        .metadata()
        .map_err(|_| DurableInboxError::StorageUnavailable)?;
    let expected = (retained.dev(), retained.ino());
    let after = process_descriptor_snapshot()?;
    let mut candidates = after.iter().filter_map(|(fd, identity)| {
        (*identity == expected && before.get(fd) != Some(identity)).then_some(*fd)
    });
    let candidate = candidates
        .next()
        .ok_or(DurableInboxError::InvalidConfiguration)?;
    if candidates.next().is_some() {
        return Err(DurableInboxError::InvalidConfiguration);
    }
    let proof = File::open(PathBuf::from("/proc/self/fd").join(candidate.to_string()))
        .map_err(|_| DurableInboxError::StorageUnavailable)?;
    let proof_metadata = proof
        .metadata()
        .map_err(|_| DurableInboxError::StorageUnavailable)?;
    if (proof_metadata.dev(), proof_metadata.ino()) != expected {
        return Err(DurableInboxError::InvalidConfiguration);
    }
    Ok(proof)
}

fn acquire_resume_lock(root: &Path) -> Result<File, DurableInboxError> {
    match fs::symlink_metadata(root) {
        Ok(_) => validate_root(root)?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => create_root(root)?,
        Err(_) => return Err(DurableInboxError::StorageUnavailable),
    }
    validate_root_entries(root)?;
    let lock_path = root.join(LOCK_FILE_NAME);
    let lock_exists = lock_path
        .try_exists()
        .map_err(|_| DurableInboxError::StorageUnavailable)?;
    if lock_exists {
        acquire_lock(root, false)
    } else {
        let mut entries = fs::read_dir(root).map_err(|_| DurableInboxError::StorageUnavailable)?;
        if entries.next().is_some() {
            return Err(DurableInboxError::InvalidConfiguration);
        }
        acquire_lock(root, true)
    }
}

fn validate_resumable_database_files(
    root: &Path,
    database_exists: bool,
) -> Result<(), DurableInboxError> {
    if database_exists {
        validate_owner_file(&root.join(DATABASE_FILE_NAME))?;
    }
    for suffix in ["-wal", "-shm"] {
        let sidecar = root.join(format!("{DATABASE_FILE_NAME}{suffix}"));
        if sidecar
            .try_exists()
            .map_err(|_| DurableInboxError::StorageUnavailable)?
        {
            if !database_exists {
                return Err(DurableInboxError::InvalidConfiguration);
            }
            validate_owner_file(&sidecar)?;
        }
    }
    Ok(())
}

fn validate_owner_directory(path: &Path) -> Result<(), DurableInboxError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| DurableInboxError::StorageUnavailable)?;
    if !metadata.file_type().is_dir()
        || metadata.file_type().is_symlink()
        || metadata.uid() != geteuid().as_raw()
        || metadata.mode() & 0o7777 != ROOT_MODE
        || metadata.nlink() == 0
    {
        return Err(DurableInboxError::InvalidConfiguration);
    }
    Ok(())
}

fn validate_owner_file(path: &Path) -> Result<(), DurableInboxError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| DurableInboxError::StorageUnavailable)?;
    if !metadata.file_type().is_file()
        || metadata.file_type().is_symlink()
        || metadata.uid() != geteuid().as_raw()
        || metadata.mode() & 0o7777 != FILE_MODE
        || metadata.nlink() != 1
    {
        return Err(DurableInboxError::InvalidConfiguration);
    }
    Ok(())
}

fn acquire_lock(root: &Path, create: bool) -> Result<File, DurableInboxError> {
    let path = root.join(LOCK_FILE_NAME);
    let mut options = OpenOptions::new();
    options.read(true).write(true).mode(FILE_MODE);
    if create {
        options.create_new(true);
    }
    let file = options
        .open(&path)
        .map_err(|_| DurableInboxError::StorageUnavailable)?;
    validate_owner_file(&path)?;
    let retained = file
        .metadata()
        .map_err(|_| DurableInboxError::StorageUnavailable)?;
    let named = fs::symlink_metadata(&path).map_err(|_| DurableInboxError::StorageUnavailable)?;
    if retained.dev() != named.dev() || retained.ino() != named.ino() {
        return Err(DurableInboxError::InvalidConfiguration);
    }
    flock(file.as_fd(), FlockOperation::NonBlockingLockExclusive)
        .map_err(|_| DurableInboxError::StorageUnavailable)?;
    if create {
        file.sync_all()
            .map_err(|_| DurableInboxError::StorageUnavailable)?;
        sync_directory(root)?;
    }
    Ok(file)
}

fn sync_directory(path: &Path) -> Result<(), DurableInboxError> {
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| DurableInboxError::StorageUnavailable)
}

#[cfg(test)]
mod database_authority_tests {
    use std::error::Error;
    use std::os::unix::fs::PermissionsExt;

    use super::*;

    fn sqlite_file(path: &Path, marker: i64) -> Result<(), Box<dyn Error>> {
        let connection = Connection::open(path)?;
        connection.pragma_update(None, "user_version", marker)?;
        drop(connection);
        fs::set_permissions(path, fs::Permissions::from_mode(FILE_MODE))?;
        Ok(())
    }

    #[test]
    fn sqlite_fd_proof_preserves_named_wal_authority() -> Result<(), Box<dyn Error>> {
        let temporary = tempfile::tempdir()?;
        let database = temporary.path().join(DATABASE_FILE_NAME);
        sqlite_file(&database, 7)?;
        let authority = open_database_authority(&database)?;
        let (connection, sqlite_authority) = open_connection_via_authority(
            &authority,
            &database,
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;
        configure_connection(&connection)?;
        connection.execute("CREATE TABLE authority_probe (value INTEGER) STRICT", [])?;
        validate_connection_authority(&authority, &sqlite_authority, &database)?;
        let journal: String = connection.query_row("PRAGMA journal_mode", [], |row| row.get(0))?;
        assert!(journal.eq_ignore_ascii_case("wal"));
        assert_eq!(
            connection.pragma_query_value::<i64, _>(None, "user_version", |row| row.get(0))?,
            7
        );
        assert!(temporary
            .path()
            .join(format!("{DATABASE_FILE_NAME}-wal"))
            .exists());
        Ok(())
    }

    #[test]
    fn sqlite_fd_proof_refuses_swap_open_swap_back() -> Result<(), Box<dyn Error>> {
        let temporary = tempfile::tempdir()?;
        let database = temporary.path().join(DATABASE_FILE_NAME);
        let retained_name = temporary.path().join("retained.sqlite3");
        let alternate = temporary.path().join("alternate.sqlite3");
        sqlite_file(&database, 11)?;
        sqlite_file(&alternate, 22)?;
        let authority = open_database_authority(&database)?;
        let result = open_connection_via_authority_with_hooks(
            &authority,
            &database,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
            || {
                fs::rename(&database, &retained_name)
                    .and_then(|()| fs::rename(&alternate, &database))
                    .map_err(|_| DurableInboxError::StorageUnavailable)
            },
            || {
                fs::rename(&database, &alternate)
                    .and_then(|()| fs::rename(&retained_name, &database))
                    .map_err(|_| DurableInboxError::StorageUnavailable)
            },
        );
        assert!(matches!(
            result,
            Err(DurableInboxError::InvalidConfiguration)
        ));
        validate_database_authority(&authority, &database)?;
        Ok(())
    }
}
