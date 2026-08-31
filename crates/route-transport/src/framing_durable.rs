//! Owner-only durable V2 frame reassembly and Contracts adapter for Linux.

use std::collections::BTreeMap;
use std::fs::{self, DirBuilder, File, OpenOptions};
use std::os::fd::AsFd;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use blake2::{
    digest::{Update, VariableOutput},
    Blake2bVar,
};
use kaystra_core::types::Digest32;
use relay::ParticipantId;
use rusqlite::{
    params, Connection, OpenFlags, OptionalExtension, Transaction, TransactionBehavior,
};
use rustix::fs::{flock, FlockOperation};
use rustix::process::geteuid;

use crate::durable::{
    ContractsRouteDeliveryV1, ContractsTransportPortV1, DurablePayloadCommitV1,
    DurablePayloadDispositionV1,
};
use crate::framing::{
    binding_digest_v2, encode_frame, frame_count, verify_complete_message_v2, RouteFrameErrorV2,
    RouteFrameV2, MAX_FRAMED_DSC1_BYTES_V2, MAX_ROUTE_FRAME_CHUNK_BYTES_V2,
};
use crate::{DurableProductionCreationStateV1, RouteWireContextV1};

const DATABASE_FILE_NAME: &str = "route-frame-reassembly-v2.sqlite3";
const LOCK_FILE_NAME: &str = ".route-frame-reassembly-v2.lock";
const ROOT_MODE: u32 = 0o700;
const FILE_MODE: u32 = 0o600;
const SCHEMA_VERSION: i64 = 2;
const APPLICATION_ID: i64 = 0x444f_4d46; // "DOMF"
const ZERO_DIGEST: Digest32 = [0; 32];
const MAX_RETAINED_MESSAGES: u16 = 256;
const MAX_ACTIVE_BYTES: u64 = 64 * 1024 * 1024;
const MAX_ACTIVE_CHUNKS: u32 = 8_448;
const MESSAGE_ROW_DOMAIN: &[u8] = b"DOM-INTEROP/ROUTE-FRAME-STORE/MESSAGE/V2\0";
const FRAME_ROW_DOMAIN: &[u8] = b"DOM-INTEROP/ROUTE-FRAME-STORE/FRAME/V2\0";
const TERMINAL_FRAME_DOMAIN: &[u8] = b"DOM-INTEROP/ROUTE-FRAME-STORE/TERMINAL-FRAME/V2\0";
const FRAME_RECEIPT_DOMAIN: &[u8] = b"DOM-INTEROP/ROUTE-FRAME-STORE/RECEIPT/V2\0";
const REASSEMBLY_FAILURE_DOMAIN: &[u8] = b"DOM-INTEROP/ROUTE-FRAME-STORE/FAILURE/V2\0";

const SCHEMA_SQL: &str = r#"
CREATE TABLE reassembly_meta (
    singleton           INTEGER PRIMARY KEY CHECK (singleton = 1),
    schema_version      INTEGER NOT NULL CHECK (schema_version = 2),
    reassembler_id      BLOB NOT NULL CHECK (length(reassembler_id) = 32),
    network_id          BLOB NOT NULL CHECK (length(network_id) = 32),
    session_id          BLOB NOT NULL CHECK (length(session_id) = 32),
    route_id            BLOB NOT NULL CHECK (length(route_id) = 32),
    roster_snapshot     BLOB NOT NULL CHECK (length(roster_snapshot) = 32),
    recipient_id        BLOB NOT NULL CHECK (length(recipient_id) = 32),
    policy_version      INTEGER NOT NULL CHECK (policy_version > 0),
    max_messages        INTEGER NOT NULL CHECK (max_messages > 0 AND max_messages <= 256),
    max_active_bytes    INTEGER NOT NULL CHECK (max_active_bytes > 16384 AND max_active_bytes <= 67108864),
    max_active_chunks   INTEGER NOT NULL CHECK (max_active_chunks > 0 AND max_active_chunks <= 8448),
    retained_messages   INTEGER NOT NULL CHECK (retained_messages >= 0 AND retained_messages <= max_messages),
    active_bytes        INTEGER NOT NULL CHECK (active_bytes >= 0 AND active_bytes <= max_active_bytes),
    active_chunks       INTEGER NOT NULL CHECK (active_chunks >= 0 AND active_chunks <= max_active_chunks)
) STRICT;

CREATE TABLE reassembly_messages (
    binding_digest      BLOB PRIMARY KEY CHECK (length(binding_digest) = 32),
    sender_id           BLOB NOT NULL CHECK (length(sender_id) = 32),
    recipient_id        BLOB NOT NULL CHECK (length(recipient_id) = 32),
    message_digest      BLOB NOT NULL CHECK (length(message_digest) = 32),
    total_len_be        BLOB NOT NULL CHECK (length(total_len_be) = 4),
    chunk_count_be      BLOB NOT NULL CHECK (length(chunk_count_be) = 2),
    state               INTEGER NOT NULL CHECK (state BETWEEN 0 AND 3),
    delivery_receipt    BLOB NOT NULL CHECK (length(delivery_receipt) = 32),
    downstream_duplicate INTEGER NOT NULL CHECK (downstream_duplicate IN (0, 1)),
    row_digest          BLOB NOT NULL CHECK (length(row_digest) = 32),
    CHECK (
        (state IN (0, 1) AND delivery_receipt = zeroblob(32) AND downstream_duplicate = 0) OR
        (state IN (2, 3) AND delivery_receipt != zeroblob(32))
    )
) STRICT;

CREATE TABLE reassembly_frames (
    binding_digest      BLOB NOT NULL CHECK (length(binding_digest) = 32),
    chunk_index_be      BLOB NOT NULL CHECK (length(chunk_index_be) = 2),
    offset_be           BLOB NOT NULL CHECK (length(offset_be) = 4),
    chunk_digest        BLOB NOT NULL CHECK (length(chunk_digest) = 32),
    chunk               BLOB NOT NULL CHECK (length(chunk) > 0 AND length(chunk) <= 16256),
    source_sequence_be  BLOB NOT NULL CHECK (length(source_sequence_be) = 8),
    source_envelope_digest BLOB NOT NULL CHECK (length(source_envelope_digest) = 32),
    row_digest          BLOB NOT NULL CHECK (length(row_digest) = 32),
    PRIMARY KEY (binding_digest, chunk_index_be),
    FOREIGN KEY (binding_digest) REFERENCES reassembly_messages(binding_digest) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;

CREATE TABLE reassembly_terminal_frames (
    binding_digest      BLOB NOT NULL CHECK (length(binding_digest) = 32),
    chunk_index_be      BLOB NOT NULL CHECK (length(chunk_index_be) = 2),
    chunk_digest        BLOB NOT NULL CHECK (length(chunk_digest) = 32),
    row_digest          BLOB NOT NULL CHECK (length(row_digest) = 32),
    PRIMARY KEY (binding_digest, chunk_index_be),
    FOREIGN KEY (binding_digest) REFERENCES reassembly_messages(binding_digest) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;
"#;

/// Immutable identity and hard quotas of one durable frame reassembler.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DurableFrameReassemblerConfigV2 {
    reassembler_id: Digest32,
    wire: RouteWireContextV1,
    recipient_id: ParticipantId,
    max_messages: u16,
    max_active_bytes: u64,
    max_active_chunks: u32,
}

impl DurableFrameReassemblerConfigV2 {
    /// Constructs a non-null route-scoped configuration with bounded quotas.
    pub fn new(
        reassembler_id: Digest32,
        wire: RouteWireContextV1,
        recipient_id: ParticipantId,
        max_messages: u16,
        max_active_bytes: u64,
        max_active_chunks: u32,
    ) -> Result<Self, DurableFrameReassemblerErrorV2> {
        if reassembler_id == ZERO_DIGEST
            || wire.network_id == ZERO_DIGEST
            || wire.session_id == ZERO_DIGEST
            || wire.route_id == ZERO_DIGEST
            || wire.roster_snapshot == ZERO_DIGEST
            || wire.policy_version == 0
            || recipient_id.0 == ZERO_DIGEST
            || max_messages == 0
            || max_messages > MAX_RETAINED_MESSAGES
            || max_active_bytes <= 16_384
            || max_active_bytes > MAX_ACTIVE_BYTES
            || max_active_chunks == 0
            || max_active_chunks > MAX_ACTIVE_CHUNKS
        {
            return Err(DurableFrameReassemblerErrorV2::InvalidConfiguration);
        }
        Ok(Self {
            reassembler_id,
            wire,
            recipient_id,
            max_messages,
            max_active_bytes,
            max_active_chunks,
        })
    }

    /// Stable reassembler authority identity.
    pub const fn reassembler_id(&self) -> &Digest32 {
        &self.reassembler_id
    }

    /// Frozen network/session/route/roster/policy context.
    pub const fn wire_context(&self) -> RouteWireContextV1 {
        self.wire
    }

    /// Recipient whose already-authenticated frames may enter this store.
    pub const fn recipient_id(&self) -> ParticipantId {
        self.recipient_id
    }

    /// Maximum retained message identities, including terminal summaries.
    pub const fn max_messages(&self) -> u16 {
        self.max_messages
    }

    /// Maximum sum of full lengths reserved by incomplete/ready messages.
    pub const fn max_active_bytes(&self) -> u64 {
        self.max_active_bytes
    }

    /// Maximum chunks retained across incomplete/ready messages.
    pub const fn max_active_chunks(&self) -> u32 {
        self.max_active_chunks
    }
}

/// Redacted durable reassembly failures.
#[derive(Debug, thiserror::Error)]
pub enum DurableFrameReassemblerErrorV2 {
    /// A zero binding, unsafe path, or quota outside the hard cap was supplied.
    #[error("invalid durable frame reassembler configuration")]
    InvalidConfiguration,
    /// Explicit creation found an existing root.
    #[error("durable frame reassembler root already exists")]
    AlreadyExists,
    /// Reopen found no database.
    #[error("durable frame reassembler database is missing")]
    DatabaseMissing,
    /// Retained identity does not match the expected route/configuration.
    #[error("wrong durable frame reassembler identity")]
    WrongIdentity,
    /// Owner/mode/lock/storage operation failed.
    #[error("durable frame reassembler storage unavailable")]
    StorageUnavailable,
    /// Database application/schema version is not V2.
    #[error("unsupported durable frame reassembler format")]
    UnsupportedFormat,
    /// Retained counters, rows, digests, or complete bytes do not authenticate.
    #[error("corrupt durable frame reassembler state")]
    CorruptState,
    /// The authenticated inner frame is malformed or bound elsewhere.
    #[error("route frame: {0}")]
    Frame(#[from] RouteFrameErrorV2),
    /// A different valid chunk reused one message/index position.
    #[error("route frame equivocation at a retained chunk position")]
    FrameEquivocation,
    /// Retained terminal-message identity quota is exhausted.
    #[error("durable frame message quota exhausted")]
    MessageQuotaExceeded,
    /// Reserving the advertised full message would exceed the byte quota.
    #[error("durable frame byte quota exhausted")]
    ByteQuotaExceeded,
    /// Retaining another authenticated chunk would exceed the chunk quota.
    #[error("durable frame chunk quota exhausted")]
    ChunkQuotaExceeded,
    /// A downstream commit was empty or contradicted a retained terminal result.
    #[error("invalid framed Contracts durable commit")]
    InvalidDownstreamCommit,
}

impl From<rusqlite::Error> for DurableFrameReassemblerErrorV2 {
    fn from(_: rusqlite::Error) -> Self {
        Self::StorageUnavailable
    }
}

/// Bounded counters for operational monitoring without exposing DSC1 bytes.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct DurableFrameReassemblerStatsV2 {
    /// All retained message identities, including compact terminal summaries.
    pub retained_messages: usize,
    /// Messages still missing one or more chunks.
    pub assembling_messages: usize,
    /// Complete messages awaiting a durable Contracts receipt.
    pub ready_messages: usize,
    /// Messages durably applied by Contracts.
    pub delivered_messages: usize,
    /// Messages durably failed closed by reassembly or Contracts.
    pub failed_closed_messages: usize,
    /// Sum of full lengths reserved by assembling/ready messages.
    pub active_reserved_bytes: u64,
    /// Number of chunk rows retained for assembling/ready messages.
    pub active_chunks: u32,
}

#[derive(Clone)]
struct StoredMessageV2 {
    binding_digest: Digest32,
    sender_id: ParticipantId,
    recipient_id: ParticipantId,
    message_digest: Digest32,
    total_len: u32,
    chunk_count: u16,
    state: u8,
    delivery_receipt: Digest32,
    downstream_duplicate: bool,
    row_digest: Digest32,
}

#[derive(Clone)]
struct StoredFrameV2 {
    binding_digest: Digest32,
    index: u16,
    offset: u32,
    chunk_digest: Digest32,
    chunk: Vec<u8>,
    source_sequence: u64,
}

#[derive(Clone, Copy)]
struct TerminalFrameV2 {
    index: u16,
    chunk_digest: Digest32,
}

enum FrameIngressV2 {
    Incomplete(DurablePayloadCommitV1),
    Ready {
        binding_digest: Digest32,
        sender_id: ParticipantId,
        first_sequence: u64,
        message: Vec<u8>,
    },
    Terminal(DurablePayloadCommitV1),
}

/// Owner-only, route-scoped durable reassembly authority.
pub struct DurableFrameReassemblerV2 {
    connection: Connection,
    root: PathBuf,
    config: DurableFrameReassemblerConfigV2,
    _database_authority: File,
    _sqlite_database_authority: File,
    _lock: File,
}

impl core::fmt::Debug for DurableFrameReassemblerV2 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("DurableFrameReassemblerV2")
            .field("reassembler_id", &self.config.reassembler_id)
            .field("session_id", &self.config.wire.session_id)
            .field("root", &"[redacted]")
            .finish()
    }
}

/// Error returned by the framed adapter. Deterministic frame refusals remain
/// named; downstream and storage errors never expose payload bytes.
#[derive(Debug, thiserror::Error)]
pub enum FramedContractsTransportErrorV2<E: std::error::Error + Send + Sync + 'static> {
    /// Durable reassembly refused or could not commit the frame.
    #[error("durable frame reassembly: {0}")]
    Reassembly(#[source] DurableFrameReassemblerErrorV2),
    /// The Contracts authority refused or lost its durable receipt.
    #[error("Contracts transport port: {0}")]
    Contracts(#[source] E),
}

/// Adapter preserving direct V1 while routing only V2 frames through durable
/// reassembly. Incomplete frames never reach the wrapped Contracts port.
pub struct FramedContractsTransportV2<P> {
    reassembler: DurableFrameReassemblerV2,
    contracts: P,
}

impl<P> core::fmt::Debug for FramedContractsTransportV2<P> {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("FramedContractsTransportV2")
            .field("reassembler", &self.reassembler)
            .field("contracts", &"[redacted]")
            .finish()
    }
}

impl<P> FramedContractsTransportV2<P> {
    /// Composes an already-open reassembler with the phase-owning Contracts port.
    pub const fn new(reassembler: DurableFrameReassemblerV2, contracts: P) -> Self {
        Self {
            reassembler,
            contracts,
        }
    }

    /// Borrows bounded reassembly counters.
    pub fn stats(&self) -> Result<DurableFrameReassemblerStatsV2, DurableFrameReassemblerErrorV2> {
        self.reassembler.stats()
    }

    /// Returns both authorities for coordinated shutdown/reopen in the
    /// composition root.
    pub fn into_parts(self) -> (DurableFrameReassemblerV2, P) {
        (self.reassembler, self.contracts)
    }

    /// Mutable access to the wrapped typed Contracts authority.
    pub fn contracts_mut(&mut self) -> &mut P {
        &mut self.contracts
    }
}

impl<P> ContractsTransportPortV1 for FramedContractsTransportV2<P>
where
    P: ContractsTransportPortV1,
{
    type Error = FramedContractsTransportErrorV2<P::Error>;

    fn accept_signed_dsc1(
        &mut self,
        delivery: ContractsRouteDeliveryV1<'_>,
    ) -> Result<DurablePayloadCommitV1, Self::Error> {
        if !RouteFrameV2::is_framed_payload(delivery.signed_dsc1()) {
            return self
                .contracts
                .accept_signed_dsc1(delivery)
                .map_err(FramedContractsTransportErrorV2::Contracts);
        }
        let ingress = self
            .reassembler
            .ingest_authenticated_frame(&delivery)
            .map_err(FramedContractsTransportErrorV2::Reassembly)?;
        match ingress {
            FrameIngressV2::Incomplete(commit) | FrameIngressV2::Terminal(commit) => Ok(commit),
            FrameIngressV2::Ready {
                binding_digest,
                sender_id,
                first_sequence,
                message,
            } => {
                let commit = self
                    .contracts
                    .accept_signed_dsc1(ContractsRouteDeliveryV1::from_reassembled_parts(
                        sender_id,
                        first_sequence,
                        binding_digest,
                        &message,
                    ))
                    .map_err(FramedContractsTransportErrorV2::Contracts)?;
                self.reassembler
                    .commit_downstream(binding_digest, commit)
                    .map_err(FramedContractsTransportErrorV2::Reassembly)
            }
        }
    }
}

impl DurableFrameReassemblerV2 {
    /// Creates a brand-new owner-only reassembly store.
    pub fn create(
        root: &Path,
        config: DurableFrameReassemblerConfigV2,
    ) -> Result<Self, DurableFrameReassemblerErrorV2> {
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
            .map_err(|_| DurableFrameReassemblerErrorV2::StorageUnavailable)?;
        sync_directory(root)?;
        let reassembler = Self {
            connection,
            root: root.to_path_buf(),
            config,
            _database_authority: database_authority,
            _sqlite_database_authority: sqlite_database_authority,
            _lock: lock,
        };
        reassembler.validate_storage()?;
        reassembler.audit_rows()?;
        Ok(reassembler)
    }

    /// Resumes only a pristine prefix of an explicitly journaled production
    /// create. Missing/empty roots and empty SQLite files may be completed;
    /// an initialized authority is accepted only before any frame reservation
    /// or terminal message exists. Foreign schema/identity, extra files and
    /// hard-link transplants are refused.
    pub fn resume_create_production(
        root: &Path,
        config: DurableFrameReassemblerConfigV2,
    ) -> Result<Self, DurableFrameReassemblerErrorV2> {
        let lock = acquire_resume_lock(root)?;
        let database_path = root.join(DATABASE_FILE_NAME);
        let database_exists = database_path
            .try_exists()
            .map_err(|_| DurableFrameReassemblerErrorV2::StorageUnavailable)?;
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
            return Err(DurableFrameReassemblerErrorV2::InvalidConfiguration);
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
                return Err(DurableFrameReassemblerErrorV2::CorruptState)
            }
        }
        let reassembler = Self {
            connection,
            root: root.to_path_buf(),
            config,
            _database_authority: database_authority,
            _sqlite_database_authority: sqlite_database_authority,
            _lock: lock,
        };
        reassembler.validate_storage()?;
        reassembler.audit_rows()?;
        reassembler.require_pristine_creation_state()?;
        reassembler
            .connection
            .execute_batch("PRAGMA wal_checkpoint(FULL);")
            .map_err(|_| DurableFrameReassemblerErrorV2::StorageUnavailable)?;
        sync_directory(root)?;
        Ok(reassembler)
    }

    /// Performs the non-mutating half of production resume planning.
    pub fn production_creation_state(
        root: &Path,
        config: DurableFrameReassemblerConfigV2,
    ) -> Result<DurableProductionCreationStateV1, DurableFrameReassemblerErrorV2> {
        inspect_creation_state(root, &config)
    }

    /// Reopens the exact existing authority without creating or migrating it.
    pub fn open(
        root: &Path,
        expected: DurableFrameReassemblerConfigV2,
    ) -> Result<Self, DurableFrameReassemblerErrorV2> {
        validate_root(root)?;
        validate_root_entries(root)?;
        let lock = acquire_lock(root, false)?;
        let database_path = root.join(DATABASE_FILE_NAME);
        if !database_path
            .try_exists()
            .map_err(|_| DurableFrameReassemblerErrorV2::StorageUnavailable)?
        {
            return Err(DurableFrameReassemblerErrorV2::DatabaseMissing);
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
        let reassembler = Self {
            connection,
            root: root.to_path_buf(),
            config: expected,
            _database_authority: database_authority,
            _sqlite_database_authority: sqlite_database_authority,
            _lock: lock,
        };
        reassembler.validate_storage()?;
        reassembler.audit_rows()?;
        let Self {
            connection,
            root,
            config,
            _database_authority: database_authority,
            _sqlite_database_authority: sqlite_database_authority,
            _lock: lock,
        } = reassembler;
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
        rw_preflight.audit_rows()?;
        let Self {
            connection,
            root,
            config,
            _database_authority: database_authority,
            _sqlite_database_authority: sqlite_database_authority,
            _lock: lock,
        } = rw_preflight;
        configure_connection(&connection)?;
        let reassembler = Self {
            connection,
            root,
            config,
            _database_authority: database_authority,
            _sqlite_database_authority: sqlite_database_authority,
            _lock: lock,
        };
        reassembler.validate_storage()?;
        reassembler.audit_rows()?;
        Ok(reassembler)
    }

    /// Returns bounded counters after authenticating retained metadata.
    pub fn stats(&self) -> Result<DurableFrameReassemblerStatsV2, DurableFrameReassemblerErrorV2> {
        self.require_meta()?;
        let mut stats = DurableFrameReassemblerStatsV2::default();
        let mut statement = self
            .connection
            .prepare("SELECT state, COUNT(*) FROM reassembly_messages GROUP BY state")?;
        let rows =
            statement.query_map([], |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)))?;
        for row in rows {
            let (state, count) = row?;
            let count =
                usize::try_from(count).map_err(|_| DurableFrameReassemblerErrorV2::CorruptState)?;
            stats.retained_messages = stats
                .retained_messages
                .checked_add(count)
                .ok_or(DurableFrameReassemblerErrorV2::CorruptState)?;
            match state {
                0 => stats.assembling_messages = count,
                1 => stats.ready_messages = count,
                2 => stats.delivered_messages = count,
                3 => stats.failed_closed_messages = count,
                _ => return Err(DurableFrameReassemblerErrorV2::CorruptState),
            }
        }
        let (active_bytes, active_chunks): (i64, i64) = self.connection.query_row(
            "SELECT active_bytes, active_chunks FROM reassembly_meta WHERE singleton = 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        stats.active_reserved_bytes = u64::try_from(active_bytes)
            .map_err(|_| DurableFrameReassemblerErrorV2::CorruptState)?;
        stats.active_chunks = u32::try_from(active_chunks)
            .map_err(|_| DurableFrameReassemblerErrorV2::CorruptState)?;
        Ok(stats)
    }

    fn ingest_authenticated_frame(
        &mut self,
        delivery: &ContractsRouteDeliveryV1<'_>,
    ) -> Result<FrameIngressV2, DurableFrameReassemblerErrorV2> {
        let frame = RouteFrameV2::decode_for_flow(
            delivery.signed_dsc1(),
            self.config.wire,
            delivery.sender_id(),
            self.config.recipient_id,
        )?;
        let config = self.config;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let existing = load_message_tx(&transaction, frame.binding_digest(), &config)?;
        let mut duplicate = false;
        let message = if let Some(message) = existing {
            require_message_matches(&message, &frame, delivery.sender_id(), &config)?;
            if message.state >= 2 {
                require_terminal_frame_tx(&transaction, &message, &frame, &config)?;
                let commit = terminal_commit(&message)?;
                transaction.commit()?;
                return Ok(FrameIngressV2::Terminal(commit));
            }
            if let Some(retained) = load_frame_tx(
                &transaction,
                frame.binding_digest(),
                frame.index(),
                &message,
                &config,
            )? {
                if retained.offset != frame.offset()
                    || retained.chunk_digest != *frame.chunk_digest()
                    || retained.chunk != frame.chunk()
                {
                    return Err(DurableFrameReassemblerErrorV2::FrameEquivocation);
                }
                duplicate = true;
            } else {
                reserve_additional_chunk(&transaction, &config)?;
                insert_frame(
                    &transaction,
                    &config,
                    &frame,
                    delivery.sequence(),
                    delivery.envelope_digest(),
                )?;
            }
            message
        } else {
            reserve_new_message(&transaction, &config, frame.total_len())?;
            let message = new_message(&config, &frame, delivery.sender_id())?;
            insert_message(&transaction, &message)?;
            insert_frame(
                &transaction,
                &config,
                &frame,
                delivery.sequence(),
                delivery.envelope_digest(),
            )?;
            message
        };

        let frames = load_frames_tx(&transaction, &message, &config)?;
        if frames.len() < usize::from(message.chunk_count) {
            let receipt = frame_receipt(
                &config,
                &message.binding_digest,
                frame.index(),
                frame.chunk_digest(),
            )?;
            transaction.commit()?;
            return DurablePayloadCommitV1::new(
                DurablePayloadDispositionV1::Applied,
                receipt,
                duplicate,
            )
            .map(FrameIngressV2::Incomplete)
            .map_err(|_| DurableFrameReassemblerErrorV2::InvalidDownstreamCommit);
        }
        if frames.len() != usize::from(message.chunk_count) {
            return Err(DurableFrameReassemblerErrorV2::CorruptState);
        }
        let (first_sequence, complete) = assemble_frames(&message, &frames)?;
        if verify_complete_message_v2(&complete, message.total_len, &message.message_digest)
            .is_err()
        {
            let receipt = reassembly_failure_receipt(&config, &message.binding_digest)?;
            fail_message_digest(&transaction, &config, &message, &frames, receipt)?;
            transaction.commit()?;
            let commit = DurablePayloadCommitV1::new(
                DurablePayloadDispositionV1::FailedClosed,
                receipt,
                false,
            )
            .map_err(|_| DurableFrameReassemblerErrorV2::InvalidDownstreamCommit)?;
            return Ok(FrameIngressV2::Terminal(commit));
        }
        if message.state == 0 {
            mark_ready(&transaction, &config, &message)?;
        } else if message.state != 1 {
            return Err(DurableFrameReassemblerErrorV2::CorruptState);
        }
        transaction.commit()?;
        Ok(FrameIngressV2::Ready {
            binding_digest: message.binding_digest,
            sender_id: message.sender_id,
            first_sequence,
            message: complete,
        })
    }

    fn commit_downstream(
        &mut self,
        binding_digest: Digest32,
        commit: DurablePayloadCommitV1,
    ) -> Result<DurablePayloadCommitV1, DurableFrameReassemblerErrorV2> {
        if commit.durable_receipt() == &ZERO_DIGEST {
            return Err(DurableFrameReassemblerErrorV2::InvalidDownstreamCommit);
        }
        let config = self.config;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let message = load_message_tx(&transaction, &binding_digest, &config)?
            .ok_or(DurableFrameReassemblerErrorV2::CorruptState)?;
        if message.state >= 2 {
            let retained = terminal_commit(&message)?;
            if retained.disposition() != commit.disposition()
                || retained.durable_receipt() != commit.durable_receipt()
                || retained.duplicate() != commit.duplicate()
            {
                return Err(DurableFrameReassemblerErrorV2::InvalidDownstreamCommit);
            }
            transaction.commit()?;
            return Ok(retained);
        }
        if message.state != 1 {
            return Err(DurableFrameReassemblerErrorV2::CorruptState);
        }
        let frames = load_frames_tx(&transaction, &message, &config)?;
        if frames.len() != usize::from(message.chunk_count) {
            return Err(DurableFrameReassemblerErrorV2::CorruptState);
        }
        let state = match commit.disposition() {
            DurablePayloadDispositionV1::Applied => 2_u8,
            DurablePayloadDispositionV1::FailedClosed => 3_u8,
        };
        let row_digest = message_row_digest(
            &config,
            &message.binding_digest,
            message.sender_id,
            message.recipient_id,
            &message.message_digest,
            message.total_len,
            message.chunk_count,
            state,
            commit.durable_receipt(),
            commit.duplicate(),
        )?;
        let changed = transaction.execute(
            "UPDATE reassembly_messages
             SET state = ?1, delivery_receipt = ?2, downstream_duplicate = ?3,
                 row_digest = ?4
             WHERE binding_digest = ?5 AND state = 1 AND row_digest = ?6",
            params![
                i64::from(state),
                commit.durable_receipt().as_slice(),
                i64::from(u8::from(commit.duplicate())),
                row_digest.as_slice(),
                binding_digest.as_slice(),
                message.row_digest.as_slice(),
            ],
        )?;
        if changed != 1 {
            return Err(DurableFrameReassemblerErrorV2::CorruptState);
        }
        insert_terminal_summaries(&transaction, &config, &frames)?;
        let deleted = transaction.execute(
            "DELETE FROM reassembly_frames WHERE binding_digest = ?1",
            params![binding_digest.as_slice()],
        )?;
        if deleted != frames.len() {
            return Err(DurableFrameReassemblerErrorV2::CorruptState);
        }
        release_active_reservation(&transaction, &config, message.total_len, frames.len())?;
        transaction.commit()?;
        Ok(commit)
    }

    fn validate_storage(&self) -> Result<(), DurableFrameReassemblerErrorV2> {
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
                .map_err(|_| DurableFrameReassemblerErrorV2::StorageUnavailable)?
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
            return Err(DurableFrameReassemblerErrorV2::UnsupportedFormat);
        }
        validate_database_path(&self.connection, &self.root.join(DATABASE_FILE_NAME))?;
        let quick: String = self
            .connection
            .query_row("PRAGMA quick_check", [], |row| row.get(0))?;
        if quick != "ok" {
            return Err(DurableFrameReassemblerErrorV2::CorruptState);
        }
        audit_schema(&self.connection)?;
        self.require_meta()
    }

    fn require_pristine_creation_state(&self) -> Result<(), DurableFrameReassemblerErrorV2> {
        if self.stats()? != DurableFrameReassemblerStatsV2::default() {
            return Err(DurableFrameReassemblerErrorV2::UnsupportedFormat);
        }
        Ok(())
    }

    fn require_meta(&self) -> Result<(), DurableFrameReassemblerErrorV2> {
        let retained = self
            .connection
            .query_row(
                "SELECT schema_version, reassembler_id, network_id, session_id,
                        route_id, roster_snapshot, recipient_id, policy_version,
                        max_messages, max_active_bytes, max_active_chunks,
                        retained_messages, active_bytes, active_chunks
                 FROM reassembly_meta WHERE singleton = 1",
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
                        row.get::<_, i64>(10)?,
                        row.get::<_, i64>(11)?,
                        row.get::<_, i64>(12)?,
                        row.get::<_, i64>(13)?,
                    ))
                },
            )
            .optional()?;
        let Some((
            version,
            id,
            network,
            session,
            route,
            roster,
            recipient,
            policy,
            max_messages,
            max_bytes,
            max_chunks,
            retained_messages,
            active_bytes,
            active_chunks,
        )) = retained
        else {
            return Err(DurableFrameReassemblerErrorV2::WrongIdentity);
        };
        if version != SCHEMA_VERSION
            || as_digest(&id)? != self.config.reassembler_id
            || as_digest(&network)? != self.config.wire.network_id
            || as_digest(&session)? != self.config.wire.session_id
            || as_digest(&route)? != self.config.wire.route_id
            || as_digest(&roster)? != self.config.wire.roster_snapshot
            || as_digest(&recipient)? != self.config.recipient_id.0
            || policy != i64::from(self.config.wire.policy_version)
            || max_messages != i64::from(self.config.max_messages)
            || max_bytes != i64::try_from(self.config.max_active_bytes).unwrap_or(-1)
            || max_chunks != i64::from(self.config.max_active_chunks)
            || retained_messages < 0
            || active_bytes < 0
            || active_chunks < 0
        {
            return Err(DurableFrameReassemblerErrorV2::WrongIdentity);
        }
        Ok(())
    }

    fn audit_rows(&self) -> Result<(), DurableFrameReassemblerErrorV2> {
        self.require_meta()?;
        let messages = load_all_messages(&self.connection, &self.config)?;
        let mut computed_active_bytes = 0_u64;
        let mut computed_active_chunks = 0_u32;
        for message in &messages {
            let frames = load_frames_connection(&self.connection, message, &self.config)?;
            let terminal_frames =
                load_terminal_frames_connection(&self.connection, message, &self.config)?;
            match message.state {
                0 => {
                    if frames.is_empty()
                        || frames.len() >= usize::from(message.chunk_count)
                        || !terminal_frames.is_empty()
                    {
                        return Err(DurableFrameReassemblerErrorV2::CorruptState);
                    }
                }
                1 => {
                    if frames.len() != usize::from(message.chunk_count)
                        || !terminal_frames.is_empty()
                    {
                        return Err(DurableFrameReassemblerErrorV2::CorruptState);
                    }
                    let (_, complete) = assemble_frames(message, &frames)?;
                    verify_complete_message_v2(
                        &complete,
                        message.total_len,
                        &message.message_digest,
                    )?;
                }
                2 | 3
                    if frames.is_empty()
                        && terminal_frames.len() == usize::from(message.chunk_count) => {}
                _ => return Err(DurableFrameReassemblerErrorV2::CorruptState),
            }
            if message.state <= 1 {
                computed_active_bytes = computed_active_bytes
                    .checked_add(u64::from(message.total_len))
                    .ok_or(DurableFrameReassemblerErrorV2::CorruptState)?;
                computed_active_chunks = computed_active_chunks
                    .checked_add(
                        u32::try_from(frames.len())
                            .map_err(|_| DurableFrameReassemblerErrorV2::CorruptState)?,
                    )
                    .ok_or(DurableFrameReassemblerErrorV2::CorruptState)?;
            }
        }
        let (retained, active_bytes, active_chunks): (i64, i64, i64) = self.connection.query_row(
            "SELECT retained_messages, active_bytes, active_chunks
             FROM reassembly_meta WHERE singleton = 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )?;
        if usize::try_from(retained).ok() != Some(messages.len())
            || u64::try_from(active_bytes).ok() != Some(computed_active_bytes)
            || u32::try_from(active_chunks).ok() != Some(computed_active_chunks)
            || messages.len() > usize::from(self.config.max_messages)
            || computed_active_bytes > self.config.max_active_bytes
            || computed_active_chunks > self.config.max_active_chunks
        {
            return Err(DurableFrameReassemblerErrorV2::CorruptState);
        }
        Ok(())
    }
}

fn new_message(
    config: &DurableFrameReassemblerConfigV2,
    frame: &RouteFrameV2,
    sender_id: ParticipantId,
) -> Result<StoredMessageV2, DurableFrameReassemblerErrorV2> {
    let row_digest = message_row_digest(
        config,
        frame.binding_digest(),
        sender_id,
        config.recipient_id,
        frame.message_digest(),
        frame.total_len(),
        frame.count(),
        0,
        &ZERO_DIGEST,
        false,
    )?;
    Ok(StoredMessageV2 {
        binding_digest: *frame.binding_digest(),
        sender_id,
        recipient_id: config.recipient_id,
        message_digest: *frame.message_digest(),
        total_len: frame.total_len(),
        chunk_count: frame.count(),
        state: 0,
        delivery_receipt: ZERO_DIGEST,
        downstream_duplicate: false,
        row_digest,
    })
}

fn require_message_matches(
    message: &StoredMessageV2,
    frame: &RouteFrameV2,
    sender_id: ParticipantId,
    config: &DurableFrameReassemblerConfigV2,
) -> Result<(), DurableFrameReassemblerErrorV2> {
    if message.binding_digest != *frame.binding_digest()
        || message.sender_id != sender_id
        || message.recipient_id != config.recipient_id
        || message.message_digest != *frame.message_digest()
        || message.total_len != frame.total_len()
        || message.chunk_count != frame.count()
    {
        return Err(DurableFrameReassemblerErrorV2::FrameEquivocation);
    }
    Ok(())
}

fn reserve_new_message(
    transaction: &Transaction<'_>,
    config: &DurableFrameReassemblerConfigV2,
    total_len: u32,
) -> Result<(), DurableFrameReassemblerErrorV2> {
    let (messages, bytes, chunks): (i64, i64, i64) = transaction.query_row(
        "SELECT retained_messages, active_bytes, active_chunks
         FROM reassembly_meta WHERE singleton = 1",
        [],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    )?;
    let messages =
        u16::try_from(messages).map_err(|_| DurableFrameReassemblerErrorV2::CorruptState)?;
    let bytes = u64::try_from(bytes).map_err(|_| DurableFrameReassemblerErrorV2::CorruptState)?;
    let chunks = u32::try_from(chunks).map_err(|_| DurableFrameReassemblerErrorV2::CorruptState)?;
    if messages >= config.max_messages {
        return Err(DurableFrameReassemblerErrorV2::MessageQuotaExceeded);
    }
    let next_bytes = bytes
        .checked_add(u64::from(total_len))
        .ok_or(DurableFrameReassemblerErrorV2::ByteQuotaExceeded)?;
    if next_bytes > config.max_active_bytes {
        return Err(DurableFrameReassemblerErrorV2::ByteQuotaExceeded);
    }
    let next_chunks = chunks
        .checked_add(1)
        .ok_or(DurableFrameReassemblerErrorV2::ChunkQuotaExceeded)?;
    if next_chunks > config.max_active_chunks {
        return Err(DurableFrameReassemblerErrorV2::ChunkQuotaExceeded);
    }
    let changed = transaction.execute(
        "UPDATE reassembly_meta
         SET retained_messages = ?1, active_bytes = ?2, active_chunks = ?3
         WHERE singleton = 1 AND retained_messages = ?4
               AND active_bytes = ?5 AND active_chunks = ?6",
        params![
            i64::from(messages + 1),
            i64::try_from(next_bytes).map_err(|_| DurableFrameReassemblerErrorV2::CorruptState)?,
            i64::from(next_chunks),
            i64::from(messages),
            i64::try_from(bytes).map_err(|_| DurableFrameReassemblerErrorV2::CorruptState)?,
            i64::from(chunks),
        ],
    )?;
    if changed != 1 {
        return Err(DurableFrameReassemblerErrorV2::CorruptState);
    }
    Ok(())
}

fn reserve_additional_chunk(
    transaction: &Transaction<'_>,
    config: &DurableFrameReassemblerConfigV2,
) -> Result<(), DurableFrameReassemblerErrorV2> {
    let chunks: i64 = transaction.query_row(
        "SELECT active_chunks FROM reassembly_meta WHERE singleton = 1",
        [],
        |row| row.get(0),
    )?;
    let chunks = u32::try_from(chunks).map_err(|_| DurableFrameReassemblerErrorV2::CorruptState)?;
    let next = chunks
        .checked_add(1)
        .ok_or(DurableFrameReassemblerErrorV2::ChunkQuotaExceeded)?;
    if next > config.max_active_chunks {
        return Err(DurableFrameReassemblerErrorV2::ChunkQuotaExceeded);
    }
    let changed = transaction.execute(
        "UPDATE reassembly_meta SET active_chunks = ?1
         WHERE singleton = 1 AND active_chunks = ?2",
        params![i64::from(next), i64::from(chunks)],
    )?;
    if changed != 1 {
        return Err(DurableFrameReassemblerErrorV2::CorruptState);
    }
    Ok(())
}

fn release_active_reservation(
    transaction: &Transaction<'_>,
    config: &DurableFrameReassemblerConfigV2,
    total_len: u32,
    chunks_to_release: usize,
) -> Result<(), DurableFrameReassemblerErrorV2> {
    let (bytes, chunks): (i64, i64) = transaction.query_row(
        "SELECT active_bytes, active_chunks FROM reassembly_meta WHERE singleton = 1",
        [],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    let bytes = u64::try_from(bytes).map_err(|_| DurableFrameReassemblerErrorV2::CorruptState)?;
    let chunks = u32::try_from(chunks).map_err(|_| DurableFrameReassemblerErrorV2::CorruptState)?;
    let released_chunks = u32::try_from(chunks_to_release)
        .map_err(|_| DurableFrameReassemblerErrorV2::CorruptState)?;
    let next_bytes = bytes
        .checked_sub(u64::from(total_len))
        .ok_or(DurableFrameReassemblerErrorV2::CorruptState)?;
    let next_chunks = chunks
        .checked_sub(released_chunks)
        .ok_or(DurableFrameReassemblerErrorV2::CorruptState)?;
    if next_bytes > config.max_active_bytes || next_chunks > config.max_active_chunks {
        return Err(DurableFrameReassemblerErrorV2::CorruptState);
    }
    let changed = transaction.execute(
        "UPDATE reassembly_meta SET active_bytes = ?1, active_chunks = ?2
         WHERE singleton = 1 AND active_bytes = ?3 AND active_chunks = ?4",
        params![
            i64::try_from(next_bytes).map_err(|_| DurableFrameReassemblerErrorV2::CorruptState)?,
            i64::from(next_chunks),
            i64::try_from(bytes).map_err(|_| DurableFrameReassemblerErrorV2::CorruptState)?,
            i64::from(chunks),
        ],
    )?;
    if changed != 1 {
        return Err(DurableFrameReassemblerErrorV2::CorruptState);
    }
    Ok(())
}

fn insert_message(
    transaction: &Transaction<'_>,
    message: &StoredMessageV2,
) -> Result<(), DurableFrameReassemblerErrorV2> {
    transaction.execute(
        "INSERT INTO reassembly_messages
         (binding_digest, sender_id, recipient_id, message_digest, total_len_be,
          chunk_count_be, state, delivery_receipt, downstream_duplicate, row_digest)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, 0, ?7, 0, ?8)",
        params![
            message.binding_digest.as_slice(),
            message.sender_id.0.as_slice(),
            message.recipient_id.0.as_slice(),
            message.message_digest.as_slice(),
            message.total_len.to_be_bytes().as_slice(),
            message.chunk_count.to_be_bytes().as_slice(),
            ZERO_DIGEST.as_slice(),
            message.row_digest.as_slice(),
        ],
    )?;
    Ok(())
}

fn insert_frame(
    transaction: &Transaction<'_>,
    config: &DurableFrameReassemblerConfigV2,
    frame: &RouteFrameV2,
    source_sequence: u64,
    source_envelope_digest: &Digest32,
) -> Result<(), DurableFrameReassemblerErrorV2> {
    let row_digest = frame_row_digest(
        config,
        frame.binding_digest(),
        frame.index(),
        frame.offset(),
        frame.chunk_digest(),
        frame.chunk(),
        source_sequence,
        source_envelope_digest,
    )?;
    transaction.execute(
        "INSERT INTO reassembly_frames
         (binding_digest, chunk_index_be, offset_be, chunk_digest, chunk,
          source_sequence_be, source_envelope_digest, row_digest)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        params![
            frame.binding_digest().as_slice(),
            frame.index().to_be_bytes().as_slice(),
            frame.offset().to_be_bytes().as_slice(),
            frame.chunk_digest().as_slice(),
            frame.chunk(),
            source_sequence.to_be_bytes().as_slice(),
            source_envelope_digest.as_slice(),
            row_digest.as_slice(),
        ],
    )?;
    Ok(())
}

fn mark_ready(
    transaction: &Transaction<'_>,
    config: &DurableFrameReassemblerConfigV2,
    message: &StoredMessageV2,
) -> Result<(), DurableFrameReassemblerErrorV2> {
    let row_digest = message_row_digest(
        config,
        &message.binding_digest,
        message.sender_id,
        message.recipient_id,
        &message.message_digest,
        message.total_len,
        message.chunk_count,
        1,
        &ZERO_DIGEST,
        false,
    )?;
    let changed = transaction.execute(
        "UPDATE reassembly_messages SET state = 1, row_digest = ?1
         WHERE binding_digest = ?2 AND state = 0 AND row_digest = ?3",
        params![
            row_digest.as_slice(),
            message.binding_digest.as_slice(),
            message.row_digest.as_slice(),
        ],
    )?;
    if changed != 1 {
        return Err(DurableFrameReassemblerErrorV2::CorruptState);
    }
    Ok(())
}

fn fail_message_digest(
    transaction: &Transaction<'_>,
    config: &DurableFrameReassemblerConfigV2,
    message: &StoredMessageV2,
    frames: &[StoredFrameV2],
    receipt: Digest32,
) -> Result<(), DurableFrameReassemblerErrorV2> {
    let row_digest = message_row_digest(
        config,
        &message.binding_digest,
        message.sender_id,
        message.recipient_id,
        &message.message_digest,
        message.total_len,
        message.chunk_count,
        3,
        &receipt,
        false,
    )?;
    let changed = transaction.execute(
        "UPDATE reassembly_messages
         SET state = 3, delivery_receipt = ?1, row_digest = ?2
         WHERE binding_digest = ?3 AND state IN (0, 1) AND row_digest = ?4",
        params![
            receipt.as_slice(),
            row_digest.as_slice(),
            message.binding_digest.as_slice(),
            message.row_digest.as_slice(),
        ],
    )?;
    if changed != 1 {
        return Err(DurableFrameReassemblerErrorV2::CorruptState);
    }
    insert_terminal_summaries(transaction, config, frames)?;
    let deleted = transaction.execute(
        "DELETE FROM reassembly_frames WHERE binding_digest = ?1",
        params![message.binding_digest.as_slice()],
    )?;
    if deleted != frames.len() {
        return Err(DurableFrameReassemblerErrorV2::CorruptState);
    }
    release_active_reservation(transaction, config, message.total_len, frames.len())
}

fn terminal_commit(
    message: &StoredMessageV2,
) -> Result<DurablePayloadCommitV1, DurableFrameReassemblerErrorV2> {
    let disposition = match message.state {
        2 => DurablePayloadDispositionV1::Applied,
        3 => DurablePayloadDispositionV1::FailedClosed,
        _ => return Err(DurableFrameReassemblerErrorV2::CorruptState),
    };
    DurablePayloadCommitV1::new(
        disposition,
        message.delivery_receipt,
        message.downstream_duplicate,
    )
    .map_err(|_| DurableFrameReassemblerErrorV2::InvalidDownstreamCommit)
}

fn assemble_frames(
    message: &StoredMessageV2,
    frames: &[StoredFrameV2],
) -> Result<(u64, Vec<u8>), DurableFrameReassemblerErrorV2> {
    if frames.len() != usize::from(message.chunk_count) {
        return Err(DurableFrameReassemblerErrorV2::CorruptState);
    }
    let capacity = usize::try_from(message.total_len)
        .map_err(|_| DurableFrameReassemblerErrorV2::CorruptState)?;
    let mut complete = Vec::with_capacity(capacity);
    let mut first_sequence = None;
    for (expected, frame) in frames.iter().enumerate() {
        let expected =
            u16::try_from(expected).map_err(|_| DurableFrameReassemblerErrorV2::CorruptState)?;
        if frame.binding_digest != message.binding_digest
            || frame.index != expected
            || usize::try_from(frame.offset).ok() != Some(complete.len())
        {
            return Err(DurableFrameReassemblerErrorV2::CorruptState);
        }
        if expected == 0 {
            first_sequence = Some(frame.source_sequence);
        }
        complete.extend_from_slice(&frame.chunk);
        if complete.len() > capacity {
            return Err(DurableFrameReassemblerErrorV2::CorruptState);
        }
    }
    if complete.len() != capacity {
        return Err(DurableFrameReassemblerErrorV2::CorruptState);
    }
    Ok((
        first_sequence.ok_or(DurableFrameReassemblerErrorV2::CorruptState)?,
        complete,
    ))
}

type RawMessageV2 = (
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    i64,
    Vec<u8>,
    i64,
    Vec<u8>,
);

fn raw_message(row: &rusqlite::Row<'_>) -> rusqlite::Result<RawMessageV2> {
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
    ))
}

fn load_message_tx(
    transaction: &Transaction<'_>,
    binding: &Digest32,
    config: &DurableFrameReassemblerConfigV2,
) -> Result<Option<StoredMessageV2>, DurableFrameReassemblerErrorV2> {
    let raw = transaction
        .query_row(
            "SELECT binding_digest, sender_id, recipient_id, message_digest,
                    total_len_be, chunk_count_be, state, delivery_receipt,
                    downstream_duplicate, row_digest
             FROM reassembly_messages WHERE binding_digest = ?1",
            params![binding.as_slice()],
            raw_message,
        )
        .optional()?;
    raw.map(|raw| validate_message(raw, config)).transpose()
}

fn load_all_messages(
    connection: &Connection,
    config: &DurableFrameReassemblerConfigV2,
) -> Result<Vec<StoredMessageV2>, DurableFrameReassemblerErrorV2> {
    let mut statement = connection.prepare(
        "SELECT binding_digest, sender_id, recipient_id, message_digest,
                total_len_be, chunk_count_be, state, delivery_receipt,
                downstream_duplicate, row_digest
         FROM reassembly_messages ORDER BY binding_digest ASC",
    )?;
    let rows = statement.query_map([], raw_message)?;
    let mut messages = Vec::new();
    for row in rows {
        messages.push(validate_message(row?, config)?);
    }
    Ok(messages)
}

fn validate_message(
    raw: RawMessageV2,
    config: &DurableFrameReassemblerConfigV2,
) -> Result<StoredMessageV2, DurableFrameReassemblerErrorV2> {
    let (
        binding_raw,
        sender_raw,
        recipient_raw,
        message_digest_raw,
        total_raw,
        count_raw,
        state_raw,
        receipt_raw,
        duplicate_raw,
        row_digest_raw,
    ) = raw;
    let binding_digest = as_digest(&binding_raw)?;
    let sender_id = ParticipantId(as_digest(&sender_raw)?);
    let recipient_id = ParticipantId(as_digest(&recipient_raw)?);
    let message_digest = as_digest(&message_digest_raw)?;
    let total_len = as_u32_be(&total_raw)?;
    let chunk_count = as_u16_be(&count_raw)?;
    let state =
        u8::try_from(state_raw).map_err(|_| DurableFrameReassemblerErrorV2::CorruptState)?;
    let delivery_receipt = as_digest(&receipt_raw)?;
    let downstream_duplicate = match duplicate_raw {
        0 => false,
        1 => true,
        _ => return Err(DurableFrameReassemblerErrorV2::CorruptState),
    };
    let row_digest = as_digest(&row_digest_raw)?;
    let total =
        usize::try_from(total_len).map_err(|_| DurableFrameReassemblerErrorV2::CorruptState)?;
    if recipient_id != config.recipient_id
        || sender_id.0 == ZERO_DIGEST
        || sender_id == recipient_id
        || total <= 16_384
        || total > MAX_FRAMED_DSC1_BYTES_V2
        || frame_count(total)? != chunk_count
        || binding_digest
            != binding_digest_v2(
                config.wire,
                sender_id,
                recipient_id,
                &message_digest,
                total_len,
                chunk_count,
            )?
        || state > 3
        || (state <= 1 && (delivery_receipt != ZERO_DIGEST || downstream_duplicate))
        || (state >= 2 && delivery_receipt == ZERO_DIGEST)
        || message_row_digest(
            config,
            &binding_digest,
            sender_id,
            recipient_id,
            &message_digest,
            total_len,
            chunk_count,
            state,
            &delivery_receipt,
            downstream_duplicate,
        )? != row_digest
    {
        return Err(DurableFrameReassemblerErrorV2::CorruptState);
    }
    Ok(StoredMessageV2 {
        binding_digest,
        sender_id,
        recipient_id,
        message_digest,
        total_len,
        chunk_count,
        state,
        delivery_receipt,
        downstream_duplicate,
        row_digest,
    })
}

type RawFrameV2 = (
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
);

fn raw_frame(row: &rusqlite::Row<'_>) -> rusqlite::Result<RawFrameV2> {
    Ok((
        row.get(0)?,
        row.get(1)?,
        row.get(2)?,
        row.get(3)?,
        row.get(4)?,
        row.get(5)?,
        row.get(6)?,
        row.get(7)?,
    ))
}

fn load_frame_tx(
    transaction: &Transaction<'_>,
    binding: &Digest32,
    index: u16,
    message: &StoredMessageV2,
    config: &DurableFrameReassemblerConfigV2,
) -> Result<Option<StoredFrameV2>, DurableFrameReassemblerErrorV2> {
    let raw = transaction
        .query_row(
            "SELECT binding_digest, chunk_index_be, offset_be, chunk_digest,
                    chunk, source_sequence_be, source_envelope_digest, row_digest
             FROM reassembly_frames
             WHERE binding_digest = ?1 AND chunk_index_be = ?2",
            params![binding.as_slice(), index.to_be_bytes().as_slice()],
            raw_frame,
        )
        .optional()?;
    raw.map(|raw| validate_frame(raw, message, config))
        .transpose()
}

fn load_frames_tx(
    transaction: &Transaction<'_>,
    message: &StoredMessageV2,
    config: &DurableFrameReassemblerConfigV2,
) -> Result<Vec<StoredFrameV2>, DurableFrameReassemblerErrorV2> {
    let mut statement = transaction.prepare(
        "SELECT binding_digest, chunk_index_be, offset_be, chunk_digest,
                chunk, source_sequence_be, source_envelope_digest, row_digest
         FROM reassembly_frames WHERE binding_digest = ?1
         ORDER BY chunk_index_be ASC",
    )?;
    let rows = statement.query_map(params![message.binding_digest.as_slice()], raw_frame)?;
    collect_frames(rows, message, config)
}

fn load_frames_connection(
    connection: &Connection,
    message: &StoredMessageV2,
    config: &DurableFrameReassemblerConfigV2,
) -> Result<Vec<StoredFrameV2>, DurableFrameReassemblerErrorV2> {
    let mut statement = connection.prepare(
        "SELECT binding_digest, chunk_index_be, offset_be, chunk_digest,
                chunk, source_sequence_be, source_envelope_digest, row_digest
         FROM reassembly_frames WHERE binding_digest = ?1
         ORDER BY chunk_index_be ASC",
    )?;
    let rows = statement.query_map(params![message.binding_digest.as_slice()], raw_frame)?;
    collect_frames(rows, message, config)
}

fn collect_frames(
    rows: rusqlite::MappedRows<'_, impl FnMut(&rusqlite::Row<'_>) -> rusqlite::Result<RawFrameV2>>,
    message: &StoredMessageV2,
    config: &DurableFrameReassemblerConfigV2,
) -> Result<Vec<StoredFrameV2>, DurableFrameReassemblerErrorV2> {
    let mut frames = Vec::new();
    for row in rows {
        frames.push(validate_frame(row?, message, config)?);
    }
    Ok(frames)
}

fn validate_frame(
    raw: RawFrameV2,
    message: &StoredMessageV2,
    config: &DurableFrameReassemblerConfigV2,
) -> Result<StoredFrameV2, DurableFrameReassemblerErrorV2> {
    let (
        binding_raw,
        index_raw,
        offset_raw,
        chunk_digest_raw,
        chunk,
        source_sequence_raw,
        source_envelope_raw,
        row_digest_raw,
    ) = raw;
    let binding_digest = as_digest(&binding_raw)?;
    let index = as_u16_be(&index_raw)?;
    let offset = as_u32_be(&offset_raw)?;
    let chunk_digest = as_digest(&chunk_digest_raw)?;
    let source_sequence = as_u64_be(&source_sequence_raw)?;
    let source_envelope_digest = as_digest(&source_envelope_raw)?;
    let row_digest = as_digest(&row_digest_raw)?;
    if binding_digest != message.binding_digest
        || index >= message.chunk_count
        || chunk.is_empty()
        || chunk.len() > MAX_ROUTE_FRAME_CHUNK_BYTES_V2
        || frame_row_digest(
            config,
            &binding_digest,
            index,
            offset,
            &chunk_digest,
            &chunk,
            source_sequence,
            &source_envelope_digest,
        )? != row_digest
    {
        return Err(DurableFrameReassemblerErrorV2::CorruptState);
    }
    let canonical = encode_frame(
        binding_digest,
        message.message_digest,
        index,
        message.chunk_count,
        message.total_len,
        offset,
        &chunk,
    )?;
    let decoded = RouteFrameV2::decode_for_flow(
        &canonical,
        config.wire,
        message.sender_id,
        message.recipient_id,
    )?;
    if decoded.chunk_digest() != &chunk_digest || decoded.binding_digest() != &binding_digest {
        return Err(DurableFrameReassemblerErrorV2::CorruptState);
    }
    Ok(StoredFrameV2 {
        binding_digest,
        index,
        offset,
        chunk_digest,
        chunk,
        source_sequence,
    })
}

fn insert_terminal_summaries(
    transaction: &Transaction<'_>,
    config: &DurableFrameReassemblerConfigV2,
    frames: &[StoredFrameV2],
) -> Result<(), DurableFrameReassemblerErrorV2> {
    for frame in frames {
        let row_digest = terminal_frame_digest(
            config,
            &frame.binding_digest,
            frame.index,
            &frame.chunk_digest,
        )?;
        transaction.execute(
            "INSERT INTO reassembly_terminal_frames
             (binding_digest, chunk_index_be, chunk_digest, row_digest)
             VALUES (?1, ?2, ?3, ?4)",
            params![
                frame.binding_digest.as_slice(),
                frame.index.to_be_bytes().as_slice(),
                frame.chunk_digest.as_slice(),
                row_digest.as_slice(),
            ],
        )?;
    }
    Ok(())
}

fn require_terminal_frame_tx(
    transaction: &Transaction<'_>,
    message: &StoredMessageV2,
    frame: &RouteFrameV2,
    config: &DurableFrameReassemblerConfigV2,
) -> Result<(), DurableFrameReassemblerErrorV2> {
    let raw = transaction
        .query_row(
            "SELECT binding_digest, chunk_index_be, chunk_digest, row_digest
             FROM reassembly_terminal_frames
             WHERE binding_digest = ?1 AND chunk_index_be = ?2",
            params![
                message.binding_digest.as_slice(),
                frame.index().to_be_bytes().as_slice(),
            ],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, Vec<u8>>(3)?,
                ))
            },
        )
        .optional()?;
    let Some(raw) = raw else {
        return Err(DurableFrameReassemblerErrorV2::CorruptState);
    };
    let retained = validate_terminal_frame(raw, message, config)?;
    if retained.chunk_digest != *frame.chunk_digest() {
        return Err(DurableFrameReassemblerErrorV2::FrameEquivocation);
    }
    Ok(())
}

type RawTerminalFrameV2 = (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>);

fn load_terminal_frames_connection(
    connection: &Connection,
    message: &StoredMessageV2,
    config: &DurableFrameReassemblerConfigV2,
) -> Result<Vec<TerminalFrameV2>, DurableFrameReassemblerErrorV2> {
    let mut statement = connection.prepare(
        "SELECT binding_digest, chunk_index_be, chunk_digest, row_digest
         FROM reassembly_terminal_frames WHERE binding_digest = ?1
         ORDER BY chunk_index_be ASC",
    )?;
    let rows = statement.query_map(params![message.binding_digest.as_slice()], |row| {
        Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
    })?;
    let mut summaries = Vec::new();
    for (expected, row) in rows.enumerate() {
        let summary = validate_terminal_frame(row?, message, config)?;
        if usize::from(summary.index) != expected {
            return Err(DurableFrameReassemblerErrorV2::CorruptState);
        }
        summaries.push(summary);
    }
    Ok(summaries)
}

fn validate_terminal_frame(
    raw: RawTerminalFrameV2,
    message: &StoredMessageV2,
    config: &DurableFrameReassemblerConfigV2,
) -> Result<TerminalFrameV2, DurableFrameReassemblerErrorV2> {
    let (binding_raw, index_raw, chunk_digest_raw, row_digest_raw) = raw;
    let binding_digest = as_digest(&binding_raw)?;
    let index = as_u16_be(&index_raw)?;
    let chunk_digest = as_digest(&chunk_digest_raw)?;
    let row_digest = as_digest(&row_digest_raw)?;
    if binding_digest != message.binding_digest
        || index >= message.chunk_count
        || terminal_frame_digest(config, &binding_digest, index, &chunk_digest)? != row_digest
    {
        return Err(DurableFrameReassemblerErrorV2::CorruptState);
    }
    Ok(TerminalFrameV2 {
        index,
        chunk_digest,
    })
}

#[allow(clippy::too_many_arguments)]
fn message_row_digest(
    config: &DurableFrameReassemblerConfigV2,
    binding: &Digest32,
    sender: ParticipantId,
    recipient: ParticipantId,
    message_digest: &Digest32,
    total_len: u32,
    chunk_count: u16,
    state: u8,
    receipt: &Digest32,
    duplicate: bool,
) -> Result<Digest32, DurableFrameReassemblerErrorV2> {
    digest_parts(
        MESSAGE_ROW_DOMAIN,
        &[
            config.reassembler_id.as_slice(),
            binding.as_slice(),
            sender.0.as_slice(),
            recipient.0.as_slice(),
            message_digest.as_slice(),
            &total_len.to_be_bytes(),
            &chunk_count.to_be_bytes(),
            &[state],
            receipt.as_slice(),
            &[u8::from(duplicate)],
        ],
    )
}

#[allow(clippy::too_many_arguments)]
fn frame_row_digest(
    config: &DurableFrameReassemblerConfigV2,
    binding: &Digest32,
    index: u16,
    offset: u32,
    chunk_digest: &Digest32,
    chunk: &[u8],
    source_sequence: u64,
    source_envelope_digest: &Digest32,
) -> Result<Digest32, DurableFrameReassemblerErrorV2> {
    let chunk_len =
        u32::try_from(chunk.len()).map_err(|_| DurableFrameReassemblerErrorV2::CorruptState)?;
    digest_parts(
        FRAME_ROW_DOMAIN,
        &[
            config.reassembler_id.as_slice(),
            binding.as_slice(),
            &index.to_be_bytes(),
            &offset.to_be_bytes(),
            chunk_digest.as_slice(),
            &chunk_len.to_be_bytes(),
            chunk,
            &source_sequence.to_be_bytes(),
            source_envelope_digest.as_slice(),
        ],
    )
}

fn frame_receipt(
    config: &DurableFrameReassemblerConfigV2,
    binding: &Digest32,
    index: u16,
    chunk_digest: &Digest32,
) -> Result<Digest32, DurableFrameReassemblerErrorV2> {
    digest_parts(
        FRAME_RECEIPT_DOMAIN,
        &[
            config.reassembler_id.as_slice(),
            binding.as_slice(),
            &index.to_be_bytes(),
            chunk_digest.as_slice(),
        ],
    )
}

fn terminal_frame_digest(
    config: &DurableFrameReassemblerConfigV2,
    binding: &Digest32,
    index: u16,
    chunk_digest: &Digest32,
) -> Result<Digest32, DurableFrameReassemblerErrorV2> {
    digest_parts(
        TERMINAL_FRAME_DOMAIN,
        &[
            config.reassembler_id.as_slice(),
            binding.as_slice(),
            &index.to_be_bytes(),
            chunk_digest.as_slice(),
        ],
    )
}

fn reassembly_failure_receipt(
    config: &DurableFrameReassemblerConfigV2,
    binding: &Digest32,
) -> Result<Digest32, DurableFrameReassemblerErrorV2> {
    digest_parts(
        REASSEMBLY_FAILURE_DOMAIN,
        &[config.reassembler_id.as_slice(), binding.as_slice(), &[1]],
    )
}

fn digest_parts(
    domain: &[u8],
    parts: &[&[u8]],
) -> Result<Digest32, DurableFrameReassemblerErrorV2> {
    let mut hasher =
        Blake2bVar::new(32).map_err(|_| DurableFrameReassemblerErrorV2::CorruptState)?;
    hasher.update(domain);
    for part in parts {
        hasher.update(part);
    }
    let mut digest = [0; 32];
    hasher
        .finalize_variable(&mut digest)
        .map_err(|_| DurableFrameReassemblerErrorV2::CorruptState)?;
    Ok(digest)
}

fn as_digest(bytes: &[u8]) -> Result<Digest32, DurableFrameReassemblerErrorV2> {
    bytes
        .try_into()
        .map_err(|_| DurableFrameReassemblerErrorV2::CorruptState)
}

fn as_u16_be(bytes: &[u8]) -> Result<u16, DurableFrameReassemblerErrorV2> {
    let exact: [u8; 2] = bytes
        .try_into()
        .map_err(|_| DurableFrameReassemblerErrorV2::CorruptState)?;
    Ok(u16::from_be_bytes(exact))
}

fn as_u32_be(bytes: &[u8]) -> Result<u32, DurableFrameReassemblerErrorV2> {
    let exact: [u8; 4] = bytes
        .try_into()
        .map_err(|_| DurableFrameReassemblerErrorV2::CorruptState)?;
    Ok(u32::from_be_bytes(exact))
}

fn as_u64_be(bytes: &[u8]) -> Result<u64, DurableFrameReassemblerErrorV2> {
    let exact: [u8; 8] = bytes
        .try_into()
        .map_err(|_| DurableFrameReassemblerErrorV2::CorruptState)?;
    Ok(u64::from_be_bytes(exact))
}

fn configure_connection(connection: &Connection) -> Result<(), DurableFrameReassemblerErrorV2> {
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
        return Err(DurableFrameReassemblerErrorV2::UnsupportedFormat);
    }
    let journal_mode: String = connection.query_row("PRAGMA journal_mode", [], |row| row.get(0))?;
    let synchronous: i64 = connection.query_row("PRAGMA synchronous", [], |row| row.get(0))?;
    let foreign_keys: i64 = connection.query_row("PRAGMA foreign_keys", [], |row| row.get(0))?;
    let read_uncommitted: i64 =
        connection.query_row("PRAGMA read_uncommitted", [], |row| row.get(0))?;
    let trusted_schema: i64 =
        connection.query_row("PRAGMA trusted_schema", [], |row| row.get(0))?;
    let secure_delete: i64 = connection.query_row("PRAGMA secure_delete", [], |row| row.get(0))?;
    let temp_store: i64 = connection.query_row("PRAGMA temp_store", [], |row| row.get(0))?;
    let busy_timeout: i64 = connection.query_row("PRAGMA busy_timeout", [], |row| row.get(0))?;
    if !journal_mode.eq_ignore_ascii_case("wal")
        || synchronous != 2
        || foreign_keys != 1
        || read_uncommitted != 0
        || trusted_schema != 0
        || secure_delete != 1
        || temp_store != 2
        || busy_timeout != 5_000
    {
        return Err(DurableFrameReassemblerErrorV2::UnsupportedFormat);
    }
    Ok(())
}

fn insert_meta(
    connection: &Connection,
    config: DurableFrameReassemblerConfigV2,
) -> Result<(), DurableFrameReassemblerErrorV2> {
    connection.execute(
        "INSERT INTO reassembly_meta
         (singleton, schema_version, reassembler_id, network_id, session_id,
          route_id, roster_snapshot, recipient_id, policy_version, max_messages,
          max_active_bytes, max_active_chunks, retained_messages, active_bytes,
          active_chunks)
         VALUES (1, ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, 0, 0, 0)",
        params![
            SCHEMA_VERSION,
            config.reassembler_id.as_slice(),
            config.wire.network_id.as_slice(),
            config.wire.session_id.as_slice(),
            config.wire.route_id.as_slice(),
            config.wire.roster_snapshot.as_slice(),
            config.recipient_id.0.as_slice(),
            i64::from(config.wire.policy_version),
            i64::from(config.max_messages),
            i64::try_from(config.max_active_bytes)
                .map_err(|_| DurableFrameReassemblerErrorV2::InvalidConfiguration)?,
            i64::from(config.max_active_chunks),
        ],
    )?;
    Ok(())
}

fn initialize_pristine_store(
    connection: &Connection,
    config: DurableFrameReassemblerConfigV2,
) -> Result<(), DurableFrameReassemblerErrorV2> {
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

fn audit_schema(connection: &Connection) -> Result<(), DurableFrameReassemblerErrorV2> {
    let objects = schema_objects(connection)?;
    let expected = reference_schema_objects()?;
    if objects != expected {
        return Err(DurableFrameReassemblerErrorV2::UnsupportedFormat);
    }
    Ok(())
}

fn reference_schema_objects(
) -> Result<Vec<(String, String, String, String)>, DurableFrameReassemblerErrorV2> {
    let reference = Connection::open_in_memory()?;
    reference.execute_batch(SCHEMA_SQL)?;
    schema_objects(&reference)
}

fn require_pristine_connection(
    connection: &Connection,
    config: &DurableFrameReassemblerConfigV2,
) -> Result<(), DurableFrameReassemblerErrorV2> {
    let retained = connection
        .query_row(
            "SELECT schema_version, reassembler_id, network_id, session_id,
                    route_id, roster_snapshot, recipient_id, policy_version,
                    max_messages, max_active_bytes, max_active_chunks,
                    retained_messages, active_bytes, active_chunks
             FROM reassembly_meta WHERE singleton = 1",
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
                    row.get::<_, i64>(10)?,
                    row.get::<_, i64>(11)?,
                    row.get::<_, i64>(12)?,
                    row.get::<_, i64>(13)?,
                ))
            },
        )
        .optional()?;
    let Some((
        version,
        id,
        network,
        session,
        route,
        roster,
        recipient,
        policy,
        max_messages,
        max_bytes,
        max_chunks,
        retained,
        active_bytes,
        active_chunks,
    )) = retained
    else {
        return Err(DurableFrameReassemblerErrorV2::WrongIdentity);
    };
    let (messages, frames, terminals): (i64, i64, i64) = connection.query_row(
        "SELECT
            (SELECT COUNT(*) FROM reassembly_messages),
            (SELECT COUNT(*) FROM reassembly_frames),
            (SELECT COUNT(*) FROM reassembly_terminal_frames)",
        [],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    )?;
    let expected_max_bytes = i64::try_from(config.max_active_bytes)
        .map_err(|_| DurableFrameReassemblerErrorV2::InvalidConfiguration)?;
    if version != SCHEMA_VERSION
        || as_digest(&id)? != config.reassembler_id
        || as_digest(&network)? != config.wire.network_id
        || as_digest(&session)? != config.wire.session_id
        || as_digest(&route)? != config.wire.route_id
        || as_digest(&roster)? != config.wire.roster_snapshot
        || as_digest(&recipient)? != config.recipient_id.0
        || policy != i64::from(config.wire.policy_version)
        || max_messages != i64::from(config.max_messages)
        || max_bytes != expected_max_bytes
        || max_chunks != i64::from(config.max_active_chunks)
        || retained != 0
        || active_bytes != 0
        || active_chunks != 0
        || messages != 0
        || frames != 0
        || terminals != 0
    {
        return Err(DurableFrameReassemblerErrorV2::UnsupportedFormat);
    }
    Ok(())
}

fn preflight_resumable_database(
    database_path: &Path,
    authority: &File,
    config: &DurableFrameReassemblerConfigV2,
) -> Result<DurableProductionCreationStateV1, DurableFrameReassemblerErrorV2> {
    validate_database_authority(authority, database_path)?;
    if authority
        .metadata()
        .map_err(|_| DurableFrameReassemblerErrorV2::StorageUnavailable)?
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
    config: &DurableFrameReassemblerConfigV2,
) -> Result<DurableProductionCreationStateV1, DurableFrameReassemblerErrorV2> {
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
        return Err(DurableFrameReassemblerErrorV2::UnsupportedFormat);
    };
    Ok(state)
}

fn validate_database_path(
    connection: &Connection,
    expected_path: &Path,
) -> Result<(), DurableFrameReassemblerErrorV2> {
    let expected = fs::canonicalize(expected_path)
        .map_err(|_| DurableFrameReassemblerErrorV2::InvalidConfiguration)?;
    if expected != expected_path {
        return Err(DurableFrameReassemblerErrorV2::InvalidConfiguration);
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
            _ => return Err(DurableFrameReassemblerErrorV2::InvalidConfiguration),
        }
    }
    if !saw_main {
        return Err(DurableFrameReassemblerErrorV2::InvalidConfiguration);
    }
    Ok(())
}

type SchemaObjectV2 = (String, String, String, String);

fn schema_objects(
    connection: &Connection,
) -> Result<Vec<SchemaObjectV2>, DurableFrameReassemblerErrorV2> {
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
        return Err(DurableFrameReassemblerErrorV2::UnsupportedFormat);
    }

    let mut statement = connection.prepare(
        "SELECT type, name, tbl_name, COALESCE(sql, '') FROM sqlite_schema
         WHERE name NOT LIKE 'sqlite_%' ORDER BY type, name, tbl_name",
    )?;
    let rows = statement.query_map([], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, String>(3)?,
        ))
    })?;
    let mut actual = Vec::new();
    for row in rows {
        actual.push(row?);
    }
    if i64::try_from(actual.len()).ok() != Some(count) {
        return Err(DurableFrameReassemblerErrorV2::UnsupportedFormat);
    }
    Ok(actual)
}

fn create_root(root: &Path) -> Result<(), DurableFrameReassemblerErrorV2> {
    validate_new_path(root)?;
    match DirBuilder::new().mode(ROOT_MODE).create(root) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            return Err(DurableFrameReassemblerErrorV2::AlreadyExists)
        }
        Err(_) => return Err(DurableFrameReassemblerErrorV2::StorageUnavailable),
    }
    sync_directory(root)?;
    let parent = root
        .parent()
        .ok_or(DurableFrameReassemblerErrorV2::InvalidConfiguration)?;
    sync_directory(parent)?;
    validate_root(root)
}

fn validate_new_path(root: &Path) -> Result<(), DurableFrameReassemblerErrorV2> {
    if !root.is_absolute() || root.file_name().is_none() {
        return Err(DurableFrameReassemblerErrorV2::InvalidConfiguration);
    }
    let parent = root
        .parent()
        .ok_or(DurableFrameReassemblerErrorV2::InvalidConfiguration)?;
    let canonical_parent = fs::canonicalize(parent)
        .map_err(|_| DurableFrameReassemblerErrorV2::InvalidConfiguration)?;
    if canonical_parent != parent {
        return Err(DurableFrameReassemblerErrorV2::InvalidConfiguration);
    }
    validate_owner_directory(parent)
}

fn validate_root(root: &Path) -> Result<(), DurableFrameReassemblerErrorV2> {
    if !root.is_absolute()
        || fs::canonicalize(root).map_err(|_| DurableFrameReassemblerErrorV2::StorageUnavailable)?
            != root
    {
        return Err(DurableFrameReassemblerErrorV2::InvalidConfiguration);
    }
    validate_owner_directory(root)
}

fn validate_root_entries(root: &Path) -> Result<(), DurableFrameReassemblerErrorV2> {
    let allowed = [
        LOCK_FILE_NAME,
        DATABASE_FILE_NAME,
        "route-frame-reassembly-v2.sqlite3-wal",
        "route-frame-reassembly-v2.sqlite3-shm",
    ];
    let entries =
        fs::read_dir(root).map_err(|_| DurableFrameReassemblerErrorV2::StorageUnavailable)?;
    for entry in entries {
        let name = entry
            .map_err(|_| DurableFrameReassemblerErrorV2::StorageUnavailable)?
            .file_name()
            .into_string()
            .map_err(|_| DurableFrameReassemblerErrorV2::InvalidConfiguration)?;
        if !allowed.contains(&name.as_str()) {
            return Err(DurableFrameReassemblerErrorV2::InvalidConfiguration);
        }
    }
    Ok(())
}

fn inspect_creation_state(
    root: &Path,
    config: &DurableFrameReassemblerConfigV2,
) -> Result<DurableProductionCreationStateV1, DurableFrameReassemblerErrorV2> {
    match fs::symlink_metadata(root) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            validate_new_path(root)?;
            return Ok(DurableProductionCreationStateV1::Missing);
        }
        Err(_) => return Err(DurableFrameReassemblerErrorV2::StorageUnavailable),
        Ok(_) => validate_root(root)?,
    }
    validate_root_entries(root)?;
    let lock_path = root.join(LOCK_FILE_NAME);
    let database_path = root.join(DATABASE_FILE_NAME);
    let lock_exists = lock_path
        .try_exists()
        .map_err(|_| DurableFrameReassemblerErrorV2::StorageUnavailable)?;
    let database_exists = database_path
        .try_exists()
        .map_err(|_| DurableFrameReassemblerErrorV2::StorageUnavailable)?;
    if !lock_exists {
        if fs::read_dir(root)
            .map_err(|_| DurableFrameReassemblerErrorV2::StorageUnavailable)?
            .next()
            .is_none()
        {
            return Ok(DurableProductionCreationStateV1::Incomplete);
        }
        return Err(DurableFrameReassemblerErrorV2::InvalidConfiguration);
    }
    validate_owner_file(&lock_path)?;
    validate_resumable_database_files(root, database_exists)?;
    if !database_exists {
        return Ok(DurableProductionCreationStateV1::Incomplete);
    }
    let authority = open_database_authority(&database_path)?;
    preflight_resumable_database(&database_path, &authority, config)
}

fn create_database_authority(path: &Path) -> Result<File, DurableFrameReassemblerErrorV2> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(FILE_MODE)
        .open(path)
        .map_err(|_| DurableFrameReassemblerErrorV2::StorageUnavailable)?;
    validate_database_authority(&file, path)?;
    file.sync_all()
        .map_err(|_| DurableFrameReassemblerErrorV2::StorageUnavailable)?;
    sync_directory(
        path.parent()
            .ok_or(DurableFrameReassemblerErrorV2::InvalidConfiguration)?,
    )?;
    Ok(file)
}

fn open_database_authority(path: &Path) -> Result<File, DurableFrameReassemblerErrorV2> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .map_err(|_| DurableFrameReassemblerErrorV2::StorageUnavailable)?;
    validate_database_authority(&file, path)?;
    Ok(file)
}

fn open_connection_via_authority(
    authority: &File,
    database_path: &Path,
    flags: OpenFlags,
) -> Result<(Connection, File), DurableFrameReassemblerErrorV2> {
    open_connection_via_authority_with_hooks(authority, database_path, flags, || Ok(()), || Ok(()))
}

fn open_connection_via_authority_with_hooks<BeforeOpen, AfterOpen>(
    authority: &File,
    database_path: &Path,
    flags: OpenFlags,
    before_open: BeforeOpen,
    after_open: AfterOpen,
) -> Result<(Connection, File), DurableFrameReassemblerErrorV2>
where
    BeforeOpen: FnOnce() -> Result<(), DurableFrameReassemblerErrorV2>,
    AfterOpen: FnOnce() -> Result<(), DurableFrameReassemblerErrorV2>,
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

fn validate_database_authority(
    authority: &File,
    path: &Path,
) -> Result<(), DurableFrameReassemblerErrorV2> {
    validate_owner_file(path)?;
    let retained = authority
        .metadata()
        .map_err(|_| DurableFrameReassemblerErrorV2::StorageUnavailable)?;
    let named = fs::symlink_metadata(path)
        .map_err(|_| DurableFrameReassemblerErrorV2::StorageUnavailable)?;
    if retained.dev() != named.dev() || retained.ino() != named.ino() {
        return Err(DurableFrameReassemblerErrorV2::InvalidConfiguration);
    }
    Ok(())
}

fn validate_connection_authority(
    authority: &File,
    sqlite_authority: &File,
    path: &Path,
) -> Result<(), DurableFrameReassemblerErrorV2> {
    validate_database_authority(authority, path)?;
    let retained = authority
        .metadata()
        .map_err(|_| DurableFrameReassemblerErrorV2::StorageUnavailable)?;
    let sqlite = sqlite_authority
        .metadata()
        .map_err(|_| DurableFrameReassemblerErrorV2::StorageUnavailable)?;
    if retained.dev() != sqlite.dev() || retained.ino() != sqlite.ino() {
        return Err(DurableFrameReassemblerErrorV2::InvalidConfiguration);
    }
    Ok(())
}

fn process_descriptor_snapshot() -> Result<BTreeMap<i32, (u64, u64)>, DurableFrameReassemblerErrorV2>
{
    let mut snapshot = BTreeMap::new();
    for entry in fs::read_dir("/proc/self/fd")
        .map_err(|_| DurableFrameReassemblerErrorV2::StorageUnavailable)?
    {
        let entry = entry.map_err(|_| DurableFrameReassemblerErrorV2::StorageUnavailable)?;
        let Ok(fd) = entry.file_name().to_string_lossy().parse::<i32>() else {
            continue;
        };
        match fs::metadata(entry.path()) {
            Ok(metadata) => {
                snapshot.insert(fd, (metadata.dev(), metadata.ino()));
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err(DurableFrameReassemblerErrorV2::StorageUnavailable),
        }
    }
    Ok(snapshot)
}

fn capture_new_sqlite_database_authority(
    authority: &File,
    before: &BTreeMap<i32, (u64, u64)>,
) -> Result<File, DurableFrameReassemblerErrorV2> {
    let retained = authority
        .metadata()
        .map_err(|_| DurableFrameReassemblerErrorV2::StorageUnavailable)?;
    let expected = (retained.dev(), retained.ino());
    let after = process_descriptor_snapshot()?;
    let mut candidates = after.iter().filter_map(|(fd, identity)| {
        (*identity == expected && before.get(fd) != Some(identity)).then_some(*fd)
    });
    let candidate = candidates
        .next()
        .ok_or(DurableFrameReassemblerErrorV2::InvalidConfiguration)?;
    if candidates.next().is_some() {
        return Err(DurableFrameReassemblerErrorV2::InvalidConfiguration);
    }
    let proof = File::open(PathBuf::from("/proc/self/fd").join(candidate.to_string()))
        .map_err(|_| DurableFrameReassemblerErrorV2::StorageUnavailable)?;
    let proof_metadata = proof
        .metadata()
        .map_err(|_| DurableFrameReassemblerErrorV2::StorageUnavailable)?;
    if (proof_metadata.dev(), proof_metadata.ino()) != expected {
        return Err(DurableFrameReassemblerErrorV2::InvalidConfiguration);
    }
    Ok(proof)
}

fn acquire_resume_lock(root: &Path) -> Result<File, DurableFrameReassemblerErrorV2> {
    match fs::symlink_metadata(root) {
        Ok(_) => validate_root(root)?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => create_root(root)?,
        Err(_) => return Err(DurableFrameReassemblerErrorV2::StorageUnavailable),
    }
    validate_root_entries(root)?;
    let lock_path = root.join(LOCK_FILE_NAME);
    let lock_exists = lock_path
        .try_exists()
        .map_err(|_| DurableFrameReassemblerErrorV2::StorageUnavailable)?;
    if lock_exists {
        acquire_lock(root, false)
    } else {
        let mut entries =
            fs::read_dir(root).map_err(|_| DurableFrameReassemblerErrorV2::StorageUnavailable)?;
        if entries.next().is_some() {
            return Err(DurableFrameReassemblerErrorV2::InvalidConfiguration);
        }
        acquire_lock(root, true)
    }
}

fn validate_resumable_database_files(
    root: &Path,
    database_exists: bool,
) -> Result<(), DurableFrameReassemblerErrorV2> {
    if database_exists {
        validate_owner_file(&root.join(DATABASE_FILE_NAME))?;
    }
    for suffix in ["-wal", "-shm"] {
        let sidecar = root.join(format!("{DATABASE_FILE_NAME}{suffix}"));
        if sidecar
            .try_exists()
            .map_err(|_| DurableFrameReassemblerErrorV2::StorageUnavailable)?
        {
            if !database_exists {
                return Err(DurableFrameReassemblerErrorV2::InvalidConfiguration);
            }
            validate_owner_file(&sidecar)?;
        }
    }
    Ok(())
}

fn validate_owner_directory(path: &Path) -> Result<(), DurableFrameReassemblerErrorV2> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|_| DurableFrameReassemblerErrorV2::StorageUnavailable)?;
    if !metadata.file_type().is_dir()
        || metadata.file_type().is_symlink()
        || metadata.uid() != geteuid().as_raw()
        || metadata.mode() & 0o7777 != ROOT_MODE
        || metadata.nlink() == 0
    {
        return Err(DurableFrameReassemblerErrorV2::InvalidConfiguration);
    }
    Ok(())
}

fn validate_owner_file(path: &Path) -> Result<(), DurableFrameReassemblerErrorV2> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|_| DurableFrameReassemblerErrorV2::StorageUnavailable)?;
    if !metadata.file_type().is_file()
        || metadata.file_type().is_symlink()
        || metadata.uid() != geteuid().as_raw()
        || metadata.mode() & 0o7777 != FILE_MODE
        || metadata.nlink() != 1
    {
        return Err(DurableFrameReassemblerErrorV2::InvalidConfiguration);
    }
    Ok(())
}

fn acquire_lock(root: &Path, create: bool) -> Result<File, DurableFrameReassemblerErrorV2> {
    let path = root.join(LOCK_FILE_NAME);
    let mut options = OpenOptions::new();
    options.read(true).write(true).mode(FILE_MODE);
    if create {
        options.create_new(true);
    }
    let file = options
        .open(&path)
        .map_err(|_| DurableFrameReassemblerErrorV2::StorageUnavailable)?;
    validate_owner_file(&path)?;
    let retained = file
        .metadata()
        .map_err(|_| DurableFrameReassemblerErrorV2::StorageUnavailable)?;
    let named = fs::symlink_metadata(&path)
        .map_err(|_| DurableFrameReassemblerErrorV2::StorageUnavailable)?;
    if retained.dev() != named.dev() || retained.ino() != named.ino() {
        return Err(DurableFrameReassemblerErrorV2::InvalidConfiguration);
    }
    flock(file.as_fd(), FlockOperation::NonBlockingLockExclusive)
        .map_err(|_| DurableFrameReassemblerErrorV2::StorageUnavailable)?;
    if create {
        file.sync_all()
            .map_err(|_| DurableFrameReassemblerErrorV2::StorageUnavailable)?;
        sync_directory(root)?;
    }
    Ok(file)
}

fn sync_directory(path: &Path) -> Result<(), DurableFrameReassemblerErrorV2> {
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| DurableFrameReassemblerErrorV2::StorageUnavailable)
}

#[cfg(test)]
mod tests {
    use std::error::Error;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    use relay::SenderRoleV1;

    use super::*;
    use crate::{RouteFramePlanV2, RouteSenderV1, MAX_ROUTE_FRAME_CHUNK_BYTES_V2};

    const SENDER: ParticipantId = ParticipantId([0x51; 32]);
    const RECIPIENT: ParticipantId = ParticipantId([0x61; 32]);

    fn wire() -> RouteWireContextV1 {
        RouteWireContextV1 {
            network_id: [0x11; 32],
            session_id: [0x12; 32],
            route_id: [0x13; 32],
            roster_snapshot: [0x14; 32],
            policy_version: 1,
        }
    }

    fn config(
        id: u8,
        max_messages: u16,
        max_bytes: u64,
        max_chunks: u32,
    ) -> DurableFrameReassemblerConfigV2 {
        DurableFrameReassemblerConfigV2::new(
            [id; 32],
            wire(),
            RECIPIENT,
            max_messages,
            max_bytes,
            max_chunks,
        )
        .unwrap()
    }

    fn plan(byte: u8, len: usize) -> (RouteFramePlanV2, Vec<u8>) {
        let sender = RouteSenderV1::new(
            wire(),
            SENDER,
            RECIPIENT,
            SenderRoleV1::Initiator,
            [0x21; 32],
            [0x22; 32],
        )
        .unwrap();
        let message = vec![byte; len];
        let plan = RouteFramePlanV2::new(sender.checkpoint(), &message).unwrap();
        (plan, message)
    }

    fn delivery<'a>(
        plan: &'a RouteFramePlanV2,
        index: usize,
        sequence: u64,
    ) -> ContractsRouteDeliveryV1<'a> {
        ContractsRouteDeliveryV1::from_authenticated_parts(
            SENDER,
            sequence,
            [u8::try_from(index + 1).unwrap_or(0xfe); 32],
            plan.frame_payload(index).unwrap(),
        )
    }

    fn secure_temporary() -> tempfile::TempDir {
        let temporary = tempfile::tempdir().unwrap();
        fs::set_permissions(temporary.path(), fs::Permissions::from_mode(0o700)).unwrap();
        temporary
    }

    #[test]
    fn production_resume_recovers_only_pristine_frame_prefixes() -> Result<(), Box<dyn Error>> {
        let temporary = secure_temporary();
        let cfg = config(0x70, 8, 2 * 1024 * 1024, 64);
        for name in [
            "absent",
            "empty-root",
            "lock-only",
            "database-file-synced",
            "initialized",
        ] {
            let root = temporary.path().join(name);
            match name {
                "absent" => {}
                "empty-root" => {
                    fs::create_dir(&root)?;
                    fs::set_permissions(&root, fs::Permissions::from_mode(0o700))?;
                }
                "lock-only" | "database-file-synced" => {
                    fs::create_dir(&root)?;
                    fs::set_permissions(&root, fs::Permissions::from_mode(0o700))?;
                    let lock = OpenOptions::new()
                        .read(true)
                        .write(true)
                        .create_new(true)
                        .mode(0o600)
                        .open(root.join(".route-frame-reassembly-v2.lock"))?;
                    lock.sync_all()?;
                    if name == "database-file-synced" {
                        let database = OpenOptions::new()
                            .read(true)
                            .write(true)
                            .create_new(true)
                            .mode(0o600)
                            .open(root.join("route-frame-reassembly-v2.sqlite3"))?;
                        database.sync_all()?;
                    }
                }
                "initialized" => {
                    drop(DurableFrameReassemblerV2::create(&root, cfg)?);
                }
                _ => return Err("unreachable frame prefix".into()),
            }
            let resumed = DurableFrameReassemblerV2::resume_create_production(&root, cfg)?;
            assert_eq!(resumed.stats()?, DurableFrameReassemblerStatsV2::default());
            assert_eq!(
                fs::metadata(root.join(DATABASE_FILE_NAME))?
                    .permissions()
                    .mode()
                    & 0o7777,
                FILE_MODE
            );
            drop(resumed);
            drop(DurableFrameReassemblerV2::open(&root, cfg)?);
        }
        Ok(())
    }

    #[test]
    fn production_resume_refuses_frame_state_transplant_and_unknown_entry(
    ) -> Result<(), Box<dyn Error>> {
        let temporary = secure_temporary();
        let cfg = config(0x79, 8, 2 * 1024 * 1024, 64);
        let economic = temporary.path().join("economic");
        let (frame_plan, _) = plan(0x44, MAX_ROUTE_FRAME_CHUNK_BYTES_V2 + 200);
        let mut store = DurableFrameReassemblerV2::create(&economic, cfg)?;
        let ingress = store.ingest_authenticated_frame(&delivery(&frame_plan, 0, 0))?;
        assert!(matches!(ingress, FrameIngressV2::Incomplete(_)));
        drop(store);
        assert!(matches!(
            DurableFrameReassemblerV2::resume_create_production(&economic, cfg),
            Err(DurableFrameReassemblerErrorV2::UnsupportedFormat)
        ));

        let transplanted = temporary.path().join("transplanted");
        drop(DurableFrameReassemblerV2::create(&transplanted, cfg)?);
        fs::hard_link(
            transplanted.join("route-frame-reassembly-v2.sqlite3"),
            temporary.path().join("frame-hardlink.sqlite3"),
        )?;
        assert!(matches!(
            DurableFrameReassemblerV2::resume_create_production(&transplanted, cfg),
            Err(DurableFrameReassemblerErrorV2::InvalidConfiguration)
        ));

        let unknown = temporary.path().join("unknown");
        drop(DurableFrameReassemblerV2::create(&unknown, cfg)?);
        fs::write(unknown.join("caller-shaped"), b"foreign")?;
        assert!(matches!(
            DurableFrameReassemblerV2::resume_create_production(&unknown, cfg),
            Err(DurableFrameReassemblerErrorV2::InvalidConfiguration)
        ));
        Ok(())
    }

    #[test]
    fn loss_reorder_duplicate_restart_and_terminal_redelivery_are_safe() {
        let temporary = secure_temporary();
        let root = temporary.path().join("frames");
        let cfg = config(0x71, 8, 2 * 1024 * 1024, 64);
        let (plan, original) = plan(0xa5, 2 * MAX_ROUTE_FRAME_CHUNK_BYTES_V2 + 17);
        assert_eq!(plan.frame_count(), 3);
        let mut store = DurableFrameReassemblerV2::create(&root, cfg).unwrap();

        assert!(matches!(
            store
                .ingest_authenticated_frame(&delivery(&plan, 2, 12))
                .unwrap(),
            FrameIngressV2::Incomplete(_)
        ));
        assert!(matches!(
            store
                .ingest_authenticated_frame(&delivery(&plan, 0, 10))
                .unwrap(),
            FrameIngressV2::Incomplete(_)
        ));
        let duplicate = store
            .ingest_authenticated_frame(&delivery(&plan, 0, 99))
            .unwrap();
        let FrameIngressV2::Incomplete(duplicate) = duplicate else {
            panic!("duplicate incomplete frame must stay incomplete");
        };
        assert!(duplicate.duplicate());
        assert_eq!(store.stats().unwrap().active_chunks, 2);
        drop(store);

        let mut store = DurableFrameReassemblerV2::open(&root, cfg).unwrap();
        let ready = store
            .ingest_authenticated_frame(&delivery(&plan, 1, 11))
            .unwrap();
        let FrameIngressV2::Ready {
            binding_digest,
            first_sequence,
            message,
            ..
        } = ready
        else {
            panic!("last missing frame must complete reassembly");
        };
        assert_eq!(first_sequence, 10);
        assert_eq!(message, original);
        let commit =
            DurablePayloadCommitV1::new(DurablePayloadDispositionV1::Applied, [0x91; 32], false)
                .unwrap();
        store.commit_downstream(binding_digest, commit).unwrap();
        let stats = store.stats().unwrap();
        assert_eq!(stats.delivered_messages, 1);
        assert_eq!(stats.active_chunks, 0);
        assert_eq!(stats.active_reserved_bytes, 0);
        drop(store);

        let mut store = DurableFrameReassemblerV2::open(&root, cfg).unwrap();
        let terminal = store
            .ingest_authenticated_frame(&delivery(&plan, 2, 100))
            .unwrap();
        let FrameIngressV2::Terminal(retained) = terminal else {
            panic!("terminal message must not be delivered twice");
        };
        assert_eq!(retained.disposition(), DurablePayloadDispositionV1::Applied);
        assert_eq!(retained.durable_receipt(), &[0x91; 32]);

        let decoded = RouteFrameV2::decode_for_flow(
            plan.frame_payload(2).unwrap(),
            wire(),
            SENDER,
            RECIPIENT,
        )
        .unwrap();
        let mut alternate = decoded.chunk().to_vec();
        alternate[0] ^= 1;
        let alternate = encode_frame(
            *decoded.binding_digest(),
            *decoded.message_digest(),
            decoded.index(),
            decoded.count(),
            decoded.total_len(),
            decoded.offset(),
            &alternate,
        )
        .unwrap();
        let alternate_delivery =
            ContractsRouteDeliveryV1::from_authenticated_parts(SENDER, 101, [0x92; 32], &alternate);
        assert!(matches!(
            store.ingest_authenticated_frame(&alternate_delivery),
            Err(DurableFrameReassemblerErrorV2::FrameEquivocation)
        ));
    }

    #[test]
    fn valid_per_chunk_equivocation_and_mixed_message_fail_closed() {
        let temporary = secure_temporary();
        let root = temporary.path().join("equivocation");
        let cfg = config(0x72, 8, 2 * 1024 * 1024, 64);
        let (plan, _) = plan(0x44, MAX_ROUTE_FRAME_CHUNK_BYTES_V2 + 200);
        let mut store = DurableFrameReassemblerV2::create(&root, cfg).unwrap();
        store
            .ingest_authenticated_frame(&delivery(&plan, 0, 0))
            .unwrap();
        let decoded = RouteFrameV2::decode_for_flow(
            plan.frame_payload(0).unwrap(),
            wire(),
            SENDER,
            RECIPIENT,
        )
        .unwrap();
        let mut alternate = decoded.chunk().to_vec();
        alternate[0] ^= 1;
        let alternate = encode_frame(
            *decoded.binding_digest(),
            *decoded.message_digest(),
            decoded.index(),
            decoded.count(),
            decoded.total_len(),
            decoded.offset(),
            &alternate,
        )
        .unwrap();
        let alternate_delivery =
            ContractsRouteDeliveryV1::from_authenticated_parts(SENDER, 1, [0x88; 32], &alternate);
        assert!(matches!(
            store.ingest_authenticated_frame(&alternate_delivery),
            Err(DurableFrameReassemblerErrorV2::FrameEquivocation)
        ));
        drop(store);

        let root = temporary.path().join("mixed");
        let mut store =
            DurableFrameReassemblerV2::create(&root, config(0x73, 8, 2_000_000, 64)).unwrap();
        let mut outcome = None;
        for index in 0..plan.frame_count() {
            let decoded = RouteFrameV2::decode_for_flow(
                plan.frame_payload(index).unwrap(),
                wire(),
                SENDER,
                RECIPIENT,
            )
            .unwrap();
            let foreign_chunk = vec![0x99; decoded.chunk().len()];
            let mixed = encode_frame(
                *decoded.binding_digest(),
                *decoded.message_digest(),
                decoded.index(),
                decoded.count(),
                decoded.total_len(),
                decoded.offset(),
                &foreign_chunk,
            )
            .unwrap();
            let mixed_delivery = ContractsRouteDeliveryV1::from_authenticated_parts(
                SENDER,
                index as u64,
                [0x89; 32],
                &mixed,
            );
            outcome = Some(store.ingest_authenticated_frame(&mixed_delivery).unwrap());
        }
        let FrameIngressV2::Terminal(failed) = outcome.unwrap() else {
            panic!("full-message digest mismatch must become terminal");
        };
        assert_eq!(
            failed.disposition(),
            DurablePayloadDispositionV1::FailedClosed
        );
        assert_eq!(store.stats().unwrap().active_reserved_bytes, 0);
    }

    #[test]
    fn message_byte_and_chunk_quotas_refuse_before_overcommit() {
        let temporary = secure_temporary();
        let (first, _) = plan(1, 20_000);
        let (second, _) = plan(2, 20_000);
        let root = temporary.path().join("messages");
        let mut store =
            DurableFrameReassemblerV2::create(&root, config(0x74, 1, 1_000_000, 64)).unwrap();
        store
            .ingest_authenticated_frame(&delivery(&first, 0, 0))
            .unwrap();
        assert!(matches!(
            store.ingest_authenticated_frame(&delivery(&second, 0, 1)),
            Err(DurableFrameReassemblerErrorV2::MessageQuotaExceeded)
        ));
        drop(store);

        let root = temporary.path().join("bytes");
        let mut store =
            DurableFrameReassemblerV2::create(&root, config(0x75, 4, 19_999, 64)).unwrap();
        assert!(matches!(
            store.ingest_authenticated_frame(&delivery(&first, 0, 0)),
            Err(DurableFrameReassemblerErrorV2::ByteQuotaExceeded)
        ));
        drop(store);

        let root = temporary.path().join("chunks");
        let mut store =
            DurableFrameReassemblerV2::create(&root, config(0x76, 4, 1_000_000, 1)).unwrap();
        store
            .ingest_authenticated_frame(&delivery(&first, 0, 0))
            .unwrap();
        assert!(matches!(
            store.ingest_authenticated_frame(&delivery(&first, 1, 1)),
            Err(DurableFrameReassemblerErrorV2::ChunkQuotaExceeded)
        ));
    }

    #[test]
    fn owner_lock_and_schema_audit_fail_closed() {
        let temporary = secure_temporary();
        let root = temporary.path().join("authority");
        let cfg = config(0x77, 4, 1_000_000, 64);
        let store = DurableFrameReassemblerV2::create(&root, cfg).unwrap();
        assert!(matches!(
            DurableFrameReassemblerV2::open(&root, cfg),
            Err(DurableFrameReassemblerErrorV2::StorageUnavailable)
        ));
        drop(store);
        let database = root.join(DATABASE_FILE_NAME);
        let connection = Connection::open(database).unwrap();
        connection
            .execute("CREATE TABLE injected (value INTEGER) STRICT", [])
            .unwrap();
        drop(connection);
        assert!(matches!(
            DurableFrameReassemblerV2::open(&root, cfg),
            Err(DurableFrameReassemblerErrorV2::UnsupportedFormat)
        ));

        let root = temporary.path().join("changed-schema");
        let store = DurableFrameReassemblerV2::create(&root, cfg).unwrap();
        drop(store);
        let database = root.join(DATABASE_FILE_NAME);
        let connection = Connection::open(&database).unwrap();
        connection
            .execute(
                "ALTER TABLE reassembly_meta ADD COLUMN injected INTEGER",
                [],
            )
            .unwrap();
        drop(connection);
        assert!(matches!(
            DurableFrameReassemblerV2::open(&root, cfg),
            Err(DurableFrameReassemblerErrorV2::UnsupportedFormat)
        ));

        let root = temporary.path().join("wrong-mode");
        let store = DurableFrameReassemblerV2::create(&root, cfg).unwrap();
        drop(store);
        let database = root.join(DATABASE_FILE_NAME);
        fs::set_permissions(&database, fs::Permissions::from_mode(0o640)).unwrap();
        assert!(matches!(
            DurableFrameReassemblerV2::open(&root, cfg),
            Err(DurableFrameReassemblerErrorV2::InvalidConfiguration)
        ));
    }

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
                    .map_err(|_| DurableFrameReassemblerErrorV2::StorageUnavailable)
            },
            || {
                fs::rename(&database, &alternate)
                    .and_then(|()| fs::rename(&retained_name, &database))
                    .map_err(|_| DurableFrameReassemblerErrorV2::StorageUnavailable)
            },
        );
        assert!(matches!(
            result,
            Err(DurableFrameReassemblerErrorV2::InvalidConfiguration)
        ));
        validate_database_authority(&authority, &database)?;
        Ok(())
    }
}
