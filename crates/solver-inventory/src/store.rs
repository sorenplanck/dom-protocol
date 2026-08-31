//! SQLite/WAL inventory ledger, idempotency journal and authority fencing.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::time::Duration;

#[cfg(target_os = "linux")]
use std::os::fd::AsFd;
#[cfg(target_os = "linux")]
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

use blake2::digest::{consts::U32, Digest};
use blake2::Blake2b;
use f6_engine::composition::accepted_negotiation;
use f6_engine::v2::{AcceptedBindingAuthorityV2, AcceptedBindingViewV2};
use f6_engine::{BindingLog, DurableBinding};
use rfq::v2::{QuoteV2, SettlementPositionV2};
use rfq::{AssetId, ChainId, LegDirectionV1, ParticipantId, QuoteV1};
use rusqlite::{
    params, Connection, OpenFlags, OptionalExtension, Transaction, TransactionBehavior,
};
#[cfg(target_os = "linux")]
use rustix::fs::{flock, fstat, FileType, FlockOperation, Mode};
#[cfg(target_os = "linux")]
use rustix::process::geteuid;
use thiserror::Error;

use crate::model::{
    CommittedInventoryCapabilityV1, CommittedInventoryCapabilityV2, Digest32,
    InventoryAllocationCapabilityV1, InventoryAllocationRequestV1, InventoryExecutionV1,
    InventoryKeyV1, InventoryMutationContextV1, InventoryObservationKindV1, InventoryObservationV1,
    InventoryPurposeV1, InventorySnapshotRefV1, InventorySnapshotV1, MutationOutcomeV1,
    MutationStatusV1, PendingConsumptionV1, QuoteInventoryCapabilityV1, QuoteInventoryCapabilityV2,
    ReservationStateV1, ReservationViewV1, ReserveQuoteRequestV1, ReserveQuoteRequestV2,
    MAX_RESERVATION_ALLOCATIONS_V1,
};

const SCHEMA_VERSION: i64 = 2;
const APPLICATION_ID: i64 = 0x4449_4e56; // "DINV"
const DIRECTORY_MODE: u32 = 0o700;
const FILE_MODE: u32 = 0o600;
const MAX_LEASE_DURATION_MS: u64 = 86_400_000;
const MAX_OBSERVATION_VALIDITY_MS: u64 = 86_400_000;
const MAX_RESERVATION_TTL_MS: u64 = 86_400_000;
const MAX_PENDING_CONSUMPTIONS: usize = 65_536;

const STATE_RESERVED: i64 = 0;
const STATE_COMMITTED: i64 = 1;
const STATE_CONSUMED: i64 = 2;
const STATE_RELEASED: i64 = 3;

const PURPOSE_SETTLEMENT: i64 = 0;
const PURPOSE_BOND: i64 = 1;

/// Durable inventory authority failure. Storage diagnostics and opaque rows
/// are intentionally omitted from display output.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum InventoryStoreErrorV1 {
    /// SQLite was unavailable or an atomic operation failed.
    #[error("inventory storage unavailable")]
    StorageUnavailable,
    /// Schema or connection safety properties are incompatible.
    #[error("unsupported inventory database format")]
    UnsupportedFormat,
    /// The requested production authority does not exist.
    #[error("inventory database missing")]
    DatabaseMissing,
    /// Creation refused to replace an existing database, lock or sidecar.
    #[error("inventory database already exists")]
    DatabasePresent,
    /// Provisioning started but did not publish a complete empty authority.
    #[error("inventory database creation incomplete")]
    CreationIncomplete,
    /// Filesystem ownership, permissions, names or retained identities diverge.
    #[error("invalid inventory storage authority")]
    InvalidStorageAuthority,
    /// A second process already owns the physical authority.
    #[error("inventory storage authority held")]
    StorageAuthorityHeld,
    /// The persisted store binding differs from the authenticated production pin.
    #[error("inventory store binding mismatch")]
    BindingMismatch,
    /// A zero identity, zero amount, invalid ordering or defensive bound was
    /// supplied.
    #[error("invalid inventory material")]
    InvalidMaterial,
    /// Another unexpired process owns the authority.
    #[error("inventory authority lease held")]
    LeaseHeld,
    /// Owner or fencing generation is stale.
    #[error("stale inventory fencing generation")]
    StaleFencing,
    /// The exact lease expired.
    #[error("inventory lease expired")]
    LeaseExpired,
    /// Snapshot or reservation CAS revision changed.
    #[error("inventory revision conflict")]
    RevisionConflict,
    /// An operation id was reused for different material.
    #[error("inventory idempotency conflict")]
    IdempotencyConflict,
    /// No reconciled snapshot exists for an allocation.
    #[error("inventory snapshot not found")]
    SnapshotNotFound,
    /// Snapshot is past its authenticated validity window.
    #[error("inventory snapshot stale")]
    SnapshotStale,
    /// Snapshot version/evidence/config does not match the request.
    #[error("inventory snapshot mismatch")]
    SnapshotMismatch,
    /// Forward observations attempted an unexplained height/anchor regression.
    #[error("inventory observation regressed without reorg evidence")]
    ObservationRegression,
    /// Reorg metadata is invalid or absent.
    #[error("invalid inventory reorg evidence")]
    ReorgEvidenceRequired,
    /// Active and unreconciled allocations exceed observed spendable funds.
    #[error("inventory account undercollateralized")]
    UnderCollateralized,
    /// Reservation would exceed observed unencumbered funds.
    #[error("inventory capacity already reserved")]
    CapacityAlreadyReserved,
    /// Reservation id is already one-shot occupied.
    #[error("inventory reservation already exists")]
    ReservationAlreadyExists,
    /// Reservation was not found.
    #[error("inventory reservation not found")]
    ReservationNotFound,
    /// Reservation lifecycle does not admit the requested transition.
    #[error("invalid inventory reservation state")]
    InvalidReservationState,
    /// Reservation expired before it could be committed or offered.
    #[error("inventory reservation expired")]
    ReservationExpired,
    /// Expiry was requested before the deadline.
    #[error("inventory reservation is not expired")]
    ReservationNotExpired,
    /// Quote, output allocation, bond or accepted F6 facts diverge.
    #[error("inventory and f6 binding mismatch")]
    F6BindingMismatch,
    /// A takeover must reconcile and re-fence committed execution first.
    #[error("inventory execution reauthorization required")]
    ReauthorizationRequired,
    /// Persisted rows or commitments disagree.
    #[error("corrupt inventory state")]
    CorruptState,
}

impl From<rusqlite::Error> for InventoryStoreErrorV1 {
    fn from(_: rusqlite::Error) -> Self {
        Self::StorageUnavailable
    }
}

/// Exact process lease for one solver/custody authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InventoryLeaseV1 {
    /// Authority exclusively owned by this lease.
    pub authority_id: ParticipantId,
    /// Stable process identity.
    pub owner_id: Digest32,
    /// Monotonic generation external actuators must fence.
    pub fencing_epoch: u64,
    /// Absolute lease expiry.
    pub lease_until_unix_ms: u64,
}

/// Result of acquiring an inventory authority lease.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LeaseAcquireOutcomeV1 {
    /// A new fencing generation was allocated.
    Acquired(InventoryLeaseV1),
    /// This owner already holds the current live generation.
    AlreadyOwned(InventoryLeaseV1),
}

impl LeaseAcquireOutcomeV1 {
    /// Return the lease for either successful outcome.
    pub fn lease(self) -> InventoryLeaseV1 {
        match self {
            Self::Acquired(lease) | Self::AlreadyOwned(lease) => lease,
        }
    }
}

/// Single-process durable inventory authority retaining the exact database and
/// lock identities. Logical leases fence custody generations inside that sole
/// physical owner; a second process is refused before SQLite is opened.
pub struct DurableInventoryStoreV1 {
    connection: Connection,
    binding_digest: Digest32,
    path: PathBuf,
    lock_path: PathBuf,
    authority_file: File,
    lock_file: File,
    authority_identity: RetainedFileIdentityV1,
    lock_identity: RetainedFileIdentityV1,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct RetainedFileIdentityV1 {
    device: u64,
    inode: u64,
}

struct OpenedAuthorityV1 {
    connection: Connection,
    authority_file: File,
    lock_file: File,
    authority_identity: RetainedFileIdentityV1,
    lock_identity: RetainedFileIdentityV1,
    lock_path: PathBuf,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AuthorityOpenModeV1 {
    Create,
    OpenExisting,
    ResumeCreate,
}

#[cfg(target_os = "linux")]
fn open_authority(
    path: &Path,
    mode: AuthorityOpenModeV1,
) -> Result<OpenedAuthorityV1, InventoryStoreErrorV1> {
    validate_parent(path)?;
    let lock_path = lock_path(path);
    if mode == AuthorityOpenModeV1::Create {
        ensure_sidecars_absent(path)?;
        if std::fs::symlink_metadata(path).is_ok() || std::fs::symlink_metadata(&lock_path).is_ok()
        {
            return Err(InventoryStoreErrorV1::DatabasePresent);
        }
    }
    let lock_file = match mode {
        AuthorityOpenModeV1::Create => OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(FILE_MODE)
            .open(&lock_path)
            .map_err(map_create_error)?,
        AuthorityOpenModeV1::OpenExisting | AuthorityOpenModeV1::ResumeCreate => OpenOptions::new()
            .read(true)
            .write(true)
            .open(&lock_path)
            .map_err(|error| {
                if error.kind() == std::io::ErrorKind::NotFound {
                    if std::fs::symlink_metadata(path).is_ok() {
                        InventoryStoreErrorV1::InvalidStorageAuthority
                    } else {
                        InventoryStoreErrorV1::DatabaseMissing
                    }
                } else {
                    InventoryStoreErrorV1::InvalidStorageAuthority
                }
            })?,
    };
    validate_lock_file(&lock_path, &lock_file)?;
    let lock_identity = retained_identity(&lock_file)?;
    flock(lock_file.as_fd(), FlockOperation::NonBlockingLockExclusive)
        .map_err(|_| InventoryStoreErrorV1::StorageAuthorityHeld)?;
    if mode == AuthorityOpenModeV1::Create {
        lock_file
            .sync_all()
            .map_err(|_| InventoryStoreErrorV1::InvalidStorageAuthority)?;
        sync_parent(&lock_path)?;
        test_creation_crash_hook("after-lock-fsync");
    }
    let authority_file = match mode {
        AuthorityOpenModeV1::Create => create_database_file(path)?,
        AuthorityOpenModeV1::OpenExisting => OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .map_err(|error| {
            if error.kind() == std::io::ErrorKind::NotFound {
                InventoryStoreErrorV1::CreationIncomplete
            } else {
                InventoryStoreErrorV1::InvalidStorageAuthority
            }
        })?,
        AuthorityOpenModeV1::ResumeCreate => {
            match OpenOptions::new().read(true).write(true).open(path) {
                Ok(file) => file,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    create_database_file(path)?
                }
                Err(_) => return Err(InventoryStoreErrorV1::InvalidStorageAuthority),
            }
        }
    };
    validate_authority_file(path, &authority_file)?;
    validate_sqlite_header(&authority_file, mode != AuthorityOpenModeV1::OpenExisting)?;
    let authority_identity = retained_identity(&authority_file)?;
    validate_sidecars_for_mode(path, mode)?;
    let connection = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?;
    if retained_identity(&authority_file)? != authority_identity
        || named_identity(path)? != authority_identity
        || retained_identity(&lock_file)? != lock_identity
        || named_identity(&lock_path)? != lock_identity
    {
        return Err(InventoryStoreErrorV1::InvalidStorageAuthority);
    }
    Ok(OpenedAuthorityV1 {
        connection,
        authority_file,
        lock_file,
        authority_identity,
        lock_identity,
        lock_path,
    })
}

#[cfg(target_os = "linux")]
fn create_database_file(path: &Path) -> Result<File, InventoryStoreErrorV1> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(FILE_MODE)
        .open(path)
        .map_err(map_create_error)?;
    file.sync_all()
        .map_err(|_| InventoryStoreErrorV1::InvalidStorageAuthority)?;
    sync_parent(path)?;
    test_creation_crash_hook("after-database-fsync");
    Ok(file)
}

fn map_create_error(error: std::io::Error) -> InventoryStoreErrorV1 {
    if error.kind() == std::io::ErrorKind::AlreadyExists {
        InventoryStoreErrorV1::DatabasePresent
    } else {
        InventoryStoreErrorV1::InvalidStorageAuthority
    }
}

impl core::fmt::Debug for DurableInventoryStoreV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("DurableInventoryStoreV1([redacted])")
    }
}

impl DurableInventoryStoreV1 {
    /// Creates one new owner-only production authority without replacement.
    pub fn create(path: &Path, binding_digest: Digest32) -> Result<Self, InventoryStoreErrorV1> {
        validate_digest(binding_digest)?;
        #[cfg(not(target_os = "linux"))]
        {
            let _ = path;
            return Err(InventoryStoreErrorV1::InvalidStorageAuthority);
        }
        #[cfg(target_os = "linux")]
        {
            let mut opened = open_authority(path, AuthorityOpenModeV1::Create)?;
            configure_creation(&opened.connection)?;
            initialize_schema(&mut opened.connection, binding_digest)?;
            configure_connection(&opened.connection, true)?;
            test_creation_crash_hook("after-wal-transition");
            let store = Self::from_opened(path, binding_digest, opened);
            store.audit_storage()?;
            sync_parent(path)?;
            Ok(store)
        }
    }

    /// Opens one exact existing authority without creating or migrating it.
    pub fn open_existing(
        path: &Path,
        binding_digest: Digest32,
    ) -> Result<Self, InventoryStoreErrorV1> {
        validate_digest(binding_digest)?;
        #[cfg(not(target_os = "linux"))]
        {
            let _ = path;
            return Err(InventoryStoreErrorV1::InvalidStorageAuthority);
        }
        #[cfg(target_os = "linux")]
        {
            let opened = open_authority(path, AuthorityOpenModeV1::OpenExisting)?;
            let version: i64 = opened
                .connection
                .query_row("PRAGMA user_version", [], |row| row.get(0))?;
            if version == 0 {
                return Err(InventoryStoreErrorV1::CreationIncomplete);
            }
            configure_connection(&opened.connection, false)?;
            let store = Self::from_opened(path, binding_digest, opened);
            store.audit_storage()?;
            Ok(store)
        }
    }

    /// Atomically migrates one exact, fully authenticated production schema
    /// V1 authority to schema V2. V1 economic rows are audited before and
    /// after the transaction; the new V2 scope table starts empty, so no
    /// legacy reservation is promoted into a V2 composition.
    pub fn migrate_v1_to_v2_production(
        path: &Path,
        binding_digest: Digest32,
    ) -> Result<Self, InventoryStoreErrorV1> {
        validate_digest(binding_digest)?;
        #[cfg(not(target_os = "linux"))]
        {
            let _ = path;
            return Err(InventoryStoreErrorV1::InvalidStorageAuthority);
        }
        #[cfg(target_os = "linux")]
        {
            let mut opened = open_authority(path, AuthorityOpenModeV1::OpenExisting)?;
            configure_connection(&opened.connection, false)?;
            audit_schema_v1(&opened.connection, binding_digest)?;
            test_migration_crash_hook("before-migration-transaction");
            let transaction = opened
                .connection
                .transaction_with_behavior(TransactionBehavior::Exclusive)?;
            transaction.execute_batch(MIGRATE_SCHEMA_V1_TO_V2_SQL)?;
            audit_schema(&transaction, binding_digest)?;
            audit_runtime_state(&transaction)?;
            test_migration_crash_hook("before-migration-commit");
            transaction.commit()?;
            test_migration_crash_hook("after-migration-commit");
            let store = Self::from_opened(path, binding_digest, opened);
            store.audit_storage()?;
            sync_parent(path)?;
            Ok(store)
        }
    }

    /// Resumes only a pristine authority whose provisioning was already started.
    ///
    /// The exact empty lock must exist. The database may be absent, empty,
    /// pristine SQLite, or a complete store containing no economic state.
    /// This API never acts as a generic open-or-create fallback.
    pub fn resume_create_production(
        path: &Path,
        binding_digest: Digest32,
    ) -> Result<Self, InventoryStoreErrorV1> {
        validate_digest(binding_digest)?;
        #[cfg(not(target_os = "linux"))]
        {
            let _ = path;
            return Err(InventoryStoreErrorV1::InvalidStorageAuthority);
        }
        #[cfg(target_os = "linux")]
        {
            let mut opened = open_authority(path, AuthorityOpenModeV1::ResumeCreate)?;
            let version: i64 = opened
                .connection
                .query_row("PRAGMA user_version", [], |row| row.get(0))?;
            let journal: String =
                opened
                    .connection
                    .query_row("PRAGMA journal_mode", [], |row| row.get(0))?;
            let objects: i64 = opened.connection.query_row(
                "SELECT COUNT(*) FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%'",
                [],
                |row| row.get(0),
            )?;
            if version == 0 && objects == 0 {
                if !journal.eq_ignore_ascii_case("delete") {
                    return Err(InventoryStoreErrorV1::CorruptState);
                }
                configure_creation(&opened.connection)?;
                initialize_schema(&mut opened.connection, binding_digest)?;
            } else {
                audit_schema(&opened.connection, binding_digest)?;
                require_no_economic_state(&opened.connection)?;
                if journal.eq_ignore_ascii_case("delete") {
                    configure_creation(&opened.connection)?;
                } else if journal.eq_ignore_ascii_case("wal") {
                    configure_connection(&opened.connection, false)?;
                } else {
                    return Err(InventoryStoreErrorV1::CorruptState);
                }
            }
            if !journal.eq_ignore_ascii_case("wal") {
                configure_connection(&opened.connection, true)?;
            }
            let store = Self::from_opened(path, binding_digest, opened);
            store.audit_storage()?;
            sync_parent(path)?;
            Ok(store)
        }
    }

    #[cfg(target_os = "linux")]
    fn from_opened(path: &Path, binding_digest: Digest32, opened: OpenedAuthorityV1) -> Self {
        Self {
            connection: opened.connection,
            binding_digest,
            path: path.to_path_buf(),
            lock_path: opened.lock_path,
            authority_file: opened.authority_file,
            lock_file: opened.lock_file,
            authority_identity: opened.authority_identity,
            lock_identity: opened.lock_identity,
        }
    }

    /// Exact public binding pinned into this physical authority.
    pub const fn binding_digest(&self) -> Digest32 {
        self.binding_digest
    }

    /// Acquire an absent/expired authority lease. Every takeover increments
    /// the fencing generation; a live different owner fails closed.
    pub fn acquire_lease(
        &mut self,
        authority_id: ParticipantId,
        owner_id: Digest32,
        now_unix_ms: u64,
        duration_ms: u64,
    ) -> Result<LeaseAcquireOutcomeV1, InventoryStoreErrorV1> {
        self.audit_storage()?;
        validate_participant(authority_id)?;
        validate_digest(owner_id)?;
        let lease_until = deadline(now_unix_ms, duration_ms, MAX_LEASE_DURATION_MS)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let existing = load_lease_row(&transaction, authority_id)?;
        let outcome = match existing {
            None => {
                transaction.execute(
                    "INSERT INTO inventory_leases
                     (authority_id, owner_id, fencing_epoch,
                      lease_until_unix_ms, updated_at_unix_ms)
                     VALUES (?1, ?2, 1, ?3, ?4)",
                    params![
                        authority_id.0.as_slice(),
                        owner_id.as_slice(),
                        to_sql_u64(lease_until)?,
                        to_sql_u64(now_unix_ms)?
                    ],
                )?;
                LeaseAcquireOutcomeV1::Acquired(InventoryLeaseV1 {
                    authority_id,
                    owner_id,
                    fencing_epoch: 1,
                    lease_until_unix_ms: lease_until,
                })
            }
            Some((current_owner, epoch, current_until)) if current_until >= now_unix_ms => {
                if current_owner != owner_id {
                    return Err(InventoryStoreErrorV1::LeaseHeld);
                }
                LeaseAcquireOutcomeV1::AlreadyOwned(InventoryLeaseV1 {
                    authority_id,
                    owner_id,
                    fencing_epoch: epoch,
                    lease_until_unix_ms: current_until,
                })
            }
            Some((_old_owner, epoch, _old_until)) => {
                let next_epoch = epoch
                    .checked_add(1)
                    .ok_or(InventoryStoreErrorV1::InvalidMaterial)?;
                transaction.execute(
                    "UPDATE inventory_leases
                     SET owner_id = ?2, fencing_epoch = ?3,
                         lease_until_unix_ms = ?4, updated_at_unix_ms = ?5
                     WHERE authority_id = ?1",
                    params![
                        authority_id.0.as_slice(),
                        owner_id.as_slice(),
                        to_sql_u64(next_epoch)?,
                        to_sql_u64(lease_until)?,
                        to_sql_u64(now_unix_ms)?
                    ],
                )?;
                LeaseAcquireOutcomeV1::Acquired(InventoryLeaseV1 {
                    authority_id,
                    owner_id,
                    fencing_epoch: next_epoch,
                    lease_until_unix_ms: lease_until,
                })
            }
        };
        audit_runtime_state(&transaction)?;
        transaction.commit()?;
        self.audit_storage()?;
        Ok(outcome)
    }

    /// Renew the exact current lease without changing its fencing generation.
    pub fn renew_lease(
        &mut self,
        lease: InventoryLeaseV1,
        now_unix_ms: u64,
        duration_ms: u64,
    ) -> Result<InventoryLeaseV1, InventoryStoreErrorV1> {
        self.audit_storage()?;
        let lease_until = deadline(now_unix_ms, duration_ms, MAX_LEASE_DURATION_MS)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        validate_lease(&transaction, lease, now_unix_ms)?;
        let changed = transaction.execute(
            "UPDATE inventory_leases
             SET lease_until_unix_ms = ?4, updated_at_unix_ms = ?5
             WHERE authority_id = ?1 AND owner_id = ?2 AND fencing_epoch = ?3",
            params![
                lease.authority_id.0.as_slice(),
                lease.owner_id.as_slice(),
                to_sql_u64(lease.fencing_epoch)?,
                to_sql_u64(lease_until)?,
                to_sql_u64(now_unix_ms)?
            ],
        )?;
        if changed != 1 {
            return Err(InventoryStoreErrorV1::StaleFencing);
        }
        audit_runtime_state(&transaction)?;
        transaction.commit()?;
        self.audit_storage()?;
        Ok(InventoryLeaseV1 {
            lease_until_unix_ms: lease_until,
            ..lease
        })
    }

    /// Load and verify one materialized inventory snapshot.
    pub fn load_snapshot(
        &mut self,
        key: InventoryKeyV1,
    ) -> Result<InventorySnapshotV1, InventoryStoreErrorV1> {
        self.audit_storage()?;
        validate_key(key)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Deferred)?;
        let snapshot = load_snapshot_transaction(&transaction, key)?
            .ok_or(InventoryStoreErrorV1::SnapshotNotFound)?;
        audit_runtime_state(&transaction)?;
        transaction.commit()?;
        self.audit_storage()?;
        Ok(snapshot)
    }

    /// Load and verify one reservation without granting quote or execution
    /// authority.
    pub fn load_reservation(
        &mut self,
        reservation_id: Digest32,
    ) -> Result<ReservationViewV1, InventoryStoreErrorV1> {
        self.audit_storage()?;
        validate_digest(reservation_id)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Deferred)?;
        let record = load_reservation_transaction(&transaction, reservation_id)?
            .ok_or(InventoryStoreErrorV1::ReservationNotFound)?;
        audit_runtime_state(&transaction)?;
        transaction.commit()?;
        self.audit_storage()?;
        Ok(record.view())
    }

    /// Atomically install a first observation or reconcile a later one under
    /// snapshot CAS. Reorg observations may reduce height/balance but must
    /// carry explicit evidence; existing reservations are never erased and a
    /// resulting deficit blocks new authority.
    pub fn reconcile_snapshot(
        &mut self,
        lease: InventoryLeaseV1,
        expected_revision: u64,
        operation_id: Digest32,
        observation: &InventoryObservationV1,
        now_unix_ms: u64,
    ) -> Result<MutationOutcomeV1, InventoryStoreErrorV1> {
        self.audit_storage()?;
        validate_digest(operation_id)?;
        validate_observation(observation, now_unix_ms)?;
        if observation.key.authority_id != lease.authority_id {
            return Err(InventoryStoreErrorV1::SnapshotMismatch);
        }
        let request_digest = reconcile_request_digest(expected_revision, observation);
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        validate_lease(&transaction, lease, now_unix_ms)?;
        if let Some(outcome) = prior_operation(
            &transaction,
            lease.authority_id,
            operation_id,
            request_digest,
        )? {
            audit_runtime_state(&transaction)?;
            transaction.commit()?;
            self.audit_storage()?;
            return Ok(outcome);
        }

        let current = load_snapshot_transaction(&transaction, observation.key)?;
        let actual_revision = current.map_or(0, |snapshot| snapshot.revision);
        if actual_revision != expected_revision {
            return Err(InventoryStoreErrorV1::RevisionConflict);
        }
        let issued_sequence = current.map_or(0, |snapshot| snapshot.issued_consumption_sequence);
        if observation.acknowledged_consumption_sequence > issued_sequence {
            return Err(InventoryStoreErrorV1::SnapshotMismatch);
        }
        if let Some(previous) = current {
            validate_observation_successor(previous, observation)?;
            let configuration_changed = previous.registry_manifest_digest
                != observation.registry_manifest_digest
                || previous.profile_bundle_digest != observation.profile_bundle_digest
                || previous.asset_binding_digest != observation.asset_binding_digest;
            if configuration_changed && previous.encumbered_amount != 0 {
                return Err(InventoryStoreErrorV1::SnapshotMismatch);
            }
        } else if !matches!(observation.kind, InventoryObservationKindV1::Forward)
            || observation.acknowledged_consumption_sequence != 0
        {
            return Err(InventoryStoreErrorV1::ObservationRegression);
        }

        let revision = expected_revision
            .checked_add(1)
            .ok_or(InventoryStoreErrorV1::InvalidMaterial)?;
        let row_digest = account_row_digest(
            observation,
            revision,
            issued_sequence,
            observation.acknowledged_consumption_sequence,
        );
        if expected_revision == 0 {
            transaction.execute(
                "INSERT INTO inventory_accounts
                 (authority_id, chain_id, asset_id, revision, spendable_amount,
                  canonical_height, canonical_anchor_digest, evidence_digest,
                  registry_manifest_digest, profile_bundle_digest,
                  asset_binding_digest, observed_at_unix_ms,
                  valid_until_unix_ms, issued_consumption_sequence,
                  acknowledged_consumption_sequence, row_digest,
                  updated_at_unix_ms)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10,
                         ?11, ?12, ?13, ?14, ?15, ?16, ?17)",
                params![
                    observation.key.authority_id.0.as_slice(),
                    observation.key.chain_id.0.as_slice(),
                    observation.key.asset_id.0.as_slice(),
                    to_sql_u64(revision)?,
                    u128_blob(observation.spendable_amount).as_slice(),
                    to_sql_u64(observation.canonical_height)?,
                    observation.canonical_anchor_digest.as_slice(),
                    observation.evidence_digest.as_slice(),
                    observation.registry_manifest_digest.as_slice(),
                    observation.profile_bundle_digest.as_slice(),
                    observation.asset_binding_digest.as_slice(),
                    to_sql_u64(observation.observed_at_unix_ms)?,
                    to_sql_u64(observation.valid_until_unix_ms)?,
                    to_sql_u64(issued_sequence)?,
                    to_sql_u64(observation.acknowledged_consumption_sequence)?,
                    row_digest.as_slice(),
                    to_sql_u64(now_unix_ms)?
                ],
            )?;
        } else {
            let changed = transaction.execute(
                "UPDATE inventory_accounts
                 SET revision = ?4, spendable_amount = ?5,
                     canonical_height = ?6, canonical_anchor_digest = ?7,
                     evidence_digest = ?8, registry_manifest_digest = ?9,
                     profile_bundle_digest = ?10, asset_binding_digest = ?11,
                     observed_at_unix_ms = ?12, valid_until_unix_ms = ?13,
                     acknowledged_consumption_sequence = ?14,
                     row_digest = ?15, updated_at_unix_ms = ?16
                 WHERE authority_id = ?1 AND chain_id = ?2 AND asset_id = ?3
                   AND revision = ?17",
                params![
                    observation.key.authority_id.0.as_slice(),
                    observation.key.chain_id.0.as_slice(),
                    observation.key.asset_id.0.as_slice(),
                    to_sql_u64(revision)?,
                    u128_blob(observation.spendable_amount).as_slice(),
                    to_sql_u64(observation.canonical_height)?,
                    observation.canonical_anchor_digest.as_slice(),
                    observation.evidence_digest.as_slice(),
                    observation.registry_manifest_digest.as_slice(),
                    observation.profile_bundle_digest.as_slice(),
                    observation.asset_binding_digest.as_slice(),
                    to_sql_u64(observation.observed_at_unix_ms)?,
                    to_sql_u64(observation.valid_until_unix_ms)?,
                    to_sql_u64(observation.acknowledged_consumption_sequence)?,
                    row_digest.as_slice(),
                    to_sql_u64(now_unix_ms)?,
                    to_sql_u64(expected_revision)?
                ],
            )?;
            if changed != 1 {
                return Err(InventoryStoreErrorV1::RevisionConflict);
            }
        }
        insert_operation(
            &transaction,
            OperationInsertV1 {
                authority_id: lease.authority_id,
                operation_id,
                request_digest,
                result_revision: revision,
                reservation_id: None,
                now_unix_ms,
            },
        )?;
        audit_runtime_state(&transaction)?;
        transaction.commit()?;
        self.audit_storage()?;
        Ok(MutationOutcomeV1 {
            status: MutationStatusV1::Applied,
            revision,
        })
    }

    /// Atomically reserve real settlement output and bond collateral for one
    /// already-signed F6 quote. The quote must not be published before this
    /// method returns successfully.
    pub fn reserve_quote(
        &mut self,
        lease: InventoryLeaseV1,
        operation_id: Digest32,
        quote: &QuoteV1,
        request: &ReserveQuoteRequestV1,
        now_unix_ms: u64,
    ) -> Result<MutationOutcomeV1, InventoryStoreErrorV1> {
        self.audit_storage()?;
        validate_digest(operation_id)?;
        validate_reserve_request(lease, quote, request, now_unix_ms)?;
        let request_digest = reserve_request_digest(quote, request)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        validate_lease(&transaction, lease, now_unix_ms)?;
        if let Some(outcome) = prior_operation(
            &transaction,
            lease.authority_id,
            operation_id,
            request_digest,
        )? {
            audit_runtime_state(&transaction)?;
            transaction.commit()?;
            self.audit_storage()?;
            return Ok(outcome);
        }
        if load_reservation_transaction(&transaction, request.reservation_id)?.is_some() {
            return Err(InventoryStoreErrorV1::ReservationAlreadyExists);
        }

        let mut requested_by_key = BTreeMap::<InventoryKeyV1, u128>::new();
        for allocation in &request.allocations {
            let snapshot = load_snapshot_transaction(&transaction, allocation.snapshot.key)?
                .ok_or(InventoryStoreErrorV1::SnapshotNotFound)?;
            validate_allocation_snapshot(snapshot, allocation, request, now_unix_ms)?;
            let total = requested_by_key.entry(allocation.snapshot.key).or_insert(0);
            *total = total
                .checked_add(allocation.amount)
                .ok_or(InventoryStoreErrorV1::InvalidMaterial)?;
        }
        for (key, requested) in requested_by_key {
            let snapshot = load_snapshot_transaction(&transaction, key)?
                .ok_or(InventoryStoreErrorV1::SnapshotNotFound)?;
            let after = snapshot
                .encumbered_amount
                .checked_add(requested)
                .ok_or(InventoryStoreErrorV1::InvalidMaterial)?;
            if after > snapshot.spendable_amount {
                return Err(InventoryStoreErrorV1::CapacityAlreadyReserved);
            }
        }

        let allocations = request
            .allocations
            .iter()
            .map(|allocation| AllocationRecord {
                capability: InventoryAllocationCapabilityV1 {
                    key: allocation.snapshot.key,
                    purpose: allocation.purpose,
                    amount: allocation.amount,
                    reserved_snapshot: allocation.snapshot,
                },
                consumption_sequence: None,
            })
            .collect::<Vec<_>>();
        let mut record = ReservationRecord {
            reservation_id: request.reservation_id,
            authority_id: lease.authority_id,
            route_id: request.route_id,
            scope_v2: None,
            rfq_id: quote.rfq_id,
            quote_id: quote.quote_id,
            quote_bytes: quote
                .canonical_bytes()
                .map_err(|_| InventoryStoreErrorV1::F6BindingMismatch)?,
            terms_context_digest: request.terms_context_digest,
            registry_manifest_digest: request.registry_manifest_digest,
            profile_bundle_digest: request.profile_bundle_digest,
            bond_policy_hash: request.bond_policy.policy_hash,
            bond_policy_version: request.bond_policy.policy_version,
            bond_key: request.bond_policy.bond_key,
            bond_asset_binding_digest: request.bond_policy.bond_asset_binding_digest,
            required_bond_amount: request.bond_policy.required_collateral,
            expires_at_unix_ms: request.expires_at_unix_ms,
            state: ReservationStateV1::Reserved,
            revision: 1,
            creation_fencing_epoch: lease.fencing_epoch,
            accepted_terms_digest: None,
            binding_evidence_digest: None,
            execution_fencing_epoch: None,
            reauthorization_evidence_digest: None,
            release_evidence_digest: None,
            execution_id: None,
            execution_evidence_digest: None,
            execution_finalized_height: None,
            reservation_digest: [0; 32],
            allocations,
        };
        record.reservation_digest = reservation_digest(&record);
        insert_reservation(&transaction, &record, now_unix_ms)?;
        insert_operation(
            &transaction,
            OperationInsertV1 {
                authority_id: lease.authority_id,
                operation_id,
                request_digest,
                result_revision: 1,
                reservation_id: Some(request.reservation_id),
                now_unix_ms,
            },
        )?;
        audit_runtime_state(&transaction)?;
        transaction.commit()?;
        self.audit_storage()?;
        Ok(MutationOutcomeV1 {
            status: MutationStatusV1::Applied,
            revision: 1,
        })
    }

    /// Atomically reserves real capacity for one authenticated V2 quote. The
    /// composition scope is persisted in the same transaction as the quote
    /// and allocations.
    pub fn reserve_quote_v2(
        &mut self,
        lease: InventoryLeaseV1,
        operation_id: Digest32,
        quote: &QuoteV2,
        request: &ReserveQuoteRequestV2,
        now_unix_ms: u64,
    ) -> Result<MutationOutcomeV1, InventoryStoreErrorV1> {
        self.audit_storage()?;
        validate_digest(operation_id)?;
        validate_reserve_request_v2(lease, quote, request, now_unix_ms)?;
        let base = &request.base;
        let request_digest = reserve_request_digest_v2(quote, request)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        validate_lease(&transaction, lease, now_unix_ms)?;
        if let Some(outcome) = prior_operation(
            &transaction,
            lease.authority_id,
            operation_id,
            request_digest,
        )? {
            audit_runtime_state(&transaction)?;
            transaction.commit()?;
            self.audit_storage()?;
            return Ok(outcome);
        }
        if load_reservation_transaction(&transaction, base.reservation_id)?.is_some() {
            return Err(InventoryStoreErrorV1::ReservationAlreadyExists);
        }

        let mut requested_by_key = BTreeMap::<InventoryKeyV1, u128>::new();
        for allocation in &base.allocations {
            let snapshot = load_snapshot_transaction(&transaction, allocation.snapshot.key)?
                .ok_or(InventoryStoreErrorV1::SnapshotNotFound)?;
            validate_allocation_snapshot(snapshot, allocation, base, now_unix_ms)?;
            let total = requested_by_key.entry(allocation.snapshot.key).or_insert(0);
            *total = total
                .checked_add(allocation.amount)
                .ok_or(InventoryStoreErrorV1::InvalidMaterial)?;
        }
        for (key, requested) in requested_by_key {
            let snapshot = load_snapshot_transaction(&transaction, key)?
                .ok_or(InventoryStoreErrorV1::SnapshotNotFound)?;
            let after = snapshot
                .encumbered_amount
                .checked_add(requested)
                .ok_or(InventoryStoreErrorV1::InvalidMaterial)?;
            if after > snapshot.spendable_amount {
                return Err(InventoryStoreErrorV1::CapacityAlreadyReserved);
            }
        }

        let allocations = base
            .allocations
            .iter()
            .map(|allocation| AllocationRecord {
                capability: InventoryAllocationCapabilityV1 {
                    key: allocation.snapshot.key,
                    purpose: allocation.purpose,
                    amount: allocation.amount,
                    reserved_snapshot: allocation.snapshot,
                },
                consumption_sequence: None,
            })
            .collect::<Vec<_>>();
        let mut record = ReservationRecord {
            reservation_id: base.reservation_id,
            authority_id: lease.authority_id,
            route_id: base.route_id,
            scope_v2: Some(ReservationScopeV2 {
                composition_id: request.composition_id,
                position: request.position,
            }),
            rfq_id: quote.rfq_id,
            quote_id: quote.quote_id,
            quote_bytes: quote
                .canonical_bytes()
                .map_err(|_| InventoryStoreErrorV1::F6BindingMismatch)?,
            terms_context_digest: base.terms_context_digest,
            registry_manifest_digest: base.registry_manifest_digest,
            profile_bundle_digest: base.profile_bundle_digest,
            bond_policy_hash: base.bond_policy.policy_hash,
            bond_policy_version: base.bond_policy.policy_version,
            bond_key: base.bond_policy.bond_key,
            bond_asset_binding_digest: base.bond_policy.bond_asset_binding_digest,
            required_bond_amount: base.bond_policy.required_collateral,
            expires_at_unix_ms: base.expires_at_unix_ms,
            state: ReservationStateV1::Reserved,
            revision: 1,
            creation_fencing_epoch: lease.fencing_epoch,
            accepted_terms_digest: None,
            binding_evidence_digest: None,
            execution_fencing_epoch: None,
            reauthorization_evidence_digest: None,
            release_evidence_digest: None,
            execution_id: None,
            execution_evidence_digest: None,
            execution_finalized_height: None,
            reservation_digest: [0; 32],
            allocations,
        };
        record.reservation_digest = reservation_digest(&record);
        insert_reservation(&transaction, &record, now_unix_ms)?;
        insert_operation(
            &transaction,
            OperationInsertV1 {
                authority_id: lease.authority_id,
                operation_id,
                request_digest,
                result_revision: 1,
                reservation_id: Some(base.reservation_id),
                now_unix_ms,
            },
        )?;
        audit_runtime_state(&transaction)?;
        transaction.commit()?;
        self.audit_storage()?;
        Ok(MutationOutcomeV1 {
            status: MutationStatusV1::Applied,
            revision: 1,
        })
    }

    /// Recover a live quote capability after cross-checking the current
    /// snapshots, solvency, expiry, registry/profile bindings and lease.
    pub fn quote_capability(
        &mut self,
        lease: InventoryLeaseV1,
        reservation_id: Digest32,
        now_unix_ms: u64,
    ) -> Result<QuoteInventoryCapabilityV1, InventoryStoreErrorV1> {
        self.audit_storage()?;
        validate_digest(reservation_id)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Deferred)?;
        validate_lease(&transaction, lease, now_unix_ms)?;
        let record = load_reservation_transaction(&transaction, reservation_id)?
            .ok_or(InventoryStoreErrorV1::ReservationNotFound)?;
        if record.authority_id != lease.authority_id {
            return Err(InventoryStoreErrorV1::ReservationNotFound);
        }
        if record.state != ReservationStateV1::Reserved {
            return Err(InventoryStoreErrorV1::InvalidReservationState);
        }
        if now_unix_ms > record.expires_at_unix_ms {
            return Err(InventoryStoreErrorV1::ReservationExpired);
        }
        validate_live_capacity(&transaction, &record, now_unix_ms)?;
        let capability = record.quote_capability()?;
        audit_runtime_state(&transaction)?;
        transaction.commit()?;
        self.audit_storage()?;
        Ok(capability)
    }

    /// Recovers a move-only V2 capability after exact scope and live-capacity
    /// validation. A V1 reservation cannot be upgraded through this API.
    pub fn quote_capability_v2(
        &mut self,
        lease: InventoryLeaseV1,
        reservation_id: Digest32,
        now_unix_ms: u64,
    ) -> Result<QuoteInventoryCapabilityV2, InventoryStoreErrorV1> {
        self.audit_storage()?;
        validate_digest(reservation_id)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Deferred)?;
        validate_lease(&transaction, lease, now_unix_ms)?;
        let record = load_reservation_transaction(&transaction, reservation_id)?
            .ok_or(InventoryStoreErrorV1::ReservationNotFound)?;
        if record.authority_id != lease.authority_id {
            return Err(InventoryStoreErrorV1::ReservationNotFound);
        }
        if record.state != ReservationStateV1::Reserved {
            return Err(InventoryStoreErrorV1::InvalidReservationState);
        }
        if now_unix_ms > record.expires_at_unix_ms {
            return Err(InventoryStoreErrorV1::ReservationExpired);
        }
        validate_live_capacity(&transaction, &record, now_unix_ms)?;
        let capability = record.quote_capability_v2()?;
        audit_runtime_state(&transaction)?;
        transaction.commit()?;
        self.audit_storage()?;
        Ok(capability)
    }

    /// Commit a selected reservation from the existing replayed F6 journal.
    /// Its bound RFQ, quote, solver and reservation must all equal the
    /// inventory record; a free caller-supplied terms hash is intentionally
    /// not accepted.
    pub fn commit_from_f6<L: BindingLog>(
        &mut self,
        lease: InventoryLeaseV1,
        context: InventoryMutationContextV1,
        reservation_id: Digest32,
        f6: &DurableBinding<L>,
        binding_evidence_digest: Digest32,
    ) -> Result<MutationOutcomeV1, InventoryStoreErrorV1> {
        self.audit_storage()?;
        validate_digest(context.operation_id)?;
        validate_digest(reservation_id)?;
        validate_digest(binding_evidence_digest)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        validate_lease(&transaction, lease, context.now_unix_ms)?;
        let mut record = load_owned_reservation(&transaction, lease, reservation_id)?;
        let bound = f6
            .ledger()
            .binding(&record.rfq_id)
            .ok_or(InventoryStoreErrorV1::F6BindingMismatch)?;
        if bound.quote_id != record.quote_id
            || bound.solver != record.authority_id
            || bound.reservation_id != record.reservation_id
        {
            return Err(InventoryStoreErrorV1::F6BindingMismatch);
        }
        let accepted = accepted_negotiation(f6, &record.rfq_id)
            .map_err(|_| InventoryStoreErrorV1::F6BindingMismatch)?;
        let accepted_terms_digest = accepted.accepted_terms_hash();
        validate_digest(accepted_terms_digest)?;
        if accepted.rfq_id() != record.rfq_id || accepted_terms_digest != bound.terms_hash {
            return Err(InventoryStoreErrorV1::F6BindingMismatch);
        }
        let request_digest = transition_request_digest(
            b"COMMIT",
            reservation_id,
            context.expected_revision,
            &[
                record.rfq_id,
                record.quote_id,
                record.authority_id.0,
                accepted_terms_digest,
                binding_evidence_digest,
            ],
            None,
        );
        if let Some(outcome) = prior_operation(
            &transaction,
            lease.authority_id,
            context.operation_id,
            request_digest,
        )? {
            audit_runtime_state(&transaction)?;
            transaction.commit()?;
            self.audit_storage()?;
            return Ok(outcome);
        }
        require_reservation_revision(&record, context.expected_revision)?;
        if record.state != ReservationStateV1::Reserved {
            return Err(InventoryStoreErrorV1::InvalidReservationState);
        }
        if context.now_unix_ms > record.expires_at_unix_ms {
            return Err(InventoryStoreErrorV1::ReservationExpired);
        }
        validate_live_capacity(&transaction, &record, context.now_unix_ms)?;
        record.state = ReservationStateV1::Committed;
        record.accepted_terms_digest = Some(accepted_terms_digest);
        record.binding_evidence_digest = Some(binding_evidence_digest);
        record.execution_fencing_epoch = Some(lease.fencing_epoch);
        record.revision = next_revision(record.revision)?;
        record.reservation_digest = reservation_digest(&record);
        update_reservation(
            &transaction,
            &record,
            context.expected_revision,
            context.now_unix_ms,
        )?;
        insert_operation(
            &transaction,
            OperationInsertV1 {
                authority_id: lease.authority_id,
                operation_id: context.operation_id,
                request_digest,
                result_revision: record.revision,
                reservation_id: Some(reservation_id),
                now_unix_ms: context.now_unix_ms,
            },
        )?;
        audit_runtime_state(&transaction)?;
        transaction.commit()?;
        self.audit_storage()?;
        Ok(MutationOutcomeV1 {
            status: MutationStatusV1::Applied,
            revision: record.revision,
        })
    }

    /// Commits a V2 reservation only from a sealed replayed binding authority.
    /// Composition, position, RFQ, quote, solver, reservation and terms are
    /// read from durable authorities and must all match the inventory row.
    pub fn commit_from_f6_v2<A: AcceptedBindingAuthorityV2>(
        &mut self,
        lease: InventoryLeaseV1,
        context: InventoryMutationContextV1,
        reservation_id: Digest32,
        f6: &A,
    ) -> Result<MutationOutcomeV1, InventoryStoreErrorV1> {
        self.audit_storage()?;
        validate_digest(context.operation_id)?;
        validate_digest(reservation_id)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        validate_lease(&transaction, lease, context.now_unix_ms)?;
        let mut record = load_owned_reservation(&transaction, lease, reservation_id)?;
        let scope = record
            .scope_v2
            .ok_or(InventoryStoreErrorV1::F6BindingMismatch)?;
        let bound = f6
            .accepted_binding_v2(scope.composition_id, scope.position, record.rfq_id)
            .ok_or(InventoryStoreErrorV1::F6BindingMismatch)?;
        if bound.composition_id() != scope.composition_id
            || bound.position() != scope.position
            || bound.rfq_id() != record.rfq_id
            || bound.quote_id() != record.quote_id
            || bound.solver() != record.authority_id
            || bound.reservation_id() != record.reservation_id
        {
            return Err(InventoryStoreErrorV1::F6BindingMismatch);
        }
        let accepted_terms_digest = bound.terms_hash();
        validate_digest(accepted_terms_digest)?;
        let binding_evidence_digest = binding_evidence_digest_v2(bound);
        let request_digest = commit_v2_request_digest(
            &record,
            scope,
            context.expected_revision,
            accepted_terms_digest,
            binding_evidence_digest,
        );
        if let Some(outcome) = prior_operation(
            &transaction,
            lease.authority_id,
            context.operation_id,
            request_digest,
        )? {
            audit_runtime_state(&transaction)?;
            transaction.commit()?;
            self.audit_storage()?;
            return Ok(outcome);
        }
        require_reservation_revision(&record, context.expected_revision)?;
        if record.state != ReservationStateV1::Reserved {
            return Err(InventoryStoreErrorV1::InvalidReservationState);
        }
        if context.now_unix_ms > record.expires_at_unix_ms {
            return Err(InventoryStoreErrorV1::ReservationExpired);
        }
        validate_live_capacity(&transaction, &record, context.now_unix_ms)?;
        record.state = ReservationStateV1::Committed;
        record.accepted_terms_digest = Some(accepted_terms_digest);
        record.binding_evidence_digest = Some(binding_evidence_digest);
        record.execution_fencing_epoch = Some(lease.fencing_epoch);
        record.revision = next_revision(record.revision)?;
        record.reservation_digest = reservation_digest(&record);
        update_reservation(
            &transaction,
            &record,
            context.expected_revision,
            context.now_unix_ms,
        )?;
        insert_operation(
            &transaction,
            OperationInsertV1 {
                authority_id: lease.authority_id,
                operation_id: context.operation_id,
                request_digest,
                result_revision: record.revision,
                reservation_id: Some(reservation_id),
                now_unix_ms: context.now_unix_ms,
            },
        )?;
        audit_runtime_state(&transaction)?;
        transaction.commit()?;
        self.audit_storage()?;
        Ok(MutationOutcomeV1 {
            status: MutationStatusV1::Applied,
            revision: record.revision,
        })
    }

    /// Recover execution authority for a committed reservation. A takeover
    /// must first call [`Self::reauthorize_committed`] with external
    /// non-execution evidence; old fencing generations are never returned.
    pub fn committed_capability(
        &mut self,
        lease: InventoryLeaseV1,
        reservation_id: Digest32,
        now_unix_ms: u64,
    ) -> Result<CommittedInventoryCapabilityV1, InventoryStoreErrorV1> {
        self.audit_storage()?;
        validate_digest(reservation_id)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Deferred)?;
        validate_lease(&transaction, lease, now_unix_ms)?;
        let record = load_owned_reservation(&transaction, lease, reservation_id)?;
        if record.state != ReservationStateV1::Committed {
            return Err(InventoryStoreErrorV1::InvalidReservationState);
        }
        if record.execution_fencing_epoch != Some(lease.fencing_epoch) {
            return Err(InventoryStoreErrorV1::ReauthorizationRequired);
        }
        validate_live_capacity(&transaction, &record, now_unix_ms)?;
        let capability = record.committed_capability()?;
        audit_runtime_state(&transaction)?;
        transaction.commit()?;
        self.audit_storage()?;
        Ok(capability)
    }

    /// Recovers a move-only committed V2 execution authority. V1 records and
    /// stale fencing generations are refused.
    pub fn committed_capability_v2(
        &mut self,
        lease: InventoryLeaseV1,
        reservation_id: Digest32,
        now_unix_ms: u64,
    ) -> Result<CommittedInventoryCapabilityV2, InventoryStoreErrorV1> {
        self.audit_storage()?;
        validate_digest(reservation_id)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Deferred)?;
        validate_lease(&transaction, lease, now_unix_ms)?;
        let record = load_owned_reservation(&transaction, lease, reservation_id)?;
        if record.state != ReservationStateV1::Committed {
            return Err(InventoryStoreErrorV1::InvalidReservationState);
        }
        if record.execution_fencing_epoch != Some(lease.fencing_epoch) {
            return Err(InventoryStoreErrorV1::ReauthorizationRequired);
        }
        validate_live_capacity(&transaction, &record, now_unix_ms)?;
        let capability = record.committed_capability_v2()?;
        audit_runtime_state(&transaction)?;
        transaction.commit()?;
        self.audit_storage()?;
        Ok(capability)
    }

    /// Re-fence a committed capability after an actuator reconciliation proved
    /// that the older generation did not execute it.
    pub fn reauthorize_committed(
        &mut self,
        lease: InventoryLeaseV1,
        expected_revision: u64,
        operation_id: Digest32,
        reservation_id: Digest32,
        non_execution_evidence_digest: Digest32,
        now_unix_ms: u64,
    ) -> Result<MutationOutcomeV1, InventoryStoreErrorV1> {
        self.audit_storage()?;
        validate_digest(operation_id)?;
        validate_digest(reservation_id)?;
        validate_digest(non_execution_evidence_digest)?;
        let request_digest = transition_request_digest(
            b"REFENCE",
            reservation_id,
            expected_revision,
            &[non_execution_evidence_digest],
            Some(lease.fencing_epoch),
        );
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        validate_lease(&transaction, lease, now_unix_ms)?;
        if let Some(outcome) = prior_operation(
            &transaction,
            lease.authority_id,
            operation_id,
            request_digest,
        )? {
            audit_runtime_state(&transaction)?;
            transaction.commit()?;
            self.audit_storage()?;
            return Ok(outcome);
        }
        let mut record = load_owned_reservation(&transaction, lease, reservation_id)?;
        require_reservation_revision(&record, expected_revision)?;
        if record.state != ReservationStateV1::Committed {
            return Err(InventoryStoreErrorV1::InvalidReservationState);
        }
        let previous_epoch = record
            .execution_fencing_epoch
            .ok_or(InventoryStoreErrorV1::CorruptState)?;
        if previous_epoch >= lease.fencing_epoch {
            return Err(InventoryStoreErrorV1::StaleFencing);
        }
        validate_live_capacity(&transaction, &record, now_unix_ms)?;
        record.execution_fencing_epoch = Some(lease.fencing_epoch);
        record.reauthorization_evidence_digest = Some(non_execution_evidence_digest);
        record.revision = next_revision(record.revision)?;
        record.reservation_digest = reservation_digest(&record);
        update_reservation(&transaction, &record, expected_revision, now_unix_ms)?;
        insert_operation(
            &transaction,
            OperationInsertV1 {
                authority_id: lease.authority_id,
                operation_id,
                request_digest,
                result_revision: record.revision,
                reservation_id: Some(reservation_id),
                now_unix_ms,
            },
        )?;
        audit_runtime_state(&transaction)?;
        transaction.commit()?;
        self.audit_storage()?;
        Ok(MutationOutcomeV1 {
            status: MutationStatusV1::Applied,
            revision: record.revision,
        })
    }

    /// Explicitly release a reserved or committed allocation using a public
    /// reconciliation/terminal evidence commitment. A committed allocation
    /// from an older fence must first be reconciled and reauthorized;
    /// reservation ids remain spent forever.
    pub fn release_reservation(
        &mut self,
        lease: InventoryLeaseV1,
        expected_revision: u64,
        operation_id: Digest32,
        reservation_id: Digest32,
        release_evidence_digest: Digest32,
        now_unix_ms: u64,
    ) -> Result<MutationOutcomeV1, InventoryStoreErrorV1> {
        self.audit_storage()?;
        validate_digest(operation_id)?;
        validate_digest(reservation_id)?;
        validate_digest(release_evidence_digest)?;
        let request_digest = transition_request_digest(
            b"RELEASE",
            reservation_id,
            expected_revision,
            &[release_evidence_digest],
            None,
        );
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        validate_lease(&transaction, lease, now_unix_ms)?;
        if let Some(outcome) = prior_operation(
            &transaction,
            lease.authority_id,
            operation_id,
            request_digest,
        )? {
            audit_runtime_state(&transaction)?;
            transaction.commit()?;
            self.audit_storage()?;
            return Ok(outcome);
        }
        let mut record = load_owned_reservation(&transaction, lease, reservation_id)?;
        require_reservation_revision(&record, expected_revision)?;
        if !matches!(
            record.state,
            ReservationStateV1::Reserved | ReservationStateV1::Committed
        ) {
            return Err(InventoryStoreErrorV1::InvalidReservationState);
        }
        if record.state == ReservationStateV1::Committed
            && record.execution_fencing_epoch != Some(lease.fencing_epoch)
        {
            return Err(InventoryStoreErrorV1::ReauthorizationRequired);
        }
        record.state = ReservationStateV1::Released;
        record.release_evidence_digest = Some(release_evidence_digest);
        record.revision = next_revision(record.revision)?;
        record.reservation_digest = reservation_digest(&record);
        update_reservation(&transaction, &record, expected_revision, now_unix_ms)?;
        insert_operation(
            &transaction,
            OperationInsertV1 {
                authority_id: lease.authority_id,
                operation_id,
                request_digest,
                result_revision: record.revision,
                reservation_id: Some(reservation_id),
                now_unix_ms,
            },
        )?;
        audit_runtime_state(&transaction)?;
        transaction.commit()?;
        self.audit_storage()?;
        Ok(MutationOutcomeV1 {
            status: MutationStatusV1::Applied,
            revision: record.revision,
        })
    }

    /// Release an unselected reservation only after its durable local expiry.
    pub fn expire_reservation(
        &mut self,
        lease: InventoryLeaseV1,
        expected_revision: u64,
        operation_id: Digest32,
        reservation_id: Digest32,
        now_unix_ms: u64,
    ) -> Result<MutationOutcomeV1, InventoryStoreErrorV1> {
        self.audit_storage()?;
        validate_digest(operation_id)?;
        validate_digest(reservation_id)?;
        let request_digest =
            transition_request_digest(b"EXPIRE", reservation_id, expected_revision, &[], None);
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        validate_lease(&transaction, lease, now_unix_ms)?;
        if let Some(outcome) = prior_operation(
            &transaction,
            lease.authority_id,
            operation_id,
            request_digest,
        )? {
            audit_runtime_state(&transaction)?;
            transaction.commit()?;
            self.audit_storage()?;
            return Ok(outcome);
        }
        let mut record = load_owned_reservation(&transaction, lease, reservation_id)?;
        require_reservation_revision(&record, expected_revision)?;
        if record.state != ReservationStateV1::Reserved {
            return Err(InventoryStoreErrorV1::InvalidReservationState);
        }
        if now_unix_ms <= record.expires_at_unix_ms {
            return Err(InventoryStoreErrorV1::ReservationNotExpired);
        }
        record.state = ReservationStateV1::Released;
        record.revision = next_revision(record.revision)?;
        record.reservation_digest = reservation_digest(&record);
        update_reservation(&transaction, &record, expected_revision, now_unix_ms)?;
        insert_operation(
            &transaction,
            OperationInsertV1 {
                authority_id: lease.authority_id,
                operation_id,
                request_digest,
                result_revision: record.revision,
                reservation_id: Some(reservation_id),
                now_unix_ms,
            },
        )?;
        audit_runtime_state(&transaction)?;
        transaction.commit()?;
        self.audit_storage()?;
        Ok(MutationOutcomeV1 {
            status: MutationStatusV1::Applied,
            revision: record.revision,
        })
    }

    /// Record finalized actuator execution and assign per-account consumption
    /// sequences atomically. Capacity remains encumbered until a later
    /// observer snapshot explicitly acknowledges those sequences.
    pub fn consume_reservation(
        &mut self,
        lease: InventoryLeaseV1,
        expected_revision: u64,
        operation_id: Digest32,
        execution: &InventoryExecutionV1,
        now_unix_ms: u64,
    ) -> Result<MutationOutcomeV1, InventoryStoreErrorV1> {
        self.audit_storage()?;
        validate_execution(execution)?;
        validate_digest(operation_id)?;
        let request_digest = consume_request_digest(expected_revision, execution);
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        validate_lease(&transaction, lease, now_unix_ms)?;
        if let Some(outcome) = prior_operation(
            &transaction,
            lease.authority_id,
            operation_id,
            request_digest,
        )? {
            audit_runtime_state(&transaction)?;
            transaction.commit()?;
            self.audit_storage()?;
            return Ok(outcome);
        }
        let mut record = load_owned_reservation(&transaction, lease, execution.reservation_id)?;
        require_reservation_revision(&record, expected_revision)?;
        if record.state != ReservationStateV1::Committed {
            return Err(InventoryStoreErrorV1::InvalidReservationState);
        }
        if record.execution_fencing_epoch != Some(lease.fencing_epoch)
            || execution.execution_fencing_epoch != lease.fencing_epoch
        {
            return Err(InventoryStoreErrorV1::StaleFencing);
        }

        let keys = record
            .allocations
            .iter()
            .map(|allocation| allocation.capability.key)
            .collect::<BTreeSet<_>>();
        let mut sequences = BTreeMap::new();
        for key in keys {
            let snapshot = load_snapshot_transaction(&transaction, key)?
                .ok_or(InventoryStoreErrorV1::SnapshotNotFound)?;
            let next_sequence = snapshot
                .issued_consumption_sequence
                .checked_add(1)
                .ok_or(InventoryStoreErrorV1::InvalidMaterial)?;
            update_issued_consumption_sequence(&transaction, snapshot, next_sequence, now_unix_ms)?;
            sequences.insert(key, next_sequence);
        }
        for allocation in &mut record.allocations {
            allocation.consumption_sequence = sequences.get(&allocation.capability.key).copied();
        }
        update_allocation_consumption_sequences(&transaction, &record)?;
        record.state = ReservationStateV1::Consumed;
        record.execution_id = Some(execution.execution_id);
        record.execution_evidence_digest = Some(execution.evidence_digest);
        record.execution_finalized_height = Some(execution.finalized_height);
        record.revision = next_revision(record.revision)?;
        record.reservation_digest = reservation_digest(&record);
        update_reservation(&transaction, &record, expected_revision, now_unix_ms)?;
        insert_operation(
            &transaction,
            OperationInsertV1 {
                authority_id: lease.authority_id,
                operation_id,
                request_digest,
                result_revision: record.revision,
                reservation_id: Some(record.reservation_id),
                now_unix_ms,
            },
        )?;
        audit_runtime_state(&transaction)?;
        transaction.commit()?;
        self.audit_storage()?;
        Ok(MutationOutcomeV1 {
            status: MutationStatusV1::Applied,
            revision: record.revision,
        })
    }

    /// List finalized consumptions not yet reflected by an observer snapshot.
    /// These public commitments are the only execution material exposed to an
    /// inventory observer.
    pub fn pending_consumptions(
        &mut self,
        lease: InventoryLeaseV1,
        key: InventoryKeyV1,
        now_unix_ms: u64,
    ) -> Result<Vec<PendingConsumptionV1>, InventoryStoreErrorV1> {
        self.audit_storage()?;
        validate_key(key)?;
        if key.authority_id != lease.authority_id {
            return Err(InventoryStoreErrorV1::SnapshotMismatch);
        }
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Deferred)?;
        validate_lease(&transaction, lease, now_unix_ms)?;
        let snapshot = load_snapshot_transaction(&transaction, key)?
            .ok_or(InventoryStoreErrorV1::SnapshotNotFound)?;
        let mut statement = transaction.prepare(
            "SELECT r.reservation_id, r.execution_id,
                    r.execution_evidence_digest, a.amount,
                    a.consumption_sequence
             FROM inventory_allocations a
             JOIN inventory_reservations r
               ON r.reservation_id = a.reservation_id
             WHERE a.authority_id = ?1 AND a.chain_id = ?2 AND a.asset_id = ?3
               AND r.state_tag = ?4
               AND a.consumption_sequence > ?5
             ORDER BY a.consumption_sequence ASC, r.reservation_id ASC,
                      a.position ASC
             LIMIT ?6",
        )?;
        let rows = statement.query_map(
            params![
                key.authority_id.0.as_slice(),
                key.chain_id.0.as_slice(),
                key.asset_id.0.as_slice(),
                STATE_CONSUMED,
                to_sql_u64(snapshot.acknowledged_consumption_sequence)?,
                i64::try_from(MAX_PENDING_CONSUMPTIONS + 1)
                    .map_err(|_| InventoryStoreErrorV1::InvalidMaterial)?
            ],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, Vec<u8>>(3)?,
                    row.get::<_, i64>(4)?,
                ))
            },
        )?;
        let raw = rows.collect::<Result<Vec<_>, _>>()?;
        if raw.len() > MAX_PENDING_CONSUMPTIONS {
            return Err(InventoryStoreErrorV1::CorruptState);
        }
        let mut grouped = BTreeMap::<(Digest32, Digest32, Digest32, u64), u128>::new();
        for (reservation, execution, evidence, amount, sequence) in raw {
            let group = (
                blob32(reservation)?,
                blob32(execution)?,
                blob32(evidence)?,
                from_sql_u64(sequence)?,
            );
            let total = grouped.entry(group).or_insert(0);
            *total = total
                .checked_add(blob_u128(amount)?)
                .ok_or(InventoryStoreErrorV1::CorruptState)?;
        }
        let pending = grouped
            .into_iter()
            .map(
                |((reservation_id, execution_id, execution_evidence_digest, sequence), amount)| {
                    PendingConsumptionV1 {
                        key,
                        reservation_id,
                        execution_id,
                        execution_evidence_digest,
                        amount,
                        consumption_sequence: sequence,
                    }
                },
            )
            .collect();
        drop(statement);
        audit_runtime_state(&transaction)?;
        transaction.commit()?;
        self.audit_storage()?;
        Ok(pending)
    }

    /// Verify every account, reservation, allocation commitment and foreign
    /// key relationship currently retained by the store.
    pub fn verify_integrity(&mut self) -> Result<(), InventoryStoreErrorV1> {
        self.audit_storage()
    }

    fn audit_storage(&self) -> Result<(), InventoryStoreErrorV1> {
        audit_connection_config(&self.connection, "wal")?;
        audit_schema(&self.connection, self.binding_digest)?;
        audit_runtime_state(&self.connection)?;
        #[cfg(target_os = "linux")]
        {
            validate_parent(&self.path)?;
            validate_retained_file(
                &self.path,
                &self.authority_file,
                self.authority_identity,
                false,
            )?;
            validate_retained_file(&self.lock_path, &self.lock_file, self.lock_identity, true)?;
            validate_sidecars_for_mode(&self.path, AuthorityOpenModeV1::OpenExisting)?;
        }
        Ok(())
    }
}

fn binding_evidence_digest_v2(binding: AcceptedBindingViewV2) -> Digest32 {
    let mut writer = CommitmentWriter::new(b"DOM-INTEROP/F6-ACCEPTED-BINDING-EVIDENCE/V2");
    writer.digest(binding.composition_id());
    writer.u8(binding.position() as u8);
    writer.digest(binding.rfq_id());
    writer.digest(binding.quote_id());
    writer.digest(binding.solver().0);
    writer.digest(binding.accepted_by().0);
    writer.digest(binding.reservation_id());
    writer.digest(binding.terms_hash());
    writer.finish()
}

fn audit_runtime_state(connection: &Connection) -> Result<(), InventoryStoreErrorV1> {
    const MAX_ECONOMIC_ROWS: i64 = 1_000_000;
    let economic_rows: i64 = connection.query_row(
        "SELECT
           (SELECT COUNT(*) FROM inventory_leases) +
           (SELECT COUNT(*) FROM inventory_accounts) +
           (SELECT COUNT(*) FROM inventory_reservations) +
           (SELECT COUNT(*) FROM inventory_reservation_scopes_v2) +
           (SELECT COUNT(*) FROM inventory_allocations) +
           (SELECT COUNT(*) FROM inventory_operations)",
        [],
        |row| row.get(0),
    )?;
    if !(0..=MAX_ECONOMIC_ROWS).contains(&economic_rows) {
        return Err(InventoryStoreErrorV1::CorruptState);
    }
    {
        let keys = {
            let mut statement = connection.prepare(
                "SELECT authority_id, chain_id, asset_id
                 FROM inventory_accounts
                 ORDER BY authority_id, chain_id, asset_id",
            )?;
            let rows = statement.query_map([], |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                ))
            })?;
            rows.collect::<Result<Vec<_>, _>>()?
        };
        for (authority, chain, asset) in keys {
            let key = InventoryKeyV1 {
                authority_id: ParticipantId(blob32(authority)?),
                chain_id: ChainId(blob32(chain)?),
                asset_id: AssetId(blob32(asset)?),
            };
            load_snapshot_transaction(connection, key)?
                .ok_or(InventoryStoreErrorV1::CorruptState)?;
        }
        let reservations = {
            let mut statement = connection.prepare(
                "SELECT reservation_id FROM inventory_reservations
                 ORDER BY reservation_id",
            )?;
            let rows = statement.query_map([], |row| row.get::<_, Vec<u8>>(0))?;
            rows.collect::<Result<Vec<_>, _>>()?
        };
        for reservation in reservations {
            load_reservation_transaction(connection, blob32(reservation)?)?
                .ok_or(InventoryStoreErrorV1::CorruptState)?;
        }
        let foreign_keys: String = connection
            .query_row("PRAGMA foreign_key_check", [], |row| {
                row.get::<_, String>(0)
            })
            .optional()?
            .unwrap_or_default();
        if !foreign_keys.is_empty() {
            return Err(InventoryStoreErrorV1::CorruptState);
        }
    }
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct AllocationRecord {
    capability: InventoryAllocationCapabilityV1,
    consumption_sequence: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ReservationRecord {
    reservation_id: Digest32,
    authority_id: ParticipantId,
    route_id: Digest32,
    scope_v2: Option<ReservationScopeV2>,
    rfq_id: Digest32,
    quote_id: Digest32,
    quote_bytes: Vec<u8>,
    terms_context_digest: Digest32,
    registry_manifest_digest: Digest32,
    profile_bundle_digest: Digest32,
    bond_policy_hash: Digest32,
    bond_policy_version: u32,
    bond_key: InventoryKeyV1,
    bond_asset_binding_digest: Digest32,
    required_bond_amount: u128,
    expires_at_unix_ms: u64,
    state: ReservationStateV1,
    revision: u64,
    creation_fencing_epoch: u64,
    accepted_terms_digest: Option<Digest32>,
    binding_evidence_digest: Option<Digest32>,
    execution_fencing_epoch: Option<u64>,
    reauthorization_evidence_digest: Option<Digest32>,
    release_evidence_digest: Option<Digest32>,
    execution_id: Option<Digest32>,
    execution_evidence_digest: Option<Digest32>,
    execution_finalized_height: Option<u64>,
    reservation_digest: Digest32,
    allocations: Vec<AllocationRecord>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ReservationScopeV2 {
    composition_id: Digest32,
    position: SettlementPositionV2,
}

type InventoryAccountRow = (
    i64,
    Vec<u8>,
    i64,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    i64,
    i64,
    i64,
    i64,
    Vec<u8>,
);

impl ReservationRecord {
    fn view(&self) -> ReservationViewV1 {
        ReservationViewV1 {
            reservation_id: self.reservation_id,
            authority_id: self.authority_id,
            route_id: self.route_id,
            rfq_id: self.rfq_id,
            quote_id: self.quote_id,
            state: self.state,
            revision: self.revision,
            expires_at_unix_ms: self.expires_at_unix_ms,
            accepted_terms_digest: self.accepted_terms_digest,
            execution_fencing_epoch: self.execution_fencing_epoch,
            reservation_digest: self.reservation_digest,
        }
    }

    fn quote_capability(&self) -> Result<QuoteInventoryCapabilityV1, InventoryStoreErrorV1> {
        if self.scope_v2.is_some() {
            return Err(InventoryStoreErrorV1::F6BindingMismatch);
        }
        Ok(QuoteInventoryCapabilityV1 {
            reservation_id: self.reservation_id,
            route_id: self.route_id,
            rfq_id: self.rfq_id,
            quote_id: self.quote_id,
            solver_id: self.authority_id,
            terms_context_digest: self.terms_context_digest,
            registry_manifest_digest: self.registry_manifest_digest,
            profile_bundle_digest: self.profile_bundle_digest,
            bond_policy_hash: self.bond_policy_hash,
            bond_policy_version: self.bond_policy_version,
            bond_key: self.bond_key,
            bond_asset_binding_digest: self.bond_asset_binding_digest,
            required_bond_amount: self.required_bond_amount,
            expires_at_unix_ms: self.expires_at_unix_ms,
            reservation_revision: self.revision,
            reservation_digest: self.reservation_digest,
            allocations: self
                .allocations
                .iter()
                .map(|allocation| allocation.capability)
                .collect(),
        })
    }

    fn quote_capability_v2(&self) -> Result<QuoteInventoryCapabilityV2, InventoryStoreErrorV1> {
        let scope = self
            .scope_v2
            .ok_or(InventoryStoreErrorV1::F6BindingMismatch)?;
        Ok(QuoteInventoryCapabilityV2 {
            quote: QuoteInventoryCapabilityV1 {
                reservation_id: self.reservation_id,
                route_id: self.route_id,
                rfq_id: self.rfq_id,
                quote_id: self.quote_id,
                solver_id: self.authority_id,
                terms_context_digest: self.terms_context_digest,
                registry_manifest_digest: self.registry_manifest_digest,
                profile_bundle_digest: self.profile_bundle_digest,
                bond_policy_hash: self.bond_policy_hash,
                bond_policy_version: self.bond_policy_version,
                bond_key: self.bond_key,
                bond_asset_binding_digest: self.bond_asset_binding_digest,
                required_bond_amount: self.required_bond_amount,
                expires_at_unix_ms: self.expires_at_unix_ms,
                reservation_revision: self.revision,
                reservation_digest: self.reservation_digest,
                allocations: self
                    .allocations
                    .iter()
                    .map(|allocation| allocation.capability)
                    .collect(),
            },
            composition_id: scope.composition_id,
            position: scope.position,
        })
    }

    fn committed_capability(
        &self,
    ) -> Result<CommittedInventoryCapabilityV1, InventoryStoreErrorV1> {
        Ok(CommittedInventoryCapabilityV1 {
            quote: self.quote_capability()?,
            accepted_terms_digest: self
                .accepted_terms_digest
                .ok_or(InventoryStoreErrorV1::CorruptState)?,
            binding_evidence_digest: self
                .binding_evidence_digest
                .ok_or(InventoryStoreErrorV1::CorruptState)?,
            execution_fencing_epoch: self
                .execution_fencing_epoch
                .ok_or(InventoryStoreErrorV1::CorruptState)?,
            reservation_revision: self.revision,
            reservation_digest: self.reservation_digest,
        })
    }

    fn committed_capability_v2(
        &self,
    ) -> Result<CommittedInventoryCapabilityV2, InventoryStoreErrorV1> {
        Ok(CommittedInventoryCapabilityV2 {
            quote: self.quote_capability_v2()?,
            accepted_terms_digest: self
                .accepted_terms_digest
                .ok_or(InventoryStoreErrorV1::CorruptState)?,
            binding_evidence_digest: self
                .binding_evidence_digest
                .ok_or(InventoryStoreErrorV1::CorruptState)?,
            execution_fencing_epoch: self
                .execution_fencing_epoch
                .ok_or(InventoryStoreErrorV1::CorruptState)?,
            reservation_revision: self.revision,
            reservation_digest: self.reservation_digest,
        })
    }
}

struct CommitmentWriter {
    hasher: Blake2b<U32>,
}

impl CommitmentWriter {
    fn new(domain: &[u8]) -> Self {
        let mut hasher = Blake2b::<U32>::new();
        Digest::update(&mut hasher, (domain.len() as u64).to_be_bytes());
        Digest::update(&mut hasher, domain);
        Self { hasher }
    }

    fn bytes(&mut self, value: &[u8]) {
        Digest::update(&mut self.hasher, (value.len() as u64).to_be_bytes());
        Digest::update(&mut self.hasher, value);
    }

    fn digest(&mut self, value: Digest32) {
        self.bytes(&value);
    }

    fn u8(&mut self, value: u8) {
        self.bytes(&[value]);
    }

    fn u32(&mut self, value: u32) {
        self.bytes(&value.to_be_bytes());
    }

    fn u64(&mut self, value: u64) {
        self.bytes(&value.to_be_bytes());
    }

    fn u128(&mut self, value: u128) {
        self.bytes(&value.to_be_bytes());
    }

    fn optional_digest(&mut self, value: Option<Digest32>) {
        match value {
            None => self.u8(0),
            Some(digest) => {
                self.u8(1);
                self.digest(digest);
            }
        }
    }

    fn optional_u64(&mut self, value: Option<u64>) {
        match value {
            None => self.u8(0),
            Some(inner) => {
                self.u8(1);
                self.u64(inner);
            }
        }
    }

    fn finish(self) -> Digest32 {
        self.hasher.finalize().into()
    }
}

fn key_commitment(writer: &mut CommitmentWriter, key: InventoryKeyV1) {
    writer.digest(key.authority_id.0);
    writer.digest(key.chain_id.0);
    writer.digest(key.asset_id.0);
}

fn snapshot_reference_commitment(writer: &mut CommitmentWriter, reference: InventorySnapshotRefV1) {
    key_commitment(writer, reference.key);
    writer.u64(reference.revision);
    writer.u64(reference.canonical_height);
    writer.digest(reference.evidence_digest);
    writer.digest(reference.asset_binding_digest);
}

fn purpose_tag(purpose: InventoryPurposeV1) -> u8 {
    match purpose {
        InventoryPurposeV1::SettlementOutput => 0,
        InventoryPurposeV1::BondCollateral => 1,
    }
}

fn state_tag(state: ReservationStateV1) -> u8 {
    match state {
        ReservationStateV1::Reserved => STATE_RESERVED as u8,
        ReservationStateV1::Committed => STATE_COMMITTED as u8,
        ReservationStateV1::Consumed => STATE_CONSUMED as u8,
        ReservationStateV1::Released => STATE_RELEASED as u8,
    }
}

fn reservation_digest(record: &ReservationRecord) -> Digest32 {
    let domain = if record.scope_v2.is_some() {
        b"DOM-INTEROP/SOLVER-INVENTORY-RESERVATION/V3".as_slice()
    } else {
        b"DOM-INTEROP/SOLVER-INVENTORY-RESERVATION/V2".as_slice()
    };
    let mut writer = CommitmentWriter::new(domain);
    writer.digest(record.reservation_id);
    writer.digest(record.authority_id.0);
    writer.digest(record.route_id);
    if let Some(scope) = record.scope_v2 {
        writer.digest(scope.composition_id);
        writer.u8(scope.position as u8);
    }
    writer.digest(record.rfq_id);
    writer.digest(record.quote_id);
    writer.bytes(&record.quote_bytes);
    writer.digest(record.terms_context_digest);
    writer.digest(record.registry_manifest_digest);
    writer.digest(record.profile_bundle_digest);
    writer.digest(record.bond_policy_hash);
    writer.u32(record.bond_policy_version);
    key_commitment(&mut writer, record.bond_key);
    writer.digest(record.bond_asset_binding_digest);
    writer.u128(record.required_bond_amount);
    writer.u64(record.expires_at_unix_ms);
    writer.u8(state_tag(record.state));
    writer.u64(record.revision);
    writer.u64(record.creation_fencing_epoch);
    writer.optional_digest(record.accepted_terms_digest);
    writer.optional_digest(record.binding_evidence_digest);
    writer.optional_u64(record.execution_fencing_epoch);
    writer.optional_digest(record.reauthorization_evidence_digest);
    writer.optional_digest(record.release_evidence_digest);
    writer.optional_digest(record.execution_id);
    writer.optional_digest(record.execution_evidence_digest);
    writer.optional_u64(record.execution_finalized_height);
    writer.u64(record.allocations.len() as u64);
    for allocation in &record.allocations {
        snapshot_reference_commitment(&mut writer, allocation.capability.reserved_snapshot);
        writer.u8(purpose_tag(allocation.capability.purpose));
        writer.u128(allocation.capability.amount);
        writer.optional_u64(allocation.consumption_sequence);
    }
    writer.finish()
}

fn account_row_digest(
    observation: &InventoryObservationV1,
    revision: u64,
    issued_sequence: u64,
    acknowledged_sequence: u64,
) -> Digest32 {
    let mut writer = CommitmentWriter::new(b"DOM-INTEROP/SOLVER-INVENTORY-SNAPSHOT/V1");
    key_commitment(&mut writer, observation.key);
    writer.u64(revision);
    writer.u128(observation.spendable_amount);
    writer.u64(observation.canonical_height);
    writer.digest(observation.canonical_anchor_digest);
    writer.digest(observation.evidence_digest);
    writer.digest(observation.registry_manifest_digest);
    writer.digest(observation.profile_bundle_digest);
    writer.digest(observation.asset_binding_digest);
    writer.u64(observation.observed_at_unix_ms);
    writer.u64(observation.valid_until_unix_ms);
    writer.u64(issued_sequence);
    writer.u64(acknowledged_sequence);
    writer.finish()
}

fn reconcile_request_digest(
    expected_revision: u64,
    observation: &InventoryObservationV1,
) -> Digest32 {
    let mut writer = CommitmentWriter::new(b"DOM-INTEROP/SOLVER-INVENTORY-RECONCILE/V1");
    writer.u64(expected_revision);
    key_commitment(&mut writer, observation.key);
    writer.u128(observation.spendable_amount);
    writer.u64(observation.canonical_height);
    writer.digest(observation.canonical_anchor_digest);
    writer.digest(observation.evidence_digest);
    writer.digest(observation.registry_manifest_digest);
    writer.digest(observation.profile_bundle_digest);
    writer.digest(observation.asset_binding_digest);
    writer.u64(observation.observed_at_unix_ms);
    writer.u64(observation.valid_until_unix_ms);
    writer.u64(observation.acknowledged_consumption_sequence);
    match observation.kind {
        InventoryObservationKindV1::Forward => writer.u8(0),
        InventoryObservationKindV1::Reorg {
            invalidated_from_height,
            reorg_evidence_digest,
        } => {
            writer.u8(1);
            writer.u64(invalidated_from_height);
            writer.digest(reorg_evidence_digest);
        }
    }
    writer.finish()
}

fn reserve_request_digest(
    quote: &QuoteV1,
    request: &ReserveQuoteRequestV1,
) -> Result<Digest32, InventoryStoreErrorV1> {
    let mut writer = CommitmentWriter::new(b"DOM-INTEROP/SOLVER-INVENTORY-RESERVE/V2");
    let quote_bytes = quote
        .canonical_bytes()
        .map_err(|_| InventoryStoreErrorV1::F6BindingMismatch)?;
    writer.bytes(&quote_bytes);
    writer.digest(request.reservation_id);
    writer.digest(request.route_id);
    writer.digest(request.terms_context_digest);
    writer.digest(request.registry_manifest_digest);
    writer.digest(request.profile_bundle_digest);
    writer.digest(request.bond_policy.policy_hash);
    writer.u32(request.bond_policy.policy_version);
    key_commitment(&mut writer, request.bond_policy.bond_key);
    writer.digest(request.bond_policy.bond_asset_binding_digest);
    writer.u128(request.bond_policy.required_collateral);
    writer.u64(request.expires_at_unix_ms);
    writer.u64(request.allocations.len() as u64);
    for allocation in &request.allocations {
        snapshot_reference_commitment(&mut writer, allocation.snapshot);
        writer.u8(purpose_tag(allocation.purpose));
        writer.u128(allocation.amount);
    }
    Ok(writer.finish())
}

fn reserve_request_digest_v2(
    quote: &QuoteV2,
    request: &ReserveQuoteRequestV2,
) -> Result<Digest32, InventoryStoreErrorV1> {
    let mut writer = CommitmentWriter::new(b"DOM-INTEROP/SOLVER-INVENTORY-RESERVE/V3");
    let quote_bytes = quote
        .canonical_bytes()
        .map_err(|_| InventoryStoreErrorV1::F6BindingMismatch)?;
    writer.bytes(&quote_bytes);
    writer.digest(request.composition_id);
    writer.u8(request.position as u8);
    let base = &request.base;
    writer.digest(base.reservation_id);
    writer.digest(base.route_id);
    writer.digest(base.terms_context_digest);
    writer.digest(base.registry_manifest_digest);
    writer.digest(base.profile_bundle_digest);
    writer.digest(base.bond_policy.policy_hash);
    writer.u32(base.bond_policy.policy_version);
    key_commitment(&mut writer, base.bond_policy.bond_key);
    writer.digest(base.bond_policy.bond_asset_binding_digest);
    writer.u128(base.bond_policy.required_collateral);
    writer.u64(base.expires_at_unix_ms);
    writer.u64(base.allocations.len() as u64);
    for allocation in &base.allocations {
        snapshot_reference_commitment(&mut writer, allocation.snapshot);
        writer.u8(purpose_tag(allocation.purpose));
        writer.u128(allocation.amount);
    }
    Ok(writer.finish())
}

fn commit_v2_request_digest(
    record: &ReservationRecord,
    scope: ReservationScopeV2,
    expected_revision: u64,
    accepted_terms_digest: Digest32,
    binding_evidence_digest: Digest32,
) -> Digest32 {
    let mut writer = CommitmentWriter::new(b"DOM-INTEROP/SOLVER-INVENTORY-COMMIT/V2");
    writer.digest(record.reservation_id);
    writer.u64(expected_revision);
    writer.digest(scope.composition_id);
    writer.u8(scope.position as u8);
    writer.digest(record.rfq_id);
    writer.digest(record.quote_id);
    writer.digest(record.authority_id.0);
    writer.digest(accepted_terms_digest);
    writer.digest(binding_evidence_digest);
    writer.finish()
}

fn transition_request_digest(
    domain: &[u8],
    reservation_id: Digest32,
    expected_revision: u64,
    digests: &[Digest32],
    epoch: Option<u64>,
) -> Digest32 {
    let mut writer = CommitmentWriter::new(domain);
    writer.digest(reservation_id);
    writer.u64(expected_revision);
    writer.u64(digests.len() as u64);
    for digest in digests {
        writer.digest(*digest);
    }
    writer.optional_u64(epoch);
    writer.finish()
}

fn consume_request_digest(expected_revision: u64, execution: &InventoryExecutionV1) -> Digest32 {
    let mut writer = CommitmentWriter::new(b"DOM-INTEROP/SOLVER-INVENTORY-CONSUME/V1");
    writer.u64(expected_revision);
    writer.digest(execution.reservation_id);
    writer.u64(execution.execution_fencing_epoch);
    writer.digest(execution.execution_id);
    writer.digest(execution.evidence_digest);
    writer.u64(execution.finalized_height);
    writer.finish()
}

fn validate_digest(value: Digest32) -> Result<(), InventoryStoreErrorV1> {
    if value.iter().all(|byte| *byte == 0) {
        Err(InventoryStoreErrorV1::InvalidMaterial)
    } else {
        Ok(())
    }
}

fn validate_participant(value: ParticipantId) -> Result<(), InventoryStoreErrorV1> {
    validate_digest(value.0)
}

fn validate_key(key: InventoryKeyV1) -> Result<(), InventoryStoreErrorV1> {
    validate_participant(key.authority_id)?;
    validate_digest(key.chain_id.0)?;
    validate_digest(key.asset_id.0)
}

fn validate_observation(
    observation: &InventoryObservationV1,
    now_unix_ms: u64,
) -> Result<(), InventoryStoreErrorV1> {
    validate_key(observation.key)?;
    for digest in [
        observation.canonical_anchor_digest,
        observation.evidence_digest,
        observation.registry_manifest_digest,
        observation.profile_bundle_digest,
        observation.asset_binding_digest,
    ] {
        validate_digest(digest)?;
    }
    if observation.observed_at_unix_ms == 0
        || observation.observed_at_unix_ms > now_unix_ms
        || observation.valid_until_unix_ms < now_unix_ms
        || observation.valid_until_unix_ms <= observation.observed_at_unix_ms
        || observation
            .valid_until_unix_ms
            .checked_sub(observation.observed_at_unix_ms)
            .ok_or(InventoryStoreErrorV1::InvalidMaterial)?
            > MAX_OBSERVATION_VALIDITY_MS
    {
        return Err(InventoryStoreErrorV1::SnapshotStale);
    }
    if let InventoryObservationKindV1::Reorg {
        invalidated_from_height,
        reorg_evidence_digest,
    } = observation.kind
    {
        if invalidated_from_height == 0 || validate_digest(reorg_evidence_digest).is_err() {
            return Err(InventoryStoreErrorV1::ReorgEvidenceRequired);
        }
    }
    Ok(())
}

fn validate_observation_successor(
    previous: InventorySnapshotV1,
    observation: &InventoryObservationV1,
) -> Result<(), InventoryStoreErrorV1> {
    if observation.acknowledged_consumption_sequence < previous.acknowledged_consumption_sequence
        || observation.observed_at_unix_ms < previous.observed_at_unix_ms
    {
        return Err(InventoryStoreErrorV1::ObservationRegression);
    }
    match observation.kind {
        InventoryObservationKindV1::Forward => {
            if observation.canonical_height < previous.canonical_height
                || (observation.canonical_height == previous.canonical_height
                    && observation.canonical_anchor_digest != previous.canonical_anchor_digest)
            {
                return Err(InventoryStoreErrorV1::ObservationRegression);
            }
        }
        InventoryObservationKindV1::Reorg {
            invalidated_from_height,
            reorg_evidence_digest,
        } => {
            validate_digest(reorg_evidence_digest)
                .map_err(|_| InventoryStoreErrorV1::ReorgEvidenceRequired)?;
            if invalidated_from_height == 0
                || invalidated_from_height > previous.canonical_height.saturating_add(1)
            {
                return Err(InventoryStoreErrorV1::ReorgEvidenceRequired);
            }
        }
    }
    Ok(())
}

fn validate_execution(execution: &InventoryExecutionV1) -> Result<(), InventoryStoreErrorV1> {
    validate_digest(execution.reservation_id)?;
    validate_digest(execution.execution_id)?;
    validate_digest(execution.evidence_digest)?;
    if execution.execution_fencing_epoch == 0 {
        return Err(InventoryStoreErrorV1::StaleFencing);
    }
    Ok(())
}

fn validate_reserve_request(
    lease: InventoryLeaseV1,
    quote: &QuoteV1,
    request: &ReserveQuoteRequestV1,
    now_unix_ms: u64,
) -> Result<(), InventoryStoreErrorV1> {
    quote
        .validate()
        .map_err(|_| InventoryStoreErrorV1::F6BindingMismatch)?;
    validate_participant(lease.authority_id)?;
    if quote.solver != lease.authority_id
        || quote.bond_reservation_id != request.reservation_id
        || quote.bond_policy_version == 0
        || quote.bond_policy_version != request.bond_policy.policy_version
        || request.bond_policy.bond_key.authority_id != lease.authority_id
    {
        return Err(InventoryStoreErrorV1::F6BindingMismatch);
    }
    for digest in [
        request.reservation_id,
        request.route_id,
        request.terms_context_digest,
        request.registry_manifest_digest,
        request.profile_bundle_digest,
        request.bond_policy.policy_hash,
        request.bond_policy.bond_asset_binding_digest,
        quote.rfq_id,
        quote.quote_id,
    ] {
        validate_digest(digest)?;
    }
    if request.bond_policy.required_collateral == 0
        || request.allocations.is_empty()
        || request.allocations.len() > MAX_RESERVATION_ALLOCATIONS_V1
        || request.expires_at_unix_ms <= now_unix_ms
        || request
            .expires_at_unix_ms
            .checked_sub(now_unix_ms)
            .ok_or(InventoryStoreErrorV1::InvalidMaterial)?
            > MAX_RESERVATION_TTL_MS
    {
        return Err(InventoryStoreErrorV1::InvalidMaterial);
    }
    let receive_leg = quote
        .route
        .legs
        .iter()
        .find(|leg| leg.direction == LegDirectionV1::UserReceives)
        .ok_or(InventoryStoreErrorV1::F6BindingMismatch)?;
    let output_key = (receive_leg.chain_id, receive_leg.asset);
    let mut previous = None;
    let mut settlement_total = 0u128;
    let mut bond_total = 0u128;
    let mut settlement_allocations = 0u8;
    let mut bond_allocations = 0u8;
    for allocation in &request.allocations {
        validate_key(allocation.snapshot.key)?;
        validate_digest(allocation.snapshot.evidence_digest)?;
        validate_digest(allocation.snapshot.asset_binding_digest)?;
        if allocation.snapshot.key.authority_id != lease.authority_id
            || allocation.snapshot.revision == 0
            || allocation.amount == 0
        {
            return Err(InventoryStoreErrorV1::InvalidMaterial);
        }
        let order = (allocation.snapshot.key, allocation.purpose);
        if previous.is_some_and(|prior| prior >= order) {
            return Err(InventoryStoreErrorV1::InvalidMaterial);
        }
        previous = Some(order);
        match allocation.purpose {
            InventoryPurposeV1::SettlementOutput => {
                if (
                    allocation.snapshot.key.chain_id,
                    allocation.snapshot.key.asset_id,
                ) != output_key
                {
                    return Err(InventoryStoreErrorV1::F6BindingMismatch);
                }
                settlement_total = settlement_total
                    .checked_add(allocation.amount)
                    .ok_or(InventoryStoreErrorV1::InvalidMaterial)?;
                settlement_allocations = settlement_allocations
                    .checked_add(1)
                    .ok_or(InventoryStoreErrorV1::InvalidMaterial)?;
            }
            InventoryPurposeV1::BondCollateral => {
                if allocation.snapshot.key != request.bond_policy.bond_key
                    || allocation.snapshot.asset_binding_digest
                        != request.bond_policy.bond_asset_binding_digest
                {
                    return Err(InventoryStoreErrorV1::F6BindingMismatch);
                }
                bond_total = bond_total
                    .checked_add(allocation.amount)
                    .ok_or(InventoryStoreErrorV1::InvalidMaterial)?;
                bond_allocations = bond_allocations
                    .checked_add(1)
                    .ok_or(InventoryStoreErrorV1::InvalidMaterial)?;
            }
        }
    }
    if settlement_allocations != 1
        || bond_allocations != 1
        || settlement_total < quote.net_output
        || bond_total < request.bond_policy.required_collateral
    {
        return Err(InventoryStoreErrorV1::F6BindingMismatch);
    }
    Ok(())
}

fn validate_reserve_request_v2(
    lease: InventoryLeaseV1,
    quote: &QuoteV2,
    request: &ReserveQuoteRequestV2,
    now_unix_ms: u64,
) -> Result<(), InventoryStoreErrorV1> {
    quote
        .validate()
        .map_err(|_| InventoryStoreErrorV1::F6BindingMismatch)?;
    validate_participant(lease.authority_id)?;
    let base = &request.base;
    if quote.route.composition_id != request.composition_id
        || quote.route.position != request.position
        || quote.solver != lease.authority_id
        || quote.bond_reservation_id != base.reservation_id
        || quote.bond_policy_version == 0
        || quote.bond_policy_version != base.bond_policy.policy_version
        || base.bond_policy.bond_key.authority_id != lease.authority_id
    {
        return Err(InventoryStoreErrorV1::F6BindingMismatch);
    }
    for digest in [
        request.composition_id,
        base.reservation_id,
        base.route_id,
        base.terms_context_digest,
        base.registry_manifest_digest,
        base.profile_bundle_digest,
        base.bond_policy.policy_hash,
        base.bond_policy.bond_asset_binding_digest,
        quote.rfq_id,
        quote.quote_id,
    ] {
        validate_digest(digest)?;
    }
    if base.bond_policy.required_collateral == 0
        || base.allocations.is_empty()
        || base.allocations.len() > MAX_RESERVATION_ALLOCATIONS_V1
        || base.expires_at_unix_ms <= now_unix_ms
        || base
            .expires_at_unix_ms
            .checked_sub(now_unix_ms)
            .ok_or(InventoryStoreErrorV1::InvalidMaterial)?
            > MAX_RESERVATION_TTL_MS
    {
        return Err(InventoryStoreErrorV1::InvalidMaterial);
    }
    let receive_leg = quote
        .route
        .legs
        .iter()
        .find(|leg| leg.direction == LegDirectionV1::UserReceives)
        .ok_or(InventoryStoreErrorV1::F6BindingMismatch)?;
    let output_key = (receive_leg.chain_id, receive_leg.asset);
    let mut previous = None;
    let mut settlement_total = 0u128;
    let mut bond_total = 0u128;
    let mut settlement_allocations = 0u8;
    let mut bond_allocations = 0u8;
    for allocation in &base.allocations {
        validate_key(allocation.snapshot.key)?;
        validate_digest(allocation.snapshot.evidence_digest)?;
        validate_digest(allocation.snapshot.asset_binding_digest)?;
        if allocation.snapshot.key.authority_id != lease.authority_id
            || allocation.snapshot.revision == 0
            || allocation.amount == 0
        {
            return Err(InventoryStoreErrorV1::InvalidMaterial);
        }
        let order = (allocation.snapshot.key, allocation.purpose);
        if previous.is_some_and(|prior| prior >= order) {
            return Err(InventoryStoreErrorV1::InvalidMaterial);
        }
        previous = Some(order);
        match allocation.purpose {
            InventoryPurposeV1::SettlementOutput => {
                if (
                    allocation.snapshot.key.chain_id,
                    allocation.snapshot.key.asset_id,
                ) != output_key
                {
                    return Err(InventoryStoreErrorV1::F6BindingMismatch);
                }
                settlement_total = settlement_total
                    .checked_add(allocation.amount)
                    .ok_or(InventoryStoreErrorV1::InvalidMaterial)?;
                settlement_allocations = settlement_allocations
                    .checked_add(1)
                    .ok_or(InventoryStoreErrorV1::InvalidMaterial)?;
            }
            InventoryPurposeV1::BondCollateral => {
                if allocation.snapshot.key != base.bond_policy.bond_key
                    || allocation.snapshot.asset_binding_digest
                        != base.bond_policy.bond_asset_binding_digest
                {
                    return Err(InventoryStoreErrorV1::F6BindingMismatch);
                }
                bond_total = bond_total
                    .checked_add(allocation.amount)
                    .ok_or(InventoryStoreErrorV1::InvalidMaterial)?;
                bond_allocations = bond_allocations
                    .checked_add(1)
                    .ok_or(InventoryStoreErrorV1::InvalidMaterial)?;
            }
        }
    }
    if settlement_allocations != 1
        || bond_allocations != 1
        || settlement_total < quote.net_output
        || bond_total < base.bond_policy.required_collateral
    {
        return Err(InventoryStoreErrorV1::F6BindingMismatch);
    }
    Ok(())
}

fn validate_allocation_snapshot(
    snapshot: InventorySnapshotV1,
    allocation: &InventoryAllocationRequestV1,
    request: &ReserveQuoteRequestV1,
    now_unix_ms: u64,
) -> Result<(), InventoryStoreErrorV1> {
    if snapshot.reference() != allocation.snapshot
        || snapshot.registry_manifest_digest != request.registry_manifest_digest
        || snapshot.profile_bundle_digest != request.profile_bundle_digest
    {
        return Err(InventoryStoreErrorV1::SnapshotMismatch);
    }
    if now_unix_ms > snapshot.valid_until_unix_ms {
        return Err(InventoryStoreErrorV1::SnapshotStale);
    }
    if snapshot.deficit_amount != 0 {
        return Err(InventoryStoreErrorV1::UnderCollateralized);
    }
    Ok(())
}

fn validate_live_capacity(
    transaction: &Transaction<'_>,
    record: &ReservationRecord,
    now_unix_ms: u64,
) -> Result<(), InventoryStoreErrorV1> {
    let mut seen = BTreeSet::new();
    for allocation in &record.allocations {
        if !seen.insert(allocation.capability.key) {
            continue;
        }
        let snapshot = load_snapshot_transaction(transaction, allocation.capability.key)?
            .ok_or(InventoryStoreErrorV1::SnapshotNotFound)?;
        if now_unix_ms > snapshot.valid_until_unix_ms {
            return Err(InventoryStoreErrorV1::SnapshotStale);
        }
        if snapshot.deficit_amount != 0 {
            return Err(InventoryStoreErrorV1::UnderCollateralized);
        }
        if snapshot.registry_manifest_digest != record.registry_manifest_digest
            || snapshot.profile_bundle_digest != record.profile_bundle_digest
        {
            return Err(InventoryStoreErrorV1::SnapshotMismatch);
        }
        for item in record
            .allocations
            .iter()
            .filter(|item| item.capability.key == allocation.capability.key)
        {
            if item.capability.reserved_snapshot.asset_binding_digest
                != snapshot.asset_binding_digest
            {
                return Err(InventoryStoreErrorV1::SnapshotMismatch);
            }
        }
    }
    Ok(())
}

fn validate_reservation_record(record: &ReservationRecord) -> Result<(), InventoryStoreErrorV1> {
    validate_digest(record.reservation_id)?;
    validate_participant(record.authority_id)?;
    validate_key(record.bond_key)?;
    for digest in [
        record.route_id,
        record.rfq_id,
        record.quote_id,
        record.terms_context_digest,
        record.registry_manifest_digest,
        record.profile_bundle_digest,
        record.bond_policy_hash,
        record.bond_asset_binding_digest,
    ] {
        validate_digest(digest)?;
    }
    if record.bond_policy_version == 0
        || record.required_bond_amount == 0
        || record.bond_key.authority_id != record.authority_id
        || record.revision == 0
        || record.creation_fencing_epoch == 0
        || record.allocations.is_empty()
        || record.allocations.len() > MAX_RESERVATION_ALLOCATIONS_V1
    {
        return Err(InventoryStoreErrorV1::CorruptState);
    }
    let (quote_id, rfq_id, solver, reservation_id, policy_version, output, net_output) =
        match record.scope_v2 {
            None => {
                let quote = QuoteV1::decode(&record.quote_bytes)
                    .map_err(|_| InventoryStoreErrorV1::CorruptState)?;
                let output = quote
                    .route
                    .legs
                    .iter()
                    .find(|leg| leg.direction == LegDirectionV1::UserReceives)
                    .ok_or(InventoryStoreErrorV1::CorruptState)?;
                (
                    quote.quote_id,
                    quote.rfq_id,
                    quote.solver,
                    quote.bond_reservation_id,
                    quote.bond_policy_version,
                    (output.chain_id, output.asset),
                    quote.net_output,
                )
            }
            Some(scope) => {
                validate_digest(scope.composition_id)?;
                let quote = QuoteV2::decode(&record.quote_bytes)
                    .map_err(|_| InventoryStoreErrorV1::CorruptState)?;
                if quote.route.composition_id != scope.composition_id
                    || quote.route.position != scope.position
                {
                    return Err(InventoryStoreErrorV1::CorruptState);
                }
                let output = quote
                    .route
                    .legs
                    .iter()
                    .find(|leg| leg.direction == LegDirectionV1::UserReceives)
                    .ok_or(InventoryStoreErrorV1::CorruptState)?;
                (
                    quote.quote_id,
                    quote.rfq_id,
                    quote.solver,
                    quote.bond_reservation_id,
                    quote.bond_policy_version,
                    (output.chain_id, output.asset),
                    quote.net_output,
                )
            }
        };
    if quote_id != record.quote_id
        || rfq_id != record.rfq_id
        || solver != record.authority_id
        || reservation_id != record.reservation_id
        || policy_version != record.bond_policy_version
    {
        return Err(InventoryStoreErrorV1::CorruptState);
    }
    let mut previous = None;
    let mut settlement_total = 0u128;
    let mut bond_total = 0u128;
    let mut settlement_allocations = 0u8;
    let mut bond_allocations = 0u8;
    for allocation in &record.allocations {
        validate_key(allocation.capability.key)?;
        if allocation.capability.key.authority_id != record.authority_id
            || allocation.capability.amount == 0
            || allocation.capability.reserved_snapshot.key != allocation.capability.key
            || allocation.capability.reserved_snapshot.revision == 0
        {
            return Err(InventoryStoreErrorV1::CorruptState);
        }
        let order = (allocation.capability.key, allocation.capability.purpose);
        if previous.is_some_and(|prior| prior >= order) {
            return Err(InventoryStoreErrorV1::CorruptState);
        }
        previous = Some(order);
        match allocation.capability.purpose {
            InventoryPurposeV1::SettlementOutput => {
                if (
                    allocation.capability.key.chain_id,
                    allocation.capability.key.asset_id,
                ) != output
                {
                    return Err(InventoryStoreErrorV1::CorruptState);
                }
                settlement_total = settlement_total
                    .checked_add(allocation.capability.amount)
                    .ok_or(InventoryStoreErrorV1::CorruptState)?;
                settlement_allocations = settlement_allocations
                    .checked_add(1)
                    .ok_or(InventoryStoreErrorV1::CorruptState)?;
            }
            InventoryPurposeV1::BondCollateral => {
                if allocation.capability.key != record.bond_key
                    || allocation.capability.reserved_snapshot.asset_binding_digest
                        != record.bond_asset_binding_digest
                {
                    return Err(InventoryStoreErrorV1::CorruptState);
                }
                bond_total = bond_total
                    .checked_add(allocation.capability.amount)
                    .ok_or(InventoryStoreErrorV1::CorruptState)?;
                bond_allocations = bond_allocations
                    .checked_add(1)
                    .ok_or(InventoryStoreErrorV1::CorruptState)?;
            }
        }
    }
    if settlement_allocations != 1
        || bond_allocations != 1
        || settlement_total < net_output
        || bond_total < record.required_bond_amount
    {
        return Err(InventoryStoreErrorV1::CorruptState);
    }
    let committed_fields = (
        record.accepted_terms_digest,
        record.binding_evidence_digest,
        record.execution_fencing_epoch,
    );
    match record.state {
        ReservationStateV1::Reserved => {
            if committed_fields != (None, None, None)
                || record.execution_id.is_some()
                || record.release_evidence_digest.is_some()
                || record
                    .allocations
                    .iter()
                    .any(|allocation| allocation.consumption_sequence.is_some())
            {
                return Err(InventoryStoreErrorV1::CorruptState);
            }
        }
        ReservationStateV1::Committed => {
            if committed_fields.0.is_none()
                || committed_fields.1.is_none()
                || committed_fields.2.is_none()
                || record.execution_id.is_some()
                || record.release_evidence_digest.is_some()
                || record
                    .allocations
                    .iter()
                    .any(|allocation| allocation.consumption_sequence.is_some())
            {
                return Err(InventoryStoreErrorV1::CorruptState);
            }
        }
        ReservationStateV1::Consumed => {
            if committed_fields.0.is_none()
                || committed_fields.1.is_none()
                || committed_fields.2.is_none()
                || record.execution_id.is_none()
                || record.execution_evidence_digest.is_none()
                || record.execution_finalized_height.is_none()
                || record.release_evidence_digest.is_some()
                || record
                    .allocations
                    .iter()
                    .any(|allocation| allocation.consumption_sequence.is_none())
            {
                return Err(InventoryStoreErrorV1::CorruptState);
            }
        }
        ReservationStateV1::Released => {
            let never_committed = committed_fields == (None, None, None);
            let was_committed = committed_fields.0.is_some()
                && committed_fields.1.is_some()
                && committed_fields.2.is_some();
            if (!never_committed && !was_committed)
                || record.execution_id.is_some()
                || record.execution_evidence_digest.is_some()
                || record.execution_finalized_height.is_some()
                || record
                    .allocations
                    .iter()
                    .any(|allocation| allocation.consumption_sequence.is_some())
            {
                return Err(InventoryStoreErrorV1::CorruptState);
            }
        }
    }
    if record.reservation_digest != reservation_digest(record) {
        return Err(InventoryStoreErrorV1::CorruptState);
    }
    Ok(())
}

fn deadline(
    now_unix_ms: u64,
    duration_ms: u64,
    maximum_ms: u64,
) -> Result<u64, InventoryStoreErrorV1> {
    if duration_ms == 0 || duration_ms > maximum_ms {
        return Err(InventoryStoreErrorV1::InvalidMaterial);
    }
    let value = now_unix_ms
        .checked_add(duration_ms)
        .ok_or(InventoryStoreErrorV1::InvalidMaterial)?;
    to_sql_u64(value)?;
    Ok(value)
}

fn next_revision(current: u64) -> Result<u64, InventoryStoreErrorV1> {
    let next = current
        .checked_add(1)
        .ok_or(InventoryStoreErrorV1::InvalidMaterial)?;
    to_sql_u64(next)?;
    Ok(next)
}

fn u128_blob(value: u128) -> [u8; 16] {
    value.to_be_bytes()
}

fn blob_u128(value: Vec<u8>) -> Result<u128, InventoryStoreErrorV1> {
    let bytes: [u8; 16] = value
        .try_into()
        .map_err(|_| InventoryStoreErrorV1::CorruptState)?;
    Ok(u128::from_be_bytes(bytes))
}

fn blob32(value: Vec<u8>) -> Result<Digest32, InventoryStoreErrorV1> {
    value
        .try_into()
        .map_err(|_| InventoryStoreErrorV1::CorruptState)
}

fn optional_blob32(value: Option<Vec<u8>>) -> Result<Option<Digest32>, InventoryStoreErrorV1> {
    value.map(blob32).transpose()
}

fn to_sql_u64(value: u64) -> Result<i64, InventoryStoreErrorV1> {
    i64::try_from(value).map_err(|_| InventoryStoreErrorV1::InvalidMaterial)
}

fn from_sql_u64(value: i64) -> Result<u64, InventoryStoreErrorV1> {
    u64::try_from(value).map_err(|_| InventoryStoreErrorV1::CorruptState)
}

fn state_from_sql(value: i64) -> Result<ReservationStateV1, InventoryStoreErrorV1> {
    match value {
        STATE_RESERVED => Ok(ReservationStateV1::Reserved),
        STATE_COMMITTED => Ok(ReservationStateV1::Committed),
        STATE_CONSUMED => Ok(ReservationStateV1::Consumed),
        STATE_RELEASED => Ok(ReservationStateV1::Released),
        _ => Err(InventoryStoreErrorV1::CorruptState),
    }
}

fn purpose_from_sql(value: i64) -> Result<InventoryPurposeV1, InventoryStoreErrorV1> {
    match value {
        PURPOSE_SETTLEMENT => Ok(InventoryPurposeV1::SettlementOutput),
        PURPOSE_BOND => Ok(InventoryPurposeV1::BondCollateral),
        _ => Err(InventoryStoreErrorV1::CorruptState),
    }
}

fn load_lease_row(
    transaction: &Transaction<'_>,
    authority_id: ParticipantId,
) -> Result<Option<(Digest32, u64, u64)>, InventoryStoreErrorV1> {
    let row: Option<(Vec<u8>, i64, i64)> = transaction
        .query_row(
            "SELECT owner_id, fencing_epoch, lease_until_unix_ms
             FROM inventory_leases WHERE authority_id = ?1",
            params![authority_id.0.as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()?;
    row.map(|(owner, epoch, until)| {
        Ok((blob32(owner)?, from_sql_u64(epoch)?, from_sql_u64(until)?))
    })
    .transpose()
}

fn validate_lease(
    transaction: &Transaction<'_>,
    lease: InventoryLeaseV1,
    now_unix_ms: u64,
) -> Result<(), InventoryStoreErrorV1> {
    validate_participant(lease.authority_id)?;
    validate_digest(lease.owner_id)?;
    if lease.fencing_epoch == 0 {
        return Err(InventoryStoreErrorV1::StaleFencing);
    }
    let (owner, epoch, until) = load_lease_row(transaction, lease.authority_id)?
        .ok_or(InventoryStoreErrorV1::StaleFencing)?;
    if owner != lease.owner_id || epoch != lease.fencing_epoch {
        return Err(InventoryStoreErrorV1::StaleFencing);
    }
    if until < now_unix_ms || lease.lease_until_unix_ms != until {
        return Err(InventoryStoreErrorV1::LeaseExpired);
    }
    Ok(())
}

fn prior_operation(
    transaction: &Transaction<'_>,
    authority_id: ParticipantId,
    operation_id: Digest32,
    request_digest: Digest32,
) -> Result<Option<MutationOutcomeV1>, InventoryStoreErrorV1> {
    let row: Option<(Vec<u8>, i64)> = transaction
        .query_row(
            "SELECT request_digest, result_revision
             FROM inventory_operations
             WHERE authority_id = ?1 AND operation_id = ?2",
            params![authority_id.0.as_slice(), operation_id.as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    match row {
        None => Ok(None),
        Some((stored_digest, revision)) => {
            if blob32(stored_digest)? != request_digest {
                return Err(InventoryStoreErrorV1::IdempotencyConflict);
            }
            Ok(Some(MutationOutcomeV1 {
                status: MutationStatusV1::DuplicateSameBytes,
                revision: from_sql_u64(revision)?,
            }))
        }
    }
}

struct OperationInsertV1 {
    authority_id: ParticipantId,
    operation_id: Digest32,
    request_digest: Digest32,
    result_revision: u64,
    reservation_id: Option<Digest32>,
    now_unix_ms: u64,
}

fn insert_operation(
    transaction: &Transaction<'_>,
    operation: OperationInsertV1,
) -> Result<(), InventoryStoreErrorV1> {
    transaction.execute(
        "INSERT INTO inventory_operations
         (authority_id, operation_id, request_digest, result_revision,
          reservation_id, created_at_unix_ms)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![
            operation.authority_id.0.as_slice(),
            operation.operation_id.as_slice(),
            operation.request_digest.as_slice(),
            to_sql_u64(operation.result_revision)?,
            operation.reservation_id.map(|value| value.to_vec()),
            to_sql_u64(operation.now_unix_ms)?
        ],
    )?;
    Ok(())
}

fn load_snapshot_transaction(
    transaction: &Connection,
    key: InventoryKeyV1,
) -> Result<Option<InventorySnapshotV1>, InventoryStoreErrorV1> {
    let row: Option<InventoryAccountRow> = transaction
        .query_row(
            "SELECT revision, spendable_amount, canonical_height,
                    canonical_anchor_digest, evidence_digest,
                    registry_manifest_digest, profile_bundle_digest,
                    asset_binding_digest, observed_at_unix_ms,
                    valid_until_unix_ms, issued_consumption_sequence,
                    acknowledged_consumption_sequence, row_digest
             FROM inventory_accounts
             WHERE authority_id = ?1 AND chain_id = ?2 AND asset_id = ?3",
            params![
                key.authority_id.0.as_slice(),
                key.chain_id.0.as_slice(),
                key.asset_id.0.as_slice()
            ],
            |row| {
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
            },
        )
        .optional()?;
    let Some((
        revision,
        spendable_amount,
        canonical_height,
        canonical_anchor_digest,
        evidence_digest,
        registry_manifest_digest,
        profile_bundle_digest,
        asset_binding_digest,
        observed_at_unix_ms,
        valid_until_unix_ms,
        issued_sequence,
        acknowledged_sequence,
        stored_digest,
    )) = row
    else {
        return Ok(None);
    };
    let revision = from_sql_u64(revision)?;
    let issued_sequence = from_sql_u64(issued_sequence)?;
    let acknowledged_sequence = from_sql_u64(acknowledged_sequence)?;
    if revision == 0 || acknowledged_sequence > issued_sequence {
        return Err(InventoryStoreErrorV1::CorruptState);
    }
    let observation = InventoryObservationV1 {
        key,
        spendable_amount: blob_u128(spendable_amount)?,
        canonical_height: from_sql_u64(canonical_height)?,
        canonical_anchor_digest: blob32(canonical_anchor_digest)?,
        evidence_digest: blob32(evidence_digest)?,
        registry_manifest_digest: blob32(registry_manifest_digest)?,
        profile_bundle_digest: blob32(profile_bundle_digest)?,
        asset_binding_digest: blob32(asset_binding_digest)?,
        observed_at_unix_ms: from_sql_u64(observed_at_unix_ms)?,
        valid_until_unix_ms: from_sql_u64(valid_until_unix_ms)?,
        acknowledged_consumption_sequence: acknowledged_sequence,
        kind: InventoryObservationKindV1::Forward,
    };
    validate_key(key)?;
    for digest in [
        observation.canonical_anchor_digest,
        observation.evidence_digest,
        observation.registry_manifest_digest,
        observation.profile_bundle_digest,
        observation.asset_binding_digest,
    ] {
        validate_digest(digest).map_err(|_| InventoryStoreErrorV1::CorruptState)?;
    }
    if observation.observed_at_unix_ms == 0
        || observation.valid_until_unix_ms <= observation.observed_at_unix_ms
        || observation
            .valid_until_unix_ms
            .checked_sub(observation.observed_at_unix_ms)
            .ok_or(InventoryStoreErrorV1::CorruptState)?
            > MAX_OBSERVATION_VALIDITY_MS
        || blob32(stored_digest)?
            != account_row_digest(
                &observation,
                revision,
                issued_sequence,
                acknowledged_sequence,
            )
    {
        return Err(InventoryStoreErrorV1::CorruptState);
    }
    let encumbered_amount =
        encumbered_amount(transaction, key, acknowledged_sequence, issued_sequence)?;
    let deficit_amount = encumbered_amount.saturating_sub(observation.spendable_amount);
    Ok(Some(InventorySnapshotV1 {
        key,
        revision,
        spendable_amount: observation.spendable_amount,
        encumbered_amount,
        deficit_amount,
        canonical_height: observation.canonical_height,
        canonical_anchor_digest: observation.canonical_anchor_digest,
        evidence_digest: observation.evidence_digest,
        registry_manifest_digest: observation.registry_manifest_digest,
        profile_bundle_digest: observation.profile_bundle_digest,
        asset_binding_digest: observation.asset_binding_digest,
        observed_at_unix_ms: observation.observed_at_unix_ms,
        valid_until_unix_ms: observation.valid_until_unix_ms,
        issued_consumption_sequence: issued_sequence,
        acknowledged_consumption_sequence: acknowledged_sequence,
    }))
}

fn encumbered_amount(
    transaction: &Connection,
    key: InventoryKeyV1,
    acknowledged_sequence: u64,
    issued_sequence: u64,
) -> Result<u128, InventoryStoreErrorV1> {
    let mut statement = transaction.prepare(
        "SELECT a.amount, a.consumption_sequence, r.state_tag
         FROM inventory_allocations a
         JOIN inventory_reservations r ON r.reservation_id = a.reservation_id
         WHERE a.authority_id = ?1 AND a.chain_id = ?2 AND a.asset_id = ?3
           AND r.state_tag IN (?4, ?5, ?6)
         ORDER BY r.reservation_id, a.position
         LIMIT ?7",
    )?;
    let rows = statement.query_map(
        params![
            key.authority_id.0.as_slice(),
            key.chain_id.0.as_slice(),
            key.asset_id.0.as_slice(),
            STATE_RESERVED,
            STATE_COMMITTED,
            STATE_CONSUMED,
            i64::try_from(MAX_PENDING_CONSUMPTIONS + 1)
                .map_err(|_| InventoryStoreErrorV1::CorruptState)?
        ],
        |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, Option<i64>>(1)?,
                row.get::<_, i64>(2)?,
            ))
        },
    )?;
    let raw = rows.collect::<Result<Vec<_>, _>>()?;
    if raw.len() > MAX_PENDING_CONSUMPTIONS {
        return Err(InventoryStoreErrorV1::CorruptState);
    }
    let mut total = 0u128;
    for (amount, sequence, state) in raw {
        let count = match state {
            STATE_RESERVED | STATE_COMMITTED => {
                if sequence.is_some() {
                    return Err(InventoryStoreErrorV1::CorruptState);
                }
                true
            }
            STATE_CONSUMED => {
                let sequence = sequence
                    .map(from_sql_u64)
                    .transpose()?
                    .ok_or(InventoryStoreErrorV1::CorruptState)?;
                if sequence > issued_sequence {
                    return Err(InventoryStoreErrorV1::CorruptState);
                }
                sequence > acknowledged_sequence
            }
            _ => return Err(InventoryStoreErrorV1::CorruptState),
        };
        if count {
            total = total
                .checked_add(blob_u128(amount)?)
                .ok_or(InventoryStoreErrorV1::CorruptState)?;
        }
    }
    Ok(total)
}

type ReservationRowV1 = (
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    i64,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    i64,
    i64,
    i64,
    i64,
    Option<Vec<u8>>,
    Option<Vec<u8>>,
    Option<i64>,
    Option<Vec<u8>>,
    Option<Vec<u8>>,
    Option<Vec<u8>>,
    Option<Vec<u8>>,
    Option<i64>,
    Vec<u8>,
);

fn load_reservation_transaction(
    transaction: &Connection,
    reservation_id: Digest32,
) -> Result<Option<ReservationRecord>, InventoryStoreErrorV1> {
    let row: Option<ReservationRowV1> = transaction
        .query_row(
            "SELECT authority_id, route_id, rfq_id, quote_id, quote_bytes,
                    terms_context_digest, registry_manifest_digest,
                    profile_bundle_digest, bond_policy_hash, bond_policy_version,
                    bond_chain_id, bond_asset_id, bond_asset_binding_digest,
                    required_bond_amount, expires_at_unix_ms, state_tag,
                    revision, creation_fencing_epoch, accepted_terms_digest,
                    binding_evidence_digest, execution_fencing_epoch,
                    reauthorization_evidence_digest, release_evidence_digest,
                    execution_id, execution_evidence_digest,
                    execution_finalized_height, reservation_digest
             FROM inventory_reservations WHERE reservation_id = ?1",
            params![reservation_id.as_slice()],
            |row| {
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
                    row.get(13)?,
                    row.get(14)?,
                    row.get(15)?,
                    row.get(16)?,
                    row.get(17)?,
                    row.get(18)?,
                    row.get(19)?,
                    row.get(20)?,
                    row.get(21)?,
                    row.get(22)?,
                    row.get(23)?,
                    row.get(24)?,
                    row.get(25)?,
                    row.get(26)?,
                ))
            },
        )
        .optional()?;
    let Some((
        authority_id,
        route_id,
        rfq_id,
        quote_id,
        quote_bytes,
        terms_context_digest,
        registry_manifest_digest,
        profile_bundle_digest,
        bond_policy_hash,
        bond_policy_version,
        bond_chain_id,
        bond_asset_id,
        bond_asset_binding_digest,
        required_bond_amount,
        expires_at_unix_ms,
        state_tag,
        revision,
        creation_fencing_epoch,
        accepted_terms_digest,
        binding_evidence_digest,
        execution_fencing_epoch,
        reauthorization_evidence_digest,
        release_evidence_digest,
        execution_id,
        execution_evidence_digest,
        execution_finalized_height,
        stored_digest,
    )) = row
    else {
        return Ok(None);
    };
    let authority_id = ParticipantId(blob32(authority_id)?);
    let allocations = load_allocations(transaction, reservation_id, authority_id)?;
    let scope_v2 = load_reservation_scope_v2(transaction, reservation_id)?;
    let bond_policy_version =
        u32::try_from(bond_policy_version).map_err(|_| InventoryStoreErrorV1::CorruptState)?;
    let record = ReservationRecord {
        reservation_id,
        authority_id,
        route_id: blob32(route_id)?,
        scope_v2,
        rfq_id: blob32(rfq_id)?,
        quote_id: blob32(quote_id)?,
        quote_bytes,
        terms_context_digest: blob32(terms_context_digest)?,
        registry_manifest_digest: blob32(registry_manifest_digest)?,
        profile_bundle_digest: blob32(profile_bundle_digest)?,
        bond_policy_hash: blob32(bond_policy_hash)?,
        bond_policy_version,
        bond_key: InventoryKeyV1 {
            authority_id,
            chain_id: ChainId(blob32(bond_chain_id)?),
            asset_id: AssetId(blob32(bond_asset_id)?),
        },
        bond_asset_binding_digest: blob32(bond_asset_binding_digest)?,
        required_bond_amount: blob_u128(required_bond_amount)?,
        expires_at_unix_ms: from_sql_u64(expires_at_unix_ms)?,
        state: state_from_sql(state_tag)?,
        revision: from_sql_u64(revision)?,
        creation_fencing_epoch: from_sql_u64(creation_fencing_epoch)?,
        accepted_terms_digest: optional_blob32(accepted_terms_digest)?,
        binding_evidence_digest: optional_blob32(binding_evidence_digest)?,
        execution_fencing_epoch: execution_fencing_epoch.map(from_sql_u64).transpose()?,
        reauthorization_evidence_digest: optional_blob32(reauthorization_evidence_digest)?,
        release_evidence_digest: optional_blob32(release_evidence_digest)?,
        execution_id: optional_blob32(execution_id)?,
        execution_evidence_digest: optional_blob32(execution_evidence_digest)?,
        execution_finalized_height: execution_finalized_height.map(from_sql_u64).transpose()?,
        reservation_digest: blob32(stored_digest)?,
        allocations,
    };
    validate_reservation_record(&record)?;
    Ok(Some(record))
}

fn load_allocations(
    transaction: &Connection,
    reservation_id: Digest32,
    authority_id: ParticipantId,
) -> Result<Vec<AllocationRecord>, InventoryStoreErrorV1> {
    let mut statement = transaction.prepare(
        "SELECT position, authority_id, chain_id, asset_id, purpose_tag,
                amount, snapshot_revision, snapshot_height,
                snapshot_evidence_digest, asset_binding_digest,
                consumption_sequence
         FROM inventory_allocations
         WHERE reservation_id = ?1 ORDER BY position ASC
         LIMIT ?2",
    )?;
    let rows = statement.query_map(
        params![
            reservation_id.as_slice(),
            i64::try_from(MAX_RESERVATION_ALLOCATIONS_V1 + 1)
                .map_err(|_| InventoryStoreErrorV1::CorruptState)?
        ],
        |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, Vec<u8>>(2)?,
                row.get::<_, Vec<u8>>(3)?,
                row.get::<_, i64>(4)?,
                row.get::<_, Vec<u8>>(5)?,
                row.get::<_, i64>(6)?,
                row.get::<_, i64>(7)?,
                row.get::<_, Vec<u8>>(8)?,
                row.get::<_, Vec<u8>>(9)?,
                row.get::<_, Option<i64>>(10)?,
            ))
        },
    )?;
    let raw = rows.collect::<Result<Vec<_>, _>>()?;
    if raw.is_empty() || raw.len() > MAX_RESERVATION_ALLOCATIONS_V1 {
        return Err(InventoryStoreErrorV1::CorruptState);
    }
    let mut allocations = Vec::with_capacity(raw.len());
    for (
        index,
        (
            position,
            stored_authority,
            chain_id,
            asset_id,
            purpose,
            amount,
            snapshot_revision,
            snapshot_height,
            snapshot_evidence_digest,
            asset_binding_digest,
            consumption_sequence,
        ),
    ) in raw.into_iter().enumerate()
    {
        if from_sql_u64(position)? != index as u64 || blob32(stored_authority)? != authority_id.0 {
            return Err(InventoryStoreErrorV1::CorruptState);
        }
        let key = InventoryKeyV1 {
            authority_id,
            chain_id: ChainId(blob32(chain_id)?),
            asset_id: AssetId(blob32(asset_id)?),
        };
        allocations.push(AllocationRecord {
            capability: InventoryAllocationCapabilityV1 {
                key,
                purpose: purpose_from_sql(purpose)?,
                amount: blob_u128(amount)?,
                reserved_snapshot: InventorySnapshotRefV1 {
                    key,
                    revision: from_sql_u64(snapshot_revision)?,
                    canonical_height: from_sql_u64(snapshot_height)?,
                    evidence_digest: blob32(snapshot_evidence_digest)?,
                    asset_binding_digest: blob32(asset_binding_digest)?,
                },
            },
            consumption_sequence: consumption_sequence.map(from_sql_u64).transpose()?,
        });
    }
    Ok(allocations)
}

fn load_reservation_scope_v2(
    transaction: &Connection,
    reservation_id: Digest32,
) -> Result<Option<ReservationScopeV2>, InventoryStoreErrorV1> {
    let row: Option<(Vec<u8>, i64)> = transaction
        .query_row(
            "SELECT composition_id, settlement_position
             FROM inventory_reservation_scopes_v2 WHERE reservation_id = ?1",
            params![reservation_id.as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    row.map(|(composition_id, position)| {
        let position = match position {
            1 => SettlementPositionV2::Upstream,
            2 => SettlementPositionV2::Downstream,
            _ => return Err(InventoryStoreErrorV1::CorruptState),
        };
        let composition_id = blob32(composition_id)?;
        validate_digest(composition_id)?;
        Ok(ReservationScopeV2 {
            composition_id,
            position,
        })
    })
    .transpose()
}

fn load_owned_reservation(
    transaction: &Transaction<'_>,
    lease: InventoryLeaseV1,
    reservation_id: Digest32,
) -> Result<ReservationRecord, InventoryStoreErrorV1> {
    let record = load_reservation_transaction(transaction, reservation_id)?
        .ok_or(InventoryStoreErrorV1::ReservationNotFound)?;
    if record.authority_id != lease.authority_id {
        return Err(InventoryStoreErrorV1::ReservationNotFound);
    }
    Ok(record)
}

fn require_reservation_revision(
    record: &ReservationRecord,
    expected_revision: u64,
) -> Result<(), InventoryStoreErrorV1> {
    if record.revision != expected_revision {
        Err(InventoryStoreErrorV1::RevisionConflict)
    } else {
        Ok(())
    }
}

fn insert_reservation(
    transaction: &Transaction<'_>,
    record: &ReservationRecord,
    now_unix_ms: u64,
) -> Result<(), InventoryStoreErrorV1> {
    validate_reservation_record(record)?;
    transaction.execute(
        "INSERT INTO inventory_reservations
         (reservation_id, authority_id, route_id, rfq_id, quote_id,
          quote_bytes, terms_context_digest, registry_manifest_digest,
          profile_bundle_digest, bond_policy_hash, bond_policy_version,
          bond_chain_id, bond_asset_id, bond_asset_binding_digest,
          required_bond_amount,
          expires_at_unix_ms, state_tag, revision, creation_fencing_epoch,
          accepted_terms_digest, binding_evidence_digest,
          execution_fencing_epoch, reauthorization_evidence_digest,
          release_evidence_digest, execution_id, execution_evidence_digest,
          execution_finalized_height, reservation_digest,
          created_at_unix_ms, updated_at_unix_ms)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11,
                 ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21,
                 ?22, ?23, ?24, ?25, ?26, ?27, ?28, ?29, ?29)",
        params![
            record.reservation_id.as_slice(),
            record.authority_id.0.as_slice(),
            record.route_id.as_slice(),
            record.rfq_id.as_slice(),
            record.quote_id.as_slice(),
            record.quote_bytes.as_slice(),
            record.terms_context_digest.as_slice(),
            record.registry_manifest_digest.as_slice(),
            record.profile_bundle_digest.as_slice(),
            record.bond_policy_hash.as_slice(),
            i64::from(record.bond_policy_version),
            record.bond_key.chain_id.0.as_slice(),
            record.bond_key.asset_id.0.as_slice(),
            record.bond_asset_binding_digest.as_slice(),
            u128_blob(record.required_bond_amount).as_slice(),
            to_sql_u64(record.expires_at_unix_ms)?,
            i64::from(state_tag(record.state)),
            to_sql_u64(record.revision)?,
            to_sql_u64(record.creation_fencing_epoch)?,
            record.accepted_terms_digest.map(|value| value.to_vec()),
            record.binding_evidence_digest.map(|value| value.to_vec()),
            record.execution_fencing_epoch.map(to_sql_u64).transpose()?,
            record
                .reauthorization_evidence_digest
                .map(|value| value.to_vec()),
            record.release_evidence_digest.map(|value| value.to_vec()),
            record.execution_id.map(|value| value.to_vec()),
            record.execution_evidence_digest.map(|value| value.to_vec()),
            record
                .execution_finalized_height
                .map(to_sql_u64)
                .transpose()?,
            record.reservation_digest.as_slice(),
            to_sql_u64(now_unix_ms)?
        ],
    )?;
    if let Some(scope) = record.scope_v2 {
        transaction.execute(
            "INSERT INTO inventory_reservation_scopes_v2
             (reservation_id, composition_id, settlement_position)
             VALUES (?1, ?2, ?3)",
            params![
                record.reservation_id.as_slice(),
                scope.composition_id.as_slice(),
                i64::from(scope.position as u8),
            ],
        )?;
    }
    for (position, allocation) in record.allocations.iter().enumerate() {
        transaction.execute(
            "INSERT INTO inventory_allocations
             (reservation_id, position, authority_id, chain_id, asset_id,
              purpose_tag, amount, snapshot_revision, snapshot_height,
              snapshot_evidence_digest, asset_binding_digest,
              consumption_sequence)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, NULL)",
            params![
                record.reservation_id.as_slice(),
                to_sql_u64(position as u64)?,
                allocation.capability.key.authority_id.0.as_slice(),
                allocation.capability.key.chain_id.0.as_slice(),
                allocation.capability.key.asset_id.0.as_slice(),
                i64::from(purpose_tag(allocation.capability.purpose)),
                u128_blob(allocation.capability.amount).as_slice(),
                to_sql_u64(allocation.capability.reserved_snapshot.revision)?,
                to_sql_u64(allocation.capability.reserved_snapshot.canonical_height)?,
                allocation
                    .capability
                    .reserved_snapshot
                    .evidence_digest
                    .as_slice(),
                allocation
                    .capability
                    .reserved_snapshot
                    .asset_binding_digest
                    .as_slice()
            ],
        )?;
    }
    Ok(())
}

fn update_reservation(
    transaction: &Transaction<'_>,
    record: &ReservationRecord,
    expected_revision: u64,
    now_unix_ms: u64,
) -> Result<(), InventoryStoreErrorV1> {
    validate_reservation_record(record)?;
    let changed = transaction.execute(
        "UPDATE inventory_reservations
         SET state_tag = ?2, revision = ?3, accepted_terms_digest = ?4,
             binding_evidence_digest = ?5, execution_fencing_epoch = ?6,
             reauthorization_evidence_digest = ?7,
             release_evidence_digest = ?8, execution_id = ?9,
             execution_evidence_digest = ?10,
             execution_finalized_height = ?11, reservation_digest = ?12,
             updated_at_unix_ms = ?13
         WHERE reservation_id = ?1 AND revision = ?14",
        params![
            record.reservation_id.as_slice(),
            i64::from(state_tag(record.state)),
            to_sql_u64(record.revision)?,
            record.accepted_terms_digest.map(|value| value.to_vec()),
            record.binding_evidence_digest.map(|value| value.to_vec()),
            record.execution_fencing_epoch.map(to_sql_u64).transpose()?,
            record
                .reauthorization_evidence_digest
                .map(|value| value.to_vec()),
            record.release_evidence_digest.map(|value| value.to_vec()),
            record.execution_id.map(|value| value.to_vec()),
            record.execution_evidence_digest.map(|value| value.to_vec()),
            record
                .execution_finalized_height
                .map(to_sql_u64)
                .transpose()?,
            record.reservation_digest.as_slice(),
            to_sql_u64(now_unix_ms)?,
            to_sql_u64(expected_revision)?
        ],
    )?;
    if changed != 1 {
        return Err(InventoryStoreErrorV1::RevisionConflict);
    }
    Ok(())
}

fn update_allocation_consumption_sequences(
    transaction: &Transaction<'_>,
    record: &ReservationRecord,
) -> Result<(), InventoryStoreErrorV1> {
    for (position, allocation) in record.allocations.iter().enumerate() {
        let sequence = allocation
            .consumption_sequence
            .ok_or(InventoryStoreErrorV1::CorruptState)?;
        let changed = transaction.execute(
            "UPDATE inventory_allocations
             SET consumption_sequence = ?3
             WHERE reservation_id = ?1 AND position = ?2
               AND consumption_sequence IS NULL",
            params![
                record.reservation_id.as_slice(),
                to_sql_u64(position as u64)?,
                to_sql_u64(sequence)?
            ],
        )?;
        if changed != 1 {
            return Err(InventoryStoreErrorV1::CorruptState);
        }
    }
    Ok(())
}

fn update_issued_consumption_sequence(
    transaction: &Transaction<'_>,
    snapshot: InventorySnapshotV1,
    next_sequence: u64,
    now_unix_ms: u64,
) -> Result<(), InventoryStoreErrorV1> {
    let observation = InventoryObservationV1 {
        key: snapshot.key,
        spendable_amount: snapshot.spendable_amount,
        canonical_height: snapshot.canonical_height,
        canonical_anchor_digest: snapshot.canonical_anchor_digest,
        evidence_digest: snapshot.evidence_digest,
        registry_manifest_digest: snapshot.registry_manifest_digest,
        profile_bundle_digest: snapshot.profile_bundle_digest,
        asset_binding_digest: snapshot.asset_binding_digest,
        observed_at_unix_ms: snapshot.observed_at_unix_ms,
        valid_until_unix_ms: snapshot.valid_until_unix_ms,
        acknowledged_consumption_sequence: snapshot.acknowledged_consumption_sequence,
        kind: InventoryObservationKindV1::Forward,
    };
    let row_digest = account_row_digest(
        &observation,
        snapshot.revision,
        next_sequence,
        snapshot.acknowledged_consumption_sequence,
    );
    let changed = transaction.execute(
        "UPDATE inventory_accounts
         SET issued_consumption_sequence = ?4, row_digest = ?5,
             updated_at_unix_ms = ?6
         WHERE authority_id = ?1 AND chain_id = ?2 AND asset_id = ?3
           AND issued_consumption_sequence = ?7",
        params![
            snapshot.key.authority_id.0.as_slice(),
            snapshot.key.chain_id.0.as_slice(),
            snapshot.key.asset_id.0.as_slice(),
            to_sql_u64(next_sequence)?,
            row_digest.as_slice(),
            to_sql_u64(now_unix_ms)?,
            to_sql_u64(snapshot.issued_consumption_sequence)?
        ],
    )?;
    if changed != 1 {
        return Err(InventoryStoreErrorV1::RevisionConflict);
    }
    Ok(())
}

fn configure_connection(
    connection: &Connection,
    allow_journal_transition: bool,
) -> Result<(), InventoryStoreErrorV1> {
    connection.busy_timeout(Duration::from_millis(5_000))?;
    let mode: String = if allow_journal_transition {
        connection.query_row("PRAGMA journal_mode=WAL", [], |row| row.get(0))?
    } else {
        connection.query_row("PRAGMA journal_mode", [], |row| row.get(0))?
    };
    if !mode.eq_ignore_ascii_case("wal") {
        return Err(InventoryStoreErrorV1::InvalidStorageAuthority);
    }
    configure_common(connection)?;
    audit_connection_config(connection, "wal")
}

fn configure_creation(connection: &Connection) -> Result<(), InventoryStoreErrorV1> {
    connection.busy_timeout(Duration::from_millis(5_000))?;
    let mode: String = connection.query_row("PRAGMA journal_mode=DELETE", [], |row| row.get(0))?;
    if !mode.eq_ignore_ascii_case("delete") {
        return Err(InventoryStoreErrorV1::InvalidStorageAuthority);
    }
    configure_common(connection)?;
    audit_connection_config(connection, "delete")
}

fn configure_common(connection: &Connection) -> Result<(), InventoryStoreErrorV1> {
    connection.pragma_update(None, "synchronous", "FULL")?;
    connection.pragma_update(None, "foreign_keys", "ON")?;
    connection.pragma_update(None, "read_uncommitted", "OFF")?;
    connection.pragma_update(None, "trusted_schema", "OFF")?;
    connection.pragma_update(None, "secure_delete", "ON")?;
    connection.pragma_update(None, "temp_store", "MEMORY")?;
    let defensive = rusqlite::config::DbConfig::SQLITE_DBCONFIG_DEFENSIVE;
    if !connection.set_db_config(defensive, true)? || !connection.db_config(defensive)? {
        return Err(InventoryStoreErrorV1::InvalidStorageAuthority);
    }
    Ok(())
}

fn audit_connection_config(
    connection: &Connection,
    expected_journal: &str,
) -> Result<(), InventoryStoreErrorV1> {
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
    if !journal.eq_ignore_ascii_case(expected_journal)
        || synchronous != 2
        || foreign_keys != 1
        || read_uncommitted != 0
        || trusted_schema != 0
        || secure_delete != 1
        || temp_store != 2
        || busy_timeout != 5_000
    {
        return Err(InventoryStoreErrorV1::InvalidStorageAuthority);
    }
    Ok(())
}

fn initialize_schema(
    connection: &mut Connection,
    binding_digest: Digest32,
) -> Result<(), InventoryStoreErrorV1> {
    test_creation_crash_hook("before-schema-transaction");
    let version: i64 = connection.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    if version != 0 {
        return Err(InventoryStoreErrorV1::CorruptState);
    }
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Exclusive)?;
    transaction.execute_batch(SCHEMA_SQL)?;
    transaction.execute(
        "INSERT INTO inventory_meta(singleton,schema_version,binding_digest) VALUES(1,?1,?2)",
        params![SCHEMA_VERSION, binding_digest.as_slice()],
    )?;
    transaction.pragma_update(None, "user_version", SCHEMA_VERSION)?;
    transaction.pragma_update(None, "application_id", APPLICATION_ID)?;
    test_creation_crash_hook("before-schema-commit");
    transaction.commit()?;
    test_creation_crash_hook("after-schema-commit");
    Ok(())
}

const SCHEMA_SQL: &str = r#"
                 CREATE TABLE inventory_meta (
                    singleton INTEGER PRIMARY KEY NOT NULL CHECK(singleton = 1),
                    schema_version INTEGER NOT NULL CHECK(schema_version = 2),
                    binding_digest BLOB NOT NULL CHECK(length(binding_digest) = 32)
                 ) STRICT;

                 CREATE TABLE inventory_leases (
                    authority_id BLOB PRIMARY KEY NOT NULL CHECK(length(authority_id) = 32),
                    owner_id BLOB NOT NULL CHECK(length(owner_id) = 32),
                    fencing_epoch INTEGER NOT NULL CHECK(fencing_epoch > 0),
                    lease_until_unix_ms INTEGER NOT NULL CHECK(lease_until_unix_ms >= 0),
                    updated_at_unix_ms INTEGER NOT NULL CHECK(updated_at_unix_ms >= 0)
                 ) STRICT;

                 CREATE TABLE inventory_accounts (
                    authority_id BLOB NOT NULL CHECK(length(authority_id) = 32),
                    chain_id BLOB NOT NULL CHECK(length(chain_id) = 32),
                    asset_id BLOB NOT NULL CHECK(length(asset_id) = 32),
                    revision INTEGER NOT NULL CHECK(revision > 0),
                    spendable_amount BLOB NOT NULL CHECK(length(spendable_amount) = 16),
                    canonical_height INTEGER NOT NULL CHECK(canonical_height >= 0),
                    canonical_anchor_digest BLOB NOT NULL CHECK(length(canonical_anchor_digest) = 32),
                    evidence_digest BLOB NOT NULL CHECK(length(evidence_digest) = 32),
                    registry_manifest_digest BLOB NOT NULL CHECK(length(registry_manifest_digest) = 32),
                    profile_bundle_digest BLOB NOT NULL CHECK(length(profile_bundle_digest) = 32),
                    asset_binding_digest BLOB NOT NULL CHECK(length(asset_binding_digest) = 32),
                    observed_at_unix_ms INTEGER NOT NULL CHECK(observed_at_unix_ms >= 0),
                    valid_until_unix_ms INTEGER NOT NULL CHECK(valid_until_unix_ms >= observed_at_unix_ms),
                    issued_consumption_sequence INTEGER NOT NULL CHECK(issued_consumption_sequence >= 0),
                    acknowledged_consumption_sequence INTEGER NOT NULL CHECK(acknowledged_consumption_sequence >= 0),
                    row_digest BLOB NOT NULL CHECK(length(row_digest) = 32),
                    updated_at_unix_ms INTEGER NOT NULL CHECK(updated_at_unix_ms >= 0),
                    PRIMARY KEY(authority_id, chain_id, asset_id),
                    CHECK(acknowledged_consumption_sequence <= issued_consumption_sequence)
                 ) STRICT;

                 CREATE TABLE inventory_reservations (
                    reservation_id BLOB PRIMARY KEY NOT NULL CHECK(length(reservation_id) = 32),
                    authority_id BLOB NOT NULL CHECK(length(authority_id) = 32),
                    route_id BLOB NOT NULL CHECK(length(route_id) = 32),
                    rfq_id BLOB NOT NULL CHECK(length(rfq_id) = 32),
                    quote_id BLOB NOT NULL CHECK(length(quote_id) = 32),
                    quote_bytes BLOB NOT NULL CHECK(length(quote_bytes) BETWEEN 1 AND 2048),
                    terms_context_digest BLOB NOT NULL CHECK(length(terms_context_digest) = 32),
                    registry_manifest_digest BLOB NOT NULL CHECK(length(registry_manifest_digest) = 32),
                    profile_bundle_digest BLOB NOT NULL CHECK(length(profile_bundle_digest) = 32),
                    bond_policy_hash BLOB NOT NULL CHECK(length(bond_policy_hash) = 32),
                    bond_policy_version INTEGER NOT NULL CHECK(bond_policy_version > 0),
                    bond_chain_id BLOB NOT NULL CHECK(length(bond_chain_id) = 32),
                    bond_asset_id BLOB NOT NULL CHECK(length(bond_asset_id) = 32),
                    bond_asset_binding_digest BLOB NOT NULL CHECK(length(bond_asset_binding_digest) = 32),
                    required_bond_amount BLOB NOT NULL CHECK(length(required_bond_amount) = 16),
                    expires_at_unix_ms INTEGER NOT NULL CHECK(expires_at_unix_ms >= 0),
                    state_tag INTEGER NOT NULL CHECK(state_tag IN (0, 1, 2, 3)),
                    revision INTEGER NOT NULL CHECK(revision > 0),
                    creation_fencing_epoch INTEGER NOT NULL CHECK(creation_fencing_epoch > 0),
                    accepted_terms_digest BLOB CHECK(accepted_terms_digest IS NULL OR length(accepted_terms_digest) = 32),
                    binding_evidence_digest BLOB CHECK(binding_evidence_digest IS NULL OR length(binding_evidence_digest) = 32),
                    execution_fencing_epoch INTEGER CHECK(execution_fencing_epoch IS NULL OR execution_fencing_epoch > 0),
                    reauthorization_evidence_digest BLOB CHECK(reauthorization_evidence_digest IS NULL OR length(reauthorization_evidence_digest) = 32),
                    release_evidence_digest BLOB CHECK(release_evidence_digest IS NULL OR length(release_evidence_digest) = 32),
                    execution_id BLOB CHECK(execution_id IS NULL OR length(execution_id) = 32),
                    execution_evidence_digest BLOB CHECK(execution_evidence_digest IS NULL OR length(execution_evidence_digest) = 32),
                    execution_finalized_height INTEGER CHECK(execution_finalized_height IS NULL OR execution_finalized_height >= 0),
                    reservation_digest BLOB NOT NULL CHECK(length(reservation_digest) = 32),
                    created_at_unix_ms INTEGER NOT NULL CHECK(created_at_unix_ms >= 0),
                    updated_at_unix_ms INTEGER NOT NULL CHECK(updated_at_unix_ms >= 0),
                    CHECK((state_tag = 0 AND accepted_terms_digest IS NULL
                           AND binding_evidence_digest IS NULL
                           AND execution_fencing_epoch IS NULL)
                          OR (state_tag IN (1, 2) AND accepted_terms_digest IS NOT NULL
                              AND binding_evidence_digest IS NOT NULL
                              AND execution_fencing_epoch IS NOT NULL)
                          OR state_tag = 3),
                    CHECK((state_tag = 2 AND execution_id IS NOT NULL
                           AND execution_evidence_digest IS NOT NULL
                           AND execution_finalized_height IS NOT NULL)
                          OR (state_tag != 2 AND execution_id IS NULL
                              AND execution_evidence_digest IS NULL
                              AND execution_finalized_height IS NULL))
                 ) STRICT;

                 CREATE TABLE inventory_reservation_scopes_v2 (
                    reservation_id BLOB PRIMARY KEY NOT NULL
                        REFERENCES inventory_reservations(reservation_id) ON DELETE RESTRICT,
                    composition_id BLOB NOT NULL CHECK(length(composition_id) = 32),
                    settlement_position INTEGER NOT NULL CHECK(settlement_position IN (1, 2)),
                    CHECK(composition_id != zeroblob(32))
                 ) STRICT;

                 CREATE TABLE inventory_allocations (
                    reservation_id BLOB NOT NULL
                        REFERENCES inventory_reservations(reservation_id) ON DELETE RESTRICT,
                    position INTEGER NOT NULL CHECK(position >= 0),
                    authority_id BLOB NOT NULL CHECK(length(authority_id) = 32),
                    chain_id BLOB NOT NULL CHECK(length(chain_id) = 32),
                    asset_id BLOB NOT NULL CHECK(length(asset_id) = 32),
                    purpose_tag INTEGER NOT NULL CHECK(purpose_tag IN (0, 1)),
                    amount BLOB NOT NULL CHECK(length(amount) = 16),
                    snapshot_revision INTEGER NOT NULL CHECK(snapshot_revision > 0),
                    snapshot_height INTEGER NOT NULL CHECK(snapshot_height >= 0),
                    snapshot_evidence_digest BLOB NOT NULL CHECK(length(snapshot_evidence_digest) = 32),
                    asset_binding_digest BLOB NOT NULL CHECK(length(asset_binding_digest) = 32),
                    consumption_sequence INTEGER CHECK(consumption_sequence IS NULL OR consumption_sequence > 0),
                    PRIMARY KEY(reservation_id, position),
                    UNIQUE(reservation_id, authority_id, chain_id, asset_id, purpose_tag)
                 ) STRICT;

                 CREATE INDEX inventory_allocations_account_idx
                    ON inventory_allocations(authority_id, chain_id, asset_id, reservation_id);

                 CREATE TABLE inventory_operations (
                    authority_id BLOB NOT NULL CHECK(length(authority_id) = 32),
                    operation_id BLOB NOT NULL CHECK(length(operation_id) = 32),
                    request_digest BLOB NOT NULL CHECK(length(request_digest) = 32),
                    result_revision INTEGER NOT NULL CHECK(result_revision > 0),
                    reservation_id BLOB CHECK(reservation_id IS NULL OR length(reservation_id) = 32),
                    created_at_unix_ms INTEGER NOT NULL CHECK(created_at_unix_ms >= 0),
                    PRIMARY KEY(authority_id, operation_id)
                 ) STRICT;
"#;

const LEGACY_META_TABLE_SQL_V1: &str = r#"
CREATE TABLE inventory_meta (
                    singleton INTEGER PRIMARY KEY NOT NULL CHECK(singleton = 1),
                    schema_version INTEGER NOT NULL CHECK(schema_version = 1),
                    binding_digest BLOB NOT NULL CHECK(length(binding_digest) = 32)
                 ) STRICT;
"#;

const MIGRATE_SCHEMA_V1_TO_V2_SQL: &str = r#"
ALTER TABLE inventory_meta RENAME TO inventory_meta_v1;
CREATE TABLE inventory_meta (
                    singleton INTEGER PRIMARY KEY NOT NULL CHECK(singleton = 1),
                    schema_version INTEGER NOT NULL CHECK(schema_version = 2),
                    binding_digest BLOB NOT NULL CHECK(length(binding_digest) = 32)
                 ) STRICT;
INSERT INTO inventory_meta(singleton, schema_version, binding_digest)
    SELECT singleton, 2, binding_digest FROM inventory_meta_v1;
DROP TABLE inventory_meta_v1;
CREATE TABLE inventory_reservation_scopes_v2 (
                    reservation_id BLOB PRIMARY KEY NOT NULL
                        REFERENCES inventory_reservations(reservation_id) ON DELETE RESTRICT,
                    composition_id BLOB NOT NULL CHECK(length(composition_id) = 32),
                    settlement_position INTEGER NOT NULL CHECK(settlement_position IN (1, 2)),
                    CHECK(composition_id != zeroblob(32))
                 ) STRICT;
PRAGMA user_version = 2;
"#;

fn audit_schema_v1(
    connection: &Connection,
    expected_binding_digest: Digest32,
) -> Result<(), InventoryStoreErrorV1> {
    let integrity: String = connection.query_row("PRAGMA integrity_check", [], |row| row.get(0))?;
    let mut foreign_key_check = connection.prepare("PRAGMA foreign_key_check")?;
    let foreign_key_violation = foreign_key_check.exists([])?;
    let version: i64 = connection.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    let application_id: i64 =
        connection.query_row("PRAGMA application_id", [], |row| row.get(0))?;
    let meta: (i64, Vec<u8>) = connection.query_row(
        "SELECT schema_version,binding_digest FROM inventory_meta WHERE singleton=1",
        [],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    if integrity != "ok"
        || foreign_key_violation
        || version != 1
        || application_id != APPLICATION_ID
        || meta.0 != 1
    {
        return Err(InventoryStoreErrorV1::UnsupportedFormat);
    }
    if blob32(meta.1)? != expected_binding_digest {
        return Err(InventoryStoreErrorV1::BindingMismatch);
    }
    let actual = schema_objects(connection)?;
    let reference_v2 = Connection::open_in_memory()?;
    reference_v2.execute_batch(SCHEMA_SQL)?;
    let mut expected = schema_objects(&reference_v2)?;
    expected.retain(|(_, name, _, _)| {
        name != "inventory_meta" && name != "inventory_reservation_scopes_v2"
    });
    let reference_meta = Connection::open_in_memory()?;
    reference_meta.execute_batch(LEGACY_META_TABLE_SQL_V1)?;
    expected.extend(schema_objects(&reference_meta)?);
    if actual != expected {
        return Err(InventoryStoreErrorV1::CorruptState);
    }
    Ok(())
}

fn audit_schema(
    connection: &Connection,
    expected_binding_digest: Digest32,
) -> Result<(), InventoryStoreErrorV1> {
    let integrity: String = connection.query_row("PRAGMA integrity_check", [], |row| row.get(0))?;
    let mut foreign_key_check = connection.prepare("PRAGMA foreign_key_check")?;
    let foreign_key_violation = foreign_key_check.exists([])?;
    let version: i64 = connection.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    let application_id: i64 =
        connection.query_row("PRAGMA application_id", [], |row| row.get(0))?;
    let meta: (i64, Vec<u8>) = connection.query_row(
        "SELECT schema_version,binding_digest FROM inventory_meta WHERE singleton=1",
        [],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    if integrity != "ok"
        || foreign_key_violation
        || version != SCHEMA_VERSION
        || application_id != APPLICATION_ID
        || meta.0 != SCHEMA_VERSION
    {
        return Err(InventoryStoreErrorV1::CorruptState);
    }
    if blob32(meta.1)? != expected_binding_digest {
        return Err(InventoryStoreErrorV1::BindingMismatch);
    }
    let actual = schema_objects(connection)?;
    let reference = Connection::open_in_memory()?;
    reference.execute_batch(SCHEMA_SQL)?;
    let expected = schema_objects(&reference)?;
    if actual != expected {
        return Err(InventoryStoreErrorV1::CorruptState);
    }
    Ok(())
}

type SchemaObject = (String, String, String, String);

fn schema_objects(
    connection: &Connection,
) -> Result<BTreeSet<SchemaObject>, InventoryStoreErrorV1> {
    const MAX_OBJECTS: i64 = 16;
    const MAX_SCHEMA_BYTES: i64 = 262_144;
    let (count, maximum, total): (i64, Option<i64>, Option<i64>) = connection.query_row(
        "SELECT COUNT(*),MAX(length(sql)),SUM(length(sql))
         FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%'",
        [],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    )?;
    if !(0..=MAX_OBJECTS).contains(&count)
        || maximum.is_some_and(|value| !(0..=MAX_SCHEMA_BYTES).contains(&value))
        || total.is_some_and(|value| !(0..=MAX_SCHEMA_BYTES).contains(&value))
    {
        return Err(InventoryStoreErrorV1::CorruptState);
    }
    let mut statement = connection.prepare(
        "SELECT type,name,tbl_name,sql FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%'",
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
            return Err(InventoryStoreErrorV1::CorruptState);
        }
    }
    Ok(objects)
}

fn require_no_economic_state(connection: &Connection) -> Result<(), InventoryStoreErrorV1> {
    let count: i64 = connection.query_row(
        "SELECT
           (SELECT COUNT(*) FROM inventory_leases) +
           (SELECT COUNT(*) FROM inventory_accounts) +
           (SELECT COUNT(*) FROM inventory_reservations) +
           (SELECT COUNT(*) FROM inventory_allocations) +
           (SELECT COUNT(*) FROM inventory_operations)",
        [],
        |row| row.get(0),
    )?;
    if count != 0 {
        return Err(InventoryStoreErrorV1::CorruptState);
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn validate_parent(path: &Path) -> Result<(), InventoryStoreErrorV1> {
    if !path.is_absolute() || path.file_name().is_none() {
        return Err(InventoryStoreErrorV1::InvalidStorageAuthority);
    }
    let parent = path
        .parent()
        .ok_or(InventoryStoreErrorV1::InvalidStorageAuthority)?;
    let canonical = parent
        .canonicalize()
        .map_err(|_| InventoryStoreErrorV1::InvalidStorageAuthority)?;
    let metadata = std::fs::symlink_metadata(parent)
        .map_err(|_| InventoryStoreErrorV1::InvalidStorageAuthority)?;
    if canonical != parent
        || !metadata.file_type().is_dir()
        || metadata.file_type().is_symlink()
        || metadata.uid() != geteuid().as_raw()
        || metadata.mode() & 0o7777 != DIRECTORY_MODE
    {
        return Err(InventoryStoreErrorV1::InvalidStorageAuthority);
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn validate_authority_file(path: &Path, file: &File) -> Result<(), InventoryStoreErrorV1> {
    let path_metadata = std::fs::symlink_metadata(path)
        .map_err(|_| InventoryStoreErrorV1::InvalidStorageAuthority)?;
    let file_metadata = file
        .metadata()
        .map_err(|_| InventoryStoreErrorV1::InvalidStorageAuthority)?;
    let stat = fstat(file.as_fd()).map_err(|_| InventoryStoreErrorV1::InvalidStorageAuthority)?;
    if path_metadata.file_type().is_symlink()
        || !path_metadata.file_type().is_file()
        || !file_metadata.file_type().is_file()
        || FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile
        || path_metadata.uid() != geteuid().as_raw()
        || file_metadata.uid() != geteuid().as_raw()
        || stat.st_uid != geteuid().as_raw()
        || path_metadata.nlink() != 1
        || file_metadata.nlink() != 1
        || stat.st_nlink != 1
        || path_metadata.mode() & 0o7777 != FILE_MODE
        || file_metadata.mode() & 0o7777 != FILE_MODE
        || Mode::from_raw_mode(stat.st_mode).bits() & 0o7777 != FILE_MODE
        || path_metadata.dev() != file_metadata.dev()
        || path_metadata.ino() != file_metadata.ino()
    {
        return Err(InventoryStoreErrorV1::InvalidStorageAuthority);
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn retained_identity(file: &File) -> Result<RetainedFileIdentityV1, InventoryStoreErrorV1> {
    let metadata = file
        .metadata()
        .map_err(|_| InventoryStoreErrorV1::InvalidStorageAuthority)?;
    Ok(RetainedFileIdentityV1 {
        device: metadata.dev(),
        inode: metadata.ino(),
    })
}

#[cfg(target_os = "linux")]
fn named_identity(path: &Path) -> Result<RetainedFileIdentityV1, InventoryStoreErrorV1> {
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|_| InventoryStoreErrorV1::InvalidStorageAuthority)?;
    if metadata.file_type().is_symlink()
        || !metadata.file_type().is_file()
        || metadata.uid() != geteuid().as_raw()
        || metadata.nlink() != 1
        || metadata.mode() & 0o7777 != FILE_MODE
    {
        return Err(InventoryStoreErrorV1::InvalidStorageAuthority);
    }
    Ok(RetainedFileIdentityV1 {
        device: metadata.dev(),
        inode: metadata.ino(),
    })
}

#[cfg(target_os = "linux")]
fn validate_retained_file(
    path: &Path,
    file: &File,
    expected: RetainedFileIdentityV1,
    require_empty: bool,
) -> Result<(), InventoryStoreErrorV1> {
    validate_authority_file(path, file)?;
    if retained_identity(file)? != expected
        || named_identity(path)? != expected
        || (require_empty
            && file
                .metadata()
                .map_err(|_| InventoryStoreErrorV1::InvalidStorageAuthority)?
                .len()
                != 0)
    {
        return Err(InventoryStoreErrorV1::InvalidStorageAuthority);
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn lock_path(path: &Path) -> PathBuf {
    let mut bytes = path.as_os_str().to_os_string();
    bytes.push(".lock");
    PathBuf::from(bytes)
}

#[cfg(target_os = "linux")]
fn validate_lock_file(path: &Path, file: &File) -> Result<(), InventoryStoreErrorV1> {
    validate_authority_file(path, file)?;
    if file
        .metadata()
        .map_err(|_| InventoryStoreErrorV1::InvalidStorageAuthority)?
        .len()
        != 0
    {
        return Err(InventoryStoreErrorV1::InvalidStorageAuthority);
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn validate_sqlite_header(file: &File, permit_empty: bool) -> Result<(), InventoryStoreErrorV1> {
    let length = file
        .metadata()
        .map_err(|_| InventoryStoreErrorV1::InvalidStorageAuthority)?
        .len();
    if length == 0 {
        return if permit_empty {
            Ok(())
        } else {
            Err(InventoryStoreErrorV1::CreationIncomplete)
        };
    }
    if length < 16 {
        return Err(InventoryStoreErrorV1::CorruptState);
    }
    let mut retained = file
        .try_clone()
        .map_err(|_| InventoryStoreErrorV1::InvalidStorageAuthority)?;
    retained
        .seek(SeekFrom::Start(0))
        .map_err(|_| InventoryStoreErrorV1::InvalidStorageAuthority)?;
    let mut header = [0u8; 16];
    retained
        .read_exact(&mut header)
        .map_err(|_| InventoryStoreErrorV1::CorruptState)?;
    if &header != b"SQLite format 3\0" {
        return Err(InventoryStoreErrorV1::CorruptState);
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn sidecar_paths(path: &Path) -> [PathBuf; 3] {
    let mut wal = path.as_os_str().to_os_string();
    wal.push("-wal");
    let mut shm = path.as_os_str().to_os_string();
    shm.push("-shm");
    let mut journal = path.as_os_str().to_os_string();
    journal.push("-journal");
    [
        PathBuf::from(wal),
        PathBuf::from(shm),
        PathBuf::from(journal),
    ]
}

#[cfg(target_os = "linux")]
fn ensure_sidecars_absent(path: &Path) -> Result<(), InventoryStoreErrorV1> {
    if sidecar_paths(path)
        .iter()
        .any(|sidecar| std::fs::symlink_metadata(sidecar).is_ok())
    {
        return Err(InventoryStoreErrorV1::DatabasePresent);
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn validate_sidecars_for_mode(
    path: &Path,
    mode: AuthorityOpenModeV1,
) -> Result<(), InventoryStoreErrorV1> {
    for (sidecar, kind) in sidecar_paths(path).into_iter().zip([
        SqliteSidecarKindV1::Wal,
        SqliteSidecarKindV1::SharedMemory,
        SqliteSidecarKindV1::RollbackJournal,
    ]) {
        let metadata = match std::fs::symlink_metadata(&sidecar) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(_) => return Err(InventoryStoreErrorV1::InvalidStorageAuthority),
        };
        if metadata.file_type().is_symlink()
            || !metadata.file_type().is_file()
            || metadata.uid() != geteuid().as_raw()
            || metadata.nlink() != 1
            || metadata.mode() & 0o7777 != FILE_MODE
        {
            return Err(InventoryStoreErrorV1::InvalidStorageAuthority);
        }
        validate_sidecar_contents(&sidecar, kind, mode == AuthorityOpenModeV1::ResumeCreate)?;
    }
    Ok(())
}

#[cfg(target_os = "linux")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SqliteSidecarKindV1 {
    Wal,
    SharedMemory,
    RollbackJournal,
}

#[cfg(target_os = "linux")]
fn validate_sidecar_contents(
    path: &Path,
    kind: SqliteSidecarKindV1,
    permit_pristine_journal: bool,
) -> Result<(), InventoryStoreErrorV1> {
    let expected = named_identity(path)?;
    let mut file = OpenOptions::new()
        .read(true)
        .open(path)
        .map_err(|_| InventoryStoreErrorV1::InvalidStorageAuthority)?;
    if retained_identity(&file)? != expected {
        return Err(InventoryStoreErrorV1::InvalidStorageAuthority);
    }
    let length = file
        .metadata()
        .map_err(|_| InventoryStoreErrorV1::InvalidStorageAuthority)?
        .len();
    if length == 0 {
        return if retained_identity(&file)? == expected && named_identity(path)? == expected {
            Ok(())
        } else {
            Err(InventoryStoreErrorV1::InvalidStorageAuthority)
        };
    }
    if length < 28 {
        return Err(InventoryStoreErrorV1::InvalidStorageAuthority);
    }
    let mut header = [0u8; 28];
    file.read_exact(&mut header)
        .map_err(|_| InventoryStoreErrorV1::InvalidStorageAuthority)?;
    let valid = match kind {
        SqliteSidecarKindV1::Wal => {
            let magic = u32::from_be_bytes(
                header[..4]
                    .try_into()
                    .map_err(|_| InventoryStoreErrorV1::InvalidStorageAuthority)?,
            );
            let version = u32::from_be_bytes(
                header[4..8]
                    .try_into()
                    .map_err(|_| InventoryStoreErrorV1::InvalidStorageAuthority)?,
            );
            let encoded_page_size = u32::from_be_bytes(
                header[8..12]
                    .try_into()
                    .map_err(|_| InventoryStoreErrorV1::InvalidStorageAuthority)?,
            );
            let page_size = if encoded_page_size == 1 {
                65_536
            } else {
                u64::from(encoded_page_size)
            };
            matches!(magic, 0x377f_0682 | 0x377f_0683)
                && version == 3_007_000
                && (512..=65_536).contains(&page_size)
                && page_size.is_power_of_two()
                && header[16..24] != [0; 8]
                && length >= 32
                && (length - 32) % (24 + page_size) == 0
        }
        SqliteSidecarKindV1::SharedMemory => {
            length >= 32_768
                && length % 32_768 == 0
                && u32::from_ne_bytes(
                    header[..4]
                        .try_into()
                        .map_err(|_| InventoryStoreErrorV1::InvalidStorageAuthority)?,
                ) == 3_007_000
                && header[12] <= 1
        }
        SqliteSidecarKindV1::RollbackJournal => {
            header[..8] == [0xd9, 0xd5, 0x05, 0xf9, 0x20, 0xa1, 0x63, 0xd7]
                || (permit_pristine_journal
                    && pristine_rollback_journal(&mut file, length, &header)?)
        }
    };
    if !valid || retained_identity(&file)? != expected || named_identity(path)? != expected {
        return Err(InventoryStoreErrorV1::InvalidStorageAuthority);
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn pristine_rollback_journal(
    file: &mut File,
    length: u64,
    header: &[u8; 28],
) -> Result<bool, InventoryStoreErrorV1> {
    if length != 512
        || header[..12] != [0; 12]
        || header[12..16] == [0; 4]
        || header[16..20] != [0; 4]
        || header[20..24] != 512u32.to_be_bytes()
        || header[24..28] != 4096u32.to_be_bytes()
    {
        return Ok(false);
    }
    let mut tail = [0u8; 512 - 28];
    file.read_exact(&mut tail)
        .map_err(|_| InventoryStoreErrorV1::InvalidStorageAuthority)?;
    Ok(tail == [0; 512 - 28])
}

#[cfg(target_os = "linux")]
fn sync_parent(path: &Path) -> Result<(), InventoryStoreErrorV1> {
    let parent = path
        .parent()
        .ok_or(InventoryStoreErrorV1::InvalidStorageAuthority)?;
    let directory =
        File::open(parent).map_err(|_| InventoryStoreErrorV1::InvalidStorageAuthority)?;
    directory
        .sync_all()
        .map_err(|_| InventoryStoreErrorV1::InvalidStorageAuthority)
}

#[cfg(test)]
fn test_creation_crash_hook(boundary: &str) {
    if std::env::var("DOM_SOLVER_INVENTORY_TEST_CRASH_BOUNDARY").as_deref() == Ok(boundary) {
        std::process::exit(86);
    }
}

#[cfg(not(test))]
fn test_creation_crash_hook(_boundary: &str) {}

#[cfg(test)]
fn test_migration_crash_hook(boundary: &str) {
    if std::env::var("DOM_SOLVER_INVENTORY_TEST_MIGRATION_CRASH_BOUNDARY").as_deref()
        == Ok(boundary)
    {
        std::process::exit(87);
    }
}

#[cfg(not(test))]
fn test_migration_crash_hook(_boundary: &str) {}

#[cfg(all(test, target_os = "linux"))]
mod provisioning_tests {
    use std::error::Error;
    use std::io::Write;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    use super::*;

    type TestResult = core::result::Result<(), Box<dyn Error>>;

    fn owner_directory() -> core::result::Result<tempfile::TempDir, std::io::Error> {
        let directory = tempfile::tempdir()?;
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))?;
        Ok(directory)
    }

    fn create_exact_file(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(FILE_MODE)
            .open(path)?;
        file.write_all(bytes)?;
        file.sync_all()
    }

    fn pristine_journal() -> [u8; 512] {
        let mut journal = [0u8; 512];
        journal[12..16].copy_from_slice(&[1, 2, 3, 4]);
        journal[20..24].copy_from_slice(&512u32.to_be_bytes());
        journal[24..28].copy_from_slice(&4096u32.to_be_bytes());
        journal
    }

    fn downgrade_exact_v2_schema_to_v1(path: &Path) -> TestResult {
        let mut connection = Connection::open(path)?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Exclusive)?;
        transaction.execute_batch(
            r#"
DROP TABLE inventory_reservation_scopes_v2;
ALTER TABLE inventory_meta RENAME TO inventory_meta_v2;
CREATE TABLE inventory_meta (
                    singleton INTEGER PRIMARY KEY NOT NULL CHECK(singleton = 1),
                    schema_version INTEGER NOT NULL CHECK(schema_version = 1),
                    binding_digest BLOB NOT NULL CHECK(length(binding_digest) = 32)
                 ) STRICT;
INSERT INTO inventory_meta(singleton, schema_version, binding_digest)
    SELECT singleton, 1, binding_digest FROM inventory_meta_v2;
DROP TABLE inventory_meta_v2;
PRAGMA user_version = 1;
"#,
        )?;
        transaction.commit()?;
        Ok(())
    }

    fn make_v1_store_with_economic_state(path: &Path, binding: Digest32) -> TestResult {
        let mut store = DurableInventoryStoreV1::create(path, binding)?;
        let authority = ParticipantId([0x41; 32]);
        let lease = store
            .acquire_lease(authority, [0x42; 32], 1_000, 10_000)?
            .lease();
        let observation = InventoryObservationV1 {
            key: InventoryKeyV1 {
                chain_id: ChainId([0x43; 32]),
                asset_id: AssetId([0x44; 32]),
                authority_id: authority,
            },
            spendable_amount: 500,
            canonical_height: 7,
            canonical_anchor_digest: [0x45; 32],
            evidence_digest: [0x46; 32],
            registry_manifest_digest: [0x47; 32],
            profile_bundle_digest: [0x48; 32],
            asset_binding_digest: [0x49; 32],
            observed_at_unix_ms: 1_000,
            valid_until_unix_ms: 9_000,
            acknowledged_consumption_sequence: 0,
            kind: InventoryObservationKindV1::Forward,
        };
        store.reconcile_snapshot(lease, 0, [0x4a; 32], &observation, 1_000)?;
        drop(store);
        downgrade_exact_v2_schema_to_v1(path)
    }

    fn assert_resume_rejects_journal(bytes: &[u8]) -> TestResult {
        let directory = owner_directory()?;
        let path = directory.path().join("inventory.sqlite");
        create_exact_file(&lock_path(&path), &[])?;
        create_exact_file(&path, &[])?;
        create_exact_file(&sidecar_paths(&path)[2], bytes)?;
        if DurableInventoryStoreV1::resume_create_production(&path, [0xd1; 32]).is_ok() {
            return Err(std::io::Error::other("resume accepted malformed journal").into());
        }
        Ok(())
    }

    #[test]
    fn creation_crash_child() -> TestResult {
        let Some(path) = std::env::var_os("DOM_SOLVER_INVENTORY_TEST_CRASH_PATH") else {
            return Ok(());
        };
        let store = DurableInventoryStoreV1::create(Path::new(&path), [0xa1; 32])?;
        drop(store);
        Ok(())
    }

    #[test]
    fn migration_crash_child() -> TestResult {
        let Some(path) = std::env::var_os("DOM_SOLVER_INVENTORY_TEST_MIGRATION_PATH") else {
            return Ok(());
        };
        let store =
            DurableInventoryStoreV1::migrate_v1_to_v2_production(Path::new(&path), [0xd5; 32])?;
        drop(store);
        Ok(())
    }

    #[test]
    fn subprocess_creation_boundaries_require_explicit_resume() -> TestResult {
        for boundary in [
            "after-lock-fsync",
            "after-database-fsync",
            "before-schema-transaction",
            "before-schema-commit",
            "after-schema-commit",
            "after-wal-transition",
        ] {
            let directory = owner_directory()?;
            let path = directory.path().join("inventory.sqlite");
            let status = std::process::Command::new(std::env::current_exe()?)
                .arg("--exact")
                .arg("store::provisioning_tests::creation_crash_child")
                .arg("--nocapture")
                .env("DOM_SOLVER_INVENTORY_TEST_CRASH_PATH", &path)
                .env("DOM_SOLVER_INVENTORY_TEST_CRASH_BOUNDARY", boundary)
                .status()?;
            if status.code() != Some(86) {
                return Err(std::io::Error::other(format!(
                    "creation boundary did not terminate: {boundary}"
                ))
                .into());
            }
            if boundary != "after-wal-transition"
                && DurableInventoryStoreV1::open_existing(&path, [0xa1; 32]).is_ok()
            {
                return Err(std::io::Error::other(format!(
                    "open_existing accepted incomplete boundary: {boundary}"
                ))
                .into());
            }
            let resumed = DurableInventoryStoreV1::resume_create_production(&path, [0xa1; 32])?;
            drop(resumed);
            let reopened = DurableInventoryStoreV1::open_existing(&path, [0xa1; 32])?;
            drop(reopened);
        }
        Ok(())
    }

    #[test]
    fn retained_files_lock_binding_and_schema_are_fail_closed() -> TestResult {
        let directory = owner_directory()?;
        let path = directory.path().join("inventory.sqlite");
        let mut store = DurableInventoryStoreV1::create(&path, [0xb1; 32])?;
        assert!(matches!(
            DurableInventoryStoreV1::open_existing(&path, [0xb1; 32]),
            Err(InventoryStoreErrorV1::StorageAuthorityHeld)
        ));
        let displaced = directory.path().join("displaced.sqlite");
        std::fs::rename(&path, &displaced)?;
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(FILE_MODE)
            .open(&path)?;
        assert!(matches!(
            store.acquire_lease(ParticipantId([1; 32]), [2; 32], 1, 1),
            Err(InventoryStoreErrorV1::InvalidStorageAuthority)
        ));
        drop(store);

        let path = directory.path().join("lock.sqlite");
        let mut store = DurableInventoryStoreV1::create(&path, [0xb2; 32])?;
        let mut lock = OpenOptions::new().write(true).open(lock_path(&path))?;
        lock.write_all(b"payload")?;
        lock.sync_all()?;
        assert!(matches!(
            store.acquire_lease(ParticipantId([1; 32]), [2; 32], 1, 1),
            Err(InventoryStoreErrorV1::InvalidStorageAuthority)
        ));
        drop(store);

        let path = directory.path().join("binding.sqlite");
        let store = DurableInventoryStoreV1::create(&path, [0xb3; 32])?;
        drop(store);
        assert!(matches!(
            DurableInventoryStoreV1::open_existing(&path, [0xb4; 32]),
            Err(InventoryStoreErrorV1::BindingMismatch)
        ));

        let path = directory.path().join("schema.sqlite");
        let mut store = DurableInventoryStoreV1::create(&path, [0xb5; 32])?;
        store
            .connection
            .execute("CREATE TABLE foreign_state(value INTEGER) STRICT", [])?;
        assert!(matches!(
            store.acquire_lease(ParticipantId([1; 32]), [2; 32], 1, 1),
            Err(InventoryStoreErrorV1::CorruptState)
        ));
        drop(store);

        let path = directory.path().join("application.sqlite");
        let store = DurableInventoryStoreV1::create(&path, [0xb6; 32])?;
        drop(store);
        let connection = Connection::open(&path)?;
        connection.pragma_update(None, "application_id", APPLICATION_ID + 1)?;
        drop(connection);
        assert!(matches!(
            DurableInventoryStoreV1::open_existing(&path, [0xb6; 32]),
            Err(InventoryStoreErrorV1::CorruptState)
        ));
        Ok(())
    }

    #[test]
    fn strict_resume_sidecars_and_economic_state_are_fail_closed() -> TestResult {
        let directory = owner_directory()?;
        let path = directory.path().join("missing.sqlite");
        assert!(matches!(
            DurableInventoryStoreV1::resume_create_production(&path, [0xc1; 32]),
            Err(InventoryStoreErrorV1::DatabaseMissing)
        ));
        create_exact_file(&lock_path(&path), &[])?;
        let resumed = DurableInventoryStoreV1::resume_create_production(&path, [0xc1; 32])?;
        drop(resumed);
        let reopened = DurableInventoryStoreV1::open_existing(&path, [0xc1; 32])?;
        drop(reopened);

        let path = directory.path().join("economic.sqlite");
        let mut store = DurableInventoryStoreV1::create(&path, [0xc2; 32])?;
        store.acquire_lease(ParticipantId([1; 32]), [2; 32], 1, 1)?;
        drop(store);
        assert!(matches!(
            DurableInventoryStoreV1::resume_create_production(&path, [0xc2; 32]),
            Err(InventoryStoreErrorV1::CorruptState)
        ));

        let pristine = pristine_journal();
        assert_resume_rejects_journal(&pristine[..511])?;
        let mut nonzero_magic = pristine;
        nonzero_magic[0] = 1;
        assert_resume_rejects_journal(&nonzero_magic)?;
        let mut zero_nonce = pristine;
        zero_nonce[12..16].fill(0);
        assert_resume_rejects_journal(&zero_nonce)?;
        let mut wrong_page = pristine;
        wrong_page[24..28].copy_from_slice(&8192u32.to_be_bytes());
        assert_resume_rejects_journal(&wrong_page)?;
        let mut nonzero_body = pristine;
        nonzero_body[511] = 1;
        assert_resume_rejects_journal(&nonzero_body)?;

        let directory = owner_directory()?;
        let path = directory.path().join("foreign-wal.sqlite");
        let store = DurableInventoryStoreV1::create(&path, [0xc3; 32])?;
        drop(store);
        create_exact_file(&sidecar_paths(&path)[0], &[0; 32])?;
        assert!(matches!(
            DurableInventoryStoreV1::open_existing(&path, [0xc3; 32]),
            Err(InventoryStoreErrorV1::InvalidStorageAuthority)
        ));
        Ok(())
    }

    #[test]
    fn explicit_v1_migration_preserves_economic_state_and_v1_apis() -> TestResult {
        let directory = owner_directory()?;
        let path = directory.path().join("inventory-v1.sqlite");
        let binding = [0xd4; 32];
        make_v1_store_with_economic_state(&path, binding)?;
        if DurableInventoryStoreV1::open_existing(&path, binding).is_ok() {
            return Err(std::io::Error::other("V1 opened without explicit migration").into());
        }
        let mut migrated = DurableInventoryStoreV1::migrate_v1_to_v2_production(&path, binding)?;
        let key = InventoryKeyV1 {
            chain_id: ChainId([0x43; 32]),
            asset_id: AssetId([0x44; 32]),
            authority_id: ParticipantId([0x41; 32]),
        };
        let snapshot = migrated.load_snapshot(key)?;
        if snapshot.spendable_amount != 500 || snapshot.canonical_height != 7 {
            return Err(std::io::Error::other("economic state changed during migration").into());
        }
        let scopes: i64 = migrated.connection.query_row(
            "SELECT COUNT(*) FROM inventory_reservation_scopes_v2",
            [],
            |row| row.get(0),
        )?;
        if scopes != 0 {
            return Err(std::io::Error::other("legacy row was promoted into V2").into());
        }
        drop(migrated);
        let mut reopened = DurableInventoryStoreV1::open_existing(&path, binding)?;
        let snapshot = reopened.load_snapshot(key)?;
        if snapshot.evidence_digest != [0x46; 32] {
            return Err(std::io::Error::other("restart changed V1 evidence").into());
        }
        drop(reopened);
        if DurableInventoryStoreV1::migrate_v1_to_v2_production(&path, binding).is_ok() {
            return Err(std::io::Error::other("migration accepted a V2 authority").into());
        }
        Ok(())
    }

    #[test]
    fn migration_is_atomic_across_real_subprocess_crash_boundaries() -> TestResult {
        for boundary in [
            "before-migration-transaction",
            "before-migration-commit",
            "after-migration-commit",
        ] {
            let directory = owner_directory()?;
            let path = directory.path().join("inventory-migration.sqlite");
            make_v1_store_with_economic_state(&path, [0xd5; 32])?;
            let status = std::process::Command::new(std::env::current_exe()?)
                .arg("--exact")
                .arg("store::provisioning_tests::migration_crash_child")
                .arg("--nocapture")
                .env("DOM_SOLVER_INVENTORY_TEST_MIGRATION_PATH", &path)
                .env(
                    "DOM_SOLVER_INVENTORY_TEST_MIGRATION_CRASH_BOUNDARY",
                    boundary,
                )
                .status()?;
            if status.code() != Some(87) {
                return Err(std::io::Error::other(format!(
                    "migration boundary did not terminate: {boundary}"
                ))
                .into());
            }
            let mut store = if boundary == "after-migration-commit" {
                DurableInventoryStoreV1::open_existing(&path, [0xd5; 32])?
            } else {
                DurableInventoryStoreV1::migrate_v1_to_v2_production(&path, [0xd5; 32])?
            };
            let snapshot = store.load_snapshot(InventoryKeyV1 {
                chain_id: ChainId([0x43; 32]),
                asset_id: AssetId([0x44; 32]),
                authority_id: ParticipantId([0x41; 32]),
            })?;
            if snapshot.spendable_amount != 500 {
                return Err(std::io::Error::other("crash recovery lost inventory").into());
            }
        }
        Ok(())
    }

    #[test]
    fn migration_refuses_foreign_future_and_noncanonical_v1_schema() -> TestResult {
        for mutation in ["foreign", "future", "meta"] {
            let directory = owner_directory()?;
            let path = directory.path().join("inventory-invalid-v1.sqlite");
            make_v1_store_with_economic_state(&path, [0xd6; 32])?;
            let connection = Connection::open(&path)?;
            match mutation {
                "foreign" => {
                    connection.execute("CREATE TABLE foreign_state(value INTEGER) STRICT", [])?;
                }
                "future" => connection.pragma_update(None, "user_version", 3)?,
                "meta" => {
                    connection.execute(
                        "UPDATE inventory_meta SET binding_digest=?1 WHERE singleton=1",
                        params![[0xee_u8; 32].as_slice()],
                    )?;
                }
                _ => return Err(std::io::Error::other("unknown mutation").into()),
            }
            drop(connection);
            if DurableInventoryStoreV1::migrate_v1_to_v2_production(&path, [0xd6; 32]).is_ok() {
                return Err(std::io::Error::other(format!(
                    "migration accepted invalid V1 schema: {mutation}"
                ))
                .into());
            }
        }
        Ok(())
    }
}
