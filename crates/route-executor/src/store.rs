//! SQLite/WAL route authority with atomic reducer commits, durable outbox,
//! timers, leases and fencing generations.

use std::collections::BTreeSet;
#[cfg(target_os = "linux")]
use std::fs::File;
use std::fs::{self, OpenOptions};
#[cfg(target_os = "linux")]
use std::io::Read;
#[cfg(target_os = "linux")]
use std::os::fd::AsFd;
#[cfg(target_os = "linux")]
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;
use std::time::Duration;

use rusqlite::{
    params, Connection, OpenFlags, OptionalExtension, Transaction, TransactionBehavior,
};
#[cfg(target_os = "linux")]
use rustix::fs::{flock, FlockOperation};
#[cfg(target_os = "linux")]
use rustix::process::geteuid;
use thiserror::Error;

use crate::codec::{domain_digest_v1, priority_rank_v1, CanonicalCodecV1, CodecErrorV1};
use crate::model::{
    ActionProgressV1, AuthenticatedRouteInventoryReleaseFactsV1,
    AuthenticatedRouteSecretRetirementFactsV1, CoordinationPhaseV1, Digest32, EffectIdV1,
    EffectPriorityV1, EventIdV1, FrozenRouteAdmissionCheckpointV2, RouteEffectV1, RouteEventV1,
    RouteIdV1, RouteInventoryReleaseCapabilityV1, RouteInventoryReleaseDispositionV1,
    RouteSecretRetirementCapabilityV1, RouteSnapshotV1, RouteTimerMutationV1, RouteTimerV1,
    SecretVisibilityV1, TimerIdV1,
};
use crate::reducer::{reduce_route_v1, ReduceErrorV1};

const SCHEMA_VERSION: i64 = 1;
const STATUS_PENDING: i64 = 0;
const STATUS_COMPLETED: i64 = 1;
const STATUS_SUPERSEDED: i64 = 2;
const TIMER_CANCELLED: i64 = 2;
const DISPATCH_RUNNER: i64 = 0;
const DISPATCH_EXTERNAL_CUSTODY: i64 = 1;
const MAX_LEASE_DURATION_MS: u64 = 86_400_000;
const MAX_CLAIM_BATCH: usize = 64;
#[cfg(target_os = "linux")]
const DIRECTORY_MODE: u32 = 0o700;
#[cfg(target_os = "linux")]
const FILE_MODE: u32 = 0o600;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CreationBoundaryV1 {
    ProcessLockPublished,
    DatabaseFileSynced,
    BeforeSchemaTransaction,
    BeforeSchemaCommit,
    SchemaCommitted,
}

type TimerCompletionRow = (Vec<u8>, i64, Option<Vec<u8>>, Option<i64>, i64);
type SupersededEffectRow = (Vec<u8>, Vec<u8>, i64, Option<i64>);
type RetainedLeaseAuditRow = (Vec<u8>, Vec<u8>, i64, i64, i64);
type RetainedEffectAuditRow = (
    Vec<u8>,
    Vec<u8>,
    i64,
    i64,
    i64,
    i64,
    Vec<u8>,
    Vec<u8>,
    i64,
    i64,
    Option<Vec<u8>>,
    Option<i64>,
    Option<i64>,
);
type RetainedTimerAuditRow = (
    Vec<u8>,
    Vec<u8>,
    i64,
    i64,
    i64,
    Vec<u8>,
    Vec<u8>,
    i64,
    i64,
    Option<Vec<u8>>,
    Option<i64>,
    Option<i64>,
);

/// Durable route-store error.  SQLite diagnostics and persisted opaque bytes
/// are deliberately not included in display output.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum RouteStoreErrorV1 {
    /// Underlying storage failed or was unavailable.
    #[error("route storage unavailable")]
    StorageUnavailable,
    /// Database schema is newer or structurally incompatible.
    #[error("unsupported route database format")]
    UnsupportedFormat,
    /// A create operation found an existing database path.
    #[error("route database already exists")]
    DatabasePresent,
    /// An open-existing operation found no database path.
    #[error("route database does not exist")]
    DatabaseMissing,
    /// The exact create lock and pristine SQLite prefix exist, but the schema
    /// transaction has not committed yet. Only an external `Started` journal
    /// entry may authorize [`DurableRouteStoreV1::resume_create_production`].
    #[error("route database creation is incomplete")]
    CreationIncomplete,
    /// Filesystem owner, mode, link or canonical-path checks failed.
    #[error("invalid route storage authority")]
    InvalidStorageAuthority,
    /// Canonical bytes failed bounded decoding or validation.
    #[error("invalid canonical route material")]
    InvalidMaterial,
    /// The pure reducer rejected the transition.
    #[error("route transition rejected")]
    TransitionRejected,
    /// Route does not exist.
    #[error("route not found")]
    RouteNotFound,
    /// Route already exists.
    #[error("route already exists")]
    RouteAlreadyExists,
    /// Caller loaded a different snapshot revision.
    #[error("route revision conflict")]
    RevisionConflict,
    /// Same idempotency key was used with different canonical bytes.
    #[error("route idempotency conflict")]
    IdempotencyConflict,
    /// Another unexpired owner holds the route.
    #[error("route lease is held by another owner")]
    LeaseHeld,
    /// Owner or generation does not match the current fencing record.
    #[error("stale route fencing generation")]
    StaleFencing,
    /// Lease expired before this operation.
    #[error("route lease expired")]
    LeaseExpired,
    /// Duration/count is zero, overflows or exceeds a defensive bound.
    #[error("invalid route store bound")]
    InvalidBound,
    /// Persisted rows, hashes or replay results disagree.
    #[error("corrupt route state")]
    CorruptState,
    /// Referenced outbox effect does not exist.
    #[error("route effect not found")]
    EffectNotFound,
    /// Referenced timer does not exist or is not active.
    #[error("route timer not found")]
    TimerNotFound,
    /// The route has no production V2 admission checkpoint in its authenticated
    /// journal. A legacy V1 freeze is never upgraded or inferred during reopen.
    #[error("route admission checkpoint is unavailable")]
    AdmissionCheckpointUnavailable,
    /// Authenticated replay does not prove that both route legs are terminal,
    /// fully reconciled, and bound to one public exposure.
    #[error("route secret retirement is not authorized")]
    SecretRetirementUnavailable,
    /// Authenticated replay does not prove either two reconciled terminal legs
    /// or an explicit abort before any funding began.
    #[error("route inventory release is not authorized")]
    InventoryReleaseUnavailable,
    /// Claimed item does not belong to this dispatch lease.
    #[error("dispatch lease mismatch")]
    DispatchLeaseMismatch,
}

impl From<rusqlite::Error> for RouteStoreErrorV1 {
    fn from(_: rusqlite::Error) -> Self {
        Self::StorageUnavailable
    }
}

impl From<CodecErrorV1> for RouteStoreErrorV1 {
    fn from(_: CodecErrorV1) -> Self {
        Self::InvalidMaterial
    }
}

impl From<ReduceErrorV1> for RouteStoreErrorV1 {
    fn from(_: ReduceErrorV1) -> Self {
        Self::TransitionRejected
    }
}

/// Exact route lease and signer fencing capability.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RouteLeaseV1 {
    /// Route under ownership.
    pub route_id: RouteIdV1,
    /// Durable owner/process identity.
    pub owner_id: Digest32,
    /// Monotonic fencing generation.
    pub fencing_epoch: u64,
    /// Absolute expiry supplied by the caller's trusted clock.
    pub lease_until_unix_ms: u64,
}

/// Lease acquisition result distinguishes idempotent reacquisition.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LeaseAcquireOutcomeV1 {
    /// No active lease existed; a new fencing generation was allocated.
    Acquired(RouteLeaseV1),
    /// The same owner already held the unexpired generation.
    AlreadyOwned(RouteLeaseV1),
}

impl LeaseAcquireOutcomeV1 {
    /// Return the lease in either successful outcome.
    pub fn lease(self) -> RouteLeaseV1 {
        match self {
            Self::Acquired(lease) | Self::AlreadyOwned(lease) => lease,
        }
    }
}

/// Outcome of one idempotent route event commit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CommitOutcomeV1 {
    /// Journal, snapshot, outbox and timers committed atomically.
    Committed {
        /// Resulting snapshot revision.
        revision: u64,
        /// Number of new outbox rows.
        effects_created: u32,
        /// Number of new timer rows.
        timers_created: u32,
    },
    /// Exact event bytes were already committed under this event id.
    DuplicateSameBytes {
        /// Revision originally produced by the event.
        revision: u64,
    },
}

/// Idempotent dispatch/timer completion result.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CompletionOutcomeV1 {
    /// Completion was persisted now.
    Completed,
    /// The same item was already completed.
    AlreadyCompleted,
}

/// Claimed exact effect.  Workers must dispatch `effect` byte-identically and
/// present `effect_hash` when recording completion.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClaimedRouteEffectV1 {
    /// Canonically decoded effect.
    pub effect: RouteEffectV1,
    /// Commitment to its canonical bytes.
    pub effect_hash: Digest32,
    /// Number of durable delivery claims, including this one.
    pub attempts: u64,
    /// Dispatch lease expiry.
    pub dispatch_lease_until_unix_ms: u64,
}

/// Claimed external-custody request.  It intentionally exposes only public
/// identities and commitments; secret-bearing transaction bytes never enter
/// the route store or the generic runner queue.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClaimedExternalCustodyEffectV1 {
    /// Route identity.
    pub route_id: RouteIdV1,
    /// Exact effect identity.
    pub effect_id: EffectIdV1,
    /// Fencing generation the signer/custodian must enforce.
    pub fencing_epoch: u64,
    /// Target leg.
    pub leg: crate::model::LegIdV1,
    /// Economic action.
    pub kind: crate::model::ActionKindV1,
    /// Scheduling priority.
    pub priority: crate::model::EffectPriorityV1,
    /// Semantic retry commitment.
    pub semantic_digest: Digest32,
    /// Whether externally retained bytes contain/reveal the route scalar.
    pub contains_route_secret: bool,
    /// Commitment to the complete externally retained descriptor/bytes.
    pub custody_digest: Digest32,
    /// Public transaction identity expected in the receipt.
    pub transaction_id: Digest32,
    /// Number of durable custody claims, including this one.
    pub attempts: u64,
    /// Custody worker lease expiry.
    pub dispatch_lease_until_unix_ms: u64,
}

/// Exactly one claimed item from the unified route outbox.
///
/// The store selects across both dispatch classes in one SQLite transaction,
/// so a scheduler cannot accidentally lease a runner item and a custody item
/// while intending to execute only one external authority call.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ClaimedRouteWorkV1 {
    /// Bounded, non-secret runner bytes.
    Runner(ClaimedRouteEffectV1),
    /// Secret-bearing or externally retained bytes represented by commitments.
    ExternalCustody(ClaimedExternalCustodyEffectV1),
}

/// Claimed due timer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClaimedRouteTimerV1 {
    /// Canonically decoded timer.
    pub timer: RouteTimerV1,
    /// Commitment to its canonical bytes.
    pub timer_hash: Digest32,
    /// Number of durable claims, including this one.
    pub attempts: u64,
    /// Worker lease expiry.
    pub dispatch_lease_until_unix_ms: u64,
}

/// Public, replayable journal entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RouteJournalEntryV1 {
    /// Contiguous per-route sequence.
    pub sequence: u64,
    /// Idempotency key.
    pub event_id: EventIdV1,
    /// Canonical event.
    pub event: RouteEventV1,
    /// CAS revision read by the transition.
    pub expected_revision: u64,
    /// Revision produced by the transition.
    pub resulting_revision: u64,
    /// Fencing generation that authorized the event.
    pub fencing_epoch: u64,
    /// Resulting snapshot commitment.
    pub snapshot_hash: Digest32,
    /// Previous journal-chain commitment.
    pub previous_entry_hash: Digest32,
    /// This journal-chain commitment.
    pub entry_hash: Digest32,
}

/// Single-process SQLite route authority.  A higher-level composition root may
/// wrap it in a mutex; the connection itself is never exposed.
pub struct DurableRouteStoreV1 {
    connection: Connection,
    #[cfg(target_os = "linux")]
    _process_lock: Option<File>,
}

impl core::fmt::Debug for DurableRouteStoreV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("DurableRouteStoreV1([redacted])")
    }
}

impl DurableRouteStoreV1 {
    /// Compatibility open-or-create path for development and tests.
    /// Production builds do not contain this method; their composition root
    /// must distinguish [`Self::create`] from [`Self::open_existing`].
    #[cfg(any(feature = "development", test))]
    pub fn open(path: &Path) -> Result<Self, RouteStoreErrorV1> {
        let connection = Connection::open(path)?;
        configure_connection(&connection)?;
        let mut store = Self {
            connection,
            #[cfg(target_os = "linux")]
            _process_lock: None,
        };
        store.migrate()?;
        Ok(store)
    }

    /// Creates one owner-only database and refuses to replace any path.
    pub fn create(path: &Path) -> Result<Self, RouteStoreErrorV1> {
        Self::create_with_boundary_hook(path, |_| Ok(()))
    }

    fn create_with_boundary_hook<F>(path: &Path, mut boundary: F) -> Result<Self, RouteStoreErrorV1>
    where
        F: FnMut(CreationBoundaryV1) -> Result<(), RouteStoreErrorV1>,
    {
        if fs::symlink_metadata(path).is_ok() {
            return Err(RouteStoreErrorV1::DatabasePresent);
        }
        let parent = path
            .parent()
            .ok_or(RouteStoreErrorV1::InvalidStorageAuthority)?;
        #[cfg(target_os = "linux")]
        {
            validate_owner_directory(parent)?;
            require_sqlite_sidecars_absent(path)?;
        }
        #[cfg(target_os = "linux")]
        let process_lock = acquire_process_lock(path, true)?;
        boundary(CreationBoundaryV1::ProcessLockPublished)?;
        create_owner_database_file(path)?;
        boundary(CreationBoundaryV1::DatabaseFileSynced)?;
        let connection = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;
        configure_connection(&connection)?;
        validate_database_path(&connection, path)?;
        let mut store = Self {
            connection,
            #[cfg(target_os = "linux")]
            _process_lock: Some(process_lock),
        };
        boundary(CreationBoundaryV1::BeforeSchemaTransaction)?;
        store.migrate_with_boundary_hook(|| boundary(CreationBoundaryV1::BeforeSchemaCommit))?;
        boundary(CreationBoundaryV1::SchemaCommitted)?;
        validate_backend_and_schema(&store.connection)?;
        #[cfg(target_os = "linux")]
        {
            validate_owner_directory(parent)?;
            validate_owner_file(path)?;
            validate_resumable_sqlite_sidecars(path)?;
            sync_owner_directory(parent)?;
        }
        Ok(store)
    }

    /// Resumes only a route-store create whose exact intent was already
    /// published as `Started` in the caller's external provisioning journal.
    ///
    /// This is deliberately not an open-or-create operation. The owner-only
    /// lock created by [`Self::create`] must already exist and be exclusively
    /// acquirable. The database may be absent after lock publication, may be
    /// pristine SQLite, or may contain the exact V1 schema with every route,
    /// event, effect, lease and timer table empty. Alternate schema/version,
    /// any economic row, or a malformed SQLite sidecar is refused.
    pub fn resume_create_production(path: &Path) -> Result<Self, RouteStoreErrorV1> {
        let parent = path
            .parent()
            .ok_or(RouteStoreErrorV1::InvalidStorageAuthority)?;
        #[cfg(target_os = "linux")]
        validate_owner_directory(parent)?;
        #[cfg(target_os = "linux")]
        let process_lock = acquire_process_lock(path, false)?;

        match fs::symlink_metadata(path) {
            Ok(_) => {
                #[cfg(target_os = "linux")]
                {
                    validate_owner_file(path)?;
                    validate_resumable_sqlite_sidecars(path)?;
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                #[cfg(target_os = "linux")]
                require_sqlite_sidecars_absent(path)?;
                create_owner_database_file(path)?;
            }
            Err(_) => return Err(RouteStoreErrorV1::StorageUnavailable),
        }

        let connection = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;
        configure_connection(&connection)?;
        validate_database_path(&connection, path)?;
        let mut store = Self {
            connection,
            #[cfg(target_os = "linux")]
            _process_lock: Some(process_lock),
        };
        match resumable_creation_state(&store.connection)? {
            ResumableCreationStateV1::PristineSqlite => store.migrate()?,
            ResumableCreationStateV1::PristineInitialized => {}
        }
        validate_pristine_initialized_store(&store.connection)?;
        #[cfg(target_os = "linux")]
        {
            validate_owner_directory(parent)?;
            validate_owner_file(path)?;
            validate_resumable_sqlite_sidecars(path)?;
            sync_owner_directory(parent)?;
        }
        Ok(store)
    }

    /// Opens an existing owner-only v1 database without creating or migrating
    /// absent/incompatible state.
    pub fn open_existing(path: &Path) -> Result<Self, RouteStoreErrorV1> {
        match fs::symlink_metadata(path) {
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Err(RouteStoreErrorV1::DatabaseMissing)
            }
            Err(_) => return Err(RouteStoreErrorV1::StorageUnavailable),
        }
        let parent = path
            .parent()
            .ok_or(RouteStoreErrorV1::InvalidStorageAuthority)?;
        #[cfg(target_os = "linux")]
        {
            validate_owner_directory(parent)?;
            validate_owner_file(path)?;
            validate_resumable_sqlite_sidecars(path)?;
        }
        #[cfg(target_os = "linux")]
        let process_lock = acquire_process_lock(path, false)?;
        let connection = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;
        configure_connection(&connection)?;
        validate_database_path(&connection, path)?;
        if resumable_creation_state(&connection)? == ResumableCreationStateV1::PristineSqlite {
            return Err(RouteStoreErrorV1::CreationIncomplete);
        }
        validate_backend_and_schema(&connection)?;
        #[cfg(target_os = "linux")]
        {
            validate_owner_directory(parent)?;
            validate_owner_file(path)?;
            validate_resumable_sqlite_sidecars(path)?;
        }
        let store = Self {
            connection,
            #[cfg(target_os = "linux")]
            _process_lock: Some(process_lock),
        };
        validate_retained_state_on_open(&store)?;
        Ok(store)
    }

    /// Create the sole valid initial snapshot for a route.
    pub fn create_route(
        &mut self,
        route_id: RouteIdV1,
        now_unix_ms: u64,
    ) -> Result<RouteSnapshotV1, RouteStoreErrorV1> {
        let snapshot = RouteSnapshotV1::new(route_id)?;
        let bytes = snapshot.encode_canonical()?;
        let snapshot_hash = snapshot_hash(&bytes);
        let now = to_sql_u64(now_unix_ms)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let result = transaction.execute(
            "INSERT INTO route_snapshots
             (route_id, initial_snapshot_bytes, initial_snapshot_hash,
              snapshot_bytes, snapshot_hash, revision, last_event_seq,
              created_at_unix_ms, updated_at_unix_ms)
             VALUES (?1, ?2, ?3, ?2, ?3, 0, 0, ?4, ?4)",
            params![route_id.as_slice(), bytes, snapshot_hash.as_slice(), now],
        );
        match result {
            Ok(1) => transaction.commit()?,
            Ok(_) => return Err(RouteStoreErrorV1::CorruptState),
            Err(error) if is_constraint(&error) => {
                return Err(RouteStoreErrorV1::RouteAlreadyExists)
            }
            Err(error) => return Err(error.into()),
        }
        Ok(snapshot)
    }

    /// Load and validate the current materialized snapshot and its commitment.
    pub fn load_snapshot(&self, route_id: RouteIdV1) -> Result<RouteSnapshotV1, RouteStoreErrorV1> {
        let row: Option<(Vec<u8>, Vec<u8>, i64, i64)> = self
            .connection
            .query_row(
                "SELECT snapshot_bytes, snapshot_hash, revision, last_event_seq
                 FROM route_snapshots WHERE route_id = ?1",
                params![route_id.as_slice()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .optional()?;
        let (bytes, stored_hash, revision, sequence) =
            row.ok_or(RouteStoreErrorV1::RouteNotFound)?;
        validate_snapshot_row(route_id, &bytes, &stored_hash, revision, sequence)
    }

    /// Recover the exact intent for the one action that is still actively
    /// `Committed` in the snapshot.
    ///
    /// The read is authorized by the current route lease and atomically
    /// cross-checks the active snapshot reference, canonical outbox bytes,
    /// outbox hash, pending status and all route/leg/action/fencing fields.
    /// Superseded, completed, externalized or unrelated effects are refused.
    /// Runner effects return their bounded safe payload; external custody
    /// returns only commitments and a public transaction id, never secret
    /// bytes or the route scalar.
    pub fn committed_action_intent(
        &mut self,
        lease: RouteLeaseV1,
        effect_id: EffectIdV1,
        now_unix_ms: u64,
    ) -> Result<crate::model::ActionIntentV1, RouteStoreErrorV1> {
        validate_identity(effect_id)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Deferred)?;
        validate_lease(&transaction, lease, now_unix_ms)?;
        let snapshot = load_snapshot_in_transaction(&transaction, lease.route_id)?;
        let (leg, kind, reference) = active_committed_effect(&snapshot, effect_id)
            .ok_or(RouteStoreErrorV1::EffectNotFound)?;
        let row: Option<(Vec<u8>, Vec<u8>, i64)> = transaction
            .query_row(
                "SELECT effect_bytes, effect_hash, status_tag
                 FROM route_outbox WHERE route_id = ?1 AND effect_id = ?2",
                params![lease.route_id.as_slice(), effect_id.as_slice()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()?;
        let (effect_bytes, stored_hash, status) = row.ok_or(RouteStoreErrorV1::EffectNotFound)?;
        if status != STATUS_PENDING {
            return Err(RouteStoreErrorV1::EffectNotFound);
        }
        if blob32(stored_hash)? != effect_hash_value(&effect_bytes) {
            return Err(RouteStoreErrorV1::CorruptState);
        }
        let effect = RouteEffectV1::decode_canonical(&effect_bytes)?;
        if effect.route_id != lease.route_id
            || effect.effect_id != effect_id
            || effect.leg != leg
            || effect.kind != kind
            || effect.fencing_epoch != reference.fencing_epoch
            || effect.semantic_digest != reference.semantic_digest
            || effect.contains_route_secret != reference.contains_route_secret
        {
            return Err(RouteStoreErrorV1::CorruptState);
        }
        let expected_transaction_id = match effect.dispatch {
            crate::model::EffectDispatchV1::RunnerPayload { .. } => None,
            crate::model::EffectDispatchV1::ExternalCustody { transaction_id, .. } => {
                Some(transaction_id)
            }
        };
        if expected_transaction_id != reference.expected_transaction_id {
            return Err(RouteStoreErrorV1::CorruptState);
        }
        let intent = crate::model::ActionIntentV1 {
            leg,
            kind,
            semantic_digest: effect.semantic_digest,
            contains_route_secret: effect.contains_route_secret,
            dispatch: effect.dispatch,
        };
        transaction.commit()?;
        Ok(intent)
    }

    /// Acquire an absent/expired route lease.  Every takeover increments the
    /// fencing generation; an active lease owned by another identity fails.
    pub fn acquire_lease(
        &mut self,
        route_id: RouteIdV1,
        owner_id: Digest32,
        now_unix_ms: u64,
        duration_ms: u64,
    ) -> Result<LeaseAcquireOutcomeV1, RouteStoreErrorV1> {
        validate_identity(owner_id)?;
        let lease_until = lease_deadline(now_unix_ms, duration_ms)?;
        let now = to_sql_u64(now_unix_ms)?;
        let until = to_sql_u64(lease_until)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        require_route_exists(&transaction, route_id)?;
        let existing = load_lease_row(&transaction, route_id)?;
        let (outcome, lease) = match existing {
            None => {
                transaction.execute(
                    "INSERT INTO route_leases
                     (route_id, owner_id, fencing_epoch, lease_until_unix_ms, updated_at_unix_ms)
                     VALUES (?1, ?2, 1, ?3, ?4)",
                    params![route_id.as_slice(), owner_id.as_slice(), until, now],
                )?;
                let lease = RouteLeaseV1 {
                    route_id,
                    owner_id,
                    fencing_epoch: 1,
                    lease_until_unix_ms: lease_until,
                };
                (LeaseAcquireOutcomeV1::Acquired(lease), lease)
            }
            Some((current_owner, epoch, current_until)) if current_until >= now_unix_ms => {
                if current_owner != owner_id {
                    return Err(RouteStoreErrorV1::LeaseHeld);
                }
                let lease = RouteLeaseV1 {
                    route_id,
                    owner_id,
                    fencing_epoch: epoch,
                    lease_until_unix_ms: current_until,
                };
                (LeaseAcquireOutcomeV1::AlreadyOwned(lease), lease)
            }
            Some((_current_owner, epoch, _current_until)) => {
                let next_epoch = epoch
                    .checked_add(1)
                    .ok_or(RouteStoreErrorV1::InvalidBound)?;
                let changed = transaction.execute(
                    "UPDATE route_leases
                     SET owner_id = ?2, fencing_epoch = ?3,
                         lease_until_unix_ms = ?4, updated_at_unix_ms = ?5
                     WHERE route_id = ?1 AND fencing_epoch = ?6",
                    params![
                        route_id.as_slice(),
                        owner_id.as_slice(),
                        to_sql_u64(next_epoch)?,
                        until,
                        now,
                        to_sql_u64(epoch)?
                    ],
                )?;
                if changed != 1 {
                    return Err(RouteStoreErrorV1::StaleFencing);
                }
                let lease = RouteLeaseV1 {
                    route_id,
                    owner_id,
                    fencing_epoch: next_epoch,
                    lease_until_unix_ms: lease_until,
                };
                (LeaseAcquireOutcomeV1::Acquired(lease), lease)
            }
        };
        let _ = lease;
        transaction.commit()?;
        Ok(outcome)
    }

    /// Extend exactly the current unexpired lease without changing its epoch.
    pub fn renew_lease(
        &mut self,
        lease: RouteLeaseV1,
        now_unix_ms: u64,
        duration_ms: u64,
    ) -> Result<RouteLeaseV1, RouteStoreErrorV1> {
        let lease_until = lease_deadline(now_unix_ms, duration_ms)?;
        let now = to_sql_u64(now_unix_ms)?;
        let until = to_sql_u64(lease_until)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        validate_lease(&transaction, lease, now_unix_ms)?;
        let changed = transaction.execute(
            "UPDATE route_leases SET lease_until_unix_ms = ?4, updated_at_unix_ms = ?5
             WHERE route_id = ?1 AND owner_id = ?2 AND fencing_epoch = ?3",
            params![
                lease.route_id.as_slice(),
                lease.owner_id.as_slice(),
                to_sql_u64(lease.fencing_epoch)?,
                until,
                now
            ],
        )?;
        if changed != 1 {
            return Err(RouteStoreErrorV1::StaleFencing);
        }
        transaction.commit()?;
        Ok(RouteLeaseV1 {
            lease_until_unix_ms: lease_until,
            ..lease
        })
    }

    /// Run the pure reducer and atomically commit its complete write set.
    pub fn apply_event(
        &mut self,
        lease: RouteLeaseV1,
        expected_revision: u64,
        event_id: EventIdV1,
        event: &RouteEventV1,
        now_unix_ms: u64,
    ) -> Result<CommitOutcomeV1, RouteStoreErrorV1> {
        validate_identity(event_id)?;
        let event_bytes = event.encode_canonical()?;
        let now = to_sql_u64(now_unix_ms)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        validate_lease(&transaction, lease, now_unix_ms)?;

        if let Some((stored_bytes, resulting_revision)) = transaction
            .query_row(
                "SELECT event_bytes, resulting_revision FROM route_journal
                 WHERE route_id = ?1 AND event_id = ?2",
                params![lease.route_id.as_slice(), event_id.as_slice()],
                |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, i64>(1)?)),
            )
            .optional()?
        {
            if stored_bytes != event_bytes {
                return Err(RouteStoreErrorV1::IdempotencyConflict);
            }
            if let RouteEventV1::CustodyProgressRecorded { effect_id, .. } = event {
                // A coordinator may return the same durable child prefix
                // after this effect was claimed again. Release that exact
                // custody dispatch claim even though the journal event is an
                // idempotent duplicate; the aggregate itself stays pending.
                reconcile_partial_custody_progress(&transaction, lease, *effect_id, now_unix_ms)?;
                transaction.commit()?;
            }
            return Ok(CommitOutcomeV1::DuplicateSameBytes {
                revision: from_sql_u64(resulting_revision)?,
            });
        }

        let (snapshot_bytes, stored_snapshot_hash, stored_revision, stored_sequence): (
            Vec<u8>,
            Vec<u8>,
            i64,
            i64,
        ) = transaction
            .query_row(
                "SELECT snapshot_bytes, snapshot_hash, revision, last_event_seq
                 FROM route_snapshots WHERE route_id = ?1",
                params![lease.route_id.as_slice()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .optional()?
            .ok_or(RouteStoreErrorV1::RouteNotFound)?;
        let current = validate_snapshot_row(
            lease.route_id,
            &snapshot_bytes,
            &stored_snapshot_hash,
            stored_revision,
            stored_sequence,
        )?;
        if current.revision != expected_revision {
            return Err(RouteStoreErrorV1::RevisionConflict);
        }

        let decision = reduce_route_v1(&current, event_id, event, lease.fencing_epoch)?;
        let resulting_bytes = decision.snapshot.encode_canonical()?;
        let resulting_hash = snapshot_hash(&resulting_bytes);
        let sequence = decision.snapshot.last_event_sequence;
        let previous_entry_hash = previous_entry_hash(&transaction, lease.route_id)?;
        let event_hash = domain_digest_v1(b"DOM-ROUTE-EVENT-DIGEST-V1", &[&event_bytes]);
        let entry_hash = journal_entry_hash(JournalEntryHashInputV1 {
            previous: previous_entry_hash,
            route_id: lease.route_id,
            sequence,
            expected_revision,
            resulting_revision: decision.snapshot.revision,
            event_id,
            event_hash,
            resulting_snapshot_hash: resulting_hash,
            fencing_epoch: lease.fencing_epoch,
        });

        transaction.execute(
            "INSERT INTO route_journal
             (route_id, sequence, event_id, event_bytes, event_hash,
              expected_revision, resulting_revision, fencing_epoch,
              snapshot_hash, previous_entry_hash, entry_hash, created_at_unix_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
            params![
                lease.route_id.as_slice(),
                to_sql_u64(sequence)?,
                event_id.as_slice(),
                event_bytes,
                event_hash.as_slice(),
                to_sql_u64(expected_revision)?,
                to_sql_u64(decision.snapshot.revision)?,
                to_sql_u64(lease.fencing_epoch)?,
                resulting_hash.as_slice(),
                previous_entry_hash.as_slice(),
                entry_hash.as_slice(),
                now
            ],
        )?;

        let changed = transaction.execute(
            "UPDATE route_snapshots
             SET snapshot_bytes = ?3, snapshot_hash = ?4, revision = ?5,
                 last_event_seq = ?6, updated_at_unix_ms = ?7
             WHERE route_id = ?1 AND revision = ?2",
            params![
                lease.route_id.as_slice(),
                to_sql_u64(expected_revision)?,
                resulting_bytes,
                resulting_hash.as_slice(),
                to_sql_u64(decision.snapshot.revision)?,
                to_sql_u64(sequence)?,
                now
            ],
        )?;
        if changed != 1 {
            return Err(RouteStoreErrorV1::RevisionConflict);
        }

        for prior_effect_id in &decision.superseded_effects {
            supersede_effect(
                &transaction,
                lease.route_id,
                *prior_effect_id,
                &decision.effects,
                now_unix_ms,
                now,
            )?;
        }
        for effect in &decision.effects {
            insert_effect(&transaction, sequence, effect)?;
        }
        if let RouteEventV1::ActionExternalized {
            effect_id,
            transaction_id,
            ..
        } = event
        {
            reconcile_externalized_effect(
                &transaction,
                lease.route_id,
                *effect_id,
                *transaction_id,
                now,
            )?;
        }
        if let RouteEventV1::CustodyProgressRecorded { effect_id, .. } = event {
            reconcile_partial_custody_progress(&transaction, lease, *effect_id, now_unix_ms)?;
        }
        let mut timers_created = 0_u32;
        for mutation in &decision.timers {
            match mutation {
                RouteTimerMutationV1::Schedule(timer) => {
                    insert_timer(&transaction, sequence, timer)?;
                    timers_created = timers_created
                        .checked_add(1)
                        .ok_or(RouteStoreErrorV1::InvalidBound)?;
                }
                RouteTimerMutationV1::Cancel { timer_id } => {
                    let changed = transaction.execute(
                        "UPDATE route_timers
                         SET status_tag = ?3, completed_at_unix_ms = ?4,
                             dispatch_lease_owner = NULL,
                             dispatch_lease_until_unix_ms = NULL
                         WHERE route_id = ?1 AND timer_id = ?2 AND status_tag = ?5",
                        params![
                            lease.route_id.as_slice(),
                            timer_id.as_slice(),
                            TIMER_CANCELLED,
                            now,
                            STATUS_PENDING
                        ],
                    )?;
                    if changed != 1 {
                        return Err(RouteStoreErrorV1::TimerNotFound);
                    }
                }
            }
        }

        transaction.commit()?;
        Ok(CommitOutcomeV1::Committed {
            revision: decision.snapshot.revision,
            effects_created: u32::try_from(decision.effects.len())
                .map_err(|_| RouteStoreErrorV1::InvalidBound)?,
            timers_created,
        })
    }

    /// Return validated journal entries in sequence order.
    pub fn journal(
        &self,
        route_id: RouteIdV1,
    ) -> Result<Vec<RouteJournalEntryV1>, RouteStoreErrorV1> {
        let mut statement = self.connection.prepare(
            "SELECT sequence, event_id, event_bytes, event_hash, expected_revision,
                    resulting_revision, fencing_epoch, snapshot_hash,
                    previous_entry_hash, entry_hash
             FROM route_journal WHERE route_id = ?1 ORDER BY sequence ASC",
        )?;
        let rows = statement.query_map(params![route_id.as_slice()], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, Vec<u8>>(2)?,
                row.get::<_, Vec<u8>>(3)?,
                row.get::<_, i64>(4)?,
                row.get::<_, i64>(5)?,
                row.get::<_, i64>(6)?,
                row.get::<_, Vec<u8>>(7)?,
                row.get::<_, Vec<u8>>(8)?,
                row.get::<_, Vec<u8>>(9)?,
            ))
        })?;
        let mut entries = Vec::new();
        for row in rows {
            let (
                sequence,
                event_id,
                event_bytes,
                event_hash,
                expected_revision,
                resulting_revision,
                fencing_epoch,
                snapshot_hash,
                previous_entry_hash,
                entry_hash,
            ) = row?;
            if blob32(event_hash)?
                != domain_digest_v1(b"DOM-ROUTE-EVENT-DIGEST-V1", &[&event_bytes])
            {
                return Err(RouteStoreErrorV1::CorruptState);
            }
            entries.push(RouteJournalEntryV1 {
                sequence: from_sql_u64(sequence)?,
                event_id: blob32(event_id)?,
                event: RouteEventV1::decode_canonical(&event_bytes)?,
                expected_revision: from_sql_u64(expected_revision)?,
                resulting_revision: from_sql_u64(resulting_revision)?,
                fencing_epoch: from_sql_u64(fencing_epoch)?,
                snapshot_hash: blob32(snapshot_hash)?,
                previous_entry_hash: blob32(previous_entry_hash)?,
                entry_hash: blob32(entry_hash)?,
            });
        }
        Ok(entries)
    }

    /// Replay the full journal from the immutable initial snapshot, verify its
    /// hash chain and compare the replayed result with the materialized row.
    pub fn verify_replay(&self, route_id: RouteIdV1) -> Result<RouteSnapshotV1, RouteStoreErrorV1> {
        let (initial_bytes, initial_hash): (Vec<u8>, Vec<u8>) = self
            .connection
            .query_row(
                "SELECT initial_snapshot_bytes, initial_snapshot_hash
                 FROM route_snapshots WHERE route_id = ?1",
                params![route_id.as_slice()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?
            .ok_or(RouteStoreErrorV1::RouteNotFound)?;
        let expected_initial_hash = snapshot_hash(&initial_bytes);
        if blob32(initial_hash)? != expected_initial_hash {
            return Err(RouteStoreErrorV1::CorruptState);
        }
        let mut snapshot = RouteSnapshotV1::decode_canonical(&initial_bytes)?;
        if snapshot.route_id != route_id || snapshot.revision != 0 {
            return Err(RouteStoreErrorV1::CorruptState);
        }
        let mut previous_hash = initial_journal_hash(route_id, expected_initial_hash);
        for entry in self.journal(route_id)? {
            if entry.sequence != snapshot.last_event_sequence + 1
                || entry.expected_revision != snapshot.revision
                || entry.previous_entry_hash != previous_hash
            {
                return Err(RouteStoreErrorV1::CorruptState);
            }
            let event_bytes = entry.event.encode_canonical()?;
            let event_hash = domain_digest_v1(b"DOM-ROUTE-EVENT-DIGEST-V1", &[&event_bytes]);
            let decision =
                reduce_route_v1(&snapshot, entry.event_id, &entry.event, entry.fencing_epoch)?;
            let replayed_bytes = decision.snapshot.encode_canonical()?;
            let replayed_hash = snapshot_hash(&replayed_bytes);
            let expected_entry_hash = journal_entry_hash(JournalEntryHashInputV1 {
                previous: previous_hash,
                route_id,
                sequence: entry.sequence,
                expected_revision: entry.expected_revision,
                resulting_revision: entry.resulting_revision,
                event_id: entry.event_id,
                event_hash,
                resulting_snapshot_hash: replayed_hash,
                fencing_epoch: entry.fencing_epoch,
            });
            if decision.snapshot.revision != entry.resulting_revision
                || replayed_hash != entry.snapshot_hash
                || expected_entry_hash != entry.entry_hash
            {
                return Err(RouteStoreErrorV1::CorruptState);
            }
            snapshot = decision.snapshot;
            previous_hash = entry.entry_hash;
        }
        if snapshot != self.load_snapshot(route_id)? {
            return Err(RouteStoreErrorV1::CorruptState);
        }
        Ok(snapshot)
    }

    /// Authenticates the complete route history and proves that every action
    /// uses the external-custody dispatch class.
    ///
    /// The production compositor never installs a generic runner.  Checking
    /// only the current outbox would be insufficient because a completed or
    /// superseded runner effect may no longer be pending there.  This audit
    /// therefore replays the journal first and then inspects every historical
    /// action-bearing event, including takeover reauthorizations.  A legacy or
    /// transplanted runner payload is treated as corrupt production state.
    pub fn audit_external_custody_only_v1(
        &self,
        route_id: RouteIdV1,
    ) -> Result<RouteSnapshotV1, RouteStoreErrorV1> {
        let snapshot = self.verify_replay(route_id)?;
        for entry in self.journal(route_id)? {
            let intent = match &entry.event {
                RouteEventV1::CommitAction(intent)
                | RouteEventV1::ReauthorizeCommittedAction { intent, .. }
                | RouteEventV1::ReauthorizePartiallyExternalizedCustody { intent, .. } => {
                    Some(intent)
                }
                _ => None,
            };
            if intent.is_some_and(|intent| {
                matches!(
                    &intent.dispatch,
                    crate::model::EffectDispatchV1::RunnerPayload { .. }
                )
            }) {
                return Err(RouteStoreErrorV1::CorruptState);
            }
        }
        Ok(snapshot)
    }

    /// Replays and authenticates the complete route journal, then returns the
    /// exact production V2 admission checkpoint carried by its sole logical
    /// terms-freeze event.
    ///
    /// A legacy V1 freeze remains replayable for compatibility but is not a
    /// production recovery checkpoint. Missing/V1-only routes return
    /// [`RouteStoreErrorV1::AdmissionCheckpointUnavailable`]; a mixed or second
    /// freeze, route mismatch, or disagreement with the replayed snapshot fails
    /// as corrupt state. No checkpoint is synthesized from current inputs.
    pub fn audit_frozen_admission_checkpoint_v2(
        &self,
        route_id: RouteIdV1,
    ) -> Result<FrozenRouteAdmissionCheckpointV2, RouteStoreErrorV1> {
        let replayed = self.verify_replay(route_id)?;
        let mut legacy_freezes = 0u8;
        let mut v2_checkpoint: Option<FrozenRouteAdmissionCheckpointV2> = None;
        for entry in self.journal(route_id)? {
            match entry.event {
                RouteEventV1::FreezeTerms(_) => {
                    legacy_freezes = legacy_freezes
                        .checked_add(1)
                        .ok_or(RouteStoreErrorV1::CorruptState)?;
                }
                RouteEventV1::FreezeTermsV2(checkpoint) => {
                    if v2_checkpoint.replace(*checkpoint).is_some() {
                        return Err(RouteStoreErrorV1::CorruptState);
                    }
                }
                _ => {}
            }
        }
        if legacy_freezes != 0 && v2_checkpoint.is_some() {
            return Err(RouteStoreErrorV1::CorruptState);
        }
        if legacy_freezes != 0 {
            return Err(RouteStoreErrorV1::AdmissionCheckpointUnavailable);
        }
        let checkpoint = v2_checkpoint.ok_or(RouteStoreErrorV1::AdmissionCheckpointUnavailable)?;
        if checkpoint.route_id != route_id
            || replayed.bindings.as_ref() != Some(&checkpoint.bindings)
        {
            return Err(RouteStoreErrorV1::CorruptState);
        }
        Ok(checkpoint)
    }

    /// Mints an opaque capability to retire the public-scalar recovery record.
    ///
    /// The complete authenticated journal is replayed before evaluating the
    /// terminal predicate. Production V2 admission, the immutable first public
    /// exposure, both terminal legs, and absence of open funds are mandatory;
    /// none of these facts are accepted from the caller.
    pub fn mint_route_secret_retirement_capability_v1(
        &self,
        route_id: RouteIdV1,
    ) -> Result<RouteSecretRetirementCapabilityV1, RouteStoreErrorV1> {
        let snapshot = self.verify_replay(route_id)?;
        let checkpoint = self.audit_frozen_admission_checkpoint_v2(route_id)?;
        if snapshot.coordination != CoordinationPhaseV1::Terminal
            || !snapshot.upstream.is_terminal()
            || !snapshot.downstream.is_terminal()
            || snapshot.has_open_funds()
            || snapshot.aborted_unfunded
        {
            return Err(RouteStoreErrorV1::SecretRetirementUnavailable);
        }
        let first_exposure = match &snapshot.secret_visibility {
            SecretVisibilityV1::Public { first_exposure } => first_exposure.clone(),
            SecretVisibilityV1::Private => {
                return Err(RouteStoreErrorV1::SecretRetirementUnavailable);
            }
        };
        let journal = self.journal(route_id)?;
        let head = journal
            .last()
            .ok_or(RouteStoreErrorV1::SecretRetirementUnavailable)?;
        let snapshot_bytes = snapshot.encode_canonical()?;
        let final_snapshot_digest = snapshot_hash(&snapshot_bytes);
        if head.resulting_revision != snapshot.revision
            || head.sequence != snapshot.last_event_sequence
            || head.snapshot_hash != final_snapshot_digest
            || snapshot.last_event_digest
                != domain_digest_v1(
                    b"DOM-ROUTE-EVENT-DIGEST-V1",
                    &[&head.event.encode_canonical()?],
                )
        {
            return Err(RouteStoreErrorV1::CorruptState);
        }
        let checkpoint_digest = domain_digest_v1(
            b"DOM-ROUTE-ADMISSION-CHECKPOINT-V2",
            &[&checkpoint.encode_canonical()?],
        );
        RouteSecretRetirementCapabilityV1::from_authenticated_replay(
            AuthenticatedRouteSecretRetirementFactsV1 {
                route_id,
                composition_v2_digest: checkpoint.composition_v2_digest,
                first_exposure,
                revision: snapshot.revision,
                snapshot_digest: final_snapshot_digest,
                last_event_digest: snapshot.last_event_digest,
                journal_head_digest: head.entry_hash,
                admission_checkpoint_digest: checkpoint_digest,
            },
        )
        .map_err(RouteStoreErrorV1::from)
    }

    /// Mints an opaque proof that route-scoped inventory may be released.
    ///
    /// The complete authenticated journal and its production V2 admission
    /// checkpoint are replayed on every call. The route must either have both
    /// legs terminal with no open funds, or carry the reducer's explicit
    /// `AbortUnfunded` state while both funding actions remain untouched.
    /// Caller-provided terminal booleans, revisions, digests, and reservation
    /// identifiers are not accepted by this boundary.
    pub fn mint_route_inventory_release_capability_v1(
        &self,
        route_id: RouteIdV1,
    ) -> Result<RouteInventoryReleaseCapabilityV1, RouteStoreErrorV1> {
        let snapshot = self.verify_replay(route_id)?;
        let checkpoint = self.audit_frozen_admission_checkpoint_v2(route_id)?;
        let disposition = if snapshot.aborted_unfunded {
            if snapshot.coordination != CoordinationPhaseV1::Terminal
                || snapshot.has_open_funds()
                || snapshot.upstream.funding.progress() != ActionProgressV1::NotPrepared
                || snapshot.downstream.funding.progress() != ActionProgressV1::NotPrepared
                || !matches!(snapshot.secret_visibility, SecretVisibilityV1::Private)
            {
                return Err(RouteStoreErrorV1::InventoryReleaseUnavailable);
            }
            RouteInventoryReleaseDispositionV1::AbortedUnfunded
        } else {
            if snapshot.coordination != CoordinationPhaseV1::Terminal
                || !snapshot.upstream.is_terminal()
                || !snapshot.downstream.is_terminal()
                || snapshot.has_open_funds()
            {
                return Err(RouteStoreErrorV1::InventoryReleaseUnavailable);
            }
            RouteInventoryReleaseDispositionV1::BothLegsTerminal
        };
        let journal = self.journal(route_id)?;
        let head = journal
            .last()
            .ok_or(RouteStoreErrorV1::InventoryReleaseUnavailable)?;
        let snapshot_bytes = snapshot.encode_canonical()?;
        let snapshot_digest = snapshot_hash(&snapshot_bytes);
        if head.resulting_revision != snapshot.revision
            || head.sequence != snapshot.last_event_sequence
            || head.snapshot_hash != snapshot_digest
            || snapshot.last_event_digest
                != domain_digest_v1(
                    b"DOM-ROUTE-EVENT-DIGEST-V1",
                    &[&head.event.encode_canonical()?],
                )
        {
            return Err(RouteStoreErrorV1::CorruptState);
        }
        let checkpoint_digest = domain_digest_v1(
            b"DOM-ROUTE-ADMISSION-CHECKPOINT-V2",
            &[&checkpoint.encode_canonical()?],
        );
        let disposition_tag = match disposition {
            RouteInventoryReleaseDispositionV1::BothLegsTerminal => [1_u8],
            RouteInventoryReleaseDispositionV1::AbortedUnfunded => [2_u8],
        };
        let release_evidence_digest = domain_digest_v1(
            b"DOM-ROUTE-INVENTORY-RELEASE/V1",
            &[
                &route_id,
                &checkpoint.composition_v2_digest,
                &disposition_tag,
                &snapshot.revision.to_be_bytes(),
                &snapshot_digest,
                &snapshot.last_event_digest,
                &head.entry_hash,
                &checkpoint_digest,
            ],
        );
        RouteInventoryReleaseCapabilityV1::from_authenticated_replay(
            AuthenticatedRouteInventoryReleaseFactsV1 {
                route_id,
                composition_v2_digest: checkpoint.composition_v2_digest,
                disposition,
                revision: snapshot.revision,
                snapshot_digest,
                last_event_digest: snapshot.last_event_digest,
                journal_head_digest: head.entry_hash,
                admission_checkpoint_digest: checkpoint_digest,
                release_evidence_digest,
            },
        )
        .map_err(RouteStoreErrorV1::from)
    }

    /// Claims at most one dispatchable effect across runner and external-
    /// custody classes in their shared priority order.
    ///
    /// Selection, validation and the dispatch lease update occur in one
    /// `BEGIN IMMEDIATE` transaction. This is the primitive for a production
    /// scheduler that promises at most one external authority invocation per
    /// drive step; it never leases a second class speculatively.
    pub fn claim_next_effect(
        &mut self,
        lease: RouteLeaseV1,
        now_unix_ms: u64,
        dispatch_lease_ms: u64,
    ) -> Result<Option<ClaimedRouteWorkV1>, RouteStoreErrorV1> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        validate_lease(&transaction, lease, now_unix_ms)?;
        let snapshot = load_snapshot_in_transaction(&transaction, lease.route_id)?;
        let dispatch_until = dispatch_deadline(lease, now_unix_ms, dispatch_lease_ms)?;
        let now = to_sql_u64(now_unix_ms)?;
        let until = to_sql_u64(dispatch_until)?;
        let raw = {
            let mut statement = transaction.prepare(
                "SELECT effect_id, effect_bytes, effect_hash, attempts, dispatch_class
                 FROM route_outbox
                 WHERE route_id = ?1 AND fencing_epoch = ?2 AND status_tag = ?3
                   AND (dispatch_lease_until_unix_ms IS NULL
                        OR dispatch_lease_until_unix_ms < ?4)
                 ORDER BY priority_rank DESC, source_sequence ASC, effect_id ASC
                 LIMIT ?5",
            )?;
            let rows = statement.query_map(
                params![
                    lease.route_id.as_slice(),
                    to_sql_u64(lease.fencing_epoch)?,
                    STATUS_PENDING,
                    now,
                    i64::try_from(MAX_CLAIM_BATCH).map_err(|_| RouteStoreErrorV1::InvalidBound)?
                ],
                |row| {
                    Ok((
                        row.get::<_, Vec<u8>>(0)?,
                        row.get::<_, Vec<u8>>(1)?,
                        row.get::<_, Vec<u8>>(2)?,
                        row.get::<_, i64>(3)?,
                        row.get::<_, i64>(4)?,
                    ))
                },
            )?;
            rows.collect::<Result<Vec<_>, _>>()?
        };
        for (effect_id_bytes, effect_bytes, stored_hash, attempts, dispatch_class) in raw {
            let effect_id = blob32(effect_id_bytes)?;
            let effect_hash = blob32(stored_hash)?;
            if effect_hash != effect_hash_value(&effect_bytes) {
                return Err(RouteStoreErrorV1::CorruptState);
            }
            let effect = RouteEffectV1::decode_canonical(&effect_bytes)?;
            if effect.route_id != lease.route_id
                || effect.effect_id != effect_id
                || effect.fencing_epoch != lease.fencing_epoch
                || !matches!(
                    (&effect.dispatch, dispatch_class),
                    (
                        crate::model::EffectDispatchV1::RunnerPayload { .. },
                        DISPATCH_RUNNER
                    ) | (
                        crate::model::EffectDispatchV1::ExternalCustody { .. },
                        DISPATCH_EXTERNAL_CUSTODY
                    )
                )
            {
                return Err(RouteStoreErrorV1::CorruptState);
            }
            if !effect_is_dispatchable(&snapshot, &effect) {
                continue;
            }
            let next_attempts = from_sql_u64(attempts)?
                .checked_add(1)
                .ok_or(RouteStoreErrorV1::InvalidBound)?;
            let changed = transaction.execute(
                "UPDATE route_outbox
                 SET attempts = ?5, dispatch_lease_owner = ?6,
                     dispatch_lease_until_unix_ms = ?7
                 WHERE route_id = ?1 AND effect_id = ?2 AND fencing_epoch = ?3
                   AND status_tag = ?4 AND dispatch_class = ?8
                   AND (dispatch_lease_until_unix_ms IS NULL
                        OR dispatch_lease_until_unix_ms < ?9)",
                params![
                    lease.route_id.as_slice(),
                    effect_id.as_slice(),
                    to_sql_u64(lease.fencing_epoch)?,
                    STATUS_PENDING,
                    to_sql_u64(next_attempts)?,
                    lease.owner_id.as_slice(),
                    until,
                    dispatch_class,
                    now,
                ],
            )?;
            if changed != 1 {
                return Err(RouteStoreErrorV1::DispatchLeaseMismatch);
            }
            let claimed = match effect.dispatch.clone() {
                crate::model::EffectDispatchV1::RunnerPayload { .. } => {
                    ClaimedRouteWorkV1::Runner(ClaimedRouteEffectV1 {
                        effect,
                        effect_hash,
                        attempts: next_attempts,
                        dispatch_lease_until_unix_ms: dispatch_until,
                    })
                }
                crate::model::EffectDispatchV1::ExternalCustody {
                    custody_digest,
                    transaction_id,
                } => ClaimedRouteWorkV1::ExternalCustody(ClaimedExternalCustodyEffectV1 {
                    route_id: effect.route_id,
                    effect_id: effect.effect_id,
                    fencing_epoch: effect.fencing_epoch,
                    leg: effect.leg,
                    kind: effect.kind,
                    priority: effect.priority,
                    semantic_digest: effect.semantic_digest,
                    contains_route_secret: effect.contains_route_secret,
                    custody_digest,
                    transaction_id,
                    attempts: next_attempts,
                    dispatch_lease_until_unix_ms: dispatch_until,
                }),
            };
            transaction.commit()?;
            return Ok(Some(claimed));
        }
        transaction.commit()?;
        Ok(None)
    }

    /// Claim pending effects created by this exact fencing generation.  A new
    /// generation never blindly dispatches an old generation's effect.
    pub fn claim_effects(
        &mut self,
        lease: RouteLeaseV1,
        now_unix_ms: u64,
        dispatch_lease_ms: u64,
        limit: usize,
    ) -> Result<Vec<ClaimedRouteEffectV1>, RouteStoreErrorV1> {
        validate_claim_limit(limit)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        validate_lease(&transaction, lease, now_unix_ms)?;
        let snapshot = load_snapshot_in_transaction(&transaction, lease.route_id)?;
        let dispatch_until = dispatch_deadline(lease, now_unix_ms, dispatch_lease_ms)?;
        let now = to_sql_u64(now_unix_ms)?;
        let until = to_sql_u64(dispatch_until)?;
        let raw = {
            let mut statement = transaction.prepare(
                "SELECT effect_id, effect_bytes, effect_hash, attempts
                 FROM route_outbox
                 WHERE route_id = ?1 AND fencing_epoch = ?2 AND status_tag = ?3
                   AND dispatch_class = 0
                   AND (dispatch_lease_until_unix_ms IS NULL
                        OR dispatch_lease_until_unix_ms < ?4)
                 ORDER BY priority_rank DESC, source_sequence ASC, effect_id ASC
                 LIMIT ?5",
            )?;
            let rows = statement.query_map(
                params![
                    lease.route_id.as_slice(),
                    to_sql_u64(lease.fencing_epoch)?,
                    STATUS_PENDING,
                    now,
                    i64::try_from(limit).map_err(|_| RouteStoreErrorV1::InvalidBound)?
                ],
                |row| {
                    Ok((
                        row.get::<_, Vec<u8>>(0)?,
                        row.get::<_, Vec<u8>>(1)?,
                        row.get::<_, Vec<u8>>(2)?,
                        row.get::<_, i64>(3)?,
                    ))
                },
            )?;
            rows.collect::<Result<Vec<_>, _>>()?
        };
        let mut claimed = Vec::with_capacity(raw.len());
        for (effect_id_bytes, effect_bytes, stored_hash, attempts) in raw {
            let effect_id = blob32(effect_id_bytes)?;
            let effect_hash = blob32(stored_hash)?;
            if effect_hash != effect_hash_value(&effect_bytes) {
                return Err(RouteStoreErrorV1::CorruptState);
            }
            let effect = RouteEffectV1::decode_canonical(&effect_bytes)?;
            if effect.route_id != lease.route_id
                || effect.effect_id != effect_id
                || effect.fencing_epoch != lease.fencing_epoch
            {
                return Err(RouteStoreErrorV1::CorruptState);
            }
            if !effect_is_dispatchable(&snapshot, &effect) {
                continue;
            }
            let next_attempts = from_sql_u64(attempts)?
                .checked_add(1)
                .ok_or(RouteStoreErrorV1::InvalidBound)?;
            let changed = transaction.execute(
                "UPDATE route_outbox
                 SET attempts = ?4, dispatch_lease_owner = ?5,
                     dispatch_lease_until_unix_ms = ?6
                 WHERE route_id = ?1 AND effect_id = ?2 AND status_tag = ?3
                   AND (dispatch_lease_until_unix_ms IS NULL
                        OR dispatch_lease_until_unix_ms < ?7)",
                params![
                    lease.route_id.as_slice(),
                    effect_id.as_slice(),
                    STATUS_PENDING,
                    to_sql_u64(next_attempts)?,
                    lease.owner_id.as_slice(),
                    until,
                    now
                ],
            )?;
            if changed != 1 {
                return Err(RouteStoreErrorV1::DispatchLeaseMismatch);
            }
            claimed.push(ClaimedRouteEffectV1 {
                effect,
                effect_hash,
                attempts: next_attempts,
                dispatch_lease_until_unix_ms: dispatch_until,
            });
        }
        transaction.commit()?;
        Ok(claimed)
    }

    /// Claim external-custody effects without returning any retained action
    /// bytes.  Completion occurs only through a matching
    /// `ActionExternalized` event, which atomically advances the snapshot and
    /// closes this outbox row.
    pub fn claim_external_custody_effects(
        &mut self,
        lease: RouteLeaseV1,
        now_unix_ms: u64,
        dispatch_lease_ms: u64,
        limit: usize,
    ) -> Result<Vec<ClaimedExternalCustodyEffectV1>, RouteStoreErrorV1> {
        validate_claim_limit(limit)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        validate_lease(&transaction, lease, now_unix_ms)?;
        let snapshot = load_snapshot_in_transaction(&transaction, lease.route_id)?;
        let dispatch_until = dispatch_deadline(lease, now_unix_ms, dispatch_lease_ms)?;
        let now = to_sql_u64(now_unix_ms)?;
        let until = to_sql_u64(dispatch_until)?;
        let raw = {
            let mut statement = transaction.prepare(
                "SELECT effect_id, effect_bytes, effect_hash, attempts
                 FROM route_outbox
                 WHERE route_id = ?1 AND fencing_epoch = ?2 AND status_tag = ?3
                   AND dispatch_class = 1
                   AND (dispatch_lease_until_unix_ms IS NULL
                        OR dispatch_lease_until_unix_ms < ?4)
                 ORDER BY priority_rank DESC, source_sequence ASC, effect_id ASC
                 LIMIT ?5",
            )?;
            let rows = statement.query_map(
                params![
                    lease.route_id.as_slice(),
                    to_sql_u64(lease.fencing_epoch)?,
                    STATUS_PENDING,
                    now,
                    i64::try_from(limit).map_err(|_| RouteStoreErrorV1::InvalidBound)?
                ],
                |row| {
                    Ok((
                        row.get::<_, Vec<u8>>(0)?,
                        row.get::<_, Vec<u8>>(1)?,
                        row.get::<_, Vec<u8>>(2)?,
                        row.get::<_, i64>(3)?,
                    ))
                },
            )?;
            rows.collect::<Result<Vec<_>, _>>()?
        };
        let mut claimed = Vec::with_capacity(raw.len());
        for (effect_id_bytes, effect_bytes, stored_hash, attempts) in raw {
            let effect_id = blob32(effect_id_bytes)?;
            if blob32(stored_hash)? != effect_hash_value(&effect_bytes) {
                return Err(RouteStoreErrorV1::CorruptState);
            }
            let effect = RouteEffectV1::decode_canonical(&effect_bytes)?;
            if effect.route_id != lease.route_id
                || effect.effect_id != effect_id
                || effect.fencing_epoch != lease.fencing_epoch
            {
                return Err(RouteStoreErrorV1::CorruptState);
            }
            if !effect_is_dispatchable(&snapshot, &effect) {
                continue;
            }
            let (custody_digest, transaction_id) = match effect.dispatch {
                crate::model::EffectDispatchV1::ExternalCustody {
                    custody_digest,
                    transaction_id,
                } => (custody_digest, transaction_id),
                crate::model::EffectDispatchV1::RunnerPayload { .. } => {
                    return Err(RouteStoreErrorV1::CorruptState)
                }
            };
            let next_attempts = from_sql_u64(attempts)?
                .checked_add(1)
                .ok_or(RouteStoreErrorV1::InvalidBound)?;
            let changed = transaction.execute(
                "UPDATE route_outbox
                 SET attempts = ?4, dispatch_lease_owner = ?5,
                     dispatch_lease_until_unix_ms = ?6
                 WHERE route_id = ?1 AND effect_id = ?2 AND status_tag = ?3
                   AND dispatch_class = 1
                   AND (dispatch_lease_until_unix_ms IS NULL
                        OR dispatch_lease_until_unix_ms < ?7)",
                params![
                    lease.route_id.as_slice(),
                    effect_id.as_slice(),
                    STATUS_PENDING,
                    to_sql_u64(next_attempts)?,
                    lease.owner_id.as_slice(),
                    until,
                    now
                ],
            )?;
            if changed != 1 {
                return Err(RouteStoreErrorV1::DispatchLeaseMismatch);
            }
            claimed.push(ClaimedExternalCustodyEffectV1 {
                route_id: effect.route_id,
                effect_id: effect.effect_id,
                fencing_epoch: effect.fencing_epoch,
                leg: effect.leg,
                kind: effect.kind,
                priority: effect.priority,
                semantic_digest: effect.semantic_digest,
                contains_route_secret: effect.contains_route_secret,
                custody_digest,
                transaction_id,
                attempts: next_attempts,
                dispatch_lease_until_unix_ms: dispatch_until,
            });
        }
        transaction.commit()?;
        Ok(claimed)
    }

    /// Claim one exact external-custody effect without leasing any lower
    /// priority row when the requested effect is already in flight.
    ///
    /// This is the fail-closed dispatch primitive for the secret-public urgent
    /// lane. `None` means only that the exact valid pending effect is still
    /// covered by a prior dispatch lease; it never falls through to another
    /// effect. Missing or structurally inconsistent rows fail closed.
    pub fn claim_external_custody_effect_by_id(
        &mut self,
        lease: RouteLeaseV1,
        effect_id: EffectIdV1,
        now_unix_ms: u64,
        dispatch_lease_ms: u64,
    ) -> Result<Option<ClaimedExternalCustodyEffectV1>, RouteStoreErrorV1> {
        validate_identity(effect_id)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        validate_lease(&transaction, lease, now_unix_ms)?;
        let snapshot = load_snapshot_in_transaction(&transaction, lease.route_id)?;
        let dispatch_until = dispatch_deadline(lease, now_unix_ms, dispatch_lease_ms)?;
        let now = to_sql_u64(now_unix_ms)?;
        let until = to_sql_u64(dispatch_until)?;
        let raw = transaction
            .query_row(
                "SELECT effect_bytes, effect_hash, attempts, fencing_epoch,
                        status_tag, dispatch_class, dispatch_lease_until_unix_ms
                 FROM route_outbox
                 WHERE route_id = ?1 AND effect_id = ?2",
                params![lease.route_id.as_slice(), effect_id.as_slice()],
                |row| {
                    Ok((
                        row.get::<_, Vec<u8>>(0)?,
                        row.get::<_, Vec<u8>>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, i64>(3)?,
                        row.get::<_, i64>(4)?,
                        row.get::<_, i64>(5)?,
                        row.get::<_, Option<i64>>(6)?,
                    ))
                },
            )
            .optional()?;
        let Some((
            effect_bytes,
            stored_hash,
            attempts,
            stored_fence,
            status,
            dispatch_class,
            active_dispatch_until,
        )) = raw
        else {
            return Err(RouteStoreErrorV1::EffectNotFound);
        };
        if from_sql_u64(stored_fence)? != lease.fencing_epoch
            || status != STATUS_PENDING
            || dispatch_class != DISPATCH_EXTERNAL_CUSTODY
        {
            return Err(RouteStoreErrorV1::CorruptState);
        }
        if blob32(stored_hash)? != effect_hash_value(&effect_bytes) {
            return Err(RouteStoreErrorV1::CorruptState);
        }
        let effect = RouteEffectV1::decode_canonical(&effect_bytes)?;
        if effect.route_id != lease.route_id
            || effect.effect_id != effect_id
            || effect.fencing_epoch != lease.fencing_epoch
            || effect.priority != EffectPriorityV1::SecretPublicUrgent
        {
            return Err(RouteStoreErrorV1::CorruptState);
        }
        if let Some(active_until) = active_dispatch_until {
            if from_sql_u64(active_until)? >= now_unix_ms {
                transaction.commit()?;
                return Ok(None);
            }
        }
        if !effect_is_dispatchable(&snapshot, &effect) {
            return Err(RouteStoreErrorV1::CorruptState);
        }
        let (custody_digest, transaction_id) = match effect.dispatch {
            crate::model::EffectDispatchV1::ExternalCustody {
                custody_digest,
                transaction_id,
            } => (custody_digest, transaction_id),
            crate::model::EffectDispatchV1::RunnerPayload { .. } => {
                return Err(RouteStoreErrorV1::CorruptState)
            }
        };
        let next_attempts = from_sql_u64(attempts)?
            .checked_add(1)
            .ok_or(RouteStoreErrorV1::InvalidBound)?;
        let changed = transaction.execute(
            "UPDATE route_outbox
             SET attempts = ?5, dispatch_lease_owner = ?6,
                 dispatch_lease_until_unix_ms = ?7
             WHERE route_id = ?1 AND effect_id = ?2 AND fencing_epoch = ?3
               AND status_tag = ?4 AND dispatch_class = ?8 AND priority_rank = ?9
               AND (dispatch_lease_until_unix_ms IS NULL
                    OR dispatch_lease_until_unix_ms < ?10)",
            params![
                lease.route_id.as_slice(),
                effect_id.as_slice(),
                to_sql_u64(lease.fencing_epoch)?,
                STATUS_PENDING,
                to_sql_u64(next_attempts)?,
                lease.owner_id.as_slice(),
                until,
                DISPATCH_EXTERNAL_CUSTODY,
                priority_rank_v1(EffectPriorityV1::SecretPublicUrgent),
                now,
            ],
        )?;
        if changed != 1 {
            return Err(RouteStoreErrorV1::DispatchLeaseMismatch);
        }
        let claimed = ClaimedExternalCustodyEffectV1 {
            route_id: effect.route_id,
            effect_id: effect.effect_id,
            fencing_epoch: effect.fencing_epoch,
            leg: effect.leg,
            kind: effect.kind,
            priority: effect.priority,
            semantic_digest: effect.semantic_digest,
            contains_route_secret: effect.contains_route_secret,
            custody_digest,
            transaction_id,
            attempts: next_attempts,
            dispatch_lease_until_unix_ms: dispatch_until,
        };
        transaction.commit()?;
        Ok(Some(claimed))
    }

    /// Claim due timers under the current route lease.
    ///
    /// Timers are internal wakeups, not signer/broadcast capabilities. A new
    /// owner may therefore consume a timer created by an older epoch. The
    /// resulting route event is still committed under the new fence, while
    /// a stale owner cannot claim or complete the timer.
    pub fn claim_due_timers(
        &mut self,
        lease: RouteLeaseV1,
        now_unix_ms: u64,
        dispatch_lease_ms: u64,
        limit: usize,
    ) -> Result<Vec<ClaimedRouteTimerV1>, RouteStoreErrorV1> {
        validate_claim_limit(limit)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        validate_lease(&transaction, lease, now_unix_ms)?;
        let dispatch_until = dispatch_deadline(lease, now_unix_ms, dispatch_lease_ms)?;
        let now = to_sql_u64(now_unix_ms)?;
        let until = to_sql_u64(dispatch_until)?;
        let raw = {
            let mut statement = transaction.prepare(
                "SELECT timer_id, timer_bytes, timer_hash, attempts
                 FROM route_timers
                 WHERE route_id = ?1 AND status_tag = ?2
                   AND deadline_unix_ms <= ?3
                   AND (dispatch_lease_until_unix_ms IS NULL
                        OR dispatch_lease_until_unix_ms < ?3)
                 ORDER BY deadline_unix_ms ASC, source_sequence ASC, timer_id ASC
                 LIMIT ?4",
            )?;
            let rows = statement.query_map(
                params![
                    lease.route_id.as_slice(),
                    STATUS_PENDING,
                    now,
                    i64::try_from(limit).map_err(|_| RouteStoreErrorV1::InvalidBound)?
                ],
                |row| {
                    Ok((
                        row.get::<_, Vec<u8>>(0)?,
                        row.get::<_, Vec<u8>>(1)?,
                        row.get::<_, Vec<u8>>(2)?,
                        row.get::<_, i64>(3)?,
                    ))
                },
            )?;
            rows.collect::<Result<Vec<_>, _>>()?
        };
        let mut claimed = Vec::with_capacity(raw.len());
        for (timer_id_bytes, timer_bytes, stored_hash, attempts) in raw {
            let timer_id = blob32(timer_id_bytes)?;
            let timer_hash = blob32(stored_hash)?;
            if timer_hash != timer_hash_value(&timer_bytes) {
                return Err(RouteStoreErrorV1::CorruptState);
            }
            let timer = RouteTimerV1::decode_canonical(&timer_bytes)?;
            if timer.route_id != lease.route_id
                || timer.timer_id != timer_id
                || timer.fencing_epoch > lease.fencing_epoch
            {
                return Err(RouteStoreErrorV1::CorruptState);
            }
            let next_attempts = from_sql_u64(attempts)?
                .checked_add(1)
                .ok_or(RouteStoreErrorV1::InvalidBound)?;
            let changed = transaction.execute(
                "UPDATE route_timers
                 SET attempts = ?4, dispatch_lease_owner = ?5,
                     dispatch_lease_until_unix_ms = ?6
                 WHERE route_id = ?1 AND timer_id = ?2 AND status_tag = ?3
                   AND (dispatch_lease_until_unix_ms IS NULL
                        OR dispatch_lease_until_unix_ms < ?7)",
                params![
                    lease.route_id.as_slice(),
                    timer_id.as_slice(),
                    STATUS_PENDING,
                    to_sql_u64(next_attempts)?,
                    lease.owner_id.as_slice(),
                    until,
                    now
                ],
            )?;
            if changed != 1 {
                return Err(RouteStoreErrorV1::DispatchLeaseMismatch);
            }
            claimed.push(ClaimedRouteTimerV1 {
                timer,
                timer_hash,
                attempts: next_attempts,
                dispatch_lease_until_unix_ms: dispatch_until,
            });
        }
        transaction.commit()?;
        Ok(claimed)
    }

    /// Complete one claimed timer under the current route/dispatch leases.
    pub fn complete_timer(
        &mut self,
        lease: RouteLeaseV1,
        timer_id: TimerIdV1,
        timer_hash: Digest32,
        now_unix_ms: u64,
    ) -> Result<CompletionOutcomeV1, RouteStoreErrorV1> {
        validate_identity(timer_id)?;
        validate_identity(timer_hash)?;
        let now = to_sql_u64(now_unix_ms)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        validate_lease(&transaction, lease, now_unix_ms)?;
        let row: Option<TimerCompletionRow> = transaction
            .query_row(
                "SELECT timer_hash, status_tag, dispatch_lease_owner,
                        dispatch_lease_until_unix_ms, fencing_epoch
                 FROM route_timers WHERE route_id = ?1 AND timer_id = ?2",
                params![lease.route_id.as_slice(), timer_id.as_slice()],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                    ))
                },
            )
            .optional()?;
        let (stored_hash, status, dispatch_owner, dispatch_until, fence) =
            row.ok_or(RouteStoreErrorV1::TimerNotFound)?;
        if blob32(stored_hash)? != timer_hash || from_sql_u64(fence)? > lease.fencing_epoch {
            return Err(RouteStoreErrorV1::IdempotencyConflict);
        }
        if status == STATUS_COMPLETED {
            return Ok(CompletionOutcomeV1::AlreadyCompleted);
        }
        if status != STATUS_PENDING
            || dispatch_owner.map(blob32).transpose()? != Some(lease.owner_id)
            || match dispatch_until.map(from_sql_u64).transpose()? {
                Some(deadline) => deadline < now_unix_ms,
                None => true,
            }
        {
            return Err(RouteStoreErrorV1::DispatchLeaseMismatch);
        }
        let changed = transaction.execute(
            "UPDATE route_timers
             SET status_tag = ?3, completed_at_unix_ms = ?4,
                 dispatch_lease_owner = NULL, dispatch_lease_until_unix_ms = NULL
             WHERE route_id = ?1 AND timer_id = ?2 AND status_tag = ?5",
            params![
                lease.route_id.as_slice(),
                timer_id.as_slice(),
                STATUS_COMPLETED,
                now,
                STATUS_PENDING
            ],
        )?;
        if changed != 1 {
            return Err(RouteStoreErrorV1::DispatchLeaseMismatch);
        }
        transaction.commit()?;
        Ok(CompletionOutcomeV1::Completed)
    }

    /// Count unfinished outbox rows across generations for diagnostics and
    /// takeover reconciliation.  This does not lease or expose payload bytes.
    pub fn pending_effect_count(&self, route_id: RouteIdV1) -> Result<u64, RouteStoreErrorV1> {
        let count: i64 = self.connection.query_row(
            "SELECT COUNT(*) FROM route_outbox WHERE route_id = ?1 AND status_tag = ?2",
            params![route_id.as_slice(), STATUS_PENDING],
            |row| row.get(0),
        )?;
        from_sql_u64(count)
    }

    /// Count active timers across fencing generations.
    pub fn active_timer_count(&self, route_id: RouteIdV1) -> Result<u64, RouteStoreErrorV1> {
        let count: i64 = self.connection.query_row(
            "SELECT COUNT(*) FROM route_timers WHERE route_id = ?1 AND status_tag = ?2",
            params![route_id.as_slice(), STATUS_PENDING],
            |row| row.get(0),
        )?;
        from_sql_u64(count)
    }
}

fn configure_connection(connection: &Connection) -> Result<(), RouteStoreErrorV1> {
    connection.busy_timeout(Duration::from_millis(5_000))?;
    let mode: String = connection.query_row("PRAGMA journal_mode=WAL", [], |row| row.get(0))?;
    if !mode.eq_ignore_ascii_case("wal") {
        return Err(RouteStoreErrorV1::StorageUnavailable);
    }
    connection.pragma_update(None, "synchronous", "FULL")?;
    connection.pragma_update(None, "foreign_keys", "ON")?;
    connection.pragma_update(None, "read_uncommitted", "OFF")?;
    connection.pragma_update(None, "trusted_schema", "OFF")?;
    connection.pragma_update(None, "secure_delete", "ON")?;
    let defensive = rusqlite::config::DbConfig::SQLITE_DBCONFIG_DEFENSIVE;
    if !connection.set_db_config(defensive, true)? || !connection.db_config(defensive)? {
        return Err(RouteStoreErrorV1::UnsupportedFormat);
    }
    let synchronous: i64 = connection.query_row("PRAGMA synchronous", [], |row| row.get(0))?;
    let foreign_keys: i64 = connection.query_row("PRAGMA foreign_keys", [], |row| row.get(0))?;
    let read_uncommitted: i64 =
        connection.query_row("PRAGMA read_uncommitted", [], |row| row.get(0))?;
    let trusted_schema: i64 =
        connection.query_row("PRAGMA trusted_schema", [], |row| row.get(0))?;
    let secure_delete: i64 = connection.query_row("PRAGMA secure_delete", [], |row| row.get(0))?;
    let busy_timeout: i64 = connection.query_row("PRAGMA busy_timeout", [], |row| row.get(0))?;
    if synchronous != 2
        || foreign_keys != 1
        || read_uncommitted != 0
        || trusted_schema != 0
        || secure_delete != 1
        || busy_timeout != 5_000
    {
        return Err(RouteStoreErrorV1::UnsupportedFormat);
    }
    Ok(())
}

fn validate_backend_and_schema(connection: &Connection) -> Result<(), RouteStoreErrorV1> {
    let quick: String = connection.query_row("PRAGMA quick_check(1)", [], |row| row.get(0))?;
    if quick != "ok" {
        return Err(RouteStoreErrorV1::CorruptState);
    }
    let version: i64 = connection.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    if version != SCHEMA_VERSION {
        return Err(RouteStoreErrorV1::UnsupportedFormat);
    }
    let objects = schema_objects(connection)?;
    // Build the reference in memory through the one authoritative migration.
    // Comparing sqlite_schema SQL as well as names catches added columns,
    // weakened CHECK/FK constraints, changed indexes and loss of STRICT.
    let reference = Connection::open_in_memory()?;
    let mut reference_store = DurableRouteStoreV1 {
        connection: reference,
        #[cfg(target_os = "linux")]
        _process_lock: None,
    };
    reference_store.migrate()?;
    let expected = schema_objects(&reference_store.connection)?;
    if objects != expected {
        return Err(RouteStoreErrorV1::CorruptState);
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ResumableCreationStateV1 {
    PristineSqlite,
    PristineInitialized,
}

fn resumable_creation_state(
    connection: &Connection,
) -> Result<ResumableCreationStateV1, RouteStoreErrorV1> {
    let quick: String = connection.query_row("PRAGMA quick_check(1)", [], |row| row.get(0))?;
    let foreign: String = connection.query_row(
        "SELECT CASE WHEN EXISTS(SELECT 1 FROM pragma_foreign_key_check) THEN 'bad' ELSE 'ok' END",
        [],
        |row| row.get(0),
    )?;
    let version: i64 = connection.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    let application_id: i64 =
        connection.query_row("PRAGMA application_id", [], |row| row.get(0))?;
    let objects = schema_objects(connection)?;
    if quick != "ok" || foreign != "ok" || application_id != 0 {
        return Err(RouteStoreErrorV1::CorruptState);
    }
    if version == 0 && objects.is_empty() {
        return Ok(ResumableCreationStateV1::PristineSqlite);
    }
    if version == SCHEMA_VERSION {
        validate_backend_and_schema(connection)?;
        return Ok(ResumableCreationStateV1::PristineInitialized);
    }
    Err(RouteStoreErrorV1::UnsupportedFormat)
}

fn validate_pristine_initialized_store(connection: &Connection) -> Result<(), RouteStoreErrorV1> {
    validate_backend_and_schema(connection)?;
    let application_id: i64 =
        connection.query_row("PRAGMA application_id", [], |row| row.get(0))?;
    let foreign: String = connection.query_row(
        "SELECT CASE WHEN EXISTS(SELECT 1 FROM pragma_foreign_key_check) THEN 'bad' ELSE 'ok' END",
        [],
        |row| row.get(0),
    )?;
    let counts: (i64, i64, i64, i64, i64) = connection.query_row(
        "SELECT
             (SELECT COUNT(*) FROM route_snapshots),
             (SELECT COUNT(*) FROM route_leases),
             (SELECT COUNT(*) FROM route_journal),
             (SELECT COUNT(*) FROM route_outbox),
             (SELECT COUNT(*) FROM route_timers)",
        [],
        |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
            ))
        },
    )?;
    if application_id != 0 || foreign != "ok" || counts != (0, 0, 0, 0, 0) {
        return Err(RouteStoreErrorV1::CorruptState);
    }
    Ok(())
}

fn validate_retained_state_on_open(store: &DurableRouteStoreV1) -> Result<(), RouteStoreErrorV1> {
    let foreign: String = store.connection.query_row(
        "SELECT CASE WHEN EXISTS(SELECT 1 FROM pragma_foreign_key_check) THEN 'bad' ELSE 'ok' END",
        [],
        |row| row.get(0),
    )?;
    if foreign != "ok" {
        return Err(RouteStoreErrorV1::CorruptState);
    }

    let route_ids = {
        let mut statement = store
            .connection
            .prepare("SELECT route_id FROM route_snapshots ORDER BY route_id")?;
        let rows = statement.query_map([], |row| row.get::<_, Vec<u8>>(0))?;
        rows.collect::<core::result::Result<Vec<_>, _>>()?
    };
    for route_id in route_ids {
        let route_id = blob32(route_id).map_err(|_| RouteStoreErrorV1::CorruptState)?;
        validate_identity(route_id).map_err(|_| RouteStoreErrorV1::CorruptState)?;
        store
            .verify_replay(route_id)
            .map_err(|_| RouteStoreErrorV1::CorruptState)?;
    }

    let leases = {
        let mut statement = store.connection.prepare(
            "SELECT route_id, owner_id, fencing_epoch, lease_until_unix_ms,
                    updated_at_unix_ms
             FROM route_leases ORDER BY route_id",
        )?;
        let rows = statement.query_map([], |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
            ))
        })?;
        rows.collect::<core::result::Result<Vec<RetainedLeaseAuditRow>, _>>()?
    };
    for (route_id, owner_id, fencing_epoch, lease_until, updated_at) in leases {
        if validate_identity(blob32(route_id)?).is_err()
            || validate_identity(blob32(owner_id)?).is_err()
            || from_sql_u64(fencing_epoch)? == 0
        {
            return Err(RouteStoreErrorV1::CorruptState);
        }
        let _ = from_sql_u64(lease_until)?;
        let _ = from_sql_u64(updated_at)?;
    }

    let effects = {
        let mut statement = store.connection.prepare(
            "SELECT route_id, effect_id, source_sequence, fencing_epoch,
                    priority_rank, dispatch_class, effect_bytes, effect_hash,
                    status_tag, attempts, dispatch_lease_owner,
                    dispatch_lease_until_unix_ms, completed_at_unix_ms
             FROM route_outbox ORDER BY route_id, effect_id",
        )?;
        let rows = statement.query_map([], |row| {
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
        })?;
        rows.collect::<core::result::Result<Vec<RetainedEffectAuditRow>, _>>()?
    };
    for row in effects {
        validate_retained_effect_row(row)?;
    }

    let timers = {
        let mut statement = store.connection.prepare(
            "SELECT route_id, timer_id, source_sequence, fencing_epoch,
                    deadline_unix_ms, timer_bytes, timer_hash, status_tag,
                    attempts, dispatch_lease_owner, dispatch_lease_until_unix_ms,
                    completed_at_unix_ms
             FROM route_timers ORDER BY route_id, timer_id",
        )?;
        let rows = statement.query_map([], |row| {
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
            ))
        })?;
        rows.collect::<core::result::Result<Vec<RetainedTimerAuditRow>, _>>()?
    };
    for row in timers {
        validate_retained_timer_row(row)?;
    }
    Ok(())
}

fn validate_retained_effect_row(row: RetainedEffectAuditRow) -> Result<(), RouteStoreErrorV1> {
    let (
        route_id,
        effect_id,
        source_sequence,
        fencing_epoch,
        priority_rank,
        dispatch_class,
        effect_bytes,
        stored_hash,
        status,
        attempts,
        dispatch_owner,
        dispatch_until,
        completed_at,
    ) = row;
    let route_id = blob32(route_id)?;
    let effect_id = blob32(effect_id)?;
    let effect = RouteEffectV1::decode_canonical(&effect_bytes)
        .map_err(|_| RouteStoreErrorV1::CorruptState)?;
    let expected_dispatch_class = match effect.dispatch {
        crate::model::EffectDispatchV1::RunnerPayload { .. } => DISPATCH_RUNNER,
        crate::model::EffectDispatchV1::ExternalCustody { .. } => DISPATCH_EXTERNAL_CUSTODY,
    };
    if validate_identity(route_id).is_err()
        || validate_identity(effect_id).is_err()
        || from_sql_u64(source_sequence)? == 0
        || from_sql_u64(fencing_epoch)? == 0
        || effect.route_id != route_id
        || effect.effect_id != effect_id
        || to_sql_u64(effect.fencing_epoch)? != fencing_epoch
        || priority_rank_v1(effect.priority) != priority_rank
        || expected_dispatch_class != dispatch_class
        || blob32(stored_hash)? != effect_hash_value(&effect_bytes)
        || !matches!(
            status,
            STATUS_PENDING | STATUS_COMPLETED | STATUS_SUPERSEDED
        )
    {
        return Err(RouteStoreErrorV1::CorruptState);
    }
    let _ = from_sql_u64(attempts)?;
    validate_dispatch_lifecycle(status, dispatch_owner, dispatch_until, completed_at)
}

fn validate_retained_timer_row(row: RetainedTimerAuditRow) -> Result<(), RouteStoreErrorV1> {
    let (
        route_id,
        timer_id,
        source_sequence,
        fencing_epoch,
        deadline,
        timer_bytes,
        stored_hash,
        status,
        attempts,
        dispatch_owner,
        dispatch_until,
        completed_at,
    ) = row;
    let route_id = blob32(route_id)?;
    let timer_id = blob32(timer_id)?;
    let timer = RouteTimerV1::decode_canonical(&timer_bytes)
        .map_err(|_| RouteStoreErrorV1::CorruptState)?;
    if validate_identity(route_id).is_err()
        || validate_identity(timer_id).is_err()
        || from_sql_u64(source_sequence)? == 0
        || from_sql_u64(fencing_epoch)? == 0
        || timer.route_id != route_id
        || timer.timer_id != timer_id
        || to_sql_u64(timer.fencing_epoch)? != fencing_epoch
        || to_sql_u64(timer.deadline_unix_ms)? != deadline
        || blob32(stored_hash)? != timer_hash_value(&timer_bytes)
        || !matches!(status, STATUS_PENDING | STATUS_COMPLETED | TIMER_CANCELLED)
    {
        return Err(RouteStoreErrorV1::CorruptState);
    }
    let _ = from_sql_u64(attempts)?;
    validate_dispatch_lifecycle(status, dispatch_owner, dispatch_until, completed_at)
}

fn validate_dispatch_lifecycle(
    status: i64,
    dispatch_owner: Option<Vec<u8>>,
    dispatch_until: Option<i64>,
    completed_at: Option<i64>,
) -> Result<(), RouteStoreErrorV1> {
    let has_dispatch_lease = match (dispatch_owner, dispatch_until) {
        (Some(owner), Some(until)) => {
            validate_identity(blob32(owner)?).map_err(|_| RouteStoreErrorV1::CorruptState)?;
            let _ = from_sql_u64(until)?;
            true
        }
        (None, None) => false,
        _ => return Err(RouteStoreErrorV1::CorruptState),
    };
    match (status, completed_at, has_dispatch_lease) {
        (STATUS_PENDING, None, _) => Ok(()),
        (STATUS_COMPLETED | STATUS_SUPERSEDED, Some(value), false) => {
            let _ = from_sql_u64(value)?;
            Ok(())
        }
        _ => Err(RouteStoreErrorV1::CorruptState),
    }
}

type SchemaObjectV1 = (String, String, String, String);

fn schema_objects(connection: &Connection) -> Result<BTreeSet<SchemaObjectV1>, RouteStoreErrorV1> {
    const MAX_SCHEMA_OBJECTS: i64 = 16;
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
        return Err(RouteStoreErrorV1::CorruptState);
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
            return Err(RouteStoreErrorV1::CorruptState);
        }
    }
    if i64::try_from(objects.len()).map_err(|_| RouteStoreErrorV1::CorruptState)? != count {
        return Err(RouteStoreErrorV1::CorruptState);
    }
    Ok(objects)
}

fn validate_database_path(
    connection: &Connection,
    expected_path: &Path,
) -> Result<(), RouteStoreErrorV1> {
    let expected =
        fs::canonicalize(expected_path).map_err(|_| RouteStoreErrorV1::InvalidStorageAuthority)?;
    if expected != expected_path {
        return Err(RouteStoreErrorV1::InvalidStorageAuthority);
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
            _ => return Err(RouteStoreErrorV1::InvalidStorageAuthority),
        }
    }
    if !saw_main {
        return Err(RouteStoreErrorV1::InvalidStorageAuthority);
    }
    Ok(())
}

fn create_owner_database_file(path: &Path) -> Result<(), RouteStoreErrorV1> {
    let mut options = OpenOptions::new();
    options.read(true).write(true).create_new(true);
    #[cfg(target_os = "linux")]
    options.mode(FILE_MODE);
    let file = options
        .open(path)
        .map_err(|_| RouteStoreErrorV1::StorageUnavailable)?;
    file.sync_all()
        .map_err(|_| RouteStoreErrorV1::StorageUnavailable)?;
    drop(file);
    #[cfg(target_os = "linux")]
    {
        validate_owner_file(path)?;
        sync_owner_directory(
            path.parent()
                .ok_or(RouteStoreErrorV1::InvalidStorageAuthority)?,
        )?;
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn validate_owner_directory(path: &Path) -> Result<(), RouteStoreErrorV1> {
    let metadata =
        fs::symlink_metadata(path).map_err(|_| RouteStoreErrorV1::InvalidStorageAuthority)?;
    if !metadata.file_type().is_dir()
        || metadata.file_type().is_symlink()
        || metadata.uid() != geteuid().as_raw()
        || metadata.mode() & 0o7777 != DIRECTORY_MODE
        || metadata.nlink() == 0
    {
        return Err(RouteStoreErrorV1::InvalidStorageAuthority);
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn validate_owner_file(path: &Path) -> Result<(), RouteStoreErrorV1> {
    let metadata =
        fs::symlink_metadata(path).map_err(|_| RouteStoreErrorV1::InvalidStorageAuthority)?;
    if !metadata.file_type().is_file()
        || metadata.file_type().is_symlink()
        || metadata.uid() != geteuid().as_raw()
        || metadata.mode() & 0o7777 != FILE_MODE
        || metadata.nlink() != 1
    {
        return Err(RouteStoreErrorV1::InvalidStorageAuthority);
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn validate_resumable_sqlite_sidecars(path: &Path) -> Result<(), RouteStoreErrorV1> {
    for (suffix, kind) in [
        ("-wal", SqliteSidecarKindV1::Wal),
        ("-shm", SqliteSidecarKindV1::SharedMemory),
        ("-journal", SqliteSidecarKindV1::RollbackJournal),
    ] {
        let mut sidecar = path.as_os_str().to_os_string();
        sidecar.push(suffix);
        let sidecar = std::path::PathBuf::from(sidecar);
        match fs::symlink_metadata(&sidecar) {
            Ok(_) => validate_sqlite_sidecar_shape(&sidecar, kind)?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err(RouteStoreErrorV1::StorageUnavailable),
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SqliteSidecarKindV1 {
    Wal,
    SharedMemory,
    RollbackJournal,
}

#[cfg(target_os = "linux")]
fn validate_sqlite_sidecar_shape(
    path: &Path,
    kind: SqliteSidecarKindV1,
) -> Result<(), RouteStoreErrorV1> {
    validate_owner_file(path)?;
    let mut file = OpenOptions::new()
        .read(true)
        .open(path)
        .map_err(|_| RouteStoreErrorV1::StorageUnavailable)?;
    let retained = file
        .metadata()
        .map_err(|_| RouteStoreErrorV1::StorageUnavailable)?;
    let named = fs::symlink_metadata(path).map_err(|_| RouteStoreErrorV1::StorageUnavailable)?;
    if retained.dev() != named.dev() || retained.ino() != named.ino() {
        return Err(RouteStoreErrorV1::InvalidStorageAuthority);
    }
    if retained.len() == 0 {
        return Ok(());
    }
    let mut header = [0u8; 8];
    file.read_exact(&mut header)
        .map_err(|_| RouteStoreErrorV1::InvalidStorageAuthority)?;
    let valid = match kind {
        SqliteSidecarKindV1::Wal => {
            retained.len() >= 32
                && matches!(
                    u32::from_be_bytes(
                        header[..4]
                            .try_into()
                            .map_err(|_| RouteStoreErrorV1::InvalidStorageAuthority)?
                    ),
                    0x377f_0682 | 0x377f_0683
                )
        }
        SqliteSidecarKindV1::SharedMemory => {
            retained.len() >= 32_768
                && retained.len() % 32_768 == 0
                && u32::from_ne_bytes(
                    header[..4]
                        .try_into()
                        .map_err(|_| RouteStoreErrorV1::InvalidStorageAuthority)?,
                ) == 3_007_000
        }
        SqliteSidecarKindV1::RollbackJournal => {
            retained.len() >= 28 && header == [0xd9, 0xd5, 0x05, 0xf9, 0x20, 0xa1, 0x63, 0xd7]
        }
    };
    if !valid {
        return Err(RouteStoreErrorV1::InvalidStorageAuthority);
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn require_sqlite_sidecars_absent(path: &Path) -> Result<(), RouteStoreErrorV1> {
    for suffix in ["-wal", "-shm", "-journal"] {
        let mut sidecar = path.as_os_str().to_os_string();
        sidecar.push(suffix);
        match fs::symlink_metadata(std::path::PathBuf::from(sidecar)) {
            Ok(_) => return Err(RouteStoreErrorV1::InvalidStorageAuthority),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err(RouteStoreErrorV1::StorageUnavailable),
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn process_lock_path(path: &Path) -> std::path::PathBuf {
    let mut value = path.as_os_str().to_os_string();
    value.push(".lock");
    std::path::PathBuf::from(value)
}

#[cfg(target_os = "linux")]
fn acquire_process_lock(path: &Path, create: bool) -> Result<File, RouteStoreErrorV1> {
    let lock_path = process_lock_path(path);
    let mut options = OpenOptions::new();
    options.read(true).write(true).mode(FILE_MODE);
    if create {
        options.create_new(true);
    }
    let file = options
        .open(&lock_path)
        .map_err(|_| RouteStoreErrorV1::StorageUnavailable)?;
    validate_owner_file(&lock_path)?;
    let retained = file
        .metadata()
        .map_err(|_| RouteStoreErrorV1::StorageUnavailable)?;
    let named =
        fs::symlink_metadata(&lock_path).map_err(|_| RouteStoreErrorV1::StorageUnavailable)?;
    if retained.dev() != named.dev() || retained.ino() != named.ino() {
        return Err(RouteStoreErrorV1::InvalidStorageAuthority);
    }
    flock(file.as_fd(), FlockOperation::NonBlockingLockExclusive)
        .map_err(|_| RouteStoreErrorV1::StorageUnavailable)?;
    if create {
        file.sync_all()
            .map_err(|_| RouteStoreErrorV1::StorageUnavailable)?;
        sync_owner_directory(
            path.parent()
                .ok_or(RouteStoreErrorV1::InvalidStorageAuthority)?,
        )?;
    }
    Ok(file)
}

#[cfg(target_os = "linux")]
fn sync_owner_directory(path: &Path) -> Result<(), RouteStoreErrorV1> {
    fs::File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| RouteStoreErrorV1::StorageUnavailable)
}

impl DurableRouteStoreV1 {
    fn migrate(&mut self) -> Result<(), RouteStoreErrorV1> {
        self.migrate_with_boundary_hook(|| Ok(()))
    }

    fn migrate_with_boundary_hook<F>(&mut self, before_commit: F) -> Result<(), RouteStoreErrorV1>
    where
        F: FnOnce() -> Result<(), RouteStoreErrorV1>,
    {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let version: i64 = transaction.query_row("PRAGMA user_version", [], |row| row.get(0))?;
        if version > SCHEMA_VERSION {
            return Err(RouteStoreErrorV1::UnsupportedFormat);
        }
        if version < 1 {
            transaction.execute_batch(
                "CREATE TABLE route_snapshots (
                    route_id BLOB PRIMARY KEY NOT NULL CHECK(length(route_id) = 32),
                    initial_snapshot_bytes BLOB NOT NULL,
                    initial_snapshot_hash BLOB NOT NULL CHECK(length(initial_snapshot_hash) = 32),
                    snapshot_bytes BLOB NOT NULL,
                    snapshot_hash BLOB NOT NULL CHECK(length(snapshot_hash) = 32),
                    revision INTEGER NOT NULL CHECK(revision >= 0),
                    last_event_seq INTEGER NOT NULL CHECK(last_event_seq >= 0),
                    created_at_unix_ms INTEGER NOT NULL CHECK(created_at_unix_ms >= 0),
                    updated_at_unix_ms INTEGER NOT NULL CHECK(updated_at_unix_ms >= 0),
                    CHECK(revision = last_event_seq)
                 ) STRICT;

                 CREATE TABLE route_leases (
                    route_id BLOB PRIMARY KEY NOT NULL
                        REFERENCES route_snapshots(route_id) ON DELETE RESTRICT,
                    owner_id BLOB NOT NULL CHECK(length(owner_id) = 32),
                    fencing_epoch INTEGER NOT NULL CHECK(fencing_epoch > 0),
                    lease_until_unix_ms INTEGER NOT NULL CHECK(lease_until_unix_ms >= 0),
                    updated_at_unix_ms INTEGER NOT NULL CHECK(updated_at_unix_ms >= 0)
                 ) STRICT;

                 CREATE TABLE route_journal (
                    route_id BLOB NOT NULL
                        REFERENCES route_snapshots(route_id) ON DELETE RESTRICT,
                    sequence INTEGER NOT NULL CHECK(sequence > 0),
                    event_id BLOB NOT NULL CHECK(length(event_id) = 32),
                    event_bytes BLOB NOT NULL,
                    event_hash BLOB NOT NULL CHECK(length(event_hash) = 32),
                    expected_revision INTEGER NOT NULL CHECK(expected_revision >= 0),
                    resulting_revision INTEGER NOT NULL CHECK(resulting_revision > 0),
                    fencing_epoch INTEGER NOT NULL CHECK(fencing_epoch > 0),
                    snapshot_hash BLOB NOT NULL CHECK(length(snapshot_hash) = 32),
                    previous_entry_hash BLOB NOT NULL CHECK(length(previous_entry_hash) = 32),
                    entry_hash BLOB NOT NULL CHECK(length(entry_hash) = 32),
                    created_at_unix_ms INTEGER NOT NULL CHECK(created_at_unix_ms >= 0),
                    PRIMARY KEY(route_id, sequence),
                    UNIQUE(route_id, event_id),
                    CHECK(resulting_revision = expected_revision + 1),
                    CHECK(sequence = resulting_revision)
                 ) STRICT;

                 CREATE TABLE route_outbox (
                    route_id BLOB NOT NULL
                        REFERENCES route_snapshots(route_id) ON DELETE RESTRICT,
                    effect_id BLOB NOT NULL CHECK(length(effect_id) = 32),
                    source_sequence INTEGER NOT NULL CHECK(source_sequence > 0),
                    fencing_epoch INTEGER NOT NULL CHECK(fencing_epoch > 0),
                    priority_rank INTEGER NOT NULL CHECK(priority_rank BETWEEN 0 AND 2),
                    dispatch_class INTEGER NOT NULL CHECK(dispatch_class IN (0, 1)),
                    effect_bytes BLOB NOT NULL,
                    effect_hash BLOB NOT NULL CHECK(length(effect_hash) = 32),
                    status_tag INTEGER NOT NULL DEFAULT 0 CHECK(status_tag IN (0, 1, 2)),
                    attempts INTEGER NOT NULL DEFAULT 0 CHECK(attempts >= 0),
                    dispatch_lease_owner BLOB CHECK(dispatch_lease_owner IS NULL OR length(dispatch_lease_owner) = 32),
                    dispatch_lease_until_unix_ms INTEGER CHECK(dispatch_lease_until_unix_ms IS NULL OR dispatch_lease_until_unix_ms >= 0),
                    completed_at_unix_ms INTEGER CHECK(completed_at_unix_ms IS NULL OR completed_at_unix_ms >= 0),
                    PRIMARY KEY(route_id, effect_id),
                    FOREIGN KEY(route_id, source_sequence)
                        REFERENCES route_journal(route_id, sequence) ON DELETE RESTRICT,
                    CHECK((dispatch_lease_owner IS NULL) = (dispatch_lease_until_unix_ms IS NULL)),
                    CHECK((status_tag = 0 AND completed_at_unix_ms IS NULL)
                          OR (status_tag IN (1, 2) AND completed_at_unix_ms IS NOT NULL
                              AND dispatch_lease_owner IS NULL))
                 ) STRICT;

                 CREATE INDEX route_outbox_dispatch_idx
                    ON route_outbox(route_id, fencing_epoch, status_tag,
                                    priority_rank DESC, source_sequence ASC);

                 CREATE TABLE route_timers (
                    route_id BLOB NOT NULL
                        REFERENCES route_snapshots(route_id) ON DELETE RESTRICT,
                    timer_id BLOB NOT NULL CHECK(length(timer_id) = 32),
                    source_sequence INTEGER NOT NULL CHECK(source_sequence > 0),
                    fencing_epoch INTEGER NOT NULL CHECK(fencing_epoch > 0),
                    deadline_unix_ms INTEGER NOT NULL CHECK(deadline_unix_ms >= 0),
                    timer_bytes BLOB NOT NULL,
                    timer_hash BLOB NOT NULL CHECK(length(timer_hash) = 32),
                    status_tag INTEGER NOT NULL DEFAULT 0 CHECK(status_tag IN (0, 1, 2)),
                    attempts INTEGER NOT NULL DEFAULT 0 CHECK(attempts >= 0),
                    dispatch_lease_owner BLOB CHECK(dispatch_lease_owner IS NULL OR length(dispatch_lease_owner) = 32),
                    dispatch_lease_until_unix_ms INTEGER CHECK(dispatch_lease_until_unix_ms IS NULL OR dispatch_lease_until_unix_ms >= 0),
                    completed_at_unix_ms INTEGER CHECK(completed_at_unix_ms IS NULL OR completed_at_unix_ms >= 0),
                    PRIMARY KEY(route_id, timer_id),
                    FOREIGN KEY(route_id, source_sequence)
                        REFERENCES route_journal(route_id, sequence) ON DELETE RESTRICT,
                    CHECK((dispatch_lease_owner IS NULL) = (dispatch_lease_until_unix_ms IS NULL)),
                    CHECK((status_tag = 0 AND completed_at_unix_ms IS NULL)
                          OR (status_tag IN (1, 2) AND completed_at_unix_ms IS NOT NULL
                              AND dispatch_lease_owner IS NULL))
                 ) STRICT;

                 CREATE INDEX route_timers_due_idx
                    ON route_timers(route_id, status_tag, deadline_unix_ms ASC,
                                    source_sequence ASC);

                 PRAGMA user_version = 1;",
            )?;
        }
        before_commit()?;
        transaction.commit()?;
        Ok(())
    }
}

fn require_route_exists(
    transaction: &Transaction<'_>,
    route_id: RouteIdV1,
) -> Result<(), RouteStoreErrorV1> {
    let exists: Option<i64> = transaction
        .query_row(
            "SELECT 1 FROM route_snapshots WHERE route_id = ?1",
            params![route_id.as_slice()],
            |row| row.get(0),
        )
        .optional()?;
    if exists.is_none() {
        Err(RouteStoreErrorV1::RouteNotFound)
    } else {
        Ok(())
    }
}

fn load_lease_row(
    transaction: &Transaction<'_>,
    route_id: RouteIdV1,
) -> Result<Option<(Digest32, u64, u64)>, RouteStoreErrorV1> {
    let row: Option<(Vec<u8>, i64, i64)> = transaction
        .query_row(
            "SELECT owner_id, fencing_epoch, lease_until_unix_ms
             FROM route_leases WHERE route_id = ?1",
            params![route_id.as_slice()],
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
    lease: RouteLeaseV1,
    now_unix_ms: u64,
) -> Result<(), RouteStoreErrorV1> {
    validate_identity(lease.route_id)?;
    validate_identity(lease.owner_id)?;
    if lease.fencing_epoch == 0 {
        return Err(RouteStoreErrorV1::StaleFencing);
    }
    let (owner, epoch, until) =
        load_lease_row(transaction, lease.route_id)?.ok_or(RouteStoreErrorV1::StaleFencing)?;
    if owner != lease.owner_id || epoch != lease.fencing_epoch {
        return Err(RouteStoreErrorV1::StaleFencing);
    }
    if until < now_unix_ms || lease.lease_until_unix_ms != until {
        return Err(RouteStoreErrorV1::LeaseExpired);
    }
    Ok(())
}

fn insert_effect(
    transaction: &Transaction<'_>,
    sequence: u64,
    effect: &RouteEffectV1,
) -> Result<(), RouteStoreErrorV1> {
    let bytes = effect.encode_canonical()?;
    let hash = effect_hash_value(&bytes);
    transaction.execute(
        "INSERT INTO route_outbox
         (route_id, effect_id, source_sequence, fencing_epoch, priority_rank,
          dispatch_class, effect_bytes, effect_hash, status_tag, attempts)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, 0)",
        params![
            effect.route_id.as_slice(),
            effect.effect_id.as_slice(),
            to_sql_u64(sequence)?,
            to_sql_u64(effect.fencing_epoch)?,
            priority_rank_v1(effect.priority),
            match effect.dispatch {
                crate::model::EffectDispatchV1::RunnerPayload { .. } => DISPATCH_RUNNER,
                crate::model::EffectDispatchV1::ExternalCustody { .. } => {
                    DISPATCH_EXTERNAL_CUSTODY
                }
            },
            bytes,
            hash.as_slice(),
            STATUS_PENDING
        ],
    )?;
    Ok(())
}

fn supersede_effect(
    transaction: &Transaction<'_>,
    route_id: RouteIdV1,
    prior_effect_id: EffectIdV1,
    replacements: &[RouteEffectV1],
    now_unix_ms: u64,
    now_sql: i64,
) -> Result<(), RouteStoreErrorV1> {
    let row: Option<SupersededEffectRow> = transaction
        .query_row(
            "SELECT effect_bytes, effect_hash, status_tag,
                    dispatch_lease_until_unix_ms
             FROM route_outbox WHERE route_id = ?1 AND effect_id = ?2",
            params![route_id.as_slice(), prior_effect_id.as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .optional()?;
    let (prior_bytes, prior_hash, status, dispatch_until) =
        row.ok_or(RouteStoreErrorV1::EffectNotFound)?;
    if blob32(prior_hash)? != effect_hash_value(&prior_bytes) || status != STATUS_PENDING {
        return Err(RouteStoreErrorV1::IdempotencyConflict);
    }
    if dispatch_until
        .map(from_sql_u64)
        .transpose()?
        .is_some_and(|deadline| deadline >= now_unix_ms)
    {
        return Err(RouteStoreErrorV1::DispatchLeaseMismatch);
    }
    let prior = RouteEffectV1::decode_canonical(&prior_bytes)?;
    if prior.route_id != route_id || prior.effect_id != prior_effect_id {
        return Err(RouteStoreErrorV1::CorruptState);
    }
    let replacement = replacements
        .iter()
        .find(|candidate| {
            candidate.leg == prior.leg
                && candidate.kind == prior.kind
                && candidate.semantic_digest == prior.semantic_digest
        })
        .ok_or(RouteStoreErrorV1::IdempotencyConflict)?;
    if replacement.fencing_epoch <= prior.fencing_epoch
        || replacement.contains_route_secret != prior.contains_route_secret
        || replacement.dispatch != prior.dispatch
    {
        return Err(RouteStoreErrorV1::IdempotencyConflict);
    }
    let changed = transaction.execute(
        "UPDATE route_outbox
         SET status_tag = ?3, completed_at_unix_ms = ?4,
             dispatch_lease_owner = NULL, dispatch_lease_until_unix_ms = NULL
         WHERE route_id = ?1 AND effect_id = ?2 AND status_tag = ?5",
        params![
            route_id.as_slice(),
            prior_effect_id.as_slice(),
            STATUS_SUPERSEDED,
            now_sql,
            STATUS_PENDING
        ],
    )?;
    if changed != 1 {
        return Err(RouteStoreErrorV1::IdempotencyConflict);
    }
    Ok(())
}

fn reconcile_externalized_effect(
    transaction: &Transaction<'_>,
    route_id: RouteIdV1,
    effect_id: EffectIdV1,
    transaction_id: Digest32,
    now_unix_ms: i64,
) -> Result<(), RouteStoreErrorV1> {
    let row: Option<(Vec<u8>, i64)> = transaction
        .query_row(
            "SELECT effect_bytes, status_tag FROM route_outbox
             WHERE route_id = ?1 AND effect_id = ?2",
            params![route_id.as_slice(), effect_id.as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    let (effect_bytes, status) = row.ok_or(RouteStoreErrorV1::EffectNotFound)?;
    let effect = RouteEffectV1::decode_canonical(&effect_bytes)?;
    if effect.route_id != route_id || effect.effect_id != effect_id {
        return Err(RouteStoreErrorV1::CorruptState);
    }
    if let crate::model::EffectDispatchV1::ExternalCustody {
        transaction_id: expected,
        ..
    } = effect.dispatch
    {
        if expected != transaction_id {
            return Err(RouteStoreErrorV1::IdempotencyConflict);
        }
    }
    if status == STATUS_COMPLETED {
        return Ok(());
    }
    if status != STATUS_PENDING {
        return Err(RouteStoreErrorV1::CorruptState);
    }
    let changed = transaction.execute(
        "UPDATE route_outbox
         SET status_tag = ?3, completed_at_unix_ms = ?4,
             dispatch_lease_owner = NULL, dispatch_lease_until_unix_ms = NULL
         WHERE route_id = ?1 AND effect_id = ?2 AND status_tag = ?5",
        params![
            route_id.as_slice(),
            effect_id.as_slice(),
            STATUS_COMPLETED,
            now_unix_ms,
            STATUS_PENDING
        ],
    )?;
    if changed != 1 {
        return Err(RouteStoreErrorV1::CorruptState);
    }
    Ok(())
}

fn reconcile_partial_custody_progress(
    transaction: &Transaction<'_>,
    lease: RouteLeaseV1,
    effect_id: EffectIdV1,
    now_unix_ms: u64,
) -> Result<(), RouteStoreErrorV1> {
    type PartialProgressRow = (Vec<u8>, Vec<u8>, i64, i64, Option<Vec<u8>>, Option<i64>);
    let row: Option<PartialProgressRow> = transaction
        .query_row(
            "SELECT effect_bytes, effect_hash, status_tag, dispatch_class,
                    dispatch_lease_owner, dispatch_lease_until_unix_ms
             FROM route_outbox WHERE route_id = ?1 AND effect_id = ?2",
            params![lease.route_id.as_slice(), effect_id.as_slice()],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                ))
            },
        )
        .optional()?;
    let (effect_bytes, stored_hash, status, dispatch_class, dispatch_owner, dispatch_until) =
        row.ok_or(RouteStoreErrorV1::EffectNotFound)?;
    if status != STATUS_PENDING
        || dispatch_class != DISPATCH_EXTERNAL_CUSTODY
        || blob32(stored_hash)? != effect_hash_value(&effect_bytes)
    {
        return Err(RouteStoreErrorV1::CorruptState);
    }
    let effect = RouteEffectV1::decode_canonical(&effect_bytes)?;
    if effect.route_id != lease.route_id
        || effect.effect_id != effect_id
        || !matches!(
            effect.dispatch,
            crate::model::EffectDispatchV1::ExternalCustody { .. }
        )
        || effect.fencing_epoch > lease.fencing_epoch
    {
        return Err(RouteStoreErrorV1::CorruptState);
    }
    match (dispatch_owner, dispatch_until) {
        (Some(owner), Some(until)) if effect.fencing_epoch == lease.fencing_epoch => {
            if blob32(owner)? != lease.owner_id {
                return Err(RouteStoreErrorV1::DispatchLeaseMismatch);
            }
            let _ = from_sql_u64(until)?;
        }
        (Some(_), Some(until)) => {
            if from_sql_u64(until)? >= now_unix_ms {
                return Err(RouteStoreErrorV1::DispatchLeaseMismatch);
            }
        }
        (None, None) if effect.fencing_epoch < lease.fencing_epoch => {}
        _ => return Err(RouteStoreErrorV1::DispatchLeaseMismatch),
    }
    let changed = transaction.execute(
        "UPDATE route_outbox
         SET dispatch_lease_owner = NULL, dispatch_lease_until_unix_ms = NULL
         WHERE route_id = ?1 AND effect_id = ?2 AND status_tag = ?3
           AND dispatch_class = ?4",
        params![
            lease.route_id.as_slice(),
            effect_id.as_slice(),
            STATUS_PENDING,
            DISPATCH_EXTERNAL_CUSTODY,
        ],
    )?;
    if changed != 1 {
        return Err(RouteStoreErrorV1::CorruptState);
    }
    Ok(())
}

fn insert_timer(
    transaction: &Transaction<'_>,
    sequence: u64,
    timer: &RouteTimerV1,
) -> Result<(), RouteStoreErrorV1> {
    let bytes = timer.encode_canonical()?;
    let hash = timer_hash_value(&bytes);
    transaction.execute(
        "INSERT INTO route_timers
         (route_id, timer_id, source_sequence, fencing_epoch,
          deadline_unix_ms, timer_bytes, timer_hash, status_tag, attempts)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 0)",
        params![
            timer.route_id.as_slice(),
            timer.timer_id.as_slice(),
            to_sql_u64(sequence)?,
            to_sql_u64(timer.fencing_epoch)?,
            to_sql_u64(timer.deadline_unix_ms)?,
            bytes,
            hash.as_slice(),
            STATUS_PENDING
        ],
    )?;
    Ok(())
}

fn validate_snapshot_row(
    route_id: RouteIdV1,
    bytes: &[u8],
    stored_hash: &[u8],
    revision: i64,
    sequence: i64,
) -> Result<RouteSnapshotV1, RouteStoreErrorV1> {
    let hash = blob32(stored_hash.to_vec())?;
    if hash != snapshot_hash(bytes) {
        return Err(RouteStoreErrorV1::CorruptState);
    }
    let snapshot = RouteSnapshotV1::decode_canonical(bytes)?;
    if snapshot.route_id != route_id
        || snapshot.revision != from_sql_u64(revision)?
        || snapshot.last_event_sequence != from_sql_u64(sequence)?
    {
        return Err(RouteStoreErrorV1::CorruptState);
    }
    Ok(snapshot)
}

fn load_snapshot_in_transaction(
    transaction: &Transaction<'_>,
    route_id: RouteIdV1,
) -> Result<RouteSnapshotV1, RouteStoreErrorV1> {
    let row: Option<(Vec<u8>, Vec<u8>, i64, i64)> = transaction
        .query_row(
            "SELECT snapshot_bytes, snapshot_hash, revision, last_event_seq
             FROM route_snapshots WHERE route_id = ?1",
            params![route_id.as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .optional()?;
    let (bytes, hash, revision, sequence) = row.ok_or(RouteStoreErrorV1::RouteNotFound)?;
    validate_snapshot_row(route_id, &bytes, &hash, revision, sequence)
}

fn active_committed_effect(
    snapshot: &RouteSnapshotV1,
    effect_id: EffectIdV1,
) -> Option<(
    crate::model::LegIdV1,
    crate::model::ActionKindV1,
    crate::model::EffectReferenceV1,
)> {
    use crate::model::{ActionKindV1, ActionStateV1, LegIdV1};

    let actions = [
        (
            LegIdV1::Upstream,
            ActionKindV1::Funding,
            &snapshot.upstream.funding,
        ),
        (
            LegIdV1::Upstream,
            ActionKindV1::Claim,
            &snapshot.upstream.claim,
        ),
        (
            LegIdV1::Upstream,
            ActionKindV1::Refund,
            &snapshot.upstream.refund,
        ),
        (
            LegIdV1::Downstream,
            ActionKindV1::Funding,
            &snapshot.downstream.funding,
        ),
        (
            LegIdV1::Downstream,
            ActionKindV1::Claim,
            &snapshot.downstream.claim,
        ),
        (
            LegIdV1::Downstream,
            ActionKindV1::Refund,
            &snapshot.downstream.refund,
        ),
    ];
    actions.into_iter().find_map(|(leg, kind, state)| {
        if let ActionStateV1::Committed(reference) = state {
            if reference.effect_id == effect_id {
                return Some((leg, kind, reference.clone()));
            }
        }
        None
    })
}

fn effect_is_dispatchable(snapshot: &RouteSnapshotV1, effect: &RouteEffectV1) -> bool {
    use crate::model::{ActionKindV1, ActionProgressV1, ActionStateV1, LegIdV1};

    if snapshot.aborted_unfunded {
        return false;
    }
    let active = match snapshot.leg(effect.leg).action(effect.kind) {
        ActionStateV1::Committed(reference) => reference,
        ActionStateV1::NotPrepared
        | ActionStateV1::Externalized { .. }
        | ActionStateV1::Final { .. }
        | ActionStateV1::FinalityInvalidated { .. } => return false,
    };
    if active.effect_id != effect.effect_id
        || active.fencing_epoch != effect.fencing_epoch
        || active.semantic_digest != effect.semantic_digest
        || active.contains_route_secret != effect.contains_route_secret
    {
        return false;
    }
    match effect.kind {
        ActionKindV1::Funding => {
            if snapshot.health.restricts_to_recovery()
                || snapshot.refunds.is_none()
                || snapshot.upstream.is_terminal()
                || snapshot.downstream.is_terminal()
            {
                return false;
            }
            effect.leg != LegIdV1::Downstream
                || (snapshot.upstream.funding.progress() == ActionProgressV1::Final
                    && snapshot.upstream.claim.progress() == ActionProgressV1::NotPrepared
                    && snapshot.upstream.refund.progress() == ActionProgressV1::NotPrepared)
        }
        ActionKindV1::Claim if effect.leg == LegIdV1::Downstream => {
            !snapshot.health.restricts_to_recovery()
                && snapshot.upstream.funding.progress() == ActionProgressV1::Final
                && snapshot.downstream.funding.progress() == ActionProgressV1::Final
                && (snapshot.upstream.claim.progress() == ActionProgressV1::NotPrepared
                    || (matches!(
                        snapshot.secret_visibility,
                        crate::model::SecretVisibilityV1::Public { .. }
                    ) && snapshot.upstream.claim.progress() == ActionProgressV1::Final))
                && snapshot.upstream.refund.progress() == ActionProgressV1::NotPrepared
                && effect.contains_route_secret
        }
        ActionKindV1::Claim => {
            matches!(
                snapshot.secret_visibility,
                crate::model::SecretVisibilityV1::Public { .. }
            ) && matches!(
                snapshot.upstream.funding,
                ActionStateV1::Final { .. } | ActionStateV1::FinalityInvalidated { .. }
            ) && effect.contains_route_secret
        }
        ActionKindV1::Refund => matches!(
            snapshot.leg(effect.leg).funding.progress(),
            ActionProgressV1::Externalized | ActionProgressV1::Final
        ),
    }
}

fn previous_entry_hash(
    transaction: &Transaction<'_>,
    route_id: RouteIdV1,
) -> Result<Digest32, RouteStoreErrorV1> {
    if let Some(value) = transaction
        .query_row(
            "SELECT entry_hash FROM route_journal
             WHERE route_id = ?1 ORDER BY sequence DESC LIMIT 1",
            params![route_id.as_slice()],
            |row| row.get::<_, Vec<u8>>(0),
        )
        .optional()?
    {
        return blob32(value);
    }
    let initial_hash: Vec<u8> = transaction
        .query_row(
            "SELECT initial_snapshot_hash FROM route_snapshots WHERE route_id = ?1",
            params![route_id.as_slice()],
            |row| row.get(0),
        )
        .optional()?
        .ok_or(RouteStoreErrorV1::RouteNotFound)?;
    Ok(initial_journal_hash(route_id, blob32(initial_hash)?))
}

fn initial_journal_hash(route_id: RouteIdV1, initial_snapshot_hash: Digest32) -> Digest32 {
    domain_digest_v1(
        b"DOM-ROUTE-JOURNAL-GENESIS-V1",
        &[&route_id, &initial_snapshot_hash],
    )
}

struct JournalEntryHashInputV1 {
    previous: Digest32,
    route_id: RouteIdV1,
    sequence: u64,
    expected_revision: u64,
    resulting_revision: u64,
    event_id: EventIdV1,
    event_hash: Digest32,
    resulting_snapshot_hash: Digest32,
    fencing_epoch: u64,
}

fn journal_entry_hash(input: JournalEntryHashInputV1) -> Digest32 {
    let JournalEntryHashInputV1 {
        previous,
        route_id,
        sequence,
        expected_revision,
        resulting_revision,
        event_id,
        event_hash,
        resulting_snapshot_hash,
        fencing_epoch,
    } = input;
    domain_digest_v1(
        b"DOM-ROUTE-JOURNAL-ENTRY-V1",
        &[
            &previous,
            &route_id,
            &sequence.to_be_bytes(),
            &expected_revision.to_be_bytes(),
            &resulting_revision.to_be_bytes(),
            &event_id,
            &event_hash,
            &resulting_snapshot_hash,
            &fencing_epoch.to_be_bytes(),
        ],
    )
}

fn snapshot_hash(bytes: &[u8]) -> Digest32 {
    domain_digest_v1(b"DOM-ROUTE-SNAPSHOT-V1", &[bytes])
}

fn effect_hash_value(bytes: &[u8]) -> Digest32 {
    domain_digest_v1(b"DOM-ROUTE-EFFECT-V1", &[bytes])
}

fn timer_hash_value(bytes: &[u8]) -> Digest32 {
    domain_digest_v1(b"DOM-ROUTE-TIMER-V1", &[bytes])
}

fn validate_identity(value: Digest32) -> Result<(), RouteStoreErrorV1> {
    if value.iter().all(|byte| *byte == 0) {
        Err(RouteStoreErrorV1::InvalidMaterial)
    } else {
        Ok(())
    }
}

fn validate_claim_limit(limit: usize) -> Result<(), RouteStoreErrorV1> {
    if limit == 0 || limit > MAX_CLAIM_BATCH {
        Err(RouteStoreErrorV1::InvalidBound)
    } else {
        Ok(())
    }
}

fn lease_deadline(now: u64, duration: u64) -> Result<u64, RouteStoreErrorV1> {
    if duration == 0 || duration > MAX_LEASE_DURATION_MS {
        return Err(RouteStoreErrorV1::InvalidBound);
    }
    let deadline = now
        .checked_add(duration)
        .ok_or(RouteStoreErrorV1::InvalidBound)?;
    let _ = to_sql_u64(deadline)?;
    Ok(deadline)
}

fn dispatch_deadline(
    lease: RouteLeaseV1,
    now: u64,
    duration: u64,
) -> Result<u64, RouteStoreErrorV1> {
    let deadline = lease_deadline(now, duration)?;
    if deadline > lease.lease_until_unix_ms {
        return Err(RouteStoreErrorV1::InvalidBound);
    }
    Ok(deadline)
}

fn to_sql_u64(value: u64) -> Result<i64, RouteStoreErrorV1> {
    i64::try_from(value).map_err(|_| RouteStoreErrorV1::InvalidBound)
}

fn from_sql_u64(value: i64) -> Result<u64, RouteStoreErrorV1> {
    u64::try_from(value).map_err(|_| RouteStoreErrorV1::CorruptState)
}

fn blob32(value: Vec<u8>) -> Result<Digest32, RouteStoreErrorV1> {
    value
        .try_into()
        .map_err(|_| RouteStoreErrorV1::CorruptState)
}

fn is_constraint(error: &rusqlite::Error) -> bool {
    matches!(
        error,
        rusqlite::Error::SqliteFailure(code, _)
            if code.code == rusqlite::ErrorCode::ConstraintViolation
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn digest_domains_are_distinct() {
        let bytes = b"same bytes";
        assert_ne!(snapshot_hash(bytes), effect_hash_value(bytes));
        assert_ne!(effect_hash_value(bytes), timer_hash_value(bytes));
        assert_ne!(crate::codec::digest_v1(bytes), snapshot_hash(bytes));
    }

    #[cfg(target_os = "linux")]
    mod creation_recovery {
        use super::*;
        use std::error::Error;
        use std::os::unix::fs::PermissionsExt;
        use std::process::{Command, Stdio};

        type TestResult = core::result::Result<(), Box<dyn Error>>;
        type TestPath =
            core::result::Result<(tempfile::TempDir, std::path::PathBuf), Box<dyn Error>>;

        fn test_path() -> TestPath {
            let directory = tempfile::tempdir()?;
            fs::set_permissions(directory.path(), fs::Permissions::from_mode(DIRECTORY_MODE))?;
            let path = directory.path().join("route.sqlite3");
            Ok((directory, path))
        }

        fn require_error<T>(
            result: Result<T, RouteStoreErrorV1>,
        ) -> core::result::Result<RouteStoreErrorV1, std::io::Error> {
            result
                .err()
                .ok_or_else(|| std::io::Error::other("expected strict creation refusal"))
        }

        fn stage_creation_fault(path: &Path, fault: CreationBoundaryV1) -> TestResult {
            let error = require_error(DurableRouteStoreV1::create_with_boundary_hook(
                path,
                |boundary| {
                    if boundary == fault {
                        Err(RouteStoreErrorV1::StorageUnavailable)
                    } else {
                        Ok(())
                    }
                },
            ))?;
            assert_eq!(error, RouteStoreErrorV1::StorageUnavailable);
            Ok(())
        }

        fn boundary_name(boundary: CreationBoundaryV1) -> &'static str {
            match boundary {
                CreationBoundaryV1::ProcessLockPublished => "process-lock-published",
                CreationBoundaryV1::DatabaseFileSynced => "database-file-synced",
                CreationBoundaryV1::BeforeSchemaTransaction => "before-schema-transaction",
                CreationBoundaryV1::BeforeSchemaCommit => "before-schema-commit",
                CreationBoundaryV1::SchemaCommitted => "schema-committed",
            }
        }

        fn parse_boundary(name: &str) -> core::result::Result<CreationBoundaryV1, std::io::Error> {
            match name {
                "process-lock-published" => Ok(CreationBoundaryV1::ProcessLockPublished),
                "database-file-synced" => Ok(CreationBoundaryV1::DatabaseFileSynced),
                "before-schema-transaction" => Ok(CreationBoundaryV1::BeforeSchemaTransaction),
                "before-schema-commit" => Ok(CreationBoundaryV1::BeforeSchemaCommit),
                "schema-committed" => Ok(CreationBoundaryV1::SchemaCommitted),
                _ => Err(std::io::Error::other("unknown creation fault boundary")),
            }
        }

        fn stage_process_crash(path: &Path, boundary: CreationBoundaryV1) -> TestResult {
            let executable = std::env::current_exe()?;
            let status = Command::new(executable)
                .arg("--exact")
                .arg("store::tests::creation_recovery::creation_fault_process_child")
                .arg("--nocapture")
                .env("ROUTE_EXECUTOR_TEST_FAULT_PATH", path)
                .env(
                    "ROUTE_EXECUTOR_TEST_FAULT_BOUNDARY",
                    boundary_name(boundary),
                )
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()?;
            if status.code() != Some(91) {
                return Err(std::io::Error::other(
                    "creation fault child did not crash at boundary",
                )
                .into());
            }
            Ok(())
        }

        #[test]
        fn creation_fault_process_child() -> TestResult {
            let Some(path) = std::env::var_os("ROUTE_EXECUTOR_TEST_FAULT_PATH") else {
                return Ok(());
            };
            let boundary = std::env::var("ROUTE_EXECUTOR_TEST_FAULT_BOUNDARY")?;
            let fault = parse_boundary(&boundary)?;
            let store =
                DurableRouteStoreV1::create_with_boundary_hook(Path::new(&path), |boundary| {
                    if boundary == fault {
                        std::process::exit(91);
                    }
                    Ok(())
                })?;
            drop(store);
            Err(std::io::Error::other("creation fault boundary was not reached").into())
        }

        #[test]
        fn resume_create_recovers_only_real_crash_prefixes_and_reopens() -> TestResult {
            for boundary in [
                CreationBoundaryV1::ProcessLockPublished,
                CreationBoundaryV1::DatabaseFileSynced,
                CreationBoundaryV1::BeforeSchemaTransaction,
                CreationBoundaryV1::BeforeSchemaCommit,
                CreationBoundaryV1::SchemaCommitted,
            ] {
                let (_directory, path) = test_path()?;
                stage_process_crash(&path, boundary)?;
                match boundary {
                    CreationBoundaryV1::ProcessLockPublished => assert_eq!(
                        require_error(DurableRouteStoreV1::open_existing(&path))?,
                        RouteStoreErrorV1::DatabaseMissing
                    ),
                    CreationBoundaryV1::DatabaseFileSynced
                    | CreationBoundaryV1::BeforeSchemaTransaction
                    | CreationBoundaryV1::BeforeSchemaCommit => assert_eq!(
                        require_error(DurableRouteStoreV1::open_existing(&path))?,
                        RouteStoreErrorV1::CreationIncomplete
                    ),
                    CreationBoundaryV1::SchemaCommitted => {
                        let opened = DurableRouteStoreV1::open_existing(&path)?;
                        drop(opened);
                    }
                }
                let resumed = DurableRouteStoreV1::resume_create_production(&path)?;
                assert_eq!(
                    require_error(DurableRouteStoreV1::resume_create_production(&path))?,
                    RouteStoreErrorV1::StorageUnavailable
                );
                drop(resumed);
                let resumed_again = DurableRouteStoreV1::resume_create_production(&path)?;
                drop(resumed_again);
                let reopened = DurableRouteStoreV1::open_existing(&path)?;
                drop(reopened);
            }
            Ok(())
        }

        #[test]
        fn resume_create_refuses_foreign_authority_schema_meta_and_economic_rows() -> TestResult {
            let (_directory, path) = test_path()?;
            create_owner_database_file(&path)?;
            assert_eq!(
                require_error(DurableRouteStoreV1::resume_create_production(&path))?,
                RouteStoreErrorV1::StorageUnavailable
            );

            let (_directory, path) = test_path()?;
            stage_creation_fault(&path, CreationBoundaryV1::DatabaseFileSynced)?;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o640))?;
            assert_eq!(
                require_error(DurableRouteStoreV1::resume_create_production(&path))?,
                RouteStoreErrorV1::InvalidStorageAuthority
            );

            let (_directory, path) = test_path()?;
            stage_creation_fault(&path, CreationBoundaryV1::DatabaseFileSynced)?;
            let alias = path.with_extension("hardlink");
            fs::hard_link(&path, &alias)?;
            assert_eq!(
                require_error(DurableRouteStoreV1::resume_create_production(&path))?,
                RouteStoreErrorV1::InvalidStorageAuthority
            );

            let (_directory, path) = test_path()?;
            stage_creation_fault(&path, CreationBoundaryV1::DatabaseFileSynced)?;
            let lock_path = process_lock_path(&path);
            fs::set_permissions(&lock_path, fs::Permissions::from_mode(0o640))?;
            assert_eq!(
                require_error(DurableRouteStoreV1::resume_create_production(&path))?,
                RouteStoreErrorV1::InvalidStorageAuthority
            );

            let (_directory, path) = test_path()?;
            stage_creation_fault(&path, CreationBoundaryV1::DatabaseFileSynced)?;
            let alternate = Connection::open(&path)?;
            alternate.execute_batch("CREATE TABLE caller_shaped(value BLOB) STRICT;")?;
            drop(alternate);
            assert_eq!(
                require_error(DurableRouteStoreV1::resume_create_production(&path))?,
                RouteStoreErrorV1::UnsupportedFormat
            );

            let (_directory, path) = test_path()?;
            stage_creation_fault(&path, CreationBoundaryV1::DatabaseFileSynced)?;
            let alternate = Connection::open(&path)?;
            alternate.pragma_update(None, "user_version", 2)?;
            drop(alternate);
            assert_eq!(
                require_error(DurableRouteStoreV1::resume_create_production(&path))?,
                RouteStoreErrorV1::UnsupportedFormat
            );

            let (_directory, path) = test_path()?;
            stage_creation_fault(&path, CreationBoundaryV1::DatabaseFileSynced)?;
            let alternate = Connection::open(&path)?;
            alternate.pragma_update(None, "application_id", 41)?;
            drop(alternate);
            assert_eq!(
                require_error(DurableRouteStoreV1::resume_create_production(&path))?,
                RouteStoreErrorV1::CorruptState
            );

            let (_directory, path) = test_path()?;
            stage_creation_fault(&path, CreationBoundaryV1::SchemaCommitted)?;
            let alternate = Connection::open(&path)?;
            alternate.execute(
                "INSERT INTO route_snapshots(
                     route_id, initial_snapshot_bytes, initial_snapshot_hash,
                     snapshot_bytes, snapshot_hash, revision, last_event_seq,
                     created_at_unix_ms, updated_at_unix_ms
                 ) VALUES(?1, ?2, ?3, ?2, ?3, 1, 1, 0, 0)",
                params![[1u8; 32].as_slice(), [1u8].as_slice(), [2u8; 32].as_slice()],
            )?;
            alternate.execute(
                "INSERT INTO route_journal(
                     route_id, sequence, event_id, event_bytes, event_hash,
                     expected_revision, resulting_revision, fencing_epoch,
                     snapshot_hash, previous_entry_hash, entry_hash,
                     created_at_unix_ms
                 ) VALUES(?1, 1, ?2, ?3, ?4, 0, 1, 1, ?5, ?6, ?7, 0)",
                params![
                    [1u8; 32].as_slice(),
                    [3u8; 32].as_slice(),
                    [4u8].as_slice(),
                    [5u8; 32].as_slice(),
                    [2u8; 32].as_slice(),
                    [0u8; 32].as_slice(),
                    [6u8; 32].as_slice()
                ],
            )?;
            alternate.execute(
                "INSERT INTO route_outbox(
                     route_id, effect_id, source_sequence, fencing_epoch,
                     priority_rank, dispatch_class, effect_bytes, effect_hash,
                     status_tag, attempts
                 ) VALUES(?1, ?2, 1, 1, 0, 0, ?3, ?4, 0, 0)",
                params![
                    [1u8; 32].as_slice(),
                    [7u8; 32].as_slice(),
                    [8u8].as_slice(),
                    [9u8; 32].as_slice()
                ],
            )?;
            drop(alternate);
            assert_eq!(
                require_error(DurableRouteStoreV1::resume_create_production(&path))?,
                RouteStoreErrorV1::CorruptState
            );

            let (_directory, path) = test_path()?;
            let mut valid = DurableRouteStoreV1::create(&path)?;
            valid.create_route([0x31; 32], 0)?;
            drop(valid);
            let reopened = DurableRouteStoreV1::open_existing(&path)?;
            assert_eq!(reopened.load_snapshot([0x31; 32])?.route_id, [0x31; 32]);
            drop(reopened);
            assert_eq!(
                require_error(DurableRouteStoreV1::resume_create_production(&path))?,
                RouteStoreErrorV1::CorruptState
            );

            let (_directory, path) = test_path()?;
            stage_creation_fault(&path, CreationBoundaryV1::DatabaseFileSynced)?;
            let mut wal_path = path.as_os_str().to_os_string();
            wal_path.push("-wal");
            let wal_path = std::path::PathBuf::from(wal_path);
            fs::write(&wal_path, b"caller-shaped")?;
            fs::set_permissions(&wal_path, fs::Permissions::from_mode(FILE_MODE))?;
            assert_eq!(
                require_error(DurableRouteStoreV1::resume_create_production(&path))?,
                RouteStoreErrorV1::InvalidStorageAuthority
            );
            Ok(())
        }
    }
}
