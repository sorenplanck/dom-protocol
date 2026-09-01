//! Authoritative, neutral local persistence for the protocol.
//!
//! Phase 1 deliverable required by §4.7 of the Foundation Document: local
//! authoritative session, append-only journal, idempotency keys, per-chain
//! cursors, monotonic revision with CAS, durable outbox, post-crash resumption
//! and reconciliation without repeating effects.
//!
//! # Boundary
//!
//! This crate is deliberately **neutral**. It does not import `dom-adaptor`,
//! does not know about secret nonces, shares, `AdaptorSecret` or any DOM
//! cryptographic primitive. It stores opaque bytes and returns them identical.
//! The durable implementation of `NonceVaultV1` lives in `dom-vault`, which
//! uses the durable operations from here (D-005; ADR-A7 §"Decisao").
//!
//! # Durability
//!
//! SQLite in WAL mode, single database, no `ATTACH`, compiled into the binary
//! (ADR-A7). `synchronous=FULL` because Phase 1 requires surviving real
//! process termination, not just a process crash. I/O errors, an unknown
//! version, a downgrade, a partial migration or an inconsistent digest fail
//! closed before any external effect.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod settlement;

/// Crash injection at the commit and dispatch boundaries (F2 spec §13).
/// Present only under the test-only `failpoints` feature.
#[cfg(feature = "failpoints")]
pub use settlement::failpoints;

pub use settlement::{
    ClaimedEffect, CommitOutcome, CursorUpdate, EvidenceRow, ExternalCustodyCompletion,
    ExternalCustodyInsert, F2OutboxDeliveryStatusV1, F2OutboxDispatchClassV1,
    F2OutboxEffectSummaryV1, OutboxInsert, ParkOutcome, SettlementCommit, SettlementCreate,
    SettlementCursorRowV1, SettlementJournalRow, SettlementSnapshotRow, TerminalInsert,
    EVIDENCE_APPLIED, EVIDENCE_INVALIDATED, EVIDENCE_PARKED, OUTBOX_COMPLETED, OUTBOX_PENDING,
};

use std::collections::BTreeSet;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
#[cfg(target_os = "linux")]
use std::os::fd::AsFd;
#[cfg(target_os = "linux")]
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::time::Duration;

use rusqlite::{
    config::DbConfig, Connection, OpenFlags, OptionalExtension, Transaction, TransactionBehavior,
};
#[cfg(target_os = "linux")]
use rustix::fs::{flock, FlockOperation};
#[cfg(target_os = "linux")]
use rustix::process::geteuid;

/// Schema version this binary knows how to operate.
///
/// A database with a higher version is a downgrade and fails closed; a
/// database with a lower version is migrated upward, idempotently, inside a
/// transaction. Version 2 adds the F2 core settlement schema; version 3 adds
/// payload-free, non-leaseable external-custody outbox effects.
pub const SCHEMA_VERSION: i64 = 4;

const PRODUCTION_APPLICATION_ID: i64 = 0x444f_4d56;
const DIRECTORY_MODE: u32 = 0o700;
const FILE_MODE: u32 = 0o600;
const PRODUCTION_PROFILE_OPAQUE_AUTHORITY: i64 = 1;
const PREPARED_AUTHORITY_MAGIC_V1: &[u8; 8] = b"DOMSTPR1";
const PREPARED_AUTHORITY_VERSION_V1: u16 = 1;
const PREPARED_AUTHORITY_BYTES_V1: usize = 8 + 2 + 32;
const PRODUCTION_AUTHORITY_SCHEMA: &str = "CREATE TABLE production_authority (
    singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
    profile INTEGER NOT NULL CHECK(profile = 1),
    binding_digest BLOB NOT NULL CHECK(length(binding_digest) = 32)
) STRICT;";
const BASE_SCHEMA: &str = "CREATE TABLE journal (
     sequence INTEGER PRIMARY KEY,
     kind     INTEGER NOT NULL,
     payload  BLOB    NOT NULL
 ) STRICT;
 CREATE TABLE idempotency (
     key      BLOB PRIMARY KEY,
     response BLOB NOT NULL
 ) STRICT;
 CREATE TABLE cursors (
     chain  BLOB PRIMARY KEY,
     cursor BLOB NOT NULL
 ) STRICT;
 CREATE TABLE outbox (
     id        INTEGER PRIMARY KEY,
     payload   BLOB    NOT NULL,
     delivered INTEGER NOT NULL DEFAULT 0
 ) STRICT;
 CREATE TABLE revisions (
     entity   BLOB PRIMARY KEY,
     revision INTEGER NOT NULL
 ) STRICT;
 CREATE TABLE opaque_records (
     namespace BLOB NOT NULL,
     key       BLOB NOT NULL,
     value     BLOB NOT NULL,
     PRIMARY KEY (namespace, key)
 ) STRICT;";

/// F2 core settlement schema (F2 spec §8.1), applied as the 1 → 2
/// migration. `CREATE TABLE IF NOT EXISTS` keeps it idempotent.
const MIGRATION_F2_CORE: &str = include_str!("../migrations/0001_f2_core.sql");

/// Adds the neutral dispatch class and optional external transaction identity.
const MIGRATION_EXTERNAL_CUSTODY: &str = include_str!("../migrations/0002_external_custody.sql");

/// Typed store failure, with redacted observability.
///
/// No variant carries persisted bytes, keys or sensitive material: artifacts
/// are opaque to this crate and remain opaque in the error (I6).
///
/// `#[non_exhaustive]`: a consumer must decide what an UNKNOWN failure
/// means for it, and the only safe answer for a durability error is to
/// fail closed. Without this, adding a variant would silently break
/// exhaustive matches at the boundary — or, worse, tempt a wildcard that
/// treats an unknown durability failure as benign.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum StoreError {
    /// Storage layer unavailable or I/O failure.
    #[error("storage unavailable")]
    StorageUnavailable,
    /// Explicit production creation targeted an existing authority prefix.
    #[error("production store already exists")]
    DatabasePresent,
    /// Strict production reopen targeted an absent database.
    #[error("production store is missing")]
    DatabaseMissing,
    /// A durable external journal may resume this authenticated create prefix.
    #[error("production store creation is incomplete")]
    CreationIncomplete,
    /// A path, lock, sidecar, inode, owner or mode is not the retained authority.
    #[error("invalid production storage authority")]
    InvalidStorageAuthority,
    /// Another live process owns the production store authority.
    #[error("production store authority is already held")]
    ProcessLocked,
    /// The database declares a schema version this binary does not operate.
    #[error("unsupported schema version: found {found}, supported {supported}")]
    UnsupportedVersion {
        /// Version found in the database.
        found: i64,
        /// Version this binary knows how to operate.
        supported: i64,
    },
    /// Incoherent persisted state: fail closed, no salvage attempt.
    #[error("corrupt state")]
    CorruptState,
    /// The expected revision does not match the durable revision (lost CAS).
    #[error("revision conflict")]
    RevisionConflict,
    /// The same idempotency key was re-presented with different bytes.
    #[error("idempotency conflict")]
    IdempotencyConflict,
    /// The requested record does not exist.
    #[error("record not found")]
    NotFound,
    /// A monotonic counter would overflow.
    #[error("counter overflow")]
    CounterOverflow,
    /// A test failpoint fired at a commit or dispatch boundary.
    ///
    /// Exists ONLY under the `failpoints` feature (off by default, never
    /// enabled by a production dependency): the variant itself is absent
    /// from production builds.
    #[cfg(feature = "failpoints")]
    #[error("injected failpoint")]
    InjectedCrash,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ProductionDatabaseStateV1 {
    Pristine,
    Initialized,
}

type SchemaObjectV1 = (String, String, String, String);

fn initialize_production_schema(
    connection: &Connection,
    binding: ProductionStoreBindingV1,
) -> Result<()> {
    let transaction = connection.unchecked_transaction()?;
    transaction.execute_batch(BASE_SCHEMA)?;
    transaction.execute_batch(MIGRATION_F2_CORE)?;
    transaction.execute_batch(MIGRATION_EXTERNAL_CUSTODY)?;
    transaction.execute_batch(PRODUCTION_AUTHORITY_SCHEMA)?;
    transaction.execute(
        "INSERT INTO production_authority(singleton, profile, binding_digest)
         VALUES(1, ?1, ?2)",
        rusqlite::params![PRODUCTION_PROFILE_OPAQUE_AUTHORITY, binding.0.as_slice()],
    )?;
    transaction.pragma_update(None, "application_id", PRODUCTION_APPLICATION_ID)?;
    transaction.pragma_update(None, "user_version", SCHEMA_VERSION)?;
    audit_production_transaction(&transaction, binding)?;
    transaction.commit()?;
    Ok(())
}

fn configure_production_connection(connection: &Connection, install_wal: bool) -> Result<()> {
    connection.busy_timeout(Duration::from_millis(30_000))?;
    if !connection.set_db_config(DbConfig::SQLITE_DBCONFIG_DEFENSIVE, true)?
        || !connection.db_config(DbConfig::SQLITE_DBCONFIG_DEFENSIVE)?
    {
        return Err(StoreError::CorruptState);
    }
    let mode: String = connection.pragma_query_value(None, "journal_mode", |row| row.get(0))?;
    if install_wal {
        if !mode.eq_ignore_ascii_case("wal") {
            let installed: String =
                connection
                    .pragma_update_and_check(None, "journal_mode", "WAL", |row| row.get(0))?;
            if !installed.eq_ignore_ascii_case("wal") {
                return Err(StoreError::CorruptState);
            }
        }
    } else if !mode.eq_ignore_ascii_case("wal") {
        return Err(StoreError::CorruptState);
    }
    connection.execute_batch(
        "PRAGMA foreign_keys = ON;
         PRAGMA trusted_schema = OFF;
         PRAGMA read_uncommitted = OFF;
         PRAGMA secure_delete = ON;
         PRAGMA synchronous = FULL;
         PRAGMA temp_store = MEMORY;",
    )?;
    Ok(())
}

fn classify_production_database(
    connection: &Connection,
    binding: ProductionStoreBindingV1,
) -> Result<ProductionDatabaseStateV1> {
    let version: i64 = connection.pragma_query_value(None, "user_version", |row| row.get(0))?;
    let application_id: i64 =
        connection.pragma_query_value(None, "application_id", |row| row.get(0))?;
    let objects = schema_objects(connection)?;
    if version == 0 && application_id == 0 && objects.is_empty() {
        return Ok(ProductionDatabaseStateV1::Pristine);
    }
    audit_production_connection(connection, binding)?;
    Ok(ProductionDatabaseStateV1::Initialized)
}

fn audit_transaction_for_binding(
    transaction: &Transaction<'_>,
    binding: Option<ProductionStoreBindingV1>,
) -> Result<()> {
    if let Some(binding) = binding {
        audit_production_transaction(transaction, binding)?;
    }
    Ok(())
}

fn audit_production_connection(
    connection: &Connection,
    binding: ProductionStoreBindingV1,
) -> Result<()> {
    let transaction = connection.unchecked_transaction()?;
    audit_production_transaction(&transaction, binding)?;
    transaction.commit()?;
    Ok(())
}

fn audit_production_transaction(
    transaction: &Transaction<'_>,
    binding: ProductionStoreBindingV1,
) -> Result<()> {
    let version: i64 = transaction.pragma_query_value(None, "user_version", |row| row.get(0))?;
    let application_id: i64 =
        transaction.pragma_query_value(None, "application_id", |row| row.get(0))?;
    if version != SCHEMA_VERSION || application_id != PRODUCTION_APPLICATION_ID {
        return Err(StoreError::CorruptState);
    }
    if schema_objects(transaction)? != reference_schema_objects()? {
        return Err(StoreError::CorruptState);
    }
    let matching: i64 = transaction.query_row(
        "SELECT COUNT(*) FROM production_authority
         WHERE singleton=1 AND profile=?1 AND binding_digest=?2",
        rusqlite::params![PRODUCTION_PROFILE_OPAQUE_AUTHORITY, binding.0.as_slice()],
        |row| row.get(0),
    )?;
    let total: i64 =
        transaction.query_row("SELECT COUNT(*) FROM production_authority", [], |row| {
            row.get(0)
        })?;
    if matching != 1 || total != 1 {
        return Err(StoreError::CorruptState);
    }
    let integrity: String = transaction.query_row("PRAGMA quick_check", [], |row| row.get(0))?;
    let foreign_failures: i64 =
        transaction.query_row("SELECT COUNT(*) FROM pragma_foreign_key_check", [], |row| {
            row.get(0)
        })?;
    if integrity != "ok" || foreign_failures != 0 {
        return Err(StoreError::CorruptState);
    }
    audit_neutral_rows(transaction)
}

fn audit_neutral_rows(connection: &Connection) -> Result<()> {
    let malformed_journal: i64 = connection.query_row(
        "SELECT COUNT(*) FROM journal
         WHERE sequence <= 0 OR kind < 0 OR kind > 65535",
        [],
        |row| row.get(0),
    )?;
    let (journal_count, journal_min, journal_max): (i64, Option<i64>, Option<i64>) = connection
        .query_row(
            "SELECT COUNT(*), MIN(sequence), MAX(sequence) FROM journal",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )?;
    let journal_contiguous = match (journal_min, journal_max) {
        (None, None) => journal_count == 0,
        (Some(1), Some(maximum)) => maximum == journal_count,
        _ => false,
    };
    let malformed_revisions: i64 = connection.query_row(
        "SELECT COUNT(*) FROM revisions WHERE revision <= 0",
        [],
        |row| row.get(0),
    )?;
    if malformed_journal != 0 || !journal_contiguous || malformed_revisions != 0 {
        return Err(StoreError::CorruptState);
    }
    for table in [
        "idempotency",
        "cursors",
        "outbox",
        "settlement_terms",
        "settlement_snapshot",
        "settlement_journal",
        "chain_cursor",
        "observed_evidence",
        "durable_outbox",
        "terminal_outcome",
        "late_evidence",
    ] {
        let query = format!("SELECT COUNT(*) FROM {table}");
        let rows: i64 = connection.query_row(&query, [], |row| row.get(0))?;
        if rows != 0 {
            return Err(StoreError::CorruptState);
        }
    }
    Ok(())
}

fn require_production_store_empty(connection: &Connection) -> Result<()> {
    audit_neutral_rows(connection)?;
    for table in ["journal", "revisions", "opaque_records"] {
        let query = format!("SELECT COUNT(*) FROM {table}");
        let rows: i64 = connection.query_row(&query, [], |row| row.get(0))?;
        if rows != 0 {
            return Err(StoreError::CorruptState);
        }
    }
    Ok(())
}

fn schema_objects(connection: &Connection) -> Result<BTreeSet<SchemaObjectV1>> {
    const MAX_SCHEMA_OBJECTS: i64 = 32;
    const MAX_SCHEMA_SQL_BYTES: i64 = 512 * 1024;
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
        return Err(StoreError::CorruptState);
    }
    let mut statement = connection.prepare(
        "SELECT type,name,tbl_name,sql FROM sqlite_schema
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
            return Err(StoreError::CorruptState);
        }
    }
    if i64::try_from(objects.len()).map_err(|_| StoreError::CorruptState)? != count {
        return Err(StoreError::CorruptState);
    }
    Ok(objects)
}

fn reference_schema_objects() -> Result<BTreeSet<SchemaObjectV1>> {
    let reference = Connection::open_in_memory()?;
    let transaction = reference.unchecked_transaction()?;
    transaction.execute_batch(BASE_SCHEMA)?;
    transaction.execute_batch(MIGRATION_F2_CORE)?;
    transaction.execute_batch(MIGRATION_EXTERNAL_CUSTODY)?;
    transaction.execute_batch(PRODUCTION_AUTHORITY_SCHEMA)?;
    transaction.commit()?;
    schema_objects(&reference)
}

fn open_database_connection(path: &Path) -> Result<Connection> {
    Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(StoreError::from)
}

fn validate_database_path(connection: &Connection, expected_path: &Path) -> Result<()> {
    let expected =
        fs::canonicalize(expected_path).map_err(|_| StoreError::InvalidStorageAuthority)?;
    if expected != expected_path {
        return Err(StoreError::InvalidStorageAuthority);
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
            _ => return Err(StoreError::InvalidStorageAuthority),
        }
    }
    if !saw_main {
        return Err(StoreError::InvalidStorageAuthority);
    }
    Ok(())
}

fn require_linux() -> Result<()> {
    if cfg!(target_os = "linux") {
        Ok(())
    } else {
        Err(StoreError::InvalidStorageAuthority)
    }
}

fn process_lock_path(database: &Path) -> PathBuf {
    sidecar_path(database, ".lock")
}

fn prepared_authority_path(database: &Path) -> PathBuf {
    sidecar_path(database, ".prepare")
}

fn prepared_authority_staging_path(database: &Path) -> PathBuf {
    sidecar_path(database, ".prepare.new")
}

fn require_create_prefix_absent(path: &Path) -> Result<()> {
    for candidate in [
        path.to_path_buf(),
        process_lock_path(path),
        prepared_authority_path(path),
        prepared_authority_staging_path(path),
        sidecar_path(path, "-wal"),
        sidecar_path(path, "-shm"),
        sidecar_path(path, "-journal"),
    ] {
        match fs::symlink_metadata(candidate) {
            Ok(_) => return Err(StoreError::DatabasePresent),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err(StoreError::InvalidStorageAuthority),
        }
    }
    Ok(())
}

fn require_database_present(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            Err(StoreError::DatabaseMissing)
        }
        Err(_) => Err(StoreError::InvalidStorageAuthority),
    }
}

fn acquire_process_lock(database: &Path, create: bool) -> Result<File> {
    let path = process_lock_path(database);
    let mut options = OpenOptions::new();
    options.read(true).write(true);
    if create {
        options.create_new(true);
    }
    #[cfg(target_os = "linux")]
    options.mode(FILE_MODE);
    let file = options
        .open(&path)
        .map_err(|error| match (create, error.kind()) {
            (true, std::io::ErrorKind::AlreadyExists) => StoreError::DatabasePresent,
            _ => StoreError::InvalidStorageAuthority,
        })?;
    validate_open_file_identity(&file, &path)?;
    validate_empty_lock(&file)?;
    #[cfg(target_os = "linux")]
    flock(file.as_fd(), FlockOperation::NonBlockingLockExclusive)
        .map_err(|_| StoreError::ProcessLocked)?;
    validate_open_file_identity(&file, &path)?;
    if create {
        file.sync_all()
            .map_err(|_| StoreError::InvalidStorageAuthority)?;
        sync_parent(database)?;
    }
    Ok(file)
}

fn validate_empty_lock(file: &File) -> Result<()> {
    if file
        .metadata()
        .map_err(|_| StoreError::InvalidStorageAuthority)?
        .len()
        != 0
    {
        return Err(StoreError::InvalidStorageAuthority);
    }
    Ok(())
}

fn create_database_authority(path: &Path) -> Result<File> {
    let mut options = OpenOptions::new();
    options.read(true).write(true).create_new(true);
    #[cfg(target_os = "linux")]
    options.mode(FILE_MODE);
    let file = options.open(path).map_err(|error| match error.kind() {
        std::io::ErrorKind::AlreadyExists => StoreError::DatabasePresent,
        _ => StoreError::InvalidStorageAuthority,
    })?;
    validate_open_file_identity(&file, path)?;
    file.sync_all()
        .map_err(|_| StoreError::InvalidStorageAuthority)?;
    sync_parent(path)?;
    Ok(file)
}

fn open_database_authority(path: &Path) -> Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .map_err(|_| StoreError::InvalidStorageAuthority)?;
    validate_open_file_identity(&file, path)?;
    Ok(file)
}

fn validate_parent(path: &Path) -> Result<()> {
    let parent = path
        .parent()
        .filter(|value| !value.as_os_str().is_empty())
        .ok_or(StoreError::InvalidStorageAuthority)?;
    let metadata = fs::symlink_metadata(parent).map_err(|_| StoreError::InvalidStorageAuthority)?;
    if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
        return Err(StoreError::InvalidStorageAuthority);
    }
    let canonical = fs::canonicalize(parent).map_err(|_| StoreError::InvalidStorageAuthority)?;
    if canonical != parent {
        return Err(StoreError::InvalidStorageAuthority);
    }
    validate_owner_metadata(&metadata, true)
}

fn validate_owner_file(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path).map_err(|_| StoreError::InvalidStorageAuthority)?;
    if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
        return Err(StoreError::InvalidStorageAuthority);
    }
    validate_owner_metadata(&metadata, false)
}

fn validate_owner_metadata(metadata: &fs::Metadata, directory: bool) -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        let expected_mode = if directory { DIRECTORY_MODE } else { FILE_MODE };
        if metadata.uid() != geteuid().as_raw()
            || metadata.mode() & 0o7777 != expected_mode
            || (directory && metadata.nlink() == 0)
            || (!directory && metadata.nlink() != 1)
        {
            return Err(StoreError::InvalidStorageAuthority);
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (metadata, directory);
        return Err(StoreError::InvalidStorageAuthority);
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn validate_open_file_identity(file: &File, path: &Path) -> Result<()> {
    validate_owner_file(path)?;
    let retained = file
        .metadata()
        .map_err(|_| StoreError::InvalidStorageAuthority)?;
    let named = fs::symlink_metadata(path).map_err(|_| StoreError::InvalidStorageAuthority)?;
    if retained.dev() != named.dev() || retained.ino() != named.ino() {
        return Err(StoreError::InvalidStorageAuthority);
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn validate_open_file_identity(_file: &File, _path: &Path) -> Result<()> {
    Err(StoreError::InvalidStorageAuthority)
}

fn sidecar_path(path: &Path, suffix: &str) -> PathBuf {
    let mut value = path.as_os_str().to_os_string();
    value.push(suffix);
    PathBuf::from(value)
}

#[cfg(target_os = "linux")]
#[derive(Clone, Copy)]
enum SqliteSidecarKindV1 {
    Wal,
    SharedMemory,
    RollbackJournal,
}

fn validate_sqlite_sidecars(path: &Path) -> Result<()> {
    #[cfg(target_os = "linux")]
    for (suffix, kind) in [
        ("-wal", SqliteSidecarKindV1::Wal),
        ("-shm", SqliteSidecarKindV1::SharedMemory),
        ("-journal", SqliteSidecarKindV1::RollbackJournal),
    ] {
        let sidecar = sidecar_path(path, suffix);
        match fs::symlink_metadata(&sidecar) {
            Ok(_) => validate_sqlite_sidecar_shape(&sidecar, kind)?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err(StoreError::InvalidStorageAuthority),
        }
    }
    #[cfg(not(target_os = "linux"))]
    return Err(StoreError::InvalidStorageAuthority);
    Ok(())
}

#[cfg(target_os = "linux")]
fn validate_sqlite_sidecar_shape(path: &Path, kind: SqliteSidecarKindV1) -> Result<()> {
    validate_owner_file(path)?;
    let mut file = OpenOptions::new()
        .read(true)
        .open(path)
        .map_err(|_| StoreError::InvalidStorageAuthority)?;
    validate_open_file_identity(&file, path)?;
    let length = file
        .metadata()
        .map_err(|_| StoreError::InvalidStorageAuthority)?
        .len();
    if length == 0 {
        return Ok(());
    }
    let mut header = [0_u8; 8];
    file.read_exact(&mut header)
        .map_err(|_| StoreError::InvalidStorageAuthority)?;
    let valid = match kind {
        SqliteSidecarKindV1::Wal => {
            length >= 32
                && matches!(
                    u32::from_be_bytes(
                        header[..4]
                            .try_into()
                            .map_err(|_| StoreError::InvalidStorageAuthority)?
                    ),
                    0x377f_0682 | 0x377f_0683
                )
        }
        SqliteSidecarKindV1::SharedMemory => {
            length >= 32_768
                && length % 32_768 == 0
                && u32::from_ne_bytes(
                    header[..4]
                        .try_into()
                        .map_err(|_| StoreError::InvalidStorageAuthority)?,
                ) == 3_007_000
        }
        SqliteSidecarKindV1::RollbackJournal => {
            length >= 28 && header == [0xd9, 0xd5, 0x05, 0xf9, 0x20, 0xa1, 0x63, 0xd7]
        }
    };
    if valid {
        Ok(())
    } else {
        Err(StoreError::InvalidStorageAuthority)
    }
}

fn require_sqlite_sidecars_absent(path: &Path) -> Result<()> {
    for suffix in ["-wal", "-shm", "-journal"] {
        match fs::symlink_metadata(sidecar_path(path, suffix)) {
            Ok(_) => return Err(StoreError::InvalidStorageAuthority),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err(StoreError::InvalidStorageAuthority),
        }
    }
    Ok(())
}

fn sync_parent(path: &Path) -> Result<()> {
    let parent = path.parent().ok_or(StoreError::InvalidStorageAuthority)?;
    File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| StoreError::InvalidStorageAuthority)
}

impl From<rusqlite::Error> for StoreError {
    fn from(_: rusqlite::Error) -> Self {
        // The original cause is discarded on purpose: SQLite messages can
        // contain fragments of bound values. The caller receives a
        // classification, never content (I6, I14).
        StoreError::StorageUnavailable
    }
}

/// Result of store operations.
pub type Result<T> = core::result::Result<T, StoreError>;

/// Exact public binding persisted by a strict production opaque store.
///
/// The composition root derives this digest from the route, settlement,
/// participant, direction and authenticated terms. The neutral store neither
/// sees nor reconstructs those domain objects.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProductionStoreBindingV1([u8; 32]);

impl ProductionStoreBindingV1 {
    /// Accept a nonzero, already domain-separated authority binding.
    pub fn new(binding_digest: [u8; 32]) -> Result<Self> {
        if binding_digest == [0; 32] {
            return Err(StoreError::InvalidStorageAuthority);
        }
        Ok(Self(binding_digest))
    }

    /// Public digest persisted in the production authority metadata.
    pub const fn digest(self) -> [u8; 32] {
        self.0
    }
}

/// Entry of the append-only journal, already materialized.
#[derive(Clone, PartialEq, Eq)]
pub struct JournalEntry {
    /// Monotonic sequence, starting at 1.
    pub sequence: u64,
    /// Opaque semantic discriminant, defined by the caller.
    pub kind: u16,
    /// Exact bytes recorded.
    pub payload: Vec<u8>,
}

/// Hard bounds applied before a strict production semantic snapshot is materialized.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProductionAuditLimitsV1 {
    max_rows: u64,
    max_total_bytes: u64,
    max_record_bytes: u64,
}

impl ProductionAuditLimitsV1 {
    /// Construct nonzero row, aggregate-byte and per-record limits.
    pub fn new(max_rows: u64, max_total_bytes: u64, max_record_bytes: u64) -> Result<Self> {
        if max_rows == 0
            || max_total_bytes == 0
            || max_record_bytes == 0
            || max_record_bytes > max_total_bytes
        {
            return Err(StoreError::InvalidStorageAuthority);
        }
        Ok(Self {
            max_rows,
            max_total_bytes,
            max_record_bytes,
        })
    }
}

/// One opaque row captured under the retained production transaction.
///
/// Debug is redacted and the value is wiped when the snapshot is dropped.
pub struct ProductionOpaqueAuditRecordV1 {
    namespace: Vec<u8>,
    key: Vec<u8>,
    value: Vec<u8>,
}

impl ProductionOpaqueAuditRecordV1 {
    /// Opaque namespace selected by the semantic owner.
    pub fn namespace(&self) -> &[u8] {
        &self.namespace
    }

    /// Opaque key selected by the semantic owner.
    pub fn key(&self) -> &[u8] {
        &self.key
    }

    /// Exact retained bytes, available only through the borrowed snapshot row.
    pub fn value(&self) -> &[u8] {
        &self.value
    }
}

impl core::fmt::Debug for ProductionOpaqueAuditRecordV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("ProductionOpaqueAuditRecordV1([redacted])")
    }
}

impl Drop for ProductionOpaqueAuditRecordV1 {
    fn drop(&mut self) {
        self.value.fill(0);
    }
}

/// One monotonic revision row captured by a production semantic snapshot.
pub struct ProductionRevisionAuditRecordV1 {
    entity: Vec<u8>,
    revision: u64,
}

impl ProductionRevisionAuditRecordV1 {
    /// Exact opaque revision entity.
    pub fn entity(&self) -> &[u8] {
        &self.entity
    }

    /// Positive retained revision.
    pub const fn revision(&self) -> u64 {
        self.revision
    }
}

impl core::fmt::Debug for ProductionRevisionAuditRecordV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("ProductionRevisionAuditRecordV1([redacted])")
    }
}

/// One append-only journal row captured by a production semantic snapshot.
pub struct ProductionJournalAuditRecordV1 {
    sequence: u64,
    kind: u16,
    payload: Vec<u8>,
}

impl ProductionJournalAuditRecordV1 {
    /// Contiguous journal sequence, beginning at one.
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    /// Semantic discriminant owned by the vault layer.
    pub const fn kind(&self) -> u16 {
        self.kind
    }

    /// Exact retained payload, borrowed from this move-only snapshot.
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }
}

impl core::fmt::Debug for ProductionJournalAuditRecordV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("ProductionJournalAuditRecordV1([redacted])")
    }
}

impl Drop for ProductionJournalAuditRecordV1 {
    fn drop(&mut self) {
        self.payload.fill(0);
    }
}

/// Bounded, move-only snapshot of the complete neutral production state.
///
/// It has no codec or `Clone`, and its potentially sensitive values are
/// redacted from Debug and wiped on drop.  `dom-vault` consumes this snapshot
/// to apply the semantic invariants that the neutral store cannot know.
pub struct ProductionAuditSnapshotV1 {
    opaque: Vec<ProductionOpaqueAuditRecordV1>,
    revisions: Vec<ProductionRevisionAuditRecordV1>,
    journal: Vec<ProductionJournalAuditRecordV1>,
}

impl ProductionAuditSnapshotV1 {
    /// Every opaque row, ordered by namespace and key.
    pub fn opaque_records(&self) -> &[ProductionOpaqueAuditRecordV1] {
        &self.opaque
    }

    /// Every monotonic revision, ordered by entity.
    pub fn revisions(&self) -> &[ProductionRevisionAuditRecordV1] {
        &self.revisions
    }

    /// The complete contiguous append-only journal.
    pub fn journal(&self) -> &[ProductionJournalAuditRecordV1] {
        &self.journal
    }
}

impl core::fmt::Debug for ProductionAuditSnapshotV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("ProductionAuditSnapshotV1([redacted])")
    }
}

impl core::fmt::Debug for JournalEntry {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // The payload is opaque and may contain protocol artifacts: it is never printed.
        f.debug_struct("JournalEntry")
            .field("sequence", &self.sequence)
            .field("kind", &self.kind)
            .field("payload", &"[redacted]")
            .finish()
    }
}

/// Retained physical authority of one strict production opening.
struct ProductionStorageAuthorityV1 {
    path: PathBuf,
    database: File,
    lock_path: PathBuf,
    lock: File,
    binding: ProductionStoreBindingV1,
}

/// Local authoritative durable store.
pub struct Store {
    pub(crate) connection: Connection,
    production: Option<ProductionStorageAuthorityV1>,
}

impl core::fmt::Debug for Store {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Store([redacted])")
    }
}

impl Store {
    /// Opens or creates the database at `path`, applying pending migrations.
    ///
    /// Fails closed if the database declares a version higher than
    /// [`SCHEMA_VERSION`].
    pub fn open(path: &Path) -> Result<Self> {
        let connection = Connection::open(path)?;
        Self::configure(&connection)?;
        let mut store = Self {
            connection,
            production: None,
        };
        store.migrate()?;
        Ok(store)
    }

    /// Creates a new owner-only DOM participant nonce store.
    ///
    /// This is an explicit production constructor: the database, its empty
    /// retained process lock and all SQLite sidecars must be absent. Schema,
    /// application id and the exact authority binding are committed in one
    /// transaction before this function returns a usable store.
    pub fn create_production(path: &Path, binding: ProductionStoreBindingV1) -> Result<Self> {
        require_linux()?;
        validate_parent(path)?;
        require_create_prefix_absent(path)?;
        let lock = acquire_process_lock(path, true)?;
        let database = create_database_authority(path)?;
        let connection = open_database_connection(path)?;
        configure_production_connection(&connection, true)?;
        initialize_production_schema(&connection, binding)?;
        let store = Self::from_production_parts(path, connection, database, lock, binding);
        store.audit_production_authority()?;
        sync_parent(path)?;
        Ok(store)
    }

    /// Opens an existing exact production authority without creation or migration.
    pub fn open_production(path: &Path, binding: ProductionStoreBindingV1) -> Result<Self> {
        require_linux()?;
        validate_parent(path)?;
        require_database_present(path)?;
        validate_owner_file(path)?;
        validate_sqlite_sidecars(path)?;
        let lock = acquire_process_lock(path, false)?;
        let database = open_database_authority(path)?;
        let connection = open_database_connection(path)?;
        match classify_production_database(&connection, binding)? {
            ProductionDatabaseStateV1::Pristine => return Err(StoreError::CreationIncomplete),
            ProductionDatabaseStateV1::Initialized => {}
        }
        configure_production_connection(&connection, false)?;
        let store = Self::from_production_parts(path, connection, database, lock, binding);
        store.audit_production_authority()?;
        Ok(store)
    }

    /// Durably prepares the only prefix from which a later authenticated
    /// binding may create a production store.
    ///
    /// This is intentionally narrower than [`Self::create_production`]: it
    /// publishes only the empty owner-only process-lock file and never opens
    /// or initializes a database.  An external provisioning journal must
    /// durably record this step before it may call
    /// [`Self::open_or_resume_prepared_production`].  This split is required
    /// when the final store binding is learned from a durable authenticated
    /// message after the process has already provisioned its transport.
    pub fn prepare_resume_create_production(
        path: &Path,
        preparation_binding: ProductionStoreBindingV1,
    ) -> Result<()> {
        require_linux()?;
        validate_parent(path)?;
        require_database_absent_for_preparation(path)?;
        let preparation_path = prepared_authority_path(path);
        let preparation_staging_path = prepared_authority_staging_path(path);
        let preparation_present = match fs::symlink_metadata(&preparation_path) {
            Ok(_) => true,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
            Err(_) => return Err(StoreError::InvalidStorageAuthority),
        };
        let lock_present = match fs::symlink_metadata(process_lock_path(path)) {
            Ok(_) => true,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
            Err(_) => return Err(StoreError::InvalidStorageAuthority),
        };
        if preparation_present && !lock_present {
            return Err(StoreError::InvalidStorageAuthority);
        }
        let lock = acquire_process_lock(path, !lock_present)?;
        validate_open_file_identity(&lock, &process_lock_path(path))?;
        validate_empty_lock(&lock)?;
        if preparation_present {
            require_path_absent(&preparation_staging_path)?;
            validate_prepared_authority(&preparation_path, preparation_binding)?;
        } else {
            recover_or_write_prepared_authority_staging(
                &preparation_staging_path,
                preparation_binding,
            )?;
            fs::rename(&preparation_staging_path, &preparation_path)
                .map_err(|_| StoreError::InvalidStorageAuthority)?;
            sync_parent(path)?;
            validate_prepared_authority(&preparation_path, preparation_binding)?;
        }
        drop(lock);
        require_database_absent_with_prepared_lock(path, preparation_binding)
    }

    /// Opens an exact initialized production authority or completes the
    /// prepared creation prefix under the now-authenticated binding.
    ///
    /// Unlike [`Self::resume_create_production`], an already initialized
    /// authority may contain economic state: that is the necessary restart
    /// case after a lazily bound authority has processed messages.  The
    /// retained prepared lock must exist, and an initialized database must
    /// authenticate the exact supplied binding before it is exposed.  Missing
    /// locks, foreign schemas/bindings, sidecars, identities and concurrent
    /// owners all fail closed.
    pub fn open_or_resume_prepared_production(
        path: &Path,
        preparation_binding: ProductionStoreBindingV1,
        binding: ProductionStoreBindingV1,
    ) -> Result<Self> {
        require_linux()?;
        validate_parent(path)?;
        require_path_absent(&prepared_authority_staging_path(path))?;
        validate_prepared_authority(&prepared_authority_path(path), preparation_binding)?;
        let lock = acquire_process_lock(path, false)?;
        let database = match fs::symlink_metadata(path) {
            Ok(_) => {
                validate_owner_file(path)?;
                validate_sqlite_sidecars(path)?;
                open_database_authority(path)?
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                require_sqlite_sidecars_absent(path)?;
                create_database_authority(path)?
            }
            Err(_) => return Err(StoreError::InvalidStorageAuthority),
        };
        let connection = open_database_connection(path)?;
        match classify_production_database(&connection, binding)? {
            ProductionDatabaseStateV1::Pristine => {
                configure_production_connection(&connection, true)?;
                initialize_production_schema(&connection, binding)?;
            }
            ProductionDatabaseStateV1::Initialized => {
                configure_production_connection(&connection, false)?;
            }
        }
        let store = Self::from_production_parts(path, connection, database, lock, binding);
        store.audit_production_authority()?;
        sync_parent(path)?;
        Ok(store)
    }

    /// Completes only an authenticated empty prefix of an externally journalled create.
    ///
    /// The exact owner-only lock must already exist. The database may be
    /// absent, zero-length/pristine SQLite, or the exact fully committed
    /// production schema with no neutral or economic rows. Foreign schemas,
    /// bindings, versions, application ids and nonempty stores are refused.
    pub fn resume_create_production(
        path: &Path,
        binding: ProductionStoreBindingV1,
    ) -> Result<Self> {
        require_linux()?;
        validate_parent(path)?;
        let lock = acquire_process_lock(path, false)?;
        let database = match fs::symlink_metadata(path) {
            Ok(_) => {
                validate_owner_file(path)?;
                validate_sqlite_sidecars(path)?;
                open_database_authority(path)?
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                require_sqlite_sidecars_absent(path)?;
                create_database_authority(path)?
            }
            Err(_) => return Err(StoreError::InvalidStorageAuthority),
        };
        let connection = open_database_connection(path)?;
        match classify_production_database(&connection, binding)? {
            ProductionDatabaseStateV1::Pristine => {
                configure_production_connection(&connection, true)?;
                initialize_production_schema(&connection, binding)?;
            }
            ProductionDatabaseStateV1::Initialized => {
                configure_production_connection(&connection, false)?;
            }
        }
        require_production_store_empty(&connection)?;
        let store = Self::from_production_parts(path, connection, database, lock, binding);
        store.audit_production_authority()?;
        sync_parent(path)?;
        Ok(store)
    }

    /// Prove that an already initialized production authority still contains
    /// no neutral or economic state.
    ///
    /// An external multi-authority provisioning journal uses this check for
    /// completed members of a crash prefix before it is allowed to resume the
    /// next member. The retained database and lock identities are audited on
    /// both sides of the same connection-level emptiness check.
    pub fn require_empty_production(&mut self) -> Result<()> {
        self.audit_production_physical_authority()?;
        let production_binding = self
            .production_binding()
            .ok_or(StoreError::InvalidStorageAuthority)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        audit_transaction_for_binding(&transaction, Some(production_binding))?;
        require_production_store_empty(&transaction)?;
        audit_transaction_for_binding(&transaction, Some(production_binding))?;
        transaction.commit()?;
        self.audit_production_physical_authority()
    }

    fn from_production_parts(
        path: &Path,
        connection: Connection,
        database: File,
        lock: File,
        binding: ProductionStoreBindingV1,
    ) -> Self {
        Self {
            connection,
            production: Some(ProductionStorageAuthorityV1 {
                path: path.to_path_buf(),
                database,
                lock_path: process_lock_path(path),
                lock,
                binding,
            }),
        }
    }

    /// Applies the pragmas required by ADR-A7.
    fn configure(connection: &Connection) -> Result<()> {
        // WAL survives process termination while keeping concurrent readers.
        let mode: String = connection.query_row("PRAGMA journal_mode=WAL", [], |row| row.get(0))?;
        if !mode.eq_ignore_ascii_case("wal") {
            // A filesystem that does not support WAL (network, for example) is forbidden.
            return Err(StoreError::StorageUnavailable);
        }
        // FULL: Phase 1 requires durability against kill -9, not just against
        // panic. NORMAL would lose the last commit on a power failure.
        connection.pragma_update(None, "synchronous", "FULL")?;
        connection.pragma_update(None, "foreign_keys", "ON")?;
        // Minimal surface (ADR-A7). Defensive mode prevents direct writes to
        // internal structures and shadow tables. Loadable extensions are
        // already off by default: `rusqlite` only enables them via
        // `enable_load_extension`, which this crate never calls — and the
        // `SQLITE_DBCONFIG_ENABLE_LOAD_EXTENSION` constant is not even exposed
        // in this version, so there is no way to enable it by mistake.
        connection.set_db_config(rusqlite::config::DbConfig::SQLITE_DBCONFIG_DEFENSIVE, true)?;
        Ok(())
    }

    /// Migrates the schema to [`SCHEMA_VERSION`], idempotently and atomically.
    fn migrate(&mut self) -> Result<()> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let found: i64 = transaction.query_row("PRAGMA user_version", [], |row| row.get(0))?;
        if found > SCHEMA_VERSION {
            // A silent downgrade would corrupt data from a future version.
            return Err(StoreError::UnsupportedVersion {
                found,
                supported: SCHEMA_VERSION,
            });
        }
        if found < 1 {
            transaction.execute_batch(BASE_SCHEMA)?;
        }
        if found < 2 {
            transaction.execute_batch(MIGRATION_F2_CORE)?;
        }
        if found < 3 {
            transaction.execute_batch(MIGRATION_EXTERNAL_CUSTODY)?;
        }
        if found < 4 {
            transaction.execute_batch(PRODUCTION_AUTHORITY_SCHEMA)?;
        }
        transaction.pragma_update(None, "user_version", SCHEMA_VERSION)?;
        transaction.commit()?;
        Ok(())
    }

    fn production_binding(&self) -> Option<ProductionStoreBindingV1> {
        self.production.as_ref().map(|authority| authority.binding)
    }

    fn audit_production_physical_authority(&self) -> Result<()> {
        let Some(authority) = self.production.as_ref() else {
            return Ok(());
        };
        validate_parent(&authority.path)?;
        validate_open_file_identity(&authority.database, &authority.path)?;
        validate_open_file_identity(&authority.lock, &authority.lock_path)?;
        validate_empty_lock(&authority.lock)?;
        validate_sqlite_sidecars(&authority.path)?;
        validate_database_path(&self.connection, &authority.path)
    }

    fn audit_production_authority(&self) -> Result<()> {
        self.audit_production_physical_authority()?;
        if let Some(binding) = self.production_binding() {
            audit_production_connection(&self.connection, binding)?;
        }
        Ok(())
    }

    pub(crate) fn refuse_settlement_profile_for_production(&self) -> Result<()> {
        if self.production.is_some() {
            return Err(StoreError::InvalidStorageAuthority);
        }
        Ok(())
    }

    /// Appends an entry to the journal and returns its sequence.
    ///
    /// The sequence is strictly monotonic; a gap indicates corruption.
    pub fn append_journal(&mut self, kind: u16, payload: &[u8]) -> Result<u64> {
        self.audit_production_physical_authority()?;
        let production_binding = self.production_binding();
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        audit_transaction_for_binding(&transaction, production_binding)?;
        let head: Option<i64> =
            transaction.query_row("SELECT MAX(sequence) FROM journal", [], |row| row.get(0))?;
        let next = head
            .unwrap_or(0)
            .checked_add(1)
            .ok_or(StoreError::CounterOverflow)?;
        transaction.execute(
            "INSERT INTO journal (sequence, kind, payload) VALUES (?1, ?2, ?3)",
            rusqlite::params![next, i64::from(kind), payload],
        )?;
        audit_transaction_for_binding(&transaction, production_binding)?;
        transaction.commit()?;
        self.audit_production_physical_authority()?;
        u64::try_from(next).map_err(|_| StoreError::CorruptState)
    }

    /// Reads the whole journal in order, validating sequence continuity.
    pub fn read_journal(&self) -> Result<Vec<JournalEntry>> {
        self.audit_production_physical_authority()?;
        let production_binding = self.production_binding();
        let transaction = self.connection.unchecked_transaction()?;
        audit_transaction_for_binding(&transaction, production_binding)?;
        let mut statement = transaction
            .prepare("SELECT sequence, kind, payload FROM journal ORDER BY sequence ASC")?;
        let rows = statement.query_map([], |row| {
            let sequence: i64 = row.get(0)?;
            let kind: i64 = row.get(1)?;
            let payload: Vec<u8> = row.get(2)?;
            Ok((sequence, kind, payload))
        })?;
        let mut entries = Vec::new();
        let mut expected: i64 = 1;
        for row in rows {
            let (sequence, kind, payload) = row?;
            if sequence != expected {
                // A gap or reordering: the journal is append-only by
                // construction, so this only happens through tampering or
                // corruption.
                return Err(StoreError::CorruptState);
            }
            let kind = u16::try_from(kind).map_err(|_| StoreError::CorruptState)?;
            let sequence = u64::try_from(sequence).map_err(|_| StoreError::CorruptState)?;
            entries.push(JournalEntry {
                sequence,
                kind,
                payload,
            });
            expected = expected.checked_add(1).ok_or(StoreError::CounterOverflow)?;
        }
        drop(statement);
        audit_transaction_for_binding(&transaction, production_binding)?;
        transaction.commit()?;
        self.audit_production_physical_authority()?;
        Ok(entries)
    }

    /// Materialize the complete neutral production state under one bounded transaction.
    ///
    /// This API exists for the semantic owner (`dom-vault`).  The neutral
    /// store authenticates its retained files, schema, binding and row/byte
    /// bounds before allocating, holds an IMMEDIATE transaction for the whole
    /// snapshot, and re-audits before and after commit.  It performs no
    /// protocol interpretation itself.
    pub fn production_audit_snapshot(
        &mut self,
        limits: ProductionAuditLimitsV1,
    ) -> Result<ProductionAuditSnapshotV1> {
        self.audit_production_physical_authority()?;
        let production_binding = self
            .production_binding()
            .ok_or(StoreError::InvalidStorageAuthority)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        audit_transaction_for_binding(&transaction, Some(production_binding))?;

        let opaque_metrics: (i64, i64, i64) = transaction.query_row(
            "SELECT COUNT(*),
                    COALESCE(SUM(length(namespace)+length(key)+length(value)),0),
                    COALESCE(MAX(length(namespace)+length(key)+length(value)),0)
             FROM opaque_records",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )?;
        let revision_metrics: (i64, i64, i64) = transaction.query_row(
            "SELECT COUNT(*),
                    COALESCE(SUM(length(entity)+8),0),
                    COALESCE(MAX(length(entity)+8),0)
             FROM revisions",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )?;
        let journal_metrics: (i64, i64, i64) = transaction.query_row(
            "SELECT COUNT(*),
                    COALESCE(SUM(length(payload)+10),0),
                    COALESCE(MAX(length(payload)+10),0)
             FROM journal",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )?;
        let mut row_count = 0_u64;
        let mut total_bytes = 0_u64;
        for (count, total, maximum) in [opaque_metrics, revision_metrics, journal_metrics] {
            let count = u64::try_from(count).map_err(|_| StoreError::CorruptState)?;
            let total = u64::try_from(total).map_err(|_| StoreError::CorruptState)?;
            let maximum = u64::try_from(maximum).map_err(|_| StoreError::CorruptState)?;
            row_count = row_count
                .checked_add(count)
                .ok_or(StoreError::CounterOverflow)?;
            total_bytes = total_bytes
                .checked_add(total)
                .ok_or(StoreError::CounterOverflow)?;
            if maximum > limits.max_record_bytes {
                return Err(StoreError::CorruptState);
            }
        }
        if row_count > limits.max_rows || total_bytes > limits.max_total_bytes {
            return Err(StoreError::CorruptState);
        }

        let opaque = {
            let mut statement = transaction
                .prepare("SELECT namespace,key,value FROM opaque_records ORDER BY namespace,key")?;
            let rows = statement.query_map([], |row| {
                Ok(ProductionOpaqueAuditRecordV1 {
                    namespace: row.get(0)?,
                    key: row.get(1)?,
                    value: row.get(2)?,
                })
            })?;
            let mut records = Vec::new();
            for row in rows {
                records.push(row?);
            }
            records
        };
        let revisions = {
            let mut statement =
                transaction.prepare("SELECT entity,revision FROM revisions ORDER BY entity")?;
            let rows = statement.query_map([], |row| {
                let revision: i64 = row.get(1)?;
                Ok((row.get::<_, Vec<u8>>(0)?, revision))
            })?;
            let mut records = Vec::new();
            for row in rows {
                let (entity, revision) = row?;
                records.push(ProductionRevisionAuditRecordV1 {
                    entity,
                    revision: u64::try_from(revision).map_err(|_| StoreError::CorruptState)?,
                });
            }
            records
        };
        let journal = {
            let mut statement = transaction
                .prepare("SELECT sequence,kind,payload FROM journal ORDER BY sequence")?;
            let rows = statement.query_map([], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                ))
            })?;
            let mut records = Vec::new();
            let mut expected = 1_u64;
            for row in rows {
                let (sequence, kind, payload) = row?;
                let sequence = u64::try_from(sequence).map_err(|_| StoreError::CorruptState)?;
                if sequence != expected {
                    return Err(StoreError::CorruptState);
                }
                records.push(ProductionJournalAuditRecordV1 {
                    sequence,
                    kind: u16::try_from(kind).map_err(|_| StoreError::CorruptState)?,
                    payload,
                });
                expected = expected.checked_add(1).ok_or(StoreError::CounterOverflow)?;
            }
            records
        };
        audit_transaction_for_binding(&transaction, Some(production_binding))?;
        transaction.commit()?;
        self.audit_production_physical_authority()?;
        Ok(ProductionAuditSnapshotV1 {
            opaque,
            revisions,
            journal,
        })
    }

    /// Records an idempotent response, or returns the one already recorded.
    ///
    /// The same key with the same bytes returns the original response. The
    /// same key with different bytes is equivocation and fails closed (I7).
    pub fn put_idempotent(&mut self, key: &[u8], response: &[u8]) -> Result<Vec<u8>> {
        self.refuse_settlement_profile_for_production()?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let existing: Option<Vec<u8>> = transaction
            .query_row(
                "SELECT response FROM idempotency WHERE key = ?1",
                rusqlite::params![key],
                |row| row.get(0),
            )
            .optional()?;
        let stored = match existing {
            Some(previous) => {
                if previous != response {
                    return Err(StoreError::IdempotencyConflict);
                }
                previous
            }
            None => {
                transaction.execute(
                    "INSERT INTO idempotency (key, response) VALUES (?1, ?2)",
                    rusqlite::params![key, response],
                )?;
                response.to_vec()
            }
        };
        transaction.commit()?;
        Ok(stored)
    }

    /// Advances an entity's revision by compare-and-swap.
    ///
    /// `expected` is the revision the caller believes to be current. Zero
    /// means "does not exist yet". A divergence fails closed without writing.
    pub fn compare_and_swap_revision(&mut self, entity: &[u8], expected: u64) -> Result<u64> {
        self.audit_production_physical_authority()?;
        let production_binding = self.production_binding();
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        audit_transaction_for_binding(&transaction, production_binding)?;
        let current: Option<i64> = transaction
            .query_row(
                "SELECT revision FROM revisions WHERE entity = ?1",
                rusqlite::params![entity],
                |row| row.get(0),
            )
            .optional()?;
        let current = match current {
            Some(value) => u64::try_from(value).map_err(|_| StoreError::CorruptState)?,
            None => 0,
        };
        if current != expected {
            return Err(StoreError::RevisionConflict);
        }
        let next = current.checked_add(1).ok_or(StoreError::CounterOverflow)?;
        let encoded = i64::try_from(next).map_err(|_| StoreError::CounterOverflow)?;
        transaction.execute(
            "INSERT INTO revisions (entity, revision) VALUES (?1, ?2)
             ON CONFLICT(entity) DO UPDATE SET revision = ?2",
            rusqlite::params![entity, encoded],
        )?;
        audit_transaction_for_binding(&transaction, production_binding)?;
        transaction.commit()?;
        self.audit_production_physical_authority()?;
        Ok(next)
    }

    /// Records an exact nonzero high-water value for one domain-separated
    /// entity, refusing rollback and persisting forward movement atomically.
    ///
    /// This differs from [`Self::compare_and_swap_revision`]: the supplied
    /// value is an authenticated observation such as trusted wall time, not a
    /// caller-predicted increment. Equal replay is idempotent. A lower value
    /// returns [`StoreError::RevisionConflict`] without changing storage.
    pub fn record_monotonic_high_water(&mut self, entity: &[u8], observed: u64) -> Result<u64> {
        if entity.is_empty() || observed == 0 {
            return Err(StoreError::InvalidStorageAuthority);
        }
        self.audit_production_physical_authority()?;
        let production_binding = self.production_binding();
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        audit_transaction_for_binding(&transaction, production_binding)?;
        let current: Option<i64> = transaction
            .query_row(
                "SELECT revision FROM revisions WHERE entity = ?1",
                rusqlite::params![entity],
                |row| row.get(0),
            )
            .optional()?;
        let current = match current {
            Some(value) => u64::try_from(value).map_err(|_| StoreError::CorruptState)?,
            None => 0,
        };
        if observed < current {
            return Err(StoreError::RevisionConflict);
        }
        let encoded = i64::try_from(observed).map_err(|_| StoreError::CounterOverflow)?;
        if observed > current {
            transaction.execute(
                "INSERT INTO revisions (entity, revision) VALUES (?1, ?2)
                 ON CONFLICT(entity) DO UPDATE SET revision = ?2",
                rusqlite::params![entity, encoded],
            )?;
        }
        audit_transaction_for_binding(&transaction, production_binding)?;
        transaction.commit()?;
        self.audit_production_physical_authority()?;
        Ok(observed)
    }

    /// Reads an entity's current revision; zero if it does not exist yet.
    pub fn revision(&self, entity: &[u8]) -> Result<u64> {
        self.audit_production_physical_authority()?;
        let production_binding = self.production_binding();
        let transaction = self.connection.unchecked_transaction()?;
        audit_transaction_for_binding(&transaction, production_binding)?;
        let current: Option<i64> = transaction
            .query_row(
                "SELECT revision FROM revisions WHERE entity = ?1",
                rusqlite::params![entity],
                |row| row.get(0),
            )
            .optional()?;
        let revision = match current {
            Some(value) => u64::try_from(value).map_err(|_| StoreError::CorruptState),
            None => Ok(0),
        }?;
        audit_transaction_for_binding(&transaction, production_binding)?;
        transaction.commit()?;
        self.audit_production_physical_authority()?;
        Ok(revision)
    }

    /// Persists a chain cursor, replacing the previous one.
    pub fn put_cursor(&mut self, chain: &[u8], cursor: &[u8]) -> Result<()> {
        self.refuse_settlement_profile_for_production()?;
        self.connection.execute(
            "INSERT INTO cursors (chain, cursor) VALUES (?1, ?2)
             ON CONFLICT(chain) DO UPDATE SET cursor = ?2",
            rusqlite::params![chain, cursor],
        )?;
        Ok(())
    }

    /// Reads the persisted cursor of a chain.
    pub fn cursor(&self, chain: &[u8]) -> Result<Option<Vec<u8>>> {
        self.refuse_settlement_profile_for_production()?;
        let cursor: Option<Vec<u8>> = self
            .connection
            .query_row(
                "SELECT cursor FROM cursors WHERE chain = ?1",
                rusqlite::params![chain],
                |row| row.get(0),
            )
            .optional()?;
        Ok(cursor)
    }

    /// Enqueues bytes in the durable outbox and returns the identifier.
    pub fn enqueue_outbox(&mut self, payload: &[u8]) -> Result<u64> {
        self.refuse_settlement_profile_for_production()?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        transaction.execute(
            "INSERT INTO outbox (payload) VALUES (?1)",
            rusqlite::params![payload],
        )?;
        let id = transaction.last_insert_rowid();
        transaction.commit()?;
        u64::try_from(id).map_err(|_| StoreError::CorruptState)
    }

    /// Returns the exact bytes of an outbox entry, delivered or not.
    ///
    /// Retransmission reads from here; it never recomputes (I7).
    pub fn outbox_payload(&self, id: u64) -> Result<Vec<u8>> {
        self.refuse_settlement_profile_for_production()?;
        let encoded = i64::try_from(id).map_err(|_| StoreError::NotFound)?;
        let payload: Option<Vec<u8>> = self
            .connection
            .query_row(
                "SELECT payload FROM outbox WHERE id = ?1",
                rusqlite::params![encoded],
                |row| row.get(0),
            )
            .optional()?;
        payload.ok_or(StoreError::NotFound)
    }

    /// Marks an outbox entry as delivered, idempotently.
    pub fn mark_outbox_delivered(&mut self, id: u64) -> Result<()> {
        self.refuse_settlement_profile_for_production()?;
        let encoded = i64::try_from(id).map_err(|_| StoreError::NotFound)?;
        let changed = self.connection.execute(
            "UPDATE outbox SET delivered = 1 WHERE id = ?1",
            rusqlite::params![encoded],
        )?;
        if changed == 0 {
            return Err(StoreError::NotFound);
        }
        Ok(())
    }

    /// Persists an opaque record under a namespace, failing if it already
    /// exists with different bytes.
    ///
    /// This is the primitive `dom-vault` uses to write sealed artifacts
    /// without this crate knowing what they are.
    pub fn put_opaque(&mut self, namespace: &[u8], key: &[u8], value: &[u8]) -> Result<()> {
        self.audit_production_physical_authority()?;
        let production_binding = self.production_binding();
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        audit_transaction_for_binding(&transaction, production_binding)?;
        let existing: Option<Vec<u8>> = transaction
            .query_row(
                "SELECT value FROM opaque_records WHERE namespace = ?1 AND key = ?2",
                rusqlite::params![namespace, key],
                |row| row.get(0),
            )
            .optional()?;
        match existing {
            Some(previous) if previous != value => return Err(StoreError::IdempotencyConflict),
            Some(_) => {}
            None => {
                transaction.execute(
                    "INSERT INTO opaque_records (namespace, key, value) VALUES (?1, ?2, ?3)",
                    rusqlite::params![namespace, key, value],
                )?;
            }
        }
        audit_transaction_for_binding(&transaction, production_binding)?;
        transaction.commit()?;
        self.audit_production_physical_authority()?;
        Ok(())
    }

    /// Atomically persists an opaque record only when the key has never
    /// existed, returning whether this call created it.
    ///
    /// Unlike a separate `opaque`/`put_opaque` pair, this operation cannot
    /// report success to two concurrent issuers. The immediate transaction
    /// and primary-key constraint form the durable one-time issuance point.
    pub fn put_opaque_if_absent(
        &mut self,
        namespace: &[u8],
        key: &[u8],
        value: &[u8],
    ) -> Result<bool> {
        self.audit_production_physical_authority()?;
        let production_binding = self.production_binding();
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        audit_transaction_for_binding(&transaction, production_binding)?;
        let changed = transaction.execute(
            "INSERT INTO opaque_records (namespace, key, value)
             VALUES (?1, ?2, ?3)
             ON CONFLICT(namespace, key) DO NOTHING",
            rusqlite::params![namespace, key, value],
        )?;
        audit_transaction_for_binding(&transaction, production_binding)?;
        transaction.commit()?;
        self.audit_production_physical_authority()?;
        Ok(changed == 1)
    }

    /// Reads an opaque record.
    pub fn opaque(&self, namespace: &[u8], key: &[u8]) -> Result<Option<Vec<u8>>> {
        self.audit_production_physical_authority()?;
        let production_binding = self.production_binding();
        let transaction = self.connection.unchecked_transaction()?;
        audit_transaction_for_binding(&transaction, production_binding)?;
        let value: Option<Vec<u8>> = transaction
            .query_row(
                "SELECT value FROM opaque_records WHERE namespace = ?1 AND key = ?2",
                rusqlite::params![namespace, key],
                |row| row.get(0),
            )
            .optional()?;
        audit_transaction_for_binding(&transaction, production_binding)?;
        transaction.commit()?;
        self.audit_production_physical_authority()?;
        Ok(value)
    }
}

fn require_database_absent_for_preparation(path: &Path) -> Result<()> {
    for candidate in [
        path.to_path_buf(),
        sidecar_path(path, "-wal"),
        sidecar_path(path, "-shm"),
        sidecar_path(path, "-journal"),
    ] {
        match fs::symlink_metadata(candidate) {
            Ok(_) => return Err(StoreError::InvalidStorageAuthority),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err(StoreError::InvalidStorageAuthority),
        }
    }
    Ok(())
}

fn require_path_absent(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(_) => Err(StoreError::InvalidStorageAuthority),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(StoreError::InvalidStorageAuthority),
    }
}

fn require_database_absent_with_prepared_lock(
    path: &Path,
    preparation_binding: ProductionStoreBindingV1,
) -> Result<()> {
    require_database_absent_for_preparation(path)?;
    let lock_path = process_lock_path(path);
    validate_owner_file(&lock_path)?;
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .open(&lock_path)
        .map_err(|_| StoreError::InvalidStorageAuthority)?;
    validate_open_file_identity(&lock, &lock_path)?;
    validate_empty_lock(&lock)?;
    validate_prepared_authority(&prepared_authority_path(path), preparation_binding)
}

fn prepared_authority_bytes(
    binding: ProductionStoreBindingV1,
) -> [u8; PREPARED_AUTHORITY_BYTES_V1] {
    let mut bytes = [0_u8; PREPARED_AUTHORITY_BYTES_V1];
    bytes[..8].copy_from_slice(PREPARED_AUTHORITY_MAGIC_V1);
    bytes[8..10].copy_from_slice(&PREPARED_AUTHORITY_VERSION_V1.to_be_bytes());
    bytes[10..].copy_from_slice(&binding.digest());
    bytes
}

fn recover_or_write_prepared_authority_staging(
    path: &Path,
    binding: ProductionStoreBindingV1,
) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if !metadata.file_type().is_file()
                || validate_owner_file(path).is_err()
                || validate_prepared_authority(path, binding).is_err()
            {
                if !metadata.file_type().is_file() || validate_owner_file(path).is_err() {
                    return Err(StoreError::InvalidStorageAuthority);
                }
                fs::remove_file(path).map_err(|_| StoreError::InvalidStorageAuthority)?;
                sync_parent(path)?;
                write_prepared_authority_staging(path, binding)?;
            }
            Ok(())
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            write_prepared_authority_staging(path, binding)
        }
        Err(_) => Err(StoreError::InvalidStorageAuthority),
    }
}

fn write_prepared_authority_staging(path: &Path, binding: ProductionStoreBindingV1) -> Result<()> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(target_os = "linux")]
    options.mode(FILE_MODE);
    let mut file = options
        .open(path)
        .map_err(|_| StoreError::InvalidStorageAuthority)?;
    file.write_all(&prepared_authority_bytes(binding))
        .and_then(|()| file.sync_all())
        .map_err(|_| StoreError::InvalidStorageAuthority)?;
    validate_open_file_identity(&file, path)?;
    validate_owner_file(path)
}

fn validate_prepared_authority(path: &Path, binding: ProductionStoreBindingV1) -> Result<()> {
    validate_owner_file(path)?;
    let mut file = OpenOptions::new()
        .read(true)
        .open(path)
        .map_err(|_| StoreError::InvalidStorageAuthority)?;
    validate_open_file_identity(&file, path)?;
    let mut bytes = [0_u8; PREPARED_AUTHORITY_BYTES_V1];
    file.read_exact(&mut bytes)
        .map_err(|_| StoreError::InvalidStorageAuthority)?;
    let mut trailing = [0_u8; 1];
    if file
        .read(&mut trailing)
        .map_err(|_| StoreError::InvalidStorageAuthority)?
        != 0
        || bytes != prepared_authority_bytes(binding)
    {
        return Err(StoreError::InvalidStorageAuthority);
    }
    validate_open_file_identity(&file, path)
}
