//! Durable production Relay queue.
//!
//! [`crate::server::RelayV1`] remains the small in-memory protocol reference.
//! This module implements the same store-and-forward rules over a dedicated
//! owner-only SQLite/WAL database. A commit is durable before an ACK is
//! returned; after ACK loss or process restart the ACK and delivered envelope
//! are derived from the exact persisted row. Opening never creates a missing
//! database, and corruption is never salvaged.
//!
//! The database is transport state, not participant authority. It stores only
//! canonical signed Relay envelopes and public digests. It never interprets a
//! payload, holds a protocol secret, or decides a claim/refund outcome.

use std::collections::BTreeMap;
use std::fs::{self, DirBuilder, File, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::AsFd;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::Duration;

use blake2::{
    digest::{Update, VariableOutput},
    Blake2bVar,
};
use kaystra_core::types::Digest32;
use rusqlite::{params, Connection, OpenFlags, OptionalExtension, TransactionBehavior};
use rustix::fs::{flock, FlockOperation};
use rustix::process::geteuid;

use crate::recovery::{AuthenticatedRecoveryBatchV1, AuthenticatedRecoveryEntryV1};
use crate::server::{AckV1, EquivocationProofV1, IdempotencyKeyV1, MAX_STORED_ENVELOPES};
use crate::{EnvelopeError, ParticipantId, RelayEnvelopeV1, MAX_ENVELOPE_BYTES};

/// Fixed database filename within an owner-only Relay root.
pub const RELAY_DATABASE_FILE_NAME: &str = "relay-v1.sqlite3";
/// Retained instance-identity filename. Database loss does not remove it.
pub const RELAY_IDENTITY_FILE_NAME: &str = "relay-identity.v1";
/// Retained single-writer lock filename.
pub const RELAY_LOCK_FILE_NAME: &str = ".relay.lock";

pub(crate) const RELAY_DATABASE_LOSS_MARKER_NAME: &str = "relay-database-loss.v1";
pub(crate) const ROOT_MODE: u32 = 0o700;
pub(crate) const FILE_MODE: u32 = 0o600;

const SCHEMA_VERSION: i64 = 1;
const SQLITE_VERSION: &str = "3.53.2";
const SQLITE_SOURCE_ID: &str =
    "2026-06-03 19:12:13 d6e03d8c777cfa2d35e3b60d8ec3e0187f3e9f99d8e2ee9cac695fd6fcdf1a24";
const IDENTITY_MAGIC: &[u8; 8] = b"DOMRLYI1";
const IDENTITY_VERSION: u16 = 1;
const IDENTITY_DOMAIN: &[u8] = b"DOM-INTEROP/F7/RELAY-DATABASE-IDENTITY/V1\0";
const IDENTITY_RECORD_LEN: usize = 8 + 2 + 32 + 32;
pub(crate) const DATABASE_LOSS_MAGIC: &[u8; 8] = b"DOMRLYD1";
pub(crate) const DATABASE_LOSS_VERSION: u16 = 1;
pub(crate) const DATABASE_LOSS_DOMAIN: &[u8] = b"DOM-INTEROP/F7/RELAY-DATABASE-LOSS/V1\0";
pub(crate) const DATABASE_LOSS_MARKER_LEN: usize = 8 + 2 + 32 + 32;
const ROW_DOMAIN: &[u8] = b"DOM-INTEROP/F7/RELAY-DATABASE-ROW/V1\0";
const CONFLICT_DOMAIN: &[u8] = b"DOM-INTEROP/F7/RELAY-DATABASE-CONFLICT/V1\0";
const SCHEMA_DOMAIN: &[u8] = b"DOM-INTEROP/F7/RELAY-DATABASE-SCHEMA/V1\0";
const ZERO_DIGEST: Digest32 = [0_u8; 32];
const _: [(); MAX_ENVELOPE_BYTES] = [(); 16_742];

const SCHEMA_SQL: &str = r#"
CREATE TABLE relay_meta (
    singleton               INTEGER PRIMARY KEY CHECK (singleton = 1),
    schema_version          INTEGER NOT NULL CHECK (schema_version = 1),
    database_id             BLOB NOT NULL CHECK (length(database_id) = 32),
    max_envelopes           INTEGER NOT NULL CHECK (max_envelopes > 0 AND max_envelopes <= 65536),
    creation_kind           INTEGER NOT NULL CHECK (creation_kind IN (1, 2)),
    recovery_digest         BLOB NOT NULL CHECK (length(recovery_digest) = 32),
    reconstruction_complete INTEGER NOT NULL CHECK (reconstruction_complete IN (0, 1)),
    schema_digest           BLOB NOT NULL CHECK (length(schema_digest) = 32)
) STRICT;

CREATE TABLE relay_envelopes (
    ordinal            INTEGER PRIMARY KEY CHECK (ordinal > 0 AND ordinal <= 65536),
    session_id         BLOB NOT NULL CHECK (length(session_id) = 32),
    sender_id          BLOB NOT NULL CHECK (length(sender_id) = 32),
    recipient_id       BLOB NOT NULL CHECK (length(recipient_id) = 32),
    sequence_be        BLOB NOT NULL CHECK (length(sequence_be) = 8),
    canonical_bytes    BLOB NOT NULL CHECK (length(canonical_bytes) <= 16742),
    envelope_digest    BLOB NOT NULL CHECK (length(envelope_digest) = 32),
    recovery_source_mask INTEGER NOT NULL CHECK (recovery_source_mask BETWEEN 0 AND 3),
    recovery_commitment  BLOB NOT NULL CHECK (length(recovery_commitment) = 32),
    row_digest         BLOB NOT NULL CHECK (length(row_digest) = 32),
    UNIQUE (session_id, sender_id, recipient_id, sequence_be),
    CHECK (
        (recovery_source_mask = 0 AND recovery_commitment = zeroblob(32)) OR
        (recovery_source_mask > 0 AND recovery_commitment != zeroblob(32))
    )
) STRICT;

CREATE TABLE relay_conflicts (
    ordinal             INTEGER PRIMARY KEY CHECK (ordinal > 0 AND ordinal <= 65536),
    session_id          BLOB NOT NULL CHECK (length(session_id) = 32),
    sender_id           BLOB NOT NULL CHECK (length(sender_id) = 32),
    recipient_id        BLOB NOT NULL CHECK (length(recipient_id) = 32),
    sequence_be         BLOB NOT NULL CHECK (length(sequence_be) = 8),
    first_digest        BLOB NOT NULL CHECK (length(first_digest) = 32),
    conflicting_bytes   BLOB NOT NULL CHECK (length(conflicting_bytes) <= 16742),
    conflicting_digest  BLOB NOT NULL CHECK (length(conflicting_digest) = 32),
    row_digest          BLOB NOT NULL CHECK (length(row_digest) = 32),
    UNIQUE (session_id, sender_id, recipient_id, sequence_be, conflicting_digest)
) STRICT;
"#;

/// Stable public identity of one Relay database root.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RelayDatabaseIdV1(Digest32);

impl core::fmt::Debug for RelayDatabaseIdV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_tuple("RelayDatabaseIdV1")
            .field(&self.0)
            .finish()
    }
}

impl RelayDatabaseIdV1 {
    /// Creates a non-null public database identity.
    pub fn new(bytes: Digest32) -> Result<Self, ProductionRelayError> {
        if bytes == ZERO_DIGEST {
            return Err(ProductionRelayError::InvalidConfiguration);
        }
        Ok(Self(bytes))
    }

    /// Exact public identity bytes.
    pub const fn as_bytes(&self) -> &Digest32 {
        &self.0
    }
}

/// Immutable production database configuration.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct RelayDatabaseConfigV1 {
    database_id: RelayDatabaseIdV1,
    max_envelopes: u32,
}

impl RelayDatabaseConfigV1 {
    /// Creates a bounded configuration. The compiled hard ceiling remains
    /// [`MAX_STORED_ENVELOPES`].
    pub fn new(
        database_id: RelayDatabaseIdV1,
        max_envelopes: u32,
    ) -> Result<Self, ProductionRelayError> {
        if max_envelopes == 0 || max_envelopes as usize > MAX_STORED_ENVELOPES {
            return Err(ProductionRelayError::InvalidConfiguration);
        }
        Ok(Self {
            database_id,
            max_envelopes,
        })
    }

    /// Stable database identity.
    pub const fn database_id(&self) -> RelayDatabaseIdV1 {
        self.database_id
    }

    /// Configured envelope ceiling.
    pub const fn max_envelopes(&self) -> u32 {
        self.max_envelopes
    }
}

/// Redacted, fail-closed production Relay errors.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ProductionRelayError {
    /// Configuration, path or owner-only root requirements were not met.
    #[error("invalid relay database configuration")]
    InvalidConfiguration,
    /// Explicit first creation found an existing root.
    #[error("relay database root already exists")]
    AlreadyExists,
    /// Explicit open found the retained identity but no database.
    #[error("relay database is missing")]
    DatabaseMissing,
    /// Reconstruction was requested while database state still exists.
    #[error("relay database still exists")]
    DatabasePresent,
    /// The retained root identity differs from the expected identity.
    #[error("wrong relay database identity")]
    WrongDatabaseIdentity,
    /// SQLite/filesystem/lock access failed. No underlying message is logged.
    #[error("relay storage unavailable")]
    StorageUnavailable,
    /// The database schema/version/backend is not the frozen production one.
    #[error("unsupported relay database format")]
    UnsupportedFormat,
    /// Physical or logical database validation failed.
    #[error("corrupt relay database")]
    CorruptState,
    /// Envelope codec refusal before storage.
    #[error("codec: {0}")]
    Codec(EnvelopeError),
    /// The configured envelope capacity has been reached.
    #[error("relay storage is full")]
    StorageFull,
    /// Same idempotency key, different exact canonical bytes.
    #[error("relay envelope equivocation")]
    Equivocation,
    /// The supplied authenticated batch does not match its committed digest.
    #[error("recovery batch digest mismatch")]
    RecoveryDigestMismatch,
}

impl From<rusqlite::Error> for ProductionRelayError {
    fn from(_: rusqlite::Error) -> Self {
        Self::StorageUnavailable
    }
}

/// Durable production store-and-forward Relay.
pub struct ProductionRelayV1 {
    connection: Connection,
    root: PathBuf,
    config: RelayDatabaseConfigV1,
    _lock: File,
}

impl core::fmt::Debug for ProductionRelayV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("ProductionRelayV1")
            .field("database_id", &self.config.database_id)
            .field("root", &"[redacted]")
            .finish()
    }
}

impl ProductionRelayV1 {
    /// Explicitly creates a brand-new empty production Relay root.
    ///
    /// This method never reuses an existing root. Process restart must call
    /// [`Self::open`], which never creates a missing database.
    #[cfg(target_os = "linux")]
    pub fn create(
        root: &Path,
        config: RelayDatabaseConfigV1,
    ) -> Result<Self, ProductionRelayError> {
        create_root(root)?;
        write_identity(root, config.database_id)?;
        let lock = acquire_lock(root, true)?;
        let connection = create_database(root, config, 1, ZERO_DIGEST, true)?;
        let relay = Self {
            connection,
            root: root.to_path_buf(),
            config,
            _lock: lock,
        };
        relay.validate_integrity()?;
        Ok(relay)
    }

    /// Non-Linux platforms cannot satisfy the owner-only retained authority.
    #[cfg(not(target_os = "linux"))]
    pub fn create(
        _root: &Path,
        _config: RelayDatabaseConfigV1,
    ) -> Result<Self, ProductionRelayError> {
        Err(ProductionRelayError::StorageUnavailable)
    }

    /// Opens an existing database after process restart.
    ///
    /// Missing files, loss markers, a wrong identity, schema drift, tamper or
    /// any incomplete reconstruction fail closed; this method never creates or
    /// migrates anything.
    #[cfg(target_os = "linux")]
    pub fn open(
        root: &Path,
        expected: RelayDatabaseConfigV1,
    ) -> Result<Self, ProductionRelayError> {
        validate_root(root)?;
        require_identity(root, expected.database_id)?;
        let lock = acquire_lock(root, false)?;
        if root
            .join(RELAY_DATABASE_LOSS_MARKER_NAME)
            .try_exists()
            .map_err(|_| ProductionRelayError::StorageUnavailable)?
        {
            return Err(ProductionRelayError::DatabaseMissing);
        }
        let path = root.join(RELAY_DATABASE_FILE_NAME);
        if !path
            .try_exists()
            .map_err(|_| ProductionRelayError::StorageUnavailable)?
        {
            return Err(ProductionRelayError::DatabaseMissing);
        }
        validate_owner_file(&path)?;
        let connection = Connection::open_with_flags(
            &path,
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;
        configure_connection(&connection, &path)?;
        validate_database_objects(root)?;
        let relay = Self {
            connection,
            root: root.to_path_buf(),
            config: expected,
            _lock: lock,
        };
        relay.validate_integrity()?;
        Ok(relay)
    }

    /// Non-Linux platforms fail closed.
    #[cfg(not(target_os = "linux"))]
    pub fn open(
        _root: &Path,
        _expected: RelayDatabaseConfigV1,
    ) -> Result<Self, ProductionRelayError> {
        Err(ProductionRelayError::StorageUnavailable)
    }

    /// Reconstructs a missing database from one opaque authenticated batch.
    ///
    /// The retained root/identity/lock must survive, every SQLite database
    /// object must be absent, and `batch` is consumed. All rows and the final
    /// recovery digest become visible in one `BEGIN IMMEDIATE` transaction;
    /// an interrupted reconstruction remains marked incomplete and cannot be
    /// opened.
    #[cfg(target_os = "linux")]
    pub fn reconstruct(
        root: &Path,
        config: RelayDatabaseConfigV1,
        batch: AuthenticatedRecoveryBatchV1,
    ) -> Result<Self, ProductionRelayError> {
        validate_root(root)?;
        require_identity(root, config.database_id)?;
        let lock = acquire_lock(root, false)?;
        require_database_absent(root)?;
        let expected_digest = *batch.digest();
        let connection = create_database(root, config, 2, expected_digest, false)?;
        let mut relay = Self {
            connection,
            root: root.to_path_buf(),
            config,
            _lock: lock,
        };
        relay.install_recovery_batch(batch)?;
        remove_loss_marker_if_present(root, config.database_id)?;
        relay.validate_integrity()?;
        Ok(relay)
    }

    /// Non-Linux platforms fail closed.
    #[cfg(not(target_os = "linux"))]
    pub fn reconstruct(
        _root: &Path,
        _config: RelayDatabaseConfigV1,
        _batch: AuthenticatedRecoveryBatchV1,
    ) -> Result<Self, ProductionRelayError> {
        Err(ProductionRelayError::StorageUnavailable)
    }

    /// Stable public identity of this retained root.
    pub const fn database_id(&self) -> RelayDatabaseIdV1 {
        self.config.database_id
    }

    /// Number of canonical envelopes retained in the queue.
    pub fn len(&self) -> Result<usize, ProductionRelayError> {
        let count: i64 =
            self.connection
                .query_row("SELECT COUNT(*) FROM relay_envelopes", [], |row| row.get(0))?;
        usize::try_from(count).map_err(|_| ProductionRelayError::CorruptState)
    }

    /// Whether the durable queue is empty.
    pub fn is_empty(&self) -> Result<bool, ProductionRelayError> {
        Ok(self.len()? == 0)
    }

    /// Durably stores one canonical envelope before returning its ACK.
    ///
    /// Same key and exact bytes returns the same canonical ACK after any
    /// restart. Same key and different bytes is durably journaled as a
    /// conflict and fails closed. Payload bytes are never decoded.
    pub fn submit(&mut self, raw: &[u8]) -> Result<AckV1, ProductionRelayError> {
        self.submit_durable(raw).map(|(ack, _inserted)| ack)
    }

    /// Everything retained for one recipient, in durable insertion order.
    /// Repeated calls intentionally return the same exact bytes (at-least-once
    /// delivery).
    pub fn deliver(&self, recipient: &ParticipantId) -> Result<Vec<Vec<u8>>, ProductionRelayError> {
        let mut statement = self.connection.prepare(
            "SELECT ordinal, session_id, sender_id, recipient_id, sequence_be,
                    canonical_bytes, envelope_digest, recovery_source_mask,
                    recovery_commitment, row_digest
             FROM relay_envelopes
             WHERE recipient_id = ?1
             ORDER BY ordinal ASC",
        )?;
        let rows = statement.query_map(params![recipient.0.as_slice()], row_from_sql)?;
        let mut delivered = Vec::new();
        for row in rows {
            let row = row?;
            validate_envelope_row(&self.config, &row)?;
            if row.key.recipient_id != *recipient {
                return Err(ProductionRelayError::CorruptState);
            }
            delivered.push(row.bytes);
        }
        Ok(delivered)
    }

    /// Exact durable bytes under one idempotency key.
    pub fn stored_bytes(
        &self,
        key: &IdempotencyKeyV1,
    ) -> Result<Option<Vec<u8>>, ProductionRelayError> {
        self.load_envelope_row(key)
            .map(|row| row.map(|stored| stored.bytes))
    }

    /// Returns independently verifiable exact equivocation evidence, if one
    /// was durably observed for this key. Payload bytes are available only
    /// through this explicit evidence API and are redacted from errors/Debug.
    pub fn equivocation_proof(
        &self,
        key: &IdempotencyKeyV1,
    ) -> Result<Option<EquivocationProofV1>, ProductionRelayError> {
        let Some(first) = self.load_envelope_row(key)? else {
            return Ok(None);
        };
        let mut statement = self.connection.prepare(
            "SELECT ordinal, session_id, sender_id, recipient_id, sequence_be,
                    first_digest, conflicting_bytes, conflicting_digest, row_digest
             FROM relay_conflicts
             WHERE session_id = ?1 AND sender_id = ?2 AND recipient_id = ?3 AND sequence_be = ?4
             ORDER BY ordinal ASC LIMIT 1",
        )?;
        let conflict = statement
            .query_row(
                params![
                    key.session_id.as_slice(),
                    key.sender_id.0.as_slice(),
                    key.recipient_id.0.as_slice(),
                    key.sequence.to_be_bytes().as_slice(),
                ],
                conflict_from_sql,
            )
            .optional()?;
        let Some(conflict) = conflict else {
            return Ok(None);
        };
        validate_conflict_row(&self.config, &first, &conflict)?;
        Ok(Some(EquivocationProofV1 {
            key: *key,
            first: first.bytes,
            second: conflict.bytes,
        }))
    }

    pub(crate) fn submit_durable(
        &mut self,
        raw: &[u8],
    ) -> Result<(AckV1, bool), ProductionRelayError> {
        let envelope = RelayEnvelopeV1::decode(raw).map_err(ProductionRelayError::Codec)?;
        let canonical = envelope
            .canonical_bytes()
            .map_err(ProductionRelayError::Codec)?;
        if canonical.as_slice() != raw {
            return Err(ProductionRelayError::CorruptState);
        }
        let key = IdempotencyKeyV1::of(&envelope);
        let digest = envelope
            .envelope_digest()
            .map_err(ProductionRelayError::Codec)?;
        let config = self.config;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let existing = load_envelope_row_from(&transaction, &key)?;
        if let Some(existing) = existing {
            validate_envelope_row(&config, &existing)?;
            if existing.bytes == canonical {
                transaction.commit()?;
                return Ok((
                    AckV1 {
                        key,
                        digest: existing.digest,
                    },
                    false,
                ));
            }
            persist_conflict(&transaction, &config, &existing, &canonical, digest)?;
            transaction.commit()?;
            return Err(ProductionRelayError::Equivocation);
        }
        let count: i64 =
            transaction.query_row("SELECT COUNT(*) FROM relay_envelopes", [], |row| row.get(0))?;
        if count < 0 || count as u64 >= u64::from(config.max_envelopes) {
            return Err(ProductionRelayError::StorageFull);
        }
        let ordinal = count
            .checked_add(1)
            .ok_or(ProductionRelayError::CorruptState)?;
        let row_digest = envelope_row_digest(
            config.database_id,
            &key,
            &canonical,
            &digest,
            0,
            &ZERO_DIGEST,
        )?;
        transaction.execute(
            "INSERT INTO relay_envelopes
             (ordinal, session_id, sender_id, recipient_id, sequence_be,
              canonical_bytes, envelope_digest, recovery_source_mask,
              recovery_commitment, row_digest)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 0, ?8, ?9)",
            params![
                ordinal,
                key.session_id.as_slice(),
                key.sender_id.0.as_slice(),
                key.recipient_id.0.as_slice(),
                key.sequence.to_be_bytes().as_slice(),
                canonical,
                digest.as_slice(),
                ZERO_DIGEST.as_slice(),
                row_digest.as_slice(),
            ],
        )?;
        transaction.commit()?;
        let persisted = self
            .load_envelope_row(&key)?
            .ok_or(ProductionRelayError::CorruptState)?;
        if persisted.bytes.as_slice() != raw || persisted.digest != digest {
            return Err(ProductionRelayError::CorruptState);
        }
        Ok((AckV1 { key, digest }, true))
    }

    fn load_envelope_row(
        &self,
        key: &IdempotencyKeyV1,
    ) -> Result<Option<StoredEnvelopeRowV1>, ProductionRelayError> {
        let row = load_envelope_row_from(&self.connection, key)?;
        if let Some(ref row) = row {
            validate_envelope_row(&self.config, row)?;
        }
        Ok(row)
    }

    fn install_recovery_batch(
        &mut self,
        batch: AuthenticatedRecoveryBatchV1,
    ) -> Result<(), ProductionRelayError> {
        let expected_digest = *batch.digest();
        let config = self.config;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let (kind, stored_digest, complete): (i64, Vec<u8>, i64) = transaction.query_row(
            "SELECT creation_kind, recovery_digest, reconstruction_complete
             FROM relay_meta WHERE singleton = 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )?;
        if kind != 2
            || complete != 0
            || as_digest(&stored_digest)? != expected_digest
            || batch.entries.len() > config.max_envelopes as usize
        {
            return Err(ProductionRelayError::RecoveryDigestMismatch);
        }
        for (index, entry) in batch.entries.into_iter().enumerate() {
            insert_recovery_entry(&transaction, &config, index + 1, entry)?;
        }
        transaction.execute(
            "UPDATE relay_meta SET reconstruction_complete = 1 WHERE singleton = 1",
            [],
        )?;
        transaction.commit()?;
        Ok(())
    }

    fn validate_integrity(&self) -> Result<(), ProductionRelayError> {
        validate_backend_and_schema(&self.connection, &self.root, self.config)?;
        let mut statement = self.connection.prepare(
            "SELECT ordinal, session_id, sender_id, recipient_id, sequence_be,
                    canonical_bytes, envelope_digest, recovery_source_mask,
                    recovery_commitment, row_digest
             FROM relay_envelopes ORDER BY ordinal ASC",
        )?;
        let rows = statement.query_map([], row_from_sql)?;
        let mut expected = 1_i64;
        let mut retained = BTreeMap::<IdempotencyKeyV1, StoredEnvelopeRowV1>::new();
        for row in rows {
            let row = row?;
            if row.ordinal != expected {
                return Err(ProductionRelayError::CorruptState);
            }
            validate_envelope_row(&self.config, &row)?;
            if retained.insert(row.key, row).is_some() {
                return Err(ProductionRelayError::CorruptState);
            }
            expected = expected
                .checked_add(1)
                .ok_or(ProductionRelayError::CorruptState)?;
        }
        if retained.len() > self.config.max_envelopes as usize {
            return Err(ProductionRelayError::CorruptState);
        }

        let mut statement = self.connection.prepare(
            "SELECT ordinal, session_id, sender_id, recipient_id, sequence_be,
                    first_digest, conflicting_bytes, conflicting_digest, row_digest
             FROM relay_conflicts ORDER BY ordinal ASC",
        )?;
        let rows = statement.query_map([], conflict_from_sql)?;
        let mut expected_conflict = 1_i64;
        for row in rows {
            let row = row?;
            if row.ordinal != expected_conflict {
                return Err(ProductionRelayError::CorruptState);
            }
            let first = retained
                .get(&row.key)
                .ok_or(ProductionRelayError::CorruptState)?;
            validate_conflict_row(&self.config, first, &row)?;
            expected_conflict = expected_conflict
                .checked_add(1)
                .ok_or(ProductionRelayError::CorruptState)?;
        }
        Ok(())
    }

    #[cfg(feature = "relay-fault-injection")]
    pub(crate) fn into_fault_parts(self) -> (Connection, PathBuf, RelayDatabaseConfigV1, File) {
        (self.connection, self.root, self.config, self._lock)
    }

    #[cfg(feature = "relay-fault-injection")]
    pub(crate) fn fault_root_clone(&self) -> PathBuf {
        self.root.clone()
    }
}

struct StoredEnvelopeRowV1 {
    ordinal: i64,
    key: IdempotencyKeyV1,
    bytes: Vec<u8>,
    digest: Digest32,
    source_mask: u8,
    source_commitment: Digest32,
    row_digest: Digest32,
}

struct ConflictRowV1 {
    ordinal: i64,
    key: IdempotencyKeyV1,
    first_digest: Digest32,
    bytes: Vec<u8>,
    digest: Digest32,
    row_digest: Digest32,
}

fn create_database(
    root: &Path,
    config: RelayDatabaseConfigV1,
    creation_kind: i64,
    recovery_digest: Digest32,
    complete: bool,
) -> Result<Connection, ProductionRelayError> {
    let path = root.join(RELAY_DATABASE_FILE_NAME);
    if path
        .try_exists()
        .map_err(|_| ProductionRelayError::StorageUnavailable)?
    {
        return Err(ProductionRelayError::DatabasePresent);
    }
    let mut connection = Connection::open_with_flags(
        &path,
        OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_CREATE
            | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?;
    fs::set_permissions(&path, fs::Permissions::from_mode(FILE_MODE))
        .map_err(|_| ProductionRelayError::StorageUnavailable)?;
    validate_owner_file(&path)?;
    configure_connection(&connection, &path)?;
    let schema_digest = digest_parts(SCHEMA_DOMAIN, &[SCHEMA_SQL.as_bytes()])?;
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    transaction.execute_batch(SCHEMA_SQL)?;
    transaction.pragma_update(None, "user_version", SCHEMA_VERSION)?;
    transaction.execute(
        "INSERT INTO relay_meta
         (singleton, schema_version, database_id, max_envelopes, creation_kind,
          recovery_digest, reconstruction_complete, schema_digest)
         VALUES (1, 1, ?1, ?2, ?3, ?4, ?5, ?6)",
        params![
            config.database_id.0.as_slice(),
            i64::from(config.max_envelopes),
            creation_kind,
            recovery_digest.as_slice(),
            if complete { 1_i64 } else { 0_i64 },
            schema_digest.as_slice(),
        ],
    )?;
    transaction.commit()?;
    validate_database_objects(root)?;
    Ok(connection)
}

fn configure_connection(
    connection: &Connection,
    expected_path: &Path,
) -> Result<(), ProductionRelayError> {
    let version: String = connection.query_row("SELECT sqlite_version()", [], |row| row.get(0))?;
    let source: String = connection.query_row("SELECT sqlite_source_id()", [], |row| row.get(0))?;
    if version != SQLITE_VERSION || source != SQLITE_SOURCE_ID {
        return Err(ProductionRelayError::UnsupportedFormat);
    }
    connection.busy_timeout(Duration::from_millis(5_000))?;
    let mode: String = connection.query_row("PRAGMA journal_mode=WAL", [], |row| row.get(0))?;
    if !mode.eq_ignore_ascii_case("wal") {
        return Err(ProductionRelayError::StorageUnavailable);
    }
    connection.pragma_update(None, "synchronous", "FULL")?;
    connection.pragma_update(None, "foreign_keys", "ON")?;
    connection.pragma_update(None, "read_uncommitted", "OFF")?;
    connection.pragma_update(None, "trusted_schema", "OFF")?;
    connection.pragma_update(None, "secure_delete", "ON")?;
    let defensive = rusqlite::config::DbConfig::SQLITE_DBCONFIG_DEFENSIVE;
    if !connection.set_db_config(defensive, true)? || !connection.db_config(defensive)? {
        return Err(ProductionRelayError::UnsupportedFormat);
    }
    let synchronous: i64 = connection.query_row("PRAGMA synchronous", [], |row| row.get(0))?;
    let foreign_keys: i64 = connection.query_row("PRAGMA foreign_keys", [], |row| row.get(0))?;
    let read_uncommitted: i64 =
        connection.query_row("PRAGMA read_uncommitted", [], |row| row.get(0))?;
    let trusted_schema: i64 =
        connection.query_row("PRAGMA trusted_schema", [], |row| row.get(0))?;
    let busy_timeout: i64 = connection.query_row("PRAGMA busy_timeout", [], |row| row.get(0))?;
    let secure_delete: i64 = connection.query_row("PRAGMA secure_delete", [], |row| row.get(0))?;
    if synchronous != 2
        || foreign_keys != 1
        || read_uncommitted != 0
        || trusted_schema != 0
        || busy_timeout != 5_000
        || secure_delete != 1
    {
        return Err(ProductionRelayError::UnsupportedFormat);
    }
    let mut statement = connection.prepare("PRAGMA database_list")?;
    let rows = statement.query_map([], |row| {
        let name: String = row.get(1)?;
        let file: String = row.get(2)?;
        Ok((name, file))
    })?;
    let expected = expected_path
        .to_str()
        .ok_or(ProductionRelayError::InvalidConfiguration)?;
    let mut saw_main = false;
    for row in rows {
        let (name, file) = row?;
        match name.as_str() {
            "main" if file == expected => saw_main = true,
            "temp" if file.is_empty() => {}
            _ => return Err(ProductionRelayError::UnsupportedFormat),
        }
    }
    if !saw_main {
        return Err(ProductionRelayError::UnsupportedFormat);
    }
    Ok(())
}

fn validate_backend_and_schema(
    connection: &Connection,
    root: &Path,
    config: RelayDatabaseConfigV1,
) -> Result<(), ProductionRelayError> {
    validate_root(root)?;
    require_identity(root, config.database_id)?;
    validate_database_objects(root)?;
    let quick: String = connection.query_row("PRAGMA quick_check(1)", [], |row| row.get(0))?;
    if quick != "ok" {
        return Err(ProductionRelayError::CorruptState);
    }
    let user_version: i64 = connection.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    if user_version != SCHEMA_VERSION {
        return Err(ProductionRelayError::UnsupportedFormat);
    }
    let expected_schema_digest = digest_parts(SCHEMA_DOMAIN, &[SCHEMA_SQL.as_bytes()])?;
    let (
        schema_version,
        database_id,
        max_envelopes,
        creation_kind,
        recovery_digest,
        complete,
        schema_digest,
    ): (i64, Vec<u8>, i64, i64, Vec<u8>, i64, Vec<u8>) = connection.query_row(
        "SELECT schema_version, database_id, max_envelopes, creation_kind,
                recovery_digest, reconstruction_complete, schema_digest
         FROM relay_meta WHERE singleton = 1",
        [],
        |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
                row.get(5)?,
                row.get(6)?,
            ))
        },
    )?;
    if schema_version != SCHEMA_VERSION
        || as_digest(&database_id)? != config.database_id.0
        || max_envelopes != i64::from(config.max_envelopes)
        || !matches!(creation_kind, 1 | 2)
        || complete != 1
        || as_digest(&schema_digest)? != expected_schema_digest
        || (creation_kind == 1 && as_digest(&recovery_digest)? != ZERO_DIGEST)
        || (creation_kind == 2 && as_digest(&recovery_digest)? == ZERO_DIGEST)
    {
        return Err(ProductionRelayError::CorruptState);
    }
    let mut statement = connection.prepare(
        "SELECT name, sql FROM sqlite_schema
         WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name",
    )?;
    let tables: BTreeMap<String, String> = statement
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?
        .collect::<Result<_, _>>()?;
    if tables != expected_table_schema()? {
        return Err(ProductionRelayError::UnsupportedFormat);
    }
    let other_objects: i64 = connection.query_row(
        "SELECT COUNT(*) FROM sqlite_schema
         WHERE type IN ('trigger', 'view') OR (type = 'index' AND sql IS NOT NULL)",
        [],
        |row| row.get(0),
    )?;
    if other_objects != 0 {
        return Err(ProductionRelayError::UnsupportedFormat);
    }
    Ok(())
}

fn expected_table_schema() -> Result<BTreeMap<String, String>, ProductionRelayError> {
    let mut expected = BTreeMap::new();
    for statement in SCHEMA_SQL
        .split(';')
        .map(str::trim)
        .filter(|sql| !sql.is_empty())
    {
        let name = statement
            .strip_prefix("CREATE TABLE ")
            .and_then(|tail| tail.split_ascii_whitespace().next())
            .ok_or(ProductionRelayError::CorruptState)?;
        if expected
            .insert(name.to_owned(), statement.to_owned())
            .is_some()
        {
            return Err(ProductionRelayError::CorruptState);
        }
    }
    if expected.len() != 3 {
        return Err(ProductionRelayError::CorruptState);
    }
    Ok(expected)
}

fn insert_recovery_entry(
    transaction: &rusqlite::Transaction<'_>,
    config: &RelayDatabaseConfigV1,
    ordinal: usize,
    entry: AuthenticatedRecoveryEntryV1,
) -> Result<(), ProductionRelayError> {
    if entry.source_mask == 0 || entry.source_mask > 3 || entry.source_commitment == ZERO_DIGEST {
        return Err(ProductionRelayError::RecoveryDigestMismatch);
    }
    let envelope = RelayEnvelopeV1::decode(&entry.bytes).map_err(ProductionRelayError::Codec)?;
    if IdempotencyKeyV1::of(&envelope) != entry.key
        || envelope
            .envelope_digest()
            .map_err(ProductionRelayError::Codec)?
            != entry.digest
        || envelope
            .canonical_bytes()
            .map_err(ProductionRelayError::Codec)?
            != entry.bytes
    {
        return Err(ProductionRelayError::RecoveryDigestMismatch);
    }
    let row_digest = envelope_row_digest(
        config.database_id,
        &entry.key,
        &entry.bytes,
        &entry.digest,
        entry.source_mask,
        &entry.source_commitment,
    )?;
    transaction.execute(
        "INSERT INTO relay_envelopes
         (ordinal, session_id, sender_id, recipient_id, sequence_be,
          canonical_bytes, envelope_digest, recovery_source_mask,
          recovery_commitment, row_digest)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
        params![
            i64::try_from(ordinal).map_err(|_| ProductionRelayError::CorruptState)?,
            entry.key.session_id.as_slice(),
            entry.key.sender_id.0.as_slice(),
            entry.key.recipient_id.0.as_slice(),
            entry.key.sequence.to_be_bytes().as_slice(),
            entry.bytes,
            entry.digest.as_slice(),
            i64::from(entry.source_mask),
            entry.source_commitment.as_slice(),
            row_digest.as_slice(),
        ],
    )?;
    Ok(())
}

fn persist_conflict(
    transaction: &rusqlite::Transaction<'_>,
    config: &RelayDatabaseConfigV1,
    first: &StoredEnvelopeRowV1,
    conflicting_bytes: &[u8],
    conflicting_digest: Digest32,
) -> Result<(), ProductionRelayError> {
    if first.bytes == conflicting_bytes || first.digest == conflicting_digest {
        return Err(ProductionRelayError::CorruptState);
    }
    let existing: Option<Vec<u8>> = transaction
        .query_row(
            "SELECT conflicting_bytes FROM relay_conflicts
             WHERE session_id = ?1 AND sender_id = ?2 AND recipient_id = ?3
               AND sequence_be = ?4 AND conflicting_digest = ?5",
            params![
                first.key.session_id.as_slice(),
                first.key.sender_id.0.as_slice(),
                first.key.recipient_id.0.as_slice(),
                first.key.sequence.to_be_bytes().as_slice(),
                conflicting_digest.as_slice(),
            ],
            |row| row.get(0),
        )
        .optional()?;
    if let Some(existing) = existing {
        if existing == conflicting_bytes {
            return Ok(());
        }
        return Err(ProductionRelayError::CorruptState);
    }
    let count: i64 =
        transaction.query_row("SELECT COUNT(*) FROM relay_conflicts", [], |row| row.get(0))?;
    if count < 0 || count as usize >= MAX_STORED_ENVELOPES {
        return Err(ProductionRelayError::StorageFull);
    }
    let ordinal = count
        .checked_add(1)
        .ok_or(ProductionRelayError::CorruptState)?;
    let row_digest = conflict_row_digest(
        config.database_id,
        &first.key,
        &first.digest,
        conflicting_bytes,
        &conflicting_digest,
    )?;
    transaction.execute(
        "INSERT INTO relay_conflicts
         (ordinal, session_id, sender_id, recipient_id, sequence_be,
          first_digest, conflicting_bytes, conflicting_digest, row_digest)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        params![
            ordinal,
            first.key.session_id.as_slice(),
            first.key.sender_id.0.as_slice(),
            first.key.recipient_id.0.as_slice(),
            first.key.sequence.to_be_bytes().as_slice(),
            first.digest.as_slice(),
            conflicting_bytes,
            conflicting_digest.as_slice(),
            row_digest.as_slice(),
        ],
    )?;
    Ok(())
}

trait QueryRowSource {
    fn query_stored_row(
        &self,
        key: &IdempotencyKeyV1,
    ) -> rusqlite::Result<Option<StoredEnvelopeRowV1>>;
}

impl QueryRowSource for Connection {
    fn query_stored_row(
        &self,
        key: &IdempotencyKeyV1,
    ) -> rusqlite::Result<Option<StoredEnvelopeRowV1>> {
        query_stored_row_impl(self, key)
    }
}

impl QueryRowSource for rusqlite::Transaction<'_> {
    fn query_stored_row(
        &self,
        key: &IdempotencyKeyV1,
    ) -> rusqlite::Result<Option<StoredEnvelopeRowV1>> {
        query_stored_row_impl(self, key)
    }
}

fn query_stored_row_impl(
    source: &Connection,
    key: &IdempotencyKeyV1,
) -> rusqlite::Result<Option<StoredEnvelopeRowV1>> {
    source
        .query_row(
            "SELECT ordinal, session_id, sender_id, recipient_id, sequence_be,
                    canonical_bytes, envelope_digest, recovery_source_mask,
                    recovery_commitment, row_digest
             FROM relay_envelopes
             WHERE session_id = ?1 AND sender_id = ?2 AND recipient_id = ?3 AND sequence_be = ?4",
            params![
                key.session_id.as_slice(),
                key.sender_id.0.as_slice(),
                key.recipient_id.0.as_slice(),
                key.sequence.to_be_bytes().as_slice(),
            ],
            row_from_sql,
        )
        .optional()
}

fn load_envelope_row_from(
    source: &impl QueryRowSource,
    key: &IdempotencyKeyV1,
) -> Result<Option<StoredEnvelopeRowV1>, ProductionRelayError> {
    Ok(source.query_stored_row(key)?)
}

fn row_from_sql(row: &rusqlite::Row<'_>) -> rusqlite::Result<StoredEnvelopeRowV1> {
    let source_mask: i64 = row.get(7)?;
    let key = IdempotencyKeyV1 {
        session_id: sql_digest(row.get(1)?)?,
        sender_id: ParticipantId(sql_digest(row.get(2)?)?),
        recipient_id: ParticipantId(sql_digest(row.get(3)?)?),
        sequence: sql_sequence(row.get(4)?)?,
    };
    Ok(StoredEnvelopeRowV1 {
        ordinal: row.get(0)?,
        key,
        bytes: row.get(5)?,
        digest: sql_digest(row.get(6)?)?,
        source_mask: u8::try_from(source_mask).map_err(|_| rusqlite::Error::InvalidQuery)?,
        source_commitment: sql_digest(row.get(8)?)?,
        row_digest: sql_digest(row.get(9)?)?,
    })
}

fn conflict_from_sql(row: &rusqlite::Row<'_>) -> rusqlite::Result<ConflictRowV1> {
    Ok(ConflictRowV1 {
        ordinal: row.get(0)?,
        key: IdempotencyKeyV1 {
            session_id: sql_digest(row.get(1)?)?,
            sender_id: ParticipantId(sql_digest(row.get(2)?)?),
            recipient_id: ParticipantId(sql_digest(row.get(3)?)?),
            sequence: sql_sequence(row.get(4)?)?,
        },
        first_digest: sql_digest(row.get(5)?)?,
        bytes: row.get(6)?,
        digest: sql_digest(row.get(7)?)?,
        row_digest: sql_digest(row.get(8)?)?,
    })
}

fn validate_envelope_row(
    config: &RelayDatabaseConfigV1,
    row: &StoredEnvelopeRowV1,
) -> Result<(), ProductionRelayError> {
    if row.ordinal <= 0
        || row.ordinal > i64::from(config.max_envelopes)
        || row.bytes.len() > MAX_ENVELOPE_BYTES
        || row.source_mask > 3
        || (row.source_mask == 0) != (row.source_commitment == ZERO_DIGEST)
    {
        return Err(ProductionRelayError::CorruptState);
    }
    let envelope =
        RelayEnvelopeV1::decode(&row.bytes).map_err(|_| ProductionRelayError::CorruptState)?;
    if IdempotencyKeyV1::of(&envelope) != row.key
        || envelope
            .canonical_bytes()
            .map_err(|_| ProductionRelayError::CorruptState)?
            != row.bytes
        || envelope
            .envelope_digest()
            .map_err(|_| ProductionRelayError::CorruptState)?
            != row.digest
        || envelope_row_digest(
            config.database_id,
            &row.key,
            &row.bytes,
            &row.digest,
            row.source_mask,
            &row.source_commitment,
        )? != row.row_digest
    {
        return Err(ProductionRelayError::CorruptState);
    }
    Ok(())
}

fn validate_conflict_row(
    config: &RelayDatabaseConfigV1,
    first: &StoredEnvelopeRowV1,
    row: &ConflictRowV1,
) -> Result<(), ProductionRelayError> {
    if row.ordinal <= 0
        || row.ordinal > MAX_STORED_ENVELOPES as i64
        || row.key != first.key
        || row.first_digest != first.digest
        || row.bytes == first.bytes
    {
        return Err(ProductionRelayError::CorruptState);
    }
    let envelope =
        RelayEnvelopeV1::decode(&row.bytes).map_err(|_| ProductionRelayError::CorruptState)?;
    if IdempotencyKeyV1::of(&envelope) != row.key
        || envelope
            .canonical_bytes()
            .map_err(|_| ProductionRelayError::CorruptState)?
            != row.bytes
        || envelope
            .envelope_digest()
            .map_err(|_| ProductionRelayError::CorruptState)?
            != row.digest
        || conflict_row_digest(
            config.database_id,
            &row.key,
            &row.first_digest,
            &row.bytes,
            &row.digest,
        )? != row.row_digest
    {
        return Err(ProductionRelayError::CorruptState);
    }
    Ok(())
}

fn envelope_row_digest(
    database_id: RelayDatabaseIdV1,
    key: &IdempotencyKeyV1,
    bytes: &[u8],
    digest: &Digest32,
    source_mask: u8,
    source_commitment: &Digest32,
) -> Result<Digest32, ProductionRelayError> {
    digest_parts(
        ROW_DOMAIN,
        &[
            database_id.0.as_slice(),
            key.session_id.as_slice(),
            key.sender_id.0.as_slice(),
            key.recipient_id.0.as_slice(),
            key.sequence.to_be_bytes().as_slice(),
            digest.as_slice(),
            &[source_mask],
            source_commitment.as_slice(),
            &(bytes.len() as u32).to_be_bytes(),
            bytes,
        ],
    )
}

fn conflict_row_digest(
    database_id: RelayDatabaseIdV1,
    key: &IdempotencyKeyV1,
    first_digest: &Digest32,
    bytes: &[u8],
    digest: &Digest32,
) -> Result<Digest32, ProductionRelayError> {
    digest_parts(
        CONFLICT_DOMAIN,
        &[
            database_id.0.as_slice(),
            key.session_id.as_slice(),
            key.sender_id.0.as_slice(),
            key.recipient_id.0.as_slice(),
            key.sequence.to_be_bytes().as_slice(),
            first_digest.as_slice(),
            digest.as_slice(),
            &(bytes.len() as u32).to_be_bytes(),
            bytes,
        ],
    )
}

fn digest_parts(domain: &[u8], parts: &[&[u8]]) -> Result<Digest32, ProductionRelayError> {
    let mut hasher = Blake2bVar::new(32).map_err(|_| ProductionRelayError::CorruptState)?;
    hasher.update(domain);
    for part in parts {
        hasher.update(part);
    }
    let mut digest = [0_u8; 32];
    hasher
        .finalize_variable(&mut digest)
        .map_err(|_| ProductionRelayError::CorruptState)?;
    Ok(digest)
}

fn identity_record(
    database_id: RelayDatabaseIdV1,
) -> Result<[u8; IDENTITY_RECORD_LEN], ProductionRelayError> {
    let checksum = digest_parts(IDENTITY_DOMAIN, &[database_id.0.as_slice()])?;
    let mut record = [0_u8; IDENTITY_RECORD_LEN];
    record[..8].copy_from_slice(IDENTITY_MAGIC);
    record[8..10].copy_from_slice(&IDENTITY_VERSION.to_be_bytes());
    record[10..42].copy_from_slice(&database_id.0);
    record[42..].copy_from_slice(&checksum);
    Ok(record)
}

#[cfg(target_os = "linux")]
fn create_root(root: &Path) -> Result<(), ProductionRelayError> {
    validate_new_path(root)?;
    match DirBuilder::new().mode(ROOT_MODE).create(root) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            return Err(ProductionRelayError::AlreadyExists)
        }
        Err(_) => return Err(ProductionRelayError::StorageUnavailable),
    }
    File::open(root)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| ProductionRelayError::StorageUnavailable)?;
    let parent = root
        .parent()
        .ok_or(ProductionRelayError::InvalidConfiguration)?;
    File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| ProductionRelayError::StorageUnavailable)?;
    validate_root(root)
}

#[cfg(target_os = "linux")]
fn validate_new_path(root: &Path) -> Result<(), ProductionRelayError> {
    if !root.is_absolute() || root.file_name().is_none() {
        return Err(ProductionRelayError::InvalidConfiguration);
    }
    let parent = root
        .parent()
        .ok_or(ProductionRelayError::InvalidConfiguration)?;
    let canonical_parent =
        fs::canonicalize(parent).map_err(|_| ProductionRelayError::InvalidConfiguration)?;
    if canonical_parent != parent {
        return Err(ProductionRelayError::InvalidConfiguration);
    }
    validate_owner_directory(parent)?;
    Ok(())
}

#[cfg(target_os = "linux")]
pub(crate) fn validate_root(root: &Path) -> Result<(), ProductionRelayError> {
    if !root.is_absolute()
        || fs::canonicalize(root).map_err(|_| ProductionRelayError::StorageUnavailable)? != root
    {
        return Err(ProductionRelayError::InvalidConfiguration);
    }
    validate_owner_directory(root)
}

#[cfg(target_os = "linux")]
fn validate_owner_directory(path: &Path) -> Result<(), ProductionRelayError> {
    let metadata =
        fs::symlink_metadata(path).map_err(|_| ProductionRelayError::StorageUnavailable)?;
    if !metadata.file_type().is_dir()
        || metadata.file_type().is_symlink()
        || metadata.uid() != geteuid().as_raw()
        || metadata.mode() & 0o777 != ROOT_MODE
        || metadata.nlink() == 0
    {
        return Err(ProductionRelayError::InvalidConfiguration);
    }
    Ok(())
}

#[cfg(target_os = "linux")]
pub(crate) fn validate_owner_file(path: &Path) -> Result<(), ProductionRelayError> {
    let metadata =
        fs::symlink_metadata(path).map_err(|_| ProductionRelayError::StorageUnavailable)?;
    if !metadata.file_type().is_file()
        || metadata.file_type().is_symlink()
        || metadata.uid() != geteuid().as_raw()
        || metadata.mode() & 0o777 != FILE_MODE
        || metadata.nlink() != 1
    {
        return Err(ProductionRelayError::InvalidConfiguration);
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn write_identity(root: &Path, database_id: RelayDatabaseIdV1) -> Result<(), ProductionRelayError> {
    let path = root.join(RELAY_IDENTITY_FILE_NAME);
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(FILE_MODE)
        .open(&path)
        .map_err(|_| ProductionRelayError::StorageUnavailable)?;
    file.write_all(&identity_record(database_id)?)
        .and_then(|_| file.sync_all())
        .map_err(|_| ProductionRelayError::StorageUnavailable)?;
    validate_owner_file(&path)?;
    File::open(root)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| ProductionRelayError::StorageUnavailable)
}

#[cfg(target_os = "linux")]
fn require_identity(root: &Path, expected: RelayDatabaseIdV1) -> Result<(), ProductionRelayError> {
    let path = root.join(RELAY_IDENTITY_FILE_NAME);
    validate_owner_file(&path)?;
    let mut file = File::open(&path).map_err(|_| ProductionRelayError::StorageUnavailable)?;
    let mut bytes = Vec::with_capacity(IDENTITY_RECORD_LEN + 1);
    Read::by_ref(&mut file)
        .take((IDENTITY_RECORD_LEN + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| ProductionRelayError::StorageUnavailable)?;
    if bytes.len() != IDENTITY_RECORD_LEN
        || &bytes[..8] != IDENTITY_MAGIC
        || u16::from_be_bytes([bytes[8], bytes[9]]) != IDENTITY_VERSION
    {
        return Err(ProductionRelayError::WrongDatabaseIdentity);
    }
    let database_id = as_digest(&bytes[10..42])?;
    let checksum = as_digest(&bytes[42..74])?;
    if database_id != expected.0
        || checksum != digest_parts(IDENTITY_DOMAIN, &[database_id.as_slice()])?
    {
        return Err(ProductionRelayError::WrongDatabaseIdentity);
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn acquire_lock(root: &Path, create: bool) -> Result<File, ProductionRelayError> {
    let path = root.join(RELAY_LOCK_FILE_NAME);
    let mut options = OpenOptions::new();
    options.read(true).write(true).mode(FILE_MODE);
    if create {
        options.create_new(true);
    }
    let file = options
        .open(&path)
        .map_err(|_| ProductionRelayError::StorageUnavailable)?;
    validate_owner_file(&path)?;
    let retained = file
        .metadata()
        .map_err(|_| ProductionRelayError::StorageUnavailable)?;
    let named =
        fs::symlink_metadata(&path).map_err(|_| ProductionRelayError::StorageUnavailable)?;
    if retained.dev() != named.dev() || retained.ino() != named.ino() {
        return Err(ProductionRelayError::InvalidConfiguration);
    }
    flock(file.as_fd(), FlockOperation::NonBlockingLockExclusive)
        .map_err(|_| ProductionRelayError::StorageUnavailable)?;
    if create {
        file.sync_all()
            .map_err(|_| ProductionRelayError::StorageUnavailable)?;
        File::open(root)
            .and_then(|directory| directory.sync_all())
            .map_err(|_| ProductionRelayError::StorageUnavailable)?;
    }
    Ok(file)
}

#[cfg(target_os = "linux")]
fn validate_database_objects(root: &Path) -> Result<(), ProductionRelayError> {
    for name in [
        RELAY_DATABASE_FILE_NAME.to_owned(),
        format!("{RELAY_DATABASE_FILE_NAME}-wal"),
        format!("{RELAY_DATABASE_FILE_NAME}-shm"),
    ] {
        let path = root.join(name);
        if path
            .try_exists()
            .map_err(|_| ProductionRelayError::StorageUnavailable)?
        {
            validate_owner_file(&path)?;
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn require_database_absent(root: &Path) -> Result<(), ProductionRelayError> {
    for name in [
        RELAY_DATABASE_FILE_NAME.to_owned(),
        format!("{RELAY_DATABASE_FILE_NAME}-wal"),
        format!("{RELAY_DATABASE_FILE_NAME}-shm"),
    ] {
        if root
            .join(name)
            .try_exists()
            .map_err(|_| ProductionRelayError::StorageUnavailable)?
        {
            return Err(ProductionRelayError::DatabasePresent);
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn remove_loss_marker_if_present(
    root: &Path,
    database_id: RelayDatabaseIdV1,
) -> Result<(), ProductionRelayError> {
    let marker = root.join(RELAY_DATABASE_LOSS_MARKER_NAME);
    if marker
        .try_exists()
        .map_err(|_| ProductionRelayError::StorageUnavailable)?
    {
        validate_owner_file(&marker)?;
        let mut file = File::open(&marker).map_err(|_| ProductionRelayError::StorageUnavailable)?;
        let mut retained = Vec::with_capacity(DATABASE_LOSS_MARKER_LEN + 1);
        Read::by_ref(&mut file)
            .take((DATABASE_LOSS_MARKER_LEN + 1) as u64)
            .read_to_end(&mut retained)
            .map_err(|_| ProductionRelayError::StorageUnavailable)?;
        if retained != database_loss_marker(database_id)?.as_slice() {
            return Err(ProductionRelayError::CorruptState);
        }
    }
    match fs::remove_file(&marker) {
        Ok(()) => File::open(root)
            .and_then(|directory| directory.sync_all())
            .map_err(|_| ProductionRelayError::StorageUnavailable),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(ProductionRelayError::StorageUnavailable),
    }
}

pub(crate) fn database_loss_marker(
    database_id: RelayDatabaseIdV1,
) -> Result<[u8; DATABASE_LOSS_MARKER_LEN], ProductionRelayError> {
    let checksum = digest_parts(DATABASE_LOSS_DOMAIN, &[database_id.as_bytes()])?;
    let mut marker = [0_u8; DATABASE_LOSS_MARKER_LEN];
    marker[..8].copy_from_slice(DATABASE_LOSS_MAGIC);
    marker[8..10].copy_from_slice(&DATABASE_LOSS_VERSION.to_be_bytes());
    marker[10..42].copy_from_slice(database_id.as_bytes());
    marker[42..].copy_from_slice(&checksum);
    Ok(marker)
}

fn as_digest(bytes: &[u8]) -> Result<Digest32, ProductionRelayError> {
    bytes
        .try_into()
        .map_err(|_| ProductionRelayError::CorruptState)
}

fn sql_digest(bytes: Vec<u8>) -> rusqlite::Result<Digest32> {
    bytes.try_into().map_err(|_| rusqlite::Error::InvalidQuery)
}

fn sql_sequence(bytes: Vec<u8>) -> rusqlite::Result<u64> {
    let array: [u8; 8] = bytes
        .try_into()
        .map_err(|_| rusqlite::Error::InvalidQuery)?;
    Ok(u64::from_be_bytes(array))
}
