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
    SettlementJournalRow, SettlementSnapshotRow, TerminalInsert, EVIDENCE_APPLIED,
    EVIDENCE_INVALIDATED, EVIDENCE_PARKED, OUTBOX_COMPLETED, OUTBOX_PENDING,
};

use std::path::Path;

use rusqlite::{Connection, OptionalExtension, TransactionBehavior};

/// Schema version this binary knows how to operate.
///
/// A database with a higher version is a downgrade and fails closed; a
/// database with a lower version is migrated upward, idempotently, inside a
/// transaction. Version 2 adds the F2 core settlement schema; version 3 adds
/// payload-free, non-leaseable external-custody outbox effects.
pub const SCHEMA_VERSION: i64 = 3;

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

/// Local authoritative durable store.
pub struct Store {
    pub(crate) connection: Connection,
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
        let mut store = Self { connection };
        store.migrate()?;
        Ok(store)
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
            transaction.execute_batch(
                "CREATE TABLE journal (
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
                 ) STRICT;",
            )?;
        }
        if found < 2 {
            transaction.execute_batch(MIGRATION_F2_CORE)?;
        }
        if found < 3 {
            transaction.execute_batch(MIGRATION_EXTERNAL_CUSTODY)?;
        }
        transaction.pragma_update(None, "user_version", SCHEMA_VERSION)?;
        transaction.commit()?;
        Ok(())
    }

    /// Appends an entry to the journal and returns its sequence.
    ///
    /// The sequence is strictly monotonic; a gap indicates corruption.
    pub fn append_journal(&mut self, kind: u16, payload: &[u8]) -> Result<u64> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
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
        transaction.commit()?;
        u64::try_from(next).map_err(|_| StoreError::CorruptState)
    }

    /// Reads the whole journal in order, validating sequence continuity.
    pub fn read_journal(&self) -> Result<Vec<JournalEntry>> {
        let mut statement = self
            .connection
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
        Ok(entries)
    }

    /// Records an idempotent response, or returns the one already recorded.
    ///
    /// The same key with the same bytes returns the original response. The
    /// same key with different bytes is equivocation and fails closed (I7).
    pub fn put_idempotent(&mut self, key: &[u8], response: &[u8]) -> Result<Vec<u8>> {
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
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
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
        transaction.commit()?;
        Ok(next)
    }

    /// Reads an entity's current revision; zero if it does not exist yet.
    pub fn revision(&self, entity: &[u8]) -> Result<u64> {
        let current: Option<i64> = self
            .connection
            .query_row(
                "SELECT revision FROM revisions WHERE entity = ?1",
                rusqlite::params![entity],
                |row| row.get(0),
            )
            .optional()?;
        match current {
            Some(value) => u64::try_from(value).map_err(|_| StoreError::CorruptState),
            None => Ok(0),
        }
    }

    /// Persists a chain cursor, replacing the previous one.
    pub fn put_cursor(&mut self, chain: &[u8], cursor: &[u8]) -> Result<()> {
        self.connection.execute(
            "INSERT INTO cursors (chain, cursor) VALUES (?1, ?2)
             ON CONFLICT(chain) DO UPDATE SET cursor = ?2",
            rusqlite::params![chain, cursor],
        )?;
        Ok(())
    }

    /// Reads the persisted cursor of a chain.
    pub fn cursor(&self, chain: &[u8]) -> Result<Option<Vec<u8>>> {
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
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
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
        transaction.commit()?;
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
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let changed = transaction.execute(
            "INSERT INTO opaque_records (namespace, key, value)
             VALUES (?1, ?2, ?3)
             ON CONFLICT(namespace, key) DO NOTHING",
            rusqlite::params![namespace, key, value],
        )?;
        transaction.commit()?;
        Ok(changed == 1)
    }

    /// Reads an opaque record.
    pub fn opaque(&self, namespace: &[u8], key: &[u8]) -> Result<Option<Vec<u8>>> {
        let value: Option<Vec<u8>> = self
            .connection
            .query_row(
                "SELECT value FROM opaque_records WHERE namespace = ?1 AND key = ?2",
                rusqlite::params![namespace, key],
                |row| row.get(0),
            )
            .optional()?;
        Ok(value)
    }
}
