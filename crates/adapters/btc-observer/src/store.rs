//! The durable observer store and effect transaction (Annex M M.10).

use std::path::Path;

use blake2::digest::{Update, VariableOutput};
use blake2::Blake2bVar;
use rusqlite::{Connection, OptionalExtension, TransactionBehavior};

use crate::cursor::BitcoinChainCursorV1;
use crate::events::{BitcoinNetworkV1, BitcoinObservedEventV1};

/// Observer failures. No variant carries secret material (M.21).
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ObserverError {
    /// The underlying storage failed or is unavailable.
    #[error("storage unavailable")]
    StorageUnavailable,
    /// Stored state is corrupt.
    #[error("corrupt state")]
    CorruptState,
    /// The same idempotency key was seen with different bytes (M.10.4).
    #[error("terminal equivocation")]
    Equivocation,
    /// The cursor regressed or a compare-and-swap was lost.
    #[error("cursor conflict")]
    CursorConflict,
    /// The cursor for this network does not exist yet.
    #[error("no cursor")]
    NoCursor,
}

/// The outcome of applying an event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApplyOutcome {
    /// The event was applied for the first time; the cursor advanced.
    Applied,
    /// The event was an idempotent redelivery (same key, same bytes).
    Duplicate,
}

const SCHEMA_VERSION: i64 = 1;
const IDEMPOTENCY_DOMAIN: &[u8] = b"DOM-INTEROP/BTC/F5/V1/OBSERVED-EVENT\0";

/// The durable observer store over SQLite (WAL, synchronous=FULL).
pub struct ObserverStore {
    connection: Connection,
}

impl ObserverStore {
    /// Opens (or creates) the store at `path`.
    pub fn open(path: &Path) -> Result<Self, ObserverError> {
        let connection = Connection::open(path).map_err(|_| ObserverError::StorageUnavailable)?;
        Self::configure(&connection)?;
        let mut store = Self { connection };
        store.migrate()?;
        Ok(store)
    }

    fn configure(connection: &Connection) -> Result<(), ObserverError> {
        let mode: String = connection
            .query_row("PRAGMA journal_mode=WAL", [], |r| r.get(0))
            .map_err(|_| ObserverError::StorageUnavailable)?;
        if !mode.eq_ignore_ascii_case("wal") {
            return Err(ObserverError::StorageUnavailable);
        }
        connection
            .pragma_update(None, "synchronous", "FULL")
            .map_err(|_| ObserverError::StorageUnavailable)?;
        Ok(())
    }

    fn migrate(&mut self) -> Result<(), ObserverError> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| ObserverError::StorageUnavailable)?;
        let found: i64 = tx
            .query_row("PRAGMA user_version", [], |r| r.get(0))
            .map_err(|_| ObserverError::StorageUnavailable)?;
        if found > SCHEMA_VERSION {
            return Err(ObserverError::CorruptState);
        }
        if found < 1 {
            tx.execute_batch(
                "CREATE TABLE btc_cursors (
                     network_code       INTEGER PRIMARY KEY,
                     block_hash         BLOB NOT NULL CHECK(length(block_hash) = 32),
                     height             INTEGER NOT NULL,
                     header_chain_digest BLOB NOT NULL CHECK(length(header_chain_digest) = 32),
                     revision           INTEGER NOT NULL CHECK(revision >= 0)
                 ) STRICT;
                 CREATE TABLE btc_events (
                     idempotency_key BLOB PRIMARY KEY CHECK(length(idempotency_key) = 32),
                     network_code    INTEGER NOT NULL,
                     kind            INTEGER NOT NULL,
                     anchor_height   INTEGER,
                     valid           INTEGER NOT NULL CHECK(valid IN (0,1)),
                     event_bytes     BLOB NOT NULL
                 ) STRICT;
                 CREATE TABLE btc_evidence_refs (
                     evidence_ref BLOB PRIMARY KEY CHECK(length(evidence_ref) = 32),
                     network_code INTEGER NOT NULL,
                     height       INTEGER NOT NULL,
                     valid        INTEGER NOT NULL CHECK(valid IN (0,1))
                 ) STRICT;
                 CREATE TABLE btc_outbox (
                     id           INTEGER PRIMARY KEY,
                     payload      BLOB NOT NULL,
                     delivered    INTEGER NOT NULL DEFAULT 0
                 ) STRICT;",
            )
            .map_err(|_| ObserverError::StorageUnavailable)?;
        }
        tx.pragma_update(None, "user_version", SCHEMA_VERSION)
            .map_err(|_| ObserverError::StorageUnavailable)?;
        tx.commit().map_err(|_| ObserverError::StorageUnavailable)?;
        Ok(())
    }

    /// Installs the genesis cursor for a network if none exists.
    pub fn init_cursor(&mut self, cursor: &BitcoinChainCursorV1) -> Result<(), ObserverError> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| ObserverError::StorageUnavailable)?;
        tx.execute(
            "INSERT OR IGNORE INTO btc_cursors
                 (network_code, block_hash, height, header_chain_digest, revision)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
            rusqlite::params![
                cursor.network.code(),
                &cursor.block_hash[..],
                cursor.height as i64,
                &cursor.header_chain_digest[..],
                cursor.revision as i64,
            ],
        )
        .map_err(|_| ObserverError::StorageUnavailable)?;
        tx.commit().map_err(|_| ObserverError::StorageUnavailable)?;
        Ok(())
    }

    /// The canonical idempotency key of an event (M.10.4): a digest over
    /// the network, kind and the event's identifying fields.
    fn idempotency_key(
        network: BitcoinNetworkV1,
        event: &BitcoinObservedEventV1,
    ) -> ([u8; 32], Vec<u8>) {
        let mut fields = Vec::new();
        fields.push(event.kind_code());
        match event {
            BitcoinObservedEventV1::FundingSeen { txid, height } => {
                fields.extend_from_slice(txid);
                fields.extend_from_slice(&height.unwrap_or(u64::MAX).to_be_bytes());
            }
            BitcoinObservedEventV1::FundingConfirmed {
                txid,
                block_hash,
                height,
            } => {
                fields.extend_from_slice(txid);
                fields.extend_from_slice(block_hash);
                fields.extend_from_slice(&height.to_be_bytes());
            }
            BitcoinObservedEventV1::ClaimWitnessSeen { txid, wtxid }
            | BitcoinObservedEventV1::RefundSeen { txid, wtxid } => {
                fields.extend_from_slice(txid);
                fields.extend_from_slice(wtxid);
            }
            BitcoinObservedEventV1::ClaimConfirmed {
                evidence_ref,
                height,
            }
            | BitcoinObservedEventV1::RefundConfirmed {
                evidence_ref,
                height,
            } => {
                fields.extend_from_slice(evidence_ref);
                fields.extend_from_slice(&height.to_be_bytes());
            }
            BitcoinObservedEventV1::FundingConflict { expected, observed } => {
                fields.extend_from_slice(expected);
                fields.extend_from_slice(observed);
            }
            BitcoinObservedEventV1::ReorgInvalidated {
                from_height,
                old_tip,
                new_tip,
            } => {
                fields.extend_from_slice(&from_height.to_be_bytes());
                fields.extend_from_slice(old_tip);
                fields.extend_from_slice(new_tip);
            }
        }
        let mut h = Blake2bVar::new(32).expect("BLAKE2b-256 output size is valid"); // I14-ALLOW: fixed 32-byte output is always valid
        h.update(IDEMPOTENCY_DOMAIN);
        h.update(&[network.code() as u8]);
        h.update(&fields);
        let mut key = [0u8; 32];
        h.finalize_variable(&mut key)
            .expect("BLAKE2b-256 output size is valid"); // I14-ALLOW: fixed 32-byte output
        (key, fields)
    }

    /// Applies one observed event in a single durable transaction
    /// (M.10.3). Returns whether the event was newly applied or an
    /// idempotent redelivery. Same key + different bytes is terminal
    /// equivocation (M.10.4).
    pub fn apply_event(
        &mut self,
        cursor: &BitcoinChainCursorV1,
        event: &BitcoinObservedEventV1,
        new_tip: [u8; 32],
        new_height: u64,
        new_header_digest: [u8; 32],
    ) -> Result<ApplyOutcome, ObserverError> {
        let (key, bytes) = Self::idempotency_key(cursor.network, event);
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| ObserverError::StorageUnavailable)?;

        // Idempotency / equivocation check.
        let existing: Option<Vec<u8>> = tx
            .query_row(
                "SELECT event_bytes FROM btc_events WHERE idempotency_key = ?1",
                [&key[..]],
                |r| r.get(0),
            )
            .optional()
            .map_err(|_| ObserverError::StorageUnavailable)?;
        if let Some(stored) = existing {
            if stored == bytes {
                tx.commit().map_err(|_| ObserverError::StorageUnavailable)?;
                return Ok(ApplyOutcome::Duplicate);
            }
            return Err(ObserverError::Equivocation);
        }

        // Compare-and-swap the cursor revision.
        let current_rev: Option<i64> = tx
            .query_row(
                "SELECT revision FROM btc_cursors WHERE network_code = ?1",
                [cursor.network.code()],
                |r| r.get(0),
            )
            .optional()
            .map_err(|_| ObserverError::StorageUnavailable)?;
        let current_rev = current_rev.ok_or(ObserverError::NoCursor)?;
        if current_rev != cursor.revision as i64 {
            return Err(ObserverError::CursorConflict);
        }

        // Persist the event.
        tx.execute(
            "INSERT INTO btc_events
                 (idempotency_key, network_code, kind, anchor_height, valid, event_bytes)
                 VALUES (?1, ?2, ?3, ?4, 1, ?5)",
            rusqlite::params![
                &key[..],
                cursor.network.code(),
                i64::from(event.kind_code()),
                event.anchor_height().map(|h| h as i64),
                bytes,
            ],
        )
        .map_err(|_| ObserverError::StorageUnavailable)?;

        // Evidence refs.
        match event {
            BitcoinObservedEventV1::ClaimConfirmed {
                evidence_ref,
                height,
            }
            | BitcoinObservedEventV1::RefundConfirmed {
                evidence_ref,
                height,
            } => {
                tx.execute(
                    "INSERT OR IGNORE INTO btc_evidence_refs
                         (evidence_ref, network_code, height, valid) VALUES (?1, ?2, ?3, 1)",
                    rusqlite::params![&evidence_ref[..], cursor.network.code(), *height as i64],
                )
                .map_err(|_| ObserverError::StorageUnavailable)?;
            }
            _ => {}
        }

        // Reorg invalidation: void every observation and evidence ref at
        // or above the fork height (M.9.5, P12).
        if let BitcoinObservedEventV1::ReorgInvalidated { from_height, .. } = event {
            tx.execute(
                "UPDATE btc_events SET valid = 0
                     WHERE network_code = ?1 AND anchor_height IS NOT NULL
                       AND anchor_height >= ?2",
                rusqlite::params![cursor.network.code(), *from_height as i64],
            )
            .map_err(|_| ObserverError::StorageUnavailable)?;
            tx.execute(
                "UPDATE btc_evidence_refs SET valid = 0
                     WHERE network_code = ?1 AND height >= ?2",
                rusqlite::params![cursor.network.code(), *from_height as i64],
            )
            .map_err(|_| ObserverError::StorageUnavailable)?;
        }

        // Outbox (the final derived bytes to emit after commit).
        tx.execute("INSERT INTO btc_outbox (payload) VALUES (?1)", [&bytes[..]])
            .map_err(|_| ObserverError::StorageUnavailable)?;

        // Advance the cursor by CAS.
        let changed = tx
            .execute(
                "UPDATE btc_cursors
                     SET block_hash = ?1, height = ?2, header_chain_digest = ?3,
                         revision = revision + 1
                     WHERE network_code = ?4 AND revision = ?5",
                rusqlite::params![
                    &new_tip[..],
                    new_height as i64,
                    &new_header_digest[..],
                    cursor.network.code(),
                    cursor.revision as i64,
                ],
            )
            .map_err(|_| ObserverError::StorageUnavailable)?;
        if changed != 1 {
            return Err(ObserverError::CursorConflict);
        }

        tx.commit().map_err(|_| ObserverError::StorageUnavailable)?;
        Ok(ApplyOutcome::Applied)
    }

    /// Reads the current cursor for a network.
    pub fn cursor(&self, network: BitcoinNetworkV1) -> Result<BitcoinChainCursorV1, ObserverError> {
        let row: Option<(Vec<u8>, i64, Vec<u8>, i64)> = self
            .connection
            .query_row(
                "SELECT block_hash, height, header_chain_digest, revision
                     FROM btc_cursors WHERE network_code = ?1",
                [network.code()],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .optional()
            .map_err(|_| ObserverError::StorageUnavailable)?;
        let (bh, height, hcd, revision) = row.ok_or(ObserverError::NoCursor)?;
        Ok(BitcoinChainCursorV1 {
            network,
            block_hash: bh.try_into().map_err(|_| ObserverError::CorruptState)?,
            height: u64::try_from(height).map_err(|_| ObserverError::CorruptState)?,
            header_chain_digest: hcd.try_into().map_err(|_| ObserverError::CorruptState)?,
            revision: u64::try_from(revision).map_err(|_| ObserverError::CorruptState)?,
        })
    }

    /// Whether an evidence ref is currently valid (not reorged out).
    pub fn evidence_is_valid(&self, evidence_ref: &[u8; 32]) -> Result<bool, ObserverError> {
        let valid: Option<i64> = self
            .connection
            .query_row(
                "SELECT valid FROM btc_evidence_refs WHERE evidence_ref = ?1",
                [&evidence_ref[..]],
                |r| r.get(0),
            )
            .optional()
            .map_err(|_| ObserverError::StorageUnavailable)?;
        Ok(valid == Some(1))
    }

    /// Counts the currently-valid observations at or above a height (for
    /// tests: proves reorg invalidation, P12).
    pub fn valid_events_at_or_above(
        &self,
        network: BitcoinNetworkV1,
        height: u64,
    ) -> Result<u64, ObserverError> {
        let count: i64 = self
            .connection
            .query_row(
                "SELECT COUNT(*) FROM btc_events
                     WHERE network_code = ?1 AND valid = 1
                       AND anchor_height IS NOT NULL AND anchor_height >= ?2",
                rusqlite::params![network.code(), height as i64],
                |r| r.get(0),
            )
            .map_err(|_| ObserverError::StorageUnavailable)?;
        u64::try_from(count).map_err(|_| ObserverError::CorruptState)
    }
}
