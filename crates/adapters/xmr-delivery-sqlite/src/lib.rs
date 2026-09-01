//! SQLite exact-byte delivery store.

#![forbid(unsafe_code)]

use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use std::{path::Path, sync::Mutex};
use xmr_delivery::{fingerprint, DeliveryError, DeliveryRecord, DeliveryState, DeliveryStore};

/// One persisted delivery row as SQLite hands it back: the four BLOB columns
/// (terms hash, nonce, tx hash, raw transaction) and the state discriminant.
type DeliveryRow = (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, i64);

/// SQLite store.
pub struct SqliteDeliveryStore {
    connection: Mutex<Connection>,
}

impl core::fmt::Debug for SqliteDeliveryStore {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SqliteDeliveryStore")
            .finish_non_exhaustive()
    }
}

impl SqliteDeliveryStore {
    /// Opens/creates the durable table with WAL and FULL synchronization.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, DeliveryError> {
        let connection = Connection::open(path).map_err(|_| DeliveryError::StorageUnavailable)?;
        connection
            .execute_batch(
                "PRAGMA journal_mode=WAL;
             PRAGMA synchronous=FULL;
             CREATE TABLE IF NOT EXISTS xmr_delivery_v2(
               settlement_id BLOB PRIMARY KEY NOT NULL CHECK(length(settlement_id)=32),
               source_effect_id BLOB NOT NULL CHECK(length(source_effect_id)=32),
               tx_hash BLOB NOT NULL CHECK(length(tx_hash)=32),
               raw_fingerprint BLOB NOT NULL CHECK(length(raw_fingerprint)=32),
               raw_tx BLOB NOT NULL,
               state INTEGER NOT NULL CHECK(state IN (0,1,2))
             );",
            )
            .map_err(|_| DeliveryError::StorageUnavailable)?;
        Ok(Self {
            connection: Mutex::new(connection),
        })
    }

    fn transition(
        &self,
        settlement_id: &[u8; 32],
        target: DeliveryState,
    ) -> Result<(), DeliveryError> {
        let mut connection = self
            .connection
            .lock()
            .map_err(|_| DeliveryError::StorageUnavailable)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| DeliveryError::StorageUnavailable)?;
        let current: Option<i64> = transaction
            .query_row(
                "SELECT state FROM xmr_delivery_v2 WHERE settlement_id=?1",
                params![settlement_id.as_slice()],
                |row| row.get(0),
            )
            .optional()
            .map_err(|_| DeliveryError::StorageUnavailable)?;
        let current = current.ok_or(DeliveryError::NotFound)?;
        let target = encode_state(target);
        if target < current {
            return Err(DeliveryError::Corrupt);
        }
        transaction
            .execute(
                "UPDATE xmr_delivery_v2 SET state=?2 WHERE settlement_id=?1",
                params![settlement_id.as_slice(), target],
            )
            .map_err(|_| DeliveryError::StorageUnavailable)?;
        transaction
            .commit()
            .map_err(|_| DeliveryError::StorageUnavailable)
    }
}

impl DeliveryStore for SqliteDeliveryStore {
    fn load(&self, settlement_id: &[u8; 32]) -> Result<Option<DeliveryRecord>, DeliveryError> {
        let connection = self
            .connection
            .lock()
            .map_err(|_| DeliveryError::StorageUnavailable)?;
        let row: Option<DeliveryRow> = connection
            .query_row(
                "SELECT source_effect_id,tx_hash,raw_fingerprint,raw_tx,state
             FROM xmr_delivery_v2 WHERE settlement_id=?1",
                params![settlement_id.as_slice()],
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
            .optional()
            .map_err(|_| DeliveryError::StorageUnavailable)?;
        row.map(|(effect, tx_hash, stored_fingerprint, raw_tx, state)| {
            let source_effect_id: [u8; 32] =
                effect.try_into().map_err(|_| DeliveryError::Corrupt)?;
            let tx_hash: [u8; 32] = tx_hash.try_into().map_err(|_| DeliveryError::Corrupt)?;
            let raw_fingerprint: [u8; 32] = stored_fingerprint
                .try_into()
                .map_err(|_| DeliveryError::Corrupt)?;
            if raw_tx.is_empty()
                || raw_tx.len() > xmr_delivery::MAX_RAW_TRANSACTION_BYTES
                || fingerprint(&raw_tx) != raw_fingerprint
            {
                return Err(DeliveryError::Corrupt);
            }
            Ok(DeliveryRecord {
                settlement_id: *settlement_id,
                source_effect_id,
                tx_hash,
                raw_fingerprint,
                raw_tx,
                state: decode_state(state)?,
            })
        })
        .transpose()
    }

    fn prepare_exact(
        &self,
        settlement_id: [u8; 32],
        source_effect_id: [u8; 32],
        tx_hash: [u8; 32],
        raw_tx: &[u8],
    ) -> Result<DeliveryRecord, DeliveryError> {
        if settlement_id == [0; 32]
            || source_effect_id == [0; 32]
            || tx_hash == [0; 32]
            || raw_tx.is_empty()
        {
            return Err(DeliveryError::InvalidTransaction);
        }
        if raw_tx.len() > xmr_delivery::MAX_RAW_TRANSACTION_BYTES {
            return Err(DeliveryError::BoundsExceeded);
        }
        let raw_fingerprint = fingerprint(raw_tx);
        let mut connection = self
            .connection
            .lock()
            .map_err(|_| DeliveryError::StorageUnavailable)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| DeliveryError::StorageUnavailable)?;
        let existing: Option<DeliveryRow> = transaction
            .query_row(
                "SELECT source_effect_id,tx_hash,raw_fingerprint,raw_tx,state
             FROM xmr_delivery_v2 WHERE settlement_id=?1",
                params![settlement_id.as_slice()],
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
            .optional()
            .map_err(|_| DeliveryError::StorageUnavailable)?;
        if let Some((effect, existing_hash, existing_fp, existing_raw, state)) = existing {
            let effect: [u8; 32] = effect.try_into().map_err(|_| DeliveryError::Corrupt)?;
            let existing_hash: [u8; 32] = existing_hash
                .try_into()
                .map_err(|_| DeliveryError::Corrupt)?;
            let existing_fp: [u8; 32] =
                existing_fp.try_into().map_err(|_| DeliveryError::Corrupt)?;
            if effect != source_effect_id
                || existing_hash != tx_hash
                || existing_fp != raw_fingerprint
                || existing_raw != raw_tx
            {
                return Err(DeliveryError::ConflictingRetransmission);
            }
            transaction
                .commit()
                .map_err(|_| DeliveryError::StorageUnavailable)?;
            return Ok(DeliveryRecord {
                settlement_id,
                source_effect_id,
                tx_hash,
                raw_fingerprint,
                raw_tx: existing_raw,
                state: decode_state(state)?,
            });
        }
        transaction
            .execute(
                "INSERT INTO xmr_delivery_v2(
               settlement_id,source_effect_id,tx_hash,raw_fingerprint,raw_tx,state
             ) VALUES(?1,?2,?3,?4,?5,0)",
                params![
                    settlement_id.as_slice(),
                    source_effect_id.as_slice(),
                    tx_hash.as_slice(),
                    raw_fingerprint.as_slice(),
                    raw_tx,
                ],
            )
            .map_err(|_| DeliveryError::StorageUnavailable)?;
        transaction
            .commit()
            .map_err(|_| DeliveryError::StorageUnavailable)?;
        Ok(DeliveryRecord {
            settlement_id,
            source_effect_id,
            tx_hash,
            raw_fingerprint,
            raw_tx: raw_tx.to_vec(),
            state: DeliveryState::Prepared,
        })
    }

    fn mark_submitted(&self, settlement_id: &[u8; 32]) -> Result<(), DeliveryError> {
        self.transition(settlement_id, DeliveryState::Submitted)
    }

    fn mark_confirmed(&self, settlement_id: &[u8; 32]) -> Result<(), DeliveryError> {
        self.transition(settlement_id, DeliveryState::Confirmed)
    }
}

fn encode_state(state: DeliveryState) -> i64 {
    match state {
        DeliveryState::Prepared => 0,
        DeliveryState::Submitted => 1,
        DeliveryState::Confirmed => 2,
    }
}

fn decode_state(value: i64) -> Result<DeliveryState, DeliveryError> {
    match value {
        0 => Ok(DeliveryState::Prepared),
        1 => Ok(DeliveryState::Submitted),
        2 => Ok(DeliveryState::Confirmed),
        _ => Err(DeliveryError::Corrupt),
    }
}
