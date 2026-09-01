//! SQLite exact signed Solana transaction delivery store.

#![forbid(unsafe_code)]

use std::{path::Path, sync::Mutex};

use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use solana_delivery::{
    fingerprint, DeliveryError, DeliveryRecord, DeliveryState, DeliveryStore,
    MAX_SIGNED_TRANSACTION_BYTES,
};
use solana_types::SolanaSignature;

/// Durable delivery store.
pub struct SqliteSolanaDeliveryStore {
    connection: Mutex<Connection>,
}

impl core::fmt::Debug for SqliteSolanaDeliveryStore {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SqliteSolanaDeliveryStore")
            .finish_non_exhaustive()
    }
}

impl SqliteSolanaDeliveryStore {
    /// Open/create the store.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, DeliveryError> {
        let connection = Connection::open(path).map_err(|_| DeliveryError::StorageUnavailable)?;
        connection
            .execute_batch(
                "PRAGMA journal_mode=WAL;
                 PRAGMA synchronous=FULL;
                 CREATE TABLE IF NOT EXISTS solana_delivery_v1(
                   settlement_id BLOB PRIMARY KEY NOT NULL CHECK(length(settlement_id)=32),
                   source_operation_id BLOB NOT NULL CHECK(length(source_operation_id)=32),
                   signature BLOB NOT NULL CHECK(length(signature)=64),
                   raw_fingerprint BLOB NOT NULL CHECK(length(raw_fingerprint)=32),
                   raw_transaction BLOB NOT NULL,
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
                "SELECT state FROM solana_delivery_v1 WHERE settlement_id=?1",
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
                "UPDATE solana_delivery_v1 SET state=?2 WHERE settlement_id=?1",
                params![settlement_id.as_slice(), target],
            )
            .map_err(|_| DeliveryError::StorageUnavailable)?;
        transaction
            .commit()
            .map_err(|_| DeliveryError::StorageUnavailable)
    }
}

/// One raw `solana_delivery_v1` row: the four blobs plus the state column, in
/// SELECT order. Named because both the load and the persist path read it and
/// `clippy::type_complexity` refuses the anonymous tuple.
type DeliveryRow = (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, i64);

impl DeliveryStore for SqliteSolanaDeliveryStore {
    fn load(&self, settlement_id: &[u8; 32]) -> Result<Option<DeliveryRecord>, DeliveryError> {
        let connection = self
            .connection
            .lock()
            .map_err(|_| DeliveryError::StorageUnavailable)?;
        let row: Option<DeliveryRow> = connection
            .query_row(
                "SELECT source_operation_id,signature,raw_fingerprint,raw_transaction,state
                 FROM solana_delivery_v1 WHERE settlement_id=?1",
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
        row.map(
            |(operation, signature, stored_fingerprint, raw_transaction, state)| {
                let source_operation_id: [u8; 32] =
                    operation.try_into().map_err(|_| DeliveryError::Corrupt)?;
                let signature: [u8; 64] =
                    signature.try_into().map_err(|_| DeliveryError::Corrupt)?;
                let raw_fingerprint: [u8; 32] = stored_fingerprint
                    .try_into()
                    .map_err(|_| DeliveryError::Corrupt)?;
                if raw_transaction.is_empty()
                    || raw_transaction.len() > MAX_SIGNED_TRANSACTION_BYTES
                    || fingerprint(&raw_transaction) != raw_fingerprint
                {
                    return Err(DeliveryError::Corrupt);
                }
                Ok(DeliveryRecord {
                    settlement_id: *settlement_id,
                    source_operation_id,
                    signature: SolanaSignature(signature),
                    raw_fingerprint,
                    raw_transaction,
                    state: decode_state(state)?,
                })
            },
        )
        .transpose()
    }

    fn prepare_exact(
        &self,
        settlement_id: [u8; 32],
        source_operation_id: [u8; 32],
        signature: SolanaSignature,
        raw_transaction: &[u8],
    ) -> Result<DeliveryRecord, DeliveryError> {
        if settlement_id == [0; 32]
            || source_operation_id == [0; 32]
            || signature.0 == [0; 64]
            || raw_transaction.is_empty()
        {
            return Err(DeliveryError::Invalid);
        }
        if raw_transaction.len() > MAX_SIGNED_TRANSACTION_BYTES {
            return Err(DeliveryError::BoundsExceeded);
        }
        let raw_fingerprint = fingerprint(raw_transaction);
        let mut connection = self
            .connection
            .lock()
            .map_err(|_| DeliveryError::StorageUnavailable)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| DeliveryError::StorageUnavailable)?;
        let existing: Option<DeliveryRow> = transaction
            .query_row(
                "SELECT source_operation_id,signature,raw_fingerprint,raw_transaction,state
                 FROM solana_delivery_v1 WHERE settlement_id=?1",
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
        if let Some((operation, stored_signature, stored_fingerprint, stored_raw, state)) = existing
        {
            let operation: [u8; 32] = operation.try_into().map_err(|_| DeliveryError::Corrupt)?;
            let stored_signature: [u8; 64] = stored_signature
                .try_into()
                .map_err(|_| DeliveryError::Corrupt)?;
            let stored_fingerprint: [u8; 32] = stored_fingerprint
                .try_into()
                .map_err(|_| DeliveryError::Corrupt)?;
            if operation != source_operation_id
                || stored_signature != signature.0
                || stored_fingerprint != raw_fingerprint
                || stored_raw != raw_transaction
            {
                return Err(DeliveryError::ConflictingRetransmission);
            }
            transaction
                .commit()
                .map_err(|_| DeliveryError::StorageUnavailable)?;
            return Ok(DeliveryRecord {
                settlement_id,
                source_operation_id,
                signature,
                raw_fingerprint,
                raw_transaction: stored_raw,
                state: decode_state(state)?,
            });
        }
        transaction
            .execute(
                "INSERT INTO solana_delivery_v1(
                   settlement_id,source_operation_id,signature,
                   raw_fingerprint,raw_transaction,state
                 ) VALUES(?1,?2,?3,?4,?5,0)",
                params![
                    settlement_id.as_slice(),
                    source_operation_id.as_slice(),
                    signature.0.as_slice(),
                    raw_fingerprint.as_slice(),
                    raw_transaction,
                ],
            )
            .map_err(|_| DeliveryError::StorageUnavailable)?;
        transaction
            .commit()
            .map_err(|_| DeliveryError::StorageUnavailable)?;
        Ok(DeliveryRecord {
            settlement_id,
            source_operation_id,
            signature,
            raw_fingerprint,
            raw_transaction: raw_transaction.to_vec(),
            state: DeliveryState::Prepared,
        })
    }

    fn mark_submitted(&self, settlement_id: &[u8; 32]) -> Result<(), DeliveryError> {
        self.transition(settlement_id, DeliveryState::Submitted)
    }

    fn mark_finalized(&self, settlement_id: &[u8; 32]) -> Result<(), DeliveryError> {
        self.transition(settlement_id, DeliveryState::Finalized)
    }
}

fn encode_state(state: DeliveryState) -> i64 {
    match state {
        DeliveryState::Prepared => 0,
        DeliveryState::Submitted => 1,
        DeliveryState::Finalized => 2,
    }
}

fn decode_state(value: i64) -> Result<DeliveryState, DeliveryError> {
    match value {
        0 => Ok(DeliveryState::Prepared),
        1 => Ok(DeliveryState::Submitted),
        2 => Ok(DeliveryState::Finalized),
        _ => Err(DeliveryError::Corrupt),
    }
}
