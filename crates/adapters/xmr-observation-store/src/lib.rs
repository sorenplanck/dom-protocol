//! SQLite canonical-header and verified-event store for the XMR chain source.

#![forbid(unsafe_code)]

use kaystra_core::{state::EvidenceRefV1, types::ChainId};
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use std::{path::Path, sync::Mutex};
use xmr_kaystra_source::{
    VerifiedFeedError, VerifiedXmrEvent, VerifiedXmrEventKind, VerifiedXmrFeed, XmrBlockAnchor,
};

/// Store mutation failures.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ObservationStoreError {
    /// Database unavailable.
    #[error("XMR observation store unavailable")]
    Unavailable,
    /// A row conflicts with already-verified data.
    #[error("conflicting XMR observation")]
    Conflict,
    /// Input is malformed or outside SQLite integer bounds.
    #[error("invalid XMR observation")]
    Invalid,
}

/// Durable feed bound to one chain, settlement, and terms hash.
pub struct SqliteVerifiedXmrFeed {
    connection: Mutex<Connection>,
    chain_id: ChainId,
    settlement_id: [u8; 32],
    terms_hash: [u8; 32],
}

impl core::fmt::Debug for SqliteVerifiedXmrFeed {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("SqliteVerifiedXmrFeed")
            .field("chain_id", &self.chain_id)
            .field("settlement_id", &"<public-id>")
            .finish_non_exhaustive()
    }
}

impl SqliteVerifiedXmrFeed {
    /// Opens or creates the store.
    pub fn open(
        path: impl AsRef<Path>,
        chain_id: ChainId,
        settlement_id: [u8; 32],
        terms_hash: [u8; 32],
    ) -> Result<Self, ObservationStoreError> {
        if chain_id.0 == [0; 32] || settlement_id == [0; 32] || terms_hash == [0; 32] {
            return Err(ObservationStoreError::Invalid);
        }
        let connection = Connection::open(path).map_err(|_| ObservationStoreError::Unavailable)?;
        connection
            .execute_batch(
                "PRAGMA journal_mode=WAL;
             PRAGMA synchronous=FULL;
             CREATE TABLE IF NOT EXISTS xmr_canonical_blocks_v2(
               chain_id BLOB NOT NULL CHECK(length(chain_id)=32),
               height INTEGER NOT NULL CHECK(height>=0),
               block_hash BLOB NOT NULL CHECK(length(block_hash)=32),
               PRIMARY KEY(chain_id,height)
             );
             CREATE TABLE IF NOT EXISTS xmr_verified_events_v2(
               chain_id BLOB NOT NULL CHECK(length(chain_id)=32),
               settlement_id BLOB NOT NULL CHECK(length(settlement_id)=32),
               terms_hash BLOB NOT NULL CHECK(length(terms_hash)=32),
               kind INTEGER NOT NULL CHECK(kind IN (1,2,3)),
               tx_id BLOB NOT NULL CHECK(length(tx_id)=32),
               event_index INTEGER NOT NULL CHECK(event_index>=0),
               block_height INTEGER NOT NULL CHECK(block_height>=0),
               block_anchor BLOB NOT NULL CHECK(length(block_anchor)=32),
               PRIMARY KEY(settlement_id,kind,tx_id,event_index)
             );",
            )
            .map_err(|_| ObservationStoreError::Unavailable)?;
        Ok(Self {
            connection: Mutex::new(connection),
            chain_id,
            settlement_id,
            terms_hash,
        })
    }

    /// Replaces the canonical suffix atomically, deleting orphaned events.
    pub fn replace_canonical_suffix(
        &self,
        from_height: u64,
        blocks: &[XmrBlockAnchor],
    ) -> Result<(), ObservationStoreError> {
        let from = to_i64(from_height)?;
        if blocks.is_empty()
            || blocks[0].height != from_height
            || blocks
                .windows(2)
                .any(|pair| pair[1].height != pair[0].height + 1)
            || blocks.iter().any(|block| block.hash == [0; 32])
        {
            return Err(ObservationStoreError::Invalid);
        }
        let mut connection = self
            .connection
            .lock()
            .map_err(|_| ObservationStoreError::Unavailable)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| ObservationStoreError::Unavailable)?;
        transaction
            .execute(
                "DELETE FROM xmr_verified_events_v2 WHERE chain_id=?1 AND block_height>=?2",
                params![self.chain_id.0.as_slice(), from],
            )
            .map_err(|_| ObservationStoreError::Unavailable)?;
        transaction
            .execute(
                "DELETE FROM xmr_canonical_blocks_v2 WHERE chain_id=?1 AND height>=?2",
                params![self.chain_id.0.as_slice(), from],
            )
            .map_err(|_| ObservationStoreError::Unavailable)?;
        for block in blocks {
            transaction.execute(
                "INSERT INTO xmr_canonical_blocks_v2(chain_id,height,block_hash) VALUES(?1,?2,?3)",
                params![self.chain_id.0.as_slice(), to_i64(block.height)?, block.hash.as_slice()],
            ).map_err(|_| ObservationStoreError::Unavailable)?;
        }
        transaction
            .commit()
            .map_err(|_| ObservationStoreError::Unavailable)
    }

    /// Inserts an exact verified event idempotently.
    pub fn insert_event(&self, event: &VerifiedXmrEvent) -> Result<(), ObservationStoreError> {
        if event.settlement_id != self.settlement_id
            || event.terms_hash != self.terms_hash
            || event.evidence.chain_id != self.chain_id
            || event.evidence.tx_id == [0; 32]
            || event.evidence.block_anchor == [0; 32]
        {
            return Err(ObservationStoreError::Invalid);
        }
        let connection = self
            .connection
            .lock()
            .map_err(|_| ObservationStoreError::Unavailable)?;
        let canonical: Option<Vec<u8>> = connection
            .query_row(
                "SELECT block_hash FROM xmr_canonical_blocks_v2 WHERE chain_id=?1 AND height=?2",
                params![
                    self.chain_id.0.as_slice(),
                    to_i64(event.evidence.block_height)?
                ],
                |row| row.get(0),
            )
            .optional()
            .map_err(|_| ObservationStoreError::Unavailable)?;
        if canonical.as_deref() != Some(event.evidence.block_anchor.as_slice()) {
            return Err(ObservationStoreError::Conflict);
        }
        let existing: Option<(Vec<u8>, Vec<u8>, i64)> = connection
            .query_row(
                "SELECT terms_hash,block_anchor,block_height FROM xmr_verified_events_v2
             WHERE settlement_id=?1 AND kind=?2 AND tx_id=?3 AND event_index=?4",
                params![
                    self.settlement_id.as_slice(),
                    event.kind as u8,
                    event.evidence.tx_id.as_slice(),
                    i64::from(event.evidence.event_index),
                ],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()
            .map_err(|_| ObservationStoreError::Unavailable)?;
        if let Some((terms, anchor, height)) = existing {
            if terms.as_slice() != self.terms_hash
                || anchor.as_slice() != event.evidence.block_anchor
                || height != to_i64(event.evidence.block_height)?
            {
                return Err(ObservationStoreError::Conflict);
            }
            return Ok(());
        }
        connection
            .execute(
                "INSERT INTO xmr_verified_events_v2(
               chain_id,settlement_id,terms_hash,kind,tx_id,event_index,block_height,block_anchor
             ) VALUES(?1,?2,?3,?4,?5,?6,?7,?8)",
                params![
                    self.chain_id.0.as_slice(),
                    self.settlement_id.as_slice(),
                    self.terms_hash.as_slice(),
                    event.kind as u8,
                    event.evidence.tx_id.as_slice(),
                    i64::from(event.evidence.event_index),
                    to_i64(event.evidence.block_height)?,
                    event.evidence.block_anchor.as_slice(),
                ],
            )
            .map_err(|_| ObservationStoreError::Unavailable)?;
        Ok(())
    }
}

impl VerifiedXmrFeed for SqliteVerifiedXmrFeed {
    fn chain_id(&self) -> ChainId {
        self.chain_id
    }

    fn tip(&self) -> Result<Option<XmrBlockAnchor>, VerifiedFeedError> {
        let connection = self
            .connection
            .lock()
            .map_err(|_| VerifiedFeedError::Unavailable)?;
        let row: Option<(i64, Vec<u8>)> = connection
            .query_row(
                "SELECT height,block_hash FROM xmr_canonical_blocks_v2
             WHERE chain_id=?1 ORDER BY height DESC LIMIT 1",
                params![self.chain_id.0.as_slice()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(|_| VerifiedFeedError::Unavailable)?;
        row.map(|(height, hash)| {
            Ok(XmrBlockAnchor {
                height: from_i64(height)?,
                hash: vec32(hash)?,
            })
        })
        .transpose()
    }

    fn block_hash(&self, height: u64) -> Result<Option<[u8; 32]>, VerifiedFeedError> {
        let connection = self
            .connection
            .lock()
            .map_err(|_| VerifiedFeedError::Unavailable)?;
        let row: Option<Vec<u8>> = connection
            .query_row(
                "SELECT block_hash FROM xmr_canonical_blocks_v2 WHERE chain_id=?1 AND height=?2",
                params![self.chain_id.0.as_slice(), to_i64_feed(height)?],
                |row| row.get(0),
            )
            .optional()
            .map_err(|_| VerifiedFeedError::Unavailable)?;
        row.map(vec32).transpose()
    }

    fn events(
        &self,
        from_height: u64,
        to_height: u64,
    ) -> Result<Vec<VerifiedXmrEvent>, VerifiedFeedError> {
        if from_height > to_height {
            return Err(VerifiedFeedError::InvalidEvidence);
        }
        let connection = self
            .connection
            .lock()
            .map_err(|_| VerifiedFeedError::Unavailable)?;
        let mut statement = connection
            .prepare(
                "SELECT kind,tx_id,event_index,block_height,block_anchor
             FROM xmr_verified_events_v2
             WHERE chain_id=?1 AND settlement_id=?2 AND terms_hash=?3
               AND block_height>=?4 AND block_height<=?5
             ORDER BY block_height ASC,kind ASC,tx_id ASC,event_index ASC",
            )
            .map_err(|_| VerifiedFeedError::Unavailable)?;
        let rows = statement
            .query_map(
                params![
                    self.chain_id.0.as_slice(),
                    self.settlement_id.as_slice(),
                    self.terms_hash.as_slice(),
                    to_i64_feed(from_height)?,
                    to_i64_feed(to_height)?,
                ],
                |row| {
                    let kind: u8 = row.get(0)?;
                    let tx_id: Vec<u8> = row.get(1)?;
                    let event_index: i64 = row.get(2)?;
                    let block_height: i64 = row.get(3)?;
                    let block_anchor: Vec<u8> = row.get(4)?;
                    Ok((kind, tx_id, event_index, block_height, block_anchor))
                },
            )
            .map_err(|_| VerifiedFeedError::Unavailable)?;
        let mut output = Vec::new();
        for row in rows {
            let (kind, tx_id, event_index, block_height, block_anchor) =
                row.map_err(|_| VerifiedFeedError::Unavailable)?;
            output.push(VerifiedXmrEvent {
                settlement_id: self.settlement_id,
                terms_hash: self.terms_hash,
                kind: VerifiedXmrEventKind::from_code(kind)
                    .ok_or(VerifiedFeedError::InvalidEvidence)?,
                evidence: EvidenceRefV1 {
                    chain_id: self.chain_id,
                    tx_id: vec32(tx_id)?,
                    event_index: u32::try_from(event_index)
                        .map_err(|_| VerifiedFeedError::InvalidEvidence)?,
                    block_height: from_i64(block_height)?,
                    block_anchor: vec32(block_anchor)?,
                },
            });
        }
        Ok(output)
    }
}

fn to_i64(value: u64) -> Result<i64, ObservationStoreError> {
    i64::try_from(value).map_err(|_| ObservationStoreError::Invalid)
}
fn to_i64_feed(value: u64) -> Result<i64, VerifiedFeedError> {
    i64::try_from(value).map_err(|_| VerifiedFeedError::BoundsExceeded)
}
fn from_i64(value: i64) -> Result<u64, VerifiedFeedError> {
    u64::try_from(value).map_err(|_| VerifiedFeedError::InvalidEvidence)
}
fn vec32(value: Vec<u8>) -> Result<[u8; 32], VerifiedFeedError> {
    let fixed: [u8; 32] = value
        .try_into()
        .map_err(|_| VerifiedFeedError::InvalidEvidence)?;
    if fixed == [0; 32] {
        Err(VerifiedFeedError::InvalidEvidence)
    } else {
        Ok(fixed)
    }
}
