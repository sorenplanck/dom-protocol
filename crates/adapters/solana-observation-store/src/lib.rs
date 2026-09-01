//! SQLite-backed finalized Solana slots and verified settlement events.

#![forbid(unsafe_code)]

use std::{path::Path, sync::Mutex};

use kaystra_core::{state::EvidenceRefV1, types::ChainId};
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use solana_kaystra_source::{
    SolanaSlotAnchor, VerifiedFeedError, VerifiedSolanaEvent, VerifiedSolanaEventKind,
    VerifiedSolanaFeed,
};

/// Observation-store error.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ObservationStoreError {
    /// Database unavailable.
    #[error("Solana observation store unavailable")]
    Unavailable,
    /// Invalid value.
    #[error("invalid Solana observation")]
    Invalid,
    /// Existing row conflicts with supplied canonical value.
    #[error("conflicting Solana observation")]
    Conflict,
}

/// Durable verified feed for exactly one settlement.
pub struct SqliteVerifiedSolanaFeed {
    connection: Mutex<Connection>,
    chain_id: ChainId,
    settlement_id: [u8; 32],
    terms_hash: [u8; 32],
}

impl core::fmt::Debug for SqliteVerifiedSolanaFeed {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SqliteVerifiedSolanaFeed")
            .field("chain_id", &self.chain_id)
            .field("settlement_id", &"<public-id>")
            .finish_non_exhaustive()
    }
}

impl SqliteVerifiedSolanaFeed {
    /// Open/create the store.
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
                 CREATE TABLE IF NOT EXISTS solana_scan_tip_v1(
                   chain_id BLOB PRIMARY KEY NOT NULL CHECK(length(chain_id)=32),
                   finalized_slot INTEGER NOT NULL CHECK(finalized_slot>=0)
                 );
                 CREATE TABLE IF NOT EXISTS solana_canonical_slots_v1(
                   chain_id BLOB NOT NULL CHECK(length(chain_id)=32),
                   slot INTEGER NOT NULL CHECK(slot>=0),
                   blockhash BLOB NOT NULL CHECK(length(blockhash)=32),
                   PRIMARY KEY(chain_id,slot)
                 );
                 CREATE TABLE IF NOT EXISTS solana_verified_events_v1(
                   chain_id BLOB NOT NULL CHECK(length(chain_id)=32),
                   settlement_id BLOB NOT NULL CHECK(length(settlement_id)=32),
                   terms_hash BLOB NOT NULL CHECK(length(terms_hash)=32),
                   kind INTEGER NOT NULL CHECK(kind IN (1,2,3)),
                   tx_id BLOB NOT NULL CHECK(length(tx_id)=32),
                   instruction_index INTEGER NOT NULL CHECK(instruction_index>=0),
                   slot INTEGER NOT NULL CHECK(slot>=0),
                   blockhash BLOB NOT NULL CHECK(length(blockhash)=32),
                   PRIMARY KEY(settlement_id,kind,tx_id,instruction_index)
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

    /// Replace a finalized canonical suffix and delete orphaned events atomically.
    pub fn replace_canonical_suffix(
        &self,
        from_slot: u64,
        finalized_through_slot: u64,
        anchors: &[SolanaSlotAnchor],
    ) -> Result<(), ObservationStoreError> {
        if finalized_through_slot < from_slot {
            return Err(ObservationStoreError::Invalid);
        }
        validate_anchors(anchors, from_slot, finalized_through_slot)?;
        let mut connection = self
            .connection
            .lock()
            .map_err(|_| ObservationStoreError::Unavailable)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| ObservationStoreError::Unavailable)?;
        transaction
            .execute(
                "DELETE FROM solana_verified_events_v1
                 WHERE chain_id=?1 AND slot>=?2",
                params![self.chain_id.0.as_slice(), to_i64(from_slot)?],
            )
            .map_err(|_| ObservationStoreError::Unavailable)?;
        transaction
            .execute(
                "DELETE FROM solana_canonical_slots_v1
                 WHERE chain_id=?1 AND slot>=?2",
                params![self.chain_id.0.as_slice(), to_i64(from_slot)?],
            )
            .map_err(|_| ObservationStoreError::Unavailable)?;
        for anchor in anchors {
            transaction
                .execute(
                    "INSERT INTO solana_canonical_slots_v1(chain_id,slot,blockhash)
                     VALUES(?1,?2,?3)",
                    params![
                        self.chain_id.0.as_slice(),
                        to_i64(anchor.slot)?,
                        anchor.blockhash.as_slice(),
                    ],
                )
                .map_err(|_| ObservationStoreError::Unavailable)?;
        }
        transaction
            .execute(
                "INSERT INTO solana_scan_tip_v1(chain_id,finalized_slot)
                 VALUES(?1,?2)
                 ON CONFLICT(chain_id) DO UPDATE SET finalized_slot=excluded.finalized_slot",
                params![self.chain_id.0.as_slice(), to_i64(finalized_through_slot)?,],
            )
            .map_err(|_| ObservationStoreError::Unavailable)?;
        transaction
            .commit()
            .map_err(|_| ObservationStoreError::Unavailable)
    }

    /// Insert an exact verified event idempotently.
    pub fn insert_event(&self, event: &VerifiedSolanaEvent) -> Result<(), ObservationStoreError> {
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
                "SELECT blockhash FROM solana_canonical_slots_v1
                 WHERE chain_id=?1 AND slot=?2",
                params![
                    self.chain_id.0.as_slice(),
                    to_i64(event.evidence.block_height)?,
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
                "SELECT terms_hash,blockhash,slot FROM solana_verified_events_v1
                 WHERE settlement_id=?1 AND kind=?2 AND tx_id=?3 AND instruction_index=?4",
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
        if let Some((terms, blockhash, slot)) = existing {
            if terms.as_slice() != self.terms_hash
                || blockhash.as_slice() != event.evidence.block_anchor
                || slot != to_i64(event.evidence.block_height)?
            {
                return Err(ObservationStoreError::Conflict);
            }
            return Ok(());
        }
        connection
            .execute(
                "INSERT INTO solana_verified_events_v1(
                   chain_id,settlement_id,terms_hash,kind,tx_id,
                   instruction_index,slot,blockhash
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

impl VerifiedSolanaFeed for SqliteVerifiedSolanaFeed {
    fn chain_id(&self) -> ChainId {
        self.chain_id
    }

    fn tip(&self) -> Result<Option<u64>, VerifiedFeedError> {
        let connection = self
            .connection
            .lock()
            .map_err(|_| VerifiedFeedError::Unavailable)?;
        let slot: Option<i64> = connection
            .query_row(
                "SELECT finalized_slot FROM solana_scan_tip_v1 WHERE chain_id=?1",
                params![self.chain_id.0.as_slice()],
                |row| row.get(0),
            )
            .optional()
            .map_err(|_| VerifiedFeedError::Unavailable)?;
        slot.map(from_i64).transpose()
    }

    fn block_hash(&self, slot: u64) -> Result<Option<[u8; 32]>, VerifiedFeedError> {
        let connection = self
            .connection
            .lock()
            .map_err(|_| VerifiedFeedError::Unavailable)?;
        let row: Option<Vec<u8>> = connection
            .query_row(
                "SELECT blockhash FROM solana_canonical_slots_v1
                 WHERE chain_id=?1 AND slot=?2",
                params![self.chain_id.0.as_slice(), to_i64_feed(slot)?],
                |row| row.get(0),
            )
            .optional()
            .map_err(|_| VerifiedFeedError::Unavailable)?;
        row.map(vec32).transpose()
    }

    fn anchors(
        &self,
        from_slot: u64,
        to_slot: u64,
    ) -> Result<Vec<SolanaSlotAnchor>, VerifiedFeedError> {
        if from_slot > to_slot {
            return Err(VerifiedFeedError::InvalidEvidence);
        }
        let connection = self
            .connection
            .lock()
            .map_err(|_| VerifiedFeedError::Unavailable)?;
        let mut statement = connection
            .prepare(
                "SELECT slot,blockhash FROM solana_canonical_slots_v1
                 WHERE chain_id=?1 AND slot>=?2 AND slot<=?3 ORDER BY slot ASC",
            )
            .map_err(|_| VerifiedFeedError::Unavailable)?;
        let rows = statement
            .query_map(
                params![
                    self.chain_id.0.as_slice(),
                    to_i64_feed(from_slot)?,
                    to_i64_feed(to_slot)?,
                ],
                |row| Ok((row.get::<_, i64>(0)?, row.get::<_, Vec<u8>>(1)?)),
            )
            .map_err(|_| VerifiedFeedError::Unavailable)?;
        let mut output = Vec::new();
        for row in rows {
            let (slot, blockhash) = row.map_err(|_| VerifiedFeedError::Unavailable)?;
            output.push(SolanaSlotAnchor {
                slot: from_i64(slot)?,
                blockhash: vec32(blockhash)?,
            });
        }
        Ok(output)
    }

    fn events(
        &self,
        from_slot: u64,
        to_slot: u64,
    ) -> Result<Vec<VerifiedSolanaEvent>, VerifiedFeedError> {
        if from_slot > to_slot {
            return Err(VerifiedFeedError::InvalidEvidence);
        }
        let connection = self
            .connection
            .lock()
            .map_err(|_| VerifiedFeedError::Unavailable)?;
        let mut statement = connection
            .prepare(
                "SELECT kind,tx_id,instruction_index,slot,blockhash
                 FROM solana_verified_events_v1
                 WHERE chain_id=?1 AND settlement_id=?2 AND terms_hash=?3
                   AND slot>=?4 AND slot<=?5
                 ORDER BY slot ASC,kind ASC,tx_id ASC,instruction_index ASC",
            )
            .map_err(|_| VerifiedFeedError::Unavailable)?;
        let rows = statement
            .query_map(
                params![
                    self.chain_id.0.as_slice(),
                    self.settlement_id.as_slice(),
                    self.terms_hash.as_slice(),
                    to_i64_feed(from_slot)?,
                    to_i64_feed(to_slot)?,
                ],
                |row| {
                    Ok((
                        row.get::<_, u8>(0)?,
                        row.get::<_, Vec<u8>>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, i64>(3)?,
                        row.get::<_, Vec<u8>>(4)?,
                    ))
                },
            )
            .map_err(|_| VerifiedFeedError::Unavailable)?;
        let mut output = Vec::new();
        for row in rows {
            let (kind, tx_id, index, slot, blockhash) =
                row.map_err(|_| VerifiedFeedError::Unavailable)?;
            output.push(VerifiedSolanaEvent {
                settlement_id: self.settlement_id,
                terms_hash: self.terms_hash,
                kind: VerifiedSolanaEventKind::from_code(kind)
                    .ok_or(VerifiedFeedError::InvalidEvidence)?,
                evidence: EvidenceRefV1 {
                    chain_id: self.chain_id,
                    tx_id: vec32(tx_id)?,
                    event_index: u32::try_from(index)
                        .map_err(|_| VerifiedFeedError::InvalidEvidence)?,
                    block_height: from_i64(slot)?,
                    block_anchor: vec32(blockhash)?,
                },
            });
        }
        Ok(output)
    }
}

fn validate_anchors(
    anchors: &[SolanaSlotAnchor],
    from: u64,
    through: u64,
) -> Result<(), ObservationStoreError> {
    let mut previous = None;
    for anchor in anchors {
        if anchor.slot < from
            || anchor.slot > through
            || anchor.blockhash == [0; 32]
            || previous.is_some_and(|slot| slot >= anchor.slot)
        {
            return Err(ObservationStoreError::Invalid);
        }
        previous = Some(anchor.slot);
    }
    Ok(())
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
