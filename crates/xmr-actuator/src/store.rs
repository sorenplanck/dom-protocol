//! SQLite durable store for Monero sweep operations.
//!
//! One row per `(settlement_id, kind)`. The exact signed sweep bytes are
//! written once and never rewritten; every later mutation moves the stage
//! and monotone facts around them. Replay is by `attempt_id`, so a crash
//! between a daemon call and the durable write converges to one outcome.

use blake2::digest::{Update, VariableOutput};
use blake2::Blake2bVar;
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use std::{path::Path, sync::Mutex};

use crate::model::{
    Digest32, XmrActuatorErrorV1, XmrActuatorLeaseV1, XmrFinalityFactsV1, XmrOperationLocatorV1,
    XmrOperationViewV1, XmrReconciliationKindV1, XmrTxStageV1,
};

const CUSTODY_DOMAIN_V1: &[u8] = b"DOM-INTEROP/XMR-ACTUATOR/CUSTODY/V1\0";
const MUTATION_DOMAIN_V1: &[u8] = b"DOM-INTEROP/XMR-ACTUATOR/MUTATION/V1\0";
/// Frozen sidecar bound for a raw Monero transaction.
pub const MAX_RAW_TX_BYTES_V1: usize = 128 * 1024;

type Result<T> = core::result::Result<T, XmrActuatorErrorV1>;

/// Commitment to exact retained bytes.
pub fn custody_digest_v1(raw_transaction: &[u8]) -> Result<Digest32> {
    digest_parts(
        CUSTODY_DOMAIN_V1,
        &[&(raw_transaction.len() as u64).to_be_bytes(), raw_transaction],
    )
}

fn digest_parts(domain: &[u8], parts: &[&[u8]]) -> Result<Digest32> {
    let mut hasher = Blake2bVar::new(32).map_err(|_| XmrActuatorErrorV1::StorageUnavailable)?;
    hasher.update(domain);
    for part in parts {
        hasher.update(&(part.len() as u64).to_be_bytes());
        hasher.update(part);
    }
    let mut out = [0; 32];
    hasher
        .finalize_variable(&mut out)
        .map_err(|_| XmrActuatorErrorV1::StorageUnavailable)?;
    if out == [0; 32] {
        return Err(XmrActuatorErrorV1::Corrupt);
    }
    Ok(out)
}

/// Identity of one attempted mutation, for idempotent replay.
pub(crate) fn mutation_id_v1(
    locator: XmrOperationLocatorV1,
    attempt_id: Digest32,
    kind: u8,
) -> Result<Digest32> {
    digest_parts(
        MUTATION_DOMAIN_V1,
        &[
            &locator.settlement_id,
            &[locator.kind.tag()],
            &attempt_id,
            &[kind],
        ],
    )
}

/// Durable Monero operation store.
pub struct XmrOperationStoreV1 {
    connection: Mutex<Connection>,
}

impl core::fmt::Debug for XmrOperationStoreV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("XmrOperationStoreV1")
            .finish_non_exhaustive()
    }
}

impl XmrOperationStoreV1 {
    /// Opens or creates the durable store.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let connection =
            Connection::open(path).map_err(|_| XmrActuatorErrorV1::StorageUnavailable)?;
        connection
            .execute_batch(
                "PRAGMA journal_mode=WAL;
                 PRAGMA synchronous=FULL;
                 CREATE TABLE IF NOT EXISTS xmr_operation_v1(
                   settlement_id BLOB NOT NULL CHECK(length(settlement_id)=32),
                   kind INTEGER NOT NULL,
                   network_id BLOB NOT NULL CHECK(length(network_id)=32),
                   fencing_epoch INTEGER NOT NULL,
                   revision INTEGER NOT NULL,
                   stage INTEGER NOT NULL,
                   tx_hash BLOB NOT NULL CHECK(length(tx_hash)=32),
                   key_image BLOB NOT NULL CHECK(length(key_image)=32),
                   custody_digest BLOB NOT NULL CHECK(length(custody_digest)=32),
                   raw_transaction BLOB NOT NULL,
                   final_height INTEGER,
                   final_block_hash BLOB,
                   final_evidence BLOB,
                   reconciliation INTEGER,
                   PRIMARY KEY(settlement_id, kind)
                 );
                 CREATE TABLE IF NOT EXISTS xmr_mutation_v1(
                   mutation_id BLOB PRIMARY KEY NOT NULL CHECK(length(mutation_id)=32),
                   settlement_id BLOB NOT NULL,
                   kind INTEGER NOT NULL,
                   revision INTEGER NOT NULL
                 );",
            )
            .map_err(|_| XmrActuatorErrorV1::StorageUnavailable)?;
        Ok(Self {
            connection: Mutex::new(connection),
        })
    }

    /// Retains exact signed sweep bytes exactly once.
    #[allow(clippy::too_many_arguments)]
    pub fn prepare_signed(
        &self,
        lease: &XmrActuatorLeaseV1,
        locator: XmrOperationLocatorV1,
        tx_hash: Digest32,
        key_image: Digest32,
        raw_transaction: &[u8],
        now_unix_ms: u64,
    ) -> Result<XmrOperationViewV1> {
        if !lease.is_live_at(now_unix_ms) {
            return Err(XmrActuatorErrorV1::LeaseExpired);
        }
        if locator.settlement_id == [0; 32]
            || tx_hash == [0; 32]
            || key_image == [0; 32]
            || raw_transaction.is_empty()
            || raw_transaction.len() > MAX_RAW_TX_BYTES_V1
        {
            return Err(XmrActuatorErrorV1::InvalidInput);
        }
        let custody = custody_digest_v1(raw_transaction)?;
        let mut connection = self.lock()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| XmrActuatorErrorV1::StorageUnavailable)?;
        if let Some(existing) = read_row(&transaction, locator)? {
            if existing.custody_digest != custody
                || existing.view.tx_hash != tx_hash
                || existing.view.key_image != key_image
                || existing.network_id != lease.network_id
            {
                return Err(XmrActuatorErrorV1::Conflict);
            }
            transaction
                .commit()
                .map_err(|_| XmrActuatorErrorV1::StorageUnavailable)?;
            return Ok(existing.view);
        }
        transaction
            .execute(
                "INSERT INTO xmr_operation_v1(
                   settlement_id, kind, network_id, fencing_epoch, revision, stage,
                   tx_hash, key_image, custody_digest, raw_transaction
                 ) VALUES(?1,?2,?3,?4,1,?5,?6,?7,?8,?9)",
                params![
                    locator.settlement_id.as_slice(),
                    i64::from(locator.kind.tag()),
                    lease.network_id.as_slice(),
                    i64::try_from(lease.fencing_epoch)
                        .map_err(|_| XmrActuatorErrorV1::InvalidInput)?,
                    i64::from(XmrTxStageV1::Signed.tag()),
                    tx_hash.as_slice(),
                    key_image.as_slice(),
                    custody.as_slice(),
                    raw_transaction,
                ],
            )
            .map_err(|_| XmrActuatorErrorV1::StorageUnavailable)?;
        transaction
            .commit()
            .map_err(|_| XmrActuatorErrorV1::StorageUnavailable)?;
        drop(connection);
        self.view(locator)
    }

    /// The exact retained bytes, for byte-identical retransmission only.
    pub fn retained_transaction(&self, locator: XmrOperationLocatorV1) -> Result<Vec<u8>> {
        let connection = self.lock()?;
        let bytes: Option<Vec<u8>> = connection
            .query_row(
                "SELECT raw_transaction FROM xmr_operation_v1
                 WHERE settlement_id=?1 AND kind=?2",
                params![
                    locator.settlement_id.as_slice(),
                    i64::from(locator.kind.tag())
                ],
                |row| row.get(0),
            )
            .optional()
            .map_err(|_| XmrActuatorErrorV1::StorageUnavailable)?;
        bytes.ok_or(XmrActuatorErrorV1::NotFound)
    }

    /// Current projection.
    pub fn view(&self, locator: XmrOperationLocatorV1) -> Result<XmrOperationViewV1> {
        let connection = self.lock()?;
        read_row(&connection, locator)?
            .map(|row| row.view)
            .ok_or(XmrActuatorErrorV1::NotFound)
    }

    /// Records a stage transition under `attempt_id`, idempotently.
    pub(crate) fn apply_mutation(
        &self,
        lease: &XmrActuatorLeaseV1,
        locator: XmrOperationLocatorV1,
        attempt_id: Digest32,
        mutation_kind: u8,
        now_unix_ms: u64,
        transition: impl FnOnce(&XmrOperationViewV1) -> Result<StageTransitionV1>,
    ) -> Result<XmrOperationViewV1> {
        if !lease.is_live_at(now_unix_ms) {
            return Err(XmrActuatorErrorV1::LeaseExpired);
        }
        if attempt_id == [0; 32] {
            return Err(XmrActuatorErrorV1::InvalidInput);
        }
        let mutation_id = mutation_id_v1(locator, attempt_id, mutation_kind)?;
        let mut connection = self.lock()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| XmrActuatorErrorV1::StorageUnavailable)?;
        let row = read_row(&transaction, locator)?.ok_or(XmrActuatorErrorV1::NotFound)?;
        if row.network_id != lease.network_id {
            return Err(XmrActuatorErrorV1::Conflict);
        }
        // A stale fence may read, never write.
        if lease.fencing_epoch < row.view.fencing_epoch {
            return Err(XmrActuatorErrorV1::Conflict);
        }
        let replayed: Option<i64> = transaction
            .query_row(
                "SELECT revision FROM xmr_mutation_v1 WHERE mutation_id=?1",
                params![mutation_id.as_slice()],
                |r| r.get(0),
            )
            .optional()
            .map_err(|_| XmrActuatorErrorV1::StorageUnavailable)?;
        if replayed.is_some() {
            transaction
                .commit()
                .map_err(|_| XmrActuatorErrorV1::StorageUnavailable)?;
            return Ok(row.view);
        }
        let step = transition(&row.view)?;
        let revision = row
            .view
            .revision
            .checked_add(1)
            .ok_or(XmrActuatorErrorV1::Corrupt)?;
        transaction
            .execute(
                "UPDATE xmr_operation_v1
                 SET stage=?1, revision=?2, fencing_epoch=?3,
                     final_height=?4, final_block_hash=?5, final_evidence=?6, reconciliation=?7
                 WHERE settlement_id=?8 AND kind=?9",
                params![
                    i64::from(step.stage.tag()),
                    i64::try_from(revision).map_err(|_| XmrActuatorErrorV1::Corrupt)?,
                    i64::try_from(lease.fencing_epoch)
                        .map_err(|_| XmrActuatorErrorV1::InvalidInput)?,
                    step.finality
                        .map(|f| i64::try_from(f.final_height))
                        .transpose()
                        .map_err(|_| XmrActuatorErrorV1::Corrupt)?,
                    step.finality.map(|f| f.final_block_hash.to_vec()),
                    step.finality.map(|f| f.final_evidence_digest.to_vec()),
                    step.reconciliation.map(|k| i64::from(reconciliation_tag(k))),
                    locator.settlement_id.as_slice(),
                    i64::from(locator.kind.tag()),
                ],
            )
            .map_err(|_| XmrActuatorErrorV1::StorageUnavailable)?;
        transaction
            .execute(
                "INSERT INTO xmr_mutation_v1(mutation_id, settlement_id, kind, revision)
                 VALUES(?1,?2,?3,?4)",
                params![
                    mutation_id.as_slice(),
                    locator.settlement_id.as_slice(),
                    i64::from(locator.kind.tag()),
                    i64::try_from(revision).map_err(|_| XmrActuatorErrorV1::Corrupt)?,
                ],
            )
            .map_err(|_| XmrActuatorErrorV1::StorageUnavailable)?;
        transaction
            .commit()
            .map_err(|_| XmrActuatorErrorV1::StorageUnavailable)?;
        drop(connection);
        self.view(locator)
    }

    fn lock(&self) -> Result<std::sync::MutexGuard<'_, Connection>> {
        self.connection
            .lock()
            .map_err(|_| XmrActuatorErrorV1::StorageUnavailable)
    }
}

/// One durable stage transition.
pub(crate) struct StageTransitionV1 {
    pub(crate) stage: XmrTxStageV1,
    pub(crate) finality: Option<XmrFinalityFactsV1>,
    pub(crate) reconciliation: Option<XmrReconciliationKindV1>,
}

pub(crate) struct RetainedRowV1 {
    pub(crate) view: XmrOperationViewV1,
    pub(crate) network_id: Digest32,
    pub(crate) custody_digest: Digest32,
}

const fn reconciliation_tag(kind: XmrReconciliationKindV1) -> u8 {
    match kind {
        XmrReconciliationKindV1::KeyImageUnspentAbsent => 1,
        XmrReconciliationKindV1::Observed => 2,
        XmrReconciliationKindV1::Final => 3,
        XmrReconciliationKindV1::Unknown => 4,
    }
}

fn reconciliation_from_tag(value: i64) -> Option<XmrReconciliationKindV1> {
    match value {
        1 => Some(XmrReconciliationKindV1::KeyImageUnspentAbsent),
        2 => Some(XmrReconciliationKindV1::Observed),
        3 => Some(XmrReconciliationKindV1::Final),
        4 => Some(XmrReconciliationKindV1::Unknown),
        _ => None,
    }
}

fn read_row(
    connection: &Connection,
    locator: XmrOperationLocatorV1,
) -> Result<Option<RetainedRowV1>> {
    let row = connection
        .query_row(
            "SELECT network_id, fencing_epoch, revision, stage, tx_hash, key_image,
                    custody_digest, final_height, final_block_hash, final_evidence,
                    reconciliation
             FROM xmr_operation_v1 WHERE settlement_id=?1 AND kind=?2",
            params![
                locator.settlement_id.as_slice(),
                i64::from(locator.kind.tag())
            ],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, Vec<u8>>(4)?,
                    row.get::<_, Vec<u8>>(5)?,
                    row.get::<_, Vec<u8>>(6)?,
                    row.get::<_, Option<i64>>(7)?,
                    row.get::<_, Option<Vec<u8>>>(8)?,
                    row.get::<_, Option<Vec<u8>>>(9)?,
                    row.get::<_, Option<i64>>(10)?,
                ))
            },
        )
        .optional()
        .map_err(|_| XmrActuatorErrorV1::StorageUnavailable)?;
    let Some((
        network,
        fence,
        revision,
        stage,
        tx_hash,
        key_image,
        custody,
        final_height,
        final_block_hash,
        final_evidence,
        reconciliation,
    )) = row
    else {
        return Ok(None);
    };
    let network_id: Digest32 = network
        .try_into()
        .map_err(|_| XmrActuatorErrorV1::Corrupt)?;
    let tx_hash: Digest32 = tx_hash
        .try_into()
        .map_err(|_| XmrActuatorErrorV1::Corrupt)?;
    let key_image: Digest32 = key_image
        .try_into()
        .map_err(|_| XmrActuatorErrorV1::Corrupt)?;
    let custody_digest: Digest32 = custody
        .try_into()
        .map_err(|_| XmrActuatorErrorV1::Corrupt)?;
    let stage =
        XmrTxStageV1::from_tag(u8::try_from(stage).map_err(|_| XmrActuatorErrorV1::Corrupt)?)
            .ok_or(XmrActuatorErrorV1::Corrupt)?;
    let finality = match (final_height, final_block_hash, final_evidence) {
        (Some(height), Some(hash), Some(evidence)) => Some(XmrFinalityFactsV1 {
            final_height: u64::try_from(height).map_err(|_| XmrActuatorErrorV1::Corrupt)?,
            final_block_hash: hash.try_into().map_err(|_| XmrActuatorErrorV1::Corrupt)?,
            final_evidence_digest: evidence
                .try_into()
                .map_err(|_| XmrActuatorErrorV1::Corrupt)?,
        }),
        (None, None, None) => None,
        _ => return Err(XmrActuatorErrorV1::Corrupt),
    };
    if matches!(stage, XmrTxStageV1::Final) != finality.is_some()
        && !matches!(stage, XmrTxStageV1::FinalityInvalidated)
    {
        return Err(XmrActuatorErrorV1::Corrupt);
    }
    let reconciliation = match reconciliation {
        Some(value) => Some(reconciliation_from_tag(value).ok_or(XmrActuatorErrorV1::Corrupt)?),
        None => None,
    };
    Ok(Some(RetainedRowV1 {
        view: XmrOperationViewV1 {
            locator,
            fencing_epoch: u64::try_from(fence).map_err(|_| XmrActuatorErrorV1::Corrupt)?,
            revision: u64::try_from(revision).map_err(|_| XmrActuatorErrorV1::Corrupt)?,
            stage,
            tx_hash,
            key_image,
            custody_digest,
            finality,
            reconciliation_kind: reconciliation,
        },
        network_id,
        custody_digest,
    }))
}

/// Frozen mutation tags.
pub(crate) const MUTATION_BROADCAST: u8 = 1;
pub(crate) const MUTATION_OBSERVE: u8 = 2;
pub(crate) const MUTATION_RECONCILE: u8 = 3;
