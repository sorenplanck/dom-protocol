//! SQLite durable store for Solana operations.
//!
//! One row per `(settlement_id, kind)`. The exact signed bytes are written
//! once and never rewritten: every later mutation moves the stage and the
//! monotone facts around them, so a retained transaction is always the one
//! that was signed. Replay is by `attempt_id`, so a crash between the RPC
//! call and the durable write converges to exactly one outcome.

use blake2::digest::{Update, VariableOutput};
use blake2::Blake2bVar;
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use solana_types::{SolanaHash, SolanaSignature};
use std::{path::Path, sync::Mutex};

use crate::model::{
    Digest32, SolanaActuatorErrorV1, SolanaActuatorLeaseV1, SolanaFinalityFactsV1,
    SolanaOperationLocatorV1, SolanaOperationViewV1, SolanaReconciliationKindV1, SolanaTxStageV1,
};

const CUSTODY_DOMAIN_V1: &[u8] = b"DOM-INTEROP/SOLANA-ACTUATOR/CUSTODY/V1\0";
const MUTATION_DOMAIN_V1: &[u8] = b"DOM-INTEROP/SOLANA-ACTUATOR/MUTATION/V1\0";
const MAX_RAW_TRANSACTION_BYTES: usize = 1_232;

type Result<T> = core::result::Result<T, SolanaActuatorErrorV1>;

/// Commitment to exact retained bytes.
pub fn custody_digest_v1(raw_transaction: &[u8]) -> Result<Digest32> {
    digest_parts(
        CUSTODY_DOMAIN_V1,
        &[
            &(raw_transaction.len() as u64).to_be_bytes(),
            raw_transaction,
        ],
    )
}

fn digest_parts(domain: &[u8], parts: &[&[u8]]) -> Result<Digest32> {
    let mut hasher = Blake2bVar::new(32).map_err(|_| SolanaActuatorErrorV1::StorageUnavailable)?;
    hasher.update(domain);
    for part in parts {
        hasher.update(&(part.len() as u64).to_be_bytes());
        hasher.update(part);
    }
    let mut out = [0; 32];
    hasher
        .finalize_variable(&mut out)
        .map_err(|_| SolanaActuatorErrorV1::StorageUnavailable)?;
    if out == [0; 32] {
        return Err(SolanaActuatorErrorV1::Corrupt);
    }
    Ok(out)
}

/// Identity of one attempted mutation, for idempotent replay.
pub(crate) fn mutation_id_v1(
    locator: SolanaOperationLocatorV1,
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

/// Durable Solana operation store.
pub struct SolanaOperationStoreV1 {
    connection: Mutex<Connection>,
}

impl core::fmt::Debug for SolanaOperationStoreV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("SolanaOperationStoreV1")
            .finish_non_exhaustive()
    }
}

impl SolanaOperationStoreV1 {
    /// Opens or creates the durable store.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let connection =
            Connection::open(path).map_err(|_| SolanaActuatorErrorV1::StorageUnavailable)?;
        connection
            .execute_batch(
                "PRAGMA journal_mode=WAL;
                 PRAGMA synchronous=FULL;
                 CREATE TABLE IF NOT EXISTS solana_operation_v1(
                   settlement_id BLOB NOT NULL CHECK(length(settlement_id)=32),
                   kind INTEGER NOT NULL,
                   genesis_hash BLOB NOT NULL CHECK(length(genesis_hash)=32),
                   fencing_epoch INTEGER NOT NULL,
                   revision INTEGER NOT NULL,
                   stage INTEGER NOT NULL,
                   signature BLOB NOT NULL CHECK(length(signature)=64),
                   custody_digest BLOB NOT NULL CHECK(length(custody_digest)=32),
                   raw_transaction BLOB NOT NULL,
                   recent_blockhash BLOB NOT NULL CHECK(length(recent_blockhash)=32),
                   last_valid_block_height INTEGER NOT NULL,
                   secret_exposed INTEGER NOT NULL,
                   final_slot INTEGER,
                   final_blockhash BLOB,
                   final_evidence BLOB,
                   reconciliation INTEGER,
                   PRIMARY KEY(settlement_id, kind)
                 );
                 CREATE TABLE IF NOT EXISTS solana_mutation_v1(
                   mutation_id BLOB PRIMARY KEY NOT NULL CHECK(length(mutation_id)=32),
                   settlement_id BLOB NOT NULL,
                   kind INTEGER NOT NULL,
                   revision INTEGER NOT NULL
                 );",
            )
            .map_err(|_| SolanaActuatorErrorV1::StorageUnavailable)?;
        Ok(Self {
            connection: Mutex::new(connection),
        })
    }

    /// Retains exact signed bytes exactly once.
    ///
    /// An identical replay is idempotent; a different transaction for the same
    /// operation conflicts rather than overwriting, because the retained bytes
    /// are the only thing that makes a later broadcast byte-exact.
    #[allow(clippy::too_many_arguments)]
    pub fn prepare_signed(
        &self,
        lease: &SolanaActuatorLeaseV1,
        locator: SolanaOperationLocatorV1,
        signature: SolanaSignature,
        raw_transaction: &[u8],
        recent_blockhash: SolanaHash,
        last_valid_block_height: u64,
        now_unix_ms: u64,
    ) -> Result<SolanaOperationViewV1> {
        if !lease.is_live_at(now_unix_ms) {
            return Err(SolanaActuatorErrorV1::LeaseExpired);
        }
        if locator.settlement_id == [0; 32]
            || raw_transaction.is_empty()
            || raw_transaction.len() > MAX_RAW_TRANSACTION_BYTES
            || recent_blockhash.0 == [0; 32]
            || last_valid_block_height == 0
        {
            return Err(SolanaActuatorErrorV1::InvalidInput);
        }
        let custody = custody_digest_v1(raw_transaction)?;
        let mut connection = self.lock()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| SolanaActuatorErrorV1::StorageUnavailable)?;
        if let Some(existing) = read_row(&transaction, locator)? {
            // Identical replay converges; anything else is a second economic
            // transaction wearing the same identity.
            if existing.custody_digest != custody
                || existing.signature != signature
                || existing.genesis_hash != lease.genesis_hash
            {
                return Err(SolanaActuatorErrorV1::Conflict);
            }
            transaction
                .commit()
                .map_err(|_| SolanaActuatorErrorV1::StorageUnavailable)?;
            return Ok(existing.view);
        }
        transaction
            .execute(
                "INSERT INTO solana_operation_v1(
                   settlement_id, kind, genesis_hash, fencing_epoch, revision, stage,
                   signature, custody_digest, raw_transaction, recent_blockhash,
                   last_valid_block_height, secret_exposed
                 ) VALUES(?1,?2,?3,?4,1,?5,?6,?7,?8,?9,?10,?11)",
                params![
                    locator.settlement_id.as_slice(),
                    i64::from(locator.kind.tag()),
                    lease.genesis_hash.as_slice(),
                    i64::try_from(lease.fencing_epoch)
                        .map_err(|_| SolanaActuatorErrorV1::InvalidInput)?,
                    i64::from(SolanaTxStageV1::Signed.tag()),
                    signature.0.as_slice(),
                    custody.as_slice(),
                    raw_transaction,
                    recent_blockhash.0.as_slice(),
                    i64::try_from(last_valid_block_height)
                        .map_err(|_| SolanaActuatorErrorV1::InvalidInput)?,
                    i64::from(locator.kind.exposes_secret()),
                ],
            )
            .map_err(|_| SolanaActuatorErrorV1::StorageUnavailable)?;
        transaction
            .commit()
            .map_err(|_| SolanaActuatorErrorV1::StorageUnavailable)?;
        drop(connection);
        self.view(locator)
    }

    /// The exact retained bytes, for byte-identical retransmission only.
    pub fn retained_transaction(&self, locator: SolanaOperationLocatorV1) -> Result<Vec<u8>> {
        let connection = self.lock()?;
        let bytes: Option<Vec<u8>> = connection
            .query_row(
                "SELECT raw_transaction FROM solana_operation_v1
                 WHERE settlement_id=?1 AND kind=?2",
                params![
                    locator.settlement_id.as_slice(),
                    i64::from(locator.kind.tag())
                ],
                |row| row.get(0),
            )
            .optional()
            .map_err(|_| SolanaActuatorErrorV1::StorageUnavailable)?;
        bytes.ok_or(SolanaActuatorErrorV1::NotFound)
    }

    /// Current projection.
    pub fn view(&self, locator: SolanaOperationLocatorV1) -> Result<SolanaOperationViewV1> {
        let connection = self.lock()?;
        read_row(&connection, locator)?
            .map(|row| row.view)
            .ok_or(SolanaActuatorErrorV1::NotFound)
    }

    /// Records a stage transition under `attempt_id`, idempotently.
    ///
    /// Returns the view after the mutation. A replayed `attempt_id` returns
    /// the durable result of the first application rather than applying it
    /// twice: the whole point of the row is that one attempt has one outcome.
    pub(crate) fn apply_mutation(
        &self,
        lease: &SolanaActuatorLeaseV1,
        locator: SolanaOperationLocatorV1,
        attempt_id: Digest32,
        mutation_kind: u8,
        now_unix_ms: u64,
        transition: impl FnOnce(&SolanaOperationViewV1) -> Result<StageTransitionV1>,
    ) -> Result<SolanaOperationViewV1> {
        if !lease.is_live_at(now_unix_ms) {
            return Err(SolanaActuatorErrorV1::LeaseExpired);
        }
        if attempt_id == [0; 32] {
            return Err(SolanaActuatorErrorV1::InvalidInput);
        }
        let mutation_id = mutation_id_v1(locator, attempt_id, mutation_kind)?;
        let mut connection = self.lock()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| SolanaActuatorErrorV1::StorageUnavailable)?;
        let row = read_row(&transaction, locator)?.ok_or(SolanaActuatorErrorV1::NotFound)?;
        if row.genesis_hash != lease.genesis_hash {
            return Err(SolanaActuatorErrorV1::Conflict);
        }
        // A stale fence may read, never write.
        if lease.fencing_epoch < row.view.fencing_epoch {
            return Err(SolanaActuatorErrorV1::Conflict);
        }
        let replayed: Option<i64> = transaction
            .query_row(
                "SELECT revision FROM solana_mutation_v1 WHERE mutation_id=?1",
                params![mutation_id.as_slice()],
                |r| r.get(0),
            )
            .optional()
            .map_err(|_| SolanaActuatorErrorV1::StorageUnavailable)?;
        if replayed.is_some() {
            transaction
                .commit()
                .map_err(|_| SolanaActuatorErrorV1::StorageUnavailable)?;
            return Ok(row.view);
        }
        let step = transition(&row.view)?;
        let revision = row
            .view
            .revision
            .checked_add(1)
            .ok_or(SolanaActuatorErrorV1::Corrupt)?;
        transaction
            .execute(
                "UPDATE solana_operation_v1
                 SET stage=?1, revision=?2, fencing_epoch=?3,
                     final_slot=?4, final_blockhash=?5, final_evidence=?6, reconciliation=?7
                 WHERE settlement_id=?8 AND kind=?9",
                params![
                    i64::from(step.stage.tag()),
                    i64::try_from(revision).map_err(|_| SolanaActuatorErrorV1::Corrupt)?,
                    i64::try_from(lease.fencing_epoch)
                        .map_err(|_| SolanaActuatorErrorV1::InvalidInput)?,
                    step.finality
                        .map(|f| i64::try_from(f.final_slot))
                        .transpose()
                        .map_err(|_| SolanaActuatorErrorV1::Corrupt)?,
                    step.finality.map(|f| f.final_blockhash.0.to_vec()),
                    step.finality.map(|f| f.final_evidence_digest.to_vec()),
                    step.reconciliation
                        .map(|k| i64::from(reconciliation_tag(k))),
                    locator.settlement_id.as_slice(),
                    i64::from(locator.kind.tag()),
                ],
            )
            .map_err(|_| SolanaActuatorErrorV1::StorageUnavailable)?;
        transaction
            .execute(
                "INSERT INTO solana_mutation_v1(mutation_id, settlement_id, kind, revision)
                 VALUES(?1,?2,?3,?4)",
                params![
                    mutation_id.as_slice(),
                    locator.settlement_id.as_slice(),
                    i64::from(locator.kind.tag()),
                    i64::try_from(revision).map_err(|_| SolanaActuatorErrorV1::Corrupt)?,
                ],
            )
            .map_err(|_| SolanaActuatorErrorV1::StorageUnavailable)?;
        transaction
            .commit()
            .map_err(|_| SolanaActuatorErrorV1::StorageUnavailable)?;
        drop(connection);
        self.view(locator)
    }

    fn lock(&self) -> Result<std::sync::MutexGuard<'_, Connection>> {
        self.connection
            .lock()
            .map_err(|_| SolanaActuatorErrorV1::StorageUnavailable)
    }
}

/// One durable stage transition.
pub(crate) struct StageTransitionV1 {
    pub(crate) stage: SolanaTxStageV1,
    pub(crate) finality: Option<SolanaFinalityFactsV1>,
    pub(crate) reconciliation: Option<SolanaReconciliationKindV1>,
}

pub(crate) struct RetainedRowV1 {
    pub(crate) view: SolanaOperationViewV1,
    pub(crate) genesis_hash: Digest32,
    pub(crate) custody_digest: Digest32,
    pub(crate) signature: SolanaSignature,
}

const fn reconciliation_tag(kind: SolanaReconciliationKindV1) -> u8 {
    match kind {
        SolanaReconciliationKindV1::ExpiredNeverLanded => 1,
        SolanaReconciliationKindV1::Observed => 2,
        SolanaReconciliationKindV1::Final => 3,
        SolanaReconciliationKindV1::Unknown => 4,
    }
}

fn reconciliation_from_tag(value: i64) -> Option<SolanaReconciliationKindV1> {
    match value {
        1 => Some(SolanaReconciliationKindV1::ExpiredNeverLanded),
        2 => Some(SolanaReconciliationKindV1::Observed),
        3 => Some(SolanaReconciliationKindV1::Final),
        4 => Some(SolanaReconciliationKindV1::Unknown),
        _ => None,
    }
}

fn read_row(
    connection: &Connection,
    locator: SolanaOperationLocatorV1,
) -> Result<Option<RetainedRowV1>> {
    let row = connection
        .query_row(
            "SELECT genesis_hash, fencing_epoch, revision, stage, signature, custody_digest,
                    recent_blockhash, last_valid_block_height, secret_exposed,
                    final_slot, final_blockhash, final_evidence, reconciliation
             FROM solana_operation_v1 WHERE settlement_id=?1 AND kind=?2",
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
                    row.get::<_, i64>(7)?,
                    row.get::<_, i64>(8)?,
                    row.get::<_, Option<i64>>(9)?,
                    row.get::<_, Option<Vec<u8>>>(10)?,
                    row.get::<_, Option<Vec<u8>>>(11)?,
                    row.get::<_, Option<i64>>(12)?,
                ))
            },
        )
        .optional()
        .map_err(|_| SolanaActuatorErrorV1::StorageUnavailable)?;
    let Some((
        genesis,
        fence,
        revision,
        stage,
        signature,
        custody,
        blockhash,
        last_valid,
        exposed,
        final_slot,
        final_blockhash,
        final_evidence,
        reconciliation,
    )) = row
    else {
        return Ok(None);
    };
    let genesis_hash: Digest32 = genesis
        .try_into()
        .map_err(|_| SolanaActuatorErrorV1::Corrupt)?;
    let signature_bytes: [u8; 64] = signature
        .try_into()
        .map_err(|_| SolanaActuatorErrorV1::Corrupt)?;
    let custody_digest: Digest32 = custody
        .try_into()
        .map_err(|_| SolanaActuatorErrorV1::Corrupt)?;
    let blockhash_bytes: Digest32 = blockhash
        .try_into()
        .map_err(|_| SolanaActuatorErrorV1::Corrupt)?;
    let stage =
        SolanaTxStageV1::from_tag(u8::try_from(stage).map_err(|_| SolanaActuatorErrorV1::Corrupt)?)
            .ok_or(SolanaActuatorErrorV1::Corrupt)?;
    let finality = match (final_slot, final_blockhash, final_evidence) {
        (Some(slot), Some(hash), Some(evidence)) => Some(SolanaFinalityFactsV1 {
            final_slot: u64::try_from(slot).map_err(|_| SolanaActuatorErrorV1::Corrupt)?,
            final_blockhash: SolanaHash(
                hash.try_into()
                    .map_err(|_| SolanaActuatorErrorV1::Corrupt)?,
            ),
            final_evidence_digest: evidence
                .try_into()
                .map_err(|_| SolanaActuatorErrorV1::Corrupt)?,
        }),
        (None, None, None) => None,
        _ => return Err(SolanaActuatorErrorV1::Corrupt),
    };
    // Finality facts and the stages that carry them are one statement; a row
    // holding one without the other is corrupt, never merely surprising.
    if matches!(stage, SolanaTxStageV1::Final) != finality.is_some()
        && !matches!(stage, SolanaTxStageV1::FinalityInvalidated)
    {
        return Err(SolanaActuatorErrorV1::Corrupt);
    }
    let reconciliation = match reconciliation {
        Some(value) => Some(reconciliation_from_tag(value).ok_or(SolanaActuatorErrorV1::Corrupt)?),
        None => None,
    };
    Ok(Some(RetainedRowV1 {
        view: SolanaOperationViewV1 {
            locator,
            fencing_epoch: u64::try_from(fence).map_err(|_| SolanaActuatorErrorV1::Corrupt)?,
            revision: u64::try_from(revision).map_err(|_| SolanaActuatorErrorV1::Corrupt)?,
            stage,
            signature: SolanaSignature(signature_bytes),
            custody_digest,
            recent_blockhash: SolanaHash(blockhash_bytes),
            last_valid_block_height: u64::try_from(last_valid)
                .map_err(|_| SolanaActuatorErrorV1::Corrupt)?,
            secret_exposed: exposed != 0,
            finality,
            reconciliation_kind: reconciliation,
        },
        genesis_hash,
        custody_digest,
        signature: SolanaSignature(signature_bytes),
    }))
}

/// Frozen mutation tags, so a broadcast attempt and an observation attempt
/// with the same id are different mutations.
pub(crate) const MUTATION_BROADCAST: u8 = 1;
pub(crate) const MUTATION_OBSERVE: u8 = 2;
pub(crate) const MUTATION_RECONCILE: u8 = 3;
