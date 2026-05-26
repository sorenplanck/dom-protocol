//! Wallet transaction journal — append-only write-ahead log.
//!
//! The journal is the source of truth for the lifecycle of every
//! transaction the wallet has touched. Each lifecycle event (Built /
//! Submitted / Confirmed / Failed / Replaced / Canceled) is appended
//! as one JSON-encoded line to `<walletdir>/journal.log`, flushed
//! with `sync_all()`. On open, the journal replays its entries into
//! an in-memory map keyed by transaction hash.
//!
//! ## Why a journal?
//!
//! The current `WalletState.pending_txs` is rewritten on every save:
//! the whole encrypted blob churns even for a one-byte status flip.
//! A crash between "build the spend" and "save the wallet" loses the
//! reservation. A crash between "submit to the node" and the node's
//! ack is invisible to the wallet on restart.
//!
//! The journal is append-only and atomic per entry, so each
//! lifecycle event is durable the moment its append returns. Replay
//! reconstructs the canonical pending_txs view at startup; the
//! encrypted `WalletState.pending_txs` remains as a cache (for
//! backwards compat with Phase 1.2 tests) but the journal wins on
//! divergence.
//!
//! ## Layering
//!
//! Phase 1.5 ships the journal **primitive only** — the file format,
//! append, replay, and adversarial coverage. Wiring it into
//! `Wallet::build_spend` / `confirm_tx` / `cancel_tx` is the
//! responsibility of Phase 1.6 ("Tx lifecycle correctness"). Until
//! then, the journal coexists with the existing pending_txs path.
//!
//! ## Hash key
//!
//! Entries are keyed by the **mempool tx hash**: `blake2b_256(tx_bytes)`
//! (un-tagged). This matches the hash the node's mempool and
//! `node_handle::submit_tx` already use, and is the hash the
//! Phase 1.9 RPC client will return as `tx_id`. Using the mempool
//! hash here means Phase 1.7's namespace-unification work is mostly
//! a wallet-side rename, not a journal migration.
//!
//! ## State machine
//!
//! ```text
//!   Built ──► Submitted ──► Confirmed ──► (terminal)
//!     │           │            ▲    │
//!     │           │  Reorged   │    └── Reorged ──► Building
//!     │           │   (only when block_height > reorg_height)
//!     │           ├──► Failed   (terminal-ish; can be Replaced)
//!     │           ├──► Replaced (terminal)
//!     │           ├──► Canceled (terminal)
//!     ▼
//!   Canceled       Built can go straight to Canceled if the
//!  (terminal)      operator aborts before submitting.
//! ```
//!
//! `Reorged` is the only event that may transition out of a status
//! that would otherwise be terminal: a `Confirmed { block_height }`
//! record whose `block_height > reorg_height` is rewound back to
//! `Building`. The semantics intentionally drop "Submitted" rather
//! than restoring it — after a reorg the wallet cannot prove the tx
//! is still in the mempool; treating it as `Building` lets the
//! operator (or auto-resubmit logic) decide what to do next.
//!
//! Invalid transitions (e.g., `Confirmed → Submitted`, `Reorged` on
//! a non-Confirmed record, `Reorged` whose `reorg_height >=
//! block_height`) are logged and skipped during replay rather than
//! poisoning the in-memory map. This keeps replay total: a
//! forward-compat unknown event type, or a misordered log, never
//! panics.

use crate::types::WalletError;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use thiserror::Error;
use tracing::{debug, warn};

// ── Serde helpers — hex-encoded byte arrays ──────────────────────
//
// Journal entries are stored as JSON and intended to be
// human-readable for operator inspection. Fixed-size byte arrays
// are encoded as lowercase hex strings rather than JSON byte arrays
// (`[0xAA, 0xBB, ...]`) so the on-disk log is one tx_hash per line
// and visually scannable.

mod hex32 {
    use super::*;
    pub fn serialize<S: Serializer>(bytes: &[u8; 32], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(bytes))
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 32], D::Error> {
        let s: String = serde::Deserialize::deserialize(d)?;
        let v = hex::decode(&s).map_err(serde::de::Error::custom)?;
        if v.len() != 32 {
            return Err(serde::de::Error::custom(format!(
                "expected 32 bytes, got {}",
                v.len()
            )));
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(&v);
        Ok(out)
    }
}

mod hex33_vec {
    use super::*;
    use serde::ser::SerializeSeq;

    pub fn serialize<S: Serializer>(items: &Vec<[u8; 33]>, s: S) -> Result<S::Ok, S::Error> {
        let mut seq = s.serialize_seq(Some(items.len()))?;
        for item in items {
            seq.serialize_element(&hex::encode(item))?;
        }
        seq.end()
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<[u8; 33]>, D::Error> {
        let raw: Vec<String> = serde::Deserialize::deserialize(d)?;
        raw.into_iter()
            .map(|s| {
                let v = hex::decode(&s).map_err(serde::de::Error::custom)?;
                if v.len() != 33 {
                    return Err(serde::de::Error::custom(format!(
                        "expected 33 bytes, got {}",
                        v.len()
                    )));
                }
                let mut out = [0u8; 33];
                out.copy_from_slice(&v);
                Ok(out)
            })
            .collect()
    }
}

/// Filename of the journal inside a wallet directory.
pub const JOURNAL_LOG_NAME: &str = "journal.log";

/// Errors arising from journal operations.
#[derive(Debug, Error)]
pub enum JournalError {
    /// I/O error reading or writing the journal file.
    #[error("io: {0}")]
    Io(String),

    /// JSON encode failure when serialising an entry.
    #[error("encode: {0}")]
    Encode(String),

    /// JSON decode failure when reading a journal entry.
    #[error("decode at line {line}: {message}")]
    Decode {
        /// 1-indexed line number where decoding failed.
        line: usize,
        /// Underlying error description.
        message: String,
    },
}

impl From<JournalError> for WalletError {
    fn from(e: JournalError) -> Self {
        WalletError::Io(format!("journal: {e}"))
    }
}

/// Lifecycle event types the journal records.
///
/// Order of variants matches the standard transition flow; the
/// state machine in [`TxStatus::transition`] enforces validity.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum TxJournalEvent {
    /// Wallet has constructed a transaction, reserved its inputs,
    /// but has not yet submitted it to a node. Carries the inputs
    /// for reservation reconstruction during replay.
    Built {
        /// 33-byte commitments of the inputs reserved by this tx
        /// (serialised as hex strings).
        #[serde(with = "hex33_vec")]
        inputs: Vec<[u8; 33]>,
        /// Number of outputs in the transaction (informational).
        output_count: u32,
        /// Fee in noms (informational).
        fee_noms: u64,
    },
    /// Transaction has been handed off to a node / mempool.
    Submitted,
    /// Transaction has been included in a canonical block at
    /// `block_height`.
    Confirmed {
        /// Block height at which the tx was confirmed.
        block_height: u64,
    },
    /// Transaction failed at the node (relay rejection, evicted from
    /// mempool, expired).
    Failed {
        /// Operator-visible failure reason.
        reason: String,
    },
    /// Operator built a replacement transaction with `by_tx_hash`.
    /// This event marks the older tx as Replaced; the replacement
    /// gets its own Built entry under its own hash.
    Replaced {
        /// Hash of the replacement tx (serialised as hex).
        #[serde(with = "hex32")]
        by_tx_hash: [u8; 32],
    },
    /// Operator canceled before submission or after a Failed status.
    Canceled,
    /// A canonical-chain reorg rewinds the chain past this tx's
    /// confirmation height. Valid only when the current status is
    /// `Confirmed { block_height }` and `block_height > reorg_height`;
    /// transitions the record back to `Building` so reservations and
    /// pending-tx state can be reinstated.
    ///
    /// The journal stays append-only — no entries are deleted on a
    /// reorg. A subsequent confirmation on the alternate canonical
    /// chain is recorded as a fresh `Confirmed` event whose
    /// `block_height` reflects the new chain.
    Reorged {
        /// Height the chain is rolling back to (inclusive). The
        /// recorded tx's `block_height` must be strictly greater
        /// than this value for the transition to apply.
        reorg_height: u64,
    },
}

/// Coarse status of a journaled transaction.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TxStatus {
    /// Built locally; inputs reserved; not yet submitted.
    Building,
    /// Handed off to a node / mempool.
    Submitted,
    /// Included in a canonical block.
    Confirmed {
        /// Confirmation block height.
        block_height: u64,
    },
    /// Failed terminally (still convertible to Replaced if the
    /// operator builds a replacement).
    Failed {
        /// Reason for the failure.
        reason: String,
    },
    /// Replaced by another transaction.
    Replaced {
        /// Replacement transaction hash.
        by_tx_hash: [u8; 32],
    },
    /// Canceled by the operator.
    Canceled,
}

impl TxStatus {
    /// Whether this status is terminal (no further transitions).
    pub fn is_terminal(&self) -> bool {
        matches!(
            self,
            TxStatus::Confirmed { .. } | TxStatus::Replaced { .. } | TxStatus::Canceled
        )
    }
}

/// One row in the on-disk append-only journal.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JournalEntry {
    /// Unix timestamp (seconds) when the entry was written.
    pub timestamp: u64,
    /// Mempool-style transaction hash: `blake2b_256(tx_bytes)`
    /// (serialised as hex).
    #[serde(with = "hex32")]
    pub tx_hash: [u8; 32],
    /// Lifecycle event.
    pub event: TxJournalEvent,
}

/// Reconstructed in-memory record of a single transaction's
/// lifecycle, derived by replaying the journal entries for that hash.
#[derive(Debug, Clone)]
pub struct TxRecord {
    /// Mempool-style transaction hash.
    pub tx_hash: [u8; 32],
    /// Current status after applying all journal events.
    pub status: TxStatus,
    /// Inputs reserved by the original `Built` event (empty until
    /// the Built event is observed).
    pub inputs: Vec<[u8; 33]>,
    /// Fee in noms from the original Built event.
    pub fee_noms: u64,
    /// Timestamp of the Built event.
    pub created_at: u64,
    /// Timestamp of the most recently applied event.
    pub last_updated_at: u64,
}

/// Append-only journal handle.
///
/// Holds the path; the file is reopened in append mode for each
/// write so the OS-level file pointer stays consistent under
/// `sync_all` across replay calls.
pub struct TxJournal {
    path: PathBuf,
}

impl TxJournal {
    /// Open (or lazily create) the journal at `<walletdir>/journal.log`.
    pub fn open(walletdir: &Path) -> Result<Self, JournalError> {
        Ok(Self {
            path: walletdir.join(JOURNAL_LOG_NAME),
        })
    }

    /// The on-disk path of the journal file.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Append one entry, then fsync the file. The entry is durably
    /// recorded by the time this returns Ok.
    pub fn append(&self, entry: &JournalEntry) -> Result<(), JournalError> {
        let mut json =
            serde_json::to_vec(entry).map_err(|e| JournalError::Encode(e.to_string()))?;
        json.push(b'\n');

        let mut f = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .map_err(|e| JournalError::Io(format!("open append: {e}")))?;
        f.write_all(&json)
            .map_err(|e| JournalError::Io(format!("append write: {e}")))?;
        f.sync_all()
            .map_err(|e| JournalError::Io(format!("fsync: {e}")))?;
        debug!(
            "journal append: {} bytes for tx {}",
            json.len(),
            hex::encode(entry.tx_hash)
        );
        Ok(())
    }

    /// Replay the journal into an in-memory map keyed by tx hash.
    ///
    /// Missing journal file is treated as "no transactions yet" —
    /// returns an empty map.
    ///
    /// Malformed lines (truncated, invalid JSON, unknown event type
    /// not recognised by the current build) are logged and skipped:
    /// replay must be total so a partial-crash trailing line cannot
    /// poison wallet startup.
    ///
    /// Invalid state transitions (e.g., `Confirmed → Submitted`) are
    /// also logged and skipped; the recorded status remains at the
    /// earlier valid one.
    pub fn replay(&self) -> Result<HashMap<[u8; 32], TxRecord>, JournalError> {
        let mut map: HashMap<[u8; 32], TxRecord> = HashMap::new();

        let file = match File::open(&self.path) {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(map),
            Err(e) => return Err(JournalError::Io(format!("open replay: {e}"))),
        };
        let reader = BufReader::new(file);

        for (idx, line_result) in reader.lines().enumerate() {
            let line_no = idx + 1;
            let raw = match line_result {
                Ok(l) => l,
                Err(e) => {
                    warn!("journal: I/O error at line {line_no}: {e}; truncating replay here");
                    break;
                }
            };
            if raw.trim().is_empty() {
                continue;
            }
            let entry: JournalEntry = match serde_json::from_str(&raw) {
                Ok(e) => e,
                Err(e) => {
                    warn!(
                        "journal: malformed entry at line {line_no}; skipping. err = {e}; line = {raw:?}"
                    );
                    continue;
                }
            };
            apply_entry(&mut map, &entry, line_no);
        }

        Ok(map)
    }

    /// Whether the on-disk journal file exists.
    pub fn exists(&self) -> bool {
        self.path.exists()
    }
}

/// Apply one journal entry to the replay map. Validates the state
/// transition; logs and skips invalid ones.
fn apply_entry(map: &mut HashMap<[u8; 32], TxRecord>, entry: &JournalEntry, line_no: usize) {
    let tx_hash = entry.tx_hash;
    let ts = entry.timestamp;

    match &entry.event {
        TxJournalEvent::Built {
            inputs,
            output_count: _,
            fee_noms,
        } => {
            if map.contains_key(&tx_hash) {
                // Idempotent: a duplicate Built event for the same
                // tx_hash is a no-op. Operators sometimes re-issue
                // builds after a crash; we accept the first.
                warn!(
                    "journal: duplicate Built event at line {line_no} for tx {} ignored",
                    hex::encode(tx_hash)
                );
                return;
            }
            map.insert(
                tx_hash,
                TxRecord {
                    tx_hash,
                    status: TxStatus::Building,
                    inputs: inputs.clone(),
                    fee_noms: *fee_noms,
                    created_at: ts,
                    last_updated_at: ts,
                },
            );
        }
        TxJournalEvent::Submitted => {
            transition(map, &tx_hash, ts, line_no, |status| match status {
                TxStatus::Building => Some(TxStatus::Submitted),
                _ => None,
            });
        }
        TxJournalEvent::Confirmed { block_height } => {
            let bh = *block_height;
            transition(map, &tx_hash, ts, line_no, |status| match status {
                TxStatus::Submitted | TxStatus::Building => {
                    Some(TxStatus::Confirmed { block_height: bh })
                }
                _ => None,
            });
        }
        TxJournalEvent::Failed { reason } => {
            let r = reason.clone();
            transition(map, &tx_hash, ts, line_no, |status| match status {
                TxStatus::Submitted | TxStatus::Building => Some(TxStatus::Failed { reason: r }),
                _ => None,
            });
        }
        TxJournalEvent::Replaced { by_tx_hash } => {
            let by = *by_tx_hash;
            transition(map, &tx_hash, ts, line_no, |status| match status {
                TxStatus::Building | TxStatus::Submitted | TxStatus::Failed { .. } => {
                    Some(TxStatus::Replaced { by_tx_hash: by })
                }
                _ => None,
            });
        }
        TxJournalEvent::Canceled => {
            transition(map, &tx_hash, ts, line_no, |status| match status {
                TxStatus::Building | TxStatus::Submitted | TxStatus::Failed { .. } => {
                    Some(TxStatus::Canceled)
                }
                _ => None,
            });
        }
        TxJournalEvent::Reorged { reorg_height } => {
            let rh = *reorg_height;
            apply_reorged(map, &tx_hash, ts, line_no, rh);
        }
    }
}

/// Rewind a `Confirmed` record back to `Building` when a reorg has
/// invalidated its confirmation block. This is the only event that
/// transitions OUT of an otherwise-terminal status, so it cannot go
/// through the general [`transition`] helper (which guards against
/// terminal mutation).
///
/// Skipped (logged) if:
/// - the record is unknown,
/// - the record is not `Confirmed`,
/// - `reorg_height >= confirmation_height` (the confirmation block
///   survives the rollback and the record must stay terminal).
fn apply_reorged(
    map: &mut HashMap<[u8; 32], TxRecord>,
    tx_hash: &[u8; 32],
    ts: u64,
    line_no: usize,
    reorg_height: u64,
) {
    let Some(record) = map.get_mut(tx_hash) else {
        warn!(
            "journal: Reorged event at line {line_no} for unknown tx {} ignored",
            hex::encode(*tx_hash)
        );
        return;
    };
    let TxStatus::Confirmed { block_height } = record.status else {
        warn!(
            "journal: Reorged event at line {line_no} ignored; tx {} is not Confirmed (current = {:?})",
            hex::encode(*tx_hash),
            record.status
        );
        return;
    };
    if block_height <= reorg_height {
        warn!(
            "journal: Reorged event at line {line_no} ignored; tx {} confirmed at height {} survives rollback to {}",
            hex::encode(*tx_hash),
            block_height,
            reorg_height
        );
        return;
    }
    record.status = TxStatus::Building;
    record.last_updated_at = ts;
}

/// Apply a transition function to the record for `tx_hash` if it
/// exists and the transition is valid. Invalid transitions are
/// logged and skipped (state remains unchanged).
fn transition(
    map: &mut HashMap<[u8; 32], TxRecord>,
    tx_hash: &[u8; 32],
    ts: u64,
    line_no: usize,
    next: impl FnOnce(&TxStatus) -> Option<TxStatus>,
) {
    let Some(record) = map.get_mut(tx_hash) else {
        warn!(
            "journal: transition event at line {line_no} for unknown tx {} ignored",
            hex::encode(*tx_hash)
        );
        return;
    };
    if record.status.is_terminal() {
        warn!(
            "journal: transition event at line {line_no} ignored; tx {} is already terminal ({:?})",
            hex::encode(*tx_hash),
            record.status
        );
        return;
    }
    let Some(new_status) = next(&record.status) else {
        warn!(
            "journal: invalid transition at line {line_no} for tx {} (current = {:?})",
            hex::encode(*tx_hash),
            record.status
        );
        return;
    };
    record.status = new_status;
    record.last_updated_at = ts;
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn hash(b: u8) -> [u8; 32] {
        [b; 32]
    }

    fn input(b: u8) -> [u8; 33] {
        [b; 33]
    }

    fn now() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }

    #[test]
    fn missing_journal_file_replays_to_empty() {
        let temp = TempDir::new().unwrap();
        let j = TxJournal::open(temp.path()).unwrap();
        assert!(!j.exists());
        let map = j.replay().unwrap();
        assert!(map.is_empty());
    }

    #[test]
    fn built_then_submitted_then_confirmed_roundtrip() {
        let temp = TempDir::new().unwrap();
        let j = TxJournal::open(temp.path()).unwrap();
        let h = hash(0x01);
        j.append(&JournalEntry {
            timestamp: now(),
            tx_hash: h,
            event: TxJournalEvent::Built {
                inputs: vec![input(0xAA), input(0xBB)],
                output_count: 1,
                fee_noms: 100,
            },
        })
        .unwrap();
        j.append(&JournalEntry {
            timestamp: now(),
            tx_hash: h,
            event: TxJournalEvent::Submitted,
        })
        .unwrap();
        j.append(&JournalEntry {
            timestamp: now(),
            tx_hash: h,
            event: TxJournalEvent::Confirmed { block_height: 42 },
        })
        .unwrap();

        let map = j.replay().unwrap();
        let rec = map.get(&h).expect("tx must be present");
        assert_eq!(rec.status, TxStatus::Confirmed { block_height: 42 });
        assert_eq!(rec.inputs.len(), 2);
        assert_eq!(rec.fee_noms, 100);
        assert!(rec.status.is_terminal());
    }

    #[test]
    fn cancel_from_building_is_valid() {
        let temp = TempDir::new().unwrap();
        let j = TxJournal::open(temp.path()).unwrap();
        let h = hash(0x02);
        j.append(&JournalEntry {
            timestamp: now(),
            tx_hash: h,
            event: TxJournalEvent::Built {
                inputs: vec![input(0x55)],
                output_count: 1,
                fee_noms: 50,
            },
        })
        .unwrap();
        j.append(&JournalEntry {
            timestamp: now(),
            tx_hash: h,
            event: TxJournalEvent::Canceled,
        })
        .unwrap();
        let map = j.replay().unwrap();
        assert_eq!(map.get(&h).unwrap().status, TxStatus::Canceled);
    }

    #[test]
    fn duplicate_built_for_same_hash_is_idempotent() {
        let temp = TempDir::new().unwrap();
        let j = TxJournal::open(temp.path()).unwrap();
        let h = hash(0x03);
        for _ in 0..3 {
            j.append(&JournalEntry {
                timestamp: now(),
                tx_hash: h,
                event: TxJournalEvent::Built {
                    inputs: vec![input(0x11)],
                    output_count: 1,
                    fee_noms: 1,
                },
            })
            .unwrap();
        }
        let map = j.replay().unwrap();
        assert_eq!(map.len(), 1);
        assert_eq!(map.get(&h).unwrap().status, TxStatus::Building);
    }

    #[test]
    fn invalid_transition_after_terminal_is_ignored() {
        let temp = TempDir::new().unwrap();
        let j = TxJournal::open(temp.path()).unwrap();
        let h = hash(0x04);
        j.append(&JournalEntry {
            timestamp: 1,
            tx_hash: h,
            event: TxJournalEvent::Built {
                inputs: vec![input(0x22)],
                output_count: 1,
                fee_noms: 10,
            },
        })
        .unwrap();
        j.append(&JournalEntry {
            timestamp: 2,
            tx_hash: h,
            event: TxJournalEvent::Confirmed { block_height: 7 },
        })
        .unwrap();
        // Try to re-submit a confirmed tx — must be ignored.
        j.append(&JournalEntry {
            timestamp: 3,
            tx_hash: h,
            event: TxJournalEvent::Submitted,
        })
        .unwrap();
        let map = j.replay().unwrap();
        assert_eq!(
            map.get(&h).unwrap().status,
            TxStatus::Confirmed { block_height: 7 }
        );
    }

    #[test]
    fn transition_for_unknown_tx_is_ignored() {
        let temp = TempDir::new().unwrap();
        let j = TxJournal::open(temp.path()).unwrap();
        let h = hash(0x05);
        // No Built event written; a stray Submitted is ignored.
        j.append(&JournalEntry {
            timestamp: 1,
            tx_hash: h,
            event: TxJournalEvent::Submitted,
        })
        .unwrap();
        let map = j.replay().unwrap();
        assert!(map.is_empty());
    }

    #[test]
    fn replay_is_deterministic() {
        let temp = TempDir::new().unwrap();
        let j = TxJournal::open(temp.path()).unwrap();
        for i in 0..5u8 {
            let h = hash(i);
            j.append(&JournalEntry {
                timestamp: i as u64,
                tx_hash: h,
                event: TxJournalEvent::Built {
                    inputs: vec![input(i)],
                    output_count: 1,
                    fee_noms: i as u64,
                },
            })
            .unwrap();
            j.append(&JournalEntry {
                timestamp: i as u64 + 10,
                tx_hash: h,
                event: TxJournalEvent::Submitted,
            })
            .unwrap();
        }
        let m1 = j.replay().unwrap();
        let m2 = j.replay().unwrap();
        assert_eq!(m1.len(), m2.len());
        for (k, v) in &m1 {
            let v2 = m2.get(k).unwrap();
            assert_eq!(v.status, v2.status);
            assert_eq!(v.inputs, v2.inputs);
        }
    }

    /// Models crash-after-build-before-submit: a Built event is on
    /// disk but Submitted never made it. Replay must recover the
    /// Building state so the operator (or the wallet) can decide
    /// whether to resubmit, cancel, or treat as failed.
    #[test]
    fn crash_after_built_before_submitted_keeps_building_state() {
        let temp = TempDir::new().unwrap();
        let j = TxJournal::open(temp.path()).unwrap();
        let h = hash(0xCA);
        j.append(&JournalEntry {
            timestamp: now(),
            tx_hash: h,
            event: TxJournalEvent::Built {
                inputs: vec![input(0xDD)],
                output_count: 1,
                fee_noms: 99,
            },
        })
        .unwrap();
        // No Submitted event — simulate process crash here.
        let map = j.replay().unwrap();
        assert_eq!(map.get(&h).unwrap().status, TxStatus::Building);
    }

    /// Models a truncated trailing line: a write was interrupted
    /// mid-line. Replay must skip it without poisoning earlier
    /// entries.
    #[test]
    fn truncated_trailing_line_is_skipped() {
        use std::io::Write;
        let temp = TempDir::new().unwrap();
        let j = TxJournal::open(temp.path()).unwrap();
        let h = hash(0x55);
        j.append(&JournalEntry {
            timestamp: now(),
            tx_hash: h,
            event: TxJournalEvent::Built {
                inputs: vec![input(0x77)],
                output_count: 1,
                fee_noms: 5,
            },
        })
        .unwrap();
        // Append a bogus, partial JSON line manually (simulates
        // crash mid-write).
        {
            let mut f = OpenOptions::new().append(true).open(j.path()).unwrap();
            f.write_all(b"{\"timestamp\":1,\"tx_hash\":\"AAAAAAAA")
                .unwrap();
            // no newline, no closing brace — the BufRead line iterator
            // still yields this as one "line", but JSON decode fails.
        }

        let map = j.replay().unwrap();
        // The first entry must still be present.
        assert!(map.contains_key(&h));
        assert_eq!(map.get(&h).unwrap().status, TxStatus::Building);
    }

    /// A garbage line in the middle (corrupted, not at the tail)
    /// must not break replay of subsequent valid lines.
    #[test]
    fn corrupted_middle_line_does_not_break_subsequent_lines() {
        use std::io::Write;
        let temp = TempDir::new().unwrap();
        let j = TxJournal::open(temp.path()).unwrap();
        let h1 = hash(0xA1);
        let h2 = hash(0xA2);

        j.append(&JournalEntry {
            timestamp: 1,
            tx_hash: h1,
            event: TxJournalEvent::Built {
                inputs: vec![input(0x10)],
                output_count: 1,
                fee_noms: 1,
            },
        })
        .unwrap();

        // Inject a corrupted line in between.
        {
            let mut f = OpenOptions::new().append(true).open(j.path()).unwrap();
            f.write_all(b"this is not json at all\n").unwrap();
            f.sync_all().unwrap();
        }

        j.append(&JournalEntry {
            timestamp: 2,
            tx_hash: h2,
            event: TxJournalEvent::Built {
                inputs: vec![input(0x20)],
                output_count: 1,
                fee_noms: 2,
            },
        })
        .unwrap();

        let map = j.replay().unwrap();
        assert!(map.contains_key(&h1));
        assert!(map.contains_key(&h2));
        assert_eq!(map.len(), 2);
    }

    #[test]
    fn tx_status_terminality_classification() {
        assert!(TxStatus::Confirmed { block_height: 1 }.is_terminal());
        assert!(TxStatus::Canceled.is_terminal());
        assert!(TxStatus::Replaced {
            by_tx_hash: [0u8; 32]
        }
        .is_terminal());
        assert!(!TxStatus::Building.is_terminal());
        assert!(!TxStatus::Submitted.is_terminal());
        assert!(!TxStatus::Failed {
            reason: "evicted".into()
        }
        .is_terminal());
    }

    /// Replacement chain: tx A is Built → Submitted → Replaced(by=B);
    /// tx B is Built → Submitted → Confirmed. Replay must see A as
    /// Replaced (terminal) and B as Confirmed.
    #[test]
    fn replacement_chain_is_recorded_correctly() {
        let temp = TempDir::new().unwrap();
        let j = TxJournal::open(temp.path()).unwrap();
        let a = hash(0xA0);
        let b = hash(0xB0);

        j.append(&JournalEntry {
            timestamp: 1,
            tx_hash: a,
            event: TxJournalEvent::Built {
                inputs: vec![input(0x01)],
                output_count: 1,
                fee_noms: 10,
            },
        })
        .unwrap();
        j.append(&JournalEntry {
            timestamp: 2,
            tx_hash: a,
            event: TxJournalEvent::Submitted,
        })
        .unwrap();
        j.append(&JournalEntry {
            timestamp: 3,
            tx_hash: b,
            event: TxJournalEvent::Built {
                inputs: vec![input(0x01)],
                output_count: 1,
                fee_noms: 20,
            },
        })
        .unwrap();
        j.append(&JournalEntry {
            timestamp: 4,
            tx_hash: a,
            event: TxJournalEvent::Replaced { by_tx_hash: b },
        })
        .unwrap();
        j.append(&JournalEntry {
            timestamp: 5,
            tx_hash: b,
            event: TxJournalEvent::Submitted,
        })
        .unwrap();
        j.append(&JournalEntry {
            timestamp: 6,
            tx_hash: b,
            event: TxJournalEvent::Confirmed { block_height: 1000 },
        })
        .unwrap();

        let map = j.replay().unwrap();
        assert_eq!(
            map.get(&a).unwrap().status,
            TxStatus::Replaced { by_tx_hash: b }
        );
        assert_eq!(
            map.get(&b).unwrap().status,
            TxStatus::Confirmed { block_height: 1000 }
        );
    }

    /// Reorged whose `reorg_height < confirmation_height` rewinds a
    /// Confirmed record back to Building.
    #[test]
    fn reorged_rewinds_confirmed_to_building() {
        let temp = TempDir::new().unwrap();
        let j = TxJournal::open(temp.path()).unwrap();
        let h = hash(0x10);
        for event in [
            TxJournalEvent::Built {
                inputs: vec![input(0x01)],
                output_count: 1,
                fee_noms: 5,
            },
            TxJournalEvent::Submitted,
            TxJournalEvent::Confirmed { block_height: 200 },
            TxJournalEvent::Reorged { reorg_height: 150 },
        ] {
            j.append(&JournalEntry {
                timestamp: 1,
                tx_hash: h,
                event,
            })
            .unwrap();
        }
        let map = j.replay().unwrap();
        assert_eq!(map.get(&h).unwrap().status, TxStatus::Building);
    }

    /// Reorged whose `reorg_height >= confirmation_height` keeps the
    /// confirmation block within the canonical chain — the record
    /// must remain terminal.
    #[test]
    fn reorged_at_or_above_confirmation_height_is_ignored() {
        let temp = TempDir::new().unwrap();
        let j = TxJournal::open(temp.path()).unwrap();
        let h = hash(0x11);
        for event in [
            TxJournalEvent::Built {
                inputs: vec![input(0x02)],
                output_count: 1,
                fee_noms: 5,
            },
            TxJournalEvent::Confirmed { block_height: 100 },
            // reorg_height == confirmation_height: confirmation
            // survives, must be ignored.
            TxJournalEvent::Reorged { reorg_height: 100 },
            // reorg_height > confirmation_height: also ignored.
            TxJournalEvent::Reorged { reorg_height: 150 },
        ] {
            j.append(&JournalEntry {
                timestamp: 1,
                tx_hash: h,
                event,
            })
            .unwrap();
        }
        let map = j.replay().unwrap();
        assert_eq!(
            map.get(&h).unwrap().status,
            TxStatus::Confirmed { block_height: 100 }
        );
    }

    /// Reorged on a non-Confirmed record (e.g., still Building, or
    /// already Canceled) is a no-op — the only legal source state is
    /// `Confirmed`.
    #[test]
    fn reorged_on_non_confirmed_is_ignored() {
        let temp = TempDir::new().unwrap();
        let j = TxJournal::open(temp.path()).unwrap();
        let h = hash(0x12);
        for event in [
            TxJournalEvent::Built {
                inputs: vec![input(0x03)],
                output_count: 1,
                fee_noms: 5,
            },
            // Building → Reorged is invalid.
            TxJournalEvent::Reorged { reorg_height: 99 },
        ] {
            j.append(&JournalEntry {
                timestamp: 1,
                tx_hash: h,
                event,
            })
            .unwrap();
        }
        let map = j.replay().unwrap();
        assert_eq!(map.get(&h).unwrap().status, TxStatus::Building);
    }

    /// After Reorged the record can transition to Confirmed again
    /// (re-confirmation on the alternate chain). The state machine
    /// must not poison the record after a single rewind.
    #[test]
    fn confirmed_then_reorged_then_reconfirmed_lands_on_new_height() {
        let temp = TempDir::new().unwrap();
        let j = TxJournal::open(temp.path()).unwrap();
        let h = hash(0x13);
        for event in [
            TxJournalEvent::Built {
                inputs: vec![input(0x04)],
                output_count: 1,
                fee_noms: 1,
            },
            TxJournalEvent::Confirmed { block_height: 200 },
            TxJournalEvent::Reorged { reorg_height: 150 },
            TxJournalEvent::Confirmed { block_height: 205 },
        ] {
            j.append(&JournalEntry {
                timestamp: 1,
                tx_hash: h,
                event,
            })
            .unwrap();
        }
        let map = j.replay().unwrap();
        assert_eq!(
            map.get(&h).unwrap().status,
            TxStatus::Confirmed { block_height: 205 }
        );
    }
}
