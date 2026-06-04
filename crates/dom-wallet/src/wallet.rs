//! Main wallet struct and operations.

use crate::journal::{JournalEntry, TxJournal, TxJournalEvent, TxRecord, TxStatus};
use crate::output_index::OutputIndex;
use crate::restore::{ChainScanSource, RestoreError};
use crate::seed::{self, Bip39Seed};
use crate::store::{
    load_wallet as load_wallet_file, save_wallet as save_wallet_file, PendingChange,
    PendingReceiveSlate, PendingReceiveSlateSecrets, PendingSendSlate, PendingSendSlateSecrets,
    PendingTx, WalletKeychainState, WalletState,
};
use crate::types::{
    Network, OwnedOutput, ReceiveRequest, ReceiveRequestDescriptor, ReceiveRequestStatus,
    WalletBalance, WalletError,
};
use crate::unlock::{LockState, UnlockedSession};
use dom_consensus::transaction::{
    CoinbaseKernel, CoinbaseTransaction, Transaction, TransactionOutput,
};
use dom_core::{Address, Amount, BlockHeight, KERNEL_FEAT_COINBASE, KERNEL_FEAT_PLAIN};
use dom_crypto::pedersen::Commitment;
use dom_crypto::{
    blake2b_256_tagged, bp_prove, schnorr_add_public_keys, schnorr_partial_sign, BlindingFactor,
    Hash256, SecretKey,
};
use dom_serialization::DomSerialize;
use dom_tx::slate::{OutputCommitmentAndProof, Slate};
use dom_tx::SpendBuilder;
use k256::elliptic_curve::PrimeField;
use k256::Scalar;
use rand::RngCore;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::{Path, PathBuf};
use tracing::{debug, info};

/// A spend transaction that has been *constructed* but not yet reserved
/// or persisted.
///
/// This is the output of [`Wallet::build_spend_unreserved`] (phase 1 of a
/// spend): coin selection + transaction building, with **no mutation** of
/// wallet state. Handing this to [`Wallet::reserve_built_spend`] (phase 2)
/// performs the reservation under the caller's lock. Splitting the two
/// phases lets a caller validate mempool/chain admissibility *before*
/// reserving, so a rejected spend never leaves funds reserved.
pub struct BuiltSpend {
    /// The fully constructed transaction.
    pub tx: Transaction,
    /// Tracking hash (`blake2b_256(tx.to_bytes())`) — the key under which
    /// inputs are reserved and the pending tx is tracked. Equal to the
    /// hash the mempool computes for the same bytes.
    pub tx_hash: [u8; 32],
    /// Canonical serialized transaction bytes (computed once in phase 1 so
    /// serialization failures surface before any reservation).
    pub tx_bytes: Vec<u8>,
    /// Commitments of the inputs this spend consumes (to be reserved).
    selected_commitments: Vec<[u8; 33]>,
    /// Self-spend change to track, if any.
    pending_change: Option<PendingChange>,
    /// Fee in noms (recorded in the journal `Built` event).
    fee: u64,
}

/// Canonical wallet rescan execution mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WalletRescanMode {
    /// Rebuild canonical wallet state and return the comparison result
    /// without mutating persisted wallet state.
    CompareOnly,
    /// Replace persisted wallet state with the deterministic rebuild.
    Repair,
}

/// Result summary returned by a canonical wallet rescan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WalletRescanSummary {
    /// Tip height covered by the scan.
    pub scanned_tip: u64,
    /// Number of owned outputs reconstructed from canonical history.
    pub rebuilt_outputs: usize,
    /// Number of reconstructed outputs marked spent by later canonical inputs.
    pub spent_outputs: usize,
    /// Number of pending transactions preserved because all inputs remain live.
    pub pending_retained: usize,
    /// Number of pending transactions dropped because canonical history spent
    /// or removed at least one input.
    pub pending_dropped: usize,
    /// Deterministic digest of wallet state before the rebuild was applied.
    pub persisted_digest: [u8; 32],
    /// Deterministic digest of the rebuilt canonical wallet state.
    pub rebuilt_digest: [u8; 32],
    /// Whether the persisted digest already matched the rebuilt digest.
    pub matched_persisted: bool,
    /// Whether the rebuilt state was written back to disk.
    pub repaired: bool,
}

/// The DOM Protocol wallet.
///
/// Manages owned outputs, pending transactions, and persistent encrypted storage.
///
/// The wallet operates as an explicit two-state machine:
///
/// - **Unlocked** (`session: Some(...)`) — the wallet password is held
///   inside an [`UnlockedSession`] (zeroized on drop). Save, spend, and
///   coinbase derivation are allowed.
/// - **Locked** (`session: None`) — no password material is in memory.
///   `save`, `build_spend`, `build_coinbase`, `apply_canonical_block`,
///   and similar operations return [`WalletError::Locked`].
///
/// Use [`Wallet::lock`] to transition Unlocked → Locked (zeroizing the
/// session) and [`Wallet::unlock`] to transition back, supplying the
/// password and verifying it against the on-disk ciphertext.
pub struct Wallet {
    network: Network,
    chain_id: [u8; 32],
    outputs: OutputIndex,
    pending_txs: HashMap<[u8; 32], PendingTx>,
    receive_requests: Vec<ReceiveRequest>,
    keychain: WalletKeychainState,
    file_path: Option<PathBuf>,
    /// In-memory unlocked session. `None` means the wallet is locked
    /// and no operation requiring the password may proceed. The
    /// session's inner password buffer is wrapped in `Zeroizing` so
    /// it is wiped on `lock()` (which drops the session) or on
    /// `Wallet::drop`.
    session: Option<UnlockedSession>,
    /// Optional WAL journal. Set by `WalletDir::open` / `create` for
    /// wallets in a portable directory layout. When `Some`, lifecycle
    /// events (Built / Confirmed / Canceled) are appended before the
    /// corresponding in-memory mutation, so a crash between journal
    /// and state-save is recoverable on reopen.
    ///
    /// Raw single-file wallets (constructed via `Wallet::create` /
    /// `Wallet::open` without going through `WalletDir`) leave this
    /// at `None` — their lifecycle is recorded only in the encrypted
    /// `WalletState.pending_txs` blob, preserving Phase 1.2 behaviour
    /// for callers that have not yet adopted `WalletDir`.
    journal: Option<TxJournal>,
}

impl Wallet {
    /// Create a new wallet and save to disk with password encryption.
    pub fn create(
        path: &Path,
        password: &str,
        network: Network,
        genesis_hash: &Hash256,
    ) -> Result<Self, WalletError> {
        debug!("creating new wallet at {:?}", path);

        let chain_id_hash = dom_consensus::derive_chain_id(network.magic(), genesis_hash);
        let chain_id: [u8; 32] = *chain_id_hash.as_bytes();

        let state = WalletState {
            network,
            chain_id,
            outputs: Vec::new(),
            pending_txs: HashMap::new(),
            receive_requests: Vec::new(),
            keychain: WalletKeychainState::legacy(),
        };

        // Save encrypted to disk (generates fresh salt internally).
        save_wallet_file(path, &state, password)?;

        Ok(Self {
            network,
            chain_id,
            outputs: OutputIndex::new(),
            pending_txs: HashMap::new(),
            receive_requests: Vec::new(),
            keychain: WalletKeychainState::legacy(),
            file_path: Some(path.to_path_buf()),
            session: Some(UnlockedSession::from_verified_password(
                password.to_string(),
            )),
            journal: None,
        })
    }

    /// Create a new deterministic wallet from a validated BIP-39 seed.
    pub fn create_from_seed(
        path: &Path,
        password: &str,
        network: Network,
        genesis_hash: &Hash256,
        seed: &Bip39Seed,
    ) -> Result<Self, WalletError> {
        debug!("creating deterministic wallet at {:?}", path);

        let chain_id_hash = dom_consensus::derive_chain_id(network.magic(), genesis_hash);
        let chain_id: [u8; 32] = *chain_id_hash.as_bytes();

        let state = WalletState {
            network,
            chain_id,
            outputs: Vec::new(),
            pending_txs: HashMap::new(),
            receive_requests: Vec::new(),
            keychain: WalletKeychainState::deterministic(*seed.seed_bytes(), seed.word_count()),
        };

        save_wallet_file(path, &state, password)?;

        Ok(Self {
            network,
            chain_id,
            outputs: OutputIndex::new(),
            pending_txs: HashMap::new(),
            receive_requests: Vec::new(),
            keychain: WalletKeychainState::deterministic(*seed.seed_bytes(), seed.word_count()),
            file_path: Some(path.to_path_buf()),
            session: Some(UnlockedSession::from_verified_password(
                password.to_string(),
            )),
            journal: None,
        })
    }

    /// Open an existing wallet from disk with password decryption.
    pub fn open(path: &Path, password: &str) -> Result<Self, WalletError> {
        debug!("opening wallet from {:?}", path);

        let state = load_wallet_file(path, password)?;

        let mut outputs = OutputIndex::new();
        for output in state.outputs {
            outputs.insert(output);
        }

        Ok(Self {
            network: state.network,
            chain_id: state.chain_id,
            outputs,
            pending_txs: state.pending_txs,
            receive_requests: state.receive_requests,
            keychain: state.keychain,
            file_path: Some(path.to_path_buf()),
            session: Some(UnlockedSession::from_verified_password(
                password.to_string(),
            )),
            journal: None,
        })
    }

    /// Create a new in-memory wallet (for testing, no disk I/O).
    ///
    /// In-memory wallets start unlocked with an empty password. They
    /// have no on-disk ciphertext to verify against; `lock()` /
    /// `unlock()` still toggle the in-memory state for state-machine
    /// testing but `unlock` cannot reject a wrong password.
    pub fn new_in_memory(network: Network, genesis_hash: &Hash256) -> Self {
        let chain_id_hash = dom_consensus::derive_chain_id(network.magic(), genesis_hash);
        let chain_id: [u8; 32] = *chain_id_hash.as_bytes();

        Self {
            network,
            chain_id,
            outputs: OutputIndex::new(),
            pending_txs: HashMap::new(),
            receive_requests: Vec::new(),
            keychain: WalletKeychainState::legacy(),
            file_path: None,
            session: Some(UnlockedSession::from_verified_password(String::new())),
            journal: None,
        }
    }

    /// Attach a journal to this wallet. Once attached, lifecycle
    /// events (Built / Confirmed / Canceled) are appended to the
    /// journal **before** the corresponding in-memory mutation, so
    /// the journal is a true WAL.
    ///
    /// Called by `WalletDir::create` / `WalletDir::open` to wire
    /// the journal that lives alongside the encrypted wallet inside
    /// the portable directory.
    pub fn attach_journal(&mut self, journal: TxJournal) {
        self.journal = Some(journal);
    }

    /// Borrow the attached journal, if any.
    pub fn journal(&self) -> Option<&TxJournal> {
        self.journal.as_ref()
    }

    /// Whether the wallet currently tracks a pending tx by this hash.
    pub fn has_pending_tx(&self, tx_hash: &[u8; 32]) -> bool {
        self.pending_txs.contains_key(tx_hash)
    }

    /// Borrow the canonical bytes of a pending transaction, if this
    /// wallet retained them for rebroadcast/recovery.
    pub fn pending_tx_bytes(&self, tx_hash: &[u8; 32]) -> Option<&[u8]> {
        self.pending_txs.get(tx_hash).and_then(|pending| {
            (!pending.tx_bytes.is_empty()).then_some(pending.tx_bytes.as_slice())
        })
    }

    /// Iterate over the hashes of currently pending transactions.
    pub fn pending_tx_hashes(&self) -> impl Iterator<Item = [u8; 32]> + '_ {
        self.pending_txs.keys().copied()
    }

    /// Append one event to the journal if one is attached. No-op
    /// otherwise. Journal append errors propagate so callers do not
    /// mutate in-memory state unless the WAL is durable.
    fn record_journal(&self, tx_hash: [u8; 32], event: TxJournalEvent) -> Result<(), WalletError> {
        let Some(journal) = &self.journal else {
            return Ok(());
        };
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let entry = JournalEntry {
            timestamp: ts,
            tx_hash,
            event,
        };
        journal.append(&entry)?;
        Ok(())
    }

    /// Replay the attached journal and reconcile in-memory
    /// `pending_txs` + `outputs` state against it.
    ///
    /// Two divergences are recovered:
    ///
    /// 1. **Stale pending after terminal.** If the journal records a
    ///    transaction as `Confirmed { block_height }`, `Replaced`, or
    ///    `Canceled`, but the encrypted `pending_txs` still tracks it,
    ///    the pending entry is removed. For `Confirmed`, each input
    ///    is also marked spent; for all three, reservations are
    ///    released.
    /// 2. **Lost pending after Built/Submitted.** If the journal
    ///    records a transaction as `Building` or `Submitted` but the
    ///    encrypted `pending_txs` has no entry (e.g., a crash between
    ///    journal append and wallet save), the pending tx is
    ///    reinstated from the journal's `inputs` list and inputs are
    ///    re-reserved.
    ///
    /// Best-effort: inputs the wallet no longer tracks are logged and
    /// skipped rather than failing the reconcile. `Failed` records
    /// are left alone — the operator may still build a replacement.
    ///
    /// Returns `true` if anything changed and the caller should
    /// `save()` to persist the reconciled state. No-op (returns
    /// `false`) if no journal is attached or there are no
    /// divergences.
    pub fn reconcile_with_journal(&mut self) -> Result<bool, WalletError> {
        let Some(journal) = self.journal.as_ref() else {
            return Ok(false);
        };
        let records = journal.replay()?;
        let mut changed = false;

        for (tx_hash, record) in &records {
            match &record.status {
                TxStatus::Confirmed { .. } | TxStatus::Replaced { .. } | TxStatus::Canceled => {
                    if let Some(pending) = self.pending_txs.remove(tx_hash) {
                        let confirmed = matches!(record.status, TxStatus::Confirmed { .. });
                        for commitment in &pending.inputs {
                            if confirmed {
                                if let Err(e) = self.outputs.mark_spent(commitment) {
                                    tracing::warn!(
                                        "reconcile: mark_spent failed for tx {} input {}: {e}; skipping",
                                        hex::encode(tx_hash),
                                        hex::encode(commitment)
                                    );
                                }
                            }
                            if let Err(e) = self.outputs.release_reservation(commitment) {
                                tracing::warn!(
                                    "reconcile: release_reservation failed for tx {} input {}: {e}; skipping",
                                    hex::encode(tx_hash),
                                    hex::encode(commitment)
                                );
                            }
                        }
                        // Crash-recovery for the change output: if we
                        // crashed between the Confirmed journal append and
                        // `apply_canonical_block`'s save, the live path
                        // never registered the change. Reconstruct it from
                        // the persisted PendingChange + the journalled
                        // confirmation height so funds are not lost. No
                        // block hash is available here (None).
                        if confirmed {
                            if let (Some(c), TxStatus::Confirmed { block_height }) =
                                (pending.change, &record.status)
                            {
                                self.register_pending_change(c, *block_height, None);
                            }
                        }
                        changed = true;
                        tracing::info!(
                            "reconcile: cleaned up pending tx {} (journal status {:?})",
                            hex::encode(tx_hash),
                            record.status
                        );
                    }
                }
                TxStatus::Building | TxStatus::Submitted => {
                    // The journal says this tx is in-flight. Bring
                    // in-memory state into agreement: every input
                    // must be `spent=false` and `reserved_for_tx =
                    // Some(this tx_hash)`, and the pending entry
                    // must exist.
                    //
                    // This branch heals two distinct crash modes:
                    //
                    // - A crash between `build_spend`'s journal
                    //   append and `save()` — the pending entry
                    //   never made it to disk, but inputs were
                    //   reserved fine. Reinstate the pending entry.
                    // - A crash between `rollback_to`'s journal
                    //   Reorged append and `save()` — the pending
                    //   entry never made it back to disk, AND
                    //   inputs are still flagged `spent` from the
                    //   prior confirmation. Un-spend + re-reserve.
                    //
                    // Both cases collapse to the same idempotent
                    // mutation, applied per input.
                    let inputs = record.inputs.clone();
                    let any_missing = inputs.iter().any(|c| self.outputs.get(c).is_none());
                    if any_missing {
                        tracing::warn!(
                            "reconcile: cannot heal tx {} — one or more inputs absent from output index; skipping",
                            hex::encode(tx_hash)
                        );
                        continue;
                    }

                    let mut input_state_changed = false;
                    for commitment in &inputs {
                        let needs_unspend = self
                            .outputs
                            .get(commitment)
                            .map(|o| o.spent)
                            .unwrap_or(false);
                        let needs_reserve = self
                            .outputs
                            .get(commitment)
                            .map(|o| o.reserved_for_tx != Some(*tx_hash))
                            .unwrap_or(false);
                        if needs_unspend {
                            input_state_changed = true;
                            if let Err(e) = self.outputs.mark_unspent(commitment) {
                                tracing::warn!(
                                    "reconcile: mark_unspent failed for tx {} input {}: {e}; skipping",
                                    hex::encode(tx_hash),
                                    hex::encode(commitment)
                                );
                            }
                        }
                        if needs_reserve {
                            input_state_changed = true;
                            if let Err(e) = self.outputs.reserve(commitment, *tx_hash) {
                                tracing::warn!(
                                    "reconcile: reserve failed for tx {} input {}: {e}; aborting heal",
                                    hex::encode(tx_hash),
                                    hex::encode(commitment)
                                );
                            }
                        }
                    }

                    let needs_pending_insert = !self.pending_txs.contains_key(tx_hash);
                    if needs_pending_insert {
                        self.pending_txs.insert(
                            *tx_hash,
                            PendingTx {
                                tx_hash: *tx_hash,
                                inputs,
                                tx_bytes: record.tx_bytes.clone(),
                                change: record.change.clone(),
                                send_slate: None,
                                send_slate_secrets: None,
                                receive_slate: None,
                                receive_slate_secrets: None,
                            },
                        );
                    }

                    if needs_pending_insert || input_state_changed {
                        changed = true;
                        tracing::info!(
                            "reconcile: healed tx {} from journal (status {:?}; pending_reinstated={}, input_state_changed={})",
                            hex::encode(tx_hash),
                            record.status,
                            needs_pending_insert,
                            input_state_changed
                        );
                    }
                }
                TxStatus::Failed { .. } => {
                    // Left as-is. The operator may resubmit, cancel,
                    // or replace; we don't unilaterally rewrite state.
                }
            }
        }

        Ok(changed)
    }

    /// Roll the wallet back to a canonical-chain height of
    /// `target_height` (inclusive). Reverses everything the wallet
    /// did for confirmations recorded at heights strictly greater
    /// than `target_height`.
    ///
    /// For every journal record with status `Confirmed { block_height
    /// > target_height }`:
    ///
    /// 1. A `Reorged { reorg_height: target_height }` entry is
    ///    appended to the journal **before** any in-memory mutation
    ///    (WAL order).
    /// 2. The tx's input commitments are unmarked spent and
    ///    re-reserved for the tx. The pending entry is reinserted.
    /// 3. If any input would itself be removed by step 4 (it
    ///    originated at a height > `target_height`), the pending
    ///    entry is **not** restored — the spend is unreachable on
    ///    the rolled-back chain. The Reorged event still gets
    ///    journalled so replay reflects the rewind.
    ///
    /// After all tx reversals, owned outputs whose `block_height >
    /// target_height` are removed from the index. Any pending tx
    /// (rolled-back or pre-existing) whose inputs are no longer
    /// present is dropped from `pending_txs` — its inputs cannot
    /// be re-derived on the new chain.
    ///
    /// Iteration is sorted by tx_hash so successive replays of the
    /// same rollback produce a bit-identical journal suffix and
    /// in-memory state.
    ///
    /// Idempotent: a second `rollback_to(target_height)` on
    /// already-rolled-back state finds no Confirmed records above
    /// the target and is a no-op (no journal events, no state
    /// changes).
    ///
    /// Requires the wallet to be unlocked (state must be saved at
    /// the end) and a journal to be attached.
    pub fn rollback_to(&mut self, target_height: u64) -> Result<(), WalletError> {
        // Save requires an unlocked session; fail early.
        let _ = self.session()?;
        if self.journal.is_none() {
            return Err(WalletError::Io(
                "rollback_to requires an attached journal".into(),
            ));
        }

        // Snapshot the journal view. We rely on the replayed records
        // — not the (possibly stale) in-memory pending_txs — to find
        // which txs to rewind. Records are pulled into a Vec sorted
        // by tx_hash so the rollback is deterministic across runs.
        let records = self
            .journal
            .as_ref()
            .expect("journal presence checked above")
            .replay()?;
        let mut reorged: Vec<TxRecord> = records
            .into_values()
            .filter(|r| {
                matches!(
                    r.status,
                    TxStatus::Confirmed { block_height } if block_height > target_height
                )
            })
            .collect();
        reorged.sort_by_key(|r| r.tx_hash);

        for record in &reorged {
            // 1. Journal first (WAL): the rollback is durably
            //    recorded before any in-memory mutation.
            self.record_journal(
                record.tx_hash,
                TxJournalEvent::Reorged {
                    reorg_height: target_height,
                },
            )?;

            // Are this tx's inputs themselves about to disappear?
            // If so, restoring a pending entry with dangling inputs
            // would mislead callers and trip a reinstate-failure on
            // the next reopen. Drop it from the in-memory side; the
            // journal still shows the rewind.
            let inputs_survive = record.inputs.iter().all(|c| {
                self.outputs
                    .get(c)
                    .map(|o| o.block_height <= target_height)
                    .unwrap_or(false)
            });
            if !inputs_survive {
                tracing::warn!(
                    "rollback: tx {} has inputs originating above target {target_height}; not restoring in-memory pending entry",
                    hex::encode(record.tx_hash)
                );
                self.pending_txs.remove(&record.tx_hash);
                continue;
            }

            // 2. Un-spend inputs, then reserve them for this tx.
            //    Best-effort per input: a vanished output logs a
            //    warning but does not abort the rollback.
            for commitment in &record.inputs {
                if let Err(e) = self.outputs.mark_unspent(commitment) {
                    tracing::warn!(
                        "rollback: mark_unspent failed for tx {} input {}: {e}; skipping input",
                        hex::encode(record.tx_hash),
                        hex::encode(commitment)
                    );
                    continue;
                }
                if let Err(e) = self.outputs.reserve(commitment, record.tx_hash) {
                    tracing::warn!(
                        "rollback: reserve failed for tx {} input {}: {e}",
                        hex::encode(record.tx_hash),
                        hex::encode(commitment)
                    );
                }
            }

            // 3. Reinstate the pending entry.
            self.pending_txs.insert(
                record.tx_hash,
                PendingTx {
                    tx_hash: record.tx_hash,
                    inputs: record.inputs.clone(),
                    tx_bytes: record.tx_bytes.clone(),
                    change: record.change.clone(),
                    send_slate: None,
                    send_slate_secrets: None,
                    receive_slate: None,
                    receive_slate_secrets: None,
                },
            );
        }

        // 4. Remove owned outputs whose `block_height > target_height`.
        //    These cannot exist on the rolled-back chain. Coinbase
        //    outputs at these heights can be re-derived by replaying
        //    `scan_block` on the alternate chain; received outputs
        //    must be re-received via slatepack.
        let stale_outputs: Vec<[u8; 33]> = self
            .outputs
            .iter()
            .filter(|o| o.block_height > target_height)
            .map(|o| o.commitment)
            .collect();
        for commitment in &stale_outputs {
            self.outputs.remove(commitment);
        }

        // 5. Drop any pending tx whose inputs are no longer in the
        //    output index. Covers two cases:
        //    - txs we just journalled as Reorged but whose inputs got
        //      removed in step 4 (already handled above via the
        //      `inputs_survive` guard, but covered defensively here);
        //    - pre-existing pending txs (Built but not yet
        //      Confirmed) whose inputs were rolled away.
        let stranded: Vec<[u8; 32]> = self
            .pending_txs
            .iter()
            .filter(|(_, pending)| pending.inputs.iter().any(|c| self.outputs.get(c).is_none()))
            .map(|(tx_hash, _)| *tx_hash)
            .collect();
        for tx_hash in &stranded {
            tracing::warn!(
                "rollback: dropping pending tx {} — its inputs were rolled back",
                hex::encode(tx_hash)
            );
            self.pending_txs.remove(tx_hash);
        }

        // 6. Persist.
        self.save()?;

        info!(
            "rollback to height {target_height} complete: {} tx(s) reorged, {} output(s) removed, {} stranded pending dropped",
            reorged.len(),
            stale_outputs.len(),
            stranded.len()
        );
        Ok(())
    }

    /// Current lock state.
    pub fn lock_state(&self) -> LockState {
        match self.session {
            Some(_) => LockState::Unlocked,
            None => LockState::Locked,
        }
    }

    /// Whether the wallet is currently locked (no session in memory).
    pub fn is_locked(&self) -> bool {
        self.session.is_none()
    }

    /// Whether the wallet is currently unlocked.
    pub fn is_unlocked(&self) -> bool {
        self.session.is_some()
    }

    /// Whether this wallet carries deterministic seed material.
    pub fn has_deterministic_seed(&self) -> bool {
        self.keychain.has_seed()
    }

    /// Original seed phrase word count, if the wallet is deterministic.
    pub fn seed_word_count(&self) -> Option<u8> {
        self.keychain.seed_word_count
    }

    /// Lock the wallet. Consumes the in-memory session, zeroizing the
    /// held password. After this call, operations that require the
    /// password (save, spend, coinbase, scan_block, apply_canonical_block)
    /// will return [`WalletError::Locked`].
    ///
    /// On-disk state is unaffected: previously persisted pending txs,
    /// outputs, and the encrypted wallet file remain intact.
    ///
    /// Idempotent: locking an already-locked wallet is a no-op.
    pub fn lock(&mut self) {
        if let Some(session) = self.session.take() {
            session.into_locked();
            self.keychain.seed_bytes = None;
            debug!("wallet locked");
        }
    }

    /// Unlock the wallet by verifying `password` against the on-disk
    /// ciphertext.
    ///
    /// For file-backed wallets, this performs a full
    /// Argon2id+ChaCha20Poly1305 decrypt of the wallet header to
    /// confirm the password. On wrong password, returns
    /// [`WalletError::Decryption`] and the wallet remains locked.
    ///
    /// For in-memory wallets (no `file_path`), any password is
    /// accepted because there is no ciphertext to verify against.
    /// This is intended for state-machine testing.
    ///
    /// Idempotent on success: unlocking an already-unlocked wallet
    /// with the correct password is allowed (replaces the session).
    pub fn unlock(&mut self, password: &str) -> Result<(), WalletError> {
        if let Some(path) = &self.file_path {
            // Verify by attempting decrypt of the on-disk wallet and
            // refresh any secret keychain material that was dropped on
            // the prior `lock()`.
            let verified = load_wallet_file(path, password)?;
            self.keychain.seed_bytes = verified.keychain.seed_bytes;
            if self.keychain.seed_word_count.is_none() {
                self.keychain.seed_word_count = verified.keychain.seed_word_count;
            }
        }
        self.session = Some(UnlockedSession::from_verified_password(
            password.to_string(),
        ));
        debug!("wallet unlocked");
        Ok(())
    }

    /// Borrow the unlocked session, or return `WalletError::Locked`.
    fn session(&self) -> Result<&UnlockedSession, WalletError> {
        self.session.as_ref().ok_or(WalletError::Locked)
    }

    fn deterministic_root(&self) -> Result<crate::hd_wallet::ExtendedPrivKey, WalletError> {
        let seed_bytes = self
            .keychain
            .seed_bytes
            .as_ref()
            .ok_or_else(|| WalletError::Crypto("wallet has no deterministic seed".into()))?;
        crate::hd_wallet::ExtendedPrivKey::from_seed(&seed_bytes[..])
            .map_err(|e| WalletError::Crypto(format!("derive HD root: {e}")))
    }

    fn receive_blinding_for_index(&self, index: u32) -> Result<BlindingFactor, WalletError> {
        let root = self.deterministic_root()?;
        let blinding_z = seed::spend_output_blinding(&root, self.keychain.account, index)
            .map_err(|e| WalletError::Crypto(format!("seed receive blinding: {e}")))?;
        BlindingFactor::from_bytes(*blinding_z)
            .map_err(|e| WalletError::Crypto(format!("blinding from bytes: {e}")))
    }

    fn receive_descriptor_for_request(
        &self,
        request: &ReceiveRequest,
    ) -> Result<ReceiveRequestDescriptor, WalletError> {
        let blinding = self.receive_blinding_for_index(request.index)?;
        let commitment = Commitment::commit(request.amount, &blinding);
        let commitment_bytes = *commitment.as_bytes();
        if commitment_bytes != request.commitment {
            return Err(WalletError::Io(format!(
                "receive request index {} failed deterministic validation",
                request.index
            )));
        }

        let address = Address::new(commitment_bytes, matches!(self.network, Network::Mainnet));
        Ok(ReceiveRequestDescriptor {
            index: request.index,
            amount: request.amount,
            address: address.encode(),
            commitment_hex: hex::encode(commitment_bytes),
            blinding_hex: hex::encode(blinding.as_bytes()),
            created_at: request.created_at,
            status: request.status.clone(),
        })
    }

    fn coinbase_blinding_for_height(
        &self,
        height: BlockHeight,
        session: &UnlockedSession,
    ) -> Result<BlindingFactor, WalletError> {
        if let Some(seed_bytes) = &self.keychain.seed_bytes {
            let root = crate::hd_wallet::ExtendedPrivKey::from_seed(&seed_bytes[..])
                .map_err(|e| WalletError::Crypto(format!("derive HD root: {e}")))?;
            let blinding_z = seed::coinbase_blinding(&root, height.0)
                .map_err(|e| WalletError::Crypto(format!("seed coinbase blinding: {e}")))?;
            BlindingFactor::from_bytes(*blinding_z)
                .map_err(|e| WalletError::Crypto(format!("blinding from bytes: {e}")))
        } else {
            let password_seed =
                blake2b_256_tagged("DOM:wallet-coinbase-seed:v1", session.password().as_bytes());
            let mut blinding_input = Vec::with_capacity(32 + 8);
            blinding_input.extend_from_slice(password_seed.as_bytes());
            blinding_input.extend_from_slice(&height.0.to_le_bytes());
            let blinding_hash =
                blake2b_256_tagged(dom_core::TAG_COINBASE_BLINDING, &blinding_input);
            BlindingFactor::from_bytes(*blinding_hash.as_bytes())
                .map_err(|e| WalletError::Crypto(format!("blinding from bytes: {e}")))
        }
    }

    /// Compute the wallet's deterministic tracking hash for a transaction.
    ///
    /// This is the key used for pending-transaction persistence and internal
    /// reservation management. It is intentionally domain-separated from the
    /// mempool's raw-byte hash so wallet-local lifecycle state can evolve
    /// without coupling to relay internals.
    pub fn tracking_tx_hash(tx: &Transaction) -> Result<[u8; 32], WalletError> {
        compute_tx_hash(tx)
    }

    /// Save wallet to disk (if `file_path` is set).
    ///
    /// Returns [`WalletError::Locked`] if the wallet is locked and a
    /// file path is set — the password is needed to re-encrypt the
    /// payload. For in-memory wallets (no file path), save is a no-op
    /// and does not require the wallet to be unlocked.
    pub fn save(&self) -> Result<(), WalletError> {
        match &self.file_path {
            Some(path) => {
                let session = self.session()?;
                let outputs: Vec<_> = self.outputs.iter().cloned().collect();
                let state = WalletState {
                    network: self.network,
                    chain_id: self.chain_id,
                    outputs,
                    pending_txs: self.pending_txs.clone(),
                    receive_requests: self.receive_requests.clone(),
                    keychain: self.keychain.clone(),
                };
                save_wallet_file(path, &state, session.password())?;
                debug!("wallet saved");
                Ok(())
            }
            None => {
                debug!("wallet is in-memory, not saving to disk");
                Ok(())
            }
        }
    }

    /// Compute current balance broken down by maturity and reservation,
    /// honouring the wallet's network coinbase-maturity rule.
    pub fn balance(&self, current_height: u64) -> WalletBalance {
        let mut confirmed = 0u64;
        let mut immature = 0u64;
        let mut reserved = 0u64;
        let maturity = self.network.coinbase_maturity();

        for output in self.outputs.iter() {
            if output.spent {
                continue;
            }

            if output.reserved_for_tx.is_some() {
                reserved = reserved.saturating_add(output.value);
                continue;
            }

            if output.is_mature_for(current_height, maturity) {
                confirmed = confirmed.saturating_add(output.value);
            } else {
                immature = immature.saturating_add(output.value);
            }
        }

        WalletBalance {
            confirmed,
            immature,
            reserved,
        }
    }

    /// Deterministic digest of the wallet state relevant to canonical
    /// chain reconstruction.
    ///
    /// The digest deliberately excludes private blinding factors and seed
    /// material. It includes commitments, values, block attribution,
    /// spent/reserved flags, receive-request status, and pending transaction
    /// input references in sorted order.
    pub fn canonical_digest(&self) -> [u8; 32] {
        Self::digest_parts(
            self.outputs.iter(),
            &self.pending_txs,
            &self.receive_requests,
        )
    }

    /// Rebuild recoverable wallet state from canonical chain history.
    ///
    /// The scan walks `0..=scan.tip_height()` through the supplied
    /// [`ChainScanSource`]. It reconstructs deterministic coinbase outputs,
    /// deterministic receive-request outputs, spent/unspent state from
    /// canonical input commitments, receive-request confirmation status, and
    /// pending reservations that remain valid after the rebuild.
    ///
    /// `CompareOnly` returns the rebuilt digest without mutating the wallet.
    /// `Repair` replaces the persisted output index, receive statuses, and
    /// surviving pending reservations, then saves the wallet.
    pub fn rescan_canonical_chain<S: ChainScanSource>(
        &mut self,
        scan: &S,
        mode: WalletRescanMode,
    ) -> Result<WalletRescanSummary, WalletError> {
        let session = self.session()?;
        let persisted_digest = self.canonical_digest();
        let scanned_tip = scan.tip_height();
        let maturity = self.network.coinbase_maturity();

        let mut rebuilt_outputs = OutputIndex::new();
        let mut canonical_inputs = HashSet::new();
        let mut detected_receives: BTreeMap<[u8; 33], ReceiveRequestStatus> = BTreeMap::new();

        for height in 0..=scanned_tip {
            let block = scan.block_at(height).map_err(scan_error_to_wallet)?;
            let Some(block) = block else {
                continue;
            };
            if block.height != height {
                return Err(WalletError::Io(format!(
                    "canonical rescan source returned height {} for requested {}",
                    block.height, height
                )));
            }

            canonical_inputs.extend(block.input_commitments.iter().copied());

            let coinbase_blinding =
                self.coinbase_blinding_for_height(BlockHeight(height), session)?;
            let reward = dom_core::block_reward(BlockHeight(height)).noms();
            let reward_with_fees = reward
                .checked_add(block.total_fees_noms)
                .ok_or_else(|| WalletError::Crypto("coinbase value overflow".into()))?;
            for &commitment in &block.output_commitments {
                for &value in &[reward, reward_with_fees] {
                    if value == 0 {
                        continue;
                    }
                    let candidate = Commitment::commit(value, &coinbase_blinding);
                    if *candidate.as_bytes() == commitment {
                        let mut owned = OwnedOutput::new(
                            commitment,
                            value,
                            *coinbase_blinding.as_bytes(),
                            height,
                            true,
                        );
                        if let Some(hash) = block.block_hash {
                            owned = owned.with_block_hash(hash);
                        }
                        rebuilt_outputs.insert(owned);
                        break;
                    }
                }
            }

            for request in &self.receive_requests {
                if block.output_commitments.contains(&request.commitment) {
                    let blinding = self.receive_blinding_for_index(request.index)?;
                    let mut owned = OwnedOutput::new(
                        request.commitment,
                        request.amount,
                        *blinding.as_bytes(),
                        height,
                        false,
                    );
                    if let Some(hash) = block.block_hash {
                        owned = owned.with_block_hash(hash);
                    }
                    rebuilt_outputs.insert(owned);
                    detected_receives.insert(
                        request.commitment,
                        ReceiveRequestStatus::Detected {
                            block_height: height,
                            is_coinbase: false,
                            is_mature: true,
                        },
                    );
                }
            }
        }

        for commitment in &canonical_inputs {
            if let Some(output) = rebuilt_outputs.get_mut(commitment) {
                output.spent = true;
                output.reserved_for_tx = None;
            }
        }

        let mut rebuilt_pending = HashMap::new();
        let mut pending_dropped = 0usize;
        for (tx_hash, pending) in &self.pending_txs {
            let survives = pending.inputs.iter().all(|commitment| {
                rebuilt_outputs
                    .get(commitment)
                    .map(|output| !output.spent)
                    .unwrap_or(false)
            });
            if survives {
                for commitment in &pending.inputs {
                    rebuilt_outputs.reserve(commitment, *tx_hash)?;
                }
                rebuilt_pending.insert(*tx_hash, pending.clone());
            } else {
                pending_dropped = pending_dropped.saturating_add(1);
            }
        }

        let mut rebuilt_receive_requests = self.receive_requests.clone();
        for request in &mut rebuilt_receive_requests {
            request.status = detected_receives
                .get(&request.commitment)
                .cloned()
                .unwrap_or(ReceiveRequestStatus::Pending);
            if let ReceiveRequestStatus::Detected {
                block_height,
                is_coinbase,
                is_mature,
            } = &mut request.status
            {
                *is_mature = if *is_coinbase {
                    block_height.saturating_add(maturity) <= scanned_tip
                } else {
                    true
                };
            }
        }

        let rebuilt_digest = Self::digest_parts(
            rebuilt_outputs.iter(),
            &rebuilt_pending,
            &rebuilt_receive_requests,
        );
        let spent_outputs = rebuilt_outputs.iter().filter(|output| output.spent).count();
        let summary = WalletRescanSummary {
            scanned_tip,
            rebuilt_outputs: rebuilt_outputs.iter().count(),
            spent_outputs,
            pending_retained: rebuilt_pending.len(),
            pending_dropped,
            persisted_digest,
            rebuilt_digest,
            matched_persisted: persisted_digest == rebuilt_digest,
            repaired: matches!(mode, WalletRescanMode::Repair),
        };

        if matches!(mode, WalletRescanMode::Repair) {
            self.outputs = rebuilt_outputs;
            self.pending_txs = rebuilt_pending;
            self.receive_requests = rebuilt_receive_requests;
            self.save()?;
        }

        Ok(summary)
    }

    /// Add a received output to the wallet.
    pub fn add_output(&mut self, output: OwnedOutput) {
        debug!(
            "adding output: {} noms at height {}",
            output.value, output.block_height
        );
        self.outputs.insert(output);
    }

    /// Register a confirmed self-spend change output as a spendable
    /// [`OwnedOutput`].
    ///
    /// Change carries a random blinding (not re-derivable by
    /// `scan_block`), so it is registered explicitly from the persisted
    /// [`PendingChange`] at confirmation time. Idempotent: keyed by
    /// commitment in the output index, so the live confirmation path and
    /// a later crash-recovery `reconcile` cannot double-register it.
    /// Change is never coinbase, so it is immediately mature/spendable.
    fn register_pending_change(
        &mut self,
        change: PendingChange,
        block_height: u64,
        block_hash: Option<[u8; 32]>,
    ) {
        if self.outputs.get(&change.commitment).is_some() {
            return;
        }
        debug!(
            "registering spendable change output: {} noms at height {}",
            change.value, block_height
        );
        let mut owned = OwnedOutput::new(
            change.commitment,
            change.value,
            change.blinding,
            block_height,
            false,
        );
        if let Some(hash) = block_hash {
            owned = owned.with_block_hash(hash);
        }
        self.outputs.insert(owned);
    }

    /// Create the sender side of an interactive Mimblewimble slate.
    ///
    /// This is step 1 of the slate protocol. It selects mature spendable
    /// inputs, creates sender change if needed, computes the sender excess
    /// contribution, generates a fresh single-use sender nonce, reserves the
    /// selected inputs, records a pending item, and returns only the public
    /// slate data. No blinding factors or private keys are placed in the
    /// returned [`Slate`].
    pub fn create_send_slate(
        &mut self,
        amount: u64,
        fee: u64,
        current_height: u64,
    ) -> Result<Slate, WalletError> {
        debug!("creating send slate: {} noms + {} fee", amount, fee);

        let required = amount
            .checked_add(fee)
            .ok_or_else(|| WalletError::Crypto("amount + fee overflow".into()))?;
        let selected = self.outputs.select_for_spend_with_maturity(
            required,
            current_height,
            self.network.coinbase_maturity(),
        )?;
        let selected_commitments: Vec<[u8; 33]> = selected.iter().map(|o| o.commitment).collect();
        let total_selected = selected
            .iter()
            .try_fold(0u64, |acc, output| acc.checked_add(output.value))
            .ok_or_else(|| WalletError::Crypto("selected input value overflow".into()))?;

        let change_value = total_selected
            .checked_sub(required)
            .ok_or_else(|| WalletError::Crypto("selected value below spend requirement".into()))?;
        let (sender_change_output, pending_change, change_blinding) = if change_value > 0 {
            let change_blinding = BlindingFactor::random();
            let (proof, commitment_bytes) = bp_prove(change_value, &change_blinding)
                .map_err(|e| WalletError::Crypto(format!("change range proof failed: {e}")))?;
            let change_commitment = Commitment::from_compressed_bytes(&commitment_bytes)?;
            let pending_change = PendingChange {
                commitment: commitment_bytes,
                value: change_value,
                blinding: *change_blinding.as_bytes(),
            };
            (
                Some(OutputCommitmentAndProof {
                    commitment: change_commitment,
                    proof,
                }),
                Some(pending_change),
                Some(change_blinding),
            )
        } else {
            (None, None, None)
        };

        let sender_offset = BlindingFactor::random();
        let sender_excess_blinding =
            sender_excess_blinding(&selected, change_blinding.as_ref(), &sender_offset)?;
        let sender_excess_key = SecretKey::from_bytes(&sender_excess_blinding)
            .map_err(|e| WalletError::Crypto(format!("sender excess key invalid: {e}")))?;

        // Multisignature Schnorr nonces must be fresh CSPRNG output and
        // single-use. RFC6979-style deterministic nonces are unsafe here:
        // if a nonce is reused across aggregate-signing sessions, the
        // sender excess private key can be recovered. Persist this nonce
        // only in the encrypted wallet state and discard it after finalize.
        let sender_nonce_key = random_secret_key();
        let sender_nonce = sender_nonce_key.to_be_bytes_raw();

        let slate = Slate {
            version: 1,
            chain_id: self.chain_id,
            amount,
            fee,
            lock_height: 0,
            sender_inputs: selected
                .iter()
                .map(|output| Commitment::from_compressed_bytes(&output.commitment))
                .collect::<Result<Vec<_>, _>>()?,
            sender_change_output,
            sender_public_excess: sender_excess_key.public_key(),
            sender_public_nonce: sender_nonce_key.public_key(),
            sender_offset_contribution: *sender_offset.as_bytes(),
            recipient_output: None,
            recipient_public_excess: None,
            recipient_public_nonce: None,
            sender_partial_sig: None,
            recipient_partial_sig: None,
        };

        let slate_bytes = slate.to_bytes()?;
        let slate_hash = *dom_crypto::blake2b_256(&slate_bytes).as_bytes();

        self.record_journal(
            slate_hash,
            TxJournalEvent::Built {
                inputs: selected_commitments.clone(),
                tx_hex: None,
                output_count: u32::from(slate.sender_change_output.is_some()),
                fee_noms: fee,
                change: pending_change.clone(),
            },
        )?;

        for commitment in &selected_commitments {
            self.outputs.reserve(commitment, slate_hash)?;
        }

        self.pending_txs.insert(
            slate_hash,
            PendingTx {
                tx_hash: slate_hash,
                inputs: selected_commitments,
                tx_bytes: Vec::new(),
                change: pending_change,
                send_slate: Some(PendingSendSlate { slate_bytes }),
                send_slate_secrets: Some(PendingSendSlateSecrets {
                    sender_excess_blinding,
                    sender_nonce,
                }),
                receive_slate: None,
                receive_slate_secrets: None,
            },
        );

        self.save()?;
        info!("created pending send slate {}", hex::encode(slate_hash));
        Ok(slate)
    }

    /// Respond to a sender-created interactive Mimblewimble slate.
    ///
    /// This is step 2 of the slate protocol. It rejects cross-chain slates,
    /// creates the recipient output and range proof, generates a fresh
    /// single-use recipient nonce, signs the aggregate kernel message
    /// partially, persists only the recipient output blinding in encrypted
    /// wallet state, and returns a slate containing public response data.
    pub fn receive_slate(
        &mut self,
        slate: Slate,
        _current_height: u64,
    ) -> Result<Slate, WalletError> {
        if slate.chain_id != self.chain_id {
            return Err(WalletError::Crypto(
                "slate chain_id does not match wallet chain_id".into(),
            ));
        }
        if slate.recipient_output.is_some()
            || slate.recipient_public_excess.is_some()
            || slate.recipient_public_nonce.is_some()
            || slate.recipient_partial_sig.is_some()
        {
            return Err(WalletError::Crypto(
                "slate already contains recipient response fields".into(),
            ));
        }

        Amount::from_noms(slate.amount)
            .map_err(|e| WalletError::Crypto(format!("invalid slate amount: {e}")))?;
        Amount::from_noms(slate.fee)
            .map_err(|e| WalletError::Crypto(format!("invalid slate fee: {e}")))?;

        let recipient_blinding = BlindingFactor::random();
        let (proof, commitment_bytes) = bp_prove(slate.amount, &recipient_blinding)
            .map_err(|e| WalletError::Crypto(format!("recipient range proof failed: {e}")))?;
        let recipient_output = OutputCommitmentAndProof {
            commitment: Commitment::from_compressed_bytes(&commitment_bytes)?,
            proof,
        };
        let recipient_excess_key = SecretKey::from_bytes(recipient_blinding.as_bytes())
            .map_err(|e| WalletError::Crypto(format!("recipient excess key invalid: {e}")))?;
        let recipient_public_excess = recipient_excess_key.public_key();

        // Multisignature Schnorr nonces must be fresh CSPRNG output and
        // single-use. Deterministic/RFC6979 nonces are unsafe in aggregate
        // signing because nonce reuse across sessions leaks the signing key.
        // The recipient nonce is consumed immediately for s_R and is not
        // exported or persisted.
        let recipient_nonce_key = random_secret_key();
        let recipient_public_nonce = recipient_nonce_key.public_key();

        let agg_r = schnorr_add_public_keys(&[
            slate.sender_public_nonce.clone(),
            recipient_public_nonce.clone(),
        ])
        .map_err(|e| WalletError::Crypto(format!("aggregate nonce failed: {e}")))?;
        let agg_p = schnorr_add_public_keys(&[
            slate.sender_public_excess.clone(),
            recipient_public_excess.clone(),
        ])
        .map_err(|e| WalletError::Crypto(format!("aggregate public excess failed: {e}")))?;
        let kernel_message = plain_kernel_message(slate.fee, slate.lock_height)?;
        let recipient_partial_sig = schnorr_partial_sign(
            &recipient_excess_key,
            &recipient_nonce_key,
            &agg_r,
            &agg_p,
            &self.chain_id,
            kernel_message.as_bytes(),
        )
        .map_err(|e| WalletError::Crypto(format!("recipient partial signature failed: {e}")))?;

        let mut response = slate;
        response.recipient_output = Some(recipient_output);
        response.recipient_public_excess = Some(recipient_public_excess);
        response.recipient_public_nonce = Some(recipient_public_nonce);
        response.recipient_partial_sig = Some(recipient_partial_sig);

        let response_bytes = response.to_bytes()?;
        let slate_hash = *dom_crypto::blake2b_256(&response_bytes).as_bytes();
        self.pending_txs.insert(
            slate_hash,
            PendingTx {
                tx_hash: slate_hash,
                inputs: Vec::new(),
                tx_bytes: Vec::new(),
                change: None,
                send_slate: None,
                send_slate_secrets: None,
                receive_slate: Some(PendingReceiveSlate {
                    slate_bytes: response_bytes,
                }),
                receive_slate_secrets: Some(PendingReceiveSlateSecrets {
                    recipient_output_blinding: *recipient_blinding.as_bytes(),
                }),
            },
        );
        self.save()?;

        info!("created pending receive slate {}", hex::encode(slate_hash));
        Ok(response)
    }

    /// Build, reserve, and persist a single-party spend transaction.
    ///
    /// This legacy path remains for tests and non-interactive flows. Real
    /// wallet-to-wallet sends should use [`Wallet::create_send_slate`] once
    /// the full slate finalize path is available.
    pub fn build_spend(
        &mut self,
        recipient_commitment: Commitment,
        recipient_blinding: BlindingFactor,
        amount: u64,
        fee: u64,
        current_height: u64,
    ) -> Result<Transaction, WalletError> {
        // Construct then immediately reserve. The two-phase split exists so
        // callers that need to validate admissibility before committing the
        // reservation can call the phases separately (see
        // `build_spend_unreserved` / `reserve_built_spend`); this convenience
        // wrapper preserves the original construct-and-reserve behaviour.
        let built = self.build_spend_unreserved(
            recipient_commitment,
            recipient_blinding,
            amount,
            fee,
            current_height,
        )?;
        self.reserve_built_spend(&built)?;
        Ok(built.tx)
    }

    /// Phase 1 of a spend: select coins and build the transaction **without
    /// mutating wallet state** (no reservation, no pending entry, no save).
    ///
    /// Takes `&self` — it only reads the output index — so any failure here
    /// (insufficient funds, build error, serialization) leaves no funds
    /// reserved. Coin selection skips already-reserved outputs, so callers
    /// MUST hold the wallet lock continuously from this call through
    /// [`reserve_built_spend`] to avoid two concurrent spends selecting the
    /// same inputs.
    pub fn build_spend_unreserved(
        &self,
        _recipient_commitment: Commitment,
        recipient_blinding: BlindingFactor,
        amount: u64,
        fee: u64,
        current_height: u64,
    ) -> Result<BuiltSpend, WalletError> {
        debug!("building spend (unreserved): {} noms + {} fee", amount, fee);

        let required = amount.saturating_add(fee);

        // Coin selection (returns clones we can hand to the builder).
        let selected = self.outputs.select_for_spend_with_maturity(
            required,
            current_height,
            self.network.coinbase_maturity(),
        )?;
        let selected_commitments: Vec<[u8; 33]> = selected.iter().map(|o| o.commitment).collect();

        // Capture the total selected value BEFORE moving `selected` into
        // the builder. Greedy selection may overshoot `required`; the
        // surplus must be returned to ourselves as a change output, or
        // `SpendBuilder::build` rejects the tx as unbalanced
        // (inputs > outputs + fee).
        let total_selected: u64 = selected.iter().map(|o| o.value).sum();

        // Build transaction using dom_tx::SpendBuilder.
        let mut builder = SpendBuilder::new(&self.chain_id);
        builder.add_inputs(selected)?;
        builder.add_output(amount, recipient_blinding)?;
        builder.fee(fee);

        // Change = total_selected - amount - fee = total_selected - required.
        // Selection guarantees total_selected >= required, but use
        // checked_sub defensively. change == 0 means an exact spend: no
        // change output (and no PendingChange to register on confirm).
        let change_value = total_selected.saturating_sub(required);
        let pending_change = if change_value > 0 {
            // Change uses a fresh RANDOM blinding — it is NOT re-derivable
            // by scan_block (which only knows deterministic coinbase
            // blindings), so we persist it on the PendingTx and register
            // the output as spendable only at confirmation time.
            let change_blinding = BlindingFactor::random();
            // Commitment matches the on-chain output exactly: build()
            // commits each output as commit(value, blinding).
            let change_commitment = *Commitment::commit(change_value, &change_blinding).as_bytes();
            let change_blinding_bytes = *change_blinding.as_bytes();
            builder.add_output(change_value, change_blinding)?;
            Some(PendingChange {
                commitment: change_commitment,
                value: change_value,
                blinding: change_blinding_bytes,
            })
        } else {
            None
        };

        let tx = builder.build()?;

        // Compute tx_hash + canonical bytes once, here in the non-mutating
        // phase, so a serialization/hash failure can never leave a dangling
        // reservation behind.
        let tx_hash = compute_tx_hash(&tx)?;
        let tx_bytes = tx.to_bytes()?;

        Ok(BuiltSpend {
            tx,
            tx_hash,
            tx_bytes,
            selected_commitments,
            pending_change,
            fee,
        })
    }

    /// Phase 2 of a spend: reserve the inputs of an already-constructed
    /// [`BuiltSpend`] and persist the pending transaction.
    ///
    /// Mutates wallet state: appends a `Built` journal event, reserves each
    /// input, inserts the pending entry, and saves. Preserves WAL order
    /// (journal append BEFORE the in-memory mutation) so reconcile-on-open
    /// can reinstate the pending tx after a crash between append and save.
    pub fn reserve_built_spend(&mut self, built: &BuiltSpend) -> Result<(), WalletError> {
        // WAL ORDER: write the Built event to the journal FIRST,
        // before mutating any in-memory state.
        self.record_journal(
            built.tx_hash,
            TxJournalEvent::Built {
                inputs: built.selected_commitments.clone(),
                tx_hex: Some(hex::encode(&built.tx_bytes)),
                output_count: built.tx.outputs.len() as u32,
                fee_noms: built.fee,
                change: built.pending_change.clone(),
            },
        )?;

        // Reserve inputs.
        for commitment in &built.selected_commitments {
            self.outputs.reserve(commitment, built.tx_hash)?;
        }

        // Record pending transaction.
        self.pending_txs.insert(
            built.tx_hash,
            PendingTx {
                tx_hash: built.tx_hash,
                inputs: built.selected_commitments.clone(),
                tx_bytes: built.tx_bytes.clone(),
                change: built.pending_change.clone(),
                send_slate: None,
                send_slate_secrets: None,
                receive_slate: None,
                receive_slate_secrets: None,
            },
        );

        // Save wallet state.
        self.save()?;

        info!("created pending tx {}", hex::encode(built.tx_hash));
        Ok(())
    }

    /// Confirm a pending transaction (mark inputs as spent).
    pub fn confirm_tx(&mut self, tx_hash: [u8; 32]) -> Result<(), WalletError> {
        debug!("confirming tx {}", hex::encode(tx_hash));

        match self.pending_txs.remove(&tx_hash) {
            Some(pending) => {
                for commitment in pending.inputs {
                    self.outputs.mark_spent(&commitment)?;
                    self.outputs.release_reservation(&commitment)?;
                }
                self.save()?;
                info!("tx confirmed: {}", hex::encode(tx_hash));
                Ok(())
            }
            None => Err(WalletError::Io("pending tx not found".into())),
        }
    }

    /// Record that a previously built transaction has been handed off
    /// to a node or mempool. The pending reservation remains intact;
    /// only the journal state machine advances.
    pub fn mark_submitted(&mut self, tx_hash: [u8; 32]) -> Result<(), WalletError> {
        if !self.pending_txs.contains_key(&tx_hash) {
            return Err(WalletError::Io("pending tx not found".into()));
        }
        self.record_journal(tx_hash, TxJournalEvent::Submitted)?;
        Ok(())
    }

    /// Record that submission failed with an explicit operator-visible
    /// reason. The pending reservation remains in place so the wallet
    /// can survive restart and the operator can later cancel, replace,
    /// or resubmit deliberately.
    pub fn mark_failed(
        &mut self,
        tx_hash: [u8; 32],
        reason: impl Into<String>,
    ) -> Result<(), WalletError> {
        if !self.pending_txs.contains_key(&tx_hash) {
            return Err(WalletError::Io("pending tx not found".into()));
        }
        self.record_journal(
            tx_hash,
            TxJournalEvent::Failed {
                reason: reason.into(),
            },
        )?;
        Ok(())
    }

    /// Cancel a pending transaction (release reservations).
    pub fn cancel_tx(&mut self, tx_hash: [u8; 32]) -> Result<(), WalletError> {
        debug!("canceling tx {}", hex::encode(tx_hash));

        match self.pending_txs.get(&tx_hash).cloned() {
            Some(pending) => {
                // WAL: record Canceled in the journal before
                // releasing reservations / saving state.
                self.record_journal(tx_hash, TxJournalEvent::Canceled)?;
                for commitment in &pending.inputs {
                    self.outputs.release_reservation(commitment)?;
                }
                self.pending_txs.remove(&tx_hash);
                self.save()?;
                info!("tx canceled: {}", hex::encode(tx_hash));
                Ok(())
            }
            None => Err(WalletError::Io("pending tx not found".into())),
        }
    }

    /// Scan a block's transactions for coinbase outputs belonging to this wallet.
    ///
    /// For each coinbase transaction in the block, we re-derive the deterministic
    /// blinding factor (same derivation as build_coinbase) and check if the output
    /// commitment matches. If it does, the output is ours and we record it.
    ///
    /// This covers the mining reward recovery path: if the node restarts and the
    /// wallet is re-opened, scan_block on historical blocks recovers all coinbase
    /// outputs deterministically from the password alone.
    ///
    /// Non-coinbase outputs (received via Slatepack) are not yet scanned here —
    /// that requires interactive blinding factor exchange (Doc 7).
    pub fn scan_block(&mut self, transactions: &[Transaction], block_height: u64) {
        self.scan_block_with_hash(transactions, block_height, None);
    }

    /// Scan a canonical block with optional block-hash attribution.
    pub fn scan_block_with_hash(
        &mut self,
        transactions: &[Transaction],
        block_height: u64,
        block_hash: Option<[u8; 32]>,
    ) {
        use dom_core::BlockHeight;
        use dom_crypto::pedersen::Commitment;

        // Locked wallets cannot derive the coinbase seed. Silently
        // skip — scan_block is best-effort, called from relay/IBD
        // paths, and must not panic. The operator should unlock the
        // wallet to resume recovery scans.
        let Some(session) = self.session.as_ref() else {
            tracing::debug!(
                "scan_block: wallet is locked at height {block_height}; skipping recovery scan"
            );
            return;
        };

        let blinding = match self.coinbase_blinding_for_height(BlockHeight(block_height), session) {
            Ok(b) => b,
            Err(e) => {
                tracing::warn!(
                    "scan_block: blinding derivation failed at height {block_height}: {e}"
                );
                return;
            }
        };

        let total_fees = transactions.iter().try_fold(0u64, |acc, tx| {
            let fee = match tx.total_fee() {
                Ok(fee) => fee,
                Err(e) => {
                    tracing::warn!("scan_block: failed to compute transaction fee: {e}");
                    return None;
                }
            };
            match acc.checked_add(fee) {
                Some(total) => Some(total),
                None => {
                    tracing::warn!("scan_block: total fee overflow at height {block_height}");
                    None
                }
            }
        });

        // Compute the expected commitment for our coinbase at this height.
        // Re-derive the commitment the same way build_coinbase does and
        // compare directly. Try both the base reward and reward+fees so
        // historical zero-fee blocks and fee-bearing blocks both recover.
        for tx in transactions {
            for output in &tx.outputs {
                let commitment_bytes: [u8; 33] = *output.commitment.as_bytes();

                // Skip if we already have this output.
                if self.outputs.get(&commitment_bytes).is_some() {
                    continue;
                }

                let reward = dom_core::block_reward(BlockHeight(block_height)).noms();
                let reward_with_fees = total_fees.and_then(|fees| reward.checked_add(fees));
                let matched_value =
                    [Some(reward), reward_with_fees]
                        .into_iter()
                        .flatten()
                        .find(|value| {
                            *Commitment::commit(*value, &blinding).as_bytes() == commitment_bytes
                        });

                if let Some(value) = matched_value {
                    let mut owned = OwnedOutput::new(
                        commitment_bytes,
                        value,
                        *blinding.as_bytes(),
                        block_height,
                        true,
                    );
                    if let Some(hash) = block_hash {
                        owned = owned.with_block_hash(hash);
                    }
                    self.add_output(owned);
                    tracing::info!(
                        "scan_block: found output at height {block_height} value={value} noms"
                    );
                }
            }
        }
    }

    /// Apply a canonical block to wallet state.
    ///
    /// This is the replay-safe wallet hook for blocks that have already been
    /// accepted onto the best chain. It performs two deterministic actions:
    ///
    /// 1. Reconciles any pending spends whose reserved inputs are now consumed
    ///    by canonical transactions, clearing stale reservations after restart,
    ///    replay, or relay.
    /// 2. Scans the block for recoverable wallet outputs (currently deterministic
    ///    coinbase recovery only).
    ///
    /// Side-chain blocks MUST NOT be fed into this method.
    pub fn apply_canonical_block(
        &mut self,
        transactions: &[Transaction],
        block_height: u64,
    ) -> Result<(), WalletError> {
        self.apply_canonical_block_with_hash(transactions, block_height, None)
    }

    /// Apply a canonical block to wallet state with block-hash attribution.
    pub fn apply_canonical_block_with_hash(
        &mut self,
        transactions: &[Transaction],
        block_height: u64,
        block_hash: Option<[u8; 32]>,
    ) -> Result<(), WalletError> {
        let mut consumed_inputs = std::collections::HashSet::new();
        for tx in transactions {
            for input in &tx.inputs {
                consumed_inputs.insert(*input.commitment.as_bytes());
            }
        }

        if !consumed_inputs.is_empty() {
            let resolved: Vec<[u8; 32]> = self
                .pending_txs
                .iter()
                .filter_map(|(tx_hash, pending)| {
                    pending
                        .inputs
                        .iter()
                        .any(|commitment| consumed_inputs.contains(commitment))
                        .then_some(*tx_hash)
                })
                .collect();

            for tx_hash in resolved {
                // WAL ORDER: record Confirmed in the journal BEFORE
                // mutating output state. If we crash after the journal
                // append but before save, reconcile-on-open replays the
                // terminal status and cleans up the still-pending entry.
                self.record_journal(tx_hash, TxJournalEvent::Confirmed { block_height })?;
                if let Some(pending) = self.pending_txs.remove(&tx_hash) {
                    for commitment in &pending.inputs {
                        if consumed_inputs.contains(commitment) {
                            self.outputs.mark_spent(commitment)?;
                        }
                        self.outputs.release_reservation(commitment)?;
                    }
                    // The spend's self-change becomes spendable now that
                    // the tx is canonical. It carries a random blinding
                    // scan_block cannot recover, so register it explicitly
                    // from the persisted PendingChange. WAL order: this
                    // runs AFTER the Confirmed journal event above.
                    if let Some(c) = pending.change {
                        self.register_pending_change(c, block_height, block_hash);
                    }
                }
            }
        }

        self.scan_block_with_hash(transactions, block_height, block_hash);
        self.save()?;
        Ok(())
    }

    /// Remove a previously recorded output by commitment.
    ///
    /// Used by runtime recovery paths when a locally constructed tentative
    /// output never became canonical and must not remain in wallet state.
    pub fn forget_output(&mut self, commitment: &[u8; 33]) -> bool {
        let removed = self.outputs.remove(commitment).is_some();
        if removed {
            if let Err(e) = self.save() {
                tracing::warn!(
                    "wallet save failed after forgetting output {}: {e}",
                    hex::encode(commitment)
                );
            }
        }
        removed
    }

    /// Iterate over all wallet-owned outputs.
    pub fn outputs(&self) -> impl Iterator<Item = &OwnedOutput> {
        self.outputs.iter()
    }

    /// Borrow the persisted deterministic receive requests.
    pub fn receive_requests(&self) -> &[ReceiveRequest] {
        &self.receive_requests
    }

    /// Reconstruct validated receive descriptors from encrypted seed
    /// material and persisted request indexes.
    pub fn receive_descriptors(&self) -> Result<Vec<ReceiveRequestDescriptor>, WalletError> {
        self.receive_requests
            .iter()
            .map(|request| self.receive_descriptor_for_request(request))
            .collect()
    }

    /// Create and persist a deterministic fixed-amount receive
    /// request. This is the conservative V1 receive surface: the
    /// request is exact-amount and includes a deterministic blinding
    /// factor that the sender must use when building the output.
    pub fn create_receive_request(
        &mut self,
        amount: u64,
    ) -> Result<ReceiveRequestDescriptor, WalletError> {
        let _ = self.session()?;
        let index = self.keychain.next_receive_index;
        let blinding = self.receive_blinding_for_index(index)?;
        let commitment = Commitment::commit(amount, &blinding);
        let commitment_bytes = *commitment.as_bytes();
        let created_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let request = ReceiveRequest {
            index,
            amount,
            commitment: commitment_bytes,
            created_at,
            status: ReceiveRequestStatus::Pending,
        };
        self.receive_requests.push(request.clone());
        self.keychain.next_receive_index = self.keychain.next_receive_index.saturating_add(1);
        self.save()?;
        self.receive_descriptor_for_request(&request)
    }

    /// Update one receive request from an explicit canonical-chain
    /// observation. `None` means the commitment is absent from the
    /// node's current UTXO set, which may represent "not yet
    /// received" or a reorg rollback.
    pub fn update_receive_request_status(
        &mut self,
        commitment: &[u8; 33],
        observation: Option<ReceiveRequestStatus>,
    ) -> Result<bool, WalletError> {
        let Some(request) = self
            .receive_requests
            .iter_mut()
            .find(|request| &request.commitment == commitment)
        else {
            return Err(WalletError::OutputNotFound(hex::encode(commitment)));
        };

        let next_status = observation.unwrap_or(ReceiveRequestStatus::Pending);
        if request.status == next_status {
            return Ok(false);
        }

        request.status = next_status;
        self.save()?;
        Ok(true)
    }

    /// Get the chain id.
    pub fn chain_id(&self) -> &[u8; 32] {
        &self.chain_id
    }

    /// Get the network identifier.
    pub fn network(&self) -> Network {
        self.network
    }

    /// Build a coinbase transaction with a deterministic blinding factor.
    ///
    /// The blinding is derived as:
    /// ```text
    ///   password_seed = Blake2b-256-tagged("DOM:wallet-coinbase-seed:v1", password_bytes)
    ///   blinding      = Blake2b-256-tagged(TAG_COINBASE_BLINDING, password_seed || height_le8)
    /// ```
    ///
    /// This allows recovery of all historical coinbase blindings from the
    /// password alone, even if the on-disk output index is lost. Only the
    /// password and the list of mined heights are needed for full recovery.
    ///
    /// The resulting `OwnedOutput` is added to the wallet's output index, and
    /// the wallet is persisted to disk (if `file_path` is set).
    ///
    /// # Resolves
    ///
    /// **DOM-SEC-004 / TC-002 (HIGH)**: Previously the miner generated a fresh
    /// random `BlindingFactor` for each coinbase and discarded it after signing,
    /// making mining rewards consensus-valid but unspendable. This method
    /// derives the blinding deterministically and records the output in the
    /// wallet so the reward is fully spendable.
    pub fn build_coinbase(
        &mut self,
        height: BlockHeight,
        total_tx_fees: u64,
    ) -> Result<CoinbaseTransaction, WalletError> {
        use dom_crypto::bulletproof;
        use dom_crypto::keys::SecretKey;
        use dom_crypto::schnorr_sign;

        debug!(
            "building coinbase at height {} (fees: {} noms)",
            height.0, total_tx_fees
        );

        // build_coinbase needs the password to derive the deterministic
        // blinding factor. Locked wallets cannot mine — return Locked
        // and let the caller (typically the miner) decide whether to
        // skip this round or alert the operator.
        let session = self.session()?;

        // Step 1: Compute total value with overflow check.
        let reward = dom_core::block_reward(height).noms();
        let explicit_value = reward.checked_add(total_tx_fees).ok_or_else(|| {
            WalletError::Crypto("coinbase value overflow (reward + fees > u64::MAX)".into())
        })?;

        // Step 2: Derive deterministic blinding factor from either the
        // encrypted BIP-39 seed (preferred) or the legacy password-only
        // scheme for old wallets.
        let blinding = self.coinbase_blinding_for_height(height, session)?;

        // Step 4: Output commitment C = value*H + r*G
        let output_commitment = Commitment::commit(explicit_value, &blinding);
        // Save the 33-byte SEC1 representation before output_commitment is moved into the tx.
        let output_commitment_bytes: [u8; 33] = *output_commitment.as_bytes();

        // Step 5: Range proof (Bulletproofs+) proves value in [0, 2^52)
        let (range_proof, _) = bulletproof::prove(explicit_value, &blinding)
            .map_err(|e| WalletError::Crypto(format!("coinbase range proof: {e}")))?;

        // Step 6: Kernel excess = 0*H + r*G = r*G  (NOT same as output commitment!)
        let excess = Commitment::commit(0, &blinding);

        // Step 7: Kernel message = tag(TAG_KERNEL_MSG_COINBASE, features || value_le8)
        let kernel_message = {
            let mut data = Vec::with_capacity(9);
            data.push(KERNEL_FEAT_COINBASE);
            data.extend_from_slice(&explicit_value.to_le_bytes());
            blake2b_256_tagged(dom_core::TAG_KERNEL_MSG_COINBASE, &data)
        };

        // Step 8: Sign with blinding as secret key
        let sk = SecretKey::from_bytes(blinding.as_bytes())
            .map_err(|e| WalletError::Crypto(format!("coinbase blinding as key: {e}")))?;
        let signature = schnorr_sign(&sk, kernel_message.as_bytes(), &self.chain_id)
            .map_err(|e| WalletError::Crypto(format!("coinbase sign failed: {e}")))?;

        // Step 9: Build the coinbase transaction
        let coinbase_tx = CoinbaseTransaction {
            output: TransactionOutput {
                commitment: output_commitment,
                proof: range_proof.bytes,
            },
            kernel: CoinbaseKernel {
                features: KERNEL_FEAT_COINBASE,
                explicit_value,
                excess,
                excess_signature: signature.to_bytes(),
            },
            offset: [0u8; 32],
        };

        // Step 10: Record the output in the wallet (so reward is spendable)
        let owned_output = OwnedOutput::new(
            output_commitment_bytes,
            explicit_value,
            *blinding.as_bytes(),
            height.0,
            true, // is_coinbase
        );
        self.add_output(owned_output);

        // Step 11: Persist (best effort — blinding is deterministically recoverable)
        if let Err(e) = self.save() {
            tracing::warn!(
                "wallet save failed after building coinbase at height {}: {e:?}. \
                 Output is recoverable via deterministic blinding from password.",
                height.0
            );
        }

        info!(
            "coinbase built at height {}: value={} noms ({} reward + {} fees)",
            height.0, explicit_value, reward, total_tx_fees
        );

        Ok(coinbase_tx)
    }

    fn digest_parts<'a, I>(
        outputs: I,
        pending_txs: &HashMap<[u8; 32], PendingTx>,
        receive_requests: &[ReceiveRequest],
    ) -> [u8; 32]
    where
        I: IntoIterator<Item = &'a OwnedOutput>,
    {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"wallet-canonical-digest-v1");

        let mut outputs_sorted: Vec<&OwnedOutput> = outputs.into_iter().collect();
        outputs_sorted.sort_by_key(|output| output.commitment);
        bytes.extend_from_slice(&(outputs_sorted.len() as u64).to_le_bytes());
        for output in outputs_sorted {
            bytes.extend_from_slice(&output.commitment);
            bytes.extend_from_slice(&output.value.to_le_bytes());
            bytes.extend_from_slice(&output.block_height.to_le_bytes());
            match output.block_hash {
                Some(hash) => {
                    bytes.push(1);
                    bytes.extend_from_slice(&hash);
                }
                None => bytes.push(0),
            }
            bytes.push(u8::from(output.is_coinbase));
            bytes.push(u8::from(output.spent));
            match output.reserved_for_tx {
                Some(tx_hash) => {
                    bytes.push(1);
                    bytes.extend_from_slice(&tx_hash);
                }
                None => bytes.push(0),
            }
        }

        let mut pending_sorted: Vec<(&[u8; 32], &PendingTx)> = pending_txs.iter().collect();
        pending_sorted.sort_by_key(|(tx_hash, _)| **tx_hash);
        bytes.extend_from_slice(&(pending_sorted.len() as u64).to_le_bytes());
        for (tx_hash, pending) in pending_sorted {
            bytes.extend_from_slice(tx_hash);
            let mut inputs = pending.inputs.clone();
            inputs.sort();
            bytes.extend_from_slice(&(inputs.len() as u64).to_le_bytes());
            for input in inputs {
                bytes.extend_from_slice(&input);
            }
            bytes.extend_from_slice(&(pending.tx_bytes.len() as u64).to_le_bytes());
            bytes.extend_from_slice(&pending.tx_bytes);
            match &pending.change {
                Some(change) => {
                    bytes.push(1);
                    bytes.extend_from_slice(&change.commitment);
                    bytes.extend_from_slice(&change.value.to_le_bytes());
                    bytes.extend_from_slice(&change.blinding);
                }
                None => bytes.push(0),
            }
            match &pending.send_slate {
                Some(send_slate) => {
                    bytes.push(1);
                    bytes.extend_from_slice(&(send_slate.slate_bytes.len() as u64).to_le_bytes());
                    bytes.extend_from_slice(&send_slate.slate_bytes);
                }
                None => bytes.push(0),
            }
            match &pending.send_slate_secrets {
                Some(secrets) => {
                    bytes.push(1);
                    bytes.extend_from_slice(&secrets.sender_excess_blinding);
                    bytes.extend_from_slice(&secrets.sender_nonce);
                }
                None => bytes.push(0),
            }
            match &pending.receive_slate {
                Some(receive_slate) => {
                    bytes.push(1);
                    bytes
                        .extend_from_slice(&(receive_slate.slate_bytes.len() as u64).to_le_bytes());
                    bytes.extend_from_slice(&receive_slate.slate_bytes);
                }
                None => bytes.push(0),
            }
            match &pending.receive_slate_secrets {
                Some(secrets) => {
                    bytes.push(1);
                    bytes.extend_from_slice(&secrets.recipient_output_blinding);
                }
                None => bytes.push(0),
            }
        }

        let mut receives_sorted: Vec<&ReceiveRequest> = receive_requests.iter().collect();
        receives_sorted.sort_by_key(|request| request.commitment);
        bytes.extend_from_slice(&(receives_sorted.len() as u64).to_le_bytes());
        for request in receives_sorted {
            bytes.extend_from_slice(&request.index.to_le_bytes());
            bytes.extend_from_slice(&request.amount.to_le_bytes());
            bytes.extend_from_slice(&request.commitment);
            match &request.status {
                ReceiveRequestStatus::Pending => bytes.push(0),
                ReceiveRequestStatus::Detected {
                    block_height,
                    is_coinbase,
                    is_mature,
                } => {
                    bytes.push(1);
                    bytes.extend_from_slice(&block_height.to_le_bytes());
                    bytes.push(u8::from(*is_coinbase));
                    bytes.push(u8::from(*is_mature));
                }
            }
        }

        *blake2b_256_tagged("DOM:wallet-canonical-digest:v1", &bytes).as_bytes()
    }
}

fn scan_error_to_wallet(err: RestoreError) -> WalletError {
    match err {
        RestoreError::ScanError { height, message } => WalletError::Io(format!(
            "canonical rescan failed at height {height}: {message}"
        )),
        other => WalletError::Io(format!("canonical rescan failed: {other}")),
    }
}

fn plain_kernel_message(fee: u64, lock_height: u64) -> Result<Hash256, WalletError> {
    Amount::from_noms(fee).map_err(|e| WalletError::Crypto(format!("invalid kernel fee: {e}")))?;
    let mut data = Vec::with_capacity(1 + 8 + 8);
    data.push(KERNEL_FEAT_PLAIN);
    data.extend_from_slice(&fee.to_le_bytes());
    data.extend_from_slice(&lock_height.to_le_bytes());
    Ok(blake2b_256_tagged(dom_core::TAG_KERNEL_MSG, &data))
}

fn sender_excess_blinding(
    selected_inputs: &[OwnedOutput],
    change_blinding: Option<&BlindingFactor>,
    sender_offset: &BlindingFactor,
) -> Result<[u8; 32], WalletError> {
    let mut acc = Scalar::ZERO;

    if let Some(change_blinding) = change_blinding {
        acc += scalar_from_bytes(change_blinding.as_bytes())?;
    }
    for input in selected_inputs {
        acc -= scalar_from_bytes(&input.blinding)?;
    }
    acc -= scalar_from_bytes(sender_offset.as_bytes())?;

    if bool::from(acc.is_zero()) {
        return Err(WalletError::Crypto(
            "sender excess blinding unexpectedly became zero".into(),
        ));
    }

    Ok(acc.to_repr().into())
}

fn scalar_from_bytes(bytes: &[u8; 32]) -> Result<Scalar, WalletError> {
    let repr = k256::FieldBytes::from(*bytes);
    let scalar = Scalar::from_repr(repr);
    if scalar.is_some().into() {
        Ok(scalar.unwrap())
    } else {
        Err(WalletError::Crypto("invalid scalar bytes".into()))
    }
}

fn random_secret_key() -> SecretKey {
    let mut bytes = [0u8; 32];
    loop {
        rand::thread_rng().fill_bytes(&mut bytes);
        if let Ok(secret_key) = SecretKey::from_bytes(&bytes) {
            return secret_key;
        }
    }
}

/// Compute the canonical transaction hash used for wallet-mempool
/// cross-lookup.
///
/// This is the mempool-aligned hash: `blake2b_256(tx.to_bytes())`
/// with NO tag prefix. It matches the hash that
/// `dom-node::node_handle::submit_tx` and the mempool compute on the
/// same transaction bytes, so a wallet pending tx and its mempool
/// entry share one identifier.
///
/// **Phase 1.7 unification:** prior to this commit the wallet used
/// `blake2b_256_tagged("DOM:tx-hash:v1", bytes)`, producing a
/// distinct keyspace from the mempool. That divergence meant the
/// wallet could not look up its own pending tx by the mempool hash
/// returned from `submit_tx`. Switching to the un-tagged hash
/// unifies the keyspaces — same input bytes, same hash, everywhere.
fn compute_tx_hash(tx: &Transaction) -> Result<[u8; 32], WalletError> {
    let bytes = tx.to_bytes()?;
    Ok(*dom_crypto::blake2b_256(&bytes).as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn fixed_output(value: u64, height: u64, blinding_byte: u8) -> OwnedOutput {
        let blinding = BlindingFactor::from_bytes([blinding_byte; 32]).unwrap();
        let commitment = Commitment::commit(value, &blinding);
        OwnedOutput::new(
            *commitment.as_bytes(),
            value,
            *blinding.as_bytes(),
            height,
            false,
        )
    }

    fn bytes_contain(haystack: &[u8], needle: &[u8; 32]) -> bool {
        haystack
            .windows(needle.len())
            .any(|window| window == needle)
    }

    #[test]
    fn create_send_slate_reserves_inputs_and_keeps_secrets_out_of_slate() {
        let mut wallet = Wallet::new_in_memory(Network::Testnet, &Hash256::from_bytes([7u8; 32]));
        let input = fixed_output(1_000, 100, 3);
        let input_commitment = input.commitment;
        let input_blinding = *input.blinding;
        wallet.add_output(input);

        let slate = wallet.create_send_slate(900, 100, 2_000).unwrap();
        let slate_bytes = slate.to_bytes().unwrap();
        let slate_hash = *dom_crypto::blake2b_256(&slate_bytes).as_bytes();

        assert_eq!(slate.amount, 900);
        assert_eq!(slate.fee, 100);
        assert_eq!(slate.chain_id, *wallet.chain_id());
        assert_eq!(slate.sender_inputs.len(), 1);
        assert!(slate.sender_change_output.is_none());
        assert!(slate.recipient_output.is_none());
        assert!(slate.recipient_public_excess.is_none());
        assert!(slate.recipient_public_nonce.is_none());
        assert!(slate.sender_partial_sig.is_none());
        assert!(slate.recipient_partial_sig.is_none());

        assert_eq!(
            wallet
                .outputs
                .get(&input_commitment)
                .unwrap()
                .reserved_for_tx,
            Some(slate_hash)
        );
        assert!(wallet.pending_txs.contains_key(&slate_hash));

        let pending = wallet.pending_txs.get(&slate_hash).unwrap();
        let secrets = pending.send_slate_secrets.as_ref().unwrap();
        assert!(pending.send_slate.is_some());
        assert!(!bytes_contain(&slate_bytes, &input_blinding));
        assert!(!bytes_contain(
            &slate_bytes,
            &secrets.sender_excess_blinding
        ));
        assert!(!bytes_contain(&slate_bytes, &secrets.sender_nonce));
    }

    #[test]
    fn create_send_slate_uses_fresh_random_nonce_each_time() {
        let mut wallet = Wallet::new_in_memory(Network::Testnet, &Hash256::from_bytes([8u8; 32]));
        wallet.add_output(fixed_output(1_000, 100, 4));
        wallet.add_output(fixed_output(1_000, 101, 5));

        let first = wallet.create_send_slate(900, 100, 2_000).unwrap();
        let second = wallet.create_send_slate(900, 100, 2_000).unwrap();

        assert_ne!(
            first.sender_public_nonce.to_compressed_bytes(),
            second.sender_public_nonce.to_compressed_bytes(),
            "sender nonce public keys must differ across slates"
        );
    }

    fn sender_slate_for_receive() -> Slate {
        let mut sender = Wallet::new_in_memory(Network::Testnet, &Hash256::from_bytes([9u8; 32]));
        sender.add_output(fixed_output(1_000, 100, 6));
        sender.create_send_slate(900, 100, 2_000).unwrap()
    }

    #[test]
    fn receive_slate_rejects_wrong_chain_id() {
        let slate = sender_slate_for_receive();
        let mut receiver = Wallet::new_in_memory(Network::Mainnet, &Hash256::from_bytes([9u8; 32]));

        let err = receiver.receive_slate(slate, 2_000).unwrap_err();
        assert!(
            err.to_string().contains("chain_id"),
            "expected chain_id mismatch error, got {err:?}"
        );
    }

    #[test]
    fn receive_slate_populates_recipient_fields_and_preserves_sender_fields() {
        let slate = sender_slate_for_receive();
        let mut receiver = Wallet::new_in_memory(Network::Testnet, &Hash256::from_bytes([9u8; 32]));

        let response = receiver.receive_slate(slate.clone(), 2_000).unwrap();

        assert_eq!(response.version, slate.version);
        assert_eq!(response.chain_id, slate.chain_id);
        assert_eq!(response.amount, slate.amount);
        assert_eq!(response.fee, slate.fee);
        assert_eq!(response.lock_height, slate.lock_height);
        assert_eq!(response.sender_inputs, slate.sender_inputs);
        assert_eq!(response.sender_change_output, slate.sender_change_output);
        assert_eq!(response.sender_public_excess, slate.sender_public_excess);
        assert_eq!(response.sender_public_nonce, slate.sender_public_nonce);
        assert_eq!(
            response.sender_offset_contribution,
            slate.sender_offset_contribution
        );
        assert_eq!(response.sender_partial_sig, slate.sender_partial_sig);

        assert!(response.recipient_output.is_some());
        assert!(response.recipient_public_excess.is_some());
        assert!(response.recipient_public_nonce.is_some());
        assert!(response.recipient_partial_sig.is_some());
    }

    #[test]
    fn receive_slate_keeps_recipient_blinding_out_of_slate_bytes() {
        let slate = sender_slate_for_receive();
        let mut receiver = Wallet::new_in_memory(Network::Testnet, &Hash256::from_bytes([9u8; 32]));

        let response = receiver.receive_slate(slate, 2_000).unwrap();
        let response_bytes = response.to_bytes().unwrap();
        let response_hash = *dom_crypto::blake2b_256(&response_bytes).as_bytes();
        let pending = receiver.pending_txs.get(&response_hash).unwrap();
        let secrets = pending.receive_slate_secrets.as_ref().unwrap();

        assert!(pending.receive_slate.is_some());
        assert!(!bytes_contain(
            &response_bytes,
            &secrets.recipient_output_blinding
        ));
    }

    #[test]
    fn receive_slate_uses_fresh_random_nonce_each_time() {
        let slate = sender_slate_for_receive();
        let mut receiver = Wallet::new_in_memory(Network::Testnet, &Hash256::from_bytes([9u8; 32]));

        let first = receiver.receive_slate(slate.clone(), 2_000).unwrap();
        let second = receiver.receive_slate(slate, 2_000).unwrap();

        assert_ne!(
            first
                .recipient_public_nonce
                .as_ref()
                .unwrap()
                .to_compressed_bytes(),
            second
                .recipient_public_nonce
                .as_ref()
                .unwrap()
                .to_compressed_bytes(),
            "recipient nonce public keys must differ across responses"
        );
    }

    fn wallet_with_pending_cancel(journal_root: &Path) -> (Wallet, [u8; 32], [u8; 33]) {
        let tx_hash = [3u8; 32];
        let blinding = BlindingFactor::random();
        let commitment = *Commitment::commit(20, &blinding).as_bytes();
        let mut output = OwnedOutput::new(commitment, 20, *blinding.as_bytes(), 0, false);
        output.reserved_for_tx = Some(tx_hash);

        let mut outputs = OutputIndex::new();
        outputs.insert(output);

        let mut pending_txs = HashMap::new();
        pending_txs.insert(
            tx_hash,
            PendingTx {
                tx_hash,
                inputs: vec![commitment],
                tx_bytes: vec![0xab],
                change: None,
                send_slate: None,
                send_slate_secrets: None,
                receive_slate: None,
                receive_slate_secrets: None,
            },
        );

        let mut wallet = Wallet {
            network: Network::Regtest,
            chain_id: [1u8; 32],
            outputs,
            pending_txs,
            receive_requests: Vec::new(),
            keychain: WalletKeychainState::legacy(),
            file_path: None,
            session: None,
            journal: None,
        };
        wallet.attach_journal(TxJournal::open(journal_root).unwrap());
        (wallet, tx_hash, commitment)
    }

    #[test]
    fn cancel_tx_keeps_memory_state_when_journal_append_fails() {
        let dir = tempdir().unwrap();
        let not_a_dir = dir.path().join("not-a-dir");
        std::fs::write(&not_a_dir, b"not a directory").unwrap();
        let (mut wallet, tx_hash, commitment) = wallet_with_pending_cancel(&not_a_dir);

        let result = wallet.cancel_tx(tx_hash);

        assert!(result.is_err());
        assert!(wallet.pending_txs.contains_key(&tx_hash));
        assert_eq!(
            wallet.outputs.get(&commitment).unwrap().reserved_for_tx,
            Some(tx_hash)
        );
    }

    #[test]
    fn cancel_tx_updates_memory_state_when_journal_append_succeeds() {
        let dir = tempdir().unwrap();
        let (mut wallet, tx_hash, commitment) = wallet_with_pending_cancel(dir.path());

        wallet.cancel_tx(tx_hash).unwrap();

        assert!(!wallet.pending_txs.contains_key(&tx_hash));
        assert_eq!(
            wallet.outputs.get(&commitment).unwrap().reserved_for_tx,
            None
        );
        let journal_bytes = std::fs::read(wallet.journal().unwrap().path()).unwrap();
        assert!(!journal_bytes.is_empty());
        assert!(String::from_utf8(journal_bytes)
            .unwrap()
            .contains("canceled"));
    }
}
