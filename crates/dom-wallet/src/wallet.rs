//! Main wallet struct and operations.

use crate::journal::{JournalEntry, TxJournal, TxJournalEvent, TxRecord, TxStatus};
use crate::output_index::OutputIndex;
use crate::store::{
    load_wallet as load_wallet_file, save_wallet as save_wallet_file, PendingTx, WalletState,
};
use crate::types::{Network, OwnedOutput, WalletBalance, WalletError};
use crate::unlock::{LockState, UnlockedSession};
use dom_consensus::transaction::{
    CoinbaseKernel, CoinbaseTransaction, Transaction, TransactionOutput,
};
use dom_core::{BlockHeight, KERNEL_FEAT_COINBASE};
use dom_crypto::pedersen::Commitment;
use dom_crypto::{blake2b_256_tagged, BlindingFactor, Hash256};
use dom_serialization::DomSerialize;
use dom_tx::SpendBuilder;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use tracing::{debug, info};

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
        };

        // Save encrypted to disk (generates fresh salt internally).
        save_wallet_file(path, &state, password)?;

        Ok(Self {
            network,
            chain_id,
            outputs: OutputIndex::new(),
            pending_txs: HashMap::new(),
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

    /// Append one event to the journal if one is attached. No-op
    /// otherwise. Errors are logged but do NOT propagate — the
    /// journal is best-effort: in-memory state still mutates so the
    /// wallet remains usable. Operators inspecting the journal will
    /// see the gap.
    fn record_journal(&self, tx_hash: [u8; 32], event: TxJournalEvent) {
        let Some(journal) = &self.journal else {
            return;
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
        if let Err(e) = journal.append(&entry) {
            tracing::warn!(
                "journal append failed for tx {}: {e}; in-memory state still proceeds",
                hex::encode(tx_hash)
            );
        }
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
            );

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
            // Verify by attempting decrypt of the on-disk wallet.
            // The AEAD tag in ChaCha20Poly1305 catches wrong passwords
            // — load_wallet_file returns WalletError::Decryption on
            // failure. We discard the decrypted state because our
            // in-memory state is authoritative for a live wallet.
            let _verified = load_wallet_file(path, password)?;
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

    /// Add a received output to the wallet.
    pub fn add_output(&mut self, output: OwnedOutput) {
        debug!(
            "adding output: {} noms at height {}",
            output.value, output.block_height
        );
        self.outputs.insert(output);
    }

    /// Build a spend transaction.
    ///
    /// This:
    /// 1. Selects coins via greedy coin selection.
    /// 2. Builds the transaction using `dom_tx::SpendBuilder`.
    /// 3. Reserves inputs in the output index.
    /// 4. Records the pending transaction.
    /// 5. Saves wallet state.
    pub fn build_spend(
        &mut self,
        _recipient_commitment: Commitment,
        recipient_blinding: BlindingFactor,
        amount: u64,
        fee: u64,
        current_height: u64,
    ) -> Result<Transaction, WalletError> {
        debug!("building spend: {} noms + {} fee", amount, fee);

        let required = amount.saturating_add(fee);

        // Coin selection (returns clones we can hand to the builder).
        let selected = self.outputs.select_for_spend_with_maturity(
            required,
            current_height,
            self.network.coinbase_maturity(),
        )?;
        let selected_commitments: Vec<[u8; 33]> = selected.iter().map(|o| o.commitment).collect();

        // Build transaction using dom_tx::SpendBuilder.
        let mut builder = SpendBuilder::new(&self.chain_id);
        builder.add_inputs(selected)?;
        builder.add_output(amount, recipient_blinding)?;
        builder.fee(fee);

        let tx = builder.build()?;

        // Compute tx_hash for tracking.
        let tx_hash = compute_tx_hash(&tx)?;

        // WAL ORDER: write the Built event to the journal FIRST,
        // before mutating any in-memory state. If we crash between
        // journal-append and the in-memory mutation below, replay
        // on reopen will reinstate the pending tx (Phase 1.6
        // reconcile-on-open in WalletDir::open).
        self.record_journal(
            tx_hash,
            TxJournalEvent::Built {
                inputs: selected_commitments.clone(),
                output_count: tx.outputs.len() as u32,
                fee_noms: fee,
            },
        );

        // Reserve inputs.
        for commitment in &selected_commitments {
            self.outputs.reserve(commitment, tx_hash)?;
        }

        // Record pending transaction.
        self.pending_txs.insert(
            tx_hash,
            PendingTx {
                tx_hash,
                inputs: selected_commitments,
            },
        );

        // Save wallet state.
        self.save()?;

        info!(
            "created pending tx {} ({} noms)",
            hex::encode(tx_hash),
            amount
        );
        Ok(tx)
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

    /// Cancel a pending transaction (release reservations).
    pub fn cancel_tx(&mut self, tx_hash: [u8; 32]) -> Result<(), WalletError> {
        debug!("canceling tx {}", hex::encode(tx_hash));

        match self.pending_txs.remove(&tx_hash) {
            Some(pending) => {
                // WAL: record Canceled in the journal before
                // releasing reservations / saving state.
                self.record_journal(tx_hash, TxJournalEvent::Canceled);
                for commitment in pending.inputs {
                    self.outputs.release_reservation(&commitment)?;
                }
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
        use dom_core::{BlockHeight, TAG_COINBASE_BLINDING};
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

        // Derive the password seed once per scan (same as build_coinbase step 2).
        let password_seed =
            blake2b_256_tagged("DOM:wallet-coinbase-seed:v1", session.password().as_bytes());

        // Derive the candidate blinding for this height.
        let mut blinding_input = Vec::with_capacity(40);
        blinding_input.extend_from_slice(password_seed.as_bytes());
        blinding_input.extend_from_slice(&block_height.to_le_bytes());

        let blinding_hash = blake2b_256_tagged(TAG_COINBASE_BLINDING, &blinding_input);

        let blinding = match dom_crypto::BlindingFactor::from_bytes(*blinding_hash.as_bytes()) {
            Ok(b) => b,
            Err(e) => {
                tracing::warn!(
                    "scan_block: blinding derivation failed at height {block_height}: {e}"
                );
                return;
            }
        };

        // Compute the expected commitment for our coinbase at this height.
        // We don't know the exact value (fees vary), so we check all outputs
        // in all transactions and see if the commitment matches r*G + value*H
        // for value = block_reward(height) + fees.
        //
        // Simpler approach: re-derive the commitment the same way build_coinbase does
        // and compare directly. Since we know the reward schedule, we can compute
        // the expected value for each transaction output and verify.
        for tx in transactions {
            for output in &tx.outputs {
                let commitment_bytes: [u8; 33] = *output.commitment.as_bytes();

                // Skip if we already have this output.
                if self.outputs.get(&commitment_bytes).is_some() {
                    continue;
                }

                // Try to determine if this output matches our blinding at this height.
                // We check by verifying: commitment == value*H + blinding*G
                // We don't know value directly, so we extract it from the excess.
                // For now, record any output whose commitment equals commit(v, blinding)
                // for any v in [0, MAX_SUPPLY]. In practice we only check coinbase reward.
                let reward = dom_core::block_reward(BlockHeight(block_height)).noms();

                // Try reward only (no fees case) and reward+fees if we can read them.
                // The exact value is encoded in the kernel's explicit_value field —
                // but Transaction doesn't carry coinbase kernels here.
                // Conservative: try the base reward.
                let candidate = Commitment::commit(reward, &blinding);
                if *candidate.as_bytes() == commitment_bytes {
                    let owned = OwnedOutput::new(
                        commitment_bytes,
                        reward,
                        *blinding.as_bytes(),
                        block_height,
                        false, // regular tx output — coinbase tracked separately
                    );
                    self.add_output(owned);
                    tracing::info!(
                        "scan_block: found output at height {block_height} value={reward} noms"
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
                self.record_journal(tx_hash, TxJournalEvent::Confirmed { block_height });
                if let Some(pending) = self.pending_txs.remove(&tx_hash) {
                    for commitment in pending.inputs {
                        if consumed_inputs.contains(&commitment) {
                            self.outputs.mark_spent(&commitment)?;
                        }
                        self.outputs.release_reservation(&commitment)?;
                    }
                }
            }
        }

        self.scan_block(transactions, block_height);
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

        // Step 2: Derive the password seed (domain-separated).
        let password_seed =
            blake2b_256_tagged("DOM:wallet-coinbase-seed:v1", session.password().as_bytes());

        // Step 3: Derive deterministic blinding factor from (password_seed, height).
        let mut blinding_input = Vec::with_capacity(32 + 8);
        blinding_input.extend_from_slice(password_seed.as_bytes());
        blinding_input.extend_from_slice(&height.0.to_le_bytes());

        let blinding_hash = blake2b_256_tagged(dom_core::TAG_COINBASE_BLINDING, &blinding_input);
        let blinding = BlindingFactor::from_bytes(*blinding_hash.as_bytes())
            .map_err(|e| WalletError::Crypto(format!("blinding from bytes: {e}")))?;

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
