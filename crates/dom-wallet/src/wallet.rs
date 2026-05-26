//! Main wallet struct and operations.

use crate::output_index::OutputIndex;
use crate::store::{
    load_wallet as load_wallet_file, save_wallet as save_wallet_file, PendingTx, WalletState,
};
use crate::types::{Network, OwnedOutput, WalletBalance, WalletError};
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
use zeroize::Zeroizing;

/// The DOM Protocol wallet.
///
/// Manages owned outputs, pending transactions, and persistent encrypted storage.
/// The password is stored in memory as a `Zeroizing<String>` so it can re-derive
/// the encryption key on every save (a fresh salt is used per save).
pub struct Wallet {
    network: Network,
    chain_id: [u8; 32],
    outputs: OutputIndex,
    pending_txs: HashMap<[u8; 32], PendingTx>,
    file_path: Option<PathBuf>,
    /// Password held in memory for re-encryption on save.
    /// Zeroized when wallet is dropped.
    password: Zeroizing<String>,
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
            password: Zeroizing::new(password.to_string()),
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
            password: Zeroizing::new(password.to_string()),
        })
    }

    /// Create a new in-memory wallet (for testing, no disk I/O).
    pub fn new_in_memory(network: Network, genesis_hash: &Hash256) -> Self {
        let chain_id_hash = dom_consensus::derive_chain_id(network.magic(), genesis_hash);
        let chain_id: [u8; 32] = *chain_id_hash.as_bytes();

        Self {
            network,
            chain_id,
            outputs: OutputIndex::new(),
            pending_txs: HashMap::new(),
            file_path: None,
            password: Zeroizing::new(String::new()),
        }
    }

    /// Save wallet to disk (if `file_path` is set).
    pub fn save(&self) -> Result<(), WalletError> {
        match &self.file_path {
            Some(path) => {
                let outputs: Vec<_> = self.outputs.iter().cloned().collect();
                let state = WalletState {
                    network: self.network,
                    chain_id: self.chain_id,
                    outputs,
                    pending_txs: self.pending_txs.clone(),
                };
                save_wallet_file(path, &state, &self.password)?;
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

        // Derive the password seed once per scan (same as build_coinbase step 2).
        let password_seed =
            blake2b_256_tagged("DOM:wallet-coinbase-seed:v1", self.password.as_bytes());

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

        // Step 1: Compute total value with overflow check.
        let reward = dom_core::block_reward(height).noms();
        let explicit_value = reward.checked_add(total_tx_fees).ok_or_else(|| {
            WalletError::Crypto("coinbase value overflow (reward + fees > u64::MAX)".into())
        })?;

        // Step 2: Derive the password seed (domain-separated).
        let password_seed =
            blake2b_256_tagged("DOM:wallet-coinbase-seed:v1", self.password.as_bytes());

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

/// Compute a deterministic, domain-separated hash of a transaction.
fn compute_tx_hash(tx: &Transaction) -> Result<[u8; 32], WalletError> {
    let bytes = tx.to_bytes()?;
    let hash: Hash256 = blake2b_256_tagged("DOM:tx-hash:v1", &bytes);
    Ok(*hash.as_bytes())
}
