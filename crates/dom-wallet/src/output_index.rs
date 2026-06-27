//! In-memory UTXO index with coin selection.

use crate::types::{OwnedOutput, WalletError};
use std::collections::HashMap;
use tracing::debug;

/// In-memory index of wallet outputs for fast lookup and coin selection.
pub struct OutputIndex {
    /// All outputs indexed by commitment.
    outputs: HashMap<[u8; 33], OwnedOutput>,
}

impl OutputIndex {
    /// Create a new empty index.
    pub fn new() -> Self {
        Self {
            outputs: HashMap::new(),
        }
    }

    /// Add an output to the index.
    pub fn insert(&mut self, output: OwnedOutput) {
        self.outputs.insert(output.commitment, output);
    }

    /// Get an output by commitment.
    pub fn get(&self, commitment: &[u8; 33]) -> Option<&OwnedOutput> {
        self.outputs.get(commitment)
    }

    /// Get a mutable reference to an output.
    pub fn get_mut(&mut self, commitment: &[u8; 33]) -> Option<&mut OwnedOutput> {
        self.outputs.get_mut(commitment)
    }

    /// Iterator over all outputs.
    pub fn iter(&self) -> impl Iterator<Item = &OwnedOutput> {
        self.outputs.values()
    }

    /// Select outputs for spending using greedy coin selection, applying
    /// the canonical `COINBASE_MATURITY` (mainnet/testnet) rule.
    ///
    /// Wallets running on `Network::Regtest` MUST call
    /// `select_for_spend_with_maturity` so the relaxed threshold is used.
    pub fn select_for_spend(
        &self,
        amount_needed: u64,
        current_height: u64,
    ) -> Result<Vec<OwnedOutput>, WalletError> {
        self.select_for_spend_with_maturity(
            amount_needed,
            current_height,
            dom_core::COINBASE_MATURITY,
        )
    }

    /// Like `select_for_spend` but the caller supplies the maturity
    /// threshold (typically `Network::coinbase_maturity()`).
    ///
    /// Filters by:
    /// - Not spent
    /// - Not reserved
    /// - Mature under `maturity` (non-coinbase outputs always mature)
    ///
    /// Returns outputs sorted by value (descending) and selected greedily until sum >= amount_needed.
    pub fn select_for_spend_with_maturity(
        &self,
        amount_needed: u64,
        current_height: u64,
        maturity: u64,
    ) -> Result<Vec<OwnedOutput>, WalletError> {
        // Collect spendable outputs.
        let mut spendable: Vec<_> = self
            .outputs
            .values()
            .filter(|o| o.is_spendable_for(current_height, maturity))
            .collect();

        // Sort by value descending (prefer larger outputs first).
        spendable.sort_by_key(|b| std::cmp::Reverse(b.value));
        // Greedy selection.
        let mut selected = Vec::new();
        let mut sum = 0u64;

        for output in spendable {
            if sum >= amount_needed {
                break;
            }
            selected.push(output.clone());
            sum = sum
                .checked_add(output.value)
                .ok_or_else(|| WalletError::Crypto("coin selection sum overflow".into()))?;
        }

        if sum < amount_needed {
            return Err(WalletError::InsufficientFunds {
                have: sum,
                need: amount_needed,
            });
        }

        debug!("selected {} outputs totaling {} noms", selected.len(), sum);
        Ok(selected)
    }

    /// Mark an output as spent.
    pub fn mark_spent(&mut self, commitment: &[u8; 33]) -> Result<(), WalletError> {
        match self.outputs.get_mut(commitment) {
            Some(output) => {
                output.spent = true;
                Ok(())
            }
            None => Err(WalletError::OutputNotFound(format!(
                "commitment {:?}",
                hex::encode(commitment)
            ))),
        }
    }

    /// Mark an output as unspent (for reverting after tx cancellation).
    pub fn mark_unspent(&mut self, commitment: &[u8; 33]) -> Result<(), WalletError> {
        match self.outputs.get_mut(commitment) {
            Some(output) => {
                output.spent = false;
                Ok(())
            }
            None => Err(WalletError::OutputNotFound(format!(
                "commitment {:?}",
                hex::encode(commitment)
            ))),
        }
    }

    /// Reserve an output for a pending transaction.
    pub fn reserve(&mut self, commitment: &[u8; 33], tx_hash: [u8; 32]) -> Result<(), WalletError> {
        match self.outputs.get_mut(commitment) {
            Some(output) => {
                output.reserved_for_tx = Some(tx_hash);
                Ok(())
            }
            None => Err(WalletError::OutputNotFound(format!(
                "commitment {:?}",
                hex::encode(commitment)
            ))),
        }
    }

    /// Release reservation on an output.
    pub fn release_reservation(&mut self, commitment: &[u8; 33]) -> Result<(), WalletError> {
        match self.outputs.get_mut(commitment) {
            Some(output) => {
                output.reserved_for_tx = None;
                Ok(())
            }
            None => Err(WalletError::OutputNotFound(format!(
                "commitment {:?}",
                hex::encode(commitment)
            ))),
        }
    }

    /// Add a coinbase output (subject to maturity).
    pub fn add_coinbase(
        &mut self,
        output: OwnedOutput,
        block_height: u64,
    ) -> Result<(), WalletError> {
        if !output.is_coinbase {
            return Err(WalletError::Crypto("expected coinbase output".into()));
        }
        let mut out = output;
        out.block_height = block_height;
        self.insert(out);
        Ok(())
    }

    /// Count all outputs.
    pub fn count(&self) -> usize {
        self.outputs.len()
    }

    /// Count spendable outputs at given height.
    pub fn count_spendable(&self, current_height: u64) -> usize {
        self.outputs
            .values()
            .filter(|o| o.is_spendable(current_height))
            .count()
    }

    /// Remove an output (for cleanup).
    pub fn remove(&mut self, commitment: &[u8; 33]) -> Option<OwnedOutput> {
        self.outputs.remove(commitment)
    }

    /// Clear all outputs.
    pub fn clear(&mut self) {
        self.outputs.clear();
    }
}

impl Default for OutputIndex {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn output(commitment_byte: u8, value: u64) -> OwnedOutput {
        let mut commitment = [0u8; 33];
        commitment[0] = commitment_byte;
        OwnedOutput::new(commitment, value, [commitment_byte; 32], 1, false)
    }

    #[test]
    fn select_for_spend_rejects_sum_overflow() {
        let mut index = OutputIndex::new();
        index.insert(output(1, u64::MAX - 1));
        index.insert(output(2, 2));

        let err = match index.select_for_spend_with_maturity(u64::MAX, 10, 0) {
            Ok(_) => panic!("expected explicit overflow error"),
            Err(err) => err,
        };

        assert!(
            matches!(err, WalletError::Crypto(ref message) if message.contains("overflow")),
            "expected explicit overflow error, got {err:?}"
        );
    }
}
