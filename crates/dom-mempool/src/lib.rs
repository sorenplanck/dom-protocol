//! # dom-mempool
//!
//! Transaction memory pool with fee-rate ordering.
//!
//! Transactions are ordered by fee/weight for mining selection.
//! Dandelion++ routing state is tracked here.

#![deny(unsafe_code)]
#![deny(missing_docs)]

use dom_consensus::transaction::{validate_transaction_structure, Transaction};
use dom_core::{DomError, MAX_BLOCK_WEIGHT, MIN_RELAY_FEE_RATE};
use std::collections::{BTreeMap, HashMap};
use tracing::{debug, warn};

/// A mempool entry.
#[derive(Debug, Clone)]
pub struct MempoolEntry {
    /// The transaction.
    pub tx: Transaction,
    /// Transaction hash (32 bytes).
    pub tx_hash: [u8; 32],
    /// Total fee in noms.
    pub fee: u64,
    /// Transaction weight.
    pub weight: u32,
    /// Fee per weight unit (for ordering).
    pub fee_rate: u64,
    /// Unix timestamp when received.
    pub received_at: u64,
}

impl MempoolEntry {
    /// Create a mempool entry from a transaction.
    pub fn new(tx: Transaction, tx_hash: [u8; 32], received_at: u64) -> Result<Self, DomError> {
        let fee = tx.total_fee()?;
        let weight = tx.weight();
        let fee_rate = if weight == 0 { 0 } else { fee / weight as u64 };
        Ok(Self {
            tx,
            tx_hash,
            fee,
            weight,
            fee_rate,
            received_at,
        })
    }
}

/// The transaction memory pool.
pub struct Mempool {
    /// Transactions indexed by hash.
    entries: HashMap<[u8; 32], MempoolEntry>,
    /// Fee-ordered index: (fee_rate, tx_hash) → () for selection.
    fee_index: BTreeMap<(u64, [u8; 32]), ()>,
    /// Total weight of all transactions in pool.
    total_weight: u64,
    /// Maximum total weight (default: 10 * MAX_BLOCK_WEIGHT).
    max_weight: u64,
}

impl Mempool {
    /// Create a new empty mempool.
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
            fee_index: BTreeMap::new(),
            total_weight: 0,
            max_weight: MAX_BLOCK_WEIGHT as u64 * 10,
        }
    }

    /// Current transaction count.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the mempool is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Accept a transaction into the mempool.
    ///
    /// Validates structure, checks fee rate, and adds to pool.
    pub fn accept_tx(
        &mut self,
        tx: Transaction,
        tx_hash: [u8; 32],
        now_secs: u64,
    ) -> Result<(), DomError> {
        // Already in pool?
        if self.entries.contains_key(&tx_hash) {
            return Err(DomError::PolicyRejected(
                "transaction already in mempool".into(),
            ));
        }

        // Structural validation
        validate_transaction_structure(&tx)?;

        let entry = MempoolEntry::new(tx, tx_hash, now_secs)?;

        // Minimum relay fee check (policy)
        if entry.fee_rate < MIN_RELAY_FEE_RATE {
            return Err(DomError::PolicyRejected(format!(
                "fee rate {} < MIN_RELAY_FEE_RATE {}",
                entry.fee_rate, MIN_RELAY_FEE_RATE
            )));
        }

        // Evict low-fee transactions if pool is full
        if self.total_weight + entry.weight as u64 > self.max_weight {
            self.evict_lowest_fee(entry.fee_rate)?;
        }

        debug!(
            "Mempool: accepted tx {} fee_rate={}",
            hex::encode(tx_hash),
            entry.fee_rate
        );
        self.total_weight += entry.weight as u64;
        self.fee_index.insert((entry.fee_rate, tx_hash), ());
        self.entries.insert(tx_hash, entry);
        Ok(())
    }

    /// Remove a transaction from the mempool (e.g. after it's included in a block).
    pub fn remove_tx(&mut self, tx_hash: &[u8; 32]) {
        if let Some(entry) = self.entries.remove(tx_hash) {
            self.fee_index.remove(&(entry.fee_rate, *tx_hash));
            self.total_weight = self.total_weight.saturating_sub(entry.weight as u64);
        }
    }

    /// Select transactions for block mining, ordered by fee rate (highest first).
    ///
    /// Returns transactions fitting within `max_weight` weight units.
    pub fn select_for_block(&self, max_weight: u32) -> Vec<&MempoolEntry> {
        let mut selected = Vec::new();
        let mut used_weight = 0u32;

        // BTreeMap iterates in ascending order — we want descending fee_rate
        for ((_fee_rate, hash), _) in self.fee_index.iter().rev() {
            if let Some(entry) = self.entries.get(hash) {
                let new_weight = used_weight.saturating_add(entry.weight);
                if new_weight > max_weight {
                    continue;
                }
                used_weight = new_weight;
                selected.push(entry);
            }
        }
        selected
    }

    /// Evict the lowest fee-rate transaction to make room.
    fn evict_lowest_fee(&mut self, min_fee_rate: u64) -> Result<(), DomError> {
        // Find the lowest fee-rate entry
        if let Some((&(lowest_rate, hash), _)) = self.fee_index.iter().next() {
            if lowest_rate >= min_fee_rate {
                return Err(DomError::PolicyRejected(
                    "mempool full, fee too low to evict".into(),
                ));
            }
            warn!(
                "Mempool evicting tx {} (fee_rate={})",
                hex::encode(hash),
                lowest_rate
            );
            let hash_copy = hash;
            self.remove_tx(&hash_copy);
        }
        Ok(())
    }

    /// Get a transaction by hash.
    pub fn get_tx(&self, hash: &[u8; 32]) -> Option<&MempoolEntry> {
        self.entries.get(hash)
    }

    /// Get all transaction hashes (for INV messages).
    pub fn all_hashes(&self) -> Vec<[u8; 32]> {
        self.entries.keys().cloned().collect()
    }

    /// Remove all transactions whose inputs are spent by a committed block.
    pub fn remove_confirmed(&mut self, spent_commitments: &[[u8; 33]]) {
        let spent_set: std::collections::HashSet<[u8; 33]> =
            spent_commitments.iter().cloned().collect();
        let to_remove: Vec<[u8; 32]> = self
            .entries
            .values()
            .filter(|e| {
                e.tx.inputs
                    .iter()
                    .any(|i| spent_set.contains(i.commitment.as_bytes()))
            })
            .map(|e| e.tx_hash)
            .collect();
        for hash in to_remove {
            self.remove_tx(&hash);
        }
    }
}

impl Default for Mempool {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dom_consensus::transaction::{TransactionKernel, TransactionOutput};
    use dom_core::{Amount, KERNEL_FEAT_PLAIN};
    use dom_crypto::pedersen::Commitment;

    fn g_commitment() -> Commitment {
        let g = [
            0x02u8, 0x79, 0xBE, 0x66, 0x7E, 0xF9, 0xDC, 0xBB, 0xAC, 0x55, 0xA0, 0x62, 0x95, 0xCE,
            0x87, 0x0B, 0x07, 0x02, 0x9B, 0xFC, 0xDB, 0x2D, 0xCE, 0x28, 0xD9, 0x59, 0xF2, 0x81,
            0x5B, 0x16, 0xF8, 0x17, 0x98,
        ];
        Commitment::from_compressed_bytes(&g).unwrap()
    }

    fn make_tx(fee: u64) -> (Transaction, [u8; 32]) {
        let tx = Transaction {
            inputs: vec![],
            outputs: vec![TransactionOutput {
                commitment: g_commitment(),
                proof: vec![0u8; 100],
            }],
            kernels: vec![TransactionKernel {
                features: KERNEL_FEAT_PLAIN,
                fee: Amount::from_noms(fee).unwrap(),
                lock_height: 0,
                excess: g_commitment(),
                excess_signature: [0u8; 65],
            }],
            offset: [0u8; 32],
        };
        let mut hash = [0u8; 32];
        hash[0..8].copy_from_slice(&fee.to_le_bytes());
        (tx, hash)
    }

    #[test]
    fn accept_tx_basic() {
        let mut pool = Mempool::new();
        let (tx, hash) = make_tx(MIN_RELAY_FEE_RATE * 100); // weight=24, fee=high
        pool.accept_tx(tx, hash, 0).unwrap();
        assert_eq!(pool.len(), 1);
    }

    #[test]
    fn below_min_fee_rejected() {
        let mut pool = Mempool::new();
        let (tx, hash) = make_tx(1); // fee=1 nom → fee_rate=0 < MIN_RELAY_FEE_RATE
        assert!(pool.accept_tx(tx, hash, 0).is_err());
    }

    #[test]
    fn select_orders_by_fee_rate() {
        let mut pool = Mempool::new();
        let (tx_low, h_low) = make_tx(MIN_RELAY_FEE_RATE * 24); // fee_rate=1000
        let (tx_high, h_high) = make_tx(MIN_RELAY_FEE_RATE * 24 * 5); // fee_rate=5000
        pool.accept_tx(tx_low, h_low, 0).unwrap();
        pool.accept_tx(tx_high, h_high, 1).unwrap();
        let selected = pool.select_for_block(MAX_BLOCK_WEIGHT);
        // Highest fee first
        assert_eq!(selected[0].tx_hash, h_high);
        assert_eq!(selected[1].tx_hash, h_low);
    }

    #[test]
    fn duplicate_tx_rejected() {
        let mut pool = Mempool::new();
        let (tx, hash) = make_tx(MIN_RELAY_FEE_RATE * 100);
        pool.accept_tx(tx.clone(), hash, 0).unwrap();
        assert!(pool.accept_tx(tx, hash, 1).is_err());
    }

    #[test]
    fn remove_tx_works() {
        let mut pool = Mempool::new();
        let (tx, hash) = make_tx(MIN_RELAY_FEE_RATE * 100);
        pool.accept_tx(tx, hash, 0).unwrap();
        pool.remove_tx(&hash);
        assert_eq!(pool.len(), 0);
    }
}
