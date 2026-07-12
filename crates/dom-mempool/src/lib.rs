//! # dom-mempool
//!
//! Transaction memory pool with deterministic ordering.
//!
//! ## Restart policy (RFC-0012 §1) — VOLATILE
//!
//! The mempool is **volatile by protocol rule**. It is **empty by construction
//! after restart**, is **never persisted** as canonical or replayable state, and
//! reconstructs no runtime-only state implicitly. Any on-disk mempool bytes left
//! by an older build are *legacy state*: they are cleared, never loaded.
//!
//! ## Consensus-neutrality (RFC-0012 §1.3) — INVARIANT
//!
//! The mempool is a local relay/liveness cache and is **never consensus state**.
//! Block/chain validation takes no mempool argument; admission here validates a
//! candidate against a *snapshot of canonical chain state*
//! ([`validate_tx_against_chain_view`]), never against another node's mempool.
//! Mempool state — present, absent, or restarted — cannot change which blocks are
//! valid or which chain is canonical.
//!
//! ## Same-block spends (RFC-0012 §4) — FORBIDDEN
//!
//! A candidate that spends an output not present in the canonical UTXO set (e.g.
//! an output created by another still-unconfirmed transaction) is rejected at
//! admission. This is the mempool-side half of the protocol rule that a published
//! block must never spend a same-block output.
//!
//! ## [`PersistedMempoolState`]
//!
//! [`PersistedMempoolState`] / [`Mempool::snapshot`] produce a canonical,
//! hash-ordered, *in-memory* view used for diagnostics, INV listings, and
//! replay-convergence checks. Per the volatile policy this view is **not written
//! to disk by any runtime path**; it is also the wire form recognised when
//! clearing legacy on-disk state from older builds.
//!
//! ## Canonical ordering rules
//! - operator/API hash listings are lexicographic `tx_hash ASC`
//! - block selection is `fee_rate DESC`, then `tx_hash ASC`
//! - rollback/reorg reinjection sorts candidates by `tx_hash ASC`

#![deny(unsafe_code)]
#![deny(missing_docs)]

use dom_consensus::transaction::{validate_transaction_structure, Transaction};
use dom_consensus::{validate_transaction, ValidationContext};
use dom_core::{BlockHeight, DomError, Timestamp, MAX_BLOCK_WEIGHT, MIN_RELAY_FEE_RATE};
use dom_serialization::{DomDeserialize, DomSerialize, Reader, Writer};
use dom_store::utxo::UtxoEntry;
use std::collections::{BTreeMap, HashMap};
use tracing::{debug, warn};

const MAX_PERSISTED_MEMPOOL_ENTRIES: usize = dom_core::MAX_BLOCK_TXS * 10;

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

/// Deterministic mempool snapshot entry used for explicit diagnostics/tests.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PersistedMempoolEntry {
    /// Raw transaction.
    pub tx: Transaction,
    /// Canonical transaction hash.
    pub tx_hash: [u8; 32],
    /// Original receive timestamp carried only for explicit snapshot users.
    pub received_at: u64,
}

/// Bounded mempool snapshot used for explicit diagnostics/tests.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PersistedMempoolState {
    /// Canonical hash-ordered mempool entries.
    pub entries: Vec<PersistedMempoolEntry>,
}

impl DomSerialize for PersistedMempoolState {
    fn serialize(&self, w: &mut Writer) -> Result<(), DomError> {
        let len: u32 =
            self.entries.len().try_into().map_err(|_| {
                DomError::Malformed("persisted mempool entry count exceeds u32".into())
            })?;
        w.write_u32(len);
        for entry in &self.entries {
            w.write_bytes(&entry.tx_hash);
            w.write_u64(entry.received_at);
            entry.tx.serialize(w)?;
        }
        Ok(())
    }
}

impl DomDeserialize for PersistedMempoolState {
    const MIN_SERIALIZED_SIZE: usize = 4;

    fn deserialize(r: &mut Reader<'_>) -> Result<Self, DomError> {
        let len = r.read_u32()? as usize;
        if len > MAX_PERSISTED_MEMPOOL_ENTRIES {
            return Err(DomError::Malformed(format!(
                "persisted mempool entry count {len} exceeds limit {MAX_PERSISTED_MEMPOOL_ENTRIES}"
            )));
        }
        let mut entries = Vec::with_capacity(len);
        for _ in 0..len {
            let tx_hash = r.read_array::<32>()?;
            let received_at = r.read_u64()?;
            let tx = Transaction::deserialize(r)?;
            entries.push(PersistedMempoolEntry {
                tx,
                tx_hash,
                received_at,
            });
        }
        Ok(Self { entries })
    }
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
    /// Input commitments currently reserved by in-pool transactions.
    input_index: HashMap<[u8; 33], [u8; 32]>,
    /// Fee-ordered index: (fee_rate, tx_hash) → () for low-fee eviction.
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
            input_index: HashMap::new(),
            fee_index: BTreeMap::new(),
            total_weight: 0,
            max_weight: MAX_BLOCK_WEIGHT as u64 * 10,
        }
    }

    /// Override the weight cap. Test-only: lets eviction tests fill the pool
    /// with a handful of small transactions instead of `10 * MAX_BLOCK_WEIGHT`.
    #[cfg(test)]
    fn set_max_weight_for_test(&mut self, max_weight: u64) {
        self.max_weight = max_weight;
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
    /// Legacy/test-only admission path. It validates structure, checks fee
    /// rate, and adds to the pool without chain-context cryptographic checks.
    /// Production callers must use [`Mempool::accept_tx_with_chain_view`].
    pub fn accept_tx(
        &mut self,
        tx: Transaction,
        tx_hash: [u8; 32],
        now_secs: u64,
    ) -> Result<(), DomError> {
        validate_transaction_structure(&tx)?;
        self.accept_validated_tx(tx, tx_hash, now_secs)
    }

    /// Accept a transaction after validating it against a bounded snapshot of
    /// canonical chainstate.
    ///
    /// This keeps mempool admission deterministic: the caller supplies an
    /// explicit lookup function over the exact input commitments in the
    /// candidate transaction, plus the current canonical height and network
    /// maturity rule.
    #[allow(clippy::too_many_arguments)]
    pub fn accept_tx_with_chain_view<F>(
        &mut self,
        tx: Transaction,
        tx_hash: [u8; 32],
        now_secs: u64,
        current_height: u64,
        chain_id: [u8; 32],
        coinbase_maturity: u64,
        mut lookup_utxo: F,
    ) -> Result<(), DomError>
    where
        F: FnMut(&[u8; 33]) -> Result<Option<UtxoEntry>, DomError>,
    {
        // FABLE5-001: run the cheap, crypto-independent admission gates BEFORE the
        // expensive `validate_transaction` (Bulletproof + Schnorr). A duplicate or
        // below-floor-fee/over-capacity tx is rejected without paying for crypto, so
        // a peer replaying a known tx can no longer force repeated range-proof
        // verification. These gates are structural only (hash lookup, kernel-fee
        // sum, weight) — they never depend on cryptographic validity — so detecting
        // them earlier cannot change any tx's accept/reject verdict, only the
        // (cheaper) rejection reason. `accept_validated_tx` re-checks the same
        // conditions, so the legacy `accept_tx` path is unaffected.
        //
        // `tx_hash` must be the canonical hash of the tx bytes; the production
        // callers pass `blake2b_256(tx_bytes)` (see dom-node node.rs / node_handle).
        self.precheck_cheap_admission_gates(&tx, &tx_hash)?;

        let ctx = ValidationContext {
            current_height: BlockHeight(current_height),
            chain_id,
            now: Timestamp(now_secs),
        };
        validate_transaction(&tx, &ctx)?;
        validate_tx_against_chain_view(&tx, current_height, coinbase_maturity, &mut lookup_utxo)?;
        self.accept_validated_tx(tx, tx_hash, now_secs)
    }

    /// Cheap, crypto-independent admission gates, hoisted ahead of
    /// `validate_transaction` (FABLE5-001). Mirrors exactly the duplicate,
    /// min-relay-fee, and capacity checks inside `accept_validated_tx` (same
    /// error messages), so moving them earlier changes no verdict — only how
    /// soon a rejection is detected. Returns `Ok(())` when the tx is not a
    /// duplicate, meets the fee floor, and could fit within the weight cap.
    fn precheck_cheap_admission_gates(
        &self,
        tx: &Transaction,
        tx_hash: &[u8; 32],
    ) -> Result<(), DomError> {
        if self.entries.contains_key(tx_hash) {
            return Err(DomError::PolicyRejected(
                "transaction already in mempool".into(),
            ));
        }

        let fee = tx.total_fee()?;
        let weight = tx.weight();
        let fee_rate = if weight == 0 { 0 } else { fee / weight as u64 };
        if fee_rate < MIN_RELAY_FEE_RATE {
            return Err(DomError::PolicyRejected(format!(
                "fee rate {} < MIN_RELAY_FEE_RATE {}",
                fee_rate, MIN_RELAY_FEE_RATE
            )));
        }
        if weight as u64 > self.max_weight {
            return Err(DomError::PolicyRejected(format!(
                "tx weight {} exceeds mempool max_weight {}",
                weight, self.max_weight
            )));
        }
        Ok(())
    }

    fn accept_validated_tx(
        &mut self,
        tx: Transaction,
        tx_hash: [u8; 32],
        now_secs: u64,
    ) -> Result<(), DomError> {
        if self.entries.contains_key(&tx_hash) {
            return Err(DomError::PolicyRejected(
                "transaction already in mempool".into(),
            ));
        }

        if let Some(conflict_hash) = self.first_conflicting_tx(&tx, &tx_hash) {
            return Err(DomError::PolicyRejected(format!(
                "input already reserved by mempool tx {}",
                hex::encode(conflict_hash)
            )));
        }

        let entry = MempoolEntry::new(tx, tx_hash, now_secs)?;

        // Minimum relay fee check (policy)
        if entry.fee_rate < MIN_RELAY_FEE_RATE {
            return Err(DomError::PolicyRejected(format!(
                "fee rate {} < MIN_RELAY_FEE_RATE {}",
                entry.fee_rate, MIN_RELAY_FEE_RATE
            )));
        }

        // A transaction heavier than the entire pool capacity can never be
        // admitted — no amount of eviction frees enough room. Reject up front
        // so the eviction loop below always has a reachable exit (DOM-AUDIT-003).
        if entry.weight as u64 > self.max_weight {
            return Err(DomError::PolicyRejected(format!(
                "tx weight {} exceeds mempool max_weight {}",
                entry.weight, self.max_weight
            )));
        }

        // Evict low-fee transactions until the incoming tx fits. A single
        // eviction can be insufficient when the incoming tx is heavier than
        // the one evicted, which previously left total_weight above max_weight
        // (DOM-AUDIT-003, DoS). Loop instead — but never spin: each iteration
        // either removes exactly one strictly-cheaper tx (evict_lowest_fee
        // returns Ok) or returns Err. The fee policy is preserved across the
        // whole loop: evict_lowest_fee refuses (PolicyRejected) once the
        // cheapest pooled tx is not strictly cheaper than the incoming one, so
        // we never evict a >= fee tx to admit a < fee one. The weight-progress
        // guard is a defensive backstop: if a successful eviction ever freed
        // nothing (e.g. an empty pool still over cap), stop instead of looping.
        while self.total_weight + entry.weight as u64 > self.max_weight {
            let weight_before = self.total_weight;
            self.evict_lowest_fee(entry.fee_rate)?;
            if self.total_weight >= weight_before {
                return Err(DomError::PolicyRejected(
                    "mempool full, unable to free enough space for incoming tx".into(),
                ));
            }
        }

        // Invariant: after the loop the incoming tx fits within the weight cap.
        debug_assert!(
            self.total_weight + entry.weight as u64 <= self.max_weight,
            "eviction loop must leave room for the incoming tx"
        );

        debug!(
            "Mempool: accepted tx {} fee_rate={}",
            hex::encode(tx_hash),
            entry.fee_rate
        );
        self.total_weight += entry.weight as u64;
        self.fee_index.insert((entry.fee_rate, tx_hash), ());
        for input in &entry.tx.inputs {
            self.input_index
                .insert(*input.commitment.as_bytes(), tx_hash);
        }
        self.entries.insert(tx_hash, entry);
        Ok(())
    }

    /// Remove a transaction from the mempool (e.g. after it's included in a block).
    pub fn remove_tx(&mut self, tx_hash: &[u8; 32]) {
        if let Some(entry) = self.entries.remove(tx_hash) {
            for input in &entry.tx.inputs {
                let commitment = *input.commitment.as_bytes();
                if self.input_index.get(&commitment) == Some(tx_hash) {
                    self.input_index.remove(&commitment);
                }
            }
            self.fee_index.remove(&(entry.fee_rate, *tx_hash));
            self.total_weight = self.total_weight.saturating_sub(entry.weight as u64);
        }
    }

    /// Select transactions for block mining, ordered by fee rate (highest first).
    ///
    /// Returns transactions fitting within `max_weight` weight units, ordered
    /// canonically by `fee_rate DESC`, then `tx_hash ASC`.
    pub fn select_for_block(&self, max_weight: u32) -> Vec<&MempoolEntry> {
        let mut selected = Vec::new();
        let mut used_weight = 0u32;

        for entry in self.entries_in_block_order() {
            let new_weight = used_weight.saturating_add(entry.weight);
            if new_weight > max_weight {
                continue;
            }
            used_weight = new_weight;
            selected.push(entry);
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

    /// Whether a transaction with this hash is already pooled. Cheap O(1) lookup
    /// used by the P2P relay path to short-circuit replays of already-known txs
    /// before acquiring the chain lock or running validation (FABLE5-001).
    pub fn contains(&self, hash: &[u8; 32]) -> bool {
        self.entries.contains_key(hash)
    }

    /// Get all transaction hashes (for INV messages).
    pub fn all_hashes(&self) -> Vec<[u8; 32]> {
        let mut hashes: Vec<[u8; 32]> = self.entries.keys().cloned().collect();
        hashes.sort_unstable();
        hashes
    }

    /// Capture a canonical snapshot of the accepted mempool set.
    pub fn snapshot(&self) -> PersistedMempoolState {
        let mut entries: Vec<PersistedMempoolEntry> = self
            .entries
            .values()
            .map(|entry| PersistedMempoolEntry {
                tx: entry.tx.clone(),
                tx_hash: entry.tx_hash,
                received_at: entry.received_at,
            })
            .collect();
        entries.sort_unstable_by_key(|entry| entry.tx_hash);
        PersistedMempoolState { entries }
    }

    /// Canonical 32-byte digest of the accepted mempool set.
    ///
    /// Computed over the canonical hash-ordered [`snapshot`](Self::snapshot), so
    /// two mempools that have admitted the same transaction set produce the same
    /// digest regardless of admission/delivery order. Used to assert reorg/relay
    /// convergence (RFC-0012 §3.4); it is a diagnostic, never consensus state.
    pub fn digest(&self) -> [u8; 32] {
        use dom_serialization::DomSerialize;

        let bytes = self
            .snapshot()
            .to_bytes()
            .expect("canonical mempool snapshot serialization is infallible");
        *dom_crypto::hash::blake2b_256(&bytes).as_bytes()
    }

    /// Deterministically re-accept a batch of transactions after rollback.
    ///
    /// Transactions are sorted by hash before admission so the same batch
    /// produces the same reinjection order regardless of upstream iteration
    /// order. The returned outcomes preserve that canonical hash order.
    pub fn reinject_batch(
        &mut self,
        mut txs: Vec<(Transaction, [u8; 32], u64)>,
    ) -> Vec<([u8; 32], Result<(), DomError>)> {
        txs.sort_unstable_by_key(|tx| tx.1);
        txs.into_iter()
            .map(|(tx, tx_hash, now_secs)| {
                let result = self.accept_tx(tx, tx_hash, now_secs);
                (tx_hash, result)
            })
            .collect()
    }

    /// Deterministically re-accept a batch of transactions after rollback
    /// while revalidating each entry against a caller-supplied
    /// canonical chain snapshot.
    pub fn reinject_batch_with_chain_view<F>(
        &mut self,
        mut txs: Vec<(Transaction, [u8; 32], u64)>,
        current_height: u64,
        chain_id: [u8; 32],
        coinbase_maturity: u64,
        mut lookup_utxo: F,
    ) -> Vec<([u8; 32], Result<(), DomError>)>
    where
        F: FnMut(&[u8; 33]) -> Result<Option<UtxoEntry>, DomError>,
    {
        txs.sort_unstable_by_key(|tx| tx.1);
        txs.into_iter()
            .map(|(tx, tx_hash, now_secs)| {
                let result = self.accept_tx_with_chain_view(
                    tx,
                    tx_hash,
                    now_secs,
                    current_height,
                    chain_id,
                    coinbase_maturity,
                    &mut lookup_utxo,
                );
                (tx_hash, result)
            })
            .collect()
    }

    /// Remove all transactions whose inputs are spent by a committed block.
    pub fn remove_confirmed(&mut self, spent_commitments: &[[u8; 33]]) {
        let spent_set: std::collections::HashSet<[u8; 33]> =
            spent_commitments.iter().cloned().collect();
        let mut to_remove: Vec<[u8; 32]> = self
            .entries
            .values()
            .filter(|e| {
                e.tx.inputs
                    .iter()
                    .any(|i| spent_set.contains(i.commitment.as_bytes()))
            })
            .map(|e| e.tx_hash)
            .collect();
        to_remove.sort_unstable();
        for hash in to_remove {
            self.remove_tx(&hash);
        }
    }

    fn first_conflicting_tx(&self, tx: &Transaction, tx_hash: &[u8; 32]) -> Option<[u8; 32]> {
        tx.inputs.iter().find_map(|input| {
            let commitment = input.commitment.as_bytes();
            self.input_index
                .get(commitment)
                .copied()
                .filter(|existing| existing != tx_hash)
        })
    }

    fn entries_in_block_order(&self) -> Vec<&MempoolEntry> {
        let mut entries: Vec<&MempoolEntry> = self.entries.values().collect();
        entries.sort_unstable_by(|a, b| {
            b.fee_rate
                .cmp(&a.fee_rate)
                .then_with(|| a.tx_hash.cmp(&b.tx_hash))
        });
        entries
    }
}

/// Validate that every input in `tx` exists in canonical chainstate and obeys
/// the caller-supplied maturity rule.
pub fn validate_tx_against_chain_view<F>(
    tx: &Transaction,
    current_height: u64,
    coinbase_maturity: u64,
    mut lookup_utxo: F,
) -> Result<(), DomError>
where
    F: FnMut(&[u8; 33]) -> Result<Option<UtxoEntry>, DomError>,
{
    for input in &tx.inputs {
        let commitment = input.commitment.as_bytes();
        let Some(entry) = lookup_utxo(commitment)? else {
            return Err(DomError::PolicyRejected(format!(
                "input commitment not found in canonical UTXO set: {}",
                hex::encode(commitment)
            )));
        };
        if entry.is_coinbase && !entry.is_mature_for(current_height, coinbase_maturity) {
            return Err(DomError::TemporarilyInvalid(format!(
                "immature coinbase spend at height {} (created at {}, maturity {})",
                current_height, entry.block_height, coinbase_maturity
            )));
        }
    }
    Ok(())
}

impl Default for Mempool {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dom_consensus::transaction::{TransactionInput, TransactionKernel, TransactionOutput};
    use dom_core::{Amount, KERNEL_FEAT_PLAIN, TAG_KERNEL_MSG};
    use dom_crypto::hash::blake2b_256_tagged;
    use dom_crypto::pedersen::{BlindingFactor, Commitment};
    use dom_crypto::{bp2_prove, schnorr_sign, SecretKey};

    const TEST_CHAIN_ID: [u8; 32] = [0x42; 32];

    fn g_commitment() -> Commitment {
        let g = [
            0x02u8, 0x79, 0xBE, 0x66, 0x7E, 0xF9, 0xDC, 0xBB, 0xAC, 0x55, 0xA0, 0x62, 0x95, 0xCE,
            0x87, 0x0B, 0x07, 0x02, 0x9B, 0xFC, 0xDB, 0x2D, 0xCE, 0x28, 0xD9, 0x59, 0xF2, 0x81,
            0x5B, 0x16, 0xF8, 0x17, 0x98,
        ];
        Commitment::from_compressed_bytes(&g).unwrap()
    }

    fn h_commitment() -> Commitment {
        let h = [
            0x02u8, 0x0e, 0x2c, 0xfc, 0x9a, 0xba, 0x78, 0x45, 0x5f, 0xfd, 0x39, 0x0c, 0xf5, 0xf1,
            0xd1, 0x7b, 0x99, 0x82, 0xd0, 0xee, 0x29, 0xb2, 0x66, 0xbb, 0x3e, 0xa6, 0x21, 0x7b,
            0x07, 0x8f, 0x09, 0xd5, 0x50,
        ];
        Commitment::from_compressed_bytes(&h).unwrap()
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

    fn make_spending_tx(
        input_commitment: Commitment,
        fee: u64,
        seed: u8,
    ) -> (Transaction, [u8; 32]) {
        let tx = Transaction {
            inputs: vec![dom_consensus::transaction::TransactionInput {
                commitment: input_commitment,
            }],
            outputs: vec![TransactionOutput {
                commitment: g_commitment(),
                proof: vec![seed; 100],
            }],
            kernels: vec![TransactionKernel {
                features: KERNEL_FEAT_PLAIN,
                fee: Amount::from_noms(fee).unwrap(),
                lock_height: 0,
                excess: g_commitment(),
                excess_signature: [seed; 65],
            }],
            offset: [0u8; 32],
        };
        let mut hash = [0u8; 32];
        hash[0..8].copy_from_slice(&fee.to_le_bytes());
        hash[8] = seed;
        (tx, hash)
    }

    fn scalar(seed: u8) -> BlindingFactor {
        let mut bytes = [0u8; 32];
        bytes[31] = seed.max(1);
        BlindingFactor::from_bytes(bytes).expect("deterministic scalar")
    }

    fn kernel_message(fee: u64, lock_height: u64) -> [u8; 32] {
        let mut data = Vec::with_capacity(1 + 8 + 8);
        data.push(KERNEL_FEAT_PLAIN);
        data.extend_from_slice(&fee.to_le_bytes());
        data.extend_from_slice(&lock_height.to_le_bytes());
        *blake2b_256_tagged(TAG_KERNEL_MSG, &data).as_bytes()
    }

    fn make_valid_chain_view_tx(fee: u64, seed: u8) -> (Transaction, [u8; 32], UtxoEntry) {
        let output_value = 10_000;
        let input_value = output_value + fee;
        let input_blinding = scalar(seed);
        let kernel_blinding = scalar(seed.wrapping_add(80));
        let output_blinding = input_blinding
            .add(&kernel_blinding)
            .expect("output blinding");
        let input_commitment = Commitment::commit(input_value, &input_blinding);
        let output_commitment = Commitment::commit(output_value, &output_blinding);
        let (proof, _) = bp2_prove(output_value, &output_blinding).expect("range proof");
        let excess = Commitment::commit(0, &kernel_blinding);
        let secret = SecretKey::from_bytes(kernel_blinding.as_bytes()).expect("kernel secret");
        let sig = schnorr_sign(&secret, &kernel_message(fee, 0), &TEST_CHAIN_ID)
            .expect("kernel signature");

        let tx = Transaction {
            inputs: vec![TransactionInput {
                commitment: input_commitment,
            }],
            outputs: vec![TransactionOutput {
                commitment: output_commitment,
                proof,
            }],
            kernels: vec![TransactionKernel {
                features: KERNEL_FEAT_PLAIN,
                fee: Amount::from_noms(fee).unwrap(),
                lock_height: 0,
                excess,
                excess_signature: sig.to_bytes(),
            }],
            offset: [0u8; 32],
        };
        let mut hash = [0u8; 32];
        hash[0..8].copy_from_slice(&fee.to_le_bytes());
        hash[8] = seed;
        let entry = UtxoEntry {
            block_height: 1,
            is_coinbase: false,
            proof: vec![],
        };
        (tx, hash, entry)
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
    fn select_breaks_fee_rate_ties_by_hash_ascending() {
        let mut pool = Mempool::new();
        let fee = MIN_RELAY_FEE_RATE * 100;
        let (tx_b, mut hash_b) = make_tx(fee);
        let (tx_a, mut hash_a) = make_tx(fee);
        hash_b[31] = 0xBB;
        hash_a[31] = 0x0A;
        pool.accept_tx(tx_b, hash_b, 1).unwrap();
        pool.accept_tx(tx_a, hash_a, 2).unwrap();

        let selected = pool.select_for_block(MAX_BLOCK_WEIGHT);
        assert_eq!(selected.len(), 2);
        assert_eq!(selected[0].tx_hash, hash_a);
        assert_eq!(selected[1].tx_hash, hash_b);
        assert_eq!(
            pool.select_for_block(MAX_BLOCK_WEIGHT)
                .iter()
                .map(|entry| entry.tx_hash)
                .collect::<Vec<_>>(),
            vec![hash_a, hash_b],
            "repeated block selection must remain stable"
        );
    }

    #[test]
    fn duplicate_tx_rejected() {
        let mut pool = Mempool::new();
        let (tx, hash) = make_tx(MIN_RELAY_FEE_RATE * 100);
        pool.accept_tx(tx.clone(), hash, 0).unwrap();
        assert!(pool.accept_tx(tx, hash, 1).is_err());
    }

    #[test]
    fn accept_tx_with_chain_view_rejects_invalid_range_proof() {
        let fee = MIN_RELAY_FEE_RATE * 100;
        let (mut tx, hash, entry) = make_valid_chain_view_tx(fee, 0x11);
        tx.outputs[0].proof = vec![0xAB; 100];
        let mut pool = Mempool::new();

        let err = pool
            .accept_tx_with_chain_view(tx, hash, 0, 100, TEST_CHAIN_ID, 10, |_| {
                Ok(Some(entry.clone()))
            })
            .expect_err("invalid range proof must reject");
        assert!(
            matches!(err, DomError::Invalid(ref msg) if msg.contains("range proof")),
            "expected range proof rejection, got {err}"
        );
        assert!(pool.get_tx(&hash).is_none());
    }

    #[test]
    fn accept_tx_with_chain_view_rejects_invalid_kernel_signature() {
        let fee = MIN_RELAY_FEE_RATE * 100;
        let (mut tx, hash, entry) = make_valid_chain_view_tx(fee, 0x12);
        tx.kernels[0].excess_signature = [0u8; 65];
        let mut pool = Mempool::new();

        let err = pool
            .accept_tx_with_chain_view(tx, hash, 0, 100, TEST_CHAIN_ID, 10, |_| {
                Ok(Some(entry.clone()))
            })
            .expect_err("invalid kernel signature must reject");
        assert!(
            matches!(err, DomError::Invalid(ref msg) if msg.contains("signature")),
            "expected signature rejection, got {err}"
        );
        assert!(pool.get_tx(&hash).is_none());
    }

    #[test]
    fn accept_tx_with_chain_view_accepts_valid_transaction() {
        let fee = MIN_RELAY_FEE_RATE * 100;
        let (tx, hash, entry) = make_valid_chain_view_tx(fee, 0x13);
        let mut pool = Mempool::new();

        pool.accept_tx_with_chain_view(tx, hash, 0, 100, TEST_CHAIN_ID, 10, |_| {
            Ok(Some(entry.clone()))
        })
        .expect("valid tx must admit");
        assert!(pool.get_tx(&hash).is_some());
    }

    #[test]
    fn remove_tx_works() {
        let mut pool = Mempool::new();
        let (tx, hash) = make_tx(MIN_RELAY_FEE_RATE * 100);
        pool.accept_tx(tx, hash, 0).unwrap();
        pool.remove_tx(&hash);
        assert_eq!(pool.len(), 0);
    }

    #[test]
    fn all_hashes_are_sorted_by_hash() {
        let mut pool = Mempool::new();
        let (tx_c, hash_c) = make_tx(MIN_RELAY_FEE_RATE * 300);
        let (tx_a, hash_a) = make_tx(MIN_RELAY_FEE_RATE * 100);
        let (tx_b, hash_b) = make_tx(MIN_RELAY_FEE_RATE * 200);

        pool.accept_tx(tx_c, hash_c, 3).unwrap();
        pool.accept_tx(tx_a, hash_a, 1).unwrap();
        pool.accept_tx(tx_b, hash_b, 2).unwrap();

        let mut expected = vec![hash_a, hash_b, hash_c];
        expected.sort_unstable();
        assert_eq!(pool.all_hashes(), expected);
        assert_eq!(
            pool.all_hashes(),
            expected,
            "repeated calls must remain stable"
        );
    }

    #[test]
    fn reinject_batch_is_permutation_invariant() {
        let (tx_a, hash_a) = make_tx(MIN_RELAY_FEE_RATE * 100);
        let (tx_b, hash_b) = make_tx(MIN_RELAY_FEE_RATE * 200);
        let (tx_c, hash_c) = make_tx(MIN_RELAY_FEE_RATE * 300);

        let mut forward = Mempool::new();
        let forward_results = forward.reinject_batch(vec![
            (tx_b.clone(), hash_b, 2),
            (tx_c.clone(), hash_c, 3),
            (tx_a.clone(), hash_a, 1),
        ]);

        let mut reverse = Mempool::new();
        let reverse_results = reverse.reinject_batch(vec![
            (tx_a, hash_a, 1),
            (tx_c, hash_c, 3),
            (tx_b, hash_b, 2),
        ]);

        let forward_hashes: Vec<[u8; 32]> = forward_results.iter().map(|(hash, _)| *hash).collect();
        let reverse_hashes: Vec<[u8; 32]> = reverse_results.iter().map(|(hash, _)| *hash).collect();
        let mut expected = vec![hash_a, hash_b, hash_c];
        expected.sort_unstable();
        assert_eq!(forward_hashes, expected);
        assert_eq!(forward_hashes, reverse_hashes);
        assert!(forward_results.iter().all(|(_, result)| result.is_ok()));
        assert!(reverse_results.iter().all(|(_, result)| result.is_ok()));
        assert_eq!(forward.all_hashes(), reverse.all_hashes());
        // RFC-0012 §3.4: convergence is byte-level, not merely order-level.
        assert_eq!(
            forward.digest(),
            reverse.digest(),
            "permutation-invariant admission must yield an identical mempool digest"
        );
    }

    #[test]
    fn digest_is_permutation_invariant_and_distinguishes_contents() {
        let (tx_a, hash_a) = make_tx(MIN_RELAY_FEE_RATE * 100);
        let (tx_b, hash_b) = make_tx(MIN_RELAY_FEE_RATE * 200);

        let mut forward = Mempool::new();
        forward.accept_tx(tx_a.clone(), hash_a, 1).expect("a");
        forward.accept_tx(tx_b.clone(), hash_b, 2).expect("b");

        let mut reverse = Mempool::new();
        reverse.accept_tx(tx_b, hash_b, 2).expect("b");
        reverse.accept_tx(tx_a, hash_a, 1).expect("a");

        assert_eq!(
            forward.digest(),
            reverse.digest(),
            "same admitted set in different orders → identical digest"
        );

        // A different set must produce a different digest, and the empty mempool
        // is distinct from any populated one.
        let empty = Mempool::new();
        assert_ne!(forward.digest(), empty.digest());
        let (tx_c, hash_c) = make_tx(MIN_RELAY_FEE_RATE * 300);
        let mut other = Mempool::new();
        other.accept_tx(tx_c, hash_c, 3).expect("c");
        assert_ne!(forward.digest(), other.digest());
    }

    #[test]
    fn reinject_batch_reports_outcomes_in_canonical_order() {
        let (tx_low, hash_low) = make_tx(MIN_RELAY_FEE_RATE - 1);
        let (tx_high, hash_high) = make_tx(MIN_RELAY_FEE_RATE * 200);

        let mut pool = Mempool::new();
        let results = pool.reinject_batch(vec![(tx_high, hash_high, 2), (tx_low, hash_low, 1)]);

        assert_eq!(results.len(), 2);
        let mut expected = [hash_low, hash_high];
        expected.sort_unstable();
        assert_eq!(results[0].0, expected[0]);
        assert_eq!(results[1].0, expected[1]);
        let by_hash: std::collections::HashMap<[u8; 32], bool> = results
            .iter()
            .map(|(hash, result)| (*hash, result.is_ok()))
            .collect();
        assert!(
            !by_hash[&hash_low],
            "low-fee tx must be rejected even after canonical reorder"
        );
        assert!(
            by_hash[&hash_high],
            "high-fee tx must be accepted even after canonical reorder"
        );
        assert_eq!(pool.all_hashes(), vec![hash_high]);
    }

    #[test]
    fn persisted_snapshot_roundtrips_canonically() {
        let mut pool = Mempool::new();
        let (tx_c, hash_c) = make_tx(MIN_RELAY_FEE_RATE * 300);
        let (tx_a, hash_a) = make_tx(MIN_RELAY_FEE_RATE * 100);
        let (tx_b, hash_b) = make_tx(MIN_RELAY_FEE_RATE * 200);

        pool.accept_tx(tx_c, hash_c, 3).unwrap();
        pool.accept_tx(tx_a, hash_a, 1).unwrap();
        pool.accept_tx(tx_b, hash_b, 2).unwrap();

        let snapshot = pool.snapshot();
        let decoded = PersistedMempoolState::from_bytes(&snapshot.to_bytes().expect("serialize"))
            .expect("decode");

        let mut expected = vec![hash_a, hash_b, hash_c];
        expected.sort_unstable();
        assert_eq!(decoded, snapshot);
        assert_eq!(
            decoded
                .entries
                .iter()
                .map(|entry| entry.tx_hash)
                .collect::<Vec<_>>(),
            expected
        );
    }

    #[test]
    fn remove_confirmed_keeps_non_conflicting_transactions() {
        let mut pool = Mempool::new();
        let input_a = g_commitment();
        let input_b = h_commitment();
        let (tx_a, hash_a) = make_spending_tx(input_a.clone(), MIN_RELAY_FEE_RATE * 100, 0x01);
        let (tx_b, hash_b) = make_spending_tx(input_b.clone(), MIN_RELAY_FEE_RATE * 110, 0x02);

        pool.accept_tx(tx_a, hash_a, 1).unwrap();
        pool.accept_tx(tx_b, hash_b, 2).unwrap();
        pool.remove_confirmed(&[*input_a.as_bytes()]);

        assert!(pool.get_tx(&hash_a).is_none());
        assert!(pool.get_tx(&hash_b).is_some());
        assert_eq!(pool.all_hashes(), vec![hash_b]);
    }

    /// Build a structurally-valid (legacy-path) tx with `num_outputs` distinct
    /// outputs and one kernel, so its weight is
    /// `num_outputs * WEIGHT_OUTPUT + WEIGHT_KERNEL`. `seed` makes the output
    /// commitments and `tx_hash` distinct across calls.
    fn make_tx_weighted(fee: u64, num_outputs: u32, seed: u8) -> (Transaction, [u8; 32]) {
        let outputs = (0..num_outputs)
            .map(|i| TransactionOutput {
                // Distinct value per output guarantees a distinct commitment
                // (so structural duplicate-output detection passes).
                commitment: Commitment::commit(
                    1_000 + i as u64,
                    &scalar(seed.wrapping_add(i as u8)),
                ),
                proof: vec![seed; 100],
            })
            .collect();
        let tx = Transaction {
            inputs: vec![],
            outputs,
            kernels: vec![TransactionKernel {
                features: KERNEL_FEAT_PLAIN,
                fee: Amount::from_noms(fee).unwrap(),
                lock_height: 0,
                excess: g_commitment(),
                excess_signature: [seed; 65],
            }],
            offset: [0u8; 32],
        };
        let mut hash = [0u8; 32];
        hash[0..8].copy_from_slice(&fee.to_le_bytes());
        hash[8] = seed;
        (tx, hash)
    }

    // DOM-AUDIT-003: a single eviction can free less weight than a heavier
    // incoming tx needs. Admission must evict in a loop until it fits, while
    // preserving the fee policy and never spinning.

    #[test]
    fn eviction_loops_until_heavy_high_fee_tx_fits() {
        let mut pool = Mempool::new();
        pool.set_max_weight_for_test(96); // exactly four small (weight-24) txs

        // Fill to capacity with four small, low-fee txs (weight 24 each).
        let mut filler_hashes = vec![];
        for i in 0..4u64 {
            let fee = 24_000 + i * 24; // fee_rate = 1000 + i (low, >= MIN_RELAY)
            let (tx, hash) = make_tx(fee);
            pool.accept_tx(tx, hash, i).unwrap();
            filler_hashes.push(hash);
        }
        assert_eq!(pool.len(), 4);
        assert_eq!(pool.total_weight, 96);

        // Incoming: heavy (3 outputs + 1 kernel = weight 66) with a far higher
        // fee rate. 96 + 66 = 162 > 96, and evicting a single 24-weight filler
        // (→ 138) still doesn't fit: the loop must evict three of them.
        let (big_tx, big_hash) = make_tx_weighted(66 * 1_000_000, 3, 0x70);
        assert_eq!(big_tx.weight(), 66);
        pool.accept_tx(big_tx, big_hash, 100).unwrap();

        // (b) the heavy high-fee tx was accepted.
        assert!(pool.get_tx(&big_hash).is_some());
        // (c) the weight cap holds after the single accept call.
        assert!(pool.total_weight <= pool.max_weight);
        assert_eq!(pool.total_weight, 90); // one filler (24) + big (66)
                                           // (a) exactly the necessary number of small txs were evicted (3 of 4).
        assert_eq!(pool.len(), 2);
        let remaining = filler_hashes
            .iter()
            .filter(|h| pool.get_tx(h).is_some())
            .count();
        assert_eq!(remaining, 1, "three of four fillers must be evicted");
    }

    #[test]
    fn heavy_low_fee_tx_rejected_and_pool_left_intact() {
        let mut pool = Mempool::new();
        pool.set_max_weight_for_test(96);

        // Fill to capacity with four small HIGH-fee txs.
        let mut hashes = vec![];
        for i in 0..4u64 {
            let fee = 24 * 1_000_000 + i * 24; // fee_rate ~ 1_000_000 (high)
            let (tx, hash) = make_tx(fee);
            pool.accept_tx(tx, hash, i).unwrap();
            hashes.push(hash);
        }
        assert_eq!(pool.len(), 4);
        let weight_before = pool.total_weight;

        // Incoming heavy tx whose fee rate (1000) is below everything pooled:
        // the fee policy forbids evicting any of them, so it must be rejected.
        let (big_tx, big_hash) = make_tx_weighted(66 * 1_000, 3, 0x70);
        let err = pool.accept_tx(big_tx, big_hash, 100).unwrap_err();
        assert!(
            matches!(err, DomError::PolicyRejected(_)),
            "expected policy rejection, got {err:?}"
        );

        // Pool untouched: nothing evicted, nothing added.
        assert_eq!(pool.len(), 4);
        assert_eq!(pool.total_weight, weight_before);
        assert!(pool.get_tx(&big_hash).is_none());
        for h in &hashes {
            assert!(
                pool.get_tx(h).is_some(),
                "high-fee txs must survive a rejected low-fee insert"
            );
        }
    }

    #[test]
    fn tx_heavier_than_cap_rejected_without_eviction() {
        let mut pool = Mempool::new();
        pool.set_max_weight_for_test(50); // smaller than one heavy tx

        // weight = 3 * 21 + 3 = 66 > 50; no eviction can ever make room.
        let (big_tx, big_hash) = make_tx_weighted(66 * 1_000_000, 3, 0x70);
        assert!(big_tx.weight() as u64 > 50);
        let err = pool.accept_tx(big_tx, big_hash, 0).unwrap_err();
        assert!(
            matches!(err, DomError::PolicyRejected(ref m) if m.contains("exceeds mempool max_weight")),
            "expected max_weight rejection, got {err:?}"
        );
        assert!(pool.is_empty());
    }
}
