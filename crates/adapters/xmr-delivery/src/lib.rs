//! Exact signed-transaction delivery records and storage port.

#![forbid(unsafe_code)]

use sha2::{Digest, Sha256};
use std::{collections::HashMap, sync::RwLock};

/// Raw-transaction upper bound.
pub const MAX_RAW_TRANSACTION_BYTES: usize = 512 * 1024;

/// Monotonic delivery state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeliveryState {
    /// Exact bytes are durable but may not have been submitted.
    Prepared,
    /// Submission was accepted or reconciled as already known.
    Submitted,
    /// A chain adapter later confirmed inclusion/finality.
    Confirmed,
}

/// Durable record. Raw bytes are public signed transaction data, not secrets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeliveryRecord {
    /// Settlement id.
    pub settlement_id: [u8; 32],
    /// Kaystra effect id that caused construction.
    pub source_effect_id: [u8; 32],
    /// Consensus transaction hash returned by the builder.
    pub tx_hash: [u8; 32],
    /// Domain-separated fingerprint of `raw_tx`.
    pub raw_fingerprint: [u8; 32],
    /// Exact signed bytes reused on every retry.
    pub raw_tx: Vec<u8>,
    /// Monotonic state.
    pub state: DeliveryState,
}

/// Delivery failures.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DeliveryError {
    /// Zero ids/hash or empty bytes.
    #[error("invalid XMR delivery transaction")]
    InvalidTransaction,
    /// Bound exceeded before durable write.
    #[error("XMR delivery bound exceeded")]
    BoundsExceeded,
    /// Same settlement/effect attempted different bytes or hash.
    #[error("non-canonical XMR retransmission")]
    ConflictingRetransmission,
    /// Record does not exist.
    #[error("XMR delivery record not found")]
    NotFound,
    /// In-memory lock failed.
    #[error("XMR delivery lock poisoned")]
    Poisoned,
    /// Durable storage is temporarily unavailable.
    #[error("XMR delivery storage unavailable")]
    StorageUnavailable,
    /// Persisted row violates schema/invariants.
    #[error("XMR delivery storage corrupt")]
    Corrupt,
}

/// Calculates the exact-byte fingerprint.
pub fn fingerprint(raw_tx: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"DOM-INTEROP/XMR-EXACT-DELIVERY/V2\0");
    hasher.update((raw_tx.len() as u64).to_be_bytes());
    hasher.update(raw_tx);
    hasher.finalize().into()
}

fn validate_input(
    settlement_id: &[u8; 32],
    source_effect_id: &[u8; 32],
    tx_hash: &[u8; 32],
    raw_tx: &[u8],
) -> Result<(), DeliveryError> {
    if settlement_id == &[0; 32]
        || source_effect_id == &[0; 32]
        || tx_hash == &[0; 32]
        || raw_tx.is_empty()
    {
        return Err(DeliveryError::InvalidTransaction);
    }
    if raw_tx.len() > MAX_RAW_TRANSACTION_BYTES {
        return Err(DeliveryError::BoundsExceeded);
    }
    Ok(())
}

/// Exact delivery store used by the Kaystra effect bridge.
pub trait DeliveryStore: Send + Sync {
    /// Returns an existing record for the settlement.
    fn load(&self, settlement_id: &[u8; 32]) -> Result<Option<DeliveryRecord>, DeliveryError>;
    /// Atomically inserts exact bytes or returns the byte-identical existing row.
    fn prepare_exact(
        &self,
        settlement_id: [u8; 32],
        source_effect_id: [u8; 32],
        tx_hash: [u8; 32],
        raw_tx: &[u8],
    ) -> Result<DeliveryRecord, DeliveryError>;
    /// Marks accepted/already-known submission.
    fn mark_submitted(&self, settlement_id: &[u8; 32]) -> Result<(), DeliveryError>;
    /// Marks chain-confirmed delivery.
    fn mark_confirmed(&self, settlement_id: &[u8; 32]) -> Result<(), DeliveryError>;
}

/// In-memory implementation for model/E2E tests.
#[derive(Default)]
pub struct MemoryDeliveryStore {
    records: RwLock<HashMap<[u8; 32], DeliveryRecord>>,
}

impl DeliveryStore for MemoryDeliveryStore {
    fn load(&self, settlement_id: &[u8; 32]) -> Result<Option<DeliveryRecord>, DeliveryError> {
        Ok(self
            .records
            .read()
            .map_err(|_| DeliveryError::Poisoned)?
            .get(settlement_id)
            .cloned())
    }

    fn prepare_exact(
        &self,
        settlement_id: [u8; 32],
        source_effect_id: [u8; 32],
        tx_hash: [u8; 32],
        raw_tx: &[u8],
    ) -> Result<DeliveryRecord, DeliveryError> {
        validate_input(&settlement_id, &source_effect_id, &tx_hash, raw_tx)?;
        let raw_fingerprint = fingerprint(raw_tx);
        let mut records = self.records.write().map_err(|_| DeliveryError::Poisoned)?;
        if let Some(existing) = records.get(&settlement_id) {
            if existing.source_effect_id != source_effect_id
                || existing.tx_hash != tx_hash
                || existing.raw_fingerprint != raw_fingerprint
                || existing.raw_tx != raw_tx
            {
                return Err(DeliveryError::ConflictingRetransmission);
            }
            return Ok(existing.clone());
        }
        let record = DeliveryRecord {
            settlement_id,
            source_effect_id,
            tx_hash,
            raw_fingerprint,
            raw_tx: raw_tx.to_vec(),
            state: DeliveryState::Prepared,
        };
        records.insert(settlement_id, record.clone());
        Ok(record)
    }

    fn mark_submitted(&self, settlement_id: &[u8; 32]) -> Result<(), DeliveryError> {
        let mut records = self.records.write().map_err(|_| DeliveryError::Poisoned)?;
        let record = records
            .get_mut(settlement_id)
            .ok_or(DeliveryError::NotFound)?;
        if record.state == DeliveryState::Prepared {
            record.state = DeliveryState::Submitted;
        }
        Ok(())
    }

    fn mark_confirmed(&self, settlement_id: &[u8; 32]) -> Result<(), DeliveryError> {
        let mut records = self.records.write().map_err(|_| DeliveryError::Poisoned)?;
        let record = records
            .get_mut(settlement_id)
            .ok_or(DeliveryError::NotFound)?;
        record.state = DeliveryState::Confirmed;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SETTLEMENT: [u8; 32] = [9; 32];
    const EFFECT: [u8; 32] = [3; 32];
    const TX: [u8; 32] = [0x66; 32];
    const RAW: &[u8] = b"exact-signed-monero-tx";

    #[test]
    fn preparing_the_same_bytes_twice_returns_the_same_record() {
        // Restart safety depends on this: a replayed effect must find the row
        // it already wrote, never sign or store a second transaction.
        let store = MemoryDeliveryStore::default();
        let first = store
            .prepare_exact(SETTLEMENT, EFFECT, TX, RAW)
            .expect("first prepare");
        let second = store
            .prepare_exact(SETTLEMENT, EFFECT, TX, RAW)
            .expect("idempotent replay");
        assert_eq!(first.raw_tx, second.raw_tx);
        assert_eq!(first.tx_hash, second.tx_hash);
    }

    #[test]
    fn different_bytes_for_the_same_settlement_are_refused() {
        // A second, different transaction for one settlement is a conflicting
        // retransmission: accepting it could double-spend the shared output.
        let store = MemoryDeliveryStore::default();
        store
            .prepare_exact(SETTLEMENT, EFFECT, TX, RAW)
            .expect("first prepare");
        assert_eq!(
            store
                .prepare_exact(SETTLEMENT, EFFECT, TX, b"a different transaction")
                .unwrap_err(),
            DeliveryError::ConflictingRetransmission
        );
    }

    #[test]
    fn a_different_effect_id_for_the_same_settlement_is_refused() {
        let store = MemoryDeliveryStore::default();
        store
            .prepare_exact(SETTLEMENT, EFFECT, TX, RAW)
            .expect("first prepare");
        assert_eq!(
            store
                .prepare_exact(SETTLEMENT, [4; 32], TX, RAW)
                .unwrap_err(),
            DeliveryError::ConflictingRetransmission
        );
    }

    #[test]
    fn zero_identifiers_and_empty_bytes_are_refused() {
        let store = MemoryDeliveryStore::default();
        assert_eq!(
            store.prepare_exact([0; 32], EFFECT, TX, RAW).unwrap_err(),
            DeliveryError::InvalidTransaction
        );
        assert_eq!(
            store
                .prepare_exact(SETTLEMENT, [0; 32], TX, RAW)
                .unwrap_err(),
            DeliveryError::InvalidTransaction
        );
        assert_eq!(
            store
                .prepare_exact(SETTLEMENT, EFFECT, [0; 32], RAW)
                .unwrap_err(),
            DeliveryError::InvalidTransaction
        );
        assert_eq!(
            store
                .prepare_exact(SETTLEMENT, EFFECT, TX, b"")
                .unwrap_err(),
            DeliveryError::InvalidTransaction
        );
    }

    #[test]
    fn an_oversized_transaction_is_refused_before_storage() {
        let store = MemoryDeliveryStore::default();
        let oversized = vec![0_u8; MAX_RAW_TRANSACTION_BYTES + 1];
        assert_eq!(
            store
                .prepare_exact(SETTLEMENT, EFFECT, TX, &oversized)
                .unwrap_err(),
            DeliveryError::BoundsExceeded
        );
    }

    #[test]
    fn the_fingerprint_is_domain_separated_and_length_committed() {
        // Two different byte strings must not share a fingerprint, and the
        // length is committed so a prefix cannot collide with a longer body.
        assert_ne!(fingerprint(b"ab"), fingerprint(b"ba"));
        assert_ne!(fingerprint(b"a"), fingerprint(b"a\0"));
    }

    #[test]
    fn marking_an_absent_settlement_is_refused() {
        let store = MemoryDeliveryStore::default();
        assert_eq!(
            store.mark_submitted(&SETTLEMENT).unwrap_err(),
            DeliveryError::NotFound
        );
    }
}
