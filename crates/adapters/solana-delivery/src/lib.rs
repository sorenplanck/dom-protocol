//! Exact signed Solana transaction delivery records.

#![forbid(unsafe_code)]

use std::{collections::HashMap, sync::RwLock};

use sha2::{Digest, Sha256};
use solana_types::SolanaSignature;

/// Conservative signed-transaction upper bound.
pub const MAX_SIGNED_TRANSACTION_BYTES: usize = 4_096;

/// Monotonic delivery state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeliveryState {
    /// Exact bytes persisted, not yet reconciled with RPC.
    Prepared,
    /// RPC accepted or already knew the signature.
    Submitted,
    /// Finalized chain evidence observed.
    Finalized,
}

/// Durable exact-byte delivery record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeliveryRecord {
    pub settlement_id: [u8; 32],
    pub source_operation_id: [u8; 32],
    pub signature: SolanaSignature,
    pub raw_fingerprint: [u8; 32],
    pub raw_transaction: Vec<u8>,
    pub state: DeliveryState,
}

/// Delivery error.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DeliveryError {
    #[error("invalid Solana delivery record")]
    Invalid,
    #[error("Solana signed transaction exceeds bound")]
    BoundsExceeded,
    #[error("non-canonical Solana retransmission")]
    ConflictingRetransmission,
    #[error("Solana delivery record not found")]
    NotFound,
    #[error("Solana delivery lock poisoned")]
    Poisoned,
    #[error("Solana delivery storage unavailable")]
    StorageUnavailable,
    #[error("Solana delivery storage corrupt")]
    Corrupt,
}

/// Domain-separated exact-byte fingerprint.
pub fn fingerprint(raw_transaction: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"DOM-INTEROP/SOLANA-EXACT-DELIVERY/V1\0");
    hasher.update((raw_transaction.len() as u64).to_be_bytes());
    hasher.update(raw_transaction);
    hasher.finalize().into()
}

/// Delivery store contract.
pub trait DeliveryStore: Send + Sync {
    fn load(&self, settlement_id: &[u8; 32]) -> Result<Option<DeliveryRecord>, DeliveryError>;
    fn prepare_exact(
        &self,
        settlement_id: [u8; 32],
        source_operation_id: [u8; 32],
        signature: SolanaSignature,
        raw_transaction: &[u8],
    ) -> Result<DeliveryRecord, DeliveryError>;
    fn mark_submitted(&self, settlement_id: &[u8; 32]) -> Result<(), DeliveryError>;
    fn mark_finalized(&self, settlement_id: &[u8; 32]) -> Result<(), DeliveryError>;
}

/// In-memory implementation for model tests.
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
        source_operation_id: [u8; 32],
        signature: SolanaSignature,
        raw_transaction: &[u8],
    ) -> Result<DeliveryRecord, DeliveryError> {
        validate(
            &settlement_id,
            &source_operation_id,
            signature,
            raw_transaction,
        )?;
        let raw_fingerprint = fingerprint(raw_transaction);
        let mut records = self.records.write().map_err(|_| DeliveryError::Poisoned)?;
        if let Some(existing) = records.get(&settlement_id) {
            if existing.source_operation_id != source_operation_id
                || existing.signature != signature
                || existing.raw_fingerprint != raw_fingerprint
                || existing.raw_transaction != raw_transaction
            {
                return Err(DeliveryError::ConflictingRetransmission);
            }
            return Ok(existing.clone());
        }
        let record = DeliveryRecord {
            settlement_id,
            source_operation_id,
            signature,
            raw_fingerprint,
            raw_transaction: raw_transaction.to_vec(),
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

    fn mark_finalized(&self, settlement_id: &[u8; 32]) -> Result<(), DeliveryError> {
        let mut records = self.records.write().map_err(|_| DeliveryError::Poisoned)?;
        let record = records
            .get_mut(settlement_id)
            .ok_or(DeliveryError::NotFound)?;
        record.state = DeliveryState::Finalized;
        Ok(())
    }
}

fn validate(
    settlement_id: &[u8; 32],
    source_operation_id: &[u8; 32],
    signature: SolanaSignature,
    raw_transaction: &[u8],
) -> Result<(), DeliveryError> {
    if settlement_id == &[0; 32]
        || source_operation_id == &[0; 32]
        || signature.0 == [0; 64]
        || raw_transaction.is_empty()
    {
        return Err(DeliveryError::Invalid);
    }
    if raw_transaction.len() > MAX_SIGNED_TRANSACTION_BYTES {
        return Err(DeliveryError::BoundsExceeded);
    }
    Ok(())
}
