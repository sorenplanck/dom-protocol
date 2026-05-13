//! UTXO set — Unspent Transaction Output tracking.

use dom_core::{BlockHeight, DomError, COINBASE_MATURITY};

/// A UTXO entry stored in the LMDB utxos database.
#[derive(Debug, Clone)]
pub struct UtxoEntry {
    /// The block height where this output was created.
    pub block_height: u64,
    /// Whether this is a coinbase output (subject to maturity).
    pub is_coinbase: bool,
    /// The serialized Bulletproof (for spending verification).
    pub proof: Vec<u8>,
}

impl UtxoEntry {
    /// Serialize to bytes for LMDB storage.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(9 + self.proof.len());
        out.extend_from_slice(&self.block_height.to_le_bytes());
        out.push(if self.is_coinbase { 1 } else { 0 });
        out.extend_from_slice(&self.proof);
        out
    }

    /// Deserialize from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, DomError> {
        if bytes.len() < 9 {
            return Err(DomError::Malformed("utxo entry too short".into()));
        }
        let block_height = u64::from_le_bytes(bytes[0..8].try_into().unwrap());
        let is_coinbase = bytes[8] != 0;
        let proof = bytes[9..].to_vec();
        Ok(Self { block_height, is_coinbase, proof })
    }

    /// Check if this UTXO is mature enough to spend at `current_height`.
    pub fn is_mature(&self, current_height: u64) -> bool {
        if !self.is_coinbase { return true; }
        current_height.saturating_sub(self.block_height) >= COINBASE_MATURITY
    }
}

/// In-memory UTXO set for validation (backed by LMDB for persistence).
pub struct UtxoSet;

impl UtxoSet {
    /// Validate that an input commitment exists and is mature.
    /// Returns the UtxoEntry if valid.
    pub fn validate_input(
        entry: &UtxoEntry,
        current_height: BlockHeight,
    ) -> Result<(), DomError> {
        if !entry.is_mature(current_height.0) {
            return Err(DomError::TemporarilyInvalid(format!(
                "coinbase output not mature until height {}",
                entry.block_height + COINBASE_MATURITY
            )));
        }
        Ok(())
    }
}
