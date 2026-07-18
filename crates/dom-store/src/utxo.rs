//! UTXO set — Unspent Transaction Output tracking.

use dom_core::{BlockHeight, DomError, COINBASE_MATURITY};

pub(crate) const fn utxo_record_has_canonical_prefix(length: usize, coinbase_flag: u8) -> bool {
    length >= 9 && (coinbase_flag == 0 || coinbase_flag == 1)
}

pub(crate) const fn coinbase_is_mature_at(
    is_coinbase: bool,
    block_height: u64,
    current_height: u64,
    maturity: u64,
) -> bool {
    !is_coinbase || current_height.saturating_sub(block_height) >= maturity
}

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
        if !utxo_record_has_canonical_prefix(bytes.len(), bytes[8]) {
            return Err(DomError::Malformed(
                "utxo entry has invalid coinbase flag".into(),
            ));
        }
        let block_height = u64::from_le_bytes(bytes[0..8].try_into().unwrap());
        let is_coinbase = match bytes[8] {
            0 => false,
            1 => true,
            _ => unreachable!("canonical prefix rejects invalid coinbase flags"),
        };
        let proof = bytes[9..].to_vec();
        Ok(Self {
            block_height,
            is_coinbase,
            proof,
        })
    }

    /// Check if this UTXO is mature enough to spend at `current_height`
    /// under the canonical `COINBASE_MATURITY` (Mainnet / Testnet).
    ///
    /// Networks that use a different maturity (e.g. `Network::Regtest`
    /// with `REGTEST_COINBASE_MATURITY`) MUST call `is_mature_for`
    /// instead. This method is kept unchanged for backwards
    /// compatibility with code that hard-binds to mainnet rules.
    pub fn is_mature(&self, current_height: u64) -> bool {
        self.is_mature_for(current_height, COINBASE_MATURITY)
    }

    /// Check maturity against a network-specific maturity threshold.
    ///
    /// Non-coinbase outputs are always mature (the maturity rule
    /// applies only to coinbase outputs, identical to Mainnet/Testnet
    /// rules). The only knob the caller controls is the number of
    /// confirmations required for a coinbase to be spendable.
    pub fn is_mature_for(&self, current_height: u64, maturity: u64) -> bool {
        coinbase_is_mature_at(
            self.is_coinbase,
            self.block_height,
            current_height,
            maturity,
        )
    }
}

/// In-memory UTXO set for validation (backed by LMDB for persistence).
pub struct UtxoSet;

impl UtxoSet {
    /// Validate that an input commitment exists and is mature under the
    /// canonical `COINBASE_MATURITY`. Network-aware callers should use
    /// `validate_input_with_maturity`.
    pub fn validate_input(entry: &UtxoEntry, current_height: BlockHeight) -> Result<(), DomError> {
        Self::validate_input_with_maturity(entry, current_height, COINBASE_MATURITY)
    }

    /// Validate that `entry` is spendable at `current_height` under an
    /// explicit `maturity` threshold. Used by `ChainState` to honour
    /// `Network::Regtest`'s shorter maturity (`REGTEST_COINBASE_MATURITY`)
    /// while keeping Mainnet/Testnet validation unchanged.
    pub fn validate_input_with_maturity(
        entry: &UtxoEntry,
        current_height: BlockHeight,
        maturity: u64,
    ) -> Result<(), DomError> {
        if !entry.is_mature_for(current_height.0, maturity) {
            let mature_at = entry.block_height.saturating_add(maturity);
            return Err(DomError::TemporarilyInvalid(format!(
                "coinbase output not mature until height {}",
                mature_at
            )));
        }
        Ok(())
    }
}

#[cfg(test)]
mod is_mature_for_tests {
    use super::*;

    fn cb_entry(at: u64) -> UtxoEntry {
        UtxoEntry {
            block_height: at,
            is_coinbase: true,
            proof: vec![],
        }
    }

    #[test]
    fn non_coinbase_is_always_mature_regardless_of_threshold() {
        let mut e = cb_entry(100);
        e.is_coinbase = false;
        assert!(e.is_mature_for(0, COINBASE_MATURITY));
        assert!(e.is_mature_for(50, COINBASE_MATURITY));
        assert!(e.is_mature_for(150, COINBASE_MATURITY));
        assert!(e.is_mature_for(150, 1));
    }

    #[test]
    fn coinbase_is_immature_at_height_equal_to_creation() {
        let e = cb_entry(100);
        assert!(!e.is_mature_for(100, COINBASE_MATURITY));
        assert!(!e.is_mature_for(100, 1));
    }

    #[test]
    fn coinbase_matures_when_delta_reaches_threshold_exactly() {
        let e = cb_entry(100);
        assert!(e.is_mature_for(100 + COINBASE_MATURITY, COINBASE_MATURITY));
        assert!(e.is_mature_for(101, 1));
    }

    #[test]
    fn regtest_threshold_one_matures_after_a_single_confirmation() {
        let e = cb_entry(10);
        assert!(!e.is_mature_for(10, 1));
        assert!(e.is_mature_for(11, 1));
        // and the mainnet rule still rejects until 1010
        assert!(!e.is_mature_for(11, COINBASE_MATURITY));
    }

    #[test]
    fn is_mature_legacy_method_still_uses_mainnet_threshold() {
        let e = cb_entry(0);
        assert!(!e.is_mature(999));
        assert!(e.is_mature(1000));
    }
}
