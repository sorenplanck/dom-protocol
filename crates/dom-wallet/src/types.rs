//! Core wallet types.

// Custom serde for [u8; 33]
mod serde_commitment {
    use serde::{Deserializer, Serializer};
    pub fn serialize<S>(bytes: &[u8; 33], s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        s.serialize_bytes(&bytes[..])
    }
    pub fn deserialize<'de, D>(d: D) -> Result<[u8; 33], D::Error>
    where
        D: Deserializer<'de>,
    {
        let v: Vec<u8> = serde::de::Deserialize::deserialize(d)?;
        if v.len() != 33 {
            return Err(serde::de::Error::custom("commitment must be 33 bytes"));
        }
        let mut a = [0u8; 33];
        a.copy_from_slice(&v);
        Ok(a)
    }
}
use dom_core::DomError;
use dom_tx::TxError;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use zeroize::Zeroizing;

/// A wallet-owned unspent transaction output.
///
/// Implements [`dom_tx::InputSource`] for use in transaction building.
/// The blinding factor is held in a [`Zeroizing<[u8; 32]>`] so it is wiped from
/// memory when the output is dropped.
#[derive(Clone, Serialize, Deserialize)]
pub struct OwnedOutput {
    /// Compressed 33-byte Pedersen commitment.
    #[serde(with = "serde_commitment")]
    pub commitment: [u8; 33],
    /// Value in noms.
    pub value: u64,
    /// 32-byte blinding factor (zeroized on drop).
    #[serde(with = "serde_blinding")]
    pub blinding: Zeroizing<[u8; 32]>,
    /// Block height where output was created.
    pub block_height: u64,
    /// Whether this is a coinbase output (subject to maturity).
    pub is_coinbase: bool,
    /// Whether this output has been spent.
    pub spent: bool,
    /// If reserved for a pending transaction, the tx hash.
    pub reserved_for_tx: Option<[u8; 32]>,
}

// Custom serialization for Zeroizing<[u8; 32]> blinding factor.
mod serde_blinding {
    use serde::{Deserializer, Serializer};
    use zeroize::Zeroizing;

    pub fn serialize<S>(bytes: &Zeroizing<[u8; 32]>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(&bytes[..])
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Zeroizing<[u8; 32]>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes: Vec<u8> = serde::de::Deserialize::deserialize(deserializer)?;
        if bytes.len() != 32 {
            return Err(serde::de::Error::custom("blinding factor must be 32 bytes"));
        }
        let mut array = [0u8; 32];
        array.copy_from_slice(&bytes);
        Ok(Zeroizing::new(array))
    }
}

impl OwnedOutput {
    /// Create a new unspent output.
    pub fn new(
        commitment: [u8; 33],
        value: u64,
        blinding: [u8; 32],
        block_height: u64,
        is_coinbase: bool,
    ) -> Self {
        Self {
            commitment,
            value,
            blinding: Zeroizing::new(blinding),
            block_height,
            is_coinbase,
            spent: false,
            reserved_for_tx: None,
        }
    }

    /// Check if this output is mature under the canonical
    /// `COINBASE_MATURITY` rule (1000 blocks for coinbase outputs;
    /// non-coinbase outputs are always mature).
    ///
    /// Network-aware callers (e.g. wallets running on `Network::Regtest`)
    /// MUST use `is_mature_for` so the appropriate threshold is applied.
    pub fn is_mature(&self, current_height: u64) -> bool {
        self.is_mature_for(current_height, dom_core::COINBASE_MATURITY)
    }

    /// Check maturity against an explicit threshold (e.g. the
    /// `Network::coinbase_maturity()` value).
    pub fn is_mature_for(&self, current_height: u64, maturity: u64) -> bool {
        if !self.is_coinbase {
            return true;
        }
        current_height.saturating_sub(self.block_height) >= maturity
    }

    /// Check if this output can be spent (not spent, not reserved, and
    /// mature under the mainnet rule). See `is_spendable_for`.
    pub fn is_spendable(&self, current_height: u64) -> bool {
        !self.spent && self.reserved_for_tx.is_none() && self.is_mature(current_height)
    }

    /// Spend-eligibility check parameterised by `maturity`. Honours the
    /// caller's network rule (mainnet 1000, regtest 1, etc).
    pub fn is_spendable_for(&self, current_height: u64, maturity: u64) -> bool {
        !self.spent
            && self.reserved_for_tx.is_none()
            && self.is_mature_for(current_height, maturity)
    }
}

impl dom_tx::InputSource for OwnedOutput {
    fn commitment(&self) -> [u8; 33] {
        self.commitment
    }

    fn value(&self) -> u64 {
        self.value
    }

    fn blinding(&self) -> [u8; 32] {
        *self.blinding
    }

    fn block_height(&self) -> u64 {
        self.block_height
    }

    fn is_coinbase(&self) -> bool {
        self.is_coinbase
    }
}

/// Network identifier (wallet-side mirror of `dom_config::Network`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Network {
    /// Mainnet (magic: 0x444F_4D31).
    Mainnet,
    /// Testnet (magic: 0x444F_4D54).
    Testnet,
    /// Regtest — DEV-ONLY (magic: 0x444F_4D52). Wallet coinbase maturity
    /// in this network is `dom_core::REGTEST_COINBASE_MATURITY` instead
    /// of the canonical `COINBASE_MATURITY`. Magic-byte isolation in
    /// `dom-wire` prevents Regtest peers from talking to real-network nodes.
    Regtest,
}

impl Network {
    /// Get the network magic bytes.
    pub fn magic(self) -> u32 {
        match self {
            Network::Mainnet => dom_core::NETWORK_MAGIC_MAINNET,
            Network::Testnet => dom_core::NETWORK_MAGIC_TESTNET,
            Network::Regtest => dom_core::NETWORK_MAGIC_REGTEST,
        }
    }

    /// Coinbase maturity (blocks) for this network. Mainnet / Testnet:
    /// `dom_core::COINBASE_MATURITY`. Regtest: `REGTEST_COINBASE_MATURITY`.
    pub fn coinbase_maturity(self) -> u64 {
        match self {
            Network::Mainnet | Network::Testnet => dom_core::COINBASE_MATURITY,
            Network::Regtest => dom_core::REGTEST_COINBASE_MATURITY,
        }
    }
}

/// Wallet balance breakdown.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
pub struct WalletBalance {
    /// Value in confirmed, mature outputs.
    pub confirmed: u64,
    /// Value in immature coinbase outputs.
    pub immature: u64,
    /// Value reserved for pending transactions.
    pub reserved: u64,
}

impl WalletBalance {
    /// Total value (confirmed + immature + reserved).
    pub fn total(&self) -> u64 {
        self.confirmed
            .saturating_add(self.immature)
            .saturating_add(self.reserved)
    }

    /// Spendable value (confirmed - reserved).
    pub fn spendable(&self) -> u64 {
        self.confirmed.saturating_sub(self.reserved)
    }
}

/// Errors that can occur in wallet operations.
#[derive(Debug, Error)]
pub enum WalletError {
    /// Insufficient funds to complete transaction.
    #[error("insufficient funds: have {have}, need {need}")]
    InsufficientFunds {
        /// Available value.
        have: u64,
        /// Required value.
        need: u64,
    },

    /// Output not found in wallet.
    #[error("output not found: {0}")]
    OutputNotFound(String),

    /// Output already spent.
    #[error("output already spent")]
    AlreadySpent,

    /// Coinbase output not yet mature.
    #[error("coinbase output matures at height {matures_at}")]
    NotMature {
        /// Block height at which the output matures.
        matures_at: u64,
    },

    /// I/O error.
    #[error("io error: {0}")]
    Io(String),

    /// Encryption error.
    #[error("encryption failed")]
    Encryption,

    /// Decryption error (likely wrong password).
    #[error("decryption failed")]
    Decryption,

    /// Serialization error.
    #[error("serialization error: {0}")]
    Serialization(String),

    /// Invalid password.
    #[error("invalid password")]
    InvalidPassword,

    /// Operation requires the wallet to be unlocked.
    #[error("wallet is locked; call unlock(password) before performing this operation")]
    Locked,

    /// Underlying error from dom-core.
    #[error("dom error: {0}")]
    Dom(#[from] DomError),

    /// Underlying error from dom-tx.
    #[error("tx error: {0}")]
    Tx(#[from] TxError),

    /// Cryptographic error.
    #[error("crypto error: {0}")]
    Crypto(String),
}
