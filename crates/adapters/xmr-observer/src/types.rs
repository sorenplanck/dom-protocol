//! Neutral Monero observation types.

/// Monero network.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum XmrNetwork {
    /// Mainnet.
    Mainnet,
    /// Stagenet.
    Stagenet,
    /// Testnet/regtest.
    Testnet,
}

/// Canonical chain tip agreed by quorum.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CanonicalTip {
    /// Height of the top block, not chain length.
    pub height: u64,
    /// Top block hash.
    pub hash: [u8; 32],
}

/// One node's health/tip observation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeObservation {
    /// Redacted/public node label.
    pub node: String,
    /// Reported network.
    pub network: XmrNetwork,
    /// RPC synchronization flag.
    pub synchronized: bool,
    /// Top block height.
    pub tip_height: u64,
    /// Target chain length reported by the node.
    pub target_height: u64,
    /// Top block hash.
    pub top_hash: [u8; 32],
}

impl NodeObservation {
    /// Converts to the quorum key.
    pub const fn canonical_tip(&self) -> CanonicalTip {
        CanonicalTip {
            height: self.tip_height,
            hash: self.top_hash,
        }
    }
}

/// Transaction location reported by a node.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum XmrTransactionStatus {
    /// Unknown to the node.
    Unseen,
    /// Present in the mempool.
    InPool,
    /// Included in a canonical block according to the node.
    InBlock { block_height: u64 },
}

/// Quorum-backed status and inclusion anchor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct XmrConfirmationStatus {
    /// Transaction location.
    pub status: XmrTransactionStatus,
    /// Inclusion block hash when mined.
    pub inclusion_block_hash: Option<[u8; 32]>,
    /// Relative confirmations.
    pub confirmations: u64,
    /// Agreed tip used for the calculation.
    pub canonical_tip: CanonicalTip,
}

impl XmrConfirmationStatus {
    /// True only for a mined transaction meeting the threshold.
    pub fn is_final(&self, required: u64) -> bool {
        matches!(self.status, XmrTransactionStatus::InBlock { .. })
            && self.confirmations >= required
    }
}

/// Relative confirmations, including the inclusion block as confirmation one.
pub fn relative_confirmations(inclusion_height: u64, latest_height: u64) -> Option<u64> {
    latest_height
        .checked_sub(inclusion_height)
        .map(|distance| distance + 1)
}
