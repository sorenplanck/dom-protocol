//! Observed events and the cursor's network identity (Annex M M.9.2).

/// The F5 networks (M.3.1). Mainnet is absent by design.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum BitcoinNetworkV1 {
    /// Deterministic local network.
    Regtest = 0x01,
    /// Persistent controlled signet.
    CustomSignet = 0x02,
    /// The public signet.
    PublicSignet = 0x03,
}

impl BitcoinNetworkV1 {
    pub(crate) fn code(self) -> i64 {
        self as i64
    }
}

/// A previous output being spent (M.9.2).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct BitcoinOutPointV1 {
    /// Transaction id (internal byte order).
    pub txid: [u8; 32],
    /// Output index.
    pub vout: u32,
}

/// A bounded, observed Bitcoin event (M.9.2). Heights are `Option` where
/// the mempool has not yet confirmed a transaction.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum BitcoinObservedEventV1 {
    /// The funding transaction was seen (possibly unconfirmed).
    FundingSeen {
        /// Funding txid.
        txid: [u8; 32],
        /// Confirmation height, if mined.
        height: Option<u64>,
    },
    /// The funding transaction confirmed.
    FundingConfirmed {
        /// Funding txid.
        txid: [u8; 32],
        /// Containing block hash.
        block_hash: [u8; 32],
        /// Block height.
        height: u64,
    },
    /// A key-path claim witness was seen.
    ClaimWitnessSeen {
        /// Claim txid.
        txid: [u8; 32],
        /// Claim wtxid.
        wtxid: [u8; 32],
    },
    /// The claim confirmed, producing an evidence ref.
    ClaimConfirmed {
        /// Reference to the verified evidence.
        evidence_ref: [u8; 32],
        /// Block height.
        height: u64,
    },
    /// A script-path refund was seen.
    RefundSeen {
        /// Refund txid.
        txid: [u8; 32],
        /// Refund wtxid.
        wtxid: [u8; 32],
    },
    /// The refund confirmed, producing an evidence ref.
    RefundConfirmed {
        /// Reference to the verified evidence.
        evidence_ref: [u8; 32],
        /// Block height.
        height: u64,
    },
    /// A conflicting funding output was observed (double-spend).
    FundingConflict {
        /// The expected outpoint txid.
        expected: [u8; 32],
        /// The observed conflicting txid.
        observed: [u8; 32],
    },
    /// A reorg invalidated observations from `from_height` upward.
    ReorgInvalidated {
        /// The fork height (inclusive) from which observations are void.
        from_height: u64,
        /// The old chain tip.
        old_tip: [u8; 32],
        /// The new chain tip.
        new_tip: [u8; 32],
    },
}

impl BitcoinObservedEventV1 {
    /// The event kind discriminant, for the idempotency key (M.10.4).
    pub(crate) fn kind_code(&self) -> u8 {
        match self {
            Self::FundingSeen { .. } => 1,
            Self::FundingConfirmed { .. } => 2,
            Self::ClaimWitnessSeen { .. } => 3,
            Self::ClaimConfirmed { .. } => 4,
            Self::RefundSeen { .. } => 5,
            Self::RefundConfirmed { .. } => 6,
            Self::FundingConflict { .. } => 7,
            Self::ReorgInvalidated { .. } => 8,
        }
    }

    /// The height an observation is anchored at, if any. Reorg
    /// invalidation voids every stored observation at or above the fork
    /// height (M.9.5, P12).
    pub(crate) fn anchor_height(&self) -> Option<u64> {
        match self {
            Self::FundingSeen { height, .. } => *height,
            Self::FundingConfirmed { height, .. }
            | Self::ClaimConfirmed { height, .. }
            | Self::RefundConfirmed { height, .. } => Some(*height),
            Self::ClaimWitnessSeen { .. }
            | Self::RefundSeen { .. }
            | Self::FundingConflict { .. }
            | Self::ReorgInvalidated { .. } => None,
        }
    }
}
