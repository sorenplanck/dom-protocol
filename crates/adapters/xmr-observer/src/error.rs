//! Observer error taxonomy.

/// Every observer failure is fail-closed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum XmrObserverError {
    /// Transport/node unavailable.
    #[error("Monero RPC transport failure")]
    RpcTransport,
    /// Malformed or internally inconsistent response.
    #[error("malformed Monero RPC response")]
    MalformedResponse,
    /// Node serves another network.
    #[error("Monero RPC serves the wrong network")]
    WrongNetwork,
    /// Node is not synchronized.
    #[error("Monero RPC is not synchronized")]
    NotSynchronized,
    /// Observation lies above the agreed canonical tip.
    #[error("Monero observation is above the canonical tip")]
    StaleTip,
    /// Quorum configuration is impossible.
    #[error("invalid quorum: required {required}, available {available}")]
    InvalidQuorum { required: usize, available: usize },
    /// No unique canonical-tip winner reached quorum.
    #[error("conflicting Monero canonical tips")]
    ConflictingCanonicalTip,
    /// No unique transaction-status winner reached quorum.
    #[error("conflicting Monero transaction status")]
    ConflictingTransactionStatus,
    /// No unique block hash winner reached quorum.
    #[error("conflicting Monero block hash")]
    ConflictingBlockHash,
    /// Cursor bytes are invalid.
    #[error("invalid Monero observer cursor")]
    InvalidCursor,
}
