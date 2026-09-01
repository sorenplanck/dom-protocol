//! Reorg-aware, multi-RPC Monero observer primitives.

#![forbid(unsafe_code)]

mod confirmations;
mod daemon;
mod error;
mod pool;
mod types;

pub use confirmations::confirmation_status;
pub use daemon::{HttpXmrRpc, XmrRpc};
pub use error::XmrObserverError;
pub use pool::XmrRpcPool;
pub use types::{
    relative_confirmations, CanonicalTip, NodeObservation, XmrConfirmationStatus, XmrNetwork,
    XmrTransactionStatus,
};

/// Opaque cursor version for simple consumers.
pub const CURSOR_VERSION: u8 = 2;

/// Minimal versioned cursor used outside Kaystra's richer source cursor.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct XmrCursor {
    /// Next height to scan.
    pub next_height: u64,
    /// Last canonical hash already consumed.
    pub last_canonical_hash: Option<[u8; 32]>,
}

impl XmrCursor {
    /// Deterministic encoding.
    pub fn encode(&self) -> Vec<u8> {
        let mut output = Vec::with_capacity(42);
        output.push(CURSOR_VERSION);
        output.extend_from_slice(&self.next_height.to_be_bytes());
        match self.last_canonical_hash {
            Some(hash) => {
                output.push(1);
                output.extend_from_slice(&hash);
            }
            None => output.push(0),
        }
        output
    }

    /// Strict decoding.
    pub fn decode(bytes: &[u8]) -> Result<Self, XmrObserverError> {
        if bytes.len() < 10 || bytes[0] != CURSOR_VERSION {
            return Err(XmrObserverError::InvalidCursor);
        }
        let mut height = [0_u8; 8];
        height.copy_from_slice(&bytes[1..9]);
        let next_height = u64::from_be_bytes(height);
        match (bytes[9], bytes.len()) {
            (0, 10) => Ok(Self {
                next_height,
                last_canonical_hash: None,
            }),
            (1, 42) => {
                let mut hash = [0_u8; 32];
                hash.copy_from_slice(&bytes[10..42]);
                if hash == [0; 32] {
                    return Err(XmrObserverError::InvalidCursor);
                }
                Ok(Self {
                    next_height,
                    last_canonical_hash: Some(hash),
                })
            }
            _ => Err(XmrObserverError::InvalidCursor),
        }
    }
}
