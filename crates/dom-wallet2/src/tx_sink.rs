//! [`TxSink`] — the write side of the node transport (broadcast a finalized tx).
//!
//! Mirrors the [`crate::ChainSource`] read side: a trait with a real impl
//! ([`crate::RpcChainSource`], over `POST /tx/submit`) and an in-memory fake
//! ([`InMemoryTxSink`]) so the wallet's submit orchestration is testable without
//! a node. The sink is pure transport — it never touches wallet state.

use dom_consensus::transaction::Transaction;
use thiserror::Error;

/// Outcome of a successful submission (mirrors the node's `/tx/submit` 200).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubmitOutcome {
    /// Hash the node assigned the accepted transaction.
    pub tx_hash: [u8; 32],
    /// Whether the node relayed it to a peer. `false` = accepted into the local
    /// (volatile) mempool but not yet retransmitted — the caller may resubmit.
    pub relayed: bool,
    /// Non-fatal node advisory (e.g. accepted-but-not-relayed).
    pub warning: Option<String>,
}

/// Broadcasts a finalized transaction to the network. Pure transport.
pub trait TxSink {
    /// Error surfaced by the backend. The fake uses [`FakeSinkError`].
    type Error: std::error::Error + 'static;

    /// Submit `tx` to the node. A successful return means the node accepted it
    /// into its mempool (see [`SubmitOutcome::relayed`] for whether it was
    /// relayed onward).
    fn submit_tx(&self, tx: &Transaction) -> Result<SubmitOutcome, Self::Error>;
}

/// Error type for the in-memory fake sink.
#[derive(Debug, Clone, Error)]
#[error("fake sink: {0}")]
pub struct FakeSinkError(pub String);

/// In-memory [`TxSink`] for tests: returns a preconfigured outcome (or error)
/// and counts submissions. No network.
pub struct InMemoryTxSink {
    result: Result<SubmitOutcome, FakeSinkError>,
    calls: std::cell::Cell<usize>,
}

impl InMemoryTxSink {
    /// A sink that accepts and relays.
    pub fn accepting(tx_hash: [u8; 32]) -> Self {
        Self {
            result: Ok(SubmitOutcome {
                tx_hash,
                relayed: true,
                warning: None,
            }),
            calls: std::cell::Cell::new(0),
        }
    }

    /// A sink that accepts but does NOT relay, carrying a warning.
    pub fn accepting_not_relayed(tx_hash: [u8; 32], warning: &str) -> Self {
        Self {
            result: Ok(SubmitOutcome {
                tx_hash,
                relayed: false,
                warning: Some(warning.to_owned()),
            }),
            calls: std::cell::Cell::new(0),
        }
    }

    /// A sink that rejects every submission.
    pub fn rejecting(reason: &str) -> Self {
        Self {
            result: Err(FakeSinkError(reason.to_owned())),
            calls: std::cell::Cell::new(0),
        }
    }

    /// Number of `submit_tx` calls so far.
    pub fn calls(&self) -> usize {
        self.calls.get()
    }
}

impl TxSink for InMemoryTxSink {
    type Error = FakeSinkError;

    fn submit_tx(&self, _tx: &Transaction) -> Result<SubmitOutcome, FakeSinkError> {
        self.calls.set(self.calls.get() + 1);
        self.result.clone()
    }
}
