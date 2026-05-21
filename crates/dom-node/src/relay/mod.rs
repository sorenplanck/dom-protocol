//! Transaction relay subsystem.
//!
//! Provides mempool relay deduplication and Dandelion++ privacy routing
//! for transaction propagation across the P2P network.

pub mod dandelion;
pub mod tx_relay;

pub use dandelion::{DandelionRouter, PropagationPhase};
pub use tx_relay::{RelayDecision, TxRelay};
