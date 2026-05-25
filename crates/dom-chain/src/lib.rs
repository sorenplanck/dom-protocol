//! # dom-chain
//!
//! Chain state management: IBD, block validation, reorganization, chain selection.
//!
//! ## IBD (Initial Block Download) — headers-first
//!
//! 1. Connect to peers and request headers (GET_HEADERS)
//! 2. Validate headers (PoW, timestamps, difficulty)
//! 3. Once headers are verified, download full blocks in parallel
//! 4. Validate and commit each block atomically
//!
//! This prevents a low-work chain from wasting significant CPU.

#![deny(unsafe_code)]
#![deny(missing_docs)]

pub mod chain_state;
pub mod genesis;
pub mod ibd;
pub mod reorg;

pub use chain_state::{ChainState, ConnectResult, CHAIN_CORRUPT_SENTINEL};
pub use genesis::{build_genesis, build_mainnet_genesis, build_testnet_genesis, GenesisResult};
pub use ibd::{IbdPhase, IbdState};
