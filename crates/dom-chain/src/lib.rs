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

#[cfg(kani)]
mod kani_invariants;

pub use chain_state::{
    genesis_canonical_changeset, ChainState, ConnectResult, ReorgBlockDelta, ReorgDelta,
    CHAIN_CORRUPT_SENTINEL, MAX_RETAINED_SIDE_BRANCH_LENGTH, MAX_RETAINED_SIDE_BRANCH_REORG_DEPTH,
    MAX_RETAINED_SIDE_BRANCH_TIPS,
};
pub use genesis::{
    build_canonical_genesis, canonical_genesis_inscription, canonical_header_identifier,
    validate_mainnet_genesis_identity, CanonicalGenesis, GenesisInscriptionV1,
    MainnetGenesisIdentityV1, GENESIS_INSCRIPTION_VERSION, MAINNET_GENESIS_IDENTITY_VERSION,
    MAX_GENESIS_INSCRIPTION_BYTES,
};
pub use ibd::{
    IbdControl, IbdInterruption, IbdPhase, IbdState, PersistedIbdState, IBD_SESSION_METADATA_KEY,
};
