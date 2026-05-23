//! # dom-core
//!
//! Consensus constants and primitive types for the DOM protocol.
//!
//! All constants in this crate are consensus-critical unless explicitly
//! marked as `POLICY`. Modifications require a network-wide upgrade.
//!
//! Source of truth: DOM_RFC_0000_Consensus_Constants.md

#![deny(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::arithmetic_side_effects)]
#![deny(clippy::cast_possible_truncation)]
#![deny(clippy::cast_sign_loss)]
#![deny(clippy::integer_division)]

pub mod address;
pub mod constants;
pub mod error;
pub mod types;

pub use address::{Address, ADDRESS_HRP_MAINNET, ADDRESS_HRP_TESTNET};
pub use constants::*;
pub use error::DomError;
pub use types::*;
