//! Native Solana escrow program for the DOM `ConditionLock` leg.
//!
//! It supports native SOL and the classic SPL Token Program. Token-2022 is
//! rejected by strict program-id checks in V1.

#![forbid(unsafe_code)]

pub mod error;
pub mod processor;
pub mod secret;

#[cfg(not(feature = "no-entrypoint"))]
mod entrypoint;

solana_program::declare_id!("3KN5WMzZsmwDCfKYheaVgx8Xo4veke815LJo3iYrdeNw");
