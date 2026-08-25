//! Gate G-F2 harness: adapts `dom-sim` to the durable engine's ports.
//!
//! G-F2 requires E2E against dom-sim with fault injection (crash at every
//! commit and dispatch boundary, duplication, reorder, reorg, late
//! evidence). This crate is NOT production: it is the test bench for the
//! engine + simulated chain + USPE composition.

#![forbid(unsafe_code)]

pub mod settlement;

pub use settlement::{SimEffectSink, SimSettlementChain, SinkAction};
