//! End-to-end integration tests for DOM Protocol.
//!
//! These tests spawn real nodes, mine blocks, relay transactions, and verify
//! the full system works together (not just unit-level correctness).

#![deny(unsafe_code)]

pub mod helpers;

// Tests are in separate modules but not exported
// They run via `cargo test -p dom-integration-tests`
