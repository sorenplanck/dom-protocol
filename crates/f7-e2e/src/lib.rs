//! Compatibility facade for the F7 real-chain execution harness.
//!
//! Real anchor validation lives in the lower, Store-free
//! `f7-anchor-authority` crate so the Contracts Store can consume its opaque
//! capability without a dependency cycle.  This crate intentionally adds no
//! alternate constructor or caller-shaped evidence path.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub use f7_anchor_authority::{
    verify_bitcoin_funding_evidence, verify_f7_route_anchor_authority, F7AnchorAuthorityError,
    F7AnchorValidationRequestV1, VerifiedBitcoinFundingEvidenceV1, VerifiedF7AnchorAuthorizationV1,
    VerifiedF7RouteAnchorAuthorizationsV1, MAX_F7_DOM_SCAN_PAGES, MAX_F7_HEADER_CHAIN,
};

/// Backward-compatible error name retained for existing F7 diagnostics.
pub type F7EvidenceError = F7AnchorAuthorityError;
