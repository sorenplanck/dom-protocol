//! Bitcoin evidence verifier and USPE bridge (Annex M v3.2, M.9).
//!
//! Keystone's role (M.9.1): a trust-minimized, replaceable, NON-custodial
//! evidence module. It MAY verify headers, inclusion, witness and outcome
//! rules; it MAY NOT build or authorize funding, generate or select a
//! nonce, sign, adapt a signature, export a share or key, choose
//! templates/terms/policies, or trigger a claim/refund bypass. It never
//! sees `t`.
//!
//! This crate is that module in native Rust over the audited `bitcoin`
//! crate. The verifier turns a [`KeystoneBitcoinEvidenceV1`] into a
//! [`VerifiedBitcoinOutcomeV1`], and the bridge feeds only the verified
//! public outcome and `terms_hash` into the USPE — never `t`, never a
//! nonce, never a preimage (M.9.5, M.10.1).

#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod bridge;
mod evidence;
mod verifier;

pub use bridge::verified_outcome_to_uspe_event;
pub use evidence::{
    BitcoinEvidenceNetworkV1, BitcoinOutPointV1, BitcoinOutcomeV1, BoundedMerkleBranchV1,
    KeystoneBitcoinEvidenceV1, VerifiedBitcoinOutcomeV1,
};
pub use verifier::{verify_evidence, EvidenceError};
