//! Bitcoin evidence verifier and USPE bridge (Annex M v3.2, M.9).
//!
//! Keystone's role (M.9.1): a trust-minimized, replaceable, NON-custodial
//! evidence module. It MAY verify headers, inclusion, witness and outcome
//! rules; it MAY NOT build or authorize funding, generate or select a
//! nonce, sign, adapt a signature, export a share or key, choose
//! templates/terms/policies, or trigger a claim/refund bypass. It never
//! sees `t`.
//!
//! This crate is that module in native Rust over the audited `bitcoin` crate.
//! V1 remains available as a byte-frozen legacy structural format. V2 requires
//! a complete mutation-checked block, authenticates its exact witnesses through
//! the coinbase commitment, and can produce the opaque, externally
//! header-authenticated outcome accepted by the USPE bridge only when that
//! authority also binds the canonical evidence/route provenance — never `t`,
//! never a nonce, never a preimage (M.9.5, M.10.1).

#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod bridge;
mod evidence;
mod evidence_v2;
mod merkle_v2;
mod verifier;
mod verifier_v2;

pub use bridge::verified_v2_outcome_to_uspe_event;
pub use evidence::{
    BitcoinEvidenceNetworkV1, BitcoinOutPointV1, BitcoinOutcomeV1, BoundedMerkleBranchV1,
    KeystoneBitcoinEvidenceV1, VerifiedBitcoinOutcomeV1,
};
pub use evidence_v2::{
    BitcoinEvidenceNetworkV2, BitcoinEvidenceRouteBindingV2, BitcoinHeaderPolicyBindingV2,
    BitcoinOutPointV2, BitcoinOutcomeV2, BitcoinTransactionClaimV2, EvidenceCodecErrorV2,
    KeystoneBitcoinEvidenceV2,
};
pub use verifier::{verify_evidence, EvidenceError};
pub use verifier_v2::{
    verify_evidence_v2, AuthenticatedBlockV2, EvidenceVerificationErrorV2,
    RegtestHeaderAuthorityErrorV2, RegtestHeaderAuthorityV2, RegtestHeaderCheckpointV2,
    RegtestHeaderPolicyV2, VerifiedBitcoinOutcomeV2,
};
