//! The V2-only USPE bridge (Annex M M.9.5).
//!
//! The USPE consumes only the externally header-authenticated public outcome
//! and its `terms_hash`. Legacy V1 structural evidence has no bridge here.
//! `t`, nonces and preimages never reach this boundary.

use uspe::AssuranceEvent;

use crate::verifier_v2::VerifiedBitcoinOutcomeV2;

/// Turns an opaque, externally header-authenticated V2 outcome into the USPE
/// event that binds the claim to the frozen terms.
///
/// [`VerifiedBitcoinOutcomeV2`] has no public constructor, so legacy or merely
/// structural evidence cannot cross this operational boundary.
#[must_use]
pub fn verified_v2_outcome_to_uspe_event(outcome: &VerifiedBitcoinOutcomeV2) -> AssuranceEvent {
    // Only the terms binding crosses; the outcome's txid/wtxid/height are
    // recorded elsewhere as evidence refs, never as secret material.
    AssuranceEvent::CompensationClaimed {
        terms_hash: outcome.terms_hash(),
    }
}
