//! The USPE bridge (Annex M M.9.5).
//!
//! The USPE consumes ONLY the verified public outcome and its
//! `terms_hash`. `t`, nonces and preimages never reach it (M.9.5,
//! M.10.1): this function's input is a [`VerifiedBitcoinOutcomeV1`], which
//! by construction contains no secret material, and its output is a plain
//! USPE event.

use uspe::AssuranceEvent;

use crate::evidence::VerifiedBitcoinOutcomeV1;

/// Turns a verified Bitcoin outcome into the USPE event that binds the
/// claim to the terms (M.9.5). The outcome proves the obligation's
/// on-chain resolution; the USPE decides the economic consequence under
/// its ratified policy, not on any assertion by Relay or Keystone.
#[must_use]
pub fn verified_outcome_to_uspe_event(outcome: &VerifiedBitcoinOutcomeV1) -> AssuranceEvent {
    // Only the terms binding crosses; the outcome's txid/wtxid/height are
    // recorded elsewhere as evidence refs, never as secret material.
    AssuranceEvent::CompensationClaimed {
        terms_hash: outcome.terms_hash,
    }
}
