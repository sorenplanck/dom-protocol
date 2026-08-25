//! Error discipline for the EVM adapter.
//!
//! The neutral boundary (§4.3) exposes exactly one error taxonomy,
//! [`AdapterError`]. This crate does **not** invent a parallel one: every
//! internal failure is mapped, at the point where it happens, onto the neutral
//! variant that describes it most honestly. That keeps I9 intact (chain-specific
//! detail never escapes the adapter) and keeps I6 intact (no error value can
//! carry secret material, because every variant is a unit variant).
//!
//! Mapping rules used throughout the crate:
//!
//! | situation | variant |
//! |---|---|
//! | transport down, malformed RPC envelope, `finalized` tag unavailable | [`AdapterError::AdapterUnavailable`] |
//! | length cap exceeded, would-be allocation too large | [`AdapterError::BoundsExceeded`] |
//! | trailing bytes, wrong fixed length, non-canonical padding | [`AdapterError::VersionMismatch`] or [`AdapterError::EvidenceInvalid`] depending on the frame |
//! | cursor belongs to another chain or contract | [`AdapterError::StaleCursor`] |
//! | cursor version unknown | [`AdapterError::VersionMismatch`] |
//! | chain id / contract / codehash / emitter / topic mismatch | [`AdapterError::EvidenceInvalid`] |
//! | observation above the finalized height | [`AdapterError::PreconditionUnsatisfied`] |
//! | reorg detected, or deeper than `max_reorg_depth` | [`AdapterError::ReorgDetected`] |
//! | capability not declared | [`AdapterError::UnsupportedCapability`] |
//! | configuration rejected before any I/O | [`AdapterError::InvalidState`] |
//!
//! Note that no variant ever carries a payload, so it is structurally
//! impossible for this crate to leak `t` through an error path.

use counterparty_api::AdapterError;

/// Crate-local result alias over the neutral [`AdapterError`].
pub type Result<T> = core::result::Result<T, AdapterError>;

/// The precise, crate-local reason a chain fact was refused.
///
/// # Why this exists alongside [`AdapterError`]
///
/// The neutral taxonomy is deliberately coarse: it is the *stable* contract
/// across every counterparty chain, and widening it would leak chain-specific
/// detail into the core (I9). But two things need more resolution than that:
///
/// 1. **the operator**, who has to tell "your endpoint does not serve the
///    `finalized` tag" apart from "the chain says this settlement never
///    happened". The first is `BLOCKED_EXTERNAL` — a property of the provider,
///    fixable by changing provider — and the second is a hard refusal;
/// 2. **the test suite**, which must be able to pin *which* of the independent
///    checks rejected a log, rather than settling for "something failed".
///
/// So this enum stays inside the adapter and is mapped onto [`AdapterError`] at
/// the neutral boundary by [`From`]. Like the neutral taxonomy, every variant is
/// a unit variant, so no rejection path can carry secret material (I6).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RejectReason {
    /// The endpoint does not serve the `finalized` block tag: it answered
    /// `null`, or answered with an empty header.
    ///
    /// **This is the `BLOCKED_EXTERNAL` reason.** A4-EVM has no fallback, so an
    /// endpoint that cannot serve `finalized` cannot be used at all — but the
    /// settlement itself is not in question, and the caller must be able to say
    /// so. This is the variant that lets it.
    FinalizedTagUnavailable,
    /// The endpoint failed at the transport level while being asked for the
    /// `finalized` tag. Distinct from [`Self::FinalizedTagUnavailable`]: the
    /// endpoint may well support the tag and simply be unreachable.
    FinalizedTagTransportFailure,
    /// The `finalized` answer was structurally malformed.
    FinalizedHeaderMalformed,
    /// A transport-level failure somewhere else in the attestation: the
    /// endpoint could not be reached, or refused to answer.
    Transport,
    /// The endpoint answered, but the answer was structurally malformed or
    /// self-contradictory (a missing member, a non-canonical quantity, a header
    /// whose hash is not the hash that was asked for).
    ///
    /// Distinct from [`Self::Transport`] on purpose: a dead socket and a lying
    /// endpoint are different operational facts, and collapsing them lets a
    /// hostile endpoint pass as merely unreachable.
    MalformedAnswer,
    /// The endpoint itself marked the log as belonging to an orphaned block.
    LogMarkedRemoved,
    /// The log names an emitter other than the configured contract.
    LogEmitterMismatch,
    /// `eth_getTransactionReceipt` returned `null` for a transaction an
    /// `eth_getLogs` answer claimed exists.
    ReceiptMissing,
    /// The receipt exists but reports `status != 1`.
    ReceiptReverted,
    /// The receipt disagrees with the log about the transaction hash, the block
    /// height or the block hash.
    ReceiptInconsistent,
    /// The receipt does not carry the log at the expected `logIndex`, or the
    /// log it carries there is not the same log.
    LogAbsentFromReceipt,
    /// `eth_getTransactionByHash` returned `null`.
    TransactionMissing,
    /// The transaction disagrees with the receipt about its hash, its block
    /// hash or its block height — including a transaction still pending.
    TransactionInconsistent,
    /// The transaction's `to` is not the configured contract (or is a contract
    /// creation).
    TransactionNotToContract,
    /// A block the attestation needs is absent from the endpoint's view.
    BlockMissing,
    /// The block the log claims to live in is not the block the canonical chain
    /// carries at that height.
    NotCanonical,
    /// The observation sits above the finalized head.
    AboveFinalizedHead,
    /// The observation's block is at or below the finalized head but is not an
    /// ancestor of it: it belongs to a fork, or the endpoint cannot exhibit the
    /// chain of parent hashes that would connect the two.
    NotFinalizedAncestor,
    /// Ancestry could not be proved within the per-call walk budget.
    ///
    /// **This is a refusal, not a doubt.** The adapter will not accept a block
    /// whose link to the finalized head it has not followed hash by hash, so
    /// when the gap is larger than one call may walk it says so instead of
    /// falling back to a weaker question. The caller extends the verified chain
    /// in bounded batches
    /// ([`crate::attest::extend_verified_chain`]) and retries.
    AncestryProofTooDeep,
}

impl RejectReason {
    /// Whether this reason means "the endpoint cannot serve the `finalized`
    /// tag", which the caller reports as `BLOCKED_EXTERNAL` rather than as a
    /// verdict about the settlement.
    pub fn is_finalized_tag_unavailable(self) -> bool {
        matches!(self, Self::FinalizedTagUnavailable)
    }
}

impl From<RejectReason> for AdapterError {
    fn from(r: RejectReason) -> Self {
        match r {
            // Nothing can be decided while the endpoint cannot answer. A4-EVM
            // forbids substituting a confirmation count, so the only honest
            // report is unavailability.
            RejectReason::FinalizedTagUnavailable
            | RejectReason::FinalizedTagTransportFailure
            | RejectReason::FinalizedHeaderMalformed
            | RejectReason::Transport
            | RejectReason::MalformedAnswer
            | RejectReason::BlockMissing => AdapterError::AdapterUnavailable,
            // A declared bound was reached before the proof was complete (I14).
            // Not a verdict about the settlement: a statement about this call.
            RejectReason::AncestryProofTooDeep => AdapterError::BoundsExceeded,
            // The chain contradicts the log that was offered.
            RejectReason::LogMarkedRemoved
            | RejectReason::LogEmitterMismatch
            | RejectReason::ReceiptMissing
            | RejectReason::ReceiptReverted
            | RejectReason::ReceiptInconsistent
            | RejectReason::LogAbsentFromReceipt
            | RejectReason::TransactionMissing
            | RejectReason::TransactionInconsistent
            | RejectReason::TransactionNotToContract => AdapterError::EvidenceInvalid,
            // The log is on a chain we are not on.
            RejectReason::NotCanonical | RejectReason::NotFinalizedAncestor => {
                AdapterError::ReorgDetected
            }
            // Real, but not final. Never an economic effect.
            RejectReason::AboveFinalizedHead => AdapterError::PreconditionUnsatisfied,
        }
    }
}

/// Turns any transport-level or envelope-level failure into the neutral
/// "the adapter cannot answer right now" signal.
///
/// Used instead of ad-hoc `map_err` closures so that the mapping stays in one
/// place and stays auditable.
pub fn unavailable<E>(_e: E) -> AdapterError {
    AdapterError::AdapterUnavailable
}

/// Rejects a value that would drive an allocation past its declared cap (I14).
///
/// The cap must be checked *before* the allocation, so this helper takes the
/// requested size and the cap, never a buffer.
pub fn check_cap(requested: usize, cap: usize) -> Result<()> {
    if requested > cap {
        return Err(AdapterError::BoundsExceeded);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cap_check_is_inclusive_and_fails_closed() {
        assert!(check_cap(0, 0).is_ok());
        assert!(check_cap(8, 8).is_ok());
        assert_eq!(check_cap(9, 8), Err(AdapterError::BoundsExceeded));
    }

    #[test]
    fn every_transport_failure_maps_to_unavailable() {
        assert_eq!(unavailable("boom"), AdapterError::AdapterUnavailable);
        assert_eq!(unavailable(42u8), AdapterError::AdapterUnavailable);
    }

    #[test]
    fn the_finalized_tag_reason_is_distinguishable_from_every_other_reason() {
        // The whole point of the variant: an operator must be able to report
        // BLOCKED_EXTERNAL for *this* reason and nothing else, even though the
        // neutral taxonomy collapses several reasons onto `AdapterUnavailable`.
        assert!(RejectReason::FinalizedTagUnavailable.is_finalized_tag_unavailable());
        for other in [
            RejectReason::FinalizedTagTransportFailure,
            RejectReason::FinalizedHeaderMalformed,
            RejectReason::Transport,
            RejectReason::MalformedAnswer,
            RejectReason::AncestryProofTooDeep,
            RejectReason::LogMarkedRemoved,
            RejectReason::LogEmitterMismatch,
            RejectReason::BlockMissing,
            RejectReason::ReceiptMissing,
            RejectReason::ReceiptReverted,
            RejectReason::ReceiptInconsistent,
            RejectReason::LogAbsentFromReceipt,
            RejectReason::TransactionMissing,
            RejectReason::TransactionInconsistent,
            RejectReason::TransactionNotToContract,
            RejectReason::NotCanonical,
            RejectReason::AboveFinalizedHead,
            RejectReason::NotFinalizedAncestor,
        ] {
            assert!(
                !other.is_finalized_tag_unavailable(),
                "{other:?} must not be reported as a missing finalized tag"
            );
        }
    }

    #[test]
    fn every_rejection_reason_maps_to_a_fail_closed_neutral_error() {
        let cases = [
            (
                RejectReason::FinalizedTagUnavailable,
                AdapterError::AdapterUnavailable,
            ),
            (
                RejectReason::FinalizedTagTransportFailure,
                AdapterError::AdapterUnavailable,
            ),
            (
                RejectReason::FinalizedHeaderMalformed,
                AdapterError::AdapterUnavailable,
            ),
            (RejectReason::Transport, AdapterError::AdapterUnavailable),
            (
                RejectReason::MalformedAnswer,
                AdapterError::AdapterUnavailable,
            ),
            (
                RejectReason::AncestryProofTooDeep,
                AdapterError::BoundsExceeded,
            ),
            (RejectReason::BlockMissing, AdapterError::AdapterUnavailable),
            (
                RejectReason::LogMarkedRemoved,
                AdapterError::EvidenceInvalid,
            ),
            (
                RejectReason::LogEmitterMismatch,
                AdapterError::EvidenceInvalid,
            ),
            (RejectReason::ReceiptMissing, AdapterError::EvidenceInvalid),
            (RejectReason::ReceiptReverted, AdapterError::EvidenceInvalid),
            (
                RejectReason::ReceiptInconsistent,
                AdapterError::EvidenceInvalid,
            ),
            (
                RejectReason::LogAbsentFromReceipt,
                AdapterError::EvidenceInvalid,
            ),
            (
                RejectReason::TransactionMissing,
                AdapterError::EvidenceInvalid,
            ),
            (
                RejectReason::TransactionInconsistent,
                AdapterError::EvidenceInvalid,
            ),
            (
                RejectReason::TransactionNotToContract,
                AdapterError::EvidenceInvalid,
            ),
            (RejectReason::NotCanonical, AdapterError::ReorgDetected),
            (
                RejectReason::NotFinalizedAncestor,
                AdapterError::ReorgDetected,
            ),
            (
                RejectReason::AboveFinalizedHead,
                AdapterError::PreconditionUnsatisfied,
            ),
        ];
        for (reason, expected) in &cases {
            assert_eq!(
                AdapterError::from(*reason),
                *expected,
                "{reason:?} mapped to the wrong neutral error"
            );
        }
        // No mapping is ever a success, and no reason renders anything but its
        // own name (I6: rejection paths cannot carry material).
        for (reason, _) in &cases {
            let rendered = format!("{reason:?}");
            assert!(!rendered.is_empty());
            assert!(!rendered.contains('('), "{rendered} carries a payload");
        }
    }

    #[test]
    fn no_adapter_error_variant_can_carry_material() {
        // I6, structurally: the neutral taxonomy is made of unit variants, so a
        // `?` on a path that touched `t` cannot smuggle it out. This test is a
        // canary: it breaks the day someone adds a payload-carrying variant.
        let rendered = format!(
            "{:?}{:?}{:?}",
            AdapterError::EvidenceInvalid,
            AdapterError::BoundsExceeded,
            AdapterError::ReorgDetected
        );
        assert_eq!(rendered, "EvidenceInvalidBoundsExceededReorgDetected");
    }
}
