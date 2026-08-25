//! The closed phase topology (Master §9, NAR-DC-P1-007 §3).
//!
//! §9.1 declares the phase registry with frozen `#[repr(u16)]` discriminants,
//! including `RefundSigning` (90), `ClaimSigning` (110) and `RefundBroadcast`
//! (180). The §9.2 table as published enters none of them: it publishes two
//! shortcuts instead, and lists `RefundBroadcast -> Refunded` without any row
//! entering `RefundBroadcast`. Read literally as a closed table, all three
//! phases are unreachable and the refund terminal `Refunded` cannot be reached
//! at all.
//!
//! NAR-DC-P1-007 §3.2 adjudicated that divergence and fixed the canonical table
//! at exactly 22 unique directed edges: the two shortcuts are removed, the four
//! signing edges and `RefundEligible -> RefundBroadcast` are added, and every
//! other §9.2 row is retained as published.
//!
//! This module is that table as data, and nothing else. §3.4 requires a
//! conforming implementation to expose the closed edge set *"as data that can
//! be enumerated and compared, so that conformance is machine-checkable rather
//! than asserted"*, which is what [`NORMATIVE_EDGES`] is for.
//!
//! `SessionPhaseV1` is deliberately not redefined here. The phase registry and
//! its frozen discriminants are owned by `dom-scriptless-store`, the crate that
//! owns the canonical Contracts codecs; a second declaration would be a second
//! source of truth for bytes that are already signed.
//!
//! # What this module is not
//!
//! It is not a state machine. There is no event type, no executor, no advance
//! or transition function that mutates anything, no attestation, no evidence
//! flag, no durable write, no I/O and no authority token. Asking whether an
//! edge is published is a question about the adjudicated table, not permission
//! to take it: the preconditions §9.2 attaches to each row, and the §7.3
//! funding gate, are not implemented here and are not implied by an edge being
//! present.
//!
//! Per §3.4, `Aborted` (250) and `FailedClosed` (255) are absent from the
//! table. They are entered through the §9.3 abort disposition and the
//! fail-closed rules, which this module does not implement.

use dom_scriptless_store::SessionPhaseV1;

/// The number of edges the adjudicated table is closed at (NAR-DC-P1-007 §3.2).
pub const NORMATIVE_EDGE_COUNT: usize = 22;

/// The §9.2 table as adjudicated by NAR-DC-P1-007 §3.2, in its published order.
///
/// Exactly [`NORMATIVE_EDGE_COUNT`] unique directed `(origin, destination)`
/// pairs. §3.4 closes the set: no edge may be added, removed, widened, narrowed
/// or inferred without a new signed record, so this constant is the whole
/// table and not a starting point.
///
/// Every edge strictly increases the §9.1 discriminant of its origin, which
/// preserves the monotonic-advance rule. The reversible chain projection of
/// §10.1 and §11.1 is the only category a reorg may rewrite and is not a phase
/// transition, so no edge here moves backwards.
pub const NORMATIVE_EDGES: [(SessionPhaseV1, SessionPhaseV1); NORMATIVE_EDGE_COUNT] = [
    (SessionPhaseV1::Created, SessionPhaseV1::TermsCommitted),
    (
        SessionPhaseV1::TermsCommitted,
        SessionPhaseV1::SharesCommitted,
    ),
    (
        SessionPhaseV1::SharesCommitted,
        SessionPhaseV1::SharesRevealed,
    ),
    (
        SessionPhaseV1::SharesRevealed,
        SessionPhaseV1::BpCommonCommitted,
    ),
    (
        SessionPhaseV1::BpCommonCommitted,
        SessionPhaseV1::BpCommonEstablished,
    ),
    (
        SessionPhaseV1::BpCommonEstablished,
        SessionPhaseV1::BpNonceCommitted,
    ),
    (
        SessionPhaseV1::BpNonceCommitted,
        SessionPhaseV1::BpRound1Complete,
    ),
    (
        SessionPhaseV1::BpRound1Complete,
        SessionPhaseV1::BpRound2Complete,
    ),
    (
        SessionPhaseV1::BpRound2Complete,
        SessionPhaseV1::OutputFinalized,
    ),
    (
        SessionPhaseV1::OutputFinalized,
        SessionPhaseV1::TemplatesCommitted,
    ),
    (
        SessionPhaseV1::TemplatesCommitted,
        SessionPhaseV1::RefundSigning,
    ),
    (SessionPhaseV1::RefundSigning, SessionPhaseV1::RefundSigned),
    (SessionPhaseV1::RefundSigned, SessionPhaseV1::ClaimSigning),
    (SessionPhaseV1::ClaimSigning, SessionPhaseV1::ClaimPrepared),
    (
        SessionPhaseV1::ClaimPrepared,
        SessionPhaseV1::FundingAuthorized,
    ),
    (
        SessionPhaseV1::FundingAuthorized,
        SessionPhaseV1::FundingBroadcast,
    ),
    (
        SessionPhaseV1::FundingBroadcast,
        SessionPhaseV1::FundingConfirmed,
    ),
    (
        SessionPhaseV1::FundingConfirmed,
        SessionPhaseV1::ClaimBroadcast,
    ),
    (
        SessionPhaseV1::FundingConfirmed,
        SessionPhaseV1::RefundEligible,
    ),
    (SessionPhaseV1::ClaimBroadcast, SessionPhaseV1::Settled),
    (
        SessionPhaseV1::RefundEligible,
        SessionPhaseV1::RefundBroadcast,
    ),
    (SessionPhaseV1::RefundBroadcast, SessionPhaseV1::Refunded),
];

/// Whether `(from, to)` is one of the adjudicated edges.
///
/// This is a read-only question about [`NORMATIVE_EDGES`]. A `true` answer
/// states that the pair appears in the adjudicated table; it authorises
/// nothing, checks no precondition, and moves no session.
#[must_use]
pub fn is_normative_edge(from: SessionPhaseV1, to: SessionPhaseV1) -> bool {
    NORMATIVE_EDGES
        .iter()
        .any(|&(origin, destination)| origin == from && destination == to)
}
