//! Conformance tests for the NAR-DC-P1-007 policy foundation.
//!
//! These tests restate the ratified rules independently of the implementation:
//! the expected edge list is written out in full rather than derived from
//! `NORMATIVE_EDGES`, so a wrong edge in the crate cannot make its own test
//! pass.

use dom_scriptless_protocol::{
    is_normative_edge, ParticipantSetError, ParticipantSetV1, NORMATIVE_EDGES,
    NORMATIVE_EDGE_COUNT, PARTICIPANT_COUNT,
};
use dom_scriptless_store::SessionPhaseV1;

/// Compile-time link between [`ALL_PHASES`] and the §9.1 registry.
///
/// The exhaustive match has no wildcard arm, so adding a phase to the registry
/// fails to compile here. Without it, `ALL_PHASES` could silently fall behind
/// and `every_pair_outside_the_table_is_rejected` would keep claiming to cover
/// the complete pair space while covering less of it.
fn assert_registry_is_fully_enumerated(phase: SessionPhaseV1) -> bool {
    let known = match phase {
        SessionPhaseV1::Created
        | SessionPhaseV1::TermsCommitted
        | SessionPhaseV1::SharesCommitted
        | SessionPhaseV1::SharesRevealed
        | SessionPhaseV1::BpCommonCommitted
        | SessionPhaseV1::BpCommonEstablished
        | SessionPhaseV1::BpNonceCommitted
        | SessionPhaseV1::BpRound1Complete
        | SessionPhaseV1::BpRound2Complete
        | SessionPhaseV1::OutputFinalized
        | SessionPhaseV1::TemplatesCommitted
        | SessionPhaseV1::RefundSigning
        | SessionPhaseV1::RefundSigned
        | SessionPhaseV1::ClaimSigning
        | SessionPhaseV1::ClaimPrepared
        | SessionPhaseV1::FundingAuthorized
        | SessionPhaseV1::FundingBroadcast
        | SessionPhaseV1::FundingConfirmed
        | SessionPhaseV1::ClaimBroadcast
        | SessionPhaseV1::RefundEligible
        | SessionPhaseV1::RefundBroadcast
        | SessionPhaseV1::Settled
        | SessionPhaseV1::Refunded
        | SessionPhaseV1::Aborted
        | SessionPhaseV1::FailedClosed => true,
    };
    known && ALL_PHASES.contains(&phase)
}

/// Every phase in the §9.1 registry, used to enumerate the complete pair space.
const ALL_PHASES: [SessionPhaseV1; 25] = [
    SessionPhaseV1::Created,
    SessionPhaseV1::TermsCommitted,
    SessionPhaseV1::SharesCommitted,
    SessionPhaseV1::SharesRevealed,
    SessionPhaseV1::BpCommonCommitted,
    SessionPhaseV1::BpCommonEstablished,
    SessionPhaseV1::BpNonceCommitted,
    SessionPhaseV1::BpRound1Complete,
    SessionPhaseV1::BpRound2Complete,
    SessionPhaseV1::OutputFinalized,
    SessionPhaseV1::TemplatesCommitted,
    SessionPhaseV1::RefundSigning,
    SessionPhaseV1::RefundSigned,
    SessionPhaseV1::ClaimSigning,
    SessionPhaseV1::ClaimPrepared,
    SessionPhaseV1::FundingAuthorized,
    SessionPhaseV1::FundingBroadcast,
    SessionPhaseV1::FundingConfirmed,
    SessionPhaseV1::ClaimBroadcast,
    SessionPhaseV1::RefundEligible,
    SessionPhaseV1::RefundBroadcast,
    SessionPhaseV1::Settled,
    SessionPhaseV1::Refunded,
    SessionPhaseV1::Aborted,
    SessionPhaseV1::FailedClosed,
];

/// The NAR-DC-P1-007 §3.2 enumeration, transcribed independently.
fn adjudicated_edges() -> Vec<(SessionPhaseV1, SessionPhaseV1)> {
    vec![
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
    ]
}

#[test]
fn the_table_matches_the_adjudicated_enumeration_in_order() {
    let expected = adjudicated_edges();
    assert_eq!(
        expected.len(),
        NORMATIVE_EDGE_COUNT,
        "the transcribed enumeration must itself hold the adjudicated count"
    );
    assert_eq!(NORMATIVE_EDGES.len(), NORMATIVE_EDGE_COUNT);
    // Ordered equality: a reordering is a divergence from the published table,
    // not an equivalent set.
    assert_eq!(NORMATIVE_EDGES.to_vec(), expected);
}

#[test]
fn every_edge_is_unique() {
    let mut seen = Vec::new();
    for edge in NORMATIVE_EDGES {
        assert!(!seen.contains(&edge), "edge declared twice: {edge:?}");
        seen.push(edge);
    }
    assert_eq!(seen.len(), NORMATIVE_EDGE_COUNT);
}

#[test]
fn every_edge_strictly_increases_the_phase_discriminant() {
    for (origin, destination) in NORMATIVE_EDGES {
        assert!(
            (origin as u16) < (destination as u16),
            "{origin:?} -> {destination:?} does not advance the §9.1 discriminant"
        );
    }
}

#[test]
fn the_phases_section_9_2_could_not_enter_are_reachable() {
    for phase in [
        SessionPhaseV1::RefundSigning,
        SessionPhaseV1::ClaimSigning,
        SessionPhaseV1::RefundBroadcast,
        SessionPhaseV1::Refunded,
    ] {
        assert!(
            NORMATIVE_EDGES
                .iter()
                .any(|&(_, destination)| destination == phase),
            "{phase:?} has no entry edge"
        );
    }
}

#[test]
fn both_removed_shortcuts_are_absent() {
    assert!(!is_normative_edge(
        SessionPhaseV1::TemplatesCommitted,
        SessionPhaseV1::RefundSigned
    ));
    assert!(!is_normative_edge(
        SessionPhaseV1::RefundSigned,
        SessionPhaseV1::ClaimPrepared
    ));
}

#[test]
fn the_terminal_failure_phases_are_not_in_the_table() {
    // §3.4: Aborted and FailedClosed are entered through the §9.3 abort
    // disposition, which this crate does not implement.
    for phase in [SessionPhaseV1::Aborted, SessionPhaseV1::FailedClosed] {
        assert!(
            !NORMATIVE_EDGES
                .iter()
                .any(|&(origin, destination)| origin == phase || destination == phase),
            "{phase:?} appears in the closed table"
        );
    }
}

#[test]
fn the_enumerated_phase_registry_is_complete() {
    for phase in ALL_PHASES {
        assert!(
            assert_registry_is_fully_enumerated(phase),
            "{phase:?} is not enumerated in ALL_PHASES"
        );
    }
}

#[test]
fn every_pair_outside_the_table_is_rejected() {
    let expected = adjudicated_edges();
    let mut accepted = 0_usize;
    for from in ALL_PHASES {
        for to in ALL_PHASES {
            let published = expected.contains(&(from, to));
            assert_eq!(
                is_normative_edge(from, to),
                published,
                "{from:?} -> {to:?} disagrees with the adjudicated table"
            );
            if published {
                accepted += 1;
            }
        }
    }
    // The complete 25x25 pair space is covered, and exactly the adjudicated
    // edges are accepted within it.
    assert_eq!(accepted, NORMATIVE_EDGE_COUNT);
}

#[test]
fn a_two_party_roster_is_accepted_in_canonical_order() -> Result<(), ParticipantSetError> {
    let low = [0x11_u8; 32];
    let high = [0x22_u8; 32];

    let ascending = ParticipantSetV1::new(&[low, high])?;
    let descending = ParticipantSetV1::new(&[high, low])?;

    assert_eq!(ascending, descending, "input order must not be observable");
    assert_eq!(ascending.lower(), low);
    assert_eq!(ascending.higher(), high);
    assert_eq!(ascending.identities(), [low, high]);
    assert!(ascending.contains(&low));
    assert!(ascending.contains(&high));
    assert!(!ascending.contains(&[0x33_u8; 32]));
    assert_eq!(PARTICIPANT_COUNT, 2);
    Ok(())
}

#[test]
fn canonical_order_holds_when_the_pair_differs_in_the_last_byte_only(
) -> Result<(), ParticipantSetError> {
    let mut low = [0x00_u8; 32];
    let mut high = [0x00_u8; 32];
    low[31] = 1;
    high[31] = 2;
    let set = ParticipantSetV1::new(&[high, low])?;
    assert_eq!(set.identities(), [low, high]);
    Ok(())
}

#[test]
fn each_refusal_is_a_distinct_outcome() {
    let identity = [0x44_u8; 32];

    assert_eq!(
        ParticipantSetV1::new(&[]),
        Err(ParticipantSetError::TooFew { found: 0 })
    );
    assert_eq!(
        ParticipantSetV1::new(&[identity]),
        Err(ParticipantSetError::TooFew { found: 1 })
    );
    assert_eq!(
        ParticipantSetV1::new(&[[0x01_u8; 32], [0x02_u8; 32], [0x03_u8; 32]]),
        Err(ParticipantSetError::TooMany { found: 3 })
    );
    assert_eq!(
        ParticipantSetV1::new(&[[0x01_u8; 32], [0x02_u8; 32], [0x03_u8; 32], [0x04_u8; 32]]),
        Err(ParticipantSetError::TooMany { found: 4 })
    );
    // Two equal identities name one participant twice; that is neither a
    // cardinality shortage nor a scope violation.
    assert_eq!(
        ParticipantSetV1::new(&[identity, identity]),
        Err(ParticipantSetError::Duplicate)
    );

    // The three refusals must remain distinguishable from one another.
    let too_few = ParticipantSetError::TooFew { found: 1 };
    let too_many = ParticipantSetError::TooMany { found: 3 };
    let duplicate = ParticipantSetError::Duplicate;
    assert_ne!(too_few, too_many);
    assert_ne!(too_few, duplicate);
    assert_ne!(too_many, duplicate);
    assert_ne!(too_few.to_string(), too_many.to_string());
    assert_ne!(too_few.to_string(), duplicate.to_string());
    assert_ne!(too_many.to_string(), duplicate.to_string());
}

#[test]
fn cardinality_is_decided_before_distinctness() {
    let identity = [0x55_u8; 32];
    // An oversized roster that also repeats an identity is TooMany, not
    // Duplicate: cardinality is checked first. Both refuse and neither builds a
    // set, so the precedence changes which refusal is reported, never whether
    // the roster is refused.
    assert_eq!(
        ParticipantSetV1::new(&[identity, identity, identity]),
        Err(ParticipantSetError::TooMany { found: 3 })
    );
    assert_eq!(
        ParticipantSetV1::new(&[identity, identity, [0x66_u8; 32]]),
        Err(ParticipantSetError::TooMany { found: 3 })
    );
    // A single repeated identity is still a shortage, not a duplicate.
    assert_eq!(
        ParticipantSetV1::new(&[identity]),
        Err(ParticipantSetError::TooFew { found: 1 })
    );
}

#[test]
fn n_of_n_rosters_are_refused_for_every_size_up_to_a_bound() {
    for size in 3..=8_usize {
        let roster: Vec<[u8; 32]> = (0..size)
            .map(|index| {
                let mut identity = [0x00_u8; 32];
                identity[0] = u8::try_from(index).unwrap_or(u8::MAX);
                identity
            })
            .collect();
        assert_eq!(
            ParticipantSetV1::new(&roster),
            Err(ParticipantSetError::TooMany { found: size }),
            "a roster of {size} participants must be refused"
        );
    }
}
