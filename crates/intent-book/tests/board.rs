//! The seven proofs STATUS.md requires before any behavioural claim,
//! each written against INTENT_BOOK_DESIGN.md's own invariants:
//!
//! 1. the public phase opens only at `solver_window_end`, boundary-exact;
//! 2. a non-privileged party cannot quote during the private window, and
//!    can after it;
//! 3. phase-1 quotes survive the phase change and compete under ONE
//!    `select_winner` call with phase-2 quotes;
//! 4. the board refuses to start without merit configuration, per field;
//! 5. the entry ladder — automatic and reconquerable, volume-first;
//! 6. canonical bytes round-trip; truncation, trailing bytes and hostile
//!    length prefixes are rejected;
//! 7. end to end: intent → private window → two solvers → one selection →
//!    frozen terms carrying the winner's `solver_id`, with the adversarial
//!    cases (unregistered, suspended, post-deadline, and a D-019-forbidden
//!    kind refused by the relay).

use intent_book::config::{MeritConfigError, MeritPolicyV1};
use intent_book::merit::{MeritLedger, PrivilegeRefusal};
use intent_book::wire::{IntentError, IntentV1, NegotiationKey};
use intent_book::{BoardRefusal, IntentBoardV1, PhaseV1, SOLVER_WINDOW_SECONDS};
use kaystra_core::types::Digest32;
use relay::{ParticipantId, TimelockSpec};
use rfq::selection::{AdmissibilityRefusal, CandidateFactsV1};
use rfq::{
    AssetId, ChainId, FeeLimitV1, LegDirectionV1, PolicyId, RfqModeV1, RfqV1, RouteLegV1, RouteV1,
    TermsBindingV1, TimelockDomainV1,
};
use solver::{BondFactsV1, ReferenceSolverV1, SolverPolicyV1};

const SESSION: Digest32 = [0x22; 32];
const DOM: ChainId = ChainId([0xD0; 32]);
const BTC: ChainId = ChainId([0xB1; 32]);
const INITIATOR: ParticipantId = ParticipantId([0x31; 32]);
const FAST_SOLVER: ParticipantId = ParticipantId([0x61; 32]);
const SLOW_SOLVER: ParticipantId = ParticipantId([0x62; 32]);
const OUTSIDER: ParticipantId = ParticipantId([0x63; 32]);
const SUSPENDED: ParticipantId = ParticipantId([0x64; 32]);
const INTENT_ID: Digest32 = [0x1D; 32];

/// Publication instant of the fixture intent; the window ends at
/// `PUBLISHED + SOLVER_WINDOW_SECONDS` = 1_120.
const PUBLISHED: u64 = 1_000;
const DEADLINE: u64 = 5_000;

fn route() -> RouteV1 {
    RouteV1 {
        legs: [
            RouteLegV1 {
                chain_id: BTC,
                asset: AssetId([0x01; 32]),
                direction: LegDirectionV1::UserGives,
            },
            RouteLegV1 {
                chain_id: DOM,
                asset: AssetId([0x02; 32]),
                direction: LegDirectionV1::UserReceives,
            },
        ],
    }
}

fn rfq() -> RfqV1 {
    RfqV1::create(
        INITIATOR,
        route(),
        RfqModeV1::ExactIn {
            input_amount: 1_000_000,
            minimum_output: 900_000,
        },
        FeeLimitV1 {
            dom_max: 30_000,
            counterparty_max: 0,
        },
        TimelockDomainV1::TimestampSeconds,
        TimelockSpec::TimestampSeconds { value: DEADLINE },
        PolicyId([0xAA; 32]),
        1,
        SESSION,
    )
    .expect("rfq builds")
}

fn intent() -> IntentV1 {
    IntentV1 {
        version: 1,
        intent_id: INTENT_ID,
        rfq: rfq(),
        published_at_seconds: PUBLISHED,
        quote_deadline_seconds: DEADLINE,
        negotiation_key: NegotiationKey([0x4E; 32]),
    }
}

/// The operator policy of the fixture: threshold 10 s mean, floor
/// 1_000_000 executed volume inside a 30-day window. The NUMBERS are
/// fixture values, not defaults — the crate has no default (OQ-S4).
fn policy() -> MeritPolicyV1 {
    MeritPolicyV1::new(Some(10_000), Some(1_000_000), Some(2_592_000))
        .expect("explicit operator values build")
}

/// A ledger where `solver` already carries qualifying executed volume.
fn ledger_with_privileged(solvers: &[ParticipantId]) -> MeritLedger {
    let mut ledger = MeritLedger::new(policy());
    for solver in solvers {
        ledger.record_execution(*solver, 2_000_000, PUBLISHED.saturating_sub(100));
    }
    ledger
}

fn reference_solver(id: ParticipantId, secret: [u8; 32], spread_bps: u128) -> ReferenceSolverV1 {
    ReferenceSolverV1::new(
        id,
        SolverPolicyV1 {
            rate_num: 1,
            rate_den: 1,
            spread_bps,
            execution_delta: 1_000,
            expiry_delta: 500,
        },
        secret,
        [0x99; 32],
    )
}

fn bond(tag: u8) -> BondFactsV1 {
    BondFactsV1 {
        reservation_id: [tag; 32],
        policy_version: 7,
    }
}

fn good_facts() -> CandidateFactsV1 {
    CandidateFactsV1 {
        solver_registered: true,
        signature_valid: true,
        bond_reserved_exclusive: true,
        exposure_covered: true,
        coverage_excess: 0,
        solver_active: true,
        policy_version_accepted: true,
    }
}

fn now_spec() -> TimelockSpec {
    TimelockSpec::TimestampSeconds { value: 1_000 }
}

/// 1. The boundary is exact: one second before `solver_window_end` the
///    window is private; AT `solver_window_end` the board is public — a
///    120-second window lasts 120 seconds and not one more.
#[test]
fn the_public_phase_opens_exactly_at_solver_window_end() {
    let mut board = IntentBoardV1::new(ledger_with_privileged(&[]));
    board.publish(intent()).expect("publishes");
    let end = PUBLISHED + SOLVER_WINDOW_SECONDS;
    assert_eq!(intent().solver_window_end_seconds(), end);

    assert_eq!(
        board.phase_at(&INTENT_ID, end - 1).unwrap(),
        PhaseV1::PrivateSolverWindow
    );
    assert_eq!(
        board.phase_at(&INTENT_ID, end).unwrap(),
        PhaseV1::PublicBoard
    );

    // The same-content invariant: during the window an outsider sees
    // NOTHING; from the boundary on it sees the IDENTICAL object.
    assert_eq!(
        board.view(&INTENT_ID, Some(&OUTSIDER), end - 1).unwrap(),
        None
    );
    assert_eq!(
        board.view(&INTENT_ID, Some(&OUTSIDER), end).unwrap(),
        Some(&intent())
    );
    assert!(board.public_board(end - 1).is_empty());
    assert_eq!(board.public_board(end).len(), 1);
}

/// 2. A non-privileged party cannot quote during the private window, and
///    can after it.
#[test]
fn a_non_privileged_solver_is_refused_in_the_window_and_admitted_after() {
    let mut board = IntentBoardV1::new(ledger_with_privileged(&[]));
    board.publish(intent()).expect("publishes");
    let quote = reference_solver(OUTSIDER, [0x53; 32], 100)
        .answer(&intent().rfq, DOM, bond(0xB2), [0x02; 32])
        .expect("prices");

    assert_eq!(
        board.submit_quote(&INTENT_ID, quote, good_facts(), PUBLISHED + 10),
        Err(BoardRefusal::NotPrivilegedInWindow)
    );
    assert_eq!(
        board.submit_quote(
            &INTENT_ID,
            quote,
            good_facts(),
            PUBLISHED + SOLVER_WINDOW_SECONDS
        ),
        Ok(PhaseV1::PublicBoard)
    );
}

/// 3. A phase-1 quote survives the phase change and competes with a
///    phase-2 quote under ONE `select_winner` call — and wins here, because
///    its net output is better.
#[test]
fn phase_one_quotes_survive_and_compete_in_one_selection() {
    let mut board = IntentBoardV1::new(ledger_with_privileged(&[FAST_SOLVER]));
    board.publish(intent()).expect("publishes");

    // Phase 1: the privileged solver, 0.50% spread → net 995_000.
    let early = reference_solver(FAST_SOLVER, [0x51; 32], 50)
        .answer(&intent().rfq, DOM, bond(0xB1), [0x02; 32])
        .expect("prices");
    assert_eq!(
        board.submit_quote(&INTENT_ID, early, good_facts(), PUBLISHED + 5),
        Ok(PhaseV1::PrivateSolverWindow)
    );

    // Phase 2: an outsider, 2.00% spread → net 980_000.
    let late = reference_solver(SLOW_SOLVER, [0x53; 32], 200)
        .answer(&intent().rfq, DOM, bond(0xB2), [0x03; 32])
        .expect("prices");
    assert_eq!(
        board.submit_quote(&INTENT_ID, late, good_facts(), PUBLISHED + 200),
        Ok(PhaseV1::PublicBoard)
    );

    // Both are held, in arrival order, with their phases recorded.
    let held = board.quotes(&INTENT_ID).unwrap();
    assert_eq!(held.len(), 2);
    assert_eq!(held[0].arrived_in, PhaseV1::PrivateSolverWindow);
    assert_eq!(held[1].arrived_in, PhaseV1::PublicBoard);

    // ONE selection over every candidate of any phase.
    let outcome = board.select(&INTENT_ID, DOM, now_spec()).expect("a winner");
    assert_eq!(outcome.selection.winning_quote, early.quote_id);
    assert_eq!(outcome.verdicts.len(), 2);
}

/// 4. The board refuses to start without merit configuration, per field —
///    and a vacuous zero threshold or window is a refusal, not a wildcard.
#[test]
fn merit_configuration_is_fail_closed_per_field() {
    assert_eq!(
        MeritPolicyV1::new(None, Some(1), Some(1)).unwrap_err(),
        MeritConfigError::MissingResponseThreshold
    );
    assert_eq!(
        MeritPolicyV1::new(Some(1), None, Some(1)).unwrap_err(),
        MeritConfigError::MissingVolumeFloor
    );
    assert_eq!(
        MeritPolicyV1::new(Some(1), Some(1), None).unwrap_err(),
        MeritConfigError::MissingVolumeWindow
    );
    assert_eq!(
        MeritPolicyV1::new(Some(0), Some(1), Some(1)).unwrap_err(),
        MeritConfigError::VacuousThreshold
    );
    assert_eq!(
        MeritPolicyV1::new(Some(1), Some(1), Some(0)).unwrap_err(),
        MeritConfigError::VacuousThreshold
    );
    // A zero volume FLOOR is an operator choice, not an omission.
    assert!(MeritPolicyV1::new(Some(1), Some(0), Some(1)).is_ok());
}

/// 5. The entry ladder: volume admits a newcomer with no phase-1 history;
///    a failing mean revokes; recovery reconquers — automatic in both
///    directions, and volume is judged first.
#[test]
fn the_entry_ladder_is_automatic_and_reconquerable() {
    let mut ledger = MeritLedger::new(policy());

    // No history at all: refused on volume, the entry gate.
    let verdict = ledger.verdict(&FAST_SOLVER, PUBLISHED);
    assert!(!verdict.privileged);
    assert_eq!(verdict.refusal, Some(PrivilegeRefusal::VolumeBelowFloor));

    // Qualifying volume, NO phase-1 history: privileged (the ladder).
    ledger.record_execution(FAST_SOLVER, 2_000_000, PUBLISHED - 50);
    let verdict = ledger.verdict(&FAST_SOLVER, PUBLISHED);
    assert!(verdict.privileged);
    assert_eq!(verdict.mean_response_millis, None);

    // A mean above the threshold revokes, automatically.
    ledger.record_response(FAST_SOLVER, 50_000);
    let verdict = ledger.verdict(&FAST_SOLVER, PUBLISHED);
    assert!(!verdict.privileged);
    assert_eq!(
        verdict.refusal,
        Some(PrivilegeRefusal::ResponseAboveThreshold)
    );

    // Fast responses pull the mean back under: reconquered.
    for _ in 0..9 {
        ledger.record_response(FAST_SOLVER, 1_000);
    }
    assert!(ledger.verdict(&FAST_SOLVER, PUBLISHED).privileged);

    // Volume aging out of the window revokes again — volume-first, so the
    // refusal names the floor even though the mean is now healthy.
    let far_future = PUBLISHED + policy().volume_window_seconds() + 100;
    let verdict = ledger.verdict(&FAST_SOLVER, far_future);
    assert!(!verdict.privileged);
    assert_eq!(verdict.refusal, Some(PrivilegeRefusal::VolumeBelowFloor));
}

/// 6. Canonical bytes round-trip; the decoder rejects truncation at every
///    length, trailing bytes, hostile length prefixes, an unknown version and
///    a dead-on-arrival deadline. The negotiation key never prints.
#[test]
fn canonical_bytes_round_trip_and_the_decoder_fails_closed() {
    let intent = intent();
    let bytes = intent.canonical_bytes().expect("encodes");
    assert_eq!(IntentV1::decode(&bytes).expect("round-trips"), intent);

    // Truncation at EVERY prefix length fails; no prefix panics.
    for len in 0..bytes.len() {
        assert!(IntentV1::decode(&bytes[..len]).is_err(), "prefix {len}");
    }

    // A trailing byte fails.
    let mut trailing = bytes.clone();
    trailing.push(0x00);
    assert_eq!(IntentV1::decode(&trailing), Err(IntentError::TrailingBytes));

    // A hostile RFQ length prefix fails on the bound, not on allocation.
    let mut hostile = bytes.clone();
    let len_offset = 2 + 32 + 8 + 8 + 32;
    hostile[len_offset..len_offset + 4].copy_from_slice(&u32::MAX.to_le_bytes());
    assert_eq!(IntentV1::decode(&hostile), Err(IntentError::BadLength));

    // An unknown version fails closed.
    let mut wrong_version = intent.clone();
    wrong_version.version = 2;
    let bytes = wrong_version.canonical_bytes().expect("encodes");
    assert_eq!(IntentV1::decode(&bytes), Err(IntentError::UnknownVersion));

    // A deadline at publication is dead on arrival.
    let mut dead = intent.clone();
    dead.quote_deadline_seconds = dead.published_at_seconds;
    assert_eq!(
        dead.validate(),
        Err(IntentError::DeadlineNotAfterPublication)
    );

    // The negotiation key is redacted wherever Debug reaches.
    let printed = format!("{:?}", intent.negotiation_key);
    assert!(printed.contains("REDACTED"));
    assert!(!printed.contains("78"), "no key byte leaks: {printed}");
}

#[test]
fn publish_refuses_invalid_intents_without_inserting_them() {
    let mut board = IntentBoardV1::new(ledger_with_privileged(&[]));

    let mut wrong_version = intent();
    wrong_version.version = 2;
    assert_eq!(
        board.publish(wrong_version),
        Err(BoardRefusal::MalformedIntent(IntentError::UnknownVersion))
    );
    assert_eq!(
        board.phase_at(&INTENT_ID, PUBLISHED),
        Err(BoardRefusal::UnknownIntent)
    );

    let mut divergent_deadline = intent();
    divergent_deadline.quote_deadline_seconds += 1;
    assert_eq!(
        board.publish(divergent_deadline),
        Err(BoardRefusal::MalformedIntent(
            IntentError::RfqDeadlineMismatch
        ))
    );
    assert_eq!(
        board.phase_at(&INTENT_ID, PUBLISHED),
        Err(BoardRefusal::UnknownIntent)
    );

    let mut tampered_rfq = intent();
    tampered_rfq.rfq.rfq_id[0] ^= 1;
    assert_eq!(
        board.publish(tampered_rfq),
        Err(BoardRefusal::MalformedIntent(IntentError::MalformedRfq))
    );
    assert_eq!(
        board.phase_at(&INTENT_ID, PUBLISHED),
        Err(BoardRefusal::UnknownIntent)
    );
}

/// 7. End to end: intent → private window → quotes from two solver
///    instances → one ratified selection → frozen terms carrying the
///    winner's `solver_id` — with the adversarial candidates adjudicated by
///    name and the post-deadline quote refused at the board.
#[test]
fn end_to_end_intent_to_frozen_terms_with_adversaries() {
    let mut board = IntentBoardV1::new(ledger_with_privileged(&[FAST_SOLVER, SLOW_SOLVER]));
    board.publish(intent()).expect("publishes");
    board
        .publish(intent())
        .expect_err("a duplicate intent is refused");

    // Phase 1 — both privileged solvers answer inside the window.
    let winner_quote = reference_solver(FAST_SOLVER, [0x51; 32], 50)
        .answer(&intent().rfq, DOM, bond(0xB1), [0x02; 32])
        .expect("prices");
    let loser_quote = reference_solver(SLOW_SOLVER, [0x52; 32], 200)
        .answer(&intent().rfq, DOM, bond(0xB2), [0x03; 32])
        .expect("prices");
    board
        .submit_quote(&INTENT_ID, winner_quote, good_facts(), PUBLISHED + 3)
        .expect("phase-1 quote lands");
    board
        .submit_quote(&INTENT_ID, loser_quote, good_facts(), PUBLISHED + 7)
        .expect("phase-1 quote lands");

    // Phase 2 — the adversarial candidates arrive on the public board.
    let unregistered_quote = reference_solver(OUTSIDER, [0x53; 32], 100)
        .answer(&intent().rfq, DOM, bond(0xB3), [0x04; 32])
        .expect("prices");
    let suspended_quote = reference_solver(SUSPENDED, [0x54; 32], 100)
        .answer(&intent().rfq, DOM, bond(0xB4), [0x05; 32])
        .expect("prices");
    let public_at = PUBLISHED + SOLVER_WINDOW_SECONDS + 1;
    board
        .submit_quote(
            &INTENT_ID,
            unregistered_quote,
            CandidateFactsV1 {
                solver_registered: false,
                ..good_facts()
            },
            public_at,
        )
        .expect("the board holds it; admissibility adjudicates it");
    board
        .submit_quote(
            &INTENT_ID,
            suspended_quote,
            CandidateFactsV1 {
                solver_active: false,
                ..good_facts()
            },
            public_at,
        )
        .expect("the board holds it; admissibility adjudicates it");

    // A quote after the intent's own deadline is refused AT THE BOARD —
    // the deadline, never the phase change, is what expires quotes.
    let late_quote = reference_solver(OUTSIDER, [0x53; 32], 100)
        .answer(&intent().rfq, DOM, bond(0xB5), [0x06; 32])
        .expect("prices");
    assert_eq!(
        board.submit_quote(&INTENT_ID, late_quote, good_facts(), DEADLINE + 1),
        Err(BoardRefusal::QuoteAfterDeadline)
    );

    // ONE selection over all four held candidates.
    let outcome = board.select(&INTENT_ID, DOM, now_spec()).expect("a winner");
    assert_eq!(outcome.selection.winning_quote, winner_quote.quote_id);
    assert_eq!(outcome.verdicts.len(), 4);
    let verdict_of = |id: &Digest32| {
        outcome
            .verdicts
            .iter()
            .find(|(quote_id, _)| quote_id == id)
            .map(|(_, verdict)| *verdict)
            .expect("adjudicated")
    };
    assert_eq!(verdict_of(&winner_quote.quote_id), None);
    assert_eq!(verdict_of(&loser_quote.quote_id), None);
    assert_eq!(
        verdict_of(&unregistered_quote.quote_id),
        Some(AdmissibilityRefusal::SolverNotRegistered)
    );
    assert_eq!(
        verdict_of(&suspended_quote.quote_id),
        Some(AdmissibilityRefusal::SolverSuspended)
    );

    // The frozen terms carry the WINNER's solver id.
    let terms = TermsBindingV1::from_parts(
        board.rfq_for_bridge(&INTENT_ID).unwrap(),
        &winner_quote,
        [
            TimelockSpec::TimestampSeconds { value: 8_000 },
            TimelockSpec::TimestampSeconds { value: 9_000 },
        ],
        [[0xC1; 32], [0xC2; 32]],
    )
    .expect("terms bind");
    assert_eq!(terms.solver_id, FAST_SOLVER);

    // Closing the intent refuses further quotes.
    board.close(&INTENT_ID).expect("closes");
    let after_close = reference_solver(OUTSIDER, [0x53; 32], 100)
        .answer(&intent().rfq, DOM, bond(0xB6), [0x07; 32])
        .expect("prices");
    assert_eq!(
        board.submit_quote(&INTENT_ID, after_close, good_facts(), public_at),
        Err(BoardRefusal::IntentClosed)
    );
}

/// 7 (adversarial, transport): the D-019 registry is closed — a
/// hypothetical INTENT kind (0x0006) is unknown to the relay and the
/// canonical policy refuses it for EVERY role. The board never touches
/// the registry (OQ-S3).
#[test]
fn a_board_message_kind_is_refused_by_the_relay_registry() {
    use relay::auth::{message_type, CanonicalMessageTypePolicyV1};
    use relay::SenderRoleV1;

    const INTENT_KIND: u16 = 0x0006;
    assert!(!message_type::is_known(INTENT_KIND));
    let policy = CanonicalMessageTypePolicyV1;
    for role in [
        SenderRoleV1::Initiator,
        SenderRoleV1::Solver,
        SenderRoleV1::Observer,
    ] {
        assert!(
            !policy.permits(role, INTENT_KIND),
            "the closed registry must refuse kind 0x0006 for {role:?}"
        );
    }
    // And the five ratified kinds are exactly the known set.
    for kind in [
        message_type::RFQ,
        message_type::QUOTE,
        message_type::ACCEPTANCE,
        message_type::SELECTION,
        message_type::ROUTE_TRANSPORT,
    ] {
        assert!(message_type::is_known(kind));
    }
}
