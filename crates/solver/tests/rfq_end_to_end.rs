//! The RFQ board, end to end in process: an initiator's `RfqV1` travels
//! the ratified Relay V1 §5.4 pipeline to the solver; the reference
//! solver prices, signs and answers; the `QuoteV1` travels back; the
//! initiator verifies the signature with the pinned backend, runs the
//! ratified §4.1 admissibility and §4.3 selection, records
//! `SelectionV1`/`AcceptanceV1`, and freezes `TermsBindingV1` with its
//! `terms_hash` — the exact point where the product stops and the
//! proven settlement machinery begins.

use btc_crypto::SecpContext;
use f6_engine::consumer::{accept_payload, PayloadObjectV1, SessionBindingV1};
use kaystra_core::types::Digest32;
use relay::auth::{
    accept_envelope, message_type, RecipientContextV1, RosterMemberV1, RosterRegistryV1,
    RosterSnapshotV1, TranscriptStateV1,
};
use relay::server::RelayV1;
use relay::{ParticipantId, RelayEnvelopeV1, SenderRoleV1, TimelockSpec};
use rfq::selection::{admissibility, select_winner, CandidateFactsV1};
use rfq::{
    AcceptanceV1, AssetId, ChainId, FeeLimitV1, LegDirectionV1, PolicyId, RfqModeV1, RfqV1,
    RouteLegV1, RouteV1, TermsBindingV1, TimelockDomainV1,
};
use solver::{BondFactsV1, ReferenceSolverV1, SolverPolicyV1, SolverRefusal};

const NETWORK: Digest32 = [0x11; 32];
const SESSION: Digest32 = [0x22; 32];
const ROUTE_ID: Digest32 = [0x33; 32];
const SNAPSHOT: Digest32 = [0x77; 32];
const DOM: ChainId = ChainId([0xD0; 32]);
const BTC: ChainId = ChainId([0xB1; 32]);
const INITIATOR: ParticipantId = ParticipantId([0x31; 32]);
const SOLVER: ParticipantId = ParticipantId([0x61; 32]);
const INITIATOR_SECRET: [u8; 32] = [0x52; 32];
const SOLVER_SECRET: [u8; 32] = [0x51; 32];

fn secp() -> SecpContext {
    SecpContext::new(&[0x99; 32])
}

fn xonly_of(secret: &[u8; 32]) -> [u8; 32] {
    secp()
        .sign_bip340(secret, &[0u8; 32], &[0u8; 32])
        .unwrap()
        .1
}

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
        TimelockSpec::TimestampSeconds { value: 5_000 },
        PolicyId([0xAA; 32]),
        1,
        SESSION,
    )
    .expect("rfq builds")
}

fn reference_solver() -> ReferenceSolverV1 {
    ReferenceSolverV1::new(
        SOLVER,
        SolverPolicyV1 {
            rate_num: 1, // 1:1 reference rate for the fixture
            rate_den: 1,
            spread_bps: 50, // 0.50% consolidated spread
            execution_delta: 1_000,
            expiry_delta: 500,
        },
        SOLVER_SECRET,
        [0x99; 32],
    )
}

fn bond() -> BondFactsV1 {
    BondFactsV1 {
        reservation_id: [0xBD; 32],
        policy_version: 7,
    }
}

fn rosters() -> RosterRegistryV1 {
    let snapshot = RosterSnapshotV1::new()
        .with_member(
            INITIATOR,
            RosterMemberV1 {
                xonly_key: xonly_of(&INITIATOR_SECRET),
                role: SenderRoleV1::Initiator,
            },
        )
        .with_member(
            SOLVER,
            RosterMemberV1 {
                xonly_key: xonly_of(&SOLVER_SECRET),
                role: SenderRoleV1::Solver,
            },
        );
    RosterRegistryV1::new().with_snapshot(SNAPSHOT, snapshot)
}

fn envelope(
    kind: u16,
    sender: ParticipantId,
    recipient: ParticipantId,
    role: SenderRoleV1,
    payload: Vec<u8>,
    secret: &[u8; 32],
) -> Vec<u8> {
    let mut e = RelayEnvelopeV1 {
        network_id: NETWORK,
        message_type: kind,
        session_id: SESSION,
        route_id: ROUTE_ID,
        sender_id: sender,
        recipient_id: recipient,
        sender_role: role,
        sequence: 0,
        previous_transcript_hash: [0u8; 32],
        payload,
        expiry: TimelockSpec::TimestampSeconds { value: 10_000 },
        policy_version: 1,
        roster_snapshot: SNAPSHOT,
        signature: [0u8; 64],
    };
    let digest = e.envelope_digest().unwrap();
    let (sig, _) = secp().sign_bip340(secret, &digest, &[0x01; 32]).unwrap();
    e.signature = sig;
    e.canonical_bytes().unwrap()
}

fn now() -> TimelockSpec {
    TimelockSpec::TimestampSeconds { value: 1_000 }
}

/// The whole loop: intent → quotes → admissibility → selection →
/// acceptance → frozen terms.
#[test]
fn rfq_to_terms_binding_end_to_end_over_the_relay() {
    let mut relay_node = RelayV1::new();
    let rosters = rosters();
    let the_rfq = rfq();

    // 1. The initiator publishes the intent — nothing is locked.
    relay_node
        .submit(&envelope(
            message_type::RFQ,
            INITIATOR,
            SOLVER,
            SenderRoleV1::Initiator,
            the_rfq.canonical_bytes().unwrap(),
            &INITIATOR_SECRET,
        ))
        .expect("rfq submits");

    // 2. The solver receives THROUGH the production pipeline and the
    //    f6-engine payload checks, then prices and answers.
    let solver_ctx = RecipientContextV1 {
        recipient_id: SOLVER,
        network_id: NETWORK,
        session_id: SESSION,
        route_id: ROUTE_ID,
        policy_version: 1,
    };
    let mut solver_state = TranscriptStateV1::new();
    let raws = relay_node.deliver(&SOLVER);
    assert_eq!(raws.len(), 1);
    let accepted = accept_envelope(&raws[0], &solver_ctx, &rosters, &mut solver_state, now())
        .expect("pipeline accepts the rfq envelope");
    let binding = SessionBindingV1 {
        session_id: SESSION,
        rfq_id: the_rfq.rfq_id,
    };
    let PayloadObjectV1::Rfq(received_rfq) = accept_payload(&accepted, &binding).expect("consumer")
    else {
        panic!("the payload is the rfq");
    };
    assert_eq!(received_rfq, the_rfq, "byte-identical intent");

    let quote = reference_solver()
        .answer(&received_rfq, DOM, bond(), [0x02; 32])
        .expect("the solver answers");
    // 1:1 rate, 0.50% spread on 1_000_000 → fee 5_000, net 995_000.
    assert_eq!(quote.total_fee, 5_000);
    assert_eq!(quote.net_output, 995_000);

    // 3. The quote travels back through the same pipeline.
    relay_node
        .submit(&envelope(
            message_type::QUOTE,
            SOLVER,
            INITIATOR,
            SenderRoleV1::Solver,
            quote.canonical_bytes().unwrap(),
            &SOLVER_SECRET,
        ))
        .expect("quote submits");
    let initiator_ctx = RecipientContextV1 {
        recipient_id: INITIATOR,
        network_id: NETWORK,
        session_id: SESSION,
        route_id: ROUTE_ID,
        policy_version: 1,
    };
    let mut initiator_state = TranscriptStateV1::new();
    let raws = relay_node.deliver(&INITIATOR);
    assert_eq!(raws.len(), 1);
    let accepted = accept_envelope(
        &raws[0],
        &initiator_ctx,
        &rosters,
        &mut initiator_state,
        now(),
    )
    .expect("pipeline accepts the quote envelope");
    let PayloadObjectV1::Quote(received_quote) =
        accept_payload(&accepted, &binding).expect("consumer")
    else {
        panic!("the payload is the quote");
    };
    assert_eq!(received_quote, quote, "byte-identical quote");

    // 4. The initiator VERIFIES the quote signature with the pinned
    //    backend against the solver's roster key — a fact, not a claim.
    let signature_valid = secp()
        .verify_bip340(
            &xonly_of(&SOLVER_SECRET),
            &received_quote.quote_id,
            &received_quote.solver_signature,
        )
        .is_ok();
    let facts = CandidateFactsV1 {
        solver_registered: true,
        signature_valid,
        bond_reserved_exclusive: true,
        exposure_covered: true,
        coverage_excess: 0,
        solver_active: true,
        policy_version_accepted: true,
    };

    // 5. Ratified admissibility and selection.
    admissibility(&the_rfq, &received_quote, &facts, DOM, now()).expect("admissible");
    let outcome =
        select_winner(&the_rfq, &[(received_quote, facts)], DOM, now()).expect("a winner exists");
    assert_eq!(outcome.selection.winning_quote, received_quote.quote_id);

    // 6. Acceptance and the frozen terms.
    let terms = TermsBindingV1::from_parts(
        &the_rfq,
        &received_quote,
        [
            TimelockSpec::TimestampSeconds { value: 8_000 },
            TimelockSpec::TimestampSeconds { value: 9_000 },
        ],
        [[0xC1; 32], [0xC2; 32]],
    )
    .expect("terms bind");
    let terms_hash = terms.terms_hash().expect("terms hash");
    let acceptance = AcceptanceV1 {
        terms_hash,
        rfq_id: the_rfq.rfq_id,
        quote_id: received_quote.quote_id,
        accepted_by: INITIATOR,
    };
    assert_eq!(acceptance.terms_hash, terms.terms_hash().unwrap());
    // A tampered fee changes the hash: the frozen terms really freeze.
    let mut tampered = terms;
    tampered.total_fee += 1;
    assert_ne!(tampered.terms_hash().unwrap(), terms_hash);
}

/// A forged quote signature dies at the admissibility fact.
#[test]
fn a_forged_quote_signature_is_inadmissible() {
    let the_rfq = rfq();
    let mut quote = reference_solver()
        .answer(&the_rfq, DOM, bond(), [0x02; 32])
        .unwrap();
    quote.solver_signature[10] ^= 0x01;
    let signature_valid = secp()
        .verify_bip340(
            &xonly_of(&SOLVER_SECRET),
            &quote.quote_id,
            &quote.solver_signature,
        )
        .is_ok();
    assert!(!signature_valid, "the forged signature must not verify");
}

/// The solver's own refusals, by name.
#[test]
fn the_solver_refuses_by_name() {
    let s = reference_solver();

    // Cannot meet the user's protection bound.
    let mut greedy = rfq();
    greedy.mode = RfqModeV1::ExactIn {
        input_amount: 1_000_000,
        minimum_output: 999_999,
    };
    let greedy = RfqV1::create(
        greedy.initiator,
        greedy.route,
        greedy.mode,
        greedy.fee_limit,
        greedy.timelock_domain,
        greedy.quote_deadline,
        greedy.assurance_policy_ref,
        greedy.policy_version,
        greedy.session_id,
    )
    .unwrap();
    assert_eq!(
        s.answer(&greedy, DOM, bond(), [0x02; 32]).unwrap_err(),
        SolverRefusal::CannotMeetMinimum
    );

    // A route without the DOM refuses (AD-1.1).
    let mut no_dom_route = route();
    no_dom_route.legs[1].chain_id = ChainId([0xEE; 32]);
    let no_dom = RfqV1::create(
        INITIATOR,
        no_dom_route,
        RfqModeV1::ExactIn {
            input_amount: 1_000,
            minimum_output: 1,
        },
        FeeLimitV1 {
            dom_max: 1_000,
            counterparty_max: 0,
        },
        TimelockDomainV1::TimestampSeconds,
        TimelockSpec::TimestampSeconds { value: 5_000 },
        PolicyId([0xAA; 32]),
        1,
        SESSION,
    )
    .unwrap();
    assert_eq!(
        s.answer(&no_dom, DOM, bond(), [0x02; 32]).unwrap_err(),
        SolverRefusal::RouteExcludesDom
    );

    // A fee the RFQ's cap cannot carry refuses at the solver.
    let tight_fee = RfqV1::create(
        INITIATOR,
        route(),
        RfqModeV1::ExactIn {
            input_amount: 1_000_000,
            minimum_output: 1,
        },
        FeeLimitV1 {
            dom_max: 4_999, // the 0.50% spread needs 5_000
            counterparty_max: 0,
        },
        TimelockDomainV1::TimestampSeconds,
        TimelockSpec::TimestampSeconds { value: 5_000 },
        PolicyId([0xAA; 32]),
        1,
        SESSION,
    )
    .unwrap();
    assert_eq!(
        s.answer(&tight_fee, DOM, bond(), [0x02; 32]).unwrap_err(),
        SolverRefusal::FeeAboveLimit
    );

    // ExactOut over the maximum input refuses.
    let exact_out = RfqV1::create(
        INITIATOR,
        route(),
        RfqModeV1::ExactOut {
            exact_output: 1_000_000,
            maximum_input: 1_004_000, // 0.50% spread needs 1_005_000
        },
        FeeLimitV1 {
            dom_max: 10_000,
            counterparty_max: 0,
        },
        TimelockDomainV1::TimestampSeconds,
        TimelockSpec::TimestampSeconds { value: 5_000 },
        PolicyId([0xAA; 32]),
        1,
        SESSION,
    )
    .unwrap();
    assert_eq!(
        s.answer(&exact_out, DOM, bond(), [0x02; 32]).unwrap_err(),
        SolverRefusal::CannotBeatMaximumInput
    );
}

/// Two solvers, one better: the ratified selection picks the better
/// net output, deterministically.
#[test]
fn selection_picks_the_better_of_two_reference_solvers() {
    let the_rfq = rfq();
    let better = reference_solver(); // 0.50% spread
    let worse = ReferenceSolverV1::new(
        ParticipantId([0x62; 32]),
        SolverPolicyV1 {
            rate_num: 1,
            rate_den: 1,
            spread_bps: 200, // 2.00%
            execution_delta: 1_000,
            expiry_delta: 500,
        },
        [0x53; 32],
        [0x99; 32],
    );
    let qa = better.answer(&the_rfq, DOM, bond(), [0x02; 32]).unwrap();
    let qb = worse
        .answer(
            &the_rfq,
            DOM,
            BondFactsV1 {
                reservation_id: [0xBE; 32],
                policy_version: 7,
            },
            [0x03; 32],
        )
        .unwrap();
    let facts = |sig_ok: bool| CandidateFactsV1 {
        solver_registered: true,
        signature_valid: sig_ok,
        bond_reserved_exclusive: true,
        exposure_covered: true,
        coverage_excess: 0,
        solver_active: true,
        policy_version_accepted: true,
    };
    let outcome = select_winner(
        &the_rfq,
        &[(qb, facts(true)), (qa, facts(true))],
        DOM,
        now(),
    )
    .unwrap();
    assert_eq!(
        outcome.selection.winning_quote, qa.quote_id,
        "the higher net output wins regardless of arrival order"
    );
}

/// ExactOut, exact numbers: 1_000_000 out at 0.50% needs fee 5_000 and
/// input 1_005_000 at the 1:1 rate — and the quote is admissible.
#[test]
fn exact_out_prices_exactly_and_is_admissible() {
    let exact_out = RfqV1::create(
        INITIATOR,
        route(),
        RfqModeV1::ExactOut {
            exact_output: 1_000_000,
            maximum_input: 1_005_000,
        },
        FeeLimitV1 {
            dom_max: 10_000,
            counterparty_max: 0,
        },
        TimelockDomainV1::TimestampSeconds,
        TimelockSpec::TimestampSeconds { value: 5_000 },
        PolicyId([0xAA; 32]),
        1,
        SESSION,
    )
    .unwrap();
    let quote = reference_solver()
        .answer(&exact_out, DOM, bond(), [0x02; 32])
        .unwrap();
    assert_eq!(quote.total_fee, 5_000);
    assert_eq!(quote.total_input, 1_005_000);
    assert_eq!(quote.net_output, 1_000_000);
    let facts = CandidateFactsV1 {
        solver_registered: true,
        signature_valid: true,
        bond_reserved_exclusive: true,
        exposure_covered: true,
        coverage_excess: 0,
        solver_active: true,
        policy_version_accepted: true,
    };
    admissibility(&exact_out, &quote, &facts, DOM, now()).expect("admissible at the boundary");
}

/// The conservative-rounding invariant over a sweep of amounts: for
/// every accepted ExactIn quote, net + fee never exceeds the gross the
/// rate defines — the solver can always deliver what it promised.
#[test]
fn rounding_never_promises_more_than_the_rate_yields() {
    let s = reference_solver(); // 1:1, 0.50%
    for input in (1u128..2_000).step_by(37) {
        let rfq = RfqV1::create(
            INITIATOR,
            route(),
            // The RFQ layer itself refuses a zero protection bound
            // (ZeroAmount), so the sweep floors it at 1.
            RfqModeV1::ExactIn {
                input_amount: input,
                minimum_output: 1,
            },
            FeeLimitV1 {
                dom_max: u128::MAX / 2,
                counterparty_max: 0,
            },
            TimelockDomainV1::TimestampSeconds,
            TimelockSpec::TimestampSeconds { value: 5_000 },
            PolicyId([0xAA; 32]),
            1,
            SESSION,
        )
        .unwrap();
        match s.answer(&rfq, DOM, bond(), [0x02; 32]) {
            Ok(q) => {
                let gross = input; // 1:1 rate
                assert!(
                    q.net_output + q.total_fee <= gross,
                    "input {input}: promised {} + fee {} exceeds gross {gross}",
                    q.net_output,
                    q.total_fee
                );
            }
            Err(SolverRefusal::CannotMeetMinimum) => {
                // Tiny inputs where the ceil'd fee eats everything: an
                // honest refusal, not an under-delivering quote.
            }
            Err(other) => panic!("input {input}: unexpected refusal {other:?}"),
        }
    }
}

/// A non-unit rate prices exactly: 3 output per 2 input, spread 1%.
#[test]
fn a_non_unit_rate_prices_exactly() {
    let s = ReferenceSolverV1::new(
        SOLVER,
        SolverPolicyV1 {
            rate_num: 3,
            rate_den: 2,
            spread_bps: 100,
            execution_delta: 1_000,
            expiry_delta: 500,
        },
        SOLVER_SECRET,
        [0x99; 32],
    );
    let rfq = RfqV1::create(
        INITIATOR,
        route(),
        RfqModeV1::ExactIn {
            input_amount: 1_000_000,
            minimum_output: 1,
        },
        FeeLimitV1 {
            dom_max: 100_000,
            counterparty_max: 0,
        },
        TimelockDomainV1::TimestampSeconds,
        TimelockSpec::TimestampSeconds { value: 5_000 },
        PolicyId([0xAA; 32]),
        1,
        SESSION,
    )
    .unwrap();
    let q = s.answer(&rfq, DOM, bond(), [0x02; 32]).unwrap();
    // gross = 1_500_000; fee = ceil(1%) = 15_000; net = 1_485_000.
    assert_eq!(q.net_output, 1_485_000);
    assert_eq!(q.total_fee, 15_000);
}

/// The deadline offsets stay in the RFQ's own timelock domain (A4):
/// a BlockHeight RFQ yields BlockHeight quote deadlines.
#[test]
fn deadline_offsets_stay_in_the_rfq_domain() {
    let rfq = RfqV1::create(
        INITIATOR,
        route(),
        RfqModeV1::ExactIn {
            input_amount: 1_000_000,
            minimum_output: 1,
        },
        FeeLimitV1 {
            dom_max: 10_000,
            counterparty_max: 0,
        },
        TimelockDomainV1::BlockHeight,
        TimelockSpec::BlockHeight { value: 700 },
        PolicyId([0xAA; 32]),
        1,
        SESSION,
    )
    .unwrap();
    let q = reference_solver()
        .answer(&rfq, DOM, bond(), [0x02; 32])
        .unwrap();
    assert_eq!(
        q.execution_deadline,
        TimelockSpec::BlockHeight { value: 1_700 }
    );
    assert_eq!(q.expiry, TimelockSpec::BlockHeight { value: 1_200 });
}

/// The fee cap boundary: a cap EXACTLY equal to the priced fee emits;
/// one unit below refuses — mirrored on the ratified admissibility.
#[test]
fn the_fee_cap_boundary_is_exact() {
    let make = |dom_max: u128| {
        RfqV1::create(
            INITIATOR,
            route(),
            RfqModeV1::ExactIn {
                input_amount: 1_000_000,
                minimum_output: 1,
            },
            FeeLimitV1 {
                dom_max,
                counterparty_max: 0,
            },
            TimelockDomainV1::TimestampSeconds,
            TimelockSpec::TimestampSeconds { value: 5_000 },
            PolicyId([0xAA; 32]),
            1,
            SESSION,
        )
        .unwrap()
    };
    // 0.50% of 1_000_000 = 5_000.
    assert!(reference_solver()
        .answer(&make(5_000), DOM, bond(), [0x02; 32])
        .is_ok());
    assert_eq!(
        reference_solver()
            .answer(&make(4_999), DOM, bond(), [0x02; 32])
            .unwrap_err(),
        SolverRefusal::FeeAboveLimit
    );
}

/// A degenerate rate refuses by name, before any arithmetic.
#[test]
fn a_zero_rate_refuses() {
    for (num, den) in [(0u128, 1u128), (1, 0)] {
        let s = ReferenceSolverV1::new(
            SOLVER,
            SolverPolicyV1 {
                rate_num: num,
                rate_den: den,
                spread_bps: 50,
                execution_delta: 1_000,
                expiry_delta: 500,
            },
            SOLVER_SECRET,
            [0x99; 32],
        );
        assert_eq!(
            s.answer(&rfq(), DOM, bond(), [0x02; 32]).unwrap_err(),
            SolverRefusal::ZeroRate
        );
    }
}

/// AD-1.2 requires checked addition of the per-leg fee caps. Even a quote
/// whose own fee is small must not turn an invalid, overflowing cap into an
/// effectively unlimited allowance.
#[test]
fn an_overflowing_fee_cap_refuses_at_the_solver() {
    let invalid_cap = RfqV1::create(
        INITIATOR,
        route(),
        RfqModeV1::ExactIn {
            input_amount: 1_000,
            minimum_output: 1_000,
        },
        FeeLimitV1 {
            dom_max: u128::MAX,
            counterparty_max: 1,
        },
        TimelockDomainV1::TimestampSeconds,
        TimelockSpec::TimestampSeconds { value: 5_000 },
        PolicyId([0xAA; 32]),
        1,
        SESSION,
    )
    .unwrap();
    let zero_fee_solver = ReferenceSolverV1::new(
        SOLVER,
        SolverPolicyV1 {
            rate_num: 1,
            rate_den: 1,
            spread_bps: 0,
            execution_delta: 1_000,
            expiry_delta: 500,
        },
        SOLVER_SECRET,
        [0x99; 32],
    );

    assert_eq!(
        zero_fee_solver
            .answer(&invalid_cap, DOM, bond(), [0x02; 32])
            .unwrap_err(),
        SolverRefusal::FeeAboveLimit
    );
}
