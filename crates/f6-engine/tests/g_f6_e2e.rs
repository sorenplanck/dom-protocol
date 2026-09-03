//! F6 build-order step 8 — the end-to-end composition (spec v1.0.3 §7):
//!
//! > RFQ → quotes → selection → binding → F2 settlement → F3/F5 legs →
//! > F4 assurance, driven with the dom-sim seam (F7 swaps the real DOM).
//!
//! What step 7 deliberately did not claim, this suite does: the
//! negotiated §4.2 `terms_hash` is CARRIED into the settlement's
//! `SettlementTermsV1` (spec §4.2: "The accepted terms_hash is carried
//! into the settlement's SettlementTermsV1 so the F2 engine adjudicates
//! under it") and into the F4 assurance binding, and both machines are
//! then driven to their terminals under it — so the thing the F2 engine
//! settles and the thing the F4 machine compensates is provably the
//! thing the market step negotiated, not a parallel object that merely
//! resembles it.
//!
//! **The seam, stated honestly.** "Driven with the dom-sim seam" is the
//! build order's own phrase: the chains here are `SimSettlementChain`
//! (chain SEMANTICS only — funding, claim, timelock, finality — no
//! cryptography, I13/I15), exactly as the ratified G-F2 scenarios drive
//! them. The real-chain legs have their own gate suites — F3 on
//! Anvil/Sepolia, F5 on regtest/signet — and F7 swaps the real DOM into
//! this seam. This suite proves the COMPOSITION; it does not re-prove
//! the legs.
//!
//! **The carry — RATIFIED by D-023** (operator decision, 2026-08-10):
//! the accepted_terms_hash is carried in `SettlementTermsV1.metadata`
//! under the exact encoding `DOM-INTEROP/F6-TERMS-CARRY/V1\0 ||
//! accepted_terms_hash`, exactly once, no trailing bytes. The copy is a
//! COMMITMENT, not an input — metadata stays economically
//! non-authoritative; the F4 assurance receives the value as a direct
//! input from the journal-sourced composition root
//! (`f6_engine::composition`, D-023 §3). The D-023 mandatory checks
//! live in `d023_terms_carry.rs`; this suite keeps the composition
//! proofs it always had.

use std::path::{Path, PathBuf};

use btc_crypto::SecpContext;
use f2_harness::{SimEffectSink, SimSettlementChain};
use f4_harness::journal::{DurableAssurance, StoreLog as AssuranceStoreLog};
use f6_engine::consumer::{accept_payload, PayloadObjectV1, SessionBindingV1};
use f6_engine::{binding_complete, BindingEventV1, DurableBinding, StoreLog as BindingStoreLog};
use kaystra_core::settlement_engine::SettlementEngine;
use kaystra_core::state::SettlementState;
use kaystra_core::store_port::{SettlementStore, SqliteSettlementStore};
use kaystra_core::terms::SettlementTermsV1;
use kaystra_core::types::{
    AssetId as CoreAssetId, ChainId as CoreChainId, FeeLimitV1 as CoreFeeLimitV1, FinalityPolicyV1,
    IntentHash, LegRole, LegTermsV1, LockMechanism, ParticipantId as CoreParticipantId,
    RecoveryPolicyV1, SessionId, SettlementId, SolverId, TimelockSpec as CoreTimelock,
};
use relay::auth::{
    accept_envelope, message_type, RecipientContextV1, RosterMemberV1, RosterRegistryV1,
    RosterSnapshotV1, TranscriptStateV1,
};
use relay::server::RelayV1;
use relay::{RelayEnvelopeV1, SenderRoleV1};
use rfq::selection::{select_winner, CandidateFactsV1};
use rfq::{
    AcceptanceV1, AssetId, ChainId, FeeLimitV1, LegDirectionV1, ParticipantId, PolicyId, QuoteV1,
    RfqModeV1, RfqV1, RouteLegV1, RouteV1, TimelockDomainV1, TimelockSpec,
};
use uspe::{AssuranceError, AssuranceEvent, AssuranceState};

// --- session constants -------------------------------------------------

const NETWORK: [u8; 32] = [0x11; 32];
const SESSION: [u8; 32] = [0x22; 32];
const ROUTE_ID: [u8; 32] = [0x33; 32];
const SNAPSHOT: [u8; 32] = [0x77; 32];
const DOM_CHAIN: [u8; 32] = [0x11; 32];
const SIM_CHAIN: [u8; 32] = [0xc1; 32];
const SECRET: [u8; 32] = [0x5e; 32];

const INITIATOR: ParticipantId = ParticipantId([0x31; 32]);
const SOLVER_A: ParticipantId = ParticipantId([0x61; 32]);
const SOLVER_B: ParticipantId = ParticipantId([0x62; 32]);

const INITIATOR_SECRET: [u8; 32] = [0x52; 32];
const SOLVER_A_SECRET: [u8; 32] = [0x51; 32];
const SOLVER_B_SECRET: [u8; 32] = [0x53; 32];

const RESERVATION_A: [u8; 32] = [0x71; 32];
const RESERVATION_B: [u8; 32] = [0x72; 32];

// --- fixtures ----------------------------------------------------------

fn secp() -> SecpContext {
    SecpContext::new(&[0x99; 32])
}

fn xonly_of(secret: &[u8; 32]) -> [u8; 32] {
    secp()
        .sign_bip340(secret, &[0u8; 32], &[0u8; 32])
        .unwrap()
        .1
}

fn ts(value: u64) -> TimelockSpec {
    TimelockSpec::TimestampSeconds { value }
}

/// A DOM-central route (AD-1.1).
fn route() -> RouteV1 {
    RouteV1 {
        legs: [
            RouteLegV1 {
                chain_id: ChainId(DOM_CHAIN),
                asset: AssetId([0x12; 32]),
                direction: LegDirectionV1::UserGives,
            },
            RouteLegV1 {
                chain_id: ChainId([0x21; 32]),
                asset: AssetId([0x22; 32]),
                direction: LegDirectionV1::UserReceives,
            },
        ],
    }
}

fn session_rfq() -> RfqV1 {
    RfqV1::create(
        INITIATOR,
        route(),
        RfqModeV1::ExactIn {
            input_amount: 1_000,
            minimum_output: 900,
        },
        FeeLimitV1 {
            dom_max: 50,
            counterparty_max: 40,
        },
        TimelockDomainV1::TimestampSeconds,
        ts(10_000),
        PolicyId([0x41; 32]),
        1,
        SESSION,
    )
    .unwrap()
}

fn quote_from(
    rfq: &RfqV1,
    solver: ParticipantId,
    reservation: [u8; 32],
    net_output: u128,
) -> QuoteV1 {
    QuoteV1::create(
        rfq.rfq_id,
        solver,
        route(),
        net_output,
        1_000,
        20,
        ts(20_000),
        reservation,
        1,
        ts(9_000),
        [0xab; 64],
    )
    .unwrap()
}

fn facts() -> CandidateFactsV1 {
    CandidateFactsV1 {
        solver_registered: true,
        signature_valid: true,
        bond_reserved_exclusive: true,
        exposure_covered: true,
        coverage_excess: 1_000,
        solver_active: true,
        policy_version_accepted: true,
    }
}

fn rosters() -> RosterRegistryV1 {
    let snapshot = RosterSnapshotV1::new()
        .with_member(
            relay::ParticipantId(INITIATOR.0),
            RosterMemberV1 {
                xonly_key: xonly_of(&INITIATOR_SECRET),
                role: SenderRoleV1::Initiator,
            },
        )
        .with_member(
            relay::ParticipantId(SOLVER_A.0),
            RosterMemberV1 {
                xonly_key: xonly_of(&SOLVER_A_SECRET),
                role: SenderRoleV1::Solver,
            },
        )
        .with_member(
            relay::ParticipantId(SOLVER_B.0),
            RosterMemberV1 {
                xonly_key: xonly_of(&SOLVER_B_SECRET),
                role: SenderRoleV1::Solver,
            },
        );
    RosterRegistryV1::new().with_snapshot(SNAPSHOT, snapshot)
}

fn context_for(recipient: ParticipantId) -> RecipientContextV1 {
    RecipientContextV1 {
        recipient_id: relay::ParticipantId(recipient.0),
        network_id: NETWORK,
        session_id: SESSION,
        route_id: ROUTE_ID,
        policy_version: 1,
    }
}

#[allow(clippy::too_many_arguments)]
fn envelope(
    sender: ParticipantId,
    role: SenderRoleV1,
    recipient: ParticipantId,
    kind: u16,
    sequence: u64,
    previous: [u8; 32],
    payload: Vec<u8>,
    secret: &[u8; 32],
) -> RelayEnvelopeV1 {
    let mut envelope = RelayEnvelopeV1 {
        network_id: NETWORK,
        message_type: kind,
        session_id: SESSION,
        route_id: ROUTE_ID,
        sender_id: relay::ParticipantId(sender.0),
        recipient_id: relay::ParticipantId(recipient.0),
        sender_role: role,
        sequence,
        previous_transcript_hash: previous,
        payload,
        expiry: relay::TimelockSpec::TimestampSeconds { value: 100_000 },
        policy_version: 1,
        roster_snapshot: SNAPSHOT,
        signature: [0u8; 64],
    };
    let digest = envelope.envelope_digest().unwrap();
    envelope.signature = secp().sign_bip340(secret, &digest, &[0x01; 32]).unwrap().0;
    envelope
}

fn send_and_receive(
    relay: &mut RelayV1,
    envelope: &RelayEnvelopeV1,
    recipient: ParticipantId,
    state: &mut TranscriptStateV1,
    session: &SessionBindingV1,
) -> PayloadObjectV1 {
    let raw = envelope.canonical_bytes().unwrap();
    relay.submit(&raw).expect("the Relay must accept the leg");
    let delivered = relay.deliver(&relay::ParticipantId(recipient.0));
    assert!(delivered.contains(&raw), "the leg was not delivered");
    let accepted = accept_envelope(
        &raw,
        &context_for(recipient),
        &rosters(),
        state,
        relay::TimelockSpec::TimestampSeconds { value: 1_000 },
    )
    .expect("the envelope must pass the ratified §5.4 pipeline");
    accept_payload(&accepted, session).expect("the payload must correspond")
}

fn temp_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "dom-interop-g-f6-e2e-{}-{name}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn fresh_db(dir: &Path, name: &str) -> PathBuf {
    for suffix in ["", "-wal", "-shm"] {
        let _ = std::fs::remove_file(dir.join(format!("{name}.sqlite{suffix}")));
    }
    dir.join(format!("{name}.sqlite"))
}

// --- the negotiated settlement terms -----------------------------------

/// The D-023 canonical carry record. Test-local mirror of
/// `composition::AcceptedNegotiationV1::carry_metadata`, kept so the
/// mutation tests can also build DIVERGENT records the production API
/// refuses to construct.
fn carry_record(accepted_terms_hash: [u8; 32]) -> Vec<u8> {
    let mut out = Vec::with_capacity(f6_engine::composition::CARRY_RECORD_LEN);
    out.extend_from_slice(f6_engine::composition::CARRY_DOMAIN);
    out.extend_from_slice(&accepted_terms_hash);
    out
}

/// `SettlementTermsV1` derived FROM the accepted negotiation — every
/// field that both layers name is taken from the F6 objects, not
/// invented at settlement time:
///
/// - `session_id` is the F6 session;
/// - `intent_hash` is the RFQ id — the RFQ IS the user intent this
///   settlement executes, and its id is content-derived;
/// - `solver_id` is the WINNING solver, no other;
/// - `fee_limit` is the RFQ's ratified F2 fee bound, verbatim;
/// - `metadata` carries the accepted `terms_hash` (D-023);
/// - the legs live on the sim chain (the dom-sim seam).
fn negotiated_terms(
    rfq: &RfqV1,
    winner: &QuoteV1,
    acceptance: &AcceptanceV1,
    deadline_height: u64,
) -> SettlementTermsV1 {
    SettlementTermsV1 {
        settlement_id: SettlementId([0xa1; 32]),
        session_id: SessionId(rfq.session_id),
        intent_hash: IntentHash(rfq.rfq_id),
        solver_id: SolverId(winner.solver.0),
        roster: [
            CoreParticipantId(INITIATOR.0),
            CoreParticipantId(winner.solver.0),
        ],
        dom_leg: LegTermsV1 {
            role: LegRole::Dom,
            chain_id: CoreChainId(SIM_CHAIN),
            asset_id: CoreAssetId([0xc2; 32]),
            amount: 5,
            beneficiary: CoreParticipantId(winner.solver.0),
            refund_to: CoreParticipantId(INITIATOR.0),
            mechanism: LockMechanism::DomAdaptor2of2,
            deadline: CoreTimelock::BlockHeight {
                value: deadline_height,
            },
            finality: FinalityPolicyV1 {
                min_confirmations: 2,
                max_reorg_depth: 10,
            },
            adapter_profile_hash: [0xc3; 32],
        },
        counterparty_leg: LegTermsV1 {
            role: LegRole::Counterparty,
            chain_id: CoreChainId([0xd1; 32]),
            asset_id: CoreAssetId([0xd2; 32]),
            amount: 7,
            beneficiary: CoreParticipantId(INITIATOR.0),
            refund_to: CoreParticipantId(winner.solver.0),
            mechanism: LockMechanism::ConditionLock,
            deadline: CoreTimelock::BlockHeight { value: 500 },
            finality: FinalityPolicyV1 {
                min_confirmations: 1,
                max_reorg_depth: 9,
            },
            adapter_profile_hash: [0xd3; 32],
        },
        adaptor_point_sec1: {
            let mut p = [0xe1u8; 33];
            p[0] = 0x02;
            p
        },
        fee_limit: CoreFeeLimitV1 {
            dom_max: rfq.fee_limit.dom_max,
            counterparty_max: rfq.fee_limit.counterparty_max,
        },
        recovery: RecoveryPolicyV1 {
            refund_before_funding: true,
            evidence_retention_blocks: 10,
        },
        assurance_policy_hash: None,
        policy_version: 1,
        metadata: carry_record(acceptance.terms_hash),
    }
}

// --- the negotiation, once, shared by every test -----------------------

/// The full market step over the real Relay and pipelines, returning
/// everything the settlement and assurance layers need.
struct Negotiated {
    rfq: RfqV1,
    winner: QuoteV1,
    acceptance: AcceptanceV1,
    initiator: DurableBinding<BindingStoreLog>,
    solver_a: DurableBinding<BindingStoreLog>,
    candidates: Vec<(QuoteV1, CandidateFactsV1)>,
}

fn negotiate(dir: &Path) -> Negotiated {
    let mut relay = RelayV1::new();
    let rfq = session_rfq();
    let session = SessionBindingV1 {
        session_id: SESSION,
        rfq_id: rfq.rfq_id,
    };

    let mut initiator =
        DurableBinding::open(BindingStoreLog::open(&fresh_db(dir, "initiator")).unwrap()).unwrap();
    let mut solver_a =
        DurableBinding::open(BindingStoreLog::open(&fresh_db(dir, "solver-a")).unwrap()).unwrap();

    let mut at_solver_a = TranscriptStateV1::new();
    let mut at_solver_b = TranscriptStateV1::new();
    let mut at_initiator = TranscriptStateV1::new();

    // RFQ to both solvers (fan-out per D-020: one addressed envelope
    // per recipient, each flow at its own sequence 0).
    let rfq_bytes = rfq.canonical_bytes().unwrap();
    let to_a = envelope(
        INITIATOR,
        SenderRoleV1::Initiator,
        SOLVER_A,
        message_type::RFQ,
        0,
        [0u8; 32],
        rfq_bytes.clone(),
        &INITIATOR_SECRET,
    );
    let to_b = envelope(
        INITIATOR,
        SenderRoleV1::Initiator,
        SOLVER_B,
        message_type::RFQ,
        0,
        [0u8; 32],
        rfq_bytes,
        &INITIATOR_SECRET,
    );
    send_and_receive(&mut relay, &to_a, SOLVER_A, &mut at_solver_a, &session);
    send_and_receive(&mut relay, &to_b, SOLVER_B, &mut at_solver_b, &session);

    // Quotes back. A nets more and must win under the ratified A5 rule.
    let quote_a = quote_from(&rfq, SOLVER_A, RESERVATION_A, 980);
    let quote_b = quote_from(&rfq, SOLVER_B, RESERVATION_B, 950);

    solver_a
        .apply(&BindingEventV1::Reserved {
            reservation_id: RESERVATION_A,
            rfq_id: rfq.rfq_id,
            quote_id: quote_a.quote_id,
            solver: SOLVER_A,
        })
        .unwrap();
    for (quote, reservation, solver) in [
        (quote_a, RESERVATION_A, SOLVER_A),
        (quote_b, RESERVATION_B, SOLVER_B),
    ] {
        initiator
            .apply(&BindingEventV1::Reserved {
                reservation_id: reservation,
                rfq_id: rfq.rfq_id,
                quote_id: quote.quote_id,
                solver,
            })
            .unwrap();
    }

    for (quote, solver, secret) in [
        (quote_a, SOLVER_A, &SOLVER_A_SECRET),
        (quote_b, SOLVER_B, &SOLVER_B_SECRET),
    ] {
        let leg = envelope(
            solver,
            SenderRoleV1::Solver,
            INITIATOR,
            message_type::QUOTE,
            0,
            [0u8; 32],
            quote.canonical_bytes().unwrap(),
            secret,
        );
        assert_eq!(
            send_and_receive(&mut relay, &leg, INITIATOR, &mut at_initiator, &session),
            PayloadObjectV1::Quote(quote)
        );
    }

    // Selection, journaled; then the atomic binding on both sides.
    let candidates = vec![(quote_a, facts()), (quote_b, facts())];
    let outcome = initiator
        .select_and_record(&rfq, &candidates, ChainId(DOM_CHAIN), ts(5_000))
        .expect("the ratified selection must resolve");
    let winner = *candidates
        .iter()
        .map(|(quote, _)| quote)
        .find(|quote| quote.quote_id == outcome.selection.winning_quote)
        .expect("the winner is a candidate");
    assert_eq!(winner.solver, SOLVER_A);

    let deadlines = [ts(30_000), ts(40_000)];
    let commitments = [[0x81; 32], [0x82; 32]];
    let acceptance = initiator
        .bind_selected(
            &rfq,
            &winner,
            &facts(),
            ChainId(DOM_CHAIN),
            ts(5_000),
            deadlines,
            commitments,
            INITIATOR,
        )
        .expect("the winner must bind");
    solver_a
        .select_and_record(&rfq, &candidates[..1], ChainId(DOM_CHAIN), ts(5_000))
        .unwrap();
    solver_a
        .bind_selected(
            &rfq,
            &winner,
            &facts(),
            ChainId(DOM_CHAIN),
            ts(5_000),
            deadlines,
            commitments,
            INITIATOR,
        )
        .expect("the winner holds the same binding");
    assert!(binding_complete(&initiator, &solver_a, &rfq.rfq_id).unwrap());

    // The acceptance travels to the winner.
    let acceptance_env = envelope(
        INITIATOR,
        SenderRoleV1::Initiator,
        SOLVER_A,
        message_type::ACCEPTANCE,
        1,
        to_a.envelope_digest().unwrap(),
        acceptance.canonical_bytes(),
        &INITIATOR_SECRET,
    );
    assert_eq!(
        send_and_receive(
            &mut relay,
            &acceptance_env,
            SOLVER_A,
            &mut at_solver_a,
            &session
        ),
        PayloadObjectV1::Acceptance(acceptance)
    );

    Negotiated {
        rfq,
        winner,
        acceptance,
        initiator,
        solver_a,
        candidates,
    }
}

// --- driving the settlement under the negotiated terms -----------------

type Engine = SettlementEngine<SqliteSettlementStore, SimSettlementChain, SimEffectSink>;

fn open_settlement(
    dir: &Path,
    name: &str,
    terms: &SettlementTermsV1,
) -> (SimSettlementChain, Engine) {
    let path = fresh_db(dir, name);
    let chain = SimSettlementChain::new(CoreChainId(SIM_CHAIN), terms.settlement_id.0);
    let store = SqliteSettlementStore::open(&path).unwrap();
    store.create(terms, 1).unwrap();
    let deadline = match terms.dom_leg.deadline {
        CoreTimelock::BlockHeight { value } => value,
        _ => unreachable!("these terms use height deadlines"),
    };
    let sink = SimEffectSink::new(chain.clone(), deadline);
    let engine = SettlementEngine::open(store, chain.clone(), sink, terms.settlement_id).unwrap();
    (chain, engine)
}

fn drive(
    chain: &SimSettlementChain,
    engine: &mut Engine,
    claim_at_round: Option<usize>,
) -> SettlementState {
    engine.arm_refund(10).unwrap();
    engine.tick(11).unwrap();
    for round in 0..24usize {
        let state = engine.snapshot().unwrap().context.state;
        if state.is_terminal() {
            return state;
        }
        if claim_at_round == Some(round) {
            chain.submit_claim(SECRET);
        }
        chain.advance(1);
        engine.tick(20 + round as i64).unwrap();
    }
    engine.snapshot().unwrap().context.state
}

// --- the tests ---------------------------------------------------------

/// **The full composition, claim path.** RFQ → quotes → selection →
/// binding over the real Relay; the accepted `terms_hash` carried into
/// `SettlementTermsV1`; the F2 engine settles UNDER those terms on the
/// sim chain; the F4 assurance reaches `Compensated` bound to the SAME
/// `terms_hash`.
#[test]
fn the_negotiated_terms_settle_end_to_end() {
    let dir = temp_dir("settle");
    let n = negotiate(&dir);

    // The negotiated F6 terms hash is recomputable from the objects
    // (I12): what the binding journaled is what the parties can derive.
    let recomputed = rfq::TermsBindingV1::from_parts(
        &n.rfq,
        &n.winner,
        [ts(30_000), ts(40_000)],
        [[0x81; 32], [0x82; 32]],
    )
    .unwrap()
    .terms_hash()
    .unwrap();
    assert_eq!(
        recomputed, n.acceptance.terms_hash,
        "the journaled terms_hash must be recomputable from the objects"
    );

    // The settlement terms are DERIVED from the negotiation.
    let terms = negotiated_terms(&n.rfq, &n.winner, &n.acceptance, 1_000);
    assert_eq!(terms.session_id.0, n.rfq.session_id);
    assert_eq!(terms.solver_id.0, n.winner.solver.0);
    assert_eq!(terms.fee_limit.dom_max, n.rfq.fee_limit.dom_max);
    assert_eq!(
        terms.fee_limit.counterparty_max,
        n.rfq.fee_limit.counterparty_max
    );

    // The F2 engine adjudicates under them, to Settled.
    let (chain, mut engine) = open_settlement(&dir, "settlement", &terms);
    assert_eq!(
        drive(&chain, &mut engine, Some(2)),
        SettlementState::Settled
    );
    assert_eq!(
        engine
            .store()
            .terminal(terms.settlement_id)
            .unwrap()
            .map(|(s, _, _)| s),
        Some(SettlementState::Settled)
    );

    // The F4 assurance is bound to the SAME negotiated terms_hash and
    // reaches Compensated under it, crash-recovered at every step.
    let assurance_path = fresh_db(&dir, "assurance");
    let history = [
        AssuranceEvent::BondLockObserved,
        AssuranceEvent::CollateralVerified {
            terms_hash: n.acceptance.terms_hash,
        },
        AssuranceEvent::ObligationFailed,
        AssuranceEvent::CompensationClaimed {
            terms_hash: n.acceptance.terms_hash,
        },
        AssuranceEvent::EvidenceVerified { valid: true },
        AssuranceEvent::CompensationConfirmed { amount: 1_000 },
    ];
    for event in &history {
        let log = AssuranceStoreLog::open(&assurance_path).unwrap();
        let mut driver = DurableAssurance::open(log, n.acceptance.terms_hash, 1_000, true).unwrap();
        driver.apply(event).unwrap();
    }
    let log = AssuranceStoreLog::open(&assurance_path).unwrap();
    let assurance = DurableAssurance::open(log, n.acceptance.terms_hash, 1_000, true).unwrap();
    assert_eq!(assurance.context().state, AssuranceState::Compensated);

    // Both parties still hold the SAME binding at the end.
    assert!(binding_complete(&n.initiator, &n.solver_a, &n.rfq.rfq_id).unwrap());
}

/// **The composition, refund path.** The same negotiation; the timelock
/// runs out on the sim chain; the settlement refunds under the same
/// negotiated terms.
#[test]
fn the_negotiated_terms_refund_on_the_timelock() {
    let dir = temp_dir("refund");
    let n = negotiate(&dir);
    let terms = negotiated_terms(&n.rfq, &n.winner, &n.acceptance, 6);
    let (chain, mut engine) = open_settlement(&dir, "settlement", &terms);
    assert_eq!(drive(&chain, &mut engine, None), SettlementState::Refunded);
}

/// **The carry is committed.** The F2 engine adjudicates under its A3
/// `terms_hash`, so "the accepted terms_hash is carried into
/// SettlementTermsV1" is only real if changing the carried value
/// changes the A3 hash. It does — and every other negotiated field is
/// spot-checked the same way, so the settlement cannot silently
/// adjudicate a different negotiation.
#[test]
fn the_settlement_terms_commit_the_negotiated_terms_hash() {
    let dir = temp_dir("commit");
    let n = negotiate(&dir);
    let terms = negotiated_terms(&n.rfq, &n.winner, &n.acceptance, 1_000);
    let baseline = terms.terms_hash().unwrap();

    // A different negotiated terms_hash → a different settlement.
    let mut other = terms.clone();
    other.metadata = carry_record([0xEE; 32]);
    assert_ne!(
        other.terms_hash().unwrap(),
        baseline,
        "the A3 hash does not commit the carried F6 terms_hash"
    );

    // A different winner → a different settlement.
    let mut other = terms.clone();
    other.solver_id = SolverId([0xEE; 32]);
    assert_ne!(other.terms_hash().unwrap(), baseline);

    // A different session → a different settlement.
    let mut other = terms.clone();
    other.session_id = SessionId([0xEE; 32]);
    assert_ne!(other.terms_hash().unwrap(), baseline);

    // A different fee bound → a different settlement.
    let mut other = terms.clone();
    other.fee_limit.dom_max += 1;
    assert_ne!(other.terms_hash().unwrap(), baseline);
}

/// **A divergent terms_hash is refused by the assurance, by name.** The
/// F6→F4 binding is not decorative: an F4 machine bound to the
/// negotiated terms refuses collateral and claims that name ANY other
/// terms_hash. This is the ratified F2-§10 rule ("a different
/// terms_hash invalidates the evidence") observed through the real
/// machine.
#[test]
fn the_assurance_refuses_any_other_terms_hash_by_name() {
    let dir = temp_dir("divergent");
    let n = negotiate(&dir);
    let path = fresh_db(&dir, "assurance");

    let log = AssuranceStoreLog::open(&path).unwrap();
    let mut driver = DurableAssurance::open(log, n.acceptance.terms_hash, 1_000, true).unwrap();
    driver.apply(&AssuranceEvent::BondLockObserved).unwrap();

    // Collateral verified against a DIFFERENT negotiation: refused.
    let err = driver
        .apply(&AssuranceEvent::CollateralVerified {
            terms_hash: [0xEE; 32],
        })
        .expect_err("a divergent terms_hash must refuse");
    assert!(
        matches!(
            err,
            f4_harness::journal::JournalError::Transition(AssuranceError::TermsMismatch)
        ),
        "expected the named TermsMismatch refusal, got {err:?}"
    );

    // The right one still works — the refusal above was the divergence,
    // not a broken machine.
    driver
        .apply(&AssuranceEvent::CollateralVerified {
            terms_hash: n.acceptance.terms_hash,
        })
        .expect("the negotiated terms_hash must be accepted");
}

/// **I12: the selection is recomputable by an observer.** Anyone holding
/// the candidate book recomputes the SAME winner and the SAME
/// candidate-set digest the initiator journaled — the composition's
/// starting point is disprovable, not taken on faith.
#[test]
fn an_observer_recomputes_the_journaled_selection() {
    let dir = temp_dir("recompute");
    let n = negotiate(&dir);

    let recomputed = select_winner(&n.rfq, &n.candidates, ChainId(DOM_CHAIN), ts(5_000))
        .expect("the observer's recomputation must resolve");
    let journaled = n
        .initiator
        .ledger()
        .selection(&n.rfq.rfq_id)
        .expect("the initiator journaled a selection");
    assert_eq!(recomputed.selection.winning_quote, journaled.winning_quote);
    assert_eq!(recomputed.selection.inputs_digest, journaled.inputs_digest);
    assert_eq!(recomputed.selection.winning_quote, n.winner.quote_id);
}
