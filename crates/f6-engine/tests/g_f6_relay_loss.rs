//! F6 build-order step 7 — Relay-loss survivability, the SECOND CLAUSE
//! of the G-F6 gate (spec v1.0.3 §6.3, ported from Foundation Document
//! §4.6).
//!
//! The ratified rule, verbatim:
//!
//! > **Relay-loss survivability (the gate's second clause).** Claim,
//! > refund and compensation read only local durable state and the
//! > chains. The G-F6 suite must kill the Relay (process AND database)
//! > at every protocol stage and prove the session still reaches its
//! > terminal state through local artifacts plus chain observation.
//!
//! What "kill" means here, with nothing softened: the `RelayV1` value is
//! DROPPED (the process dies) and replaced by a fresh empty one (the
//! database is gone). Every stored envelope, every mailbox and every ACK
//! it ever produced ceases to exist, and nothing is copied out first.
//! In the same breath each participant is restarted too — its
//! `DurableBinding` is dropped and recovered from its own SQLite file,
//! and the settlement engine is dropped and recovered from its own — so
//! what continues the session is a genuinely new process reading a
//! genuinely durable local artifact.
//!
//! **Why this suite could be vacuous, and what stops it.** If the second
//! half of a session never touched the Relay, killing the Relay would
//! prove nothing. Three assertions keep that from happening:
//!
//! 1. the negotiation up to the kill really does travel the Relay —
//!    every message is a signed [`relay::RelayEnvelopeV1`] accepted by
//!    the real §5.4 pipeline, and the test fails if any of them is
//!    refused;
//! 2. after the kill the transport really is GONE — every mailbox is
//!    asserted empty, and a message that had not yet been delivered is
//!    asserted to be unrecoverable, forever;
//! 3. the terminal is compared against a CONTROL run of the same
//!    scenario with no loss at all. "Reaches a terminal" would be a weak
//!    claim; "reaches the SAME terminal, at the same revision, with the
//!    same binding" is the claim §6.3 actually makes.
//!
//! **Scope.** Step 7 proves the Relay is not load-bearing. It does not
//! wire the negotiated `terms_hash` into the settlement's terms — that
//! is build-order step 8's end-to-end job, and claiming it here would be
//! claiming more than this suite measures.

use std::path::{Path, PathBuf};

use btc_crypto::SecpContext;
use f2_harness::{SimEffectSink, SimSettlementChain};
use f4_harness::journal::{DurableAssurance, StoreLog as AssuranceStoreLog};
use f6_engine::consumer::{accept_payload, PayloadObjectV1, SessionBindingV1};
use f6_engine::{
    binding_complete, BindingEventV1, BoundRecordV1, DurableBinding, StoreLog as BindingStoreLog,
};
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
use rfq::selection::CandidateFactsV1;
use rfq::{
    AssetId, ChainId, FeeLimitV1, LegDirectionV1, ParticipantId, PolicyId, QuoteV1, RfqModeV1,
    RfqV1, RouteLegV1, RouteV1, TimelockDomainV1, TimelockSpec,
};
use uspe::{AssuranceEvent, AssuranceState};

// --- session constants -------------------------------------------------

const NETWORK: [u8; 32] = [0x11; 32];
const SESSION: [u8; 32] = [0x22; 32];
const ROUTE_ID: [u8; 32] = [0x33; 32];
const SNAPSHOT: [u8; 32] = [0x77; 32];
const DOM_CHAIN: [u8; 32] = [0x11; 32];
const SIM_CHAIN: [u8; 32] = [0xc1; 32];
/// The secret the counterparty reveals on chain when claiming. It travels
/// the CHAIN, never the Relay — which is half of why the Relay can be
/// lost without consequence.
const SECRET: [u8; 32] = [0x5e; 32];

const INITIATOR: ParticipantId = ParticipantId([0x31; 32]);
const SOLVER_A: ParticipantId = ParticipantId([0x61; 32]);
const SOLVER_B: ParticipantId = ParticipantId([0x62; 32]);

const INITIATOR_SECRET: [u8; 32] = [0x52; 32];
const SOLVER_A_SECRET: [u8; 32] = [0x51; 32];
const SOLVER_B_SECRET: [u8; 32] = [0x53; 32];

const RESERVATION_A: [u8; 32] = [0x71; 32];
const RESERVATION_B: [u8; 32] = [0x72; 32];

/// Every protocol stage at which the Relay is killed. The ratified rule
/// says "at every protocol stage", so the list is the stages of an F6
/// session and not a sample of them.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Stage {
    /// Nothing has been sent yet.
    BeforeRfq,
    /// The RFQ reached both solvers.
    RfqDelivered,
    /// One solver's quote reached the initiator; the other's has not.
    OneQuoteDelivered,
    /// Both quotes reached the initiator.
    QuotesDelivered,
    /// The initiator journaled the ratified selection.
    SelectionRecorded,
    /// The atomic §4.2 binding is journaled on both sides.
    BindingRecorded,
    /// The acceptance reached the winning solver.
    AcceptanceDelivered,
}

const STAGES: [Stage; 7] = [
    Stage::BeforeRfq,
    Stage::RfqDelivered,
    Stage::OneQuoteDelivered,
    Stage::QuotesDelivered,
    Stage::SelectionRecorded,
    Stage::BindingRecorded,
    Stage::AcceptanceDelivered,
];

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

/// A DOM-central route (AD-1.1): the session's DOM chain on exactly one
/// leg.
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

/// Two quotes that differ only in outcome, so the ratified A5 rule has a
/// unique winner: solver A nets more, and therefore wins.
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
    }
}

/// One signed envelope in the D-020 addressed flow
/// `(session, sender, recipient)`.
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

/// Submits an envelope, then delivers and validates it at the recipient
/// through the REAL §5.4 pipeline, then runs the consumer check.
///
/// Every step is asserted, so a "successful" run cannot be one where the
/// Relay quietly carried nothing.
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
    assert!(
        delivered.contains(&raw),
        "the Relay did not deliver the envelope it acknowledged"
    );

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
    let dir = std::env::temp_dir().join(format!("dom-interop-g-f6-{}-{name}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

// --- the participants' durable local state -----------------------------

/// One participant's F6 journal, on a real SQLite file. "Restarting" it
/// means dropping the driver and recovering from that file alone.
struct Party {
    path: PathBuf,
    engine: Option<DurableBinding<BindingStoreLog>>,
}

impl Party {
    fn open(dir: &Path, name: &str) -> Self {
        let path = dir.join(format!("{name}.sqlite"));
        for suffix in ["", "-wal", "-shm"] {
            let _ = std::fs::remove_file(dir.join(format!("{name}.sqlite{suffix}")));
        }
        let engine = DurableBinding::open(BindingStoreLog::open(&path).unwrap()).unwrap();
        Self {
            path,
            engine: Some(engine),
        }
    }

    fn engine(&mut self) -> &mut DurableBinding<BindingStoreLog> {
        self.engine.as_mut().expect("engine present")
    }

    fn view(&self) -> &DurableBinding<BindingStoreLog> {
        self.engine.as_ref().expect("engine present")
    }

    /// A process restart: the driver is dropped entirely and recovered
    /// from the file. Nothing is carried across in memory.
    ///
    /// The revision is captured before the drop and asserted after the
    /// recovery. A restart that silently started from an empty journal
    /// would otherwise look exactly like a successful one — and would
    /// make every "the outcome is unchanged" assertion downstream
    /// meaningless, because there would be no local state left to be
    /// unchanged.
    fn restart(&mut self) {
        let before = self.view().revision();
        let ledger = self.view().ledger().clone();
        self.engine = None;
        let recovered = DurableBinding::open(BindingStoreLog::open(&self.path).unwrap()).unwrap();
        assert_eq!(
            recovered.revision(),
            before,
            "the restart lost journal history instead of recovering it"
        );
        assert_eq!(
            recovered.ledger(),
            &ledger,
            "the recovered ledger differs from the one that was lost"
        );
        self.engine = Some(recovered);
    }

    fn binding(&self, rfq_id: &[u8; 32]) -> Option<BoundRecordV1> {
        self.view().ledger().binding(rfq_id).copied()
    }
}

// --- the settlement, on real SQLite and a simulated chain --------------

type Engine = SettlementEngine<SqliteSettlementStore, SimSettlementChain, SimEffectSink>;

fn settlement_terms(deadline_height: u64) -> SettlementTermsV1 {
    SettlementTermsV1 {
        settlement_id: SettlementId([0xa1; 32]),
        session_id: SessionId(SESSION),
        intent_hash: IntentHash([0xa3; 32]),
        solver_id: SolverId([0xa4; 32]),
        roster: [CoreParticipantId([0xb1; 32]), CoreParticipantId([0xb2; 32])],
        dom_leg: LegTermsV1 {
            role: LegRole::Dom,
            chain_id: CoreChainId(SIM_CHAIN),
            asset_id: CoreAssetId([0xc2; 32]),
            amount: 5,
            beneficiary: CoreParticipantId([0xb2; 32]),
            refund_to: CoreParticipantId([0xb1; 32]),
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
            beneficiary: CoreParticipantId([0xb1; 32]),
            refund_to: CoreParticipantId([0xb2; 32]),
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
            dom_max: 0,
            counterparty_max: 0,
        },
        recovery: RecoveryPolicyV1 {
            refund_before_funding: true,
            evidence_retention_blocks: 10,
        },
        assurance_policy_hash: None,
        policy_version: 1,
        metadata: Vec::new(),
    }
}

/// The settlement side of one run: a real store on disk, a simulated
/// chain, and an engine that can be dropped and recovered.
struct Settlement {
    path: PathBuf,
    terms: SettlementTermsV1,
    chain: SimSettlementChain,
    engine: Option<Engine>,
}

impl Settlement {
    fn open(dir: &Path, name: &str, deadline_height: u64) -> Self {
        let path = dir.join(format!("{name}.sqlite"));
        for suffix in ["", "-wal", "-shm"] {
            let _ = std::fs::remove_file(dir.join(format!("{name}.sqlite{suffix}")));
        }
        let terms = settlement_terms(deadline_height);
        let chain = SimSettlementChain::new(CoreChainId(SIM_CHAIN), terms.settlement_id.0);
        let store = SqliteSettlementStore::open(&path).unwrap();
        store.create(&terms, 1).unwrap();
        let mut me = Self {
            path,
            terms,
            chain,
            engine: None,
        };
        me.engine = Some(me.build());
        me
    }

    fn build(&self) -> Engine {
        let store = SqliteSettlementStore::open(&self.path).unwrap();
        let deadline = match self.terms.dom_leg.deadline {
            CoreTimelock::BlockHeight { value } => value,
            _ => unreachable!("these terms use height deadlines"),
        };
        let sink = SimEffectSink::new(self.chain.clone(), deadline);
        SettlementEngine::open(store, self.chain.clone(), sink, self.terms.settlement_id).unwrap()
    }

    fn engine(&mut self) -> &mut Engine {
        self.engine.as_mut().expect("engine present")
    }

    /// A process restart: dropped entirely, recovered from the file.
    fn restart(&mut self) {
        self.engine = None;
        self.engine = Some(self.build());
    }

    fn state(&self) -> SettlementState {
        self.engine
            .as_ref()
            .expect("engine present")
            .snapshot()
            .unwrap()
            .context
            .state
    }

    /// Mines a block and ticks, until terminal or `max` rounds. The
    /// on-chain claim, when there is one, is submitted at
    /// `claim_at_round` — the same shape the ratified F2 scenarios use
    /// (`f2_e2e_001`), so this suite drives the engine the way the F2
    /// gate already proved it must be driven.
    fn run_until_terminal(&mut self, max: usize, base_now: i64, claim_at_round: Option<usize>) {
        for round in 0..max {
            if self.state().is_terminal() {
                return;
            }
            if claim_at_round == Some(round) {
                self.chain.submit_claim(SECRET);
            }
            self.chain.advance(1);
            let now = base_now + round as i64;
            self.engine().tick(now).unwrap();
        }
    }

    fn terminal(&self) -> Option<SettlementState> {
        self.engine
            .as_ref()
            .expect("engine present")
            .store()
            .terminal(self.terms.settlement_id)
            .unwrap()
            .map(|(state, _, _)| state)
    }
}

// --- what one run produces ---------------------------------------------

/// Everything the gate compares between a lossy run and its control.
#[derive(PartialEq, Eq, Debug)]
struct Outcome {
    settlement_terminal: Option<SettlementState>,
    assurance_terminal: AssuranceState,
    assurance_revision: u64,
    initiator_binding: Option<BoundRecordV1>,
    winner_binding: Option<BoundRecordV1>,
    binding_complete: bool,
    winning_quote: Option<[u8; 32]>,
}

/// The chain-observed history that drives the F4 assurance to
/// `Compensated`. Every event is an observation of a CHAIN or of local
/// evidence; not one of them is a Relay message, which is precisely why
/// compensation survives the Relay's death.
fn slash_history(terms_hash: [u8; 32]) -> Vec<AssuranceEvent> {
    vec![
        AssuranceEvent::BondLockObserved,
        AssuranceEvent::CollateralVerified { terms_hash },
        AssuranceEvent::ObligationFailed,
        AssuranceEvent::CompensationClaimed { terms_hash },
        AssuranceEvent::EvidenceVerified { valid: true },
        AssuranceEvent::CompensationConfirmed { amount: 1_000 },
    ]
}

/// Drives one whole session. `kill_at` is `None` for the control run.
///
/// `claim` selects the settlement path: `true` submits the on-chain
/// claim (terminal `Settled`), `false` lets the timelock run out
/// (terminal `Refunded`). The F4 assurance is driven to `Compensated` in
/// both, because §6.3 names all three outcomes.
fn run_session(label: &str, kill_at: Option<Stage>, claim: bool) -> Outcome {
    let dir = temp_dir(label);
    let mut relay = RelayV1::new();
    let rfq = session_rfq();
    let session = SessionBindingV1 {
        session_id: SESSION,
        rfq_id: rfq.rfq_id,
    };

    let mut initiator = Party::open(&dir, "initiator");
    let mut solver_a = Party::open(&dir, "solver-a");
    // The claim path needs a deadline far enough out for the claim to
    // confirm; the refund path needs one the chain's clock will pass.
    // Both numbers are the ones the ratified F2 scenarios use
    // (`f2_e2e_001` and `f2_e2e_002`).
    let mut settlement = Settlement::open(&dir, "settlement", if claim { 1_000 } else { 6 });

    // Each addressed flow has its own transcript state (D-020). These
    // are deliberately NOT reset by the kill: replay, gap and
    // equivocation state is the RECIPIENT's own durable state, and the
    // whole point of §6.3 is that the recipient keeps what it needs
    // while the Relay keeps nothing.
    let mut at_solver_a = TranscriptStateV1::new();
    let mut at_solver_b = TranscriptStateV1::new();
    let mut at_initiator = TranscriptStateV1::new();

    // The kill closure: process AND database, for the Relay and for
    // every participant at once.
    let mut killed = false;
    let kill = |relay: &mut RelayV1,
                initiator: &mut Party,
                solver_a: &mut Party,
                settlement: &mut Settlement,
                killed: &mut bool| {
        // The Relay's process and database, gone. Nothing is copied out.
        *relay = RelayV1::new();
        assert!(relay.is_empty(), "the killed Relay still holds state");
        for who in [INITIATOR, SOLVER_A, SOLVER_B] {
            assert!(
                relay.deliver(&relay::ParticipantId(who.0)).is_empty(),
                "a mailbox survived the kill"
            );
        }
        // The participants restart too, from their own files alone.
        initiator.restart();
        solver_a.restart();
        settlement.restart();
        *killed = true;
    };

    if kill_at == Some(Stage::BeforeRfq) {
        kill(
            &mut relay,
            &mut initiator,
            &mut solver_a,
            &mut settlement,
            &mut killed,
        );
    }

    // --- stage: the RFQ reaches both solvers ---------------------------
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
    assert_eq!(
        send_and_receive(&mut relay, &to_a, SOLVER_A, &mut at_solver_a, &session),
        PayloadObjectV1::Rfq(rfq)
    );
    assert_eq!(
        send_and_receive(&mut relay, &to_b, SOLVER_B, &mut at_solver_b, &session),
        PayloadObjectV1::Rfq(rfq)
    );

    if kill_at == Some(Stage::RfqDelivered) {
        kill(
            &mut relay,
            &mut initiator,
            &mut solver_a,
            &mut settlement,
            &mut killed,
        );
    }

    // --- stage: the quotes come back -----------------------------------
    // Solver A nets more, so the ratified A5 rule makes it the winner.
    let quote_a = quote_from(&rfq, SOLVER_A, RESERVATION_A, 980);
    let quote_b = quote_from(&rfq, SOLVER_B, RESERVATION_B, 950);

    // Each solver reserves its bond EXCLUSIVELY before quoting; the
    // reservation is journaled locally, never at the Relay.
    solver_a
        .engine()
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
            .engine()
            .apply(&BindingEventV1::Reserved {
                reservation_id: reservation,
                rfq_id: rfq.rfq_id,
                quote_id: quote.quote_id,
                solver,
            })
            .unwrap();
    }

    let quote_a_env = envelope(
        SOLVER_A,
        SenderRoleV1::Solver,
        INITIATOR,
        message_type::QUOTE,
        0,
        [0u8; 32],
        quote_a.canonical_bytes().unwrap(),
        &SOLVER_A_SECRET,
    );
    assert_eq!(
        send_and_receive(
            &mut relay,
            &quote_a_env,
            INITIATOR,
            &mut at_initiator,
            &session
        ),
        PayloadObjectV1::Quote(quote_a)
    );

    if kill_at == Some(Stage::OneQuoteDelivered) {
        // Solver B's quote has not been submitted yet, and solver A's
        // has already been delivered and consumed. The kill therefore
        // lands mid-negotiation: what the Relay held for A is destroyed
        // AFTER it was consumed, and B's leg must travel a Relay that
        // did not exist when the session started.
        //
        // B can still send it because B holds its own copy — which is
        // the point. `relay_loss_costs_the_session_its_transport_and_
        // only_that` isolates that half: an UNDELIVERED message is gone
        // from the Relay for good, and only the sender's local copy
        // gets it moving again.
        kill(
            &mut relay,
            &mut initiator,
            &mut solver_a,
            &mut settlement,
            &mut killed,
        );
    }

    let quote_b_env = envelope(
        SOLVER_B,
        SenderRoleV1::Solver,
        INITIATOR,
        message_type::QUOTE,
        0,
        [0u8; 32],
        quote_b.canonical_bytes().unwrap(),
        &SOLVER_B_SECRET,
    );
    assert_eq!(
        send_and_receive(
            &mut relay,
            &quote_b_env,
            INITIATOR,
            &mut at_initiator,
            &session
        ),
        PayloadObjectV1::Quote(quote_b)
    );

    if kill_at == Some(Stage::QuotesDelivered) {
        kill(
            &mut relay,
            &mut initiator,
            &mut solver_a,
            &mut settlement,
            &mut killed,
        );
    }

    // --- stage: the ratified selection, journaled locally --------------
    let candidates = [(quote_a, facts()), (quote_b, facts())];
    let outcome = initiator
        .engine()
        .select_and_record(&rfq, &candidates, ChainId(DOM_CHAIN), ts(5_000))
        .expect("the ratified selection must resolve");
    let winner = *candidates
        .iter()
        .map(|(quote, _)| quote)
        .find(|quote| quote.quote_id == outcome.selection.winning_quote)
        .expect("the winning quote must be one of the candidates");
    assert_eq!(
        winner.solver, SOLVER_A,
        "the greater net output must win under the ratified A5 rule"
    );

    if kill_at == Some(Stage::SelectionRecorded) {
        kill(
            &mut relay,
            &mut initiator,
            &mut solver_a,
            &mut settlement,
            &mut killed,
        );
    }

    // --- stage: the atomic §4.2 binding, on BOTH sides -----------------
    let deadlines = [ts(30_000), ts(40_000)];
    let commitments = [[0x81; 32], [0x82; 32]];
    let acceptance = initiator
        .engine()
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
        .engine()
        .select_and_record(&rfq, &candidates[..1], ChainId(DOM_CHAIN), ts(5_000))
        .expect("the winner records the same selection");
    solver_a
        .engine()
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

    if kill_at == Some(Stage::BindingRecorded) {
        kill(
            &mut relay,
            &mut initiator,
            &mut solver_a,
            &mut settlement,
            &mut killed,
        );
    }

    // --- stage: the acceptance travels ---------------------------------
    let acceptance_env = envelope(
        INITIATOR,
        SenderRoleV1::Initiator,
        SOLVER_A,
        message_type::ACCEPTANCE,
        1,
        // Chains to the RFQ leg of this flow, or opens a new flow if the
        // Relay died before that leg travelled.
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

    if kill_at == Some(Stage::AcceptanceDelivered) {
        kill(
            &mut relay,
            &mut initiator,
            &mut solver_a,
            &mut settlement,
            &mut killed,
        );
    }

    assert_eq!(killed, kill_at.is_some(), "the requested kill did not run");

    // --- terminality, from local state and the chains alone ------------
    //
    // From here on the Relay is not consulted once. If any of this
    // needed it, a killed run would diverge from the control.
    settlement.engine().arm_refund(10).unwrap();
    settlement.engine().tick(11).unwrap();
    settlement.run_until_terminal(24, 20, if claim { Some(2) } else { None });

    // Compensation: the F4 assurance journal, driven by chain
    // observations, recovered from its own file at every step.
    let assurance_path = dir.join("assurance.sqlite");
    for suffix in ["", "-wal", "-shm"] {
        let _ = std::fs::remove_file(dir.join(format!("assurance.sqlite{suffix}")));
    }
    for event in slash_history(acceptance.terms_hash) {
        let log = AssuranceStoreLog::open(&assurance_path).unwrap();
        let mut driver = DurableAssurance::open(log, acceptance.terms_hash, 1_000, true).unwrap();
        driver.apply(&event).unwrap();
    }
    let log = AssuranceStoreLog::open(&assurance_path).unwrap();
    let assurance = DurableAssurance::open(log, acceptance.terms_hash, 1_000, true).unwrap();

    Outcome {
        settlement_terminal: settlement.terminal(),
        assurance_terminal: assurance.context().state,
        assurance_revision: assurance.revision(),
        initiator_binding: initiator.binding(&rfq.rfq_id),
        winner_binding: solver_a.binding(&rfq.rfq_id),
        binding_complete: binding_complete(initiator.view(), solver_a.view(), &rfq.rfq_id).unwrap(),
        winning_quote: Some(outcome.selection.winning_quote),
    }
}

// --- the gate clause ---------------------------------------------------

/// **§6.3, claim path.** The Relay is killed — process and database — at
/// every protocol stage, and the session still reaches `Settled`, with
/// the SAME binding and the same F4 compensation, as a run that never
/// lost it.
#[test]
fn relay_loss_at_every_stage_still_reaches_the_claim_terminal() {
    let control = run_session("control-claim", None, true);
    assert_eq!(
        control.settlement_terminal,
        Some(SettlementState::Settled),
        "the control run must actually settle, or every comparison below is vacuous"
    );
    assert_eq!(control.assurance_terminal, AssuranceState::Compensated);
    assert!(control.binding_complete, "the control must bind both sides");

    for stage in STAGES {
        let lossy = run_session(&format!("claim-{stage:?}"), Some(stage), true);
        assert_eq!(
            lossy, control,
            "killing the Relay at {stage:?} changed the outcome"
        );
    }
}

/// **§6.3, refund path.** The same, for the timelock outcome: a session
/// whose transport dies still refunds on the chain's clock.
#[test]
fn relay_loss_at_every_stage_still_reaches_the_refund_terminal() {
    let control = run_session("control-refund", None, false);
    assert_eq!(
        control.settlement_terminal,
        Some(SettlementState::Refunded),
        "the control run must actually refund"
    );
    assert_eq!(control.assurance_terminal, AssuranceState::Compensated);

    for stage in STAGES {
        let lossy = run_session(&format!("refund-{stage:?}"), Some(stage), false);
        assert_eq!(
            lossy, control,
            "killing the Relay at {stage:?} changed the outcome"
        );
    }
}

/// The kill is REAL: a Relay that has carried a whole negotiation, once
/// killed, holds nothing, delivers nothing to anyone, and cannot answer
/// for a key it acknowledged moments earlier.
///
/// Without this the suite above could pass with a `kill` that did
/// nothing at all.
#[test]
fn a_killed_relay_keeps_nothing_and_can_answer_for_nothing() {
    let rfq = session_rfq();
    let session = SessionBindingV1 {
        session_id: SESSION,
        rfq_id: rfq.rfq_id,
    };
    let mut relay = RelayV1::new();
    let mut at_solver_a = TranscriptStateV1::new();

    let leg = envelope(
        INITIATOR,
        SenderRoleV1::Initiator,
        SOLVER_A,
        message_type::RFQ,
        0,
        [0u8; 32],
        rfq.canonical_bytes().unwrap(),
        &INITIATOR_SECRET,
    );
    send_and_receive(&mut relay, &leg, SOLVER_A, &mut at_solver_a, &session);

    let key = relay::server::IdempotencyKeyV1::of(&leg);
    assert!(relay.stored_bytes(&key).is_some(), "nothing was stored");
    assert_eq!(relay.len(), 1);

    // The kill.
    relay = RelayV1::new();

    assert!(relay.is_empty());
    assert_eq!(relay.len(), 0);
    assert!(
        relay.stored_bytes(&key).is_none(),
        "a killed Relay still answers for a stored key"
    );
    for who in [INITIATOR, SOLVER_A, SOLVER_B] {
        assert!(
            relay.deliver(&relay::ParticipantId(who.0)).is_empty(),
            "a killed Relay still delivers"
        );
    }
}

/// The complement, and the honest half of the claim: losing the Relay
/// DOES cost the session its transport. A message that had not yet been
/// delivered is gone and cannot be recovered from the Relay — the
/// sender must send it again, into a new Relay, and only its own local
/// copy makes that possible.
///
/// §6.3 promises that transport is all that is lost. Asserting the loss
/// is what makes the promise falsifiable.
#[test]
fn relay_loss_costs_the_session_its_transport_and_only_that() {
    let rfq = session_rfq();
    let session = SessionBindingV1 {
        session_id: SESSION,
        rfq_id: rfq.rfq_id,
    };
    let mut relay = RelayV1::new();

    let leg = envelope(
        INITIATOR,
        SenderRoleV1::Initiator,
        SOLVER_A,
        message_type::RFQ,
        0,
        [0u8; 32],
        rfq.canonical_bytes().unwrap(),
        &INITIATOR_SECRET,
    );
    let raw = leg.canonical_bytes().unwrap();
    relay.submit(&raw).unwrap();

    // Killed BEFORE the solver ever collected its mailbox.
    relay = RelayV1::new();
    assert!(
        relay.deliver(&relay::ParticipantId(SOLVER_A.0)).is_empty(),
        "the undelivered message survived the kill"
    );

    // The sender still holds the bytes, so it re-sends them into the new
    // Relay — byte-identical (I7), and the recipient accepts them
    // exactly once.
    let ack = relay.submit(&raw).expect("the resend must be accepted");
    assert_eq!(ack, relay.submit(&raw).unwrap(), "the ACK is not stable");

    let mut at_solver_a = TranscriptStateV1::new();
    let recovered = accept_envelope(
        &raw,
        &context_for(SOLVER_A),
        &rosters(),
        &mut at_solver_a,
        relay::TimelockSpec::TimestampSeconds { value: 1_000 },
    )
    .expect("the re-sent envelope is accepted");
    assert_eq!(
        accept_payload(&recovered, &session).unwrap(),
        PayloadObjectV1::Rfq(rfq)
    );
}
