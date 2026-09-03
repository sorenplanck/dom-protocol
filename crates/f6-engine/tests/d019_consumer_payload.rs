//! **D-019 test 11** — the recipient consumer rejects a payload whose
//! inner object does not correspond to the `message_kind`, the sender,
//! the settlement or the bindings.
//!
//! The ratified division this suite exists to prove (D-019, operator
//! 2026-08-10): "The Relay stays forbidden from decoding the payload.
//! The policy authorizes the HEADER; the recipient consumer decodes and
//! verifies that the inner object corresponds to the message_kind, to
//! the sender, to the settlement and to the bindings."
//!
//! Every envelope below is authenticated by the REAL §5.4 pipeline with
//! a REAL BIP340 signature first. That matters: each refusal here is a
//! payload the transport layer had every reason to accept — correct
//! header, valid signature, permitted role, clean sequence — so what is
//! being measured is the consumer's own check and nothing borrowed from
//! upstream.

use btc_crypto::SecpContext;
use f6_engine::consumer::{accept_payload, ConsumerRefusal, PayloadObjectV1, SessionBindingV1};
use relay::auth::{
    accept_envelope, message_type, RecipientContextV1, RosterMemberV1, RosterRegistryV1,
    RosterSnapshotV1, TranscriptStateV1,
};
use relay::{RelayEnvelopeV1, SenderRoleV1};
use rfq::{
    AcceptanceV1, AssetId, ChainId, FeeLimitV1, LegDirectionV1, ParticipantId, PolicyId, QuoteV1,
    RfqModeV1, RfqV1, RouteLegV1, RouteV1, SelectionV1, TimelockDomainV1, TimelockSpec,
};

const NETWORK: [u8; 32] = [0x11; 32];
const SESSION: [u8; 32] = [0x22; 32];
const ROUTE_ID: [u8; 32] = [0x33; 32];
const SNAPSHOT: [u8; 32] = [0x77; 32];

const INITIATOR: ParticipantId = ParticipantId([0x31; 32]);
const SOLVER: ParticipantId = ParticipantId([0x61; 32]);
const RECIPIENT: ParticipantId = ParticipantId([0x41; 32]);

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

fn ts(value: u64) -> TimelockSpec {
    TimelockSpec::TimestampSeconds { value }
}

fn route() -> RouteV1 {
    RouteV1 {
        legs: [
            RouteLegV1 {
                chain_id: ChainId([0x11; 32]),
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

/// The session's RFQ — the settlement binding every later object must
/// carry.
fn session_rfq() -> RfqV1 {
    RfqV1::create(
        INITIATOR,
        route(),
        RfqModeV1::ExactIn {
            input_amount: 1_000,
            minimum_output: 950,
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

fn quote_for(rfq_id: [u8; 32], solver: ParticipantId) -> QuoteV1 {
    QuoteV1::create(
        rfq_id,
        solver,
        route(),
        980,
        1_000,
        20,
        ts(20_000),
        [0x71; 32],
        1,
        ts(9_000),
        [0xab; 64],
    )
    .unwrap()
}

fn session() -> SessionBindingV1 {
    SessionBindingV1 {
        session_id: SESSION,
        rfq_id: session_rfq().rfq_id,
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
            relay::ParticipantId(SOLVER.0),
            RosterMemberV1 {
                xonly_key: xonly_of(&SOLVER_SECRET),
                role: SenderRoleV1::Solver,
            },
        );
    RosterRegistryV1::new().with_snapshot(SNAPSHOT, snapshot)
}

fn recipient() -> RecipientContextV1 {
    RecipientContextV1 {
        recipient_id: relay::ParticipantId(RECIPIENT.0),
        network_id: NETWORK,
        session_id: SESSION,
        route_id: ROUTE_ID,
        policy_version: 1,
    }
}

/// Authenticates one payload through the REAL §5.4 pipeline, then runs
/// the consumer check on what came out of it.
fn deliver(
    sender: ParticipantId,
    role: SenderRoleV1,
    kind: u16,
    secret: &[u8; 32],
    payload: Vec<u8>,
) -> Result<PayloadObjectV1, ConsumerRefusal> {
    let mut envelope = RelayEnvelopeV1 {
        network_id: NETWORK,
        message_type: kind,
        session_id: SESSION,
        route_id: ROUTE_ID,
        sender_id: relay::ParticipantId(sender.0),
        recipient_id: relay::ParticipantId(RECIPIENT.0),
        sender_role: role,
        sequence: 0,
        previous_transcript_hash: [0u8; 32],
        payload,
        expiry: relay::TimelockSpec::TimestampSeconds { value: 10_000 },
        policy_version: 1,
        roster_snapshot: SNAPSHOT,
        signature: [0u8; 64],
    };
    let digest = envelope.envelope_digest().unwrap();
    envelope.signature = secp().sign_bip340(secret, &digest, &[0x01; 32]).unwrap().0;

    let raw = envelope.canonical_bytes().unwrap();
    let mut state = TranscriptStateV1::new();
    let accepted = accept_envelope(
        &raw,
        &recipient(),
        &rosters(),
        &mut state,
        relay::TimelockSpec::TimestampSeconds { value: 1_000 },
    )
    .expect("the envelope must AUTHENTICATE: the consumer check is what is under test");
    accept_payload(&accepted, &session())
}

/// The baseline: each ratified kind, carried by the role D-019 assigns
/// it, with a payload that corresponds in every respect, is accepted.
/// Without this every refusal below could be vacuous.
#[test]
fn t11a_a_corresponding_payload_is_accepted_for_every_kind() {
    let rfq = session_rfq();
    let quote = quote_for(rfq.rfq_id, SOLVER);

    assert_eq!(
        deliver(
            INITIATOR,
            SenderRoleV1::Initiator,
            message_type::RFQ,
            &INITIATOR_SECRET,
            rfq.canonical_bytes().unwrap(),
        )
        .unwrap(),
        PayloadObjectV1::Rfq(rfq)
    );

    assert_eq!(
        deliver(
            SOLVER,
            SenderRoleV1::Solver,
            message_type::QUOTE,
            &SOLVER_SECRET,
            quote.canonical_bytes().unwrap(),
        )
        .unwrap(),
        PayloadObjectV1::Quote(quote)
    );

    let acceptance = AcceptanceV1 {
        terms_hash: [0x99; 32],
        rfq_id: rfq.rfq_id,
        quote_id: quote.quote_id,
        accepted_by: INITIATOR,
    };
    assert_eq!(
        deliver(
            INITIATOR,
            SenderRoleV1::Initiator,
            message_type::ACCEPTANCE,
            &INITIATOR_SECRET,
            acceptance.canonical_bytes(),
        )
        .unwrap(),
        PayloadObjectV1::Acceptance(acceptance)
    );

    let selection = SelectionV1 {
        rfq_id: rfq.rfq_id,
        winning_quote: quote.quote_id,
        inputs_digest: [0x88; 32],
    };
    assert_eq!(
        deliver(
            INITIATOR,
            SenderRoleV1::Initiator,
            message_type::SELECTION,
            &INITIATOR_SECRET,
            selection.canonical_bytes(),
        )
        .unwrap(),
        PayloadObjectV1::Selection(selection)
    );
}

/// **Kind correspondence.** A well-formed object of the WRONG type,
/// carried under a `message_kind` its sender is authorized for, is
/// refused. The frozen per-object magic is what makes the substitution
/// impossible: an Acceptance is not an RFQ, however valid it is on its
/// own.
#[test]
fn t11b_an_object_of_another_kind_is_refused() {
    let rfq = session_rfq();
    let quote = quote_for(rfq.rfq_id, SOLVER);
    let acceptance = AcceptanceV1 {
        terms_hash: [0x99; 32],
        rfq_id: rfq.rfq_id,
        quote_id: quote.quote_id,
        accepted_by: INITIATOR,
    };
    let selection = SelectionV1 {
        rfq_id: rfq.rfq_id,
        winning_quote: quote.quote_id,
        inputs_digest: [0x88; 32],
    };

    // Every initiator kind carrying each of the other initiator objects.
    for (kind, payload) in [
        (message_type::RFQ, acceptance.canonical_bytes()),
        (message_type::RFQ, selection.canonical_bytes()),
        (message_type::ACCEPTANCE, rfq.canonical_bytes().unwrap()),
        (message_type::ACCEPTANCE, selection.canonical_bytes()),
        (message_type::SELECTION, rfq.canonical_bytes().unwrap()),
        (message_type::SELECTION, acceptance.canonical_bytes()),
    ] {
        let refusal = deliver(
            INITIATOR,
            SenderRoleV1::Initiator,
            kind,
            &INITIATOR_SECRET,
            payload,
        )
        .expect_err("an object of another kind must be refused");
        assert!(
            matches!(refusal, ConsumerRefusal::PayloadDecode(_)),
            "kind {kind:#06x} accepted a foreign object: {refusal:?}"
        );
    }

    // And the solver's own kind carrying an RFQ.
    assert!(matches!(
        deliver(
            SOLVER,
            SenderRoleV1::Solver,
            message_type::QUOTE,
            &SOLVER_SECRET,
            rfq.canonical_bytes().unwrap(),
        )
        .unwrap_err(),
        ConsumerRefusal::PayloadDecode(_)
    ));
    let _ = quote;
}

/// **Sender correspondence.** The object names a participant other than
/// the envelope's AUTHENTICATED sender. The signature is valid and the
/// role is permitted — the envelope really is from this sender — so the
/// only thing that can catch a solver quoting in another solver's name
/// is this check.
#[test]
fn t11c_an_object_naming_another_participant_is_refused() {
    let rfq = session_rfq();

    // A quote the solver signed and sent, but which names a DIFFERENT
    // solver as the quoting party.
    let impersonating = quote_for(rfq.rfq_id, ParticipantId([0x62; 32]));
    assert_eq!(
        deliver(
            SOLVER,
            SenderRoleV1::Solver,
            message_type::QUOTE,
            &SOLVER_SECRET,
            impersonating.canonical_bytes().unwrap(),
        )
        .unwrap_err(),
        ConsumerRefusal::SenderMismatch
    );

    // An acceptance recorded in someone else's name.
    let foreign_acceptance = AcceptanceV1 {
        terms_hash: [0x99; 32],
        rfq_id: rfq.rfq_id,
        quote_id: [0x00; 32],
        accepted_by: ParticipantId([0x32; 32]),
    };
    assert_eq!(
        deliver(
            INITIATOR,
            SenderRoleV1::Initiator,
            message_type::ACCEPTANCE,
            &INITIATOR_SECRET,
            foreign_acceptance.canonical_bytes(),
        )
        .unwrap_err(),
        ConsumerRefusal::SenderMismatch
    );

    // An RFQ whose initiator is not the sender.
    let foreign_rfq = RfqV1::create(
        ParticipantId([0x39; 32]),
        route(),
        RfqModeV1::ExactIn {
            input_amount: 1_000,
            minimum_output: 950,
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
    .unwrap();
    assert_eq!(
        deliver(
            INITIATOR,
            SenderRoleV1::Initiator,
            message_type::RFQ,
            &INITIATOR_SECRET,
            foreign_rfq.canonical_bytes().unwrap(),
        )
        .unwrap_err(),
        ConsumerRefusal::SenderMismatch
    );
}

/// **Settlement correspondence.** An RFQ object naming another session
/// is refused even though the ENVELOPE names the right one — the
/// header binding and the object binding must agree, or a message from
/// one settlement could be replayed into another.
#[test]
fn t11d_an_object_from_another_session_is_refused() {
    let foreign_session = RfqV1::create(
        INITIATOR,
        route(),
        RfqModeV1::ExactIn {
            input_amount: 1_000,
            minimum_output: 950,
        },
        FeeLimitV1 {
            dom_max: 50,
            counterparty_max: 40,
        },
        TimelockDomainV1::TimestampSeconds,
        ts(10_000),
        PolicyId([0x41; 32]),
        1,
        [0xEE; 32],
    )
    .unwrap();
    assert_eq!(
        deliver(
            INITIATOR,
            SenderRoleV1::Initiator,
            message_type::RFQ,
            &INITIATOR_SECRET,
            foreign_session.canonical_bytes().unwrap(),
        )
        .unwrap_err(),
        ConsumerRefusal::SessionMismatch
    );
}

/// **Binding correspondence.** Every object after the RFQ carries the
/// `rfq_id` it belongs to; one naming a different RFQ is refused. This
/// is what stops a quote, an acceptance or a selection from a
/// concurrent negotiation being delivered into this one.
#[test]
fn t11e_an_object_bound_to_another_rfq_is_refused() {
    let other_rfq: [u8; 32] = [0xAB; 32];

    assert_eq!(
        deliver(
            SOLVER,
            SenderRoleV1::Solver,
            message_type::QUOTE,
            &SOLVER_SECRET,
            quote_for(other_rfq, SOLVER).canonical_bytes().unwrap(),
        )
        .unwrap_err(),
        ConsumerRefusal::RfqMismatch
    );

    let acceptance = AcceptanceV1 {
        terms_hash: [0x99; 32],
        rfq_id: other_rfq,
        quote_id: [0x00; 32],
        accepted_by: INITIATOR,
    };
    assert_eq!(
        deliver(
            INITIATOR,
            SenderRoleV1::Initiator,
            message_type::ACCEPTANCE,
            &INITIATOR_SECRET,
            acceptance.canonical_bytes(),
        )
        .unwrap_err(),
        ConsumerRefusal::RfqMismatch
    );

    let selection = SelectionV1 {
        rfq_id: other_rfq,
        winning_quote: [0x00; 32],
        inputs_digest: [0x88; 32],
    };
    assert_eq!(
        deliver(
            INITIATOR,
            SenderRoleV1::Initiator,
            message_type::SELECTION,
            &INITIATOR_SECRET,
            selection.canonical_bytes(),
        )
        .unwrap_err(),
        ConsumerRefusal::RfqMismatch
    );
}

/// **The complement of D-019 test 10.** The Relay routed the
/// undecodable payload because its decision is a function of the header
/// alone; the consumer is where those bytes finally fail. Both halves
/// are needed: routing it proves the Relay does not decode, refusing it
/// proves nobody treats the bytes as meaningful.
#[test]
fn t11f_the_payload_the_relay_routed_is_refused_by_the_consumer() {
    let garbage: Vec<u8> = (0..=255u8).chain(0..=255u8).map(|b| b ^ 0x5a).collect();
    let refusal = deliver(
        SOLVER,
        SenderRoleV1::Solver,
        message_type::QUOTE,
        &SOLVER_SECRET,
        garbage,
    )
    .expect_err("undecodable bytes must not become an object");
    assert!(matches!(refusal, ConsumerRefusal::PayloadDecode(_)));
}

/// An object whose own content-derived identifier does not bind its
/// content is refused: the id is a binding, not a label. The bytes are
/// mutated on the WIRE rather than through the object API, because the
/// object API cannot even encode an unbound id — which is itself part
/// of the guarantee.
#[test]
fn t11g_an_object_whose_own_id_does_not_bind_is_refused() {
    let mut bytes = session_rfq().canonical_bytes().unwrap();
    // `policy_version` is the u32 immediately before the trailing
    // 32-byte `session_id`; changing it leaves a structurally perfect
    // RFQ whose `rfq_id` no longer derives from its content.
    let at = bytes.len() - 36;
    bytes[at] ^= 0x01;

    assert_eq!(
        deliver(
            INITIATOR,
            SenderRoleV1::Initiator,
            message_type::RFQ,
            &INITIATOR_SECRET,
            bytes,
        )
        .unwrap_err(),
        ConsumerRefusal::PayloadDecode(rfq::RfqObjectError::IdMismatch)
    );
}
