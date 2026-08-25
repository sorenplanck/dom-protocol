//! The Relay transport suite (F6 spec v1.0.1 §6.1-6.4, build-order
//! step 6).
//!
//! What is asserted here is what the ratified rules actually claim —
//! not paraphrases of them:
//!
//!   * "same id + same bytes ⇒ same ACK" is asserted at the BYTE level,
//!     on the ACK and on the resent envelope;
//!   * "resend uses the persisted bytes" is asserted by resending
//!     through a Relay whose stored bytes are the only source;
//!   * "same id + different bytes ⇒ equivocation, fail closed" is
//!     asserted together with the proof standing up to INDEPENDENT
//!     verification — and with a fabricated proof failing it, because
//!     evidence that cannot fail is not evidence;
//!   * "the Relay never decodes payloads" is asserted by routing an
//!     envelope whose payload is not decodable as anything.

#![cfg(feature = "real-bip340")]

use btc_crypto::SecpContext;
use relay::auth::{
    accept_envelope, message_type, AuthRefusal, RecipientContextV1, RosterMemberV1,
    RosterRegistryV1, RosterSnapshotV1, TranscriptStateV1,
};
use relay::server::{
    verify_equivocation, EquivocationProofV1, EquivocationVerdict, IdempotencyKeyV1, RelayRefusal,
    RelayV1,
};
use relay::{ParticipantId, RelayEnvelopeV1, SenderRoleV1, TimelockSpec};

const NETWORK: [u8; 32] = [0x11; 32];
const SESSION: [u8; 32] = [0x22; 32];
const ROUTE: [u8; 32] = [0x33; 32];
const SNAPSHOT: [u8; 32] = [0x77; 32];
const SOLVER_SECRET: [u8; 32] = [0x51; 32];
const IMPOSTOR_SECRET: [u8; 32] = [0x53; 32];
const SOLVER: ParticipantId = ParticipantId([0x61; 32]);
const INITIATOR: ParticipantId = ParticipantId([0x31; 32]);

fn ctx() -> SecpContext {
    SecpContext::new(&[0x99; 32])
}

fn xonly_of(secret: &[u8; 32]) -> [u8; 32] {
    ctx().sign_bip340(secret, &[0u8; 32], &[0u8; 32]).unwrap().1
}

fn unsigned(sequence: u64, previous: [u8; 32], payload: Vec<u8>) -> RelayEnvelopeV1 {
    RelayEnvelopeV1 {
        network_id: NETWORK,
        message_type: message_type::QUOTE,
        session_id: SESSION,
        route_id: ROUTE,
        sender_id: SOLVER,
        recipient_id: INITIATOR,
        sender_role: SenderRoleV1::Solver,
        sequence,
        previous_transcript_hash: previous,
        payload,
        expiry: TimelockSpec::TimestampSeconds { value: 10_000 },
        policy_version: 1,
        roster_snapshot: SNAPSHOT,
        signature: [0u8; 64],
    }
}

fn sign(mut envelope: RelayEnvelopeV1, secret: &[u8; 32]) -> RelayEnvelopeV1 {
    let digest = envelope.envelope_digest().unwrap();
    let (sig, _) = ctx().sign_bip340(secret, &digest, &[0x01; 32]).unwrap();
    envelope.signature = sig;
    envelope
}

fn rosters() -> RosterRegistryV1 {
    let snapshot = RosterSnapshotV1::new().with_member(
        SOLVER,
        RosterMemberV1 {
            xonly_key: xonly_of(&SOLVER_SECRET),
            role: SenderRoleV1::Solver,
        },
    );
    RosterRegistryV1::new().with_snapshot(SNAPSHOT, snapshot)
}

fn recipient() -> RecipientContextV1 {
    RecipientContextV1 {
        recipient_id: INITIATOR,
        network_id: NETWORK,
        session_id: SESSION,
        route_id: ROUTE,
    }
}

/// §6.1: a byte-identical resend gets an ACK that is equal FIELD BY
/// FIELD to the first one, and the bytes the Relay hands back are the
/// ones it persisted — nothing is recomputed on the resend path.
#[test]
fn a_resend_gets_a_byte_identical_ack_and_the_persisted_bytes() {
    let envelope = sign(unsigned(0, [0u8; 32], vec![0xd0, 0xd1]), &SOLVER_SECRET);
    let raw = envelope.canonical_bytes().unwrap();
    let mut relay = RelayV1::new();

    let first = relay.submit(&raw).expect("first submission");
    let second = relay.submit(&raw).expect("resend");
    // The ratified rule is the WHOLE ACK, not some of its fields.
    assert_eq!(first, second, "the resend ACK is not byte-identical");

    // The stored bytes ARE the submitted bytes, byte for byte.
    let key = IdempotencyKeyV1::of(&envelope);
    assert_eq!(relay.stored_bytes(&key), Some(raw.as_slice()));

    // And delivery hands back exactly those bytes, however often.
    assert_eq!(relay.deliver(&INITIATOR), vec![raw.clone()]);
    assert_eq!(relay.deliver(&INITIATOR), vec![raw.clone()]);
    assert_eq!(relay.len(), 1, "a resend created no second entry");
}

/// §6.1 end to end: at-least-once transport, exactly-once effects. The
/// Relay repeats a delivery; the recipient's pipeline accepts the first
/// and names the second a duplicate — so repetition costs nothing.
#[test]
fn at_least_once_delivery_becomes_exactly_once_at_the_recipient() {
    let envelope = sign(unsigned(0, [0u8; 32], vec![0x01]), &SOLVER_SECRET);
    let mut relay = RelayV1::new();
    relay.submit(&envelope.canonical_bytes().unwrap()).unwrap();

    let mut state = TranscriptStateV1::new();
    let mut accepted = 0usize;
    let mut duplicates = 0usize;
    // Three delivery rounds of the same mailbox.
    for _ in 0..3 {
        for raw in relay.deliver(&INITIATOR) {
            match accept_envelope(
                &raw,
                &recipient(),
                &rosters(),
                &mut state,
                TimelockSpec::TimestampSeconds { value: 1_000 },
            ) {
                Ok(_) => accepted += 1,
                Err(AuthRefusal::Duplicate) => duplicates += 1,
                Err(other) => panic!("unexpected refusal: {other:?}"),
            }
        }
    }
    assert_eq!(accepted, 1, "the effect happened more than once");
    assert_eq!(duplicates, 2);
}

/// §6.1: two DIFFERENT envelopes at one idempotency key fail closed,
/// and the refusal carries a proof that stands on its own.
#[test]
fn equivocation_fails_closed_and_the_proof_verifies_independently() {
    let first = sign(unsigned(0, [0u8; 32], vec![0xaa]), &SOLVER_SECRET);
    let second = sign(unsigned(0, [0u8; 32], vec![0xbb]), &SOLVER_SECRET);
    let mut relay = RelayV1::new();
    relay.submit(&first.canonical_bytes().unwrap()).unwrap();

    let refusal = relay
        .submit(&second.canonical_bytes().unwrap())
        .expect_err("conflicting bytes at one key");
    let RelayRefusal::Equivocation(proof) = refusal else {
        panic!("expected an equivocation refusal, got {refusal:?}");
    };
    assert_eq!(proof.key, IdempotencyKeyV1::of(&first));
    assert_eq!(proof.first, first.canonical_bytes().unwrap());
    assert_eq!(proof.second, second.canonical_bytes().unwrap());

    // The proof stands WITHOUT the Relay: two signatures, two digests,
    // one roster key, one position.
    verify_equivocation(&proof, &rosters()).expect("the proof must verify");

    // The Relay did not adopt the conflicting bytes.
    assert_eq!(relay.len(), 1);
    assert_eq!(
        relay.stored_bytes(&proof.key),
        Some(first.canonical_bytes().unwrap().as_slice())
    );
}

/// Evidence that cannot fail is not evidence: a fabricated proof must
/// be rejected by the same independent check.
#[test]
fn a_fabricated_equivocation_proof_does_not_stand() {
    let honest = sign(unsigned(0, [0u8; 32], vec![0xaa]), &SOLVER_SECRET);
    let honest_bytes = honest.canonical_bytes().unwrap();

    // (a) The same envelope twice: a duplicate, not a conflict.
    let duplicate = EquivocationProofV1 {
        key: IdempotencyKeyV1::of(&honest),
        first: honest_bytes.clone(),
        second: honest_bytes.clone(),
    };
    assert_eq!(
        verify_equivocation(&duplicate, &rosters()).unwrap_err(),
        EquivocationVerdict::NotConflicting
    );

    // (b) A second envelope the sender never signed — the Relay made it
    // up and signed with its own key.
    let forged = sign(unsigned(0, [0u8; 32], vec![0xbb]), &IMPOSTOR_SECRET);
    let fabricated = EquivocationProofV1 {
        key: IdempotencyKeyV1::of(&honest),
        first: honest_bytes.clone(),
        second: forged.canonical_bytes().unwrap(),
    };
    assert_eq!(
        verify_equivocation(&fabricated, &rosters()).unwrap_err(),
        EquivocationVerdict::SignatureDoesNotVerify
    );

    // (c) Two honestly signed envelopes at DIFFERENT positions: both
    // signatures verify, but there is no conflict to prove.
    let elsewhere = sign(unsigned(1, [0u8; 32], vec![0xcc]), &SOLVER_SECRET);
    let mismatched = EquivocationProofV1 {
        key: IdempotencyKeyV1::of(&honest),
        first: honest_bytes,
        second: elsewhere.canonical_bytes().unwrap(),
    };
    assert_eq!(
        verify_equivocation(&mismatched, &rosters()).unwrap_err(),
        EquivocationVerdict::KeyMismatch
    );
}

/// §6.2: the Relay routes on the header and NEVER decodes payloads. A
/// payload of pure noise — not valid UTF-8, not a valid envelope, not
/// valid anything — routes exactly like any other.
#[test]
fn the_relay_routes_a_payload_it_cannot_possibly_interpret() {
    let noise: Vec<u8> = (0..=255u8).chain(0..=255u8).map(|b| b ^ 0x5a).collect();
    let envelope = sign(unsigned(0, [0u8; 32], noise.clone()), &SOLVER_SECRET);
    let raw = envelope.canonical_bytes().unwrap();
    let mut relay = RelayV1::new();
    relay.submit(&raw).expect("noise routes like anything else");
    assert_eq!(relay.deliver(&INITIATOR), vec![raw]);

    // And the recipient — who DOES decode — gets the payload back
    // byte for byte.
    let mut state = TranscriptStateV1::new();
    let accepted = accept_envelope(
        &relay.deliver(&INITIATOR)[0],
        &recipient(),
        &rosters(),
        &mut state,
        TimelockSpec::TimestampSeconds { value: 1_000 },
    )
    .expect("accepted");
    assert_eq!(accepted.envelope.payload, noise);
}

/// Mailboxes are per recipient: the Relay hands each participant only
/// what is addressed to it. (Misdelivery is still refused downstream —
/// tested in the adversarial suite — but a correct Relay does not
/// misdeliver in the first place.)
#[test]
fn mailboxes_are_separated_by_recipient() {
    let third = ParticipantId([0x99; 32]);
    let to_initiator = sign(unsigned(0, [0u8; 32], vec![0x01]), &SOLVER_SECRET);
    let mut for_third = unsigned(1, [0u8; 32], vec![0x02]);
    for_third.recipient_id = third;
    let for_third = sign(for_third, &SOLVER_SECRET);

    let mut relay = RelayV1::new();
    relay
        .submit(&to_initiator.canonical_bytes().unwrap())
        .unwrap();
    relay.submit(&for_third.canonical_bytes().unwrap()).unwrap();

    assert_eq!(
        relay.deliver(&INITIATOR),
        vec![to_initiator.canonical_bytes().unwrap()]
    );
    assert_eq!(
        relay.deliver(&third),
        vec![for_third.canonical_bytes().unwrap()]
    );
    assert!(relay.deliver(&SOLVER).is_empty());
}

/// The mailbox round-trips a whole session: everything submitted comes
/// back, and the recipient's pipeline accepts it. What is NOT asserted
/// here is any delivery ORDER — no source document requires one of the
/// Relay (§6.1 promises at-least-once and nothing more), and the
/// recipient survives arbitrary order by the §5.4 rules the adversarial
/// suite exercises. Asserting an order would freeze a rule nobody
/// ratified.
#[test]
fn the_mailbox_round_trips_a_whole_session() {
    let mut relay = RelayV1::new();
    let mut previous = [0u8; 32];
    let mut expected = Vec::new();
    for sequence in 0..4u64 {
        let envelope = sign(
            unsigned(sequence, previous, vec![sequence as u8]),
            &SOLVER_SECRET,
        );
        previous = envelope.envelope_digest().unwrap();
        let raw = envelope.canonical_bytes().unwrap();
        relay.submit(&raw).unwrap();
        expected.push(raw);
    }
    let delivered = relay.deliver(&INITIATOR);
    assert_eq!(delivered.len(), expected.len(), "an envelope was lost");
    for raw in &expected {
        assert!(
            delivered.contains(raw),
            "a submitted envelope was not delivered"
        );
    }

    // Delivered in the order this reference implementation happens to
    // use, the session walks the recipient pipeline clean.
    let mut state = TranscriptStateV1::new();
    for raw in delivered {
        accept_envelope(
            &raw,
            &recipient(),
            &rosters(),
            &mut state,
            TimelockSpec::TimestampSeconds { value: 1_000 },
        )
        .expect("ordered delivery accepted");
    }
    assert_eq!(state.last(&SOLVER, &INITIATOR).map(|(s, _)| s), Some(3));
}

/// A submission that does not decode is refused by the codec before
/// anything is stored — the Relay's parse exists to ROUTE, and a frame
/// it cannot route is not held.
#[test]
fn an_undecodable_submission_stores_nothing() {
    let mut relay = RelayV1::new();
    for bad in [
        vec![],
        vec![0u8; 4],
        vec![0xff; relay::MAX_ENVELOPE_BYTES + 1],
    ] {
        assert!(matches!(relay.submit(&bad), Err(RelayRefusal::Codec(_))));
    }
    assert!(relay.is_empty());
}
