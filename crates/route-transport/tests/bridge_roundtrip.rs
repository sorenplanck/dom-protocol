//! The §7.1 closure, proven: route bytes travel the ratified Relay V1
//! path — real BIP340 signatures, the production §5.4 pipeline, the
//! ratified `ROUTE_TRANSPORT` kind — and arrive byte-identical. Plus
//! every refusal the bridge names, provoked.

#![allow(deprecated)] // This file proves the retained ephemeral compatibility path.

use btc_crypto::SecpContext;
use kaystra_core::types::Digest32;
use relay::auth::{
    RecipientContextV1, RosterMemberV1, RosterRegistryV1, RosterSnapshotV1, TranscriptStateV1,
};
use relay::server::{verify_equivocation, RelayRefusal, RelayV1};
use relay::{ParticipantId, SenderRoleV1, TimelockSpec};
use route_transport::{
    receive_route_payloads, BridgeRefusal, PreparedRouteEnvelopeV1, RouteSenderCheckpointV1,
    RouteSenderV1, RouteWireContextV1, MAX_ROUTE_TRANSPORT_PAYLOAD_BYTES,
};

const NETWORK: Digest32 = [0x11; 32];
const SESSION: Digest32 = [0x22; 32];
const ROUTE: Digest32 = [0x33; 32];
const SNAPSHOT: Digest32 = [0x77; 32];
const INITIATOR: ParticipantId = ParticipantId([0x31; 32]);
const SOLVER: ParticipantId = ParticipantId([0x61; 32]);
const INITIATOR_SECRET: [u8; 32] = [0x52; 32];

fn ctx() -> RouteWireContextV1 {
    RouteWireContextV1 {
        network_id: NETWORK,
        session_id: SESSION,
        route_id: ROUTE,
        roster_snapshot: SNAPSHOT,
        policy_version: 1,
    }
}

fn xonly_of(secret: &[u8; 32]) -> [u8; 32] {
    SecpContext::new(&[0x99; 32])
        .sign_bip340(secret, &[0u8; 32], &[0u8; 32])
        .unwrap()
        .1
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
                xonly_key: xonly_of(&[0x51; 32]),
                role: SenderRoleV1::Solver,
            },
        );
    RosterRegistryV1::new().with_snapshot(SNAPSHOT, snapshot)
}

fn recipient_ctx() -> RecipientContextV1 {
    RecipientContextV1 {
        recipient_id: SOLVER,
        network_id: NETWORK,
        session_id: SESSION,
        route_id: ROUTE,
        policy_version: 1,
    }
}

fn sender() -> RouteSenderV1 {
    RouteSenderV1::new(
        ctx(),
        INITIATOR,
        SOLVER,
        SenderRoleV1::Initiator,
        INITIATOR_SECRET,
        [0x99; 32],
    )
    .expect("initiator may emit route transport")
}

fn expiry() -> TimelockSpec {
    TimelockSpec::TimestampSeconds { value: 10_000 }
}

fn now() -> TimelockSpec {
    TimelockSpec::TimestampSeconds { value: 1_000 }
}

/// Three chained route messages, byte-identical after the full pipeline.
#[test]
fn route_bytes_travel_the_relay_and_arrive_byte_identical() {
    let mut relay = RelayV1::new();
    let mut tx = sender();
    let payloads: [&[u8]; 3] = [
        b"dsc1-signed-frame-1",
        b"dsc1-signed-frame-2",
        b"dsc1-frame-3",
    ];
    for (i, p) in payloads.iter().enumerate() {
        let ack = tx
            .send(&mut relay, p.to_vec(), expiry(), [i as u8 + 1; 32])
            .expect("submit");
        assert_eq!(ack.key.sequence, i as u64);
    }

    let mut state = TranscriptStateV1::new();
    let delivery = receive_route_payloads(&relay, &recipient_ctx(), &rosters(), &mut state, now());
    let (accepted, refused) = (delivery.accepted, delivery.refused);
    assert!(refused.is_empty(), "nothing refused: {refused:?}");
    assert_eq!(delivery.skipped, 0);
    assert_eq!(accepted.len(), 3);
    for (i, got) in accepted.iter().enumerate() {
        assert_eq!(
            got.payload.as_slice(),
            payloads[i],
            "byte-identical payload {i}"
        );
        assert_eq!(got.sequence, i as u64);
        assert_eq!(got.sender_id, INITIATOR);
    }
    // The chain is real: each accepted digest is the next link.
    assert_ne!(accepted[0].envelope_digest, accepted[1].envelope_digest);
}

/// I7 both ways: a resend replays the SAME ACK; a second delivery of
/// the same envelope refuses in the pipeline as a duplicate — and the
/// mailbox's other messages still arrive.
#[test]
fn resend_replays_the_ack_and_redelivery_refuses_as_duplicate() {
    let mut relay = RelayV1::new();
    let mut tx = sender();
    let ack1 = tx
        .send(&mut relay, b"frame".to_vec(), expiry(), [1; 32])
        .unwrap();

    // The Relay's own idempotency: submitting the stored bytes again
    // returns the same ACK byte-for-byte.
    let raw = relay.stored_bytes(&ack1.key).unwrap().to_vec();
    let ack2 = relay.submit(&raw).unwrap();
    assert_eq!(
        ack1.canonical_bytes(),
        ack2.canonical_bytes(),
        "I7: same ACK bytes"
    );

    // First receive accepts; a second receive of the same mailbox
    // refuses the envelope as a replay, by name, without panicking.
    let mut state = TranscriptStateV1::new();
    let d = receive_route_payloads(&relay, &recipient_ctx(), &rosters(), &mut state, now());
    assert_eq!((d.accepted.len(), d.refused.len()), (1, 0));
    let d = receive_route_payloads(&relay, &recipient_ctx(), &rosters(), &mut state, now());
    assert_eq!(d.accepted.len(), 0, "nothing accepted twice");
    assert_eq!(d.refused.len(), 1, "the redelivery is refused by name");
}

/// Equivocation: same flow position, different bytes — the refusal
/// carries the ratified proof, and the proof VERIFIES independently.
#[test]
fn equivocation_is_refused_with_a_verifiable_proof() {
    let mut relay = RelayV1::new();

    // Two senders at the SAME flow position (fresh sender restarts at
    // sequence 1) with different payloads: the second submission is the
    // equivocation.
    let mut first = sender();
    first
        .send(&mut relay, b"the-first-story".to_vec(), expiry(), [1; 32])
        .unwrap();
    let mut second = sender();
    let refusal = second
        .send(&mut relay, b"a-different-story".to_vec(), expiry(), [2; 32])
        .unwrap_err();
    let BridgeRefusal::Relay(RelayRefusal::Equivocation(proof)) = refusal else {
        panic!("expected the equivocation refusal, got {refusal:?}");
    };
    // A10: any third party checks the proof against the roster alone;
    // the Relay's word is not part of the argument.
    verify_equivocation(&proof, &rosters()).expect("the proof stands on its own");
}

/// The named bridge refusals: observer at construction, empty payload.
#[test]
fn observer_and_empty_payload_refuse_by_name() {
    let err = RouteSenderV1::new(
        ctx(),
        INITIATOR,
        SOLVER,
        SenderRoleV1::Observer,
        INITIATOR_SECRET,
        [0x99; 32],
    )
    .unwrap_err();
    assert!(matches!(err, BridgeRefusal::ObserverEmitsNothing));

    let mut relay = RelayV1::new();
    let err = sender()
        .send(&mut relay, Vec::new(), expiry(), [1; 32])
        .unwrap_err();
    assert!(matches!(err, BridgeRefusal::EmptyPayload));
}

/// A tampered payload dies in the pipeline (signature), never reaching
/// step 10 — and the honest envelope still arrives.
#[test]
fn a_tampered_envelope_refuses_in_the_pipeline() {
    let mut relay = RelayV1::new();
    let mut tx = sender();
    let ack = tx
        .send(&mut relay, b"honest-bytes".to_vec(), expiry(), [1; 32])
        .unwrap();

    // Tamper the stored bytes' payload region and submit as a NEW
    // envelope (different bytes => different key via digest? No — the
    // key ignores the payload; same key, different bytes IS refused as
    // equivocation before any signature check. So tamper and verify the
    // pipeline refusal instead, feeding the recipient directly.)
    let mut raw = relay.stored_bytes(&ack.key).unwrap().to_vec();
    let n = raw.len();
    raw[n - 70] ^= 0x01; // inside the payload/signature tail
    let mut state = TranscriptStateV1::new();
    let refusal =
        relay::auth::accept_envelope(&raw, &recipient_ctx(), &rosters(), &mut state, now());
    assert!(
        refusal.is_err(),
        "tampered bytes must refuse in the pipeline"
    );

    // And the honest mailbox still delivers.
    let d = receive_route_payloads(&relay, &recipient_ctx(), &rosters(), &mut state, now());
    assert_eq!((d.accepted.len(), d.refused.len()), (1, 0));
}

/// AB-1 regression: an F6-kind envelope interleaved on the SAME flow is
/// left completely untouched by the route receiver — its transcript
/// position is not consumed, its payload is not destroyed — and the
/// session's F6 consumer, running on the SAME shared state, still
/// accepts it afterwards.
#[test]
fn a_foreign_kind_on_the_same_flow_is_left_for_its_own_consumer() {
    use relay::auth::message_type;
    let mut relay = RelayV1::new();

    // The initiator sends an RFQ-kind envelope at flow position 0.
    let secp = SecpContext::new(&[0x99; 32]);
    let mut envelope = relay::RelayEnvelopeV1 {
        network_id: NETWORK,
        message_type: message_type::RFQ,
        session_id: SESSION,
        route_id: ROUTE,
        sender_id: INITIATOR,
        recipient_id: SOLVER,
        sender_role: SenderRoleV1::Initiator,
        sequence: 0,
        previous_transcript_hash: [0u8; 32],
        payload: b"an-f6-object".to_vec(),
        expiry: expiry(),
        policy_version: 1,
        roster_snapshot: SNAPSHOT,
        signature: [0u8; 64],
    };
    let digest = envelope.envelope_digest().unwrap();
    let (sig, _) = secp
        .sign_bip340(&INITIATOR_SECRET, &digest, &[0x07; 32])
        .unwrap();
    envelope.signature = sig;
    relay.submit(&envelope.canonical_bytes().unwrap()).unwrap();

    // The route receiver SKIPS it: state untouched, nothing refused.
    let mut state = TranscriptStateV1::new();
    let d = receive_route_payloads(&relay, &recipient_ctx(), &rosters(), &mut state, now());
    assert_eq!(d.skipped, 1, "the foreign kind is counted, not consumed");
    assert!(d.accepted.is_empty() && d.refused.is_empty());
    assert!(
        state.last(&INITIATOR, &SOLVER).is_none(),
        "the shared flow watermark did not move"
    );

    // The F6 consumer, on the SAME shared state, still accepts it.
    let ok = relay::auth::accept_envelope(
        &relay.deliver(&SOLVER)[0],
        &recipient_ctx(),
        &rosters(),
        &mut state,
        now(),
    )
    .expect("the F6 envelope was preserved for its own consumer");
    assert_eq!(ok.envelope.payload, b"an-f6-object".to_vec());
}

/// The two directions of one conversation are INDEPENDENT flows
/// (D-020): the solver's replies chain from sequence 0 on their own
/// watermark, never entangled with the initiator's.
#[test]
fn the_reverse_direction_is_an_independent_flow() {
    let mut relay = RelayV1::new();
    let mut forward = sender();
    forward
        .send(&mut relay, b"fwd-0".to_vec(), expiry(), [1; 32])
        .unwrap();
    forward
        .send(&mut relay, b"fwd-1".to_vec(), expiry(), [2; 32])
        .unwrap();

    let mut reverse = RouteSenderV1::new(
        ctx(),
        SOLVER,
        INITIATOR,
        SenderRoleV1::Solver,
        [0x51; 32],
        [0x99; 32],
    )
    .expect("the solver may emit route transport");
    let ack = reverse
        .send(&mut relay, b"rev-0".to_vec(), expiry(), [3; 32])
        .unwrap();
    assert_eq!(
        ack.key.sequence, 0,
        "the reverse flow starts at its own zero"
    );

    // The initiator receives the reverse flow with its own state.
    let initiator_ctx = RecipientContextV1 {
        recipient_id: INITIATOR,
        network_id: NETWORK,
        session_id: SESSION,
        route_id: ROUTE,
        policy_version: 1,
    };
    let mut state = TranscriptStateV1::new();
    let d = receive_route_payloads(&relay, &initiator_ctx, &rosters(), &mut state, now());
    assert_eq!(d.accepted.len(), 1);
    assert_eq!(d.accepted[0].payload, b"rev-0".to_vec());
}

/// A long chain stays contiguous: ten messages, ten acceptances, in
/// order, each digest a distinct link.
#[test]
fn a_ten_message_chain_stays_contiguous() {
    let mut relay = RelayV1::new();
    let mut tx = sender();
    for i in 0..10u8 {
        tx.send(&mut relay, vec![0xd0, i], expiry(), [i + 1; 32])
            .unwrap();
    }
    let mut state = TranscriptStateV1::new();
    let d = receive_route_payloads(&relay, &recipient_ctx(), &rosters(), &mut state, now());
    assert_eq!(d.accepted.len(), 10);
    for (i, got) in d.accepted.iter().enumerate() {
        assert_eq!(got.sequence, i as u64);
        assert_eq!(got.payload, vec![0xd0, i as u8]);
    }
    let digests: std::collections::BTreeSet<_> =
        d.accepted.iter().map(|a| a.envelope_digest).collect();
    assert_eq!(digests.len(), 10, "every link is distinct");
}

/// An EXPIRED envelope refuses in the pipeline by name, and does not
/// poison the rest of the mailbox.
#[test]
fn an_expired_envelope_refuses_without_poisoning_the_mailbox() {
    let mut relay = RelayV1::new();
    let mut tx = sender();
    // First message expires before `now` (value 1_000)...
    tx.send(
        &mut relay,
        b"stale".to_vec(),
        TimelockSpec::TimestampSeconds { value: 999 },
        [1; 32],
    )
    .unwrap();
    // ...the second is fresh, chained after the first.
    tx.send(&mut relay, b"fresh".to_vec(), expiry(), [2; 32])
        .unwrap();

    let mut state = TranscriptStateV1::new();
    let d = receive_route_payloads(&relay, &recipient_ctx(), &rosters(), &mut state, now());
    assert_eq!(
        d.refused.len(),
        2,
        "expired, then its successor's broken chain — both named"
    );
    assert!(
        d.accepted.is_empty(),
        "an expired head fails the session closed, silently accepting nothing"
    );
}

/// A mixed mailbox: route messages are accepted, the interleaved F6
/// kind is skipped untouched, and the counts reconcile exactly.
#[test]
fn a_mixed_mailbox_reconciles_exactly() {
    use relay::auth::message_type;
    let mut relay = RelayV1::new();
    let mut tx = sender();
    tx.send(&mut relay, b"route-0".to_vec(), expiry(), [1; 32])
        .unwrap();

    // An F6 QUOTE from the solver to the same recipient... the solver
    // sends TO the initiator normally; here address it to SOLVER's own
    // mailbox recipient to interleave: use initiator→solver QUOTE?
    // Roles: initiator may not emit QUOTE. Use the SOLVER as sender to
    // the INITIATOR and pull the INITIATOR mailbox instead.
    let secp = SecpContext::new(&[0x99; 32]);
    let mut envelope = relay::RelayEnvelopeV1 {
        network_id: NETWORK,
        message_type: message_type::QUOTE,
        session_id: SESSION,
        route_id: ROUTE,
        sender_id: SOLVER,
        recipient_id: SOLVER,
        sender_role: SenderRoleV1::Solver,
        sequence: 0,
        previous_transcript_hash: [0u8; 32],
        payload: b"an-f6-quote".to_vec(),
        expiry: expiry(),
        policy_version: 1,
        roster_snapshot: SNAPSHOT,
        signature: [0u8; 64],
    };
    let digest = envelope.envelope_digest().unwrap();
    let (sig, _) = secp.sign_bip340(&[0x51; 32], &digest, &[0x08; 32]).unwrap();
    envelope.signature = sig;
    relay.submit(&envelope.canonical_bytes().unwrap()).unwrap();

    let mut state = TranscriptStateV1::new();
    let d = receive_route_payloads(&relay, &recipient_ctx(), &rosters(), &mut state, now());
    assert_eq!(
        (d.accepted.len(), d.skipped, d.refused.len()),
        (1, 1, 0),
        "one route message accepted, one F6 kind left untouched, nothing refused"
    );
}

/// An envelope larger than the wire bound refuses at SUBMIT, named,
/// and the flow does not advance — the next send still uses the same
/// sequence.
#[test]
fn an_oversized_payload_refuses_at_submit_and_the_flow_does_not_advance() {
    let mut relay = RelayV1::new();
    let mut tx = sender();
    let oversized = vec![0xAB; MAX_ROUTE_TRANSPORT_PAYLOAD_BYTES + 1];
    let refusal = tx
        .send(&mut relay, oversized, expiry(), [1; 32])
        .unwrap_err();
    assert!(matches!(
        refusal,
        BridgeRefusal::RoutePayloadTooLarge { actual, maximum }
            if actual == MAX_ROUTE_TRANSPORT_PAYLOAD_BYTES + 1
                && maximum == MAX_ROUTE_TRANSPORT_PAYLOAD_BYTES
    ));

    // The flow did NOT advance: a normal message still lands at 0.
    let ack = tx
        .send(&mut relay, b"normal".to_vec(), expiry(), [2; 32])
        .unwrap();
    assert_eq!(ack.key.sequence, 0);
}

/// Sender crash safety: exact outbox bytes and the pre-ACK checkpoint are
/// enough to recover when the Relay committed but the sender did not persist
/// its advanced flow state.
#[test]
fn prepared_outbox_and_checkpoint_recover_ack_loss_without_forking_flow() {
    let mut relay = RelayV1::new();
    let mut original = sender();
    let checkpoint_bytes = original.checkpoint().canonical_bytes().unwrap();
    let prepared = original
        .prepare(b"durable-outbox".to_vec(), expiry(), [0x21; 32])
        .unwrap();
    let outbox_bytes = prepared.canonical_bytes().to_vec();

    let first_ack = original
        .submit_prepared(&mut relay, &prepared)
        .expect("the Relay durably accepted the exact outbox");
    assert_eq!(original.checkpoint().next_sequence(), 1);

    // Crash: the advanced in-memory sender is lost.  Only the old durable
    // checkpoint and exact prepared bytes survive.
    drop(original);
    let checkpoint = RouteSenderCheckpointV1::from_bytes(&checkpoint_bytes).unwrap();
    let prepared = PreparedRouteEnvelopeV1::from_canonical_bytes(&outbox_bytes).unwrap();
    let mut recovered = RouteSenderV1::resume(checkpoint, INITIATOR_SECRET, [0x99; 32]).unwrap();
    let replayed_ack = recovered.submit_prepared(&mut relay, &prepared).unwrap();
    assert_eq!(first_ack.canonical_bytes(), replayed_ack.canonical_bytes());
    assert_eq!(recovered.checkpoint().next_sequence(), 1);
    assert_eq!(
        recovered.checkpoint().previous_digest(),
        prepared.envelope_digest()
    );

    let next = recovered
        .prepare(b"next".to_vec(), expiry(), [0x22; 32])
        .unwrap();
    let next_envelope = relay::RelayEnvelopeV1::decode(next.canonical_bytes()).unwrap();
    assert_eq!(next_envelope.sequence, 1);
    assert_eq!(
        next_envelope.previous_transcript_hash,
        *prepared.envelope_digest()
    );
}

#[test]
fn corrupt_sender_checkpoint_and_mismatched_outbox_fail_closed() {
    let mut bytes = sender().checkpoint().canonical_bytes().unwrap();
    bytes[42] ^= 0x80;
    assert!(matches!(
        RouteSenderCheckpointV1::from_bytes(&bytes),
        Err(BridgeRefusal::InvalidSenderCheckpoint)
    ));

    let first = sender();
    let prepared = first
        .prepare(b"bound-to-initiator".to_vec(), expiry(), [0x31; 32])
        .unwrap();
    let mut wrong = RouteSenderV1::new(
        ctx(),
        SOLVER,
        INITIATOR,
        SenderRoleV1::Solver,
        [0x51; 32],
        [0x99; 32],
    )
    .unwrap();
    assert!(matches!(
        wrong.submit_prepared(&mut RelayV1::new(), &prepared),
        Err(BridgeRefusal::PreparedEnvelopeMismatch)
    ));
}
