//! The D-019 mandatory suite: the CLOSED message-kind registry and the
//! canonical role→kind authorization (operator decision, 2026-08-10).
//!
//! Ratified content under test, verbatim from Foundation Document v0.19
//! §12.1, decision D-029 (which amends D-019 in one respect and states the
//! complete resulting registry and mapping in its own text):
//!
//! ```text
//! 0x0000 = INVALID/RESERVED
//! 0x0001 = RfqV1
//! 0x0002 = QuoteV1
//! 0x0003 = AcceptanceV1
//! 0x0004 = SelectionV1
//! 0x0005 = RouteTransportV1
//! 0x0006..0xffff = RESERVED/UNKNOWN in V1
//!
//! Initiator: RfqV1, AcceptanceV1, SelectionV1, RouteTransportV1
//! Solver:    QuoteV1, RouteTransportV1
//! Observer:  no type; the observer emits no messages
//! ```
//!
//! Until 2026-08-19 this block reproduced the pre-D-029 registry under the
//! label "verbatim", in the same compilation unit as a function that said
//! the opposite. Found by the independent conference of D-029.
//!
//! The tests are numbered as the decision numbers them. Tests 1-10 and
//! 12 live here (envelope and transport level); test 11 — "the consumer
//! rejects a payload whose object does not correspond to the
//! message_kind" — lives in `f6-engine`, because the ratified §6.2 rule
//! forbids the Relay from decoding payloads and `relay` therefore does
//! not depend on `rfq` at all.
//!
//! Test 12 is run under the fan-out semantics D-020 later amended into
//! §6.1, and is split into that decision's eight required proofs
//! (`t12_1`…`t12_8`, at the end of this file).

#![cfg(feature = "real-bip340")]

use btc_crypto::SecpContext;
use relay::auth::{
    accept_envelope, message_type, AuthRefusal, CanonicalMessageTypePolicyV1, RecipientContextV1,
    RosterMemberV1, RosterRegistryV1, RosterSnapshotV1, TranscriptStateV1, ValidationStep,
};
use relay::server::{IdempotencyKeyV1, RelayV1};
use relay::{ParticipantId, RelayEnvelopeV1, SenderRoleV1, TimelockSpec};

const NETWORK: [u8; 32] = [0x11; 32];
const SESSION: [u8; 32] = [0x22; 32];
const ROUTE: [u8; 32] = [0x33; 32];
const SNAPSHOT: [u8; 32] = [0x77; 32];

const INITIATOR: ParticipantId = ParticipantId([0x31; 32]);
const SOLVER: ParticipantId = ParticipantId([0x61; 32]);
const OBSERVER: ParticipantId = ParticipantId([0x71; 32]);
const RECIPIENT: ParticipantId = ParticipantId([0x41; 32]);
const STRANGER: ParticipantId = ParticipantId([0xCD; 32]);

const INITIATOR_SECRET: [u8; 32] = [0x52; 32];
const SOLVER_SECRET: [u8; 32] = [0x51; 32];
const OBSERVER_SECRET: [u8; 32] = [0x54; 32];
const STRANGER_SECRET: [u8; 32] = [0x53; 32];

/// The five kinds the closed registry defines (v0.19 §12.1, D-029).
///
/// `ROUTE_TRANSPORT` was missing here until 2026-08-19, so the one type
/// D-029 adds — the entire reason for the amendment — never crossed the
/// production pipeline in any test of this file.
const KNOWN_KINDS: [u16; 5] = [
    message_type::RFQ,
    message_type::QUOTE,
    message_type::ACCEPTANCE,
    message_type::SELECTION,
    message_type::ROUTE_TRANSPORT,
];

/// The three roles the ratified roster defines.
const ROLES: [(SenderRoleV1, ParticipantId, [u8; 32]); 3] = [
    (SenderRoleV1::Initiator, INITIATOR, INITIATOR_SECRET),
    (SenderRoleV1::Solver, SOLVER, SOLVER_SECRET),
    (SenderRoleV1::Observer, OBSERVER, OBSERVER_SECRET),
];

fn secp() -> SecpContext {
    SecpContext::new(&[0x99; 32])
}

fn xonly_of(secret: &[u8; 32]) -> [u8; 32] {
    secp()
        .sign_bip340(secret, &[0u8; 32], &[0u8; 32])
        .unwrap()
        .1
}

fn now() -> TimelockSpec {
    TimelockSpec::TimestampSeconds { value: 1_000 }
}

fn unsigned(
    sender: ParticipantId,
    role: SenderRoleV1,
    kind: u16,
    sequence: u64,
    previous: [u8; 32],
) -> RelayEnvelopeV1 {
    RelayEnvelopeV1 {
        network_id: NETWORK,
        message_type: kind,
        session_id: SESSION,
        route_id: ROUTE,
        sender_id: sender,
        recipient_id: RECIPIENT,
        sender_role: role,
        sequence,
        previous_transcript_hash: previous,
        payload: vec![0xd0, 0xd1, 0xd2],
        expiry: TimelockSpec::TimestampSeconds { value: 10_000 },
        policy_version: 1,
        roster_snapshot: SNAPSHOT,
        signature: [0u8; 64],
    }
}

fn sign(mut envelope: RelayEnvelopeV1, secret: &[u8; 32]) -> RelayEnvelopeV1 {
    let digest = envelope.envelope_digest().unwrap();
    let (sig, _) = secp().sign_bip340(secret, &digest, &[0x01; 32]).unwrap();
    envelope.signature = sig;
    envelope
}

/// The full roster: one member per ratified role.
fn rosters() -> RosterRegistryV1 {
    let mut snapshot = RosterSnapshotV1::new();
    for (role, participant, secret) in ROLES {
        snapshot = snapshot.with_member(
            participant,
            RosterMemberV1 {
                xonly_key: xonly_of(&secret),
                role,
            },
        );
    }
    RosterRegistryV1::new().with_snapshot(SNAPSHOT, snapshot)
}

fn recipient() -> RecipientContextV1 {
    RecipientContextV1 {
        recipient_id: RECIPIENT,
        network_id: NETWORK,
        session_id: SESSION,
        route_id: ROUTE,
        policy_version: 1,
    }
}

/// Runs one envelope through the PRODUCTION entry point — the one with
/// no policy parameter.
fn accept(envelope: &RelayEnvelopeV1) -> Result<[u8; 32], AuthRefusal> {
    let raw = envelope.canonical_bytes().unwrap();
    let mut state = TranscriptStateV1::new();
    accept_envelope(&raw, &recipient(), &rosters(), &mut state, now()).map(|a| a.digest)
}

/// The ratified mapping, written out independently of the
/// implementation so the test cannot agree with a bug by construction.
///
/// Transcribed from the Foundation Document v0.19 section 12.1, decision
/// D-029, "Resulting sender authorization mapping". D-029 amends D-019 in
/// one respect — it admits RouteTransportV1 for the two roles that sign
/// DSC1 rounds — and states the complete resulting mapping in its own text.
/// Values 0x0001-0x0004 and their roles are unchanged.
///
/// This function must never be derived from `crates/relay/src/auth.rs`.
/// If the normative text and this function disagree, the normative text
/// is right and the implementation is the defect — that is the entire
/// purpose of writing it out twice.
/// The numbers are written out rather than taken from `message_type::*`.
/// Those constants live in `auth.rs`, the object under judgement: with the
/// symbols, a change to `ROUTE_TRANSPORT`'s value would be followed here in
/// silence and nothing would notice. D-029 states numbers, so this states
/// numbers.
///
/// The unknown range is decided here too, for the same reason. The sweep at
/// the end of this file used to and the expected side with
/// `message_type::is_known(kind)`, which the implementation also consults
/// first — so it cancelled, and 196,593 of the 196,608 cells passed by
/// construction. Found by the independent conference of D-029.
fn ratified_permits(role: SenderRoleV1, kind: u16) -> bool {
    // D-029 §12.1: 0x0001 RfqV1, 0x0002 QuoteV1, 0x0003 AcceptanceV1,
    // 0x0004 SelectionV1, 0x0005 RouteTransportV1;
    // 0x0000 and 0x0006..=0xffff RESERVED/UNKNOWN in V1.
    match role {
        // D-029: Initiator: RfqV1, AcceptanceV1, SelectionV1, RouteTransportV1
        SenderRoleV1::Initiator => matches!(kind, 0x0001 | 0x0003 | 0x0004 | 0x0005),
        // D-029: Solver:    QuoteV1, RouteTransportV1
        SenderRoleV1::Solver => matches!(kind, 0x0002 | 0x0005),
        // D-029: Observer:  no type; the observer emits no messages
        SenderRoleV1::Observer => false,
    }
}

/// **D-019 test 1**, as amended by D-029 — the complete matrix: 3 roles ×
/// 5 kinds, every cell exercised end to end against the production pipeline
/// with a real BIP340 signature. Six cells are accepted; nine are refused as
/// `RoleNotPermitted` at step 6, and at no other step.
#[test]
fn t01_the_full_three_roles_by_five_kinds_matrix() {
    let mut accepted = 0usize;
    let mut refused = 0usize;
    for (role, participant, secret) in ROLES {
        for kind in KNOWN_KINDS {
            let envelope = sign(unsigned(participant, role, kind, 0, [0u8; 32]), &secret);
            let outcome = accept(&envelope);
            if ratified_permits(role, kind) {
                assert!(
                    outcome.is_ok(),
                    "the ratified mapping permits {role:?}/{kind:#06x}, the pipeline refused it: {outcome:?}"
                );
                accepted += 1;
            } else {
                let refusal = outcome.expect_err("the ratified mapping forbids this cell");
                assert_eq!(
                    refusal,
                    AuthRefusal::RoleNotPermitted,
                    "{role:?}/{kind:#06x}"
                );
                assert_eq!(refusal.step(), ValidationStep::RolePermission);
                refused += 1;
            }
        }
    }
    assert_eq!(accepted, 6, "the ratified mapping has exactly six cells");
    assert_eq!(refused, 9);
}

/// **D-019 test 2** — the observer is refused for EVERY kind. The
/// evidence role is strictly non-emitting (Annex M §M.9.1), and a valid
/// signature and a perfect sequence do not change that.
#[test]
fn t02_the_observer_is_refused_for_every_kind() {
    for kind in KNOWN_KINDS {
        let envelope = sign(
            unsigned(OBSERVER, SenderRoleV1::Observer, kind, 0, [0u8; 32]),
            &OBSERVER_SECRET,
        );
        assert_eq!(
            accept(&envelope).unwrap_err(),
            AuthRefusal::RoleNotPermitted,
            "the observer emitted {kind:#06x}"
        );
    }
}

/// **D-019 test 3** — the initiator may not quote. Quoting is the
/// solver's act; an initiator that quotes for itself would be a
/// privileged path (I12).
#[test]
fn t03_the_initiator_is_refused_for_quote() {
    let envelope = sign(
        unsigned(
            INITIATOR,
            SenderRoleV1::Initiator,
            message_type::QUOTE,
            0,
            [0u8; 32],
        ),
        &INITIATOR_SECRET,
    );
    assert_eq!(
        accept(&envelope).unwrap_err(),
        AuthRefusal::RoleNotPermitted
    );
}

/// **D-019 test 4** — the solver may not request, accept or adjudicate.
/// Selection and acceptance are the initiator's; a solver that could
/// emit either would be selecting itself.
#[test]
fn t04_the_solver_is_refused_for_rfq_acceptance_and_selection() {
    for kind in [
        message_type::RFQ,
        message_type::ACCEPTANCE,
        message_type::SELECTION,
    ] {
        let envelope = sign(
            unsigned(SOLVER, SenderRoleV1::Solver, kind, 0, [0u8; 32]),
            &SOLVER_SECRET,
        );
        assert_eq!(
            accept(&envelope).unwrap_err(),
            AuthRefusal::RoleNotPermitted,
            "the solver emitted {kind:#06x}"
        );
    }
}

/// **D-019 test 5** — the registry is CLOSED: `0x0000` (invalid),
/// `0x0006` (the first reserved value since the 2026-08-19 amendment
/// ratified `ROUTE_TRANSPORT = 0x0005` into the registry) and `0xffff`
/// (the last) are refused for every role. An unknown kind fails closed;
/// it is never accepted by default and never inferred into meaning.
#[test]
fn t05_invalid_and_reserved_kinds_are_refused_for_every_role() {
    for kind in [message_type::INVALID, 0x0006, 0xffff] {
        assert!(!message_type::is_known(kind), "{kind:#06x} must be unknown");
        for (role, participant, secret) in ROLES {
            let envelope = sign(unsigned(participant, role, kind, 0, [0u8; 32]), &secret);
            assert_eq!(
                accept(&envelope).unwrap_err(),
                AuthRefusal::RoleNotPermitted,
                "{role:?} emitted the unknown kind {kind:#06x}"
            );
        }
    }
    // And the registry's own predicate agrees over the WHOLE 16-bit
    // space: exactly five values are known — the original four plus
    // ROUTE_TRANSPORT, ratified 2026-08-19.
    let known = (0..=u16::MAX)
        .filter(|k| message_type::is_known(*k))
        .count();
    assert_eq!(known, 5, "the V1 registry is closed at five kinds");
}

/// **D-019 test 6** — role spoofing, in both directions it can be
/// attempted:
///
/// (a) a roster member claims a role that is not its own — refused at
///     step 6 by the ROSTER's record, never by the envelope's claim;
/// (b) an envelope claiming the right role is signed by an incompatible
///     key — refused at step 7, because the role can only be claimed by
///     whoever holds the roster key bound to it.
#[test]
fn t06_role_spoofing_with_an_incompatible_key_is_refused() {
    // (a) The solver claims the initiator role to emit a Selection.
    let mut spoofed = unsigned(
        SOLVER,
        SenderRoleV1::Initiator,
        message_type::SELECTION,
        0,
        [0u8; 32],
    );
    spoofed.sender_role = SenderRoleV1::Initiator;
    let spoofed = sign(spoofed, &SOLVER_SECRET);
    let refusal = accept(&spoofed).unwrap_err();
    assert_eq!(refusal, AuthRefusal::RoleMismatch);
    assert_eq!(refusal.step(), ValidationStep::RolePermission);

    // (b) An envelope that is correct in every header field — the
    // initiator's id, the initiator's role, a kind the initiator may
    // send — but signed with the SOLVER's key.
    let wrong_key = sign(
        unsigned(
            INITIATOR,
            SenderRoleV1::Initiator,
            message_type::SELECTION,
            0,
            [0u8; 32],
        ),
        &SOLVER_SECRET,
    );
    let refusal = accept(&wrong_key).unwrap_err();
    assert_eq!(refusal, AuthRefusal::InvalidSignature);
    assert_eq!(refusal.step(), ValidationStep::Signature);
}

/// **D-019 test 7** — a sender absent from the roster snapshot is
/// refused at step 5, before the policy is consulted and before its
/// signature is examined. It may hold a perfectly valid signature under
/// its own key; membership is what it lacks, and membership comes
/// first.
#[test]
fn t07_a_sender_absent_from_the_roster_is_refused() {
    for kind in KNOWN_KINDS {
        for role in [
            SenderRoleV1::Initiator,
            SenderRoleV1::Solver,
            SenderRoleV1::Observer,
        ] {
            let envelope = sign(
                unsigned(STRANGER, role, kind, 0, [0u8; 32]),
                &STRANGER_SECRET,
            );
            let refusal = accept(&envelope).unwrap_err();
            assert_eq!(refusal, AuthRefusal::SenderNotInRoster);
            assert_eq!(refusal.step(), ValidationStep::RosterMembership);
        }
    }
}

/// **D-019 test 8** — the production entry point enforces the canonical
/// policy. The implementation seam and policy trait are private to the
/// crate, so an external composition root cannot inject an alternative.
#[test]
fn t08_an_alternative_policy_cannot_reach_the_production_path() {
    // The observer emitting a RESERVED kind: forbidden twice over.
    let envelope = sign(
        unsigned(OBSERVER, SenderRoleV1::Observer, 0xffff, 0, [0u8; 32]),
        &OBSERVER_SECRET,
    );
    let raw = envelope.canonical_bytes().unwrap();

    // The production entry point refuses the very same bytes, and no
    // caller can hand it anything else.
    let mut state = TranscriptStateV1::new();
    assert_eq!(
        accept_envelope(&raw, &recipient(), &rosters(), &mut state, now()).unwrap_err(),
        AuthRefusal::RoleNotPermitted
    );

    // The canonical policy agrees with the ratified mapping over the
    // whole space it governs, exhaustively.
    for (role, _, _) in ROLES {
        for kind in 0..=u16::MAX {
            assert_eq!(
                CanonicalMessageTypePolicyV1.permits(role, kind),
                ratified_permits(role, kind),
                "{role:?}/{kind:#06x}"
            );
        }
    }
}

/// **D-019 test 9** — changing `message_kind` AFTER signing invalidates
/// authentication. The kind is inside the ratified digest (§5.2), so it
/// is not editable in flight.
///
/// The mutation is deliberately RFQ→Acceptance: both are kinds the
/// initiator may emit, so step 6 passes and the refusal is step 7's.
/// A mutation to a forbidden kind would have been caught one step
/// earlier and would have proved nothing about the digest.
#[test]
fn t09_altering_the_message_kind_after_signing_breaks_authentication() {
    let signed = sign(
        unsigned(
            INITIATOR,
            SenderRoleV1::Initiator,
            message_type::RFQ,
            0,
            [0u8; 32],
        ),
        &INITIATOR_SECRET,
    );
    assert!(accept(&signed).is_ok(), "the baseline must be accepted");

    let mut altered = signed;
    altered.message_type = message_type::ACCEPTANCE;
    let refusal = accept(&altered).unwrap_err();
    assert_eq!(refusal, AuthRefusal::InvalidSignature);
    assert_eq!(
        refusal.step(),
        ValidationStep::Signature,
        "the kind change must break the SIGNATURE, not an earlier check"
    );
}

/// **D-019 test 10** — a payload that decodes as nothing is still
/// routed, as long as the header is valid. This is the §6.2 rule stated
/// as an observable fact: the Relay's decision is a function of the
/// header alone, so payload bytes that no decoder in the workspace can
/// interpret travel exactly like well-formed ones.
///
/// The complementary half — the CONSUMER refusing that payload — is
/// D-019 test 11, in `f6-engine`.
#[test]
fn t10_an_undecodable_payload_is_still_routed_when_the_header_is_valid() {
    // Bytes chosen to be invalid under every F6 object codec: they
    // carry no frozen magic, and no length that any of them accepts.
    let garbage: Vec<u8> = (0..=255u8).chain(0..=255u8).map(|b| b ^ 0x5a).collect();
    let mut envelope = unsigned(
        SOLVER,
        SenderRoleV1::Solver,
        message_type::QUOTE,
        0,
        [0u8; 32],
    );
    envelope.payload = garbage.clone();
    let envelope = sign(envelope, &SOLVER_SECRET);
    let raw = envelope.canonical_bytes().unwrap();

    let mut relay = RelayV1::new();
    relay.submit(&raw).expect("a valid header routes");
    assert_eq!(
        relay.deliver(&RECIPIENT),
        vec![raw.clone()],
        "the Relay withheld a payload it could not interpret"
    );

    // And the §5.4 pipeline — which authenticates the header and does
    // NOT interpret the payload either — accepts it and hands the bytes
    // through untouched. Judging them is the consumer's job (test 11).
    let mut state = TranscriptStateV1::new();
    let accepted =
        accept_envelope(&raw, &recipient(), &rosters(), &mut state, now()).expect("accepted");
    assert_eq!(accepted.envelope.payload, garbage);
}

// ---------------------------------------------------------------------
// D-019 test 12, under the fan-out semantics AMENDED by D-020 (operator
// decision, 2026-08-10).
//
// D-020 defines the sequence domain as the ADDRESSED FLOW
//
//     sequence_domain = (session_scope, sender_id, recipient_id)
//
// and makes the §6.1 idempotency key distinguish the recipient
//
//     (session_scope, sender_id, recipient_id, sequence)
//
// with no wire change: `recipient_id` was already a ratified header
// field of D-018's envelope. Within each domain the sequence starts at
// 0, grows contiguously, chains through `previous_transcript_hash`, and
// gaps stay forbidden. Across domains there is no required total order.
//
// The eight proofs the decision mandates are the eight tests below.
// ---------------------------------------------------------------------

/// Two fan-out recipients.
const FAN_A: ParticipantId = ParticipantId([0xA1; 32]);
const FAN_B: ParticipantId = ParticipantId([0xA2; 32]);

/// An envelope from the solver to `target`, at `sequence` in THAT
/// addressed flow.
fn to(target: ParticipantId, sequence: u64, previous: [u8; 32]) -> RelayEnvelopeV1 {
    let mut envelope = unsigned(
        SOLVER,
        SenderRoleV1::Solver,
        message_type::QUOTE,
        sequence,
        previous,
    );
    envelope.recipient_id = target;
    // Distinct payloads per flow, so two envelopes are never accidentally
    // byte-identical and a "no collision" result cannot be an artefact of
    // them being the same message.
    envelope.payload = vec![target.0[0], sequence as u8];
    sign(envelope, &SOLVER_SECRET)
}

/// The pipeline as run by `target` itself: its own recipient context,
/// its own transcript state.
fn accept_at(
    target: ParticipantId,
    envelope: &RelayEnvelopeV1,
    state: &mut TranscriptStateV1,
) -> Result<[u8; 32], AuthRefusal> {
    let ctx = RecipientContextV1 {
        recipient_id: target,
        network_id: NETWORK,
        session_id: SESSION,
        route_id: ROUTE,
        policy_version: 1,
    };
    let raw = envelope.canonical_bytes().unwrap();
    accept_envelope(&raw, &ctx, &rosters(), state, now()).map(|a| a.digest)
}

/// **D-020 proof 1** — two distinct recipients each accept
/// `sequence = 0` from the same sender. Under the pre-amendment reading
/// one of them would have had to be a duplicate or an equivocation;
/// under D-020 they are two independent flows, and both are simply
/// correct first messages.
#[test]
fn t12_1_two_recipients_both_accept_sequence_zero() {
    let mut state_a = TranscriptStateV1::new();
    let mut state_b = TranscriptStateV1::new();

    let digest_a = accept_at(FAN_A, &to(FAN_A, 0, [0u8; 32]), &mut state_a)
        .expect("recipient A's flow opens at 0");
    let digest_b = accept_at(FAN_B, &to(FAN_B, 0, [0u8; 32]), &mut state_b)
        .expect("recipient B's flow opens at 0");

    assert_ne!(digest_a, digest_b, "the two legs must be distinct messages");
    assert_eq!(state_a.last(&SOLVER, &FAN_A), Some((0, digest_a)));
    assert_eq!(state_b.last(&SOLVER, &FAN_B), Some((0, digest_b)));

    // And the flows stay separate even inside ONE state object — the
    // case a process hosting both participants would hit.
    let mut shared = TranscriptStateV1::new();
    accept_at(FAN_A, &to(FAN_A, 0, [0u8; 32]), &mut shared).expect("flow A in the shared state");
    accept_at(FAN_B, &to(FAN_B, 0, [0u8; 32]), &mut shared).expect("flow B in the shared state");
    assert_eq!(shared.last(&SOLVER, &FAN_A), Some((0, digest_a)));
    assert_eq!(shared.last(&SOLVER, &FAN_B), Some((0, digest_b)));
}

/// **D-020 proof 2** — the idempotency keys of the two legs differ, and
/// they differ IN `recipient_id`: every other component is equal, so
/// the recipient is doing the distinguishing and nothing else is.
#[test]
fn t12_2_idempotency_keys_are_distinguished_by_recipient() {
    let a = to(FAN_A, 0, [0u8; 32]);
    let b = to(FAN_B, 0, [0u8; 32]);
    let key_a = IdempotencyKeyV1::of(&a);
    let key_b = IdempotencyKeyV1::of(&b);

    assert_ne!(key_a, key_b);
    assert_eq!(key_a.session_id, key_b.session_id);
    assert_eq!(key_a.sender_id, key_b.sender_id);
    assert_eq!(key_a.sequence, key_b.sequence);
    assert_ne!(key_a.recipient_id, key_b.recipient_id);

    // The Relay stores them as two entries, one per mailbox.
    let mut relay = RelayV1::new();
    relay.submit(&a.canonical_bytes().unwrap()).unwrap();
    relay.submit(&b.canonical_bytes().unwrap()).unwrap();
    assert_eq!(relay.len(), 2);
    assert_eq!(relay.deliver(&FAN_A), vec![a.canonical_bytes().unwrap()]);
    assert_eq!(relay.deliver(&FAN_B), vec![b.canonical_bytes().unwrap()]);
}

/// **D-020 proof 3** — each recipient then accepts its OWN
/// `sequence = 1`, chaining to its own `sequence = 0`. Each flow is a
/// contiguous chain in its own right.
#[test]
fn t12_3_each_recipient_continues_its_own_chain() {
    let mut state_a = TranscriptStateV1::new();
    let mut state_b = TranscriptStateV1::new();

    let a0 = accept_at(FAN_A, &to(FAN_A, 0, [0u8; 32]), &mut state_a).unwrap();
    let b0 = accept_at(FAN_B, &to(FAN_B, 0, [0u8; 32]), &mut state_b).unwrap();

    let a1 = accept_at(FAN_A, &to(FAN_A, 1, a0), &mut state_a).expect("A continues at 1");
    let b1 = accept_at(FAN_B, &to(FAN_B, 1, b0), &mut state_b).expect("B continues at 1");

    assert_eq!(state_a.last(&SOLVER, &FAN_A), Some((1, a1)));
    assert_eq!(state_b.last(&SOLVER, &FAN_B), Some((1, b1)));
}

/// **D-020 proof 4** — fan-out opens no gap. A sender that sends many
/// messages to OTHER participants between two of this recipient's own
/// messages does not make this recipient's next sequence a gap: those
/// messages are not in this flow at all.
///
/// The refusal of real gaps is asserted in the same test, so proof 4 is
/// never mistaken for a relaxation: a genuine skip WITHIN the flow is
/// still `SequenceGap`.
#[test]
fn t12_4_fan_out_to_others_opens_no_gap_but_real_gaps_still_refuse() {
    let mut relay = RelayV1::new();
    let mut state_a = TranscriptStateV1::new();

    // A's flow opens.
    let a0_envelope = to(FAN_A, 0, [0u8; 32]);
    relay
        .submit(&a0_envelope.canonical_bytes().unwrap())
        .unwrap();
    let a0 = accept_at(FAN_A, &a0_envelope, &mut state_a).unwrap();

    // The sender now fans out heavily to B and to the original
    // RECIPIENT — twelve messages A never sees.
    let mut previous_b = [0u8; 32];
    let mut previous_r = [0u8; 32];
    for sequence in 0..6u64 {
        let b = to(FAN_B, sequence, previous_b);
        previous_b = b.envelope_digest().unwrap();
        relay.submit(&b.canonical_bytes().unwrap()).unwrap();

        let r = to(RECIPIENT, sequence, previous_r);
        previous_r = r.envelope_digest().unwrap();
        relay.submit(&r.canonical_bytes().unwrap()).unwrap();
    }

    // A's next message is its own sequence 1 — not 13.
    let a1_envelope = to(FAN_A, 1, a0);
    relay
        .submit(&a1_envelope.canonical_bytes().unwrap())
        .unwrap();
    let a1 = accept_at(FAN_A, &a1_envelope, &mut state_a)
        .expect("traffic addressed elsewhere must not gap this flow");
    assert_eq!(state_a.last(&SOLVER, &FAN_A), Some((1, a1)));

    // A's mailbox holds exactly its two messages.
    assert_eq!(relay.deliver(&FAN_A).len(), 2);

    // A REAL gap inside the flow is still refused by name — D-020
    // amended what a flow is, not whether gaps are tolerated.
    let skipped = to(FAN_A, 3, a1);
    let refusal = accept_at(FAN_A, &skipped, &mut state_a).unwrap_err();
    assert_eq!(refusal, AuthRefusal::SequenceGap);
    assert_eq!(refusal.step(), ValidationStep::ReplayGapEquivocation);

    // And a flow still cannot be joined in the middle.
    let mut fresh = TranscriptStateV1::new();
    assert_eq!(
        accept_at(FAN_B, &to(FAN_B, 4, [0u8; 32]), &mut fresh).unwrap_err(),
        AuthRefusal::SequenceGap
    );
}

/// **D-020 proof 5** — a byte-identical retransmission still produces
/// the SAME ACK, byte for byte (§6.1, I7). The amended key did not
/// weaken idempotency; it only made the key name the flow correctly.
#[test]
fn t12_5_a_retransmitted_leg_gets_the_identical_ack() {
    let envelope = to(FAN_A, 0, [0u8; 32]);
    let raw = envelope.canonical_bytes().unwrap();
    let mut relay = RelayV1::new();

    let first = relay.submit(&raw).expect("first submission");
    let second = relay.submit(&raw).expect("resend");
    assert_eq!(first, second, "the resend ACK is not byte-identical");
    assert_eq!(relay.len(), 1, "a resend created a second entry");
    assert_eq!(relay.stored_bytes(&first.key), Some(raw.as_slice()));

    // At the recipient, the redelivery is the named duplicate, and the
    // watermark does not move.
    let mut state = TranscriptStateV1::new();
    let digest = accept_at(FAN_A, &envelope, &mut state).unwrap();
    assert_eq!(
        accept_at(FAN_A, &envelope, &mut state).unwrap_err(),
        AuthRefusal::Duplicate
    );
    assert_eq!(state.last(&SOLVER, &FAN_A), Some((0, digest)));
}

/// **D-020 proof 6** — different bytes at the SAME key are still
/// equivocation, and the proof still stands on the sender's own two
/// signatures. This is the case the amendment must not have dissolved:
/// same session, same sender, same recipient, same sequence.
#[test]
fn t12_6_different_bytes_at_one_key_are_still_equivocation() {
    let first = to(FAN_A, 0, [0u8; 32]);
    let mut conflicting = unsigned(
        SOLVER,
        SenderRoleV1::Solver,
        message_type::QUOTE,
        0,
        [0u8; 32],
    );
    conflicting.recipient_id = FAN_A;
    conflicting.payload = vec![0xff, 0xfe];
    let conflicting = sign(conflicting, &SOLVER_SECRET);
    assert_eq!(
        IdempotencyKeyV1::of(&first),
        IdempotencyKeyV1::of(&conflicting),
        "both must claim ONE key for this to be the equivocation case"
    );

    let mut relay = RelayV1::new();
    relay.submit(&first.canonical_bytes().unwrap()).unwrap();
    let refusal = relay
        .submit(&conflicting.canonical_bytes().unwrap())
        .expect_err("conflicting bytes at one key must fail closed");
    let relay::server::RelayRefusal::Equivocation(proof) = refusal else {
        panic!("expected the named equivocation refusal, got {refusal:?}");
    };
    relay::server::verify_equivocation(&proof, &rosters())
        .expect("the proof must stand without the Relay");

    // The Relay did not adopt the conflicting bytes.
    assert_eq!(
        relay.stored_bytes(&proof.key),
        Some(first.canonical_bytes().unwrap().as_slice())
    );

    // The recipient's pipeline names it too.
    let mut state = TranscriptStateV1::new();
    accept_at(FAN_A, &first, &mut state).unwrap();
    assert_eq!(
        accept_at(FAN_A, &conflicting, &mut state).unwrap_err(),
        AuthRefusal::Equivocation
    );
}

/// **D-020 proof 7** — the same sequence at DIFFERENT recipients is not
/// a collision. The Relay stores both, neither refuses, and no
/// equivocation is raised: the thing that would have made this a
/// conflict before the amendment is exactly the recipient the key now
/// carries.
#[test]
fn t12_7_the_same_sequence_at_different_recipients_does_not_collide() {
    let targets = [FAN_A, FAN_B, RECIPIENT, ParticipantId([0xA3; 32])];
    let mut relay = RelayV1::new();
    let mut keys = Vec::new();

    for sequence in 0..3u64 {
        for target in targets {
            // Every leg at the SAME sequence across all four recipients.
            let previous = if sequence == 0 {
                [0u8; 32]
            } else {
                to(target, sequence - 1, [0u8; 32])
                    .envelope_digest()
                    .unwrap()
            };
            let envelope = to(target, sequence, previous);
            let ack = relay
                .submit(&envelope.canonical_bytes().unwrap())
                .expect("a same-sequence leg to another recipient is not a collision");
            keys.push(ack.key);
        }
    }

    let stored = keys.len();
    keys.sort();
    keys.dedup();
    assert_eq!(keys.len(), stored, "two legs shared one key");
    assert_eq!(relay.len(), stored);
    for target in targets {
        assert_eq!(relay.deliver(&target).len(), 3);
    }
}

/// **D-020 proof 8** — `previous_transcript_hash` chains only within
/// one domain. An envelope to B that chains to A's digest is refused at
/// step 9: there is no total order across recipients to chain to, so
/// borrowing another flow's digest is a broken chain, not a shortcut.
#[test]
fn t12_8_the_transcript_chains_only_within_one_domain() {
    let mut state_a = TranscriptStateV1::new();
    let mut state_b = TranscriptStateV1::new();

    let a0 = accept_at(FAN_A, &to(FAN_A, 0, [0u8; 32]), &mut state_a).unwrap();
    let b0 = accept_at(FAN_B, &to(FAN_B, 0, [0u8; 32]), &mut state_b).unwrap();
    assert_ne!(a0, b0);

    // B's sequence 1 chaining to A's digest.
    let cross = to(FAN_B, 1, a0);
    let refusal = accept_at(FAN_B, &cross, &mut state_b).unwrap_err();
    assert_eq!(refusal, AuthRefusal::TranscriptDiscontinuity);
    assert_eq!(refusal.step(), ValidationStep::TranscriptContinuity);

    // A's sequence 1 chaining to B's digest, symmetrically.
    assert_eq!(
        accept_at(FAN_A, &to(FAN_A, 1, b0), &mut state_a).unwrap_err(),
        AuthRefusal::TranscriptDiscontinuity
    );

    // A first envelope of a flow chains to the canonical initial value
    // and to nothing else — another flow's digest does not open one.
    let mut fresh = TranscriptStateV1::new();
    assert_eq!(
        accept_at(RECIPIENT, &to(RECIPIENT, 0, a0), &mut fresh).unwrap_err(),
        AuthRefusal::TranscriptDiscontinuity
    );

    // Each flow's own chain still works after every cross attempt.
    let a1 = accept_at(FAN_A, &to(FAN_A, 1, a0), &mut state_a).expect("A's own chain");
    let b1 = accept_at(FAN_B, &to(FAN_B, 1, b0), &mut state_b).expect("B's own chain");
    assert_eq!(state_a.last(&SOLVER, &FAN_A), Some((1, a1)));
    assert_eq!(state_b.last(&SOLVER, &FAN_B), Some((1, b1)));
}
