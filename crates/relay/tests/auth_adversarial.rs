//! The A10 adversarial suite (F6 spec v1.0.1 §5, ratified by D-018).
//!
//! The ratified threat model, exercised against the REAL pipeline with
//! REAL BIP340 signatures from the pinned D-013 backend: the Relay is
//! untrusted transport — it may delay, repeat, reorder, omit,
//! misdeliver and attempt byte substitution — and it MUST NOT be able
//! to produce an envelope accepted as coming from an honest
//! participant.
//!
//! Every test below is one adversary move. Each asserts the move is
//! refused BY NAME and AT THE RATIFIED STEP, because "refused" alone
//! would not prove the §5.4 order: a recipient that checked the
//! signature before the roster, or the payload before the sequence,
//! would still refuse — and would still be wrong.

#![cfg(feature = "real-bip340")]

use btc_crypto::SecpContext;
use relay::auth::{
    accept_envelope, message_type, AuthRefusal, RecipientContextV1, RosterMemberV1,
    RosterRegistryV1, RosterSnapshotV1, TranscriptStateV1, ValidationStep,
};
use relay::{ParticipantId, RelayEnvelopeV1, SenderRoleV1, TimelockSpec, MAX_PAYLOAD_BYTES};

const NETWORK: [u8; 32] = [0x11; 32];
const SESSION: [u8; 32] = [0x22; 32];
const ROUTE: [u8; 32] = [0x33; 32];
const SNAPSHOT: [u8; 32] = [0x77; 32];
const SOLVER_SECRET: [u8; 32] = [0x51; 32];
const INITIATOR_SECRET: [u8; 32] = [0x52; 32];
const IMPOSTOR_SECRET: [u8; 32] = [0x53; 32];
const SOLVER: ParticipantId = ParticipantId([0x61; 32]);
const INITIATOR: ParticipantId = ParticipantId([0x31; 32]);

fn ctx() -> SecpContext {
    SecpContext::new(&[0x99; 32])
}

fn xonly_of(secret: &[u8; 32]) -> [u8; 32] {
    // Signing a throwaway message is the cheapest way to obtain the
    // x-only key from the SAME authority that will verify.
    ctx().sign_bip340(secret, &[0u8; 32], &[0u8; 32]).unwrap().1
}

fn now() -> TimelockSpec {
    TimelockSpec::TimestampSeconds { value: 1_000 }
}

/// An unsigned envelope from the solver, at `sequence`, chaining to
/// `previous`.
fn unsigned(sequence: u64, previous: [u8; 32]) -> RelayEnvelopeV1 {
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
        payload: vec![0xd0, 0xd1, 0xd2],
        expiry: TimelockSpec::TimestampSeconds { value: 10_000 },
        policy_version: 1,
        roster_snapshot: SNAPSHOT,
        signature: [0u8; 64],
    }
}

/// Signs an envelope with `secret` over the RATIFIED digest.
fn sign(mut envelope: RelayEnvelopeV1, secret: &[u8; 32]) -> RelayEnvelopeV1 {
    let digest = envelope.envelope_digest().unwrap();
    let (sig, _) = ctx().sign_bip340(secret, &digest, &[0x01; 32]).unwrap();
    envelope.signature = sig;
    envelope
}

fn rosters() -> RosterRegistryV1 {
    let snapshot = RosterSnapshotV1::new()
        .with_member(
            SOLVER,
            RosterMemberV1 {
                xonly_key: xonly_of(&SOLVER_SECRET),
                role: SenderRoleV1::Solver,
            },
        )
        .with_member(
            INITIATOR,
            RosterMemberV1 {
                xonly_key: xonly_of(&INITIATOR_SECRET),
                role: SenderRoleV1::Initiator,
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

fn accept(
    envelope: &RelayEnvelopeV1,
    state: &mut TranscriptStateV1,
) -> Result<[u8; 32], AuthRefusal> {
    let raw = envelope.canonical_bytes().unwrap();
    accept_envelope(&raw, &recipient(), &rosters(), state, now()).map(|a| a.digest)
}

/// The honest baseline: a correctly signed, correctly sequenced
/// envelope is accepted, and the returned digest is what the next one
/// must chain to. Without this, every refusal below could be vacuous.
#[test]
fn an_honest_envelope_is_accepted_and_extends_the_transcript() {
    let mut state = TranscriptStateV1::new();
    let first = sign(unsigned(0, [0u8; 32]), &SOLVER_SECRET);
    let digest = accept(&first, &mut state).expect("honest envelope");
    assert_eq!(state.last(&SOLVER, &INITIATOR), Some((0, digest)));

    let second = sign(unsigned(1, digest), &SOLVER_SECRET);
    let second_digest = accept(&second, &mut state).expect("honest successor");
    assert_eq!(state.last(&SOLVER, &INITIATOR), Some((1, second_digest)));
}

/// BYTE SUBSTITUTION: the Relay flips any byte of a signed envelope.
/// Every single-byte change either breaks the codec or breaks the
/// signature — the digest covers the complete canonical unsigned
/// envelope, so nothing in it can be edited in flight.
#[test]
fn no_single_byte_substitution_is_ever_accepted() {
    let envelope = sign(unsigned(0, [0u8; 32]), &SOLVER_SECRET);
    let raw = envelope.canonical_bytes().unwrap();
    let mut accepted = 0usize;
    for index in 0..raw.len() {
        let mut tampered = raw.clone();
        tampered[index] ^= 0x01;
        let mut state = TranscriptStateV1::new();
        let outcome = accept_envelope(&tampered, &recipient(), &rosters(), &mut state, now());
        if outcome.is_ok() {
            accepted += 1;
        }
    }
    assert_eq!(accepted, 0, "a substituted byte was accepted");
}

/// MISDELIVERY: an envelope addressed to somebody else is refused at
/// step 4 — before the roster is consulted and before any signature
/// work, so a misdelivered message cannot even probe the recipient's
/// verification.
#[test]
fn a_misdelivered_envelope_is_refused_at_step_four() {
    let mut envelope = unsigned(0, [0u8; 32]);
    envelope.recipient_id = ParticipantId([0xAB; 32]);
    let envelope = sign(envelope, &SOLVER_SECRET);
    let mut state = TranscriptStateV1::new();
    let refusal = accept(&envelope, &mut state).unwrap_err();
    assert_eq!(refusal, AuthRefusal::WrongRecipient);
    assert_eq!(
        refusal.step(),
        ValidationStep::NetworkRecipientSessionExpiry
    );
    assert_eq!(
        state.last(&SOLVER, &INITIATOR),
        None,
        "a refusal moved the watermark"
    );
}

/// Wrong network, session and route are the same step-4 family: an
/// envelope from another context is never somebody's message here.
#[test]
fn foreign_network_session_and_route_are_refused_at_step_four() {
    for (mutate, expected) in [
        (
            (|e: &mut RelayEnvelopeV1| e.network_id = [0xEE; 32]) as fn(&mut RelayEnvelopeV1),
            AuthRefusal::WrongNetwork,
        ),
        (|e| e.session_id = [0xEE; 32], AuthRefusal::WrongSession),
        (|e| e.route_id = [0xEE; 32], AuthRefusal::WrongRoute),
    ] {
        let mut envelope = unsigned(0, [0u8; 32]);
        mutate(&mut envelope);
        let envelope = sign(envelope, &SOLVER_SECRET);
        let mut state = TranscriptStateV1::new();
        let refusal = accept(&envelope, &mut state).unwrap_err();
        assert_eq!(refusal, expected);
        assert_eq!(
            refusal.step(),
            ValidationStep::NetworkRecipientSessionExpiry
        );
    }
}

/// EXPIRY, and the A4 domain rule: an expired envelope is refused, and
/// an expiry in another timelock domain is refused rather than
/// converted.
#[test]
fn expiry_is_enforced_and_domains_are_never_converted() {
    let mut expired = unsigned(0, [0u8; 32]);
    expired.expiry = TimelockSpec::TimestampSeconds { value: 999 };
    let expired = sign(expired, &SOLVER_SECRET);
    let mut state = TranscriptStateV1::new();
    assert_eq!(
        accept(&expired, &mut state).unwrap_err(),
        AuthRefusal::Expired
    );

    let mut cross = unsigned(0, [0u8; 32]);
    cross.expiry = TimelockSpec::BlockHeight { value: 10_000 };
    let cross = sign(cross, &SOLVER_SECRET);
    assert_eq!(
        accept(&cross, &mut state).unwrap_err(),
        AuthRefusal::WrongTimelockDomain
    );
}

/// STALE ROSTER SNAPSHOT: an envelope naming a snapshot this recipient
/// does not recognise is refused — the ratified A10 binding is what
/// keeps a later key rotation from making historical validity
/// ambiguous, and an unknown snapshot is exactly the ambiguous case.
#[test]
fn an_unknown_roster_snapshot_is_refused_at_step_five() {
    let mut envelope = unsigned(0, [0u8; 32]);
    envelope.roster_snapshot = [0xBB; 32];
    let envelope = sign(envelope, &SOLVER_SECRET);
    let mut state = TranscriptStateV1::new();
    let refusal = accept(&envelope, &mut state).unwrap_err();
    assert_eq!(refusal, AuthRefusal::UnknownRosterSnapshot);
    assert_eq!(refusal.step(), ValidationStep::RosterMembership);
}

/// IMPOSTOR: a perfectly formed envelope from a participant who is not
/// in the snapshot — refused at step 5, before its signature is even
/// examined (it might well be a valid signature under ITS own key).
#[test]
fn a_non_member_is_refused_before_its_signature_is_examined() {
    let mut envelope = unsigned(0, [0u8; 32]);
    envelope.sender_id = ParticipantId([0xCD; 32]);
    let envelope = sign(envelope, &IMPOSTOR_SECRET);
    let mut state = TranscriptStateV1::new();
    let refusal = accept(&envelope, &mut state).unwrap_err();
    assert_eq!(refusal, AuthRefusal::SenderNotInRoster);
    assert_eq!(refusal.step(), ValidationStep::RosterMembership);
}

/// ROLE VIOLATION: the roster says this member is a solver; the
/// envelope claims the initiator role, or emits a type the role may not
/// send. Both are refused at step 6 — before the signature, so a
/// role-violating message never reaches verification.
#[test]
fn role_violations_are_refused_at_step_six() {
    let mut claimed = unsigned(0, [0u8; 32]);
    claimed.sender_role = SenderRoleV1::Initiator;
    let claimed = sign(claimed, &SOLVER_SECRET);
    let mut state = TranscriptStateV1::new();
    let refusal = accept(&claimed, &mut state).unwrap_err();
    assert_eq!(refusal, AuthRefusal::RoleMismatch);
    assert_eq!(refusal.step(), ValidationStep::RolePermission);

    // The solver's own role, but a message type only the initiator may
    // send.
    let mut wrong_type = unsigned(0, [0u8; 32]);
    wrong_type.message_type = message_type::ACCEPTANCE;
    let wrong_type = sign(wrong_type, &SOLVER_SECRET);
    let refusal = accept(&wrong_type, &mut state).unwrap_err();
    assert_eq!(refusal, AuthRefusal::RoleNotPermitted);
    assert_eq!(refusal.step(), ValidationStep::RolePermission);

    // An unknown message type is refused, never accepted by default.
    let mut unknown = unsigned(0, [0u8; 32]);
    unknown.message_type = 0xBEEF;
    let unknown = sign(unknown, &SOLVER_SECRET);
    assert_eq!(
        accept(&unknown, &mut state).unwrap_err(),
        AuthRefusal::RoleNotPermitted
    );
}

/// FORGERY: the Relay signs with its own key, or replays a valid
/// signature from a DIFFERENT envelope. Both fail step 7 — the digest
/// binds the complete envelope, so a signature is not transferable.
#[test]
fn forged_and_transplanted_signatures_fail_verification() {
    let mut state = TranscriptStateV1::new();

    // Signed by a key that is not the sender's roster key.
    let forged = sign(unsigned(0, [0u8; 32]), &IMPOSTOR_SECRET);
    let refusal = accept(&forged, &mut state).unwrap_err();
    assert_eq!(refusal, AuthRefusal::InvalidSignature);
    assert_eq!(refusal.step(), ValidationStep::Signature);

    // A VALID signature lifted from another envelope of the same
    // sender: the digest differs, so it does not transfer.
    let other = sign(unsigned(1, [0xAA; 32]), &SOLVER_SECRET);
    let mut transplanted = unsigned(0, [0u8; 32]);
    transplanted.signature = other.signature;
    assert_eq!(
        accept(&transplanted, &mut state).unwrap_err(),
        AuthRefusal::InvalidSignature
    );

    // An unsigned envelope (all zeros) is not accepted either.
    assert_eq!(
        accept(&unsigned(0, [0u8; 32]), &mut state).unwrap_err(),
        AuthRefusal::InvalidSignature
    );
}

/// REPLAY: the Relay redelivers an accepted envelope byte for byte.
/// It is a DUPLICATE — named, idempotent, never re-processed — and the
/// watermark does not move.
#[test]
fn a_byte_identical_replay_is_a_named_duplicate() {
    let mut state = TranscriptStateV1::new();
    let first = sign(unsigned(0, [0u8; 32]), &SOLVER_SECRET);
    let digest = accept(&first, &mut state).unwrap();

    let refusal = accept(&first, &mut state).unwrap_err();
    assert_eq!(refusal, AuthRefusal::Duplicate);
    assert_eq!(refusal.step(), ValidationStep::ReplayGapEquivocation);
    assert_eq!(
        state.last(&SOLVER, &INITIATOR),
        Some((0, digest)),
        "a replay moved state"
    );
}

/// EQUIVOCATION: two DIFFERENT envelopes at the same sequence, both
/// validly signed by the same roster key. A10 makes this provable to a
/// third party (two signatures, two digests, one key), and the pipeline
/// fails closed on it.
#[test]
fn two_valid_envelopes_at_one_sequence_are_equivocation() {
    let mut state = TranscriptStateV1::new();
    let first = sign(unsigned(0, [0u8; 32]), &SOLVER_SECRET);
    accept(&first, &mut state).unwrap();

    let mut conflicting = unsigned(0, [0u8; 32]);
    conflicting.payload = vec![0xff, 0xfe];
    let conflicting = sign(conflicting, &SOLVER_SECRET);
    let refusal = accept(&conflicting, &mut state).unwrap_err();
    assert_eq!(refusal, AuthRefusal::Equivocation);
    assert_eq!(refusal.step(), ValidationStep::ReplayGapEquivocation);
}

/// REORDER and GAP: the Relay delivers sequence 2 before 1, or replays
/// an old position. Each is refused by its own name, and the honest
/// order still works afterwards — the transport reordering messages
/// delays the session, it does not corrupt it.
#[test]
fn reordering_and_gaps_are_refused_and_recoverable() {
    let mut state = TranscriptStateV1::new();
    let first = sign(unsigned(0, [0u8; 32]), &SOLVER_SECRET);
    let digest0 = accept(&first, &mut state).unwrap();

    // Sequence 2 arrives while 1 is missing.
    let ahead = sign(unsigned(2, digest0), &SOLVER_SECRET);
    let refusal = accept(&ahead, &mut state).unwrap_err();
    assert_eq!(refusal, AuthRefusal::SequenceGap);
    assert_eq!(refusal.step(), ValidationStep::ReplayGapEquivocation);

    // The missing 1 arrives: accepted, and the session continues.
    let second = sign(unsigned(1, digest0), &SOLVER_SECRET);
    let digest1 = accept(&second, &mut state).unwrap();

    // A stale position (0 again, different bytes) is refused by name.
    let mut stale = unsigned(0, [0u8; 32]);
    stale.payload = vec![0x01];
    let stale = sign(stale, &SOLVER_SECRET);
    assert_eq!(
        accept(&stale, &mut state).unwrap_err(),
        AuthRefusal::StaleSequence
    );
    assert_eq!(state.last(&SOLVER, &INITIATOR), Some((1, digest1)));
}

/// A first envelope must open the transcript at sequence 0: a session
/// cannot be joined in the middle by an adversary who guesses a
/// position.
#[test]
fn a_session_cannot_be_joined_mid_sequence() {
    let mut state = TranscriptStateV1::new();
    let late = sign(unsigned(7, [0u8; 32]), &SOLVER_SECRET);
    assert_eq!(
        accept(&late, &mut state).unwrap_err(),
        AuthRefusal::SequenceGap
    );
}

/// TRANSCRIPT DISCONTINUITY: a correctly signed, correctly sequenced
/// envelope that chains to the WRONG predecessor is refused at step 9.
/// This is what makes the accepted history a chain and not a set.
#[test]
fn a_broken_transcript_chain_is_refused_at_step_nine() {
    let mut state = TranscriptStateV1::new();
    let first = sign(unsigned(0, [0u8; 32]), &SOLVER_SECRET);
    accept(&first, &mut state).unwrap();

    let wrong_chain = sign(unsigned(1, [0xEE; 32]), &SOLVER_SECRET);
    let refusal = accept(&wrong_chain, &mut state).unwrap_err();
    assert_eq!(refusal, AuthRefusal::TranscriptDiscontinuity);
    assert_eq!(refusal.step(), ValidationStep::TranscriptContinuity);
}

/// The ratified order is TOTAL: an envelope that breaks several rules
/// at once reports the FIRST one. Here the same envelope is
/// misdelivered (step 4), from a non-member (step 5), in the wrong
/// role (step 6), with a forged signature (step 7), at a gapped
/// sequence (step 8) and a broken chain (step 9) — and the refusal is
/// step 4's, every time.
#[test]
fn the_validation_order_is_total_and_reports_the_first_break() {
    let mut envelope = unsigned(9, [0xEE; 32]);
    envelope.recipient_id = ParticipantId([0xAB; 32]);
    envelope.sender_id = ParticipantId([0xCD; 32]);
    envelope.sender_role = SenderRoleV1::Observer;
    let envelope = sign(envelope, &IMPOSTOR_SECRET);
    let mut state = TranscriptStateV1::new();
    let refusal = accept(&envelope, &mut state).unwrap_err();
    assert_eq!(refusal, AuthRefusal::WrongRecipient);
    assert_eq!(
        refusal.step(),
        ValidationStep::NetworkRecipientSessionExpiry
    );

    // Fix step 4 only: the next break in the order surfaces.
    let mut envelope = unsigned(9, [0xEE; 32]);
    envelope.sender_id = ParticipantId([0xCD; 32]);
    envelope.sender_role = SenderRoleV1::Observer;
    let envelope = sign(envelope, &IMPOSTOR_SECRET);
    assert_eq!(
        accept(&envelope, &mut state).unwrap_err(),
        AuthRefusal::SenderNotInRoster
    );

    // Fix step 5: the role break surfaces.
    let mut envelope = unsigned(9, [0xEE; 32]);
    envelope.sender_role = SenderRoleV1::Observer;
    let envelope = sign(envelope, &IMPOSTOR_SECRET);
    assert_eq!(
        accept(&envelope, &mut state).unwrap_err(),
        AuthRefusal::RoleMismatch
    );

    // Fix step 6: the signature break surfaces.
    let envelope = sign(unsigned(9, [0xEE; 32]), &IMPOSTOR_SECRET);
    assert_eq!(
        accept(&envelope, &mut state).unwrap_err(),
        AuthRefusal::InvalidSignature
    );

    // Fix step 7: the sequence break surfaces.
    let envelope = sign(unsigned(9, [0xEE; 32]), &SOLVER_SECRET);
    assert_eq!(
        accept(&envelope, &mut state).unwrap_err(),
        AuthRefusal::SequenceGap
    );

    // Fix step 8: only then the transcript break surfaces.
    let first = sign(unsigned(0, [0u8; 32]), &SOLVER_SECRET);
    accept(&first, &mut state).unwrap();
    let envelope = sign(unsigned(1, [0xEE; 32]), &SOLVER_SECRET);
    assert_eq!(
        accept(&envelope, &mut state).unwrap_err(),
        AuthRefusal::TranscriptDiscontinuity
    );
}

/// SIZE: an oversized transport frame is refused before it is parsed
/// (step 1, I14) — the adversary cannot make the recipient allocate.
#[test]
fn an_oversized_frame_is_refused_before_parsing() {
    let huge = vec![0u8; relay::MAX_ENVELOPE_BYTES + 1];
    let mut state = TranscriptStateV1::new();
    let refusal = accept_envelope(&huge, &recipient(), &rosters(), &mut state, now()).unwrap_err();
    assert_eq!(
        refusal,
        AuthRefusal::Codec(relay::EnvelopeError::EnvelopeTooLarge)
    );

    // A payload at the cap is fine; over it, the codec refuses.
    let mut at_cap = unsigned(0, [0u8; 32]);
    at_cap.payload = vec![0x7f; MAX_PAYLOAD_BYTES];
    let at_cap = sign(at_cap, &SOLVER_SECRET);
    let mut fresh = TranscriptStateV1::new();
    assert!(accept(&at_cap, &mut fresh).is_ok());
}

/// The observer role drives nothing (Annex M M.9.1): an evidence role
/// cannot emit protocol messages even with a valid signature and a
/// perfect sequence.
#[test]
fn the_observer_role_can_drive_nothing() {
    let observer = ParticipantId([0x71; 32]);
    let secret = [0x54u8; 32];
    let snapshot = RosterSnapshotV1::new().with_member(
        observer,
        RosterMemberV1 {
            xonly_key: xonly_of(&secret),
            role: SenderRoleV1::Observer,
        },
    );
    let rosters = RosterRegistryV1::new().with_snapshot(SNAPSHOT, snapshot);

    for message in [
        message_type::RFQ,
        message_type::QUOTE,
        message_type::ACCEPTANCE,
        message_type::SELECTION,
    ] {
        let mut envelope = unsigned(0, [0u8; 32]);
        envelope.sender_id = observer;
        envelope.sender_role = SenderRoleV1::Observer;
        envelope.message_type = message;
        let envelope = sign(envelope, &secret);
        let raw = envelope.canonical_bytes().unwrap();
        let mut state = TranscriptStateV1::new();
        let refusal = accept_envelope(&raw, &recipient(), &rosters, &mut state, now()).unwrap_err();
        assert_eq!(refusal, AuthRefusal::RoleNotPermitted);
    }
}

/// O-03 closure (2026-09-02): the committed policy version is adjudicated
/// against the closed V1 registry, in the same step-4 family as the other
/// context bindings. Before this, the field was signed but nothing compared
/// it, so a semantically downgraded envelope with a valid signature passed.
#[test]
fn an_unaccepted_policy_version_is_refused_at_step_four() {
    let mut envelope = unsigned(0, [0u8; 32]);
    envelope.policy_version = 2;
    let envelope = sign(envelope, &SOLVER_SECRET);
    let mut state = TranscriptStateV1::new();
    let refusal = accept(&envelope, &mut state).unwrap_err();
    assert_eq!(refusal, AuthRefusal::PolicyVersionNotAccepted);
    assert_eq!(
        refusal.step(),
        ValidationStep::NetworkRecipientSessionExpiry
    );
    assert_eq!(
        state.last(&SOLVER, &INITIATOR),
        None,
        "a refusal moved the watermark"
    );
    // Zero is not a permissible "before versioning" escape hatch either.
    let mut envelope = unsigned(0, [0u8; 32]);
    envelope.policy_version = 0;
    let envelope = sign(envelope, &SOLVER_SECRET);
    assert_eq!(
        accept(&envelope, &mut state).unwrap_err(),
        AuthRefusal::PolicyVersionNotAccepted
    );
}
