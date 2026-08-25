//! Envelope authentication and the mandatory recipient validation
//! order (F6 spec v1.0.1 §5, A10 RATIFIED by D-018).
//!
//! The ratified rule, in force here verbatim: every envelope carries a
//! BIP340 signature produced by the sender's canonical roster key over
//! the domain-separated digest of the COMPLETE canonical unsigned
//! envelope; the Relay is untrusted and takes no part in signature
//! production or verification authority; recipients validate canonical
//! encoding, roster membership and role, signature, replay state,
//! sequence and transcript continuity BEFORE processing the payload.
//!
//! No new cryptographic primitive (I15): verification is the pinned
//! D-013 backend's `SecpContext::verify_bip340` — the same code path
//! the F5 conformance layers prove against the official BIP340/BIP327
//! vectors. This module holds no key and produces no signature.
//!
//! The validation order of §5.4 is a TOTAL order over named refusals
//! (I13): step k is only reached when steps 1..k-1 passed, so the
//! refusal a recipient reports names the FIRST rule the envelope broke.
//! [`ValidationStep`] makes that order data, and the adversarial suite
//! asserts each step fires at its own position.

use std::collections::BTreeMap;

use kaystra_core::types::Digest32;

use crate::{EnvelopeError, ParticipantId, RelayEnvelopeV1, SenderRoleV1};

/// Cap on the per-(session, sender) replay window (I14: bounded before
/// anything is stored).
pub const MAX_TRANSCRIPT_ENTRIES: usize = 4_096;

/// One roster member at a given snapshot: the canonical x-only key and
/// the role it may speak in.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct RosterMemberV1 {
    /// BIP340 x-only public key (32 bytes), canonical roster material.
    pub xonly_key: [u8; 32],
    /// The role this member holds in the session.
    pub role: SenderRoleV1,
}

/// A frozen roster snapshot. The envelope names the snapshot it was
/// signed under (ratified A10), so a later key rotation never makes a
/// historical message's validity ambiguous: verification always uses
/// the snapshot the sender named, and an unknown snapshot is refused.
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct RosterSnapshotV1 {
    members: BTreeMap<[u8; 32], RosterMemberV1>,
}

impl RosterSnapshotV1 {
    /// An empty snapshot.
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers one member. A second registration of the same
    /// participant replaces it — a snapshot is a frozen picture, and
    /// building it is the caller's business; what is frozen is which
    /// snapshot an envelope is verified against.
    pub fn with_member(mut self, participant: ParticipantId, member: RosterMemberV1) -> Self {
        self.members.insert(participant.0, member);
        self
    }

    /// The member registered for `participant`, if any.
    pub fn member(&self, participant: &ParticipantId) -> Option<&RosterMemberV1> {
        self.members.get(&participant.0)
    }
}

/// The set of roster snapshots a recipient recognises, keyed by the
/// identifier envelopes carry.
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct RosterRegistryV1 {
    snapshots: BTreeMap<Digest32, RosterSnapshotV1>,
}

impl RosterRegistryV1 {
    /// An empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers one snapshot under its identifier.
    pub fn with_snapshot(mut self, id: Digest32, snapshot: RosterSnapshotV1) -> Self {
        self.snapshots.insert(id, snapshot);
        self
    }

    /// The snapshot registered under `id`, if any.
    pub fn snapshot(&self, id: &Digest32) -> Option<&RosterSnapshotV1> {
        self.snapshots.get(id)
    }
}

/// The steps of the ratified §5.4 validation order, in order. The value
/// is the position, so a refusal can be attributed to its step and the
/// suite can prove the order is total.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum ValidationStep {
    /// 1. Bound the size before allocating.
    SizeBound,
    /// 2. Decode canonically.
    CanonicalDecode,
    /// 3. Reject unknown versions, flags and types.
    KnownVersionsAndTypes,
    /// 4. Check network, recipient, session and expiry.
    NetworkRecipientSessionExpiry,
    /// 5. Locate the sender in the CORRECT roster snapshot.
    RosterMembership,
    /// 6. Confirm the sender's role permits this message type.
    RolePermission,
    /// 7. Verify the BIP340 signature.
    Signature,
    /// 8. Apply replay, gap and equivocation protection.
    ReplayGapEquivocation,
    /// 9. Verify chaining via the previous transcript hash.
    TranscriptContinuity,
    /// 10. Deliver the payload to the state machine.
    Deliver,
}

/// Named refusals of the validation pipeline (I13). Each carries the
/// step it was refused at, so the order is observable.
#[derive(Clone, Copy, PartialEq, Eq, Debug, thiserror::Error)]
pub enum AuthRefusal {
    /// Step 1-3: the envelope did not decode canonically.
    #[error("codec: {0}")]
    Codec(EnvelopeError),
    /// Step 4: the envelope belongs to a different network.
    #[error("wrong network")]
    WrongNetwork,
    /// Step 4: the envelope is addressed to somebody else.
    #[error("wrong recipient")]
    WrongRecipient,
    /// Step 4: the envelope belongs to a different session.
    #[error("wrong session")]
    WrongSession,
    /// Step 4: the envelope belongs to a different route.
    #[error("wrong route")]
    WrongRoute,
    /// Step 4: the envelope expired.
    #[error("expired")]
    Expired,
    /// Step 4: the expiry lives in another timelock domain (A4).
    #[error("wrong timelock domain")]
    WrongTimelockDomain,
    /// Step 5: the named roster snapshot is unknown to this recipient.
    #[error("unknown roster snapshot")]
    UnknownRosterSnapshot,
    /// Step 5: the sender is not a member of that snapshot.
    #[error("sender not in the roster snapshot")]
    SenderNotInRoster,
    /// Step 6: the claimed role is not the sender's role in the roster.
    #[error("role does not match the roster")]
    RoleMismatch,
    /// Step 6: the sender's role may not emit this message type.
    #[error("role may not send this message type")]
    RoleNotPermitted,
    /// Step 7: the BIP340 signature does not verify under the roster
    /// key over the ratified digest.
    #[error("invalid signature")]
    InvalidSignature,
    /// Step 8: this sequence was already accepted with the SAME bytes —
    /// an idempotent duplicate, answered by the ACK, never re-processed.
    #[error("duplicate")]
    Duplicate,
    /// Step 8: this sequence was already accepted with DIFFERENT bytes.
    /// Provable equivocation (A10 makes it third-party verifiable);
    /// the session fails closed.
    #[error("equivocation")]
    Equivocation,
    /// Step 8: the sequence is below the accepted watermark (a replay
    /// of an old position that is not the same message).
    #[error("stale sequence")]
    StaleSequence,
    /// Step 8: the sequence skips ahead; the gap must be filled first.
    #[error("sequence gap")]
    SequenceGap,
    /// Step 9: the transcript hash does not chain to the last accepted
    /// envelope of this (session, sender).
    #[error("transcript discontinuity")]
    TranscriptDiscontinuity,
    /// The verification backend refused to parse the roster key.
    #[error("unusable roster key")]
    UnusableRosterKey,
    /// More transcript entries than [`MAX_TRANSCRIPT_ENTRIES`] (I14).
    #[error("transcript too large")]
    TranscriptTooLarge,
}

impl AuthRefusal {
    /// The §5.4 step this refusal belongs to.
    pub fn step(self) -> ValidationStep {
        match self {
            AuthRefusal::Codec(_) => ValidationStep::CanonicalDecode,
            AuthRefusal::WrongNetwork
            | AuthRefusal::WrongRecipient
            | AuthRefusal::WrongSession
            | AuthRefusal::WrongRoute
            | AuthRefusal::Expired
            | AuthRefusal::WrongTimelockDomain => ValidationStep::NetworkRecipientSessionExpiry,
            AuthRefusal::UnknownRosterSnapshot
            | AuthRefusal::SenderNotInRoster
            | AuthRefusal::UnusableRosterKey => ValidationStep::RosterMembership,
            AuthRefusal::RoleMismatch | AuthRefusal::RoleNotPermitted => {
                ValidationStep::RolePermission
            }
            AuthRefusal::InvalidSignature => ValidationStep::Signature,
            AuthRefusal::Duplicate
            | AuthRefusal::Equivocation
            | AuthRefusal::StaleSequence
            | AuthRefusal::SequenceGap
            | AuthRefusal::TranscriptTooLarge => ValidationStep::ReplayGapEquivocation,
            AuthRefusal::TranscriptDiscontinuity => ValidationStep::TranscriptContinuity,
        }
    }
}

/// What the recipient expects of every envelope it accepts: EXACTLY
/// the four bindings the ratified §5.4 step 4 names — network,
/// recipient, session (and its route) — plus the expiry, which comes
/// from the clock the caller passes. Nothing else belongs here: the
/// envelope also carries a policy version, but no ratified step tells
/// a recipient to compare it, and a field nothing reads is how an
/// unratified rule gets invented later.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct RecipientContextV1 {
    /// The recipient's own participant id.
    pub recipient_id: ParticipantId,
    /// The network this recipient serves.
    pub network_id: Digest32,
    /// The session.
    pub session_id: Digest32,
    /// The route binding of the session.
    pub route_id: Digest32,
}

/// One accepted envelope's position, kept so replay, gap, equivocation
/// and transcript continuity are decidable.
#[derive(Clone, PartialEq, Eq, Debug)]
struct SenderPosition {
    sequence: u64,
    digest: Digest32,
    bytes: Vec<u8>,
}

/// The recipient's durable-shaped validation state: the last accepted
/// position of each ADDRESSED FLOW. The Relay holds no part of this —
/// it is the recipient's, which is what makes an untrusted transport
/// unable to replay, reorder or equivocate its way into acceptance.
///
/// The flow is the D-020 sequence domain, `(session_scope, sender_id,
/// recipient_id)`. The session scope is fixed by the
/// [`RecipientContextV1`] every call carries, so the map key is the
/// remaining pair. Keying by sender ALONE would have been enough for a
/// state object that never leaves one recipient — and wrong the moment
/// one process hosts several participants, because two flows would
/// share a watermark. The domain is therefore structural here rather
/// than assumed from the caller's discipline.
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct TranscriptStateV1 {
    positions: BTreeMap<([u8; 32], [u8; 32]), SenderPosition>,
}

impl TranscriptStateV1 {
    /// Fresh state: nothing accepted yet.
    pub fn new() -> Self {
        Self::default()
    }

    /// The last accepted (sequence, digest) of ONE addressed flow, if
    /// any. Both participants are required: a sender has an independent
    /// contiguous chain per recipient (D-020), so "the last position of
    /// a sender" is not a question with one answer.
    pub fn last(
        &self,
        sender: &ParticipantId,
        recipient: &ParticipantId,
    ) -> Option<(u64, Digest32)> {
        self.positions
            .get(&(sender.0, recipient.0))
            .map(|p| (p.sequence, p.digest))
    }
}

/// A message-type registry decision: which roles may emit which types.
/// v1 keeps it explicit and total — an unknown type is refused, never
/// accepted by default (the ratified step-3/6 discipline).
pub trait MessageTypePolicy {
    /// Whether `role` may emit `message_type`.
    fn permits(&self, role: SenderRoleV1, message_type: u16) -> bool;
}

/// The CLOSED message-kind registry of Relay V1, RATIFIED by D-019
/// (operator decision, 2026-08-10). The values 1-4 are IMMUTABLE
/// within V1; 0 is invalid and 5..=0xffff are reserved and unknown, so
/// both fail closed. A new type requires an explicit ratification and
/// a compatible normative version — never an inference.
pub mod message_type {
    /// 0x0000 — invalid/reserved. Never valid on the wire.
    pub const INVALID: u16 = 0x0000;
    /// 0x0001 — `RfqV1`, emitted by the initiator.
    pub const RFQ: u16 = 0x0001;
    /// 0x0002 — `QuoteV1`, emitted by a solver.
    pub const QUOTE: u16 = 0x0002;
    /// 0x0003 — `AcceptanceV1`, emitted by the initiator: the final
    /// acceptance of the selected quote and its terms.
    pub const ACCEPTANCE: u16 = 0x0003;
    /// 0x0004 — `SelectionV1`, emitted by the initiator: the
    /// adjudication committing the candidate set and the selected
    /// quote.
    pub const SELECTION: u16 = 0x0004;

    /// 0x0005 — `RouteTransportV1`: one canonical DSC1 signing message
    /// carried between the two route participants, opaque to the Relay.
    ///
    /// **RATIFIED 2026-08-19** by operator signature over
    /// `F7_D019_AMENDMENT_FOR_RATIFICATION.md`, amending D-019 — which closed
    /// this registry at 0x0004 and required an explicit ratification for any
    /// new type. The signature is retained with the document in
    /// `ratifications/`; verify with
    /// `minisign -Vm 1-D019-relay-message-type.md -p operator-signing-key.pub`.
    ///
    /// It exists because a DSC1 signing message matches none of
    /// RFQ/Quote/Acceptance/Selection, so without it the Relay refuses the
    /// envelope before any transport code runs. It carries no economic
    /// authority and the Relay never decodes the payload; the Contracts
    /// session store remains the sole adjudicator of the message.
    ///
    /// See `docs/adr/ADR-F7-LAB-RELAY-CARRIES-ROUTE-TRANSPORT.md`.
    pub const ROUTE_TRANSPORT: u16 = 0x0005;

    /// Whether `kind` is one of the types V1 defines. Everything else —
    /// 0x0000 and 0x0006..=0xffff — is unknown and fails closed.
    ///
    /// `ROUTE_TRANSPORT` was ratified on 2026-08-19; see its documentation.
    pub fn is_known(kind: u16) -> bool {
        matches!(kind, RFQ | QUOTE | ACCEPTANCE | SELECTION | ROUTE_TRANSPORT)
    }
}

/// The canonical authorization mapping of Relay V1, RATIFIED by D-019.
/// This is the production policy and the ONLY one the production path
/// may use ([`accept_envelope`] hard-wires it; `guards.sh` enforces
/// that no other implementation reaches a production path).
///
/// Initiator: RFQ, Acceptance, Selection. Solver: Quote. Observer:
/// nothing — the evidence role is strictly non-emitting (Annex M
/// M.9.1). Any unknown kind is refused.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct CanonicalMessageTypePolicyV1;

impl MessageTypePolicy for CanonicalMessageTypePolicyV1 {
    fn permits(&self, role: SenderRoleV1, message_type: u16) -> bool {
        if !message_type::is_known(message_type) {
            return false;
        }
        match role {
            SenderRoleV1::Initiator => matches!(
                message_type,
                message_type::RFQ
                    | message_type::ACCEPTANCE
                    | message_type::SELECTION
                    | message_type::ROUTE_TRANSPORT
            ),
            // Both route participants sign DSC1 rounds, so both may emit
            // ROUTE_TRANSPORT. Ratified 2026-08-19 with the registry value
            // itself; see `message_type::ROUTE_TRANSPORT`.
            SenderRoleV1::Solver => {
                matches!(
                    message_type,
                    message_type::QUOTE | message_type::ROUTE_TRANSPORT
                )
            }
            SenderRoleV1::Observer => false,
        }
    }
}

/// Verifies one BIP340 signature over the ratified envelope digest,
/// through the pinned D-013 backend. No key material is held here and
/// no signature is produced: the Relay and this module are verification
/// consumers only.
#[cfg(feature = "real-bip340")]
fn verify_signature_impl(
    xonly_key: &[u8; 32],
    digest: &Digest32,
    signature: &[u8; 64],
) -> Result<(), AuthRefusal> {
    use btc_crypto::SecpContext;
    // The context seed hardens the backend against side channels during
    // VERIFICATION of public data; it is not key material and nothing
    // here is secret (the F5 contexts follow the same construction).
    let ctx = SecpContext::new(&[0x11; 32]);
    ctx.verify_bip340(xonly_key, digest, signature)
        .map_err(|_| AuthRefusal::InvalidSignature)
}

/// Without the real backend the pipeline REFUSES every signature rather
/// than accepting one it cannot check: a build that cannot verify must
/// not be mistaken for a build where verification passed (I13, and the
/// F1 "no mock crypto in a gate" rule).
#[cfg(not(feature = "real-bip340"))]
fn verify_signature_impl(
    _xonly_key: &[u8; 32],
    _digest: &Digest32,
    _signature: &[u8; 64],
) -> Result<(), AuthRefusal> {
    Err(AuthRefusal::InvalidSignature)
}

/// One BIP340 check under a roster key, over the ratified digest —
/// the SAME code path step 7 of the pipeline uses. Public because the
/// equivocation proof of §6.1 must be checkable by a third party who
/// runs no pipeline (see `crate::server::verify_equivocation`).
pub fn verify_roster_signature(
    xonly_key: &[u8; 32],
    digest: &Digest32,
    signature: &[u8; 64],
) -> Result<(), AuthRefusal> {
    verify_signature_impl(xonly_key, digest, signature)
}

/// The outcome of accepting one envelope.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct AcceptedEnvelopeV1 {
    /// The validated envelope.
    pub envelope: RelayEnvelopeV1,
    /// Its ratified digest — the value the next envelope of this sender
    /// must chain to, and the ACK's identity.
    pub digest: Digest32,
}

/// The full ratified §5.4 pipeline over raw transport bytes.
///
/// Steps 1-3 are the codec's (size bounded before parsing, canonical
/// decode, unknown versions/roles refused); steps 4-9 are here; step 10
/// is the caller's — this function returns the payload's envelope only
/// after every preceding step passed.
///
/// `now` must live in the same timelock domain as the envelope expiry
/// (A4: a cross-domain comparison is refused, never converted).
pub fn accept_envelope(
    raw: &[u8],
    ctx: &RecipientContextV1,
    rosters: &RosterRegistryV1,
    state: &mut TranscriptStateV1,
    now: crate::TimelockSpec,
) -> Result<AcceptedEnvelopeV1, AuthRefusal> {
    // D-019: the production path instantiates the canonical policy and
    // accepts no substitute. There is no parameter to pass a permissive
    // policy through, no configuration hook, and no caller choice.
    accept_envelope_with_policy(raw, ctx, rosters, &CanonicalMessageTypePolicyV1, state, now)
}

/// TEST-ONLY entry point that accepts an alternative
/// [`MessageTypePolicy`]. Production code MUST call [`accept_envelope`]
/// instead; `guards.sh` refuses this symbol outside test trees
/// (the same discipline that keeps the F2 store failpoints test-only).
#[doc(hidden)]
pub fn accept_envelope_with_policy<P: MessageTypePolicy>(
    raw: &[u8],
    ctx: &RecipientContextV1,
    rosters: &RosterRegistryV1,
    policy: &P,
    state: &mut TranscriptStateV1,
    now: crate::TimelockSpec,
) -> Result<AcceptedEnvelopeV1, AuthRefusal> {
    // Steps 1-3: bounded, canonical, known.
    let envelope = RelayEnvelopeV1::decode(raw).map_err(AuthRefusal::Codec)?;

    // Step 4: network, recipient, session, route, expiry.
    if envelope.network_id != ctx.network_id {
        return Err(AuthRefusal::WrongNetwork);
    }
    if envelope.recipient_id != ctx.recipient_id {
        return Err(AuthRefusal::WrongRecipient);
    }
    if envelope.session_id != ctx.session_id {
        return Err(AuthRefusal::WrongSession);
    }
    if envelope.route_id != ctx.route_id {
        return Err(AuthRefusal::WrongRoute);
    }
    let (expiry_domain, expiry_value) = timelock_parts(envelope.expiry);
    let (now_domain, now_value) = timelock_parts(now);
    if expiry_domain != now_domain {
        return Err(AuthRefusal::WrongTimelockDomain);
    }
    if now_value > expiry_value {
        return Err(AuthRefusal::Expired);
    }

    // Step 5: the sender, in the snapshot the ENVELOPE names.
    let snapshot = rosters
        .snapshot(&envelope.roster_snapshot)
        .ok_or(AuthRefusal::UnknownRosterSnapshot)?;
    let member = snapshot
        .member(&envelope.sender_id)
        .ok_or(AuthRefusal::SenderNotInRoster)?;

    // Step 6: role, as the ROSTER records it, then the type permission.
    //
    // D-019 (as clarified by the operator, 2026-08-10): this lookup and
    // check are NON-MUTATING and PROVISIONAL. The role is never taken
    // from the envelope's claim — `member.role` is the roster's record,
    // and a claim that disagrees with it is refused here. Nothing is
    // delivered, acknowledged or committed at this point: the only
    // writes in this function happen after step 9, so a message that
    // fails step 7 leaves no trace of having been role-checked.
    if member.role != envelope.sender_role {
        return Err(AuthRefusal::RoleMismatch);
    }
    if !policy.permits(member.role, envelope.message_type) {
        return Err(AuthRefusal::RoleNotPermitted);
    }

    // Step 7: the signature, over the ratified digest of the complete
    // canonical unsigned envelope.
    let digest = envelope.envelope_digest().map_err(AuthRefusal::Codec)?;
    verify_roster_signature(&member.xonly_key, &digest, &envelope.signature)?;

    // Step 8: replay, gap, equivocation, within the D-020 sequence
    // domain `(session_scope, sender_id, recipient_id)`. Only now — an
    // unauthenticated message must never be able to move a watermark.
    //
    // The session scope is `ctx`'s (step 4 already refused any other
    // session) and the recipient is `ctx.recipient_id` (step 4 already
    // refused anything addressed elsewhere), so the flow this envelope
    // belongs to is fully determined here. Messages the same sender
    // addressed to OTHER participants are not part of this chain and
    // cannot open a gap in it — which is the whole point of D-020.
    let flow = (envelope.sender_id.0, envelope.recipient_id.0);
    let canonical = envelope.canonical_bytes().map_err(AuthRefusal::Codec)?;
    match state.positions.get(&flow) {
        None => {
            if envelope.sequence != 0 {
                return Err(AuthRefusal::SequenceGap);
            }
        }
        Some(previous) => {
            if envelope.sequence == previous.sequence {
                // Same position: identical bytes are the idempotent
                // duplicate the ACK answers; different bytes are
                // equivocation, and A10 makes it provable to a third
                // party (two signatures over two digests, one key).
                if canonical == previous.bytes {
                    return Err(AuthRefusal::Duplicate);
                }
                return Err(AuthRefusal::Equivocation);
            }
            if envelope.sequence < previous.sequence {
                return Err(AuthRefusal::StaleSequence);
            }
            if envelope.sequence != previous.sequence + 1 {
                return Err(AuthRefusal::SequenceGap);
            }
        }
    }

    // Step 9: transcript continuity — within the SAME flow (D-020:
    // `previous_transcript_hash` chains only envelopes of one addressed
    // flow; there is no total order across recipients to chain to).
    let expected_previous = state.positions.get(&flow).map_or([0u8; 32], |p| p.digest);
    if envelope.previous_transcript_hash != expected_previous {
        return Err(AuthRefusal::TranscriptDiscontinuity);
    }

    if state.positions.len() >= MAX_TRANSCRIPT_ENTRIES && !state.positions.contains_key(&flow) {
        return Err(AuthRefusal::TranscriptTooLarge);
    }
    state.positions.insert(
        flow,
        SenderPosition {
            sequence: envelope.sequence,
            digest,
            bytes: canonical,
        },
    );

    // Step 10 is the caller's: the payload reaches the state machine
    // only through this return.
    Ok(AcceptedEnvelopeV1 { envelope, digest })
}

fn timelock_parts(spec: crate::TimelockSpec) -> (u8, u64) {
    match spec {
        crate::TimelockSpec::BlockHeight { value } => (0x01, value),
        crate::TimelockSpec::TimestampSeconds { value } => (0x02, value),
        crate::TimelockSpec::BtcTime512s { value } => (0x03, value),
    }
}
