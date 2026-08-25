//! The route's messages OVER THE RELAY — NOT RATIFIED.
//!
//! The F7 record's one open row the original design got right
//! (`laboratory/F7-Laboratory-Record.md` §7.1) says: the route's DSC1
//! messages are handed straight to the Contracts store by
//! `accept_transport_message` and never travel over a relay — and that
//! manufacturing envelopes purely to give the relay something to lose
//! was considered and refused, because evidence made for the test means
//! nothing. This crate is the LEGITIMATE closure of that row: the
//! production bridge that puts the route's messages on the ratified
//! Relay V1 path, so the relay-loss machinery finally has real traffic
//! to protect.
//!
//! The message kind exists and is ratified: `RouteTransportV1 = 0x0005`
//! (D-029's closed registry, emitted by Initiator and Solver, never by
//! the Observer). The payload is the SIGNED DSC1 BYTES, opaque: the
//! Relay never decodes them (§6.2), this bridge never decodes them, and
//! the recipient hands them, byte-identical, to the Contracts store's
//! `accept_transport_message` — the same bytes that today skip the
//! relay, now carried by it.
//!
//! What the bridge enforces, fail-closed with named refusals (I13):
//!
//! - the sender is built only for a role the registry lets emit
//!   `ROUTE_TRANSPORT` (the Observer refuses at construction);
//! - an empty payload refuses (a DSC1 message is never empty);
//! - the envelope is signed with the pinned D-013 BIP340 backend — the
//!   same backend the Relay's pipeline verifies with (I15);
//! - the sender checks the ACK against its own envelope digest (I7 from
//!   the sender's side: an ACK for other bytes is refused, not trusted);
//! - the sender maintains its flow chain (D-020: per-(sender,
//!   recipient) contiguous sequence, `previous_transcript_hash` =
//!   digest of the last accepted envelope of the flow) so relay-side
//!   replay, gap and discontinuity checks have something real to bite;
//! - the recipient accepts ONLY through `relay::auth::accept_envelope`
//!   — the production §5.4 pipeline with the canonical D-019 policy,
//!   no substitute policy parameter exists on this path — and then
//!   additionally refuses any kind that is not `ROUTE_TRANSPORT`;
//! - an equivocation refusal carries the ratified proof through
//!   unchanged, checkable by `relay::server::verify_equivocation`.
//!
//! The signing secret lives in zeroizing memory and is never logged or
//! encoded (I6). This crate holds no session semantics: whether the
//! carried bytes ADVANCE a session is the Contracts store's decision
//! (step 10 is the caller's), exactly as before.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

use btc_crypto::SecpContext;
use kaystra_core::types::Digest32;
use relay::auth::{
    accept_envelope, message_type, AuthRefusal, RecipientContextV1, RosterRegistryV1,
    TranscriptStateV1,
};
use relay::server::{AckV1, RelayRefusal, RelayV1};
use relay::{ParticipantId, RelayEnvelopeV1, SenderRoleV1, TimelockSpec};
use zeroize::Zeroizing;

/// Everything a bridge step can refuse, by name (I13).
#[derive(Debug, thiserror::Error)]
pub enum BridgeRefusal {
    /// The Observer emits no message type (D-019/D-029); a sender for
    /// it must not even be constructible.
    #[error("observer emits nothing")]
    ObserverEmitsNothing,
    /// A DSC1 message is never empty; an empty payload is a caller bug.
    #[error("empty payload")]
    EmptyPayload,
    /// The envelope could not be encoded or digested.
    #[error("envelope: {0}")]
    Envelope(relay::EnvelopeError),
    /// The pinned backend refused to sign (invalid secret).
    #[error("signing refused")]
    SigningRefused,
    /// The Relay refused the submission; an equivocation refusal
    /// carries the ratified proof through unchanged.
    #[error("relay: {0}")]
    Relay(RelayRefusal),
    /// The §5.4 pipeline refused the envelope.
    #[error("pipeline: {0}")]
    Pipeline(AuthRefusal),
    /// The ACK does not acknowledge THESE bytes (I7, sender side).
    #[error("ack digest mismatch")]
    AckDigestMismatch,
}

/// The session-wide wire facts every envelope of a route shares.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct RouteWireContextV1 {
    /// Network identity (32-byte registry id).
    pub network_id: Digest32,
    /// The session.
    pub session_id: Digest32,
    /// The route binding of the session.
    pub route_id: Digest32,
    /// Roster snapshot the sender's key lives in.
    pub roster_snapshot: Digest32,
    /// Protocol policy version.
    pub policy_version: u32,
}

/// The outcome of one mailbox pull: what was accepted, what was
/// refused by name, and how many foreign-kind envelopes were left
/// untouched for their own consumer.
#[derive(Debug)]
pub struct RouteDeliveryV1 {
    /// The accepted route payloads, in pipeline order.
    pub accepted: Vec<AcceptedRoutePayloadV1>,
    /// Every refusal, named, never dropped.
    pub refused: Vec<BridgeRefusal>,
    /// Foreign-kind envelopes skipped by the codec peek — state
    /// untouched, payload preserved for the session's F6 consumer.
    pub skipped: usize,
}

/// One accepted route payload, with the metadata step 10 needs.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct AcceptedRoutePayloadV1 {
    /// Who sent it (roster-verified by the pipeline).
    pub sender_id: ParticipantId,
    /// The flow sequence.
    pub sequence: u64,
    /// The accepted envelope's digest (the flow chain's next link).
    pub envelope_digest: Digest32,
    /// The opaque DSC1 bytes, exactly as submitted.
    pub payload: Vec<u8>,
}

/// One sender's half of a route flow: builds, signs, submits and chains
/// `ROUTE_TRANSPORT` envelopes toward ONE recipient (D-020: the chain
/// is per addressed flow).
pub struct RouteSenderV1 {
    ctx: RouteWireContextV1,
    sender_id: ParticipantId,
    recipient_id: ParticipantId,
    role: SenderRoleV1,
    secret: Zeroizing<[u8; 32]>,
    secp: SecpContext,
    next_sequence: u64,
    previous_digest: Digest32,
}

impl core::fmt::Debug for RouteSenderV1 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // I6: the secret is never echoed; everything else is public.
        f.debug_struct("RouteSenderV1")
            .field("sender_id", &self.sender_id)
            .field("recipient_id", &self.recipient_id)
            .field("next_sequence", &self.next_sequence)
            .finish_non_exhaustive()
    }
}

impl RouteSenderV1 {
    /// Build a sender for one flow. Refuses the Observer at
    /// construction: the registry gives it no emittable type.
    pub fn new(
        ctx: RouteWireContextV1,
        sender_id: ParticipantId,
        recipient_id: ParticipantId,
        role: SenderRoleV1,
        secret: [u8; 32],
        secp_seed: [u8; 32],
    ) -> Result<Self, BridgeRefusal> {
        if role == SenderRoleV1::Observer {
            return Err(BridgeRefusal::ObserverEmitsNothing);
        }
        Ok(Self {
            ctx,
            sender_id,
            recipient_id,
            role,
            secret: Zeroizing::new(secret),
            secp: SecpContext::new(&secp_seed),
            next_sequence: 0,
            previous_digest: [0u8; 32],
        })
    }

    /// Wrap `payload` (signed DSC1 bytes, opaque here) into the next
    /// (flows start at sequence 0 — the §5.4 step-8 rule)
    /// `ROUTE_TRANSPORT` envelope of this flow, sign it, submit it, and
    /// advance the flow chain — only after the ACK acknowledges exactly
    /// these bytes.
    pub fn send(
        &mut self,
        relay: &mut RelayV1,
        payload: Vec<u8>,
        expiry: TimelockSpec,
        aux_rand: [u8; 32],
    ) -> Result<AckV1, BridgeRefusal> {
        if payload.is_empty() {
            return Err(BridgeRefusal::EmptyPayload);
        }
        let mut envelope = RelayEnvelopeV1 {
            network_id: self.ctx.network_id,
            message_type: message_type::ROUTE_TRANSPORT,
            session_id: self.ctx.session_id,
            route_id: self.ctx.route_id,
            sender_id: self.sender_id,
            recipient_id: self.recipient_id,
            sender_role: self.role,
            sequence: self.next_sequence,
            previous_transcript_hash: self.previous_digest,
            payload,
            expiry,
            policy_version: self.ctx.policy_version,
            roster_snapshot: self.ctx.roster_snapshot,
            signature: [0u8; 64],
        };
        let digest = envelope
            .envelope_digest()
            .map_err(BridgeRefusal::Envelope)?;
        let (signature, _xonly) = self
            .secp
            .sign_bip340(&self.secret, &digest, &aux_rand)
            .map_err(|_| BridgeRefusal::SigningRefused)?;
        envelope.signature = signature;
        let raw = envelope
            .canonical_bytes()
            .map_err(BridgeRefusal::Envelope)?;
        let ack = relay.submit(&raw).map_err(BridgeRefusal::Relay)?;
        // I7 from the sender's side: the ACK must acknowledge exactly
        // these bytes; anything else is refused, and the flow does NOT
        // advance — a resend replays the same envelope.
        if ack.digest != digest {
            return Err(BridgeRefusal::AckDigestMismatch);
        }
        self.next_sequence += 1;
        self.previous_digest = digest;
        Ok(ack)
    }
}

/// Pull the Relay's mailbox for `ctx.recipient_id` and run each
/// `ROUTE_TRANSPORT` envelope through the PRODUCTION §5.4 pipeline
/// ([`relay::auth::accept_envelope`], canonical D-019 policy — no
/// substitute exists on this path). Refusals are returned alongside,
/// named, never dropped: a replayed delivery refuses (the pipeline's
/// replay rule), and neither stops the rest of the mailbox.
///
/// A mailbox can interleave the F6 kinds with route transport on ONE
/// flow, and the flow's sequence/transcript chain is shared across
/// kinds (D-020 keys it by (sender, recipient), not by kind). So a
/// foreign kind is detected by the CODEC ALONE — before the pipeline —
/// and left completely untouched: its transcript position is not
/// consumed and its payload is not destroyed; it is counted in the
/// returned `skipped` and belongs to the session's F6 consumer, which
/// must run on the SAME shared `TranscriptStateV1`. (Audit finding
/// AB-1: the first version ran the pipeline first, which advanced the
/// shared watermark and destroyed the F6 payload it then refused.)
///
/// The accepted payload bytes are EXACTLY what the sender submitted;
/// handing them to the Contracts store's `accept_transport_message` is
/// step 10 — the caller's, as the pipeline defines.
pub fn receive_route_payloads(
    relay: &RelayV1,
    ctx: &RecipientContextV1,
    rosters: &RosterRegistryV1,
    state: &mut TranscriptStateV1,
    now: TimelockSpec,
) -> RouteDeliveryV1 {
    let mut delivery = RouteDeliveryV1 {
        accepted: Vec::new(),
        refused: Vec::new(),
        skipped: 0,
    };
    for raw in relay.deliver(&ctx.recipient_id) {
        // Codec-only peek (no authentication, no state): a kind this
        // path does not carry is left for its own consumer, untouched.
        match RelayEnvelopeV1::decode(&raw) {
            Ok(envelope) if envelope.message_type != message_type::ROUTE_TRANSPORT => {
                delivery.skipped += 1;
                continue;
            }
            Err(refusal) => {
                // Undecodable bytes belong to nobody; named, not dropped.
                delivery.refused.push(BridgeRefusal::Envelope(refusal));
                continue;
            }
            Ok(_) => {}
        }
        match accept_envelope(&raw, ctx, rosters, state, now) {
            Ok(ok) => delivery.accepted.push(AcceptedRoutePayloadV1 {
                sender_id: ok.envelope.sender_id,
                sequence: ok.envelope.sequence,
                envelope_digest: ok.digest,
                payload: ok.envelope.payload,
            }),
            Err(refusal) => delivery.refused.push(BridgeRefusal::Pipeline(refusal)),
        }
    }
    delivery
}
