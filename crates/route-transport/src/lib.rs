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
//! encoded (I6).  On Linux, [`DurableRelaySenderV1`] owns one shared outbound
//! sequence/transcript and one persist-before-submit outbox for every F6 kind
//! plus route transport; an ACK atomically advances its checkpoint.  The
//! matching [`DurableRelayInboxV1`] owns one durable recipient pipeline for
//! all Relay V1 kinds.  It journals an authenticated envelope before exposing
//! its payload to F6 or Contracts and redelivers a pending payload after
//! restart.  Contracts still decides whether DSC1 bytes advance a signing
//! session: the inbox deliberately accepts only the strict
//! [`ContractsTransportPortV1`] boundary, which has no caller-supplied
//! successor argument.
//!
//! Direct V1 remains deliberately single-envelope. Large DSC1 objects use the
//! separately versioned [`RouteFramePlanV2`] format: each ordinary signed Relay
//! envelope carries one context-bound frame, and the Linux
//! [`DurableFrameReassemblerV2`] with [`FramedContractsTransportV2`] is the only
//! production path that reconstructs one byte-identical message before
//! Contracts sees it. No implicit truncation or ephemeral reassembly exists.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

use blake2::{
    digest::{Update, VariableOutput},
    Blake2bVar,
};
use btc_crypto::SecpContext;
use kaystra_core::types::Digest32;
use relay::auth::{
    accept_envelope, message_type, AuthRefusal, RecipientContextV1, RosterRegistryV1,
    TranscriptStateV1,
};
use relay::server::{AckV1, IdempotencyKeyV1, RelayRefusal, RelayV1};
use relay::{ParticipantId, RelayEnvelopeV1, SenderRoleV1, TimelockSpec};
use zeroize::Zeroizing;

/// Largest opaque DSC1 object direct Route Transport V1 can carry in one Relay
/// envelope. Larger valid Contracts messages use [`RouteFramePlanV2`].
pub const MAX_ROUTE_TRANSPORT_PAYLOAD_BYTES: usize = relay::MAX_PAYLOAD_BYTES;

const SENDER_CHECKPOINT_MAGIC: &[u8; 8] = b"DOMRTSC1";
const SENDER_CHECKPOINT_VERSION: u16 = 1;
const SENDER_CHECKPOINT_DOMAIN: &[u8] = b"DOM-INTEROP/ROUTE-SENDER-CHECKPOINT/V1\0";
/// Exact byte length of [`RouteSenderCheckpointV1`].
pub const ROUTE_SENDER_CHECKPOINT_LEN: usize = 282;

#[cfg(target_os = "linux")]
mod durable;
#[cfg(target_os = "linux")]
mod durable_sender;
mod framing;
#[cfg(target_os = "linux")]
mod framing_durable;

pub use framing::{
    RouteFrameErrorV2, RouteFramePlanV2, RouteFrameSendErrorV2, RouteFrameV2,
    MAX_FRAMED_DSC1_BYTES_V2, MAX_ROUTE_FRAME_CHUNK_BYTES_V2, MAX_ROUTE_FRAME_COUNT_V2,
    ROUTE_FRAME_HEADER_LEN_V2, ROUTE_FRAME_MAGIC_V2, ROUTE_FRAME_VERSION_V2,
};

#[cfg(target_os = "linux")]
pub use durable::{
    ContractsRouteDeliveryEvidenceV2, ContractsRouteDeliveryV1, ContractsTransportPortV1,
    DurableInboxConfigV1, DurableInboxEnvelopeRefusalV1, DurableInboxError,
    DurableInboxIngestReportV1, DurableInboxStatsV1, DurablePayloadCommitV1,
    DurablePayloadDispositionV1, DurableQuarantineAuthorityV1, DurableQuarantineReasonV1,
    DurableQuarantineResolutionCommitV1, DurableQuarantineResolutionErrorV1,
    DurableQuarantineResolutionReportV1, DurableQuarantineResolutionRequestV1,
    DurableQuarantineResolutionV1, DurableRelayInboxV1, F6AppliedReplayErrorV1,
    F6AppliedReplayReportV1, F6DispatchErrorV1, F6DispatchReportV1, F6PayloadDeliveryV1,
    F6TransportPortV1, RouteDispatchErrorV1, RouteDispatchReportV1,
};
#[cfg(target_os = "linux")]
pub use durable_sender::{
    DurableFrameTransferStatusV2, DurableOutboundEnvelopeV1, DurableRelaySenderConfigV1,
    DurableRelaySenderErrorV1, DurableRelaySenderStatsV1, DurableRelaySenderV1,
    DurableSenderCommitV1, RouteApplicationDispositionV2, RouteApplicationStateV2,
    RouteApplicationStatusV2,
};
#[cfg(target_os = "linux")]
pub use framing_durable::{
    DurableFrameReassemblerConfigV2, DurableFrameReassemblerErrorV2,
    DurableFrameReassemblerStatsV2, DurableFrameReassemblerV2, FramedContractsTransportErrorV2,
    FramedContractsTransportV2,
};

/// Read-only classification of one production authority creation path.
///
/// Composition roots use this before mutating any member of a multi-store
/// provisioning stage. The result is advisory and must be revalidated while
/// holding the authority lock before creation is resumed.
#[cfg(target_os = "linux")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DurableProductionCreationStateV1 {
    /// No root exists yet.
    Missing,
    /// Only a safe, non-economic creation prefix exists.
    Incomplete,
    /// Exact metadata and an empty economic state are durable.
    InitializedPristine,
}

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
    /// The opaque DSC1 object does not fit the single-envelope Relay V1 wire.
    #[error("route payload too large: {actual} bytes, maximum {maximum}")]
    RoutePayloadTooLarge {
        /// Supplied payload size.
        actual: usize,
        /// Frozen single-envelope maximum.
        maximum: usize,
    },
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
    /// The durable Linux Relay queue refused or could not persist the
    /// operation.  Its error is already redacted by the Relay authority.
    #[cfg(target_os = "linux")]
    #[error("durable relay: {0}")]
    DurableRelay(relay::production::ProductionRelayError),
    /// The §5.4 pipeline refused the envelope.
    #[error("pipeline: {0}")]
    Pipeline(AuthRefusal),
    /// The ACK does not acknowledge THESE bytes (I7, sender side).
    #[error("ack digest mismatch")]
    AckDigestMismatch,
    /// A persisted sender checkpoint is malformed, corrupt, or outside its
    /// frozen V1 domain.
    #[error("invalid route sender checkpoint")]
    InvalidSenderCheckpoint,
    /// Prepared outbox bytes do not belong to the sender's exact current flow
    /// position or fail signature revalidation.
    #[error("prepared route envelope does not match sender flow")]
    PreparedEnvelopeMismatch,
    /// No further sequence can be represented in Relay V1.
    #[error("route sender sequence exhausted")]
    SequenceExhausted,
}

/// Compatibility-only full-mailbox surface for the in-memory protocol
/// reference and explicit ephemeral harnesses. Production Relay deliberately
/// does not implement this trait; outbound production code receives only
/// [`RelaySubmitQueueV1`] and inbound production code receives the concrete
/// bounded V2 authority.
pub trait RelayQueueV1 {
    /// Durably (or, for the reference queue, atomically in memory) retain one
    /// exact canonical envelope before returning its acknowledgement.
    fn queue_submit(&mut self, raw: &[u8]) -> Result<AckV1, BridgeRefusal>;

    /// Return the at-least-once mailbox for one recipient.
    fn queue_deliver_ephemeral_v1(
        &self,
        recipient: &ParticipantId,
    ) -> Result<Vec<Vec<u8>>, BridgeRefusal>;
}

/// Minimal Relay submission authority.  Production outbound code receives no
/// mailbox-reading capability through this boundary.
pub trait RelaySubmitQueueV1 {
    /// Durably (or, for a reference harness, atomically in memory) retain one
    /// exact canonical envelope before returning its acknowledgement.
    fn queue_submit(&mut self, raw: &[u8]) -> Result<AckV1, BridgeRefusal>;
}

impl<T: RelayQueueV1 + ?Sized> RelaySubmitQueueV1 for T {
    fn queue_submit(&mut self, raw: &[u8]) -> Result<AckV1, BridgeRefusal> {
        RelayQueueV1::queue_submit(self, raw)
    }
}

/// Bounded production delivery surface. Unlike [`RelayQueueV1`], this API
/// never exposes a recipient's full retained history: one page is durably
/// pinned, locally persisted by the inbox, and only then acknowledged.
#[cfg(target_os = "linux")]
trait RelayQueueV2 {
    /// Stable database identity retained by the concrete Relay authority.
    fn queue_database_id_v2(&self) -> relay::production::RelayDatabaseIdV1;

    /// Exact currently acknowledged cursor for one recipient.
    fn queue_acknowledged_cursor_v2(
        &self,
        recipient: &ParticipantId,
    ) -> Result<relay::production::DeliveryCursorV2, BridgeRefusal>;

    /// Pins or redelivers one exact bounded page.
    fn queue_delivery_page_v2(
        &mut self,
        recipient: &ParticipantId,
        current: &relay::production::DeliveryCursorV2,
        limits: relay::production::DeliveryPageLimitsV2,
    ) -> Result<relay::production::DeliveryPageV2, BridgeRefusal>;

    /// Durably advances only the exact pending page.
    fn queue_acknowledge_delivery_page_v2(
        &mut self,
        recipient: &ParticipantId,
        next: &relay::production::DeliveryCursorV2,
    ) -> Result<relay::production::DeliveryAckV2, BridgeRefusal>;
}

impl RelayQueueV1 for RelayV1 {
    fn queue_submit(&mut self, raw: &[u8]) -> Result<AckV1, BridgeRefusal> {
        self.submit(raw).map_err(BridgeRefusal::Relay)
    }

    fn queue_deliver_ephemeral_v1(
        &self,
        recipient: &ParticipantId,
    ) -> Result<Vec<Vec<u8>>, BridgeRefusal> {
        Ok(self.deliver(recipient))
    }
}

#[cfg(target_os = "linux")]
impl RelaySubmitQueueV1 for relay::production::ProductionRelayV1 {
    fn queue_submit(&mut self, raw: &[u8]) -> Result<AckV1, BridgeRefusal> {
        self.submit(raw).map_err(BridgeRefusal::DurableRelay)
    }
}

#[cfg(target_os = "linux")]
impl RelayQueueV2 for relay::production::ProductionRelayV1 {
    fn queue_database_id_v2(&self) -> relay::production::RelayDatabaseIdV1 {
        self.database_id()
    }

    fn queue_acknowledged_cursor_v2(
        &self,
        recipient: &ParticipantId,
    ) -> Result<relay::production::DeliveryCursorV2, BridgeRefusal> {
        self.acknowledged_delivery_cursor_v2(recipient)
            .map_err(BridgeRefusal::DurableRelay)
    }

    fn queue_delivery_page_v2(
        &mut self,
        recipient: &ParticipantId,
        current: &relay::production::DeliveryCursorV2,
        limits: relay::production::DeliveryPageLimitsV2,
    ) -> Result<relay::production::DeliveryPageV2, BridgeRefusal> {
        self.delivery_page_v2(recipient, current, limits)
            .map_err(BridgeRefusal::DurableRelay)
    }

    fn queue_acknowledge_delivery_page_v2(
        &mut self,
        recipient: &ParticipantId,
        next: &relay::production::DeliveryCursorV2,
    ) -> Result<relay::production::DeliveryAckV2, BridgeRefusal> {
        self.acknowledge_delivery_page_v2(recipient, next)
            .map_err(BridgeRefusal::DurableRelay)
    }
}

fn sender_role_byte(role: SenderRoleV1) -> u8 {
    match role {
        SenderRoleV1::Initiator => 1,
        SenderRoleV1::Solver => 2,
        SenderRoleV1::Observer => 3,
    }
}

fn sender_role_from_byte(byte: u8) -> Option<SenderRoleV1> {
    match byte {
        1 => Some(SenderRoleV1::Initiator),
        2 => Some(SenderRoleV1::Solver),
        3 => Some(SenderRoleV1::Observer),
        _ => None,
    }
}

fn sender_checkpoint_digest(bytes: &[u8]) -> Result<Digest32, ()> {
    let mut hasher = Blake2bVar::new(32).map_err(|_| ())?;
    hasher.update(SENDER_CHECKPOINT_DOMAIN);
    hasher.update(bytes);
    let mut digest = [0; 32];
    hasher.finalize_variable(&mut digest).map_err(|_| ())?;
    Ok(digest)
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

/// Secret-free, integrity-checked durable checkpoint of one outbound addressed
/// flow.  Owner-only storage remains its authority; the unkeyed digest is not
/// an authorization MAC.
///
/// Persist this record together with a prepared outbox envelope before
/// submission.  If the Relay ACK is lost, reopen the old checkpoint and
/// resubmit the exact prepared bytes; Relay idempotency returns the same ACK
/// and [`RouteSenderV1::submit_prepared`] advances to the same checkpoint.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RouteSenderCheckpointV1 {
    ctx: RouteWireContextV1,
    sender_id: ParticipantId,
    recipient_id: ParticipantId,
    role: SenderRoleV1,
    next_sequence: u64,
    previous_digest: Digest32,
}

impl RouteSenderCheckpointV1 {
    /// Encodes the complete secret-free checkpoint with a domain-separated
    /// integrity digest.
    pub fn canonical_bytes(&self) -> Result<[u8; ROUTE_SENDER_CHECKPOINT_LEN], BridgeRefusal> {
        let mut bytes = [0; ROUTE_SENDER_CHECKPOINT_LEN];
        bytes[..8].copy_from_slice(SENDER_CHECKPOINT_MAGIC);
        bytes[8..10].copy_from_slice(&SENDER_CHECKPOINT_VERSION.to_be_bytes());
        bytes[10..42].copy_from_slice(&self.ctx.network_id);
        bytes[42..74].copy_from_slice(&self.ctx.session_id);
        bytes[74..106].copy_from_slice(&self.ctx.route_id);
        bytes[106..138].copy_from_slice(&self.ctx.roster_snapshot);
        bytes[138..142].copy_from_slice(&self.ctx.policy_version.to_be_bytes());
        bytes[142..174].copy_from_slice(&self.sender_id.0);
        bytes[174..206].copy_from_slice(&self.recipient_id.0);
        bytes[206] = sender_role_byte(self.role);
        bytes[210..218].copy_from_slice(&self.next_sequence.to_be_bytes());
        bytes[218..250].copy_from_slice(&self.previous_digest);
        let digest = sender_checkpoint_digest(&bytes[..250])
            .map_err(|_| BridgeRefusal::InvalidSenderCheckpoint)?;
        bytes[250..].copy_from_slice(&digest);
        Ok(bytes)
    }

    /// Strictly decodes and integrity-checks one complete checkpoint.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, BridgeRefusal> {
        if bytes.len() != ROUTE_SENDER_CHECKPOINT_LEN
            || &bytes[..8] != SENDER_CHECKPOINT_MAGIC
            || u16::from_be_bytes([bytes[8], bytes[9]]) != SENDER_CHECKPOINT_VERSION
            || bytes[207..210] != [0; 3]
            || bytes[250..]
                != sender_checkpoint_digest(&bytes[..250])
                    .map_err(|_| BridgeRefusal::InvalidSenderCheckpoint)?
        {
            return Err(BridgeRefusal::InvalidSenderCheckpoint);
        }
        let digest32 = |range: core::ops::Range<usize>| -> Result<Digest32, BridgeRefusal> {
            bytes[range]
                .try_into()
                .map_err(|_| BridgeRefusal::InvalidSenderCheckpoint)
        };
        let role =
            sender_role_from_byte(bytes[206]).ok_or(BridgeRefusal::InvalidSenderCheckpoint)?;
        let network_id = digest32(10..42)?;
        let session_id = digest32(42..74)?;
        let route_id = digest32(74..106)?;
        let roster_snapshot = digest32(106..138)?;
        let sender_id = ParticipantId(digest32(142..174)?);
        let recipient_id = ParticipantId(digest32(174..206)?);
        let next_sequence = u64::from_be_bytes(
            bytes[210..218]
                .try_into()
                .map_err(|_| BridgeRefusal::InvalidSenderCheckpoint)?,
        );
        let previous_digest = digest32(218..250)?;
        let policy_version = u32::from_be_bytes(
            bytes[138..142]
                .try_into()
                .map_err(|_| BridgeRefusal::InvalidSenderCheckpoint)?,
        );
        if role == SenderRoleV1::Observer
            || network_id == [0; 32]
            || session_id == [0; 32]
            || route_id == [0; 32]
            || roster_snapshot == [0; 32]
            || sender_id.0 == [0; 32]
            || recipient_id.0 == [0; 32]
            || sender_id == recipient_id
            || policy_version == 0
            || (next_sequence == 0 && previous_digest != [0; 32])
            || (next_sequence > 0 && previous_digest == [0; 32])
        {
            return Err(BridgeRefusal::InvalidSenderCheckpoint);
        }
        Ok(Self {
            ctx: RouteWireContextV1 {
                network_id,
                session_id,
                route_id,
                roster_snapshot,
                policy_version,
            },
            sender_id,
            recipient_id,
            role,
            next_sequence,
            previous_digest,
        })
    }

    /// Sequence the next prepared envelope must use.
    pub const fn next_sequence(&self) -> u64 {
        self.next_sequence
    }

    /// Digest the next prepared envelope must chain from.
    pub const fn previous_digest(&self) -> &Digest32 {
        &self.previous_digest
    }

    /// Frozen addressed-flow sender.
    pub const fn sender_id(&self) -> ParticipantId {
        self.sender_id
    }

    /// Frozen addressed-flow recipient.
    pub const fn recipient_id(&self) -> ParticipantId {
        self.recipient_id
    }

    /// Frozen sender role used by the closed Relay kind policy.
    pub const fn sender_role(&self) -> SenderRoleV1 {
        self.role
    }

    /// Frozen route wire context.
    pub const fn wire_context(&self) -> RouteWireContextV1 {
        self.ctx
    }
}

/// Exact signed outbox bytes prepared before Relay submission.
#[derive(Clone, Eq, PartialEq)]
pub struct PreparedRouteEnvelopeV1 {
    raw: Vec<u8>,
    digest: Digest32,
    key: IdempotencyKeyV1,
}

impl core::fmt::Debug for PreparedRouteEnvelopeV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("PreparedRouteEnvelopeV1")
            .field("digest", &self.digest)
            .field("key", &self.key)
            .field("length", &self.raw.len())
            .finish_non_exhaustive()
    }
}

impl PreparedRouteEnvelopeV1 {
    /// Reconstructs exact persisted outbox bytes.  Flow ownership and the
    /// sender signature are revalidated by `submit_prepared` before use.
    pub fn from_canonical_bytes(raw: &[u8]) -> Result<Self, BridgeRefusal> {
        let envelope = RelayEnvelopeV1::decode(raw).map_err(BridgeRefusal::Envelope)?;
        if envelope.message_type != message_type::ROUTE_TRANSPORT
            || envelope.payload.is_empty()
            || envelope.payload.len() > MAX_ROUTE_TRANSPORT_PAYLOAD_BYTES
            || envelope
                .canonical_bytes()
                .map_err(BridgeRefusal::Envelope)?
                != raw
        {
            return Err(BridgeRefusal::PreparedEnvelopeMismatch);
        }
        let digest = envelope
            .envelope_digest()
            .map_err(BridgeRefusal::Envelope)?;
        let key = IdempotencyKeyV1::of(&envelope);
        Ok(Self {
            raw: raw.to_vec(),
            digest,
            key,
        })
    }

    /// Exact canonical signed bytes that must be persisted before submission.
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.raw
    }

    /// Relay envelope digest acknowledged after successful submission.
    pub const fn envelope_digest(&self) -> &Digest32 {
        &self.digest
    }

    /// Exact Relay idempotency key of this prepared envelope.
    pub const fn idempotency_key(&self) -> &IdempotencyKeyV1 {
        &self.key
    }
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
        Self::resume(
            RouteSenderCheckpointV1 {
                ctx,
                sender_id,
                recipient_id,
                role,
                next_sequence: 0,
                previous_digest: [0u8; 32],
            },
            secret,
            secp_seed,
        )
    }

    /// Restores one sender from a secret-free authenticated checkpoint.  The
    /// caller retains custody of the signing secret; it is never part of the
    /// checkpoint or prepared outbox bytes.
    pub fn resume(
        checkpoint: RouteSenderCheckpointV1,
        secret: [u8; 32],
        secp_seed: [u8; 32],
    ) -> Result<Self, BridgeRefusal> {
        let encoded = checkpoint.canonical_bytes()?;
        let validated = RouteSenderCheckpointV1::from_bytes(&encoded)?;
        if validated != checkpoint {
            return Err(BridgeRefusal::InvalidSenderCheckpoint);
        }
        Ok(Self {
            ctx: checkpoint.ctx,
            sender_id: checkpoint.sender_id,
            recipient_id: checkpoint.recipient_id,
            role: checkpoint.role,
            secret: Zeroizing::new(secret),
            secp: SecpContext::new(&secp_seed),
            next_sequence: checkpoint.next_sequence,
            previous_digest: checkpoint.previous_digest,
        })
    }

    /// Returns the complete secret-free current flow checkpoint.
    pub const fn checkpoint(&self) -> RouteSenderCheckpointV1 {
        RouteSenderCheckpointV1 {
            ctx: self.ctx,
            sender_id: self.sender_id,
            recipient_id: self.recipient_id,
            role: self.role,
            next_sequence: self.next_sequence,
            previous_digest: self.previous_digest,
        }
    }

    /// Builds and signs the next exact outbox envelope without changing flow
    /// state.  Production callers persist [`PreparedRouteEnvelopeV1::canonical_bytes`]
    /// and the current [`Self::checkpoint`] atomically before submission.
    pub fn prepare(
        &self,
        payload: Vec<u8>,
        expiry: TimelockSpec,
        aux_rand: [u8; 32],
    ) -> Result<PreparedRouteEnvelopeV1, BridgeRefusal> {
        if payload.is_empty() {
            return Err(BridgeRefusal::EmptyPayload);
        }
        if payload.len() > MAX_ROUTE_TRANSPORT_PAYLOAD_BYTES {
            return Err(BridgeRefusal::RoutePayloadTooLarge {
                actual: payload.len(),
                maximum: MAX_ROUTE_TRANSPORT_PAYLOAD_BYTES,
            });
        }
        if self.next_sequence == u64::MAX {
            return Err(BridgeRefusal::SequenceExhausted);
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
        Ok(PreparedRouteEnvelopeV1 {
            raw,
            digest,
            key: IdempotencyKeyV1::of(&envelope),
        })
    }

    /// Submits exact already-persisted outbox bytes and advances only after an
    /// ACK binds both their idempotency key and digest.  Repeating this call
    /// from the old checkpoint after ACK loss is safe and deterministic.
    pub fn submit_prepared<Q: RelaySubmitQueueV1>(
        &mut self,
        relay: &mut Q,
        prepared: &PreparedRouteEnvelopeV1,
    ) -> Result<AckV1, BridgeRefusal> {
        let envelope = RelayEnvelopeV1::decode(&prepared.raw)
            .map_err(|_| BridgeRefusal::PreparedEnvelopeMismatch)?;
        let canonical = envelope
            .canonical_bytes()
            .map_err(|_| BridgeRefusal::PreparedEnvelopeMismatch)?;
        let digest = envelope
            .envelope_digest()
            .map_err(|_| BridgeRefusal::PreparedEnvelopeMismatch)?;
        let (_, sender_xonly) = self
            .secp
            .sign_bip340(&self.secret, &[0; 32], &[0; 32])
            .map_err(|_| BridgeRefusal::SigningRefused)?;
        if canonical != prepared.raw
            || digest != prepared.digest
            || envelope.network_id != self.ctx.network_id
            || envelope.message_type != message_type::ROUTE_TRANSPORT
            || envelope.session_id != self.ctx.session_id
            || envelope.route_id != self.ctx.route_id
            || envelope.sender_id != self.sender_id
            || envelope.recipient_id != self.recipient_id
            || envelope.sender_role != self.role
            || envelope.sequence != self.next_sequence
            || envelope.previous_transcript_hash != self.previous_digest
            || envelope.policy_version != self.ctx.policy_version
            || envelope.roster_snapshot != self.ctx.roster_snapshot
            || self
                .secp
                .verify_bip340(&sender_xonly, &digest, &envelope.signature)
                .is_err()
        {
            return Err(BridgeRefusal::PreparedEnvelopeMismatch);
        }
        let key = IdempotencyKeyV1::of(&envelope);
        if prepared.key != key {
            return Err(BridgeRefusal::PreparedEnvelopeMismatch);
        }
        let ack = relay.queue_submit(&prepared.raw)?;
        if ack.digest != digest || ack.key != key {
            return Err(BridgeRefusal::AckDigestMismatch);
        }
        self.next_sequence = self
            .next_sequence
            .checked_add(1)
            .ok_or(BridgeRefusal::SequenceExhausted)?;
        self.previous_digest = digest;
        Ok(ack)
    }

    /// Wrap `payload` (signed DSC1 bytes, opaque here) into the next
    /// (flows start at sequence 0 — the §5.4 step-8 rule)
    /// `ROUTE_TRANSPORT` envelope of this flow, sign it, submit it, and
    /// advance the flow chain — only after the ACK acknowledges exactly
    /// these bytes.
    ///
    /// This convenience method does not persist its prepared envelope.  A
    /// production worker must call [`Self::prepare`], durably commit that exact
    /// outbox plus [`Self::checkpoint`], then call [`Self::submit_prepared`].
    #[deprecated(
        note = "ephemeral convenience only; production must persist prepare()+checkpoint() before submit_prepared()"
    )]
    pub fn send<Q: RelaySubmitQueueV1>(
        &mut self,
        relay: &mut Q,
        payload: Vec<u8>,
        expiry: TimelockSpec,
        aux_rand: [u8; 32],
    ) -> Result<AckV1, BridgeRefusal> {
        let prepared = self.prepare(payload, expiry, aux_rand)?;
        self.submit_prepared(relay, &prepared)
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
#[deprecated(
    note = "ephemeral harness receiver; production must use DurableRelayInboxV1 so F6 and route share one durable transcript"
)]
pub fn receive_route_payloads<Q: RelayQueueV1>(
    relay: &Q,
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
    let mailbox = match relay.queue_deliver_ephemeral_v1(&ctx.recipient_id) {
        Ok(mailbox) => mailbox,
        Err(refusal) => {
            delivery.refused.push(refusal);
            return delivery;
        }
    };
    for raw in mailbox {
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
