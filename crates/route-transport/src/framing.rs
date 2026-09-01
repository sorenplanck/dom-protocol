//! Canonical authenticated framing for large DSC1 messages over Relay V1.
//!
//! Relay authenticates every frame as an ordinary `ROUTE_TRANSPORT` payload.
//! This inner format additionally binds every chunk to the complete DSC1
//! digest and to the exact route flow.  It is deliberately a separate V2
//! format: an unframed V1 payload remains byte-for-byte compatible.

use blake2::{
    digest::{Update, VariableOutput},
    Blake2bVar,
};
use kaystra_core::types::Digest32;
use relay::{ParticipantId, TimelockSpec};

use crate::{
    BridgeRefusal, PreparedRouteEnvelopeV1, RouteSenderCheckpointV1, RouteSenderV1,
    RouteWireContextV1, MAX_ROUTE_TRANSPORT_PAYLOAD_BYTES,
};

/// Magic prefix selecting framed Route Transport V2 rather than direct V1.
pub const ROUTE_FRAME_MAGIC_V2: [u8; 8] = *b"DOMRTF2\0";
/// Canonical framing version.
pub const ROUTE_FRAME_VERSION_V2: u16 = 2;
/// Fixed canonical frame header length.
pub const ROUTE_FRAME_HEADER_LEN_V2: usize = 128;
/// Largest chunk body that still fits one Relay V1 payload.
pub const MAX_ROUTE_FRAME_CHUNK_BYTES_V2: usize =
    MAX_ROUTE_TRANSPORT_PAYLOAD_BYTES - ROUTE_FRAME_HEADER_LEN_V2;
/// Largest real DSC1 object whose type-specific payload cap is 512 KiB.
///
/// DSC1 has 148 unsigned-prefix bytes and a 65-byte identity signature in
/// addition to the type-specific payload.  `FinalRefund` and `FinalClaim` are
/// the largest current types, each with a 512 KiB payload cap.
pub const MAX_FRAMED_DSC1_BYTES_V2: usize = 148 + 65 + 512 * 1024;
/// Maximum canonical frame count for [`MAX_FRAMED_DSC1_BYTES_V2`].
pub const MAX_ROUTE_FRAME_COUNT_V2: u16 = 33;

const MESSAGE_DOMAIN_V2: &[u8] = b"DOM-INTEROP/ROUTE-FRAME/MESSAGE/V2\0";
const BINDING_DOMAIN_V2: &[u8] = b"DOM-INTEROP/ROUTE-FRAME/BINDING/V2\0";
const CHUNK_DOMAIN_V2: &[u8] = b"DOM-INTEROP/ROUTE-FRAME/CHUNK/V2\0";

/// A canonical framing or flow-binding refusal.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum RouteFrameErrorV2 {
    /// Payload does not contain a complete canonical V2 header.
    #[error("truncated route frame V2")]
    Truncated,
    /// Magic, version, flags, reserved fields, or header length is unknown.
    #[error("unsupported route frame V2 encoding")]
    UnsupportedEncoding,
    /// Full DSC1 length is not in the framed range.
    #[error("framed DSC1 length is outside the supported range")]
    InvalidMessageLength,
    /// Chunk count or index is outside the canonical bounded layout.
    #[error("invalid route frame V2 chunk position")]
    InvalidChunkPosition,
    /// Offset, chunk length, or total canonical byte length is non-canonical.
    #[error("non-canonical route frame V2 layout")]
    NonCanonicalLayout,
    /// The frame belongs to a different network/session/route/flow.
    #[error("route frame V2 flow binding mismatch")]
    FlowBindingMismatch,
    /// The chunk bytes do not match their bound digest.
    #[error("route frame V2 chunk digest mismatch")]
    ChunkDigestMismatch,
    /// Complete reassembly does not match the committed full-message digest.
    #[error("route frame V2 full-message digest mismatch")]
    MessageDigestMismatch,
    /// Bounded digest construction failed closed.
    #[error("route frame V2 digest unavailable")]
    DigestUnavailable,
}

/// Sender-side framing failure.  It keeps flow-order mistakes distinct from
/// Relay/signature failures.
#[derive(Debug, thiserror::Error)]
pub enum RouteFrameSendErrorV2 {
    /// The plan was applied to another route, party, role, or starting flow.
    #[error("framed route plan belongs to a different sender flow")]
    WrongSenderFlow,
    /// Frames must be prepared in index order with each prior ACK persisted.
    #[error("framed route plan is not at the expected frame position")]
    WrongFrameOrder,
    /// Canonical framing refused the source message.
    #[error("route framing: {0}")]
    Frame(#[from] RouteFrameErrorV2),
    /// The existing signed Relay sender refused the prepared envelope.
    #[error("route sender: {0}")]
    Bridge(#[from] BridgeRefusal),
}

/// One decoded, flow-bound V2 frame.
#[derive(Clone, Eq, PartialEq)]
pub struct RouteFrameV2 {
    binding_digest: Digest32,
    message_digest: Digest32,
    index: u16,
    count: u16,
    total_len: u32,
    offset: u32,
    chunk_digest: Digest32,
    chunk: Vec<u8>,
}

impl core::fmt::Debug for RouteFrameV2 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("RouteFrameV2")
            .field("binding_digest", &self.binding_digest)
            .field("message_digest", &self.message_digest)
            .field("index", &self.index)
            .field("count", &self.count)
            .field("total_len", &self.total_len)
            .field("offset", &self.offset)
            .field("chunk_len", &self.chunk.len())
            .finish_non_exhaustive()
    }
}

impl RouteFrameV2 {
    /// Returns whether bytes select the framed V2 namespace.  Bytes without
    /// this exact magic remain direct Route Transport V1 payloads.
    #[must_use]
    pub fn is_framed_payload(bytes: &[u8]) -> bool {
        bytes.starts_with(&ROUTE_FRAME_MAGIC_V2)
    }

    /// Strictly decodes a frame and verifies its route-flow and chunk binding.
    pub fn decode_for_flow(
        bytes: &[u8],
        wire: RouteWireContextV1,
        sender_id: ParticipantId,
        recipient_id: ParticipantId,
    ) -> Result<Self, RouteFrameErrorV2> {
        if bytes.len() < ROUTE_FRAME_HEADER_LEN_V2 {
            return Err(RouteFrameErrorV2::Truncated);
        }
        if bytes.len() > MAX_ROUTE_TRANSPORT_PAYLOAD_BYTES
            || bytes[..8] != ROUTE_FRAME_MAGIC_V2
            || read_u16(bytes, 8)? != ROUTE_FRAME_VERSION_V2
            || read_u16(bytes, 10)? != 0
            || usize::from(read_u16(bytes, 12)?) != ROUTE_FRAME_HEADER_LEN_V2
            || read_u16(bytes, 14)? != 0
        {
            return Err(RouteFrameErrorV2::UnsupportedEncoding);
        }
        let binding_digest = read_digest(bytes, 16)?;
        let message_digest = read_digest(bytes, 48)?;
        let index = read_u16(bytes, 80)?;
        let count = read_u16(bytes, 82)?;
        let total_len = read_u32(bytes, 84)?;
        let offset = read_u32(bytes, 88)?;
        let chunk_len = read_u32(bytes, 92)?;
        let chunk_digest = read_digest(bytes, 96)?;
        let total =
            usize::try_from(total_len).map_err(|_| RouteFrameErrorV2::InvalidMessageLength)?;
        if total <= MAX_ROUTE_TRANSPORT_PAYLOAD_BYTES || total > MAX_FRAMED_DSC1_BYTES_V2 {
            return Err(RouteFrameErrorV2::InvalidMessageLength);
        }
        let expected_count = frame_count(total)?;
        if count != expected_count || count == 0 || index >= count {
            return Err(RouteFrameErrorV2::InvalidChunkPosition);
        }
        let expected_offset = usize::from(index)
            .checked_mul(MAX_ROUTE_FRAME_CHUNK_BYTES_V2)
            .ok_or(RouteFrameErrorV2::NonCanonicalLayout)?;
        let expected_chunk_len = core::cmp::min(
            MAX_ROUTE_FRAME_CHUNK_BYTES_V2,
            total
                .checked_sub(expected_offset)
                .ok_or(RouteFrameErrorV2::NonCanonicalLayout)?,
        );
        let chunk_len =
            usize::try_from(chunk_len).map_err(|_| RouteFrameErrorV2::NonCanonicalLayout)?;
        if usize::try_from(offset).ok() != Some(expected_offset)
            || chunk_len != expected_chunk_len
            || bytes.len() != ROUTE_FRAME_HEADER_LEN_V2 + chunk_len
        {
            return Err(RouteFrameErrorV2::NonCanonicalLayout);
        }
        let expected_binding = binding_digest_v2(
            wire,
            sender_id,
            recipient_id,
            &message_digest,
            total_len,
            count,
        )?;
        if binding_digest != expected_binding {
            return Err(RouteFrameErrorV2::FlowBindingMismatch);
        }
        let chunk = bytes[ROUTE_FRAME_HEADER_LEN_V2..].to_vec();
        let expected_chunk_digest = chunk_digest_v2(ChunkDigestFieldsV2 {
            binding_digest: &binding_digest,
            message_digest: &message_digest,
            index,
            count,
            total_len,
            offset,
            chunk: &chunk,
        })?;
        if chunk_digest != expected_chunk_digest {
            return Err(RouteFrameErrorV2::ChunkDigestMismatch);
        }
        Ok(Self {
            binding_digest,
            message_digest,
            index,
            count,
            total_len,
            offset,
            chunk_digest,
            chunk,
        })
    }

    /// Re-encodes this exact canonical frame.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, RouteFrameErrorV2> {
        encode_frame(
            self.binding_digest,
            self.message_digest,
            self.index,
            self.count,
            self.total_len,
            self.offset,
            &self.chunk,
        )
    }

    /// Digest binding the whole message and exact route flow.
    pub const fn binding_digest(&self) -> &Digest32 {
        &self.binding_digest
    }

    /// Digest committed to the complete byte-identical DSC1 object.
    pub const fn message_digest(&self) -> &Digest32 {
        &self.message_digest
    }

    /// Zero-based canonical chunk index.
    pub const fn index(&self) -> u16 {
        self.index
    }

    /// Exact total canonical chunk count.
    pub const fn count(&self) -> u16 {
        self.count
    }

    /// Exact complete DSC1 byte length.
    pub const fn total_len(&self) -> u32 {
        self.total_len
    }

    /// Canonical byte offset of this chunk in the complete DSC1 object.
    pub const fn offset(&self) -> u32 {
        self.offset
    }

    /// Digest of this chunk and all its position/binding facts.
    pub const fn chunk_digest(&self) -> &Digest32 {
        &self.chunk_digest
    }

    /// Exact chunk body.
    pub fn chunk(&self) -> &[u8] {
        &self.chunk
    }
}

/// Deterministic frame payloads for one large DSC1 object and one exact sender
/// flow.  It contains no signing secret and does not submit anything.
///
/// Production persists its source DSC1 in the appropriate contracts authority,
/// plus the base sender checkpoint and current frame index.  For each index it
/// calls [`Self::prepare_frame`], atomically persists that exact prepared Relay
/// envelope with the current checkpoint, submits it, and persists the ACK plus
/// advanced checkpoint before moving to the next index.
pub struct RouteFramePlanV2 {
    base: RouteSenderCheckpointV1,
    message_digest: Digest32,
    binding_digest: Digest32,
    frames: Vec<Vec<u8>>,
}

impl core::fmt::Debug for RouteFramePlanV2 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("RouteFramePlanV2")
            .field("message_digest", &self.message_digest)
            .field("binding_digest", &self.binding_digest)
            .field("frame_count", &self.frames.len())
            .finish_non_exhaustive()
    }
}

impl RouteFramePlanV2 {
    /// Splits one large DSC1 object into canonical context-bound frame payloads.
    /// Small messages are intentionally refused so their direct V1 encoding
    /// remains unique.
    pub fn new(
        base: RouteSenderCheckpointV1,
        signed_dsc1: &[u8],
    ) -> Result<Self, RouteFrameSendErrorV2> {
        let encoded = base.canonical_bytes()?;
        if RouteSenderCheckpointV1::from_bytes(&encoded)? != base {
            return Err(RouteFrameSendErrorV2::WrongSenderFlow);
        }
        if signed_dsc1.len() <= MAX_ROUTE_TRANSPORT_PAYLOAD_BYTES
            || signed_dsc1.len() > MAX_FRAMED_DSC1_BYTES_V2
        {
            return Err(RouteFrameErrorV2::InvalidMessageLength.into());
        }
        let count = frame_count(signed_dsc1.len())?;
        base.next_sequence()
            .checked_add(u64::from(count))
            .ok_or(BridgeRefusal::SequenceExhausted)?;
        let total_len = u32::try_from(signed_dsc1.len())
            .map_err(|_| RouteFrameErrorV2::InvalidMessageLength)?;
        let message_digest = full_message_digest_v2(signed_dsc1)?;
        let binding_digest = binding_digest_v2(
            base.wire_context(),
            base.sender_id(),
            base.recipient_id(),
            &message_digest,
            total_len,
            count,
        )?;
        let mut frames = Vec::with_capacity(usize::from(count));
        for (index, chunk) in signed_dsc1
            .chunks(MAX_ROUTE_FRAME_CHUNK_BYTES_V2)
            .enumerate()
        {
            let index =
                u16::try_from(index).map_err(|_| RouteFrameErrorV2::InvalidChunkPosition)?;
            let offset = u32::try_from(
                usize::from(index)
                    .checked_mul(MAX_ROUTE_FRAME_CHUNK_BYTES_V2)
                    .ok_or(RouteFrameErrorV2::NonCanonicalLayout)?,
            )
            .map_err(|_| RouteFrameErrorV2::NonCanonicalLayout)?;
            frames.push(encode_frame(
                binding_digest,
                message_digest,
                index,
                count,
                total_len,
                offset,
                chunk,
            )?);
        }
        if frames.len() != usize::from(count) {
            return Err(RouteFrameErrorV2::InvalidChunkPosition.into());
        }
        Ok(Self {
            base,
            message_digest,
            binding_digest,
            frames,
        })
    }

    /// Number of Relay envelopes in this plan.
    pub fn frame_count(&self) -> usize {
        self.frames.len()
    }

    /// Full-message digest shared by all frames.
    pub const fn message_digest(&self) -> &Digest32 {
        &self.message_digest
    }

    /// Route-flow binding shared by all frames.
    pub const fn binding_digest(&self) -> &Digest32 {
        &self.binding_digest
    }

    /// Canonical inner frame bytes for an index, without signing/submitting.
    pub fn frame_payload(&self, index: usize) -> Option<&[u8]> {
        self.frames.get(index).map(Vec::as_slice)
    }

    pub(crate) const fn base_checkpoint(&self) -> RouteSenderCheckpointV1 {
        self.base
    }

    pub(crate) fn frame_payload_for_checkpoint(
        &self,
        checkpoint: RouteSenderCheckpointV1,
        index: usize,
    ) -> Result<&[u8], RouteFrameSendErrorV2> {
        if checkpoint.wire_context() != self.base.wire_context()
            || checkpoint.sender_id() != self.base.sender_id()
            || checkpoint.recipient_id() != self.base.recipient_id()
            || checkpoint.sender_role() != self.base.sender_role()
        {
            return Err(RouteFrameSendErrorV2::WrongSenderFlow);
        }
        let index_u64 = u64::try_from(index).map_err(|_| RouteFrameSendErrorV2::WrongFrameOrder)?;
        let expected_sequence = self
            .base
            .next_sequence()
            .checked_add(index_u64)
            .ok_or(RouteFrameSendErrorV2::WrongFrameOrder)?;
        if checkpoint.next_sequence() != expected_sequence {
            return Err(RouteFrameSendErrorV2::WrongFrameOrder);
        }
        self.frames
            .get(index)
            .map(Vec::as_slice)
            .ok_or(RouteFrameSendErrorV2::WrongFrameOrder)
    }

    /// Prepares exactly one current frame through the existing durable sender
    /// boundary.  The caller still owns persistence and Relay submission; this
    /// helper never advances the sender or hides an ephemeral outbox.
    pub fn prepare_frame(
        &self,
        sender: &RouteSenderV1,
        index: usize,
        expiry: TimelockSpec,
        aux_rand: [u8; 32],
    ) -> Result<PreparedRouteEnvelopeV1, RouteFrameSendErrorV2> {
        let checkpoint = sender.checkpoint();
        let payload = self.frame_payload_for_checkpoint(checkpoint, index)?;
        sender
            .prepare(payload.to_vec(), expiry, aux_rand)
            .map_err(RouteFrameSendErrorV2::Bridge)
    }
}

pub(crate) fn verify_complete_message_v2(
    bytes: &[u8],
    expected_len: u32,
    expected_digest: &Digest32,
) -> Result<(), RouteFrameErrorV2> {
    if usize::try_from(expected_len).ok() != Some(bytes.len())
        || full_message_digest_v2(bytes)? != *expected_digest
    {
        return Err(RouteFrameErrorV2::MessageDigestMismatch);
    }
    Ok(())
}

pub(crate) fn frame_count(total: usize) -> Result<u16, RouteFrameErrorV2> {
    let adjusted = total
        .checked_add(MAX_ROUTE_FRAME_CHUNK_BYTES_V2 - 1)
        .ok_or(RouteFrameErrorV2::InvalidMessageLength)?;
    let count = adjusted / MAX_ROUTE_FRAME_CHUNK_BYTES_V2;
    let count = u16::try_from(count).map_err(|_| RouteFrameErrorV2::InvalidChunkPosition)?;
    if count == 0 || count > MAX_ROUTE_FRAME_COUNT_V2 {
        return Err(RouteFrameErrorV2::InvalidChunkPosition);
    }
    Ok(count)
}

pub(crate) fn encode_frame(
    binding_digest: Digest32,
    message_digest: Digest32,
    index: u16,
    count: u16,
    total_len: u32,
    offset: u32,
    chunk: &[u8],
) -> Result<Vec<u8>, RouteFrameErrorV2> {
    if chunk.is_empty() || chunk.len() > MAX_ROUTE_FRAME_CHUNK_BYTES_V2 {
        return Err(RouteFrameErrorV2::NonCanonicalLayout);
    }
    let chunk_digest = chunk_digest_v2(ChunkDigestFieldsV2 {
        binding_digest: &binding_digest,
        message_digest: &message_digest,
        index,
        count,
        total_len,
        offset,
        chunk,
    })?;
    let mut bytes = Vec::with_capacity(ROUTE_FRAME_HEADER_LEN_V2 + chunk.len());
    bytes.extend_from_slice(&ROUTE_FRAME_MAGIC_V2);
    bytes.extend_from_slice(&ROUTE_FRAME_VERSION_V2.to_be_bytes());
    bytes.extend_from_slice(&0_u16.to_be_bytes());
    bytes.extend_from_slice(&(ROUTE_FRAME_HEADER_LEN_V2 as u16).to_be_bytes());
    bytes.extend_from_slice(&0_u16.to_be_bytes());
    bytes.extend_from_slice(&binding_digest);
    bytes.extend_from_slice(&message_digest);
    bytes.extend_from_slice(&index.to_be_bytes());
    bytes.extend_from_slice(&count.to_be_bytes());
    bytes.extend_from_slice(&total_len.to_be_bytes());
    bytes.extend_from_slice(&offset.to_be_bytes());
    bytes.extend_from_slice(&(chunk.len() as u32).to_be_bytes());
    bytes.extend_from_slice(&chunk_digest);
    bytes.extend_from_slice(chunk);
    if bytes.len() > MAX_ROUTE_TRANSPORT_PAYLOAD_BYTES {
        return Err(RouteFrameErrorV2::NonCanonicalLayout);
    }
    Ok(bytes)
}

pub(crate) fn full_message_digest_v2(bytes: &[u8]) -> Result<Digest32, RouteFrameErrorV2> {
    let length = u32::try_from(bytes.len()).map_err(|_| RouteFrameErrorV2::InvalidMessageLength)?;
    digest_parts(MESSAGE_DOMAIN_V2, &[&length.to_be_bytes(), bytes])
}

pub(crate) fn binding_digest_v2(
    wire: RouteWireContextV1,
    sender_id: ParticipantId,
    recipient_id: ParticipantId,
    message_digest: &Digest32,
    total_len: u32,
    count: u16,
) -> Result<Digest32, RouteFrameErrorV2> {
    digest_parts(
        BINDING_DOMAIN_V2,
        &[
            wire.network_id.as_slice(),
            wire.session_id.as_slice(),
            wire.route_id.as_slice(),
            wire.roster_snapshot.as_slice(),
            &wire.policy_version.to_be_bytes(),
            sender_id.0.as_slice(),
            recipient_id.0.as_slice(),
            message_digest.as_slice(),
            &total_len.to_be_bytes(),
            &count.to_be_bytes(),
        ],
    )
}

struct ChunkDigestFieldsV2<'a> {
    binding_digest: &'a Digest32,
    message_digest: &'a Digest32,
    index: u16,
    count: u16,
    total_len: u32,
    offset: u32,
    chunk: &'a [u8],
}

fn chunk_digest_v2(fields: ChunkDigestFieldsV2<'_>) -> Result<Digest32, RouteFrameErrorV2> {
    let chunk_len =
        u32::try_from(fields.chunk.len()).map_err(|_| RouteFrameErrorV2::NonCanonicalLayout)?;
    digest_parts(
        CHUNK_DOMAIN_V2,
        &[
            fields.binding_digest.as_slice(),
            fields.message_digest.as_slice(),
            &fields.index.to_be_bytes(),
            &fields.count.to_be_bytes(),
            &fields.total_len.to_be_bytes(),
            &fields.offset.to_be_bytes(),
            &chunk_len.to_be_bytes(),
            fields.chunk,
        ],
    )
}

fn digest_parts(domain: &[u8], parts: &[&[u8]]) -> Result<Digest32, RouteFrameErrorV2> {
    let mut hasher = Blake2bVar::new(32).map_err(|_| RouteFrameErrorV2::DigestUnavailable)?;
    hasher.update(domain);
    for part in parts {
        hasher.update(part);
    }
    let mut digest = [0; 32];
    hasher
        .finalize_variable(&mut digest)
        .map_err(|_| RouteFrameErrorV2::DigestUnavailable)?;
    Ok(digest)
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16, RouteFrameErrorV2> {
    let end = offset.checked_add(2).ok_or(RouteFrameErrorV2::Truncated)?;
    let exact: [u8; 2] = bytes
        .get(offset..end)
        .ok_or(RouteFrameErrorV2::Truncated)?
        .try_into()
        .map_err(|_| RouteFrameErrorV2::Truncated)?;
    Ok(u16::from_be_bytes(exact))
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, RouteFrameErrorV2> {
    let end = offset.checked_add(4).ok_or(RouteFrameErrorV2::Truncated)?;
    let exact: [u8; 4] = bytes
        .get(offset..end)
        .ok_or(RouteFrameErrorV2::Truncated)?
        .try_into()
        .map_err(|_| RouteFrameErrorV2::Truncated)?;
    Ok(u32::from_be_bytes(exact))
}

fn read_digest(bytes: &[u8], offset: usize) -> Result<Digest32, RouteFrameErrorV2> {
    let end = offset.checked_add(32).ok_or(RouteFrameErrorV2::Truncated)?;
    bytes
        .get(offset..end)
        .ok_or(RouteFrameErrorV2::Truncated)?
        .try_into()
        .map_err(|_| RouteFrameErrorV2::Truncated)
}

#[cfg(test)]
mod tests {
    use relay::server::RelayV1;
    use relay::{ParticipantId, SenderRoleV1, TimelockSpec};

    use super::*;

    const SENDER: ParticipantId = ParticipantId([0x31; 32]);
    const RECIPIENT: ParticipantId = ParticipantId([0x41; 32]);

    fn wire() -> RouteWireContextV1 {
        RouteWireContextV1 {
            network_id: [0x11; 32],
            session_id: [0x12; 32],
            route_id: [0x13; 32],
            roster_snapshot: [0x14; 32],
            policy_version: 1,
        }
    }

    fn sender() -> RouteSenderV1 {
        RouteSenderV1::new(
            wire(),
            SENDER,
            RECIPIENT,
            SenderRoleV1::Initiator,
            [0x21; 32],
            [0x22; 32],
        )
        .unwrap()
    }

    fn expiry() -> TimelockSpec {
        TimelockSpec::TimestampSeconds { value: 10_000 }
    }

    #[test]
    fn exact_maximum_is_33_canonical_context_bound_frames() {
        assert_eq!(
            MAX_FRAMED_DSC1_BYTES_V2,
            dom_scriptless_transport::MESSAGE_FIXED_LEN_V1
                + dom_scriptless_transport::MessageTypeV1::FinalClaim.payload_cap()
        );
        let tx = sender();
        let message: Vec<u8> = (0..MAX_FRAMED_DSC1_BYTES_V2)
            .map(|index| index as u8)
            .collect();
        let plan = RouteFramePlanV2::new(tx.checkpoint(), &message).unwrap();
        assert_eq!(plan.frame_count(), usize::from(MAX_ROUTE_FRAME_COUNT_V2));
        let mut reconstructed = Vec::new();
        for index in 0..plan.frame_count() {
            let payload = plan.frame_payload(index).unwrap();
            assert!(payload.len() <= MAX_ROUTE_TRANSPORT_PAYLOAD_BYTES);
            let decoded =
                RouteFrameV2::decode_for_flow(payload, wire(), SENDER, RECIPIENT).unwrap();
            assert_eq!(usize::from(decoded.index()), index);
            assert_eq!(decoded.message_digest(), plan.message_digest());
            assert_eq!(decoded.binding_digest(), plan.binding_digest());
            reconstructed.extend_from_slice(decoded.chunk());
        }
        assert_eq!(reconstructed, message);
        verify_complete_message_v2(
            &reconstructed,
            u32::try_from(reconstructed.len()).unwrap(),
            plan.message_digest(),
        )
        .unwrap();
    }

    #[test]
    fn tamper_layout_digest_and_cross_flow_are_refused() {
        let tx = sender();
        let message = vec![0x55; MAX_ROUTE_TRANSPORT_PAYLOAD_BYTES + 1];
        let plan = RouteFramePlanV2::new(tx.checkpoint(), &message).unwrap();
        let frame = plan.frame_payload(0).unwrap();

        let mut wrong_offset = frame.to_vec();
        wrong_offset[91] ^= 1;
        assert!(matches!(
            RouteFrameV2::decode_for_flow(&wrong_offset, wire(), SENDER, RECIPIENT),
            Err(RouteFrameErrorV2::NonCanonicalLayout)
        ));

        let mut wrong_chunk = frame.to_vec();
        let last = wrong_chunk.len() - 1;
        wrong_chunk[last] ^= 1;
        assert!(matches!(
            RouteFrameV2::decode_for_flow(&wrong_chunk, wire(), SENDER, RECIPIENT),
            Err(RouteFrameErrorV2::ChunkDigestMismatch)
        ));

        let mut other_wire = wire();
        other_wire.session_id = [0x99; 32];
        assert!(matches!(
            RouteFrameV2::decode_for_flow(frame, other_wire, SENDER, RECIPIENT),
            Err(RouteFrameErrorV2::FlowBindingMismatch)
        ));
        let mut other_route = wire();
        other_route.route_id = [0x97; 32];
        assert!(matches!(
            RouteFrameV2::decode_for_flow(frame, other_route, SENDER, RECIPIENT),
            Err(RouteFrameErrorV2::FlowBindingMismatch)
        ));
        assert!(matches!(
            RouteFrameV2::decode_for_flow(frame, wire(), ParticipantId([0x98; 32]), RECIPIENT),
            Err(RouteFrameErrorV2::FlowBindingMismatch)
        ));
        assert!(matches!(
            RouteFrameV2::decode_for_flow(frame, wire(), SENDER, ParticipantId([0x96; 32])),
            Err(RouteFrameErrorV2::FlowBindingMismatch)
        ));
    }

    #[test]
    fn direct_and_oversized_messages_have_one_named_path() {
        let tx = sender();
        assert!(matches!(
            RouteFramePlanV2::new(tx.checkpoint(), &[1; 16]),
            Err(RouteFrameSendErrorV2::Frame(
                RouteFrameErrorV2::InvalidMessageLength
            ))
        ));
        let oversized = vec![0; MAX_FRAMED_DSC1_BYTES_V2 + 1];
        assert!(matches!(
            RouteFramePlanV2::new(tx.checkpoint(), &oversized),
            Err(RouteFrameSendErrorV2::Frame(
                RouteFrameErrorV2::InvalidMessageLength
            ))
        ));
    }

    #[test]
    fn sender_helper_requires_ack_advanced_frame_order() {
        let mut tx = sender();
        let message = vec![0x77; MAX_ROUTE_TRANSPORT_PAYLOAD_BYTES + 1];
        let plan = RouteFramePlanV2::new(tx.checkpoint(), &message).unwrap();
        assert!(matches!(
            plan.prepare_frame(&tx, 1, expiry(), [2; 32]),
            Err(RouteFrameSendErrorV2::WrongFrameOrder)
        ));
        let first = plan.prepare_frame(&tx, 0, expiry(), [1; 32]).unwrap();
        let mut relay = RelayV1::new();
        tx.submit_prepared(&mut relay, &first).unwrap();
        plan.prepare_frame(&tx, 1, expiry(), [2; 32]).unwrap();
    }
}
