//! `relay`: the authenticated envelope of the untrusted transport
//! (Foundation Document §4.6; F6 specification §5, A10 RATIFIED by
//! D-018 on 2026-08-10).
//!
//! This crate carries the WIRE layer of the ratified decision: the
//! [`RelayEnvelopeV1`] canonical codec and the domain-separated
//! [`RelayEnvelopeV1::envelope_digest`] the sender's BIP340 roster-key
//! signature signs. The signature bytes are opaque here — production
//! and verification against the roster snapshot belong to the
//! validation pipeline (F6 spec §5.4, build-order step 5), which also
//! owns replay, gap, equivocation and transcript-continuity state.
//!
//! What the codec DOES enforce, fail-closed and in order, are the
//! §5.4 steps that need no roster: the size is bounded BEFORE any
//! allocation (step 1, I14), the encoding is canonical (step 2), and
//! unknown versions, roles and flags are rejected (step 3). The Relay
//! never decodes payloads — the payload is opaque bytes bound by
//! length and digest.

#![forbid(unsafe_code)]

use blake2::{
    digest::{Update, VariableOutput},
    Blake2bVar,
};
use kaystra_core::types::Digest32;

// Re-exported so envelope consumers can name the field types without
// importing kaystra-core themselves (the uspe/rfq precedent).
pub use kaystra_core::types::{ParticipantId, TimelockSpec};

pub mod auth;
#[cfg(feature = "relay-fault-injection")]
pub mod fault;
#[cfg(feature = "production-durable")]
pub mod production;
pub mod recovery;
pub mod server;

/// Leading magic of every canonical envelope encoding — the
/// `protocol_id` of the ratified digest list.
pub const ENVELOPE_MAGIC: &[u8; 8] = b"DOMIRLY1";
/// Frozen envelope wire version. Any other version fails closed.
pub const ENVELOPE_WIRE_VERSION: u16 = 1;
/// Domain-separation prefix of the signed envelope digest — the
/// RATIFIED string of F6 spec §5.2, byte for byte.
pub const ENVELOPE_DOMAIN: &[u8] = b"DOM-INTEROP/RELAY-ENVELOPE/V1";
/// Domain-separation prefix of the payload digest.
pub const PAYLOAD_DOMAIN: &[u8] = b"DOM-INTEROP/RELAY-PAYLOAD/V1\0";

/// Hard cap on the opaque payload (I14: bounded before stored).
pub const MAX_PAYLOAD_BYTES: usize = 16_384;
/// Fixed size of everything in the wire that is not the payload:
/// magic, version, the ratified header fields, and the signature.
pub const ENVELOPE_OVERHEAD_BYTES: usize =
    8 + 2 + 32 + 2 + 32 + 32 + 32 + 32 + 1 + 8 + 32 + 4 + 32 + 9 + 4 + 32 + 64;
/// Hard cap on one whole envelope — checked BEFORE decoding begins
/// (§5.4 step 1).
pub const MAX_ENVELOPE_BYTES: usize = ENVELOPE_OVERHEAD_BYTES + MAX_PAYLOAD_BYTES;

/// The sender's role in the session. The role gates which
/// `message_type`s the sender may emit (§5.4 step 6 — enforced by the
/// validation pipeline against the roster; the codec only guarantees
/// the tag is inside the frozen set).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SenderRoleV1 {
    /// The settlement initiator.
    Initiator,
    /// A quoting/executing solver.
    Solver,
    /// A non-signing observer.
    Observer,
}

/// The authenticated envelope (F6 spec §5.2 — every field of the
/// ratified digest list, plus the opaque payload and the signature).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct RelayEnvelopeV1 {
    /// Network identity (32-byte registry id); evidence from another
    /// network is invalid even when everything else matches.
    pub network_id: Digest32,
    /// Message type (registry-based; the recipient's accepted set is
    /// enforced by the validation pipeline).
    pub message_type: u16,
    /// Session the message belongs to.
    pub session_id: Digest32,
    /// Route binding of the session.
    pub route_id: Digest32,
    /// Sending participant (roster member at `roster_snapshot`).
    pub sender_id: ParticipantId,
    /// Intended recipient; anyone else must refuse (§5.4 step 4).
    pub recipient_id: ParticipantId,
    /// The sender's role.
    pub sender_role: SenderRoleV1,
    /// Per-(session, sender) monotonic sequence.
    pub sequence: u64,
    /// Hash chaining to the previous accepted envelope (§5.4 step 9).
    pub previous_transcript_hash: Digest32,
    /// The opaque payload. The Relay NEVER decodes it.
    pub payload: Vec<u8>,
    /// Envelope expiry.
    pub expiry: TimelockSpec,
    /// Protocol policy version.
    pub policy_version: u32,
    /// Roster snapshot (version or root) the sender's key lives in —
    /// keeps a later key rotation from making historical validity
    /// ambiguous (ratified A10).
    pub roster_snapshot: Digest32,
    /// BIP340 signature by the sender's canonical roster key over
    /// [`Self::envelope_digest`]. Opaque at this layer.
    pub signature: [u8; 64],
}

/// Fail-closed refusals of the envelope codec, each named (I13).
#[derive(Clone, Copy, PartialEq, Eq, Debug, thiserror::Error)]
pub enum EnvelopeError {
    /// The whole encoding exceeds [`MAX_ENVELOPE_BYTES`] — refused
    /// before any parsing or allocation (§5.4 step 1).
    #[error("envelope exceeds the size bound")]
    EnvelopeTooLarge,
    /// The payload exceeds [`MAX_PAYLOAD_BYTES`].
    #[error("payload exceeds the size bound")]
    PayloadTooLarge,
    /// Encoding does not start with the frozen magic.
    #[error("invalid magic")]
    InvalidMagic,
    /// Wire version outside the frozen set.
    #[error("invalid version")]
    InvalidVersion,
    /// Encoding ends before the structure is complete.
    #[error("truncated encoding")]
    TruncatedEncoding,
    /// A role or timelock byte carries a tag outside its frozen set.
    #[error("unknown enum tag")]
    UnknownTag,
    /// Bytes remain after the structure is complete.
    #[error("trailing bytes")]
    TrailingBytes,
    /// The declared payload length does not equal the payload.
    #[error("payload length mismatch")]
    PayloadLengthMismatch,
    /// The BLAKE2b-256 instance could not be initialized.
    #[error("hash initialization failed")]
    HashInitialization,
}

fn put_u16(out: &mut Vec<u8>, v: u16) {
    out.extend_from_slice(&v.to_be_bytes());
}
fn put_u32(out: &mut Vec<u8>, v: u32) {
    out.extend_from_slice(&v.to_be_bytes());
}
fn put_u64(out: &mut Vec<u8>, v: u64) {
    out.extend_from_slice(&v.to_be_bytes());
}

fn put_timelock(out: &mut Vec<u8>, v: TimelockSpec) {
    match v {
        TimelockSpec::BlockHeight { value } => {
            out.push(0x01);
            put_u64(out, value);
        }
        TimelockSpec::TimestampSeconds { value } => {
            out.push(0x02);
            put_u64(out, value);
        }
        TimelockSpec::BtcTime512s { value } => {
            out.push(0x03);
            put_u64(out, value);
        }
    }
}

fn role_tag(role: SenderRoleV1) -> u8 {
    match role {
        SenderRoleV1::Initiator => 0x01,
        SenderRoleV1::Solver => 0x02,
        SenderRoleV1::Observer => 0x03,
    }
}

struct Cursor<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 0 }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], EnvelopeError> {
        let end = self
            .pos
            .checked_add(n)
            .ok_or(EnvelopeError::TruncatedEncoding)?;
        if end > self.bytes.len() {
            return Err(EnvelopeError::TruncatedEncoding);
        }
        let slice = &self.bytes[self.pos..end];
        self.pos = end;
        Ok(slice)
    }

    fn take_array<const N: usize>(&mut self) -> Result<[u8; N], EnvelopeError> {
        let slice = self.take(N)?;
        let mut out = [0u8; N];
        out.copy_from_slice(slice);
        Ok(out)
    }

    fn take_u8(&mut self) -> Result<u8, EnvelopeError> {
        Ok(self.take(1)?[0])
    }

    fn take_u16(&mut self) -> Result<u16, EnvelopeError> {
        Ok(u16::from_be_bytes(self.take_array()?))
    }

    fn take_u32(&mut self) -> Result<u32, EnvelopeError> {
        Ok(u32::from_be_bytes(self.take_array()?))
    }

    fn take_u64(&mut self) -> Result<u64, EnvelopeError> {
        Ok(u64::from_be_bytes(self.take_array()?))
    }

    fn take_32(&mut self) -> Result<[u8; 32], EnvelopeError> {
        self.take_array()
    }

    fn finished(&self) -> bool {
        self.pos == self.bytes.len()
    }
}

fn take_timelock(c: &mut Cursor<'_>) -> Result<TimelockSpec, EnvelopeError> {
    let tag = c.take_u8()?;
    let value = c.take_u64()?;
    match tag {
        0x01 => Ok(TimelockSpec::BlockHeight { value }),
        0x02 => Ok(TimelockSpec::TimestampSeconds { value }),
        0x03 => Ok(TimelockSpec::BtcTime512s { value }),
        _ => Err(EnvelopeError::UnknownTag),
    }
}

fn digest32(domain: &[u8], bytes: &[u8]) -> Result<Digest32, EnvelopeError> {
    let mut h = Blake2bVar::new(32).map_err(|_| EnvelopeError::HashInitialization)?;
    h.update(domain);
    h.update(bytes);
    let mut out = [0u8; 32];
    h.finalize_variable(&mut out)
        .map_err(|_| EnvelopeError::HashInitialization)?;
    Ok(out)
}

/// `BLAKE2b-256(PAYLOAD_DOMAIN || payload)` — the `payload_hash` of the
/// ratified digest list.
pub fn payload_hash(payload: &[u8]) -> Result<Digest32, EnvelopeError> {
    digest32(PAYLOAD_DOMAIN, payload)
}

impl RelayEnvelopeV1 {
    /// Structural validity: the payload bound (I14). Everything else
    /// structural is enforced by construction of the types.
    pub fn validate(&self) -> Result<(), EnvelopeError> {
        if self.payload.len() > MAX_PAYLOAD_BYTES {
            return Err(EnvelopeError::PayloadTooLarge);
        }
        Ok(())
    }

    /// The canonical UNSIGNED envelope: every field of the ratified
    /// §5.2 digest list in wire order — `protocol_id` (the magic),
    /// `protocol_version`, `network_id`, `message_type`, `session_id`,
    /// `route_id`, `sender_id`, `recipient_id`, `sender_role`,
    /// `sequence`, `previous_transcript_hash`, `payload_length`,
    /// `payload_hash`, `expiry`, `policy_version`, `roster_snapshot` —
    /// followed by the payload bytes. The signature is the ONLY thing
    /// excluded.
    pub fn unsigned_bytes(&self) -> Result<Vec<u8>, EnvelopeError> {
        self.validate()?;
        let mut out = Vec::with_capacity(ENVELOPE_OVERHEAD_BYTES - 64 + self.payload.len());
        out.extend_from_slice(ENVELOPE_MAGIC);
        put_u16(&mut out, ENVELOPE_WIRE_VERSION);
        out.extend_from_slice(&self.network_id);
        put_u16(&mut out, self.message_type);
        out.extend_from_slice(&self.session_id);
        out.extend_from_slice(&self.route_id);
        out.extend_from_slice(&self.sender_id.0);
        out.extend_from_slice(&self.recipient_id.0);
        out.push(role_tag(self.sender_role));
        put_u64(&mut out, self.sequence);
        out.extend_from_slice(&self.previous_transcript_hash);
        put_u32(&mut out, self.payload.len() as u32);
        out.extend_from_slice(&payload_hash(&self.payload)?);
        put_timelock(&mut out, self.expiry);
        put_u32(&mut out, self.policy_version);
        out.extend_from_slice(&self.roster_snapshot);
        out.extend_from_slice(&self.payload);
        Ok(out)
    }

    /// The RATIFIED signed digest:
    /// `BLAKE2b-256("DOM-INTEROP/RELAY-ENVELOPE/V1" || unsigned bytes)`.
    /// These are the 32 bytes the sender's BIP340 roster key signs, and
    /// the value the transcript chains through.
    pub fn envelope_digest(&self) -> Result<Digest32, EnvelopeError> {
        digest32(ENVELOPE_DOMAIN, &self.unsigned_bytes()?)
    }

    /// Canonical wire: the unsigned envelope with the signature
    /// appended. Retransmission MUST resend exactly these persisted
    /// bytes (I7) — same key + different bytes is equivocation.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, EnvelopeError> {
        let mut out = self.unsigned_bytes()?;
        out.extend_from_slice(&self.signature);
        Ok(out)
    }

    /// Strict decoder, in the ratified §5.4 order as far as a codec
    /// reaches: the SIZE BOUND is checked before anything is parsed or
    /// allocated (step 1); the encoding must be canonical (step 2);
    /// unknown versions and tags are refused (step 3); the payload is
    /// bound by declared length and digest. Roster, role permission,
    /// signature, replay and transcript continuity are the validation
    /// pipeline's steps 4–10 and happen AFTER this returns.
    pub fn decode(bytes: &[u8]) -> Result<Self, EnvelopeError> {
        if bytes.len() > MAX_ENVELOPE_BYTES {
            return Err(EnvelopeError::EnvelopeTooLarge);
        }
        let mut c = Cursor::new(bytes);
        if c.take(ENVELOPE_MAGIC.len())? != ENVELOPE_MAGIC {
            return Err(EnvelopeError::InvalidMagic);
        }
        if c.take_u16()? != ENVELOPE_WIRE_VERSION {
            return Err(EnvelopeError::InvalidVersion);
        }
        let network_id = c.take_32()?;
        let message_type = c.take_u16()?;
        let session_id = c.take_32()?;
        let route_id = c.take_32()?;
        let sender_id = ParticipantId(c.take_32()?);
        let recipient_id = ParticipantId(c.take_32()?);
        let sender_role = match c.take_u8()? {
            0x01 => SenderRoleV1::Initiator,
            0x02 => SenderRoleV1::Solver,
            0x03 => SenderRoleV1::Observer,
            _ => return Err(EnvelopeError::UnknownTag),
        };
        let sequence = c.take_u64()?;
        let previous_transcript_hash = c.take_32()?;
        let payload_length = c.take_u32()? as usize;
        if payload_length > MAX_PAYLOAD_BYTES {
            return Err(EnvelopeError::PayloadTooLarge);
        }
        let declared_hash = c.take_32()?;
        let expiry = take_timelock(&mut c)?;
        let policy_version = c.take_u32()?;
        let roster_snapshot = c.take_32()?;
        let payload = c.take(payload_length)?.to_vec();
        let signature: [u8; 64] = c.take_array()?;
        if !c.finished() {
            return Err(EnvelopeError::TrailingBytes);
        }
        if payload_hash(&payload)? != declared_hash {
            return Err(EnvelopeError::PayloadLengthMismatch);
        }
        let envelope = Self {
            network_id,
            message_type,
            session_id,
            route_id,
            sender_id,
            recipient_id,
            sender_role,
            sequence,
            previous_transcript_hash,
            payload,
            expiry,
            policy_version,
            roster_snapshot,
            signature,
        };
        envelope.validate()?;
        Ok(envelope)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn b32(x: u8) -> [u8; 32] {
        [x; 32]
    }

    fn sample() -> RelayEnvelopeV1 {
        RelayEnvelopeV1 {
            network_id: b32(0x11),
            message_type: 7,
            session_id: b32(0x22),
            route_id: b32(0x33),
            sender_id: ParticipantId(b32(0x44)),
            recipient_id: ParticipantId(b32(0x55)),
            sender_role: SenderRoleV1::Solver,
            sequence: 9,
            previous_transcript_hash: b32(0x66),
            payload: vec![0xd0, 0xd1, 0xd2, 0xd3],
            expiry: TimelockSpec::TimestampSeconds { value: 10_000 },
            policy_version: 1,
            roster_snapshot: b32(0x77),
            signature: [0xabu8; 64],
        }
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn roundtrip_is_the_identity() {
        let envelope = sample();
        assert_eq!(
            RelayEnvelopeV1::decode(&envelope.canonical_bytes().unwrap()).unwrap(),
            envelope
        );
    }

    /// Frozen vectors: the encoding length and the ratified signed
    /// digest of the sample. A codec change that alters any byte breaks
    /// these on purpose — and a digest change is a MATERIAL change
    /// requiring a new version, a decision record and express
    /// ratification (D-018 adoption order).
    #[test]
    fn frozen_vectors_hold() {
        let envelope = sample();
        let bytes = envelope.canonical_bytes().unwrap();
        assert_eq!(&bytes[..10], b"DOMIRLY1\x00\x01");
        assert_eq!(bytes.len(), ENVELOPE_OVERHEAD_BYTES + 4);
        assert_eq!(
            hex(&envelope.envelope_digest().unwrap()),
            "5ea98453e3017707f462abc48b5b481346fabe04ece0f49ed8cee31a55ed8d1d",
        );
    }

    #[test]
    fn size_bound_is_checked_before_parsing() {
        // A garbage buffer over the cap is refused as TOO LARGE, not as
        // bad magic: nothing was parsed, nothing was allocated (I14).
        let oversized = vec![0u8; MAX_ENVELOPE_BYTES + 1];
        assert_eq!(
            RelayEnvelopeV1::decode(&oversized).unwrap_err(),
            EnvelopeError::EnvelopeTooLarge
        );
        let mut envelope = sample();
        envelope.payload = vec![0u8; MAX_PAYLOAD_BYTES + 1];
        assert_eq!(
            envelope.canonical_bytes().unwrap_err(),
            EnvelopeError::PayloadTooLarge
        );
    }

    #[test]
    fn payload_binding_is_enforced() {
        // Flip a payload byte: the declared digest no longer matches.
        let bytes = sample().canonical_bytes().unwrap();
        let payload_at = bytes.len() - 64 - 4;
        let mut tampered = bytes.clone();
        tampered[payload_at] ^= 0x01;
        assert_eq!(
            RelayEnvelopeV1::decode(&tampered).unwrap_err(),
            EnvelopeError::PayloadLengthMismatch
        );
    }

    #[test]
    fn decode_rejects_magic_version_truncation_trailing_and_tags() {
        let bytes = sample().canonical_bytes().unwrap();

        let mut wrong_magic = bytes.clone();
        wrong_magic[0] ^= 0x01;
        assert_eq!(
            RelayEnvelopeV1::decode(&wrong_magic).unwrap_err(),
            EnvelopeError::InvalidMagic
        );

        let mut wrong_version = bytes.clone();
        wrong_version[9] ^= 0x01;
        assert_eq!(
            RelayEnvelopeV1::decode(&wrong_version).unwrap_err(),
            EnvelopeError::InvalidVersion
        );

        for cut in [0, 1, 9, 10, bytes.len() - 1] {
            assert_eq!(
                RelayEnvelopeV1::decode(&bytes[..cut]).unwrap_err(),
                EnvelopeError::TruncatedEncoding,
            );
        }

        let mut trailing = bytes.clone();
        trailing.push(0x00);
        assert_eq!(
            RelayEnvelopeV1::decode(&trailing).unwrap_err(),
            EnvelopeError::TrailingBytes
        );

        // The role tag sits right after the two participant ids.
        let role_at = 8 + 2 + 32 + 2 + 32 + 32 + 32 + 32;
        assert_eq!(bytes[role_at], 0x02);
        let mut bad_role = bytes.clone();
        bad_role[role_at] = 0x7f;
        assert_eq!(
            RelayEnvelopeV1::decode(&bad_role).unwrap_err(),
            EnvelopeError::UnknownTag
        );
    }

    #[test]
    fn digest_covers_every_unsigned_byte_and_not_the_signature() {
        let envelope = sample();
        let digest = envelope.envelope_digest().unwrap();
        let unsigned = envelope.unsigned_bytes().unwrap();
        for i in 0..unsigned.len() {
            let mut flipped = unsigned.clone();
            flipped[i] ^= 0x01;
            let other = digest32(ENVELOPE_DOMAIN, &flipped).unwrap();
            assert_ne!(digest, other, "byte {i} does not participate in the digest");
        }
        // The signature is excluded: re-signing changes nothing in the
        // signed material (it could not — the signature signs it).
        let mut resigned = envelope.clone();
        resigned.signature = [0xcd; 64];
        assert_eq!(digest, resigned.envelope_digest().unwrap());
    }

    #[test]
    fn transcript_chaining_binds_the_previous_digest() {
        // An envelope chaining to a different predecessor has a
        // different digest — the §5.4 step-9 continuity check rests on
        // this.
        let a = sample();
        let mut b = sample();
        b.previous_transcript_hash = a.envelope_digest().unwrap();
        assert_ne!(a.envelope_digest().unwrap(), b.envelope_digest().unwrap());
    }
}
