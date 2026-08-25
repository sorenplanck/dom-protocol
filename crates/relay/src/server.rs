//! The Relay reference implementation (F6 spec v1.0.1 §6.1-6.4,
//! build-order step 6).
//!
//! What a Relay IS: a store-and-forward transport keyed by the ratified
//! idempotency key. What it is NOT, and the code is arranged so it
//! cannot become: an authority. It never decodes a payload, never
//! verifies or produces a signature, never decides an outcome, and
//! holds nothing a participant needs to claim, refund or compensate —
//! §6.3 is proven separately (build-order step 7), and this module is
//! written so that proof is possible.
//!
//! The three ratified rules it does enforce:
//!
//!   §6.1 same key + same bytes  => the SAME ACK, byte for byte (I7);
//!        a resend replays the PERSISTED bytes and never recomputes
//!        anything — no signature, no digest, no payload. The key is
//!        the one D-020 amended: it distinguishes the RECIPIENT, so a
//!        fan-out leg is never mistaken for a resend of another leg.
//!   §6.1 same key + different bytes => `Equivocation`: a named refusal
//!        (I13) that fails the session closed and journals BOTH
//!        conflicting envelopes. A10 makes that journal a PROOF: two
//!        signatures, two digests, one roster key, one position — any
//!        third party can check it with [`verify_equivocation`], and
//!        the Relay's word is not part of the argument.
//!   §6.2 routing reads the envelope HEADER only.
//!
//! Delivery is at-least-once by design (§6.1): the Relay may repeat,
//! and repetition is safe because the recipient's §5.4 pipeline turns
//! a byte-identical redelivery into a named duplicate.

use std::collections::BTreeMap;

use kaystra_core::types::Digest32;

use crate::{EnvelopeError, ParticipantId, RelayEnvelopeV1};

const ACK_MAGIC: &[u8; 8] = b"DOMIRLA1";
const ACK_VERSION: u16 = 1;
/// Exact byte length of a Relay V1 storage acknowledgement.
pub const ACK_V1_LEN: usize = 8 + 2 + 32 + 32 + 32 + 8 + 32;

/// Cap on stored envelopes (I14: bounded before anything is stored).
pub const MAX_STORED_ENVELOPES: usize = 65_536;

/// The idempotency key, as AMENDED by D-020 (operator decision,
/// 2026-08-10): `(session_scope, sender_id, recipient_id, sequence)`.
///
/// The §6.1 key was originally written `(settlement_id, sender_id,
/// message_id | sequence)`. D-020 makes the recipient a MANDATORY
/// distinguisher, because the sequence itself is now defined per
/// ADDRESSED FLOW — `(session_scope, sender_id, recipient_id)` — so a
/// sender fanning out keeps one contiguous chain per recipient. Two
/// recipients legitimately holding `sequence = 0` from the same sender
/// is therefore not a collision and not equivocation; without
/// `recipient_id` in the key it would have looked like both.
///
/// No wire field was added: `session_scope` is the session scope the
/// envelope already carries, and `recipient_id` is already a ratified
/// header field of D-018's `RelayEnvelopeV1`.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct IdempotencyKeyV1 {
    /// The session the envelope belongs to (`session_scope`).
    pub session_id: Digest32,
    /// The sending participant.
    pub sender_id: ParticipantId,
    /// The addressed participant — the D-020 distinguisher.
    pub recipient_id: ParticipantId,
    /// The sender's position in THIS addressed flow.
    pub sequence: u64,
}

impl IdempotencyKeyV1 {
    /// The key of one envelope — read from the HEADER alone (§6.2).
    pub fn of(envelope: &RelayEnvelopeV1) -> Self {
        Self {
            session_id: envelope.session_id,
            sender_id: envelope.sender_id,
            recipient_id: envelope.recipient_id,
            sequence: envelope.sequence,
        }
    }
}

/// The Relay's acknowledgement. It is a RECEIPT of storage, never an
/// authority: it says "these bytes are held under this key", nothing
/// about validity, which only the recipient's §5.4 pipeline decides.
///
/// Every field is a function of the STORED bytes, and there is no
/// field that could differ between a first submission and a resend:
/// the ratified §6.1 rule is "same key + same bytes ⇒ same ACK
/// (byte-identical, I7)", so an ACK that carried, say, a
/// first-time/duplicate flag would already break it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct AckV1 {
    /// The key the bytes are stored under.
    pub key: IdempotencyKeyV1,
    /// The envelope digest — derived from the stored bytes, so the ACK
    /// of a resend is identical without recomputing anything about the
    /// envelope's meaning.
    pub digest: Digest32,
}

impl AckV1 {
    /// Canonical ACK bytes. A lost ACK is regenerated from the persisted
    /// envelope row and therefore returns these exact bytes after restart.
    pub fn canonical_bytes(&self) -> [u8; ACK_V1_LEN] {
        let mut bytes = [0_u8; ACK_V1_LEN];
        let mut offset = 0;
        let version = ACK_VERSION.to_be_bytes();
        let sequence = self.key.sequence.to_be_bytes();
        for part in [
            ACK_MAGIC.as_slice(),
            version.as_slice(),
            self.key.session_id.as_slice(),
            self.key.sender_id.0.as_slice(),
            self.key.recipient_id.0.as_slice(),
            sequence.as_slice(),
            self.digest.as_slice(),
        ] {
            let end = offset + part.len();
            bytes[offset..end].copy_from_slice(part);
            offset = end;
        }
        bytes
    }

    /// Strictly decodes canonical ACK bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self, AckCodecError> {
        if bytes.len() != ACK_V1_LEN {
            return Err(AckCodecError::WrongLength);
        }
        if &bytes[..8] != ACK_MAGIC || u16::from_be_bytes([bytes[8], bytes[9]]) != ACK_VERSION {
            return Err(AckCodecError::WrongDomain);
        }
        let take32 = |start: usize| {
            let mut value = [0_u8; 32];
            value.copy_from_slice(&bytes[start..start + 32]);
            value
        };
        let sequence = u64::from_be_bytes(
            bytes[106..114]
                .try_into()
                .map_err(|_| AckCodecError::WrongLength)?,
        );
        Ok(Self {
            key: IdempotencyKeyV1 {
                session_id: take32(10),
                sender_id: ParticipantId(take32(42)),
                recipient_id: ParticipantId(take32(74)),
                sequence,
            },
            digest: take32(114),
        })
    }
}

/// Fail-closed ACK codec refusals. ACK bytes never contain the opaque payload.
#[derive(Clone, Copy, PartialEq, Eq, Debug, thiserror::Error)]
pub enum AckCodecError {
    /// The ACK is not exactly [`ACK_V1_LEN`] bytes.
    #[error("wrong acknowledgement length")]
    WrongLength,
    /// Magic or version is outside the frozen V1 domain.
    #[error("wrong acknowledgement domain")]
    WrongDomain,
}

/// Two conflicting envelopes at ONE idempotency key, kept exactly as
/// they arrived. This is third-party-verifiable evidence, not an
/// accusation: [`verify_equivocation`] re-derives both digests and
/// checks both signatures under the sender's roster key, so the Relay
/// cannot fabricate it and cannot suppress what it already forwarded.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct EquivocationProofV1 {
    /// The key both envelopes claim.
    pub key: IdempotencyKeyV1,
    /// The canonical bytes stored first.
    pub first: Vec<u8>,
    /// The conflicting canonical bytes.
    pub second: Vec<u8>,
}

/// Named refusals of the Relay (I13).
#[derive(Clone, PartialEq, Eq, Debug, thiserror::Error)]
pub enum RelayRefusal {
    /// The submission did not decode canonically (steps 1-3 of §5.4 —
    /// the Relay applies them to ROUTE, not to judge).
    #[error("codec: {0}")]
    Codec(EnvelopeError),
    /// Two different envelopes at one key: the session fails closed and
    /// the proof travels with the refusal.
    #[error("equivocation")]
    Equivocation(Box<EquivocationProofV1>),
    /// More stored envelopes than [`MAX_STORED_ENVELOPES`] (I14).
    #[error("relay storage is full")]
    StorageFull,
}

/// One stored envelope: the bytes EXACTLY as submitted, plus the header
/// facts routing needs. The payload is never interpreted.
#[derive(Clone, PartialEq, Eq, Debug)]
struct StoredEnvelope {
    bytes: Vec<u8>,
    digest: Digest32,
    recipient_id: ParticipantId,
}

/// The Relay reference: store-and-forward over the ratified key.
///
/// It is deliberately a plain in-memory structure. A production Relay
/// adds durability and a network face; neither changes the rules above,
/// and §6.3 requires that LOSING all of it — process and database —
/// costs a session its transport and nothing else.
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct RelayV1 {
    stored: BTreeMap<IdempotencyKeyV1, StoredEnvelope>,
    /// Which keys are addressed to which recipient. This reference
    /// implementation happens to keep insertion order; no source
    /// document requires a delivery order of the Relay (§6.1 promises
    /// at-least-once only), and no participant may depend on one — the
    /// recipient's §5.4 rules decide what an out-of-order arrival is.
    mailbox: BTreeMap<[u8; 32], Vec<IdempotencyKeyV1>>,
}

impl RelayV1 {
    /// An empty Relay.
    pub fn new() -> Self {
        Self::default()
    }

    /// How many envelopes are held.
    pub fn len(&self) -> usize {
        self.stored.len()
    }

    /// Whether nothing is held.
    pub fn is_empty(&self) -> bool {
        self.stored.is_empty()
    }

    /// Submits one envelope for delivery.
    ///
    /// The ratified §6.1 semantics, in order: decode the header (bounded
    /// and canonical — the Relay must be able to ROUTE, which is the
    /// only reason it parses at all); take the idempotency key from the
    /// header; then
    ///
    /// - key unknown        => store the bytes verbatim, ACK;
    /// - key held, SAME bytes => ACK **byte-identical** to the first
    ///   one, computed from the STORED bytes (I7: a resend replays what
    ///   was persisted and recomputes nothing);
    /// - key held, DIFFERENT bytes => `Equivocation`, carrying both
    ///   envelopes as evidence anyone can check.
    pub fn submit(&mut self, raw: &[u8]) -> Result<AckV1, RelayRefusal> {
        let envelope = RelayEnvelopeV1::decode(raw).map_err(RelayRefusal::Codec)?;
        let key = IdempotencyKeyV1::of(&envelope);
        // Canonical re-encoding, not the caller's buffer: two different
        // byte strings can never decode to one envelope (the codec
        // refuses trailing bytes and non-canonical forms), so this is
        // the same bytes — and taking them from the decoded value means
        // the Relay stores what it will actually resend.
        let canonical = envelope.canonical_bytes().map_err(RelayRefusal::Codec)?;

        if let Some(existing) = self.stored.get(&key) {
            if existing.bytes == canonical {
                // I7: the ACK is derived from the STORED bytes.
                return Ok(AckV1 {
                    key,
                    digest: existing.digest,
                });
            }
            return Err(RelayRefusal::Equivocation(Box::new(EquivocationProofV1 {
                key,
                first: existing.bytes.clone(),
                second: canonical,
            })));
        }

        if self.stored.len() >= MAX_STORED_ENVELOPES {
            return Err(RelayRefusal::StorageFull);
        }
        let digest = envelope.envelope_digest().map_err(RelayRefusal::Codec)?;
        self.stored.insert(
            key,
            StoredEnvelope {
                bytes: canonical,
                digest,
                recipient_id: envelope.recipient_id,
            },
        );
        self.mailbox
            .entry(envelope.recipient_id.0)
            .or_default()
            .push(key);
        Ok(AckV1 { key, digest })
    }

    /// Everything held for one recipient, as the PERSISTED bytes.
    /// Delivery is at-least-once (§6.1): calling this twice returns the
    /// same bytes twice, and that is safe because the recipient's §5.4
    /// pipeline names the second one a duplicate. The ORDER is this
    /// implementation's, not a promise — nothing ratified fixes one.
    pub fn deliver(&self, recipient: &ParticipantId) -> Vec<Vec<u8>> {
        self.mailbox
            .get(&recipient.0)
            .map(|keys| {
                keys.iter()
                    .filter_map(|k| self.stored.get(k))
                    .filter(|e| e.recipient_id == *recipient)
                    .map(|e| e.bytes.clone())
                    .collect()
            })
            .unwrap_or_default()
    }

    /// The bytes held under one key, if any — the resend path.
    pub fn stored_bytes(&self, key: &IdempotencyKeyV1) -> Option<&[u8]> {
        self.stored.get(key).map(|e| e.bytes.as_slice())
    }
}

/// Independently checks an equivocation proof: both envelopes decode,
/// both claim the SAME idempotency key, their bytes DIFFER, and both
/// signatures verify under the same roster key at the snapshot each
/// envelope names.
///
/// This is what makes §6.1's equivocation rule enforceable against a
/// signer rather than merely detectable by one Relay: the proof stands
/// on the sender's own two signatures, and this function needs nothing
/// from the Relay that produced it.
pub fn verify_equivocation(
    proof: &EquivocationProofV1,
    rosters: &crate::auth::RosterRegistryV1,
) -> Result<(), EquivocationVerdict> {
    if proof.first == proof.second {
        return Err(EquivocationVerdict::NotConflicting);
    }
    let first = RelayEnvelopeV1::decode(&proof.first).map_err(EquivocationVerdict::Codec)?;
    let second = RelayEnvelopeV1::decode(&proof.second).map_err(EquivocationVerdict::Codec)?;
    if IdempotencyKeyV1::of(&first) != proof.key || IdempotencyKeyV1::of(&second) != proof.key {
        return Err(EquivocationVerdict::KeyMismatch);
    }
    for envelope in [&first, &second] {
        let snapshot = rosters
            .snapshot(&envelope.roster_snapshot)
            .ok_or(EquivocationVerdict::UnknownRosterSnapshot)?;
        let member = snapshot
            .member(&envelope.sender_id)
            .ok_or(EquivocationVerdict::SenderNotInRoster)?;
        let digest = envelope
            .envelope_digest()
            .map_err(EquivocationVerdict::Codec)?;
        crate::auth::verify_roster_signature(&member.xonly_key, &digest, &envelope.signature)
            .map_err(|_| EquivocationVerdict::SignatureDoesNotVerify)?;
    }
    Ok(())
}

/// Why an equivocation proof does NOT stand (I13). A proof that fails
/// any of these is not evidence of anything — which is exactly the
/// protection against a Relay that invents accusations.
#[derive(Clone, Copy, PartialEq, Eq, Debug, thiserror::Error)]
pub enum EquivocationVerdict {
    /// The two envelopes are byte-identical: a duplicate, not a
    /// conflict.
    #[error("the two envelopes are identical")]
    NotConflicting,
    /// One of them does not decode canonically.
    #[error("codec: {0}")]
    Codec(EnvelopeError),
    /// They do not both claim the key the proof names.
    #[error("the envelopes do not share the claimed key")]
    KeyMismatch,
    /// The roster snapshot an envelope names is unknown to the checker.
    #[error("unknown roster snapshot")]
    UnknownRosterSnapshot,
    /// The sender is not a member of that snapshot.
    #[error("sender not in the roster snapshot")]
    SenderNotInRoster,
    /// A signature does not verify: whoever produced that envelope, it
    /// was not the roster member — so this proves nothing against them.
    #[error("a signature does not verify")]
    SignatureDoesNotVerify,
}
