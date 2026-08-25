//! Canonical intent objects — INTENT_BOOK_DESIGN.md.
//!
//! The board adds no message to the ratified Relay V1 registry (D-019 is
//! closed; operator decision OQ-S3): these objects travel the board's own
//! edge. Their encoding follows the same discipline the workspace already
//! uses for `SettlementTermsV1` — fields in declaration order, integers
//! little-endian, fixed arrays raw, and a decoder that rejects truncation
//! and trailing bytes.
//!
//! The intent CARRIES the ratified `RfqV1` rather than restating it: the
//! acceptance path is the RFQ flow ("cujo aceite continua sendo o fluxo
//! RFQ"), so there is exactly one description of the trade and the board
//! never becomes a second source of truth for it.

use crate::SOLVER_WINDOW_SECONDS;
use kaystra_core::types::Digest32;
use rfq::RfqV1;
use thiserror::Error;

/// The ephemeral per-negotiation key — design: "Uma chave descartável por
/// negociação […] A carteira deriva um par novo da seed, usa naquela
/// negociação, descarta."
///
/// The board treats it as opaque bytes: it is the address of a
/// negotiation, never an identity. Nothing here links two keys, and the
/// board has no operation that takes two negotiations and asks whether
/// they share an owner.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct NegotiationKey(pub [u8; 32]);

impl core::fmt::Debug for NegotiationKey {
    /// Redacted: an intent board that prints negotiation keys into logs
    /// would reconstruct by log correlation the linkage the design removes
    /// from the wire.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "NegotiationKey([REDACTED])")
    }
}

/// Why an intent is malformed.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Error)]
pub enum IntentError {
    /// The buffer ended before the object did.
    #[error("intent encoding is truncated")]
    Truncated,
    /// Bytes remained after a complete object.
    #[error("intent encoding has trailing bytes")]
    TrailingBytes,
    /// A length prefix exceeded the remaining buffer or the accepted bound.
    #[error("intent encoding declares an impossible length")]
    BadLength,
    /// The embedded RFQ did not decode.
    #[error("embedded RFQ is malformed")]
    MalformedRfq,
    /// `quote_deadline_seconds` is at or before publication, so the intent
    /// is dead on arrival.
    #[error("intent deadline is not after publication")]
    DeadlineNotAfterPublication,
    /// The version byte is unknown.
    #[error("unknown intent version")]
    UnknownVersion,
}

/// Upper bound on an embedded encoded RFQ, so a hostile length prefix
/// cannot drive an allocation. Generous relative to the real object; it is
/// an allocation guard, not a protocol rule.
const MAX_EMBEDDED_RFQ_BYTES: usize = 64 * 1024;

/// A published intent.
///
/// `solver_window_end` is not stored: it is DERIVED from
/// `published_at_seconds` so the 120-second rule cannot be bent per intent
/// ("Regra fixa do produto, sem opção de contorno pelo usuário"). Storing
/// it would make it forgeable input; deriving it makes it a law.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IntentV1 {
    /// Structure version.
    pub version: u16,
    /// Digest identifying this intent.
    pub intent_id: Digest32,
    /// The ratified RFQ this intent publishes; the acceptance path.
    pub rfq: RfqV1,
    /// UNIX seconds at publication; phase 1 starts here.
    pub published_at_seconds: u64,
    /// UNIX seconds after which no quote is accepted. Mirrors the RFQ's own
    /// `quote_deadline`, expressed in the board's clock domain.
    pub quote_deadline_seconds: u64,
    /// The ephemeral key addressing this negotiation.
    pub negotiation_key: NegotiationKey,
}

impl IntentV1 {
    /// The end of the private solver window — publication plus the fixed
    /// 120 seconds. Saturating, so a clock near `u64::MAX` cannot wrap the
    /// window into the past and open the public board early.
    pub fn solver_window_end_seconds(&self) -> u64 {
        self.published_at_seconds
            .saturating_add(SOLVER_WINDOW_SECONDS)
    }

    /// Structural validation.
    pub fn validate(&self) -> Result<(), IntentError> {
        if self.version != 1 {
            return Err(IntentError::UnknownVersion);
        }
        if self.quote_deadline_seconds <= self.published_at_seconds {
            return Err(IntentError::DeadlineNotAfterPublication);
        }
        Ok(())
    }

    /// Canonical bytes: `version | intent_id | published | deadline |
    /// negotiation_key | u32_le(rfq_len) | rfq_bytes`.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, IntentError> {
        let rfq_bytes = self
            .rfq
            .canonical_bytes()
            .map_err(|_| IntentError::MalformedRfq)?;
        let rfq_len = u32::try_from(rfq_bytes.len()).map_err(|_| IntentError::BadLength)?;
        let mut out = Vec::with_capacity(2 + 32 + 8 + 8 + 32 + 4 + rfq_bytes.len());
        out.extend_from_slice(&self.version.to_le_bytes());
        out.extend_from_slice(&self.intent_id);
        out.extend_from_slice(&self.published_at_seconds.to_le_bytes());
        out.extend_from_slice(&self.quote_deadline_seconds.to_le_bytes());
        out.extend_from_slice(&self.negotiation_key.0);
        out.extend_from_slice(&rfq_len.to_le_bytes());
        out.extend_from_slice(&rfq_bytes);
        Ok(out)
    }

    /// Strict decode: consumes the whole buffer or fails closed.
    pub fn decode(bytes: &[u8]) -> Result<Self, IntentError> {
        let mut cursor = Cursor::new(bytes);
        let version = cursor.take_u16()?;
        let intent_id: Digest32 = cursor.take_32()?;
        let published_at_seconds = cursor.take_u64()?;
        let quote_deadline_seconds = cursor.take_u64()?;
        let negotiation_key = NegotiationKey(cursor.take_32()?);
        let rfq_len = cursor.take_u32()? as usize;
        if rfq_len > MAX_EMBEDDED_RFQ_BYTES || rfq_len > cursor.remaining() {
            return Err(IntentError::BadLength);
        }
        let rfq_bytes = cursor.take(rfq_len)?;
        let rfq = RfqV1::decode(rfq_bytes).map_err(|_| IntentError::MalformedRfq)?;
        if cursor.remaining() != 0 {
            return Err(IntentError::TrailingBytes);
        }
        let intent = Self {
            version,
            intent_id,
            rfq,
            published_at_seconds,
            quote_deadline_seconds,
            negotiation_key,
        };
        intent.validate()?;
        Ok(intent)
    }
}

/// A minimal strict cursor. Every read is bounds-checked and no read can
/// panic on a hostile buffer.
struct Cursor<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    fn remaining(&self) -> usize {
        self.bytes.len().saturating_sub(self.position)
    }

    fn take(&mut self, count: usize) -> Result<&'a [u8], IntentError> {
        let end = self
            .position
            .checked_add(count)
            .ok_or(IntentError::BadLength)?;
        if end > self.bytes.len() {
            return Err(IntentError::Truncated);
        }
        let slice = &self.bytes[self.position..end];
        self.position = end;
        Ok(slice)
    }

    fn take_u16(&mut self) -> Result<u16, IntentError> {
        let bytes = self.take(2)?;
        Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
    }

    fn take_u32(&mut self) -> Result<u32, IntentError> {
        let bytes = self.take(4)?;
        Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    fn take_u64(&mut self) -> Result<u64, IntentError> {
        let bytes = self.take(8)?;
        let mut buffer = [0u8; 8];
        buffer.copy_from_slice(bytes);
        Ok(u64::from_le_bytes(buffer))
    }

    fn take_32(&mut self) -> Result<[u8; 32], IntentError> {
        let bytes = self.take(32)?;
        let mut buffer = [0u8; 32];
        buffer.copy_from_slice(bytes);
        Ok(buffer)
    }
}
