//! Canonical assurance journal frame (F4 spec §9, D-017).
//!
//! One accepted transition = one frame: `(revision, terms binding, event,
//! next state, effects)`, canonically encoded under the same F2 §6.2
//! discipline as every other frozen wire in this workspace. The frame is
//! the durable half of the persist-before-effect rule: the driver appends
//! it — and the append commits — BEFORE any effect leaves the process.
//!
//! The codec lives here, chain- and store-neutral, so that the journal's
//! meaning is defined exactly once; the dev harness supplies the storage
//! (the ratified `store` crate under [`ASSURANCE_JOURNAL_KIND`]).
//!
//! Recovery discipline (enforced by the driver, stated here because the
//! frame format is what makes it possible): replay does not TRUST frames
//! — it re-applies each frame's event through the real
//! [`assurance_transition`](crate::assurance_transition) and fails closed
//! if the machine disagrees. A forged or corrupted journal can therefore
//! never resurrect a state the machine would not have reached.

use crate::{AssuranceEffect, AssuranceEvent, AssuranceState};

/// Leading magic of every canonical frame encoding.
pub const FRAME_MAGIC: &[u8; 8] = b"DOMIAJR1";
/// Frozen frame wire version. Any other version fails closed.
pub const FRAME_VERSION: u16 = 1;
/// Journal `kind` under which assurance frames are stored (spec §9). The
/// assurance log holds nothing else; any other kind is a foreign record.
pub const ASSURANCE_JOURNAL_KIND: u16 = 0xF401;
/// Hard bound on one encoded frame. Applied before allocation (I14).
pub const MAX_FRAME_BYTES: usize = 512;
/// Hard bound on effects per frame. The machine emits at most two.
pub const MAX_FRAME_EFFECTS: usize = 4;

/// One accepted transition, as persisted.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct AssuranceFrameV1 {
    /// 1-based, strictly contiguous position in this obligation's log.
    pub revision: u64,
    /// Terms binding of the obligation. Detects a log swapped between
    /// obligations at replay time.
    pub terms_hash: [u8; 32],
    /// The event the machine accepted.
    pub event: AssuranceEvent,
    /// The state the machine moved to.
    pub next_state: AssuranceState,
    /// The effects the machine emitted, in order (`PersistState` first).
    pub effects: Vec<AssuranceEffect>,
}

/// Frame codec failures. Fail-closed: no partially decoded frame escapes.
#[derive(Clone, Copy, PartialEq, Eq, Debug, thiserror::Error)]
pub enum FrameError {
    /// Encoding does not start with [`FRAME_MAGIC`].
    #[error("invalid frame magic")]
    InvalidMagic,
    /// Wire version is not [`FRAME_VERSION`].
    #[error("invalid frame version")]
    InvalidVersion,
    /// Encoding ends before the structure is complete.
    #[error("truncated frame")]
    Truncated,
    /// A tag byte outside its frozen set.
    #[error("unknown frame tag")]
    UnknownTag,
    /// Bytes remain after the structure is complete.
    #[error("trailing bytes")]
    TrailingBytes,
    /// More effects than [`MAX_FRAME_EFFECTS`] (checked before decoding
    /// them) or a frame larger than [`MAX_FRAME_BYTES`].
    #[error("frame bounds exceeded")]
    BoundsExceeded,
}

fn put_u16(out: &mut Vec<u8>, v: u16) {
    out.extend_from_slice(&v.to_be_bytes());
}
fn put_u64(out: &mut Vec<u8>, v: u64) {
    out.extend_from_slice(&v.to_be_bytes());
}
fn put_u128(out: &mut Vec<u8>, v: u128) {
    out.extend_from_slice(&v.to_be_bytes());
}

fn state_tag(state: AssuranceState) -> u8 {
    match state {
        AssuranceState::NotRequired => 0x01,
        AssuranceState::BondRequired => 0x02,
        AssuranceState::BondLocking => 0x03,
        AssuranceState::Protected => 0x04,
        AssuranceState::ReleasePending => 0x05,
        AssuranceState::Released => 0x06,
        AssuranceState::ClaimWindow => 0x07,
        AssuranceState::EvidenceVerification => 0x08,
        AssuranceState::ClaimRejected => 0x09,
        AssuranceState::Slashed => 0x0a,
        AssuranceState::Compensated => 0x0b,
    }
}

fn take_state(c: &mut Cursor<'_>) -> Result<AssuranceState, FrameError> {
    Ok(match c.take_u8()? {
        0x01 => AssuranceState::NotRequired,
        0x02 => AssuranceState::BondRequired,
        0x03 => AssuranceState::BondLocking,
        0x04 => AssuranceState::Protected,
        0x05 => AssuranceState::ReleasePending,
        0x06 => AssuranceState::Released,
        0x07 => AssuranceState::ClaimWindow,
        0x08 => AssuranceState::EvidenceVerification,
        0x09 => AssuranceState::ClaimRejected,
        0x0a => AssuranceState::Slashed,
        0x0b => AssuranceState::Compensated,
        _ => return Err(FrameError::UnknownTag),
    })
}

fn put_event(out: &mut Vec<u8>, event: &AssuranceEvent) {
    match event {
        AssuranceEvent::BondLockObserved => out.push(0x01),
        AssuranceEvent::CollateralVerified { terms_hash } => {
            out.push(0x02);
            out.extend_from_slice(terms_hash);
        }
        AssuranceEvent::ObligationSettled => out.push(0x03),
        AssuranceEvent::ObligationFailed => out.push(0x04),
        AssuranceEvent::ReleaseConfirmed => out.push(0x05),
        AssuranceEvent::CompensationClaimed { terms_hash } => {
            out.push(0x06);
            out.extend_from_slice(terms_hash);
        }
        AssuranceEvent::EvidenceVerified { valid } => {
            out.push(0x07);
            out.push(u8::from(*valid));
        }
        AssuranceEvent::CollateralDeadlineExpired => out.push(0x08),
        AssuranceEvent::ClaimWindowExpired => out.push(0x09),
        AssuranceEvent::EvidenceDeadlineExpired => out.push(0x0a),
        AssuranceEvent::CompensationConfirmed { amount } => {
            out.push(0x0b);
            put_u128(out, *amount);
        }
    }
}

fn take_event(c: &mut Cursor<'_>) -> Result<AssuranceEvent, FrameError> {
    Ok(match c.take_u8()? {
        0x01 => AssuranceEvent::BondLockObserved,
        0x02 => AssuranceEvent::CollateralVerified {
            terms_hash: c.take_32()?,
        },
        0x03 => AssuranceEvent::ObligationSettled,
        0x04 => AssuranceEvent::ObligationFailed,
        0x05 => AssuranceEvent::ReleaseConfirmed,
        0x06 => AssuranceEvent::CompensationClaimed {
            terms_hash: c.take_32()?,
        },
        0x07 => AssuranceEvent::EvidenceVerified {
            valid: match c.take_u8()? {
                0x00 => false,
                0x01 => true,
                _ => return Err(FrameError::UnknownTag),
            },
        },
        0x08 => AssuranceEvent::CollateralDeadlineExpired,
        0x09 => AssuranceEvent::ClaimWindowExpired,
        0x0a => AssuranceEvent::EvidenceDeadlineExpired,
        0x0b => AssuranceEvent::CompensationConfirmed {
            amount: c.take_u128()?,
        },
        _ => return Err(FrameError::UnknownTag),
    })
}

fn put_effect(out: &mut Vec<u8>, effect: &AssuranceEffect) {
    match effect {
        AssuranceEffect::PersistState(state) => {
            out.push(0x01);
            out.push(state_tag(*state));
        }
        AssuranceEffect::IssueCertificate { terms_hash } => {
            out.push(0x02);
            out.extend_from_slice(terms_hash);
        }
        AssuranceEffect::AuthorizeRelease => out.push(0x03),
        AssuranceEffect::ExecuteSlash => out.push(0x04),
        AssuranceEffect::RecordEconomicOutcome(state) => {
            out.push(0x05);
            out.push(state_tag(*state));
        }
    }
}

fn take_effect(c: &mut Cursor<'_>) -> Result<AssuranceEffect, FrameError> {
    Ok(match c.take_u8()? {
        0x01 => AssuranceEffect::PersistState(take_state(c)?),
        0x02 => AssuranceEffect::IssueCertificate {
            terms_hash: c.take_32()?,
        },
        0x03 => AssuranceEffect::AuthorizeRelease,
        0x04 => AssuranceEffect::ExecuteSlash,
        0x05 => AssuranceEffect::RecordEconomicOutcome(take_state(c)?),
        _ => return Err(FrameError::UnknownTag),
    })
}

/// Strict big-endian cursor; every read is bounds-checked.
struct Cursor<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 0 }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], FrameError> {
        let end = self.pos.checked_add(n).ok_or(FrameError::Truncated)?;
        if end > self.bytes.len() {
            return Err(FrameError::Truncated);
        }
        let slice = &self.bytes[self.pos..end];
        self.pos = end;
        Ok(slice)
    }

    fn take_array<const N: usize>(&mut self) -> Result<[u8; N], FrameError> {
        let slice = self.take(N)?;
        let mut out = [0u8; N];
        out.copy_from_slice(slice);
        Ok(out)
    }

    fn take_u8(&mut self) -> Result<u8, FrameError> {
        Ok(self.take(1)?[0])
    }

    fn take_u16(&mut self) -> Result<u16, FrameError> {
        Ok(u16::from_be_bytes(self.take_array()?))
    }

    fn take_u64(&mut self) -> Result<u64, FrameError> {
        Ok(u64::from_be_bytes(self.take_array()?))
    }

    fn take_u128(&mut self) -> Result<u128, FrameError> {
        Ok(u128::from_be_bytes(self.take_array()?))
    }

    fn take_32(&mut self) -> Result<[u8; 32], FrameError> {
        self.take_array()
    }

    fn finished(&self) -> bool {
        self.pos == self.bytes.len()
    }
}

impl AssuranceFrameV1 {
    /// Canonical wire encoding: magic, version, fixed field order, all
    /// integers big-endian.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, FrameError> {
        if self.effects.len() > MAX_FRAME_EFFECTS {
            return Err(FrameError::BoundsExceeded);
        }
        let mut out = Vec::with_capacity(128);
        out.extend_from_slice(FRAME_MAGIC);
        put_u16(&mut out, FRAME_VERSION);
        put_u64(&mut out, self.revision);
        out.extend_from_slice(&self.terms_hash);
        put_event(&mut out, &self.event);
        out.push(state_tag(self.next_state));
        out.push(self.effects.len() as u8);
        for effect in &self.effects {
            put_effect(&mut out, effect);
        }
        if out.len() > MAX_FRAME_BYTES {
            return Err(FrameError::BoundsExceeded);
        }
        Ok(out)
    }

    /// Strict decoder. Rejects, in order: oversized input (before any
    /// allocation), wrong magic, unknown version, truncation, unknown
    /// tags, an effect count above the bound, trailing bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self, FrameError> {
        if bytes.len() > MAX_FRAME_BYTES {
            return Err(FrameError::BoundsExceeded);
        }
        let mut c = Cursor::new(bytes);
        if c.take(FRAME_MAGIC.len())? != FRAME_MAGIC {
            return Err(FrameError::InvalidMagic);
        }
        if c.take_u16()? != FRAME_VERSION {
            return Err(FrameError::InvalidVersion);
        }
        let revision = c.take_u64()?;
        let terms_hash = c.take_32()?;
        let event = take_event(&mut c)?;
        let next_state = take_state(&mut c)?;
        let count = c.take_u8()? as usize;
        if count > MAX_FRAME_EFFECTS {
            return Err(FrameError::BoundsExceeded);
        }
        let mut effects = Vec::with_capacity(count);
        for _ in 0..count {
            effects.push(take_effect(&mut c)?);
        }
        if !c.finished() {
            return Err(FrameError::TrailingBytes);
        }
        Ok(Self {
            revision,
            terms_hash,
            event,
            next_state,
            effects,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{assurance_transition, AssuranceContext};

    const TERMS: [u8; 32] = [0x11; 32];

    fn frame_of(revision: u64, ctx: AssuranceContext, event: AssuranceEvent) -> AssuranceFrameV1 {
        let t = assurance_transition(ctx, &event).expect("accepted");
        AssuranceFrameV1 {
            revision,
            terms_hash: TERMS,
            event,
            next_state: t.next.state,
            effects: t.effects,
        }
    }

    /// Every event the machine can accept roundtrips through the codec.
    #[test]
    fn every_accepted_transition_roundtrips() {
        let mut ctx = AssuranceContext::new(TERMS, 1_000, true);
        let mut revision = 0u64;
        for event in [
            AssuranceEvent::BondLockObserved,
            AssuranceEvent::CollateralVerified { terms_hash: TERMS },
            AssuranceEvent::ObligationFailed,
            AssuranceEvent::CompensationClaimed { terms_hash: TERMS },
            AssuranceEvent::EvidenceVerified { valid: true },
            AssuranceEvent::CompensationConfirmed { amount: 1_000 },
        ] {
            revision += 1;
            let frame = frame_of(revision, ctx, event.clone());
            let bytes = frame.canonical_bytes().expect("encodes");
            assert_eq!(AssuranceFrameV1::decode(&bytes).expect("decodes"), frame);
            ctx = assurance_transition(ctx, &event).expect("accepted").next;
        }
    }

    /// Frozen vector: the first frame of the canonical slash history.
    #[test]
    fn frozen_vector_holds() {
        let ctx = AssuranceContext::new(TERMS, 1_000, true);
        let frame = frame_of(1, ctx, AssuranceEvent::BondLockObserved);
        let bytes = frame.canonical_bytes().expect("encodes");
        assert_eq!(bytes.len(), 8 + 2 + 8 + 32 + 1 + 1 + 1 + 2);
        assert_eq!(&bytes[..10], b"DOMIAJR1\x00\x01");
        // revision 1, terms 0x11*32, event 0x01, state BondLocking 0x03,
        // one effect: PersistState(BondLocking).
        assert_eq!(bytes[10..18], [0, 0, 0, 0, 0, 0, 0, 1]);
        assert_eq!(&bytes[18..50], &[0x11; 32]);
        assert_eq!(&bytes[50..], &[0x01, 0x03, 0x01, 0x01, 0x03]);
    }

    #[test]
    fn decode_fails_closed() {
        let ctx = AssuranceContext::new(TERMS, 1_000, true);
        let bytes = frame_of(1, ctx, AssuranceEvent::BondLockObserved)
            .canonical_bytes()
            .expect("encodes");

        for cut in [0, 7, 9, bytes.len() - 1] {
            assert_eq!(
                AssuranceFrameV1::decode(&bytes[..cut]).unwrap_err(),
                FrameError::Truncated
            );
        }
        let mut magic = bytes.clone();
        magic[0] ^= 1;
        assert_eq!(
            AssuranceFrameV1::decode(&magic).unwrap_err(),
            FrameError::InvalidMagic
        );
        let mut version = bytes.clone();
        version[9] ^= 1;
        assert_eq!(
            AssuranceFrameV1::decode(&version).unwrap_err(),
            FrameError::InvalidVersion
        );
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert_eq!(
            AssuranceFrameV1::decode(&trailing).unwrap_err(),
            FrameError::TrailingBytes
        );
        let mut bad_tag = bytes.clone();
        bad_tag[50] = 0x7f; // event tag
        assert_eq!(
            AssuranceFrameV1::decode(&bad_tag).unwrap_err(),
            FrameError::UnknownTag
        );
        assert_eq!(
            AssuranceFrameV1::decode(&vec![0u8; MAX_FRAME_BYTES + 1]).unwrap_err(),
            FrameError::BoundsExceeded
        );
    }
}
