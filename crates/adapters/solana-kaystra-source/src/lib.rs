//! Durable-cursor Solana `ChainSourceV1` implementation.
//!
//! Solana slots may be skipped. The cursor therefore advances by slot while
//! retaining only canonical anchors for slots that actually produced blocks.

#![forbid(unsafe_code)]

use kaystra_core::{
    settlement_engine::{ChainCursorV1, ChainRecordV1, ChainSourceErrorV1, ChainSourceV1},
    state::EvidenceRefV1,
    types::{ChainId, Digest32},
};

const CURSOR_MAGIC: &[u8; 8] = b"DOMSOLC1";
const CURSOR_VERSION: u16 = 1;
const MAX_HISTORY: usize = 512;
/// Maximum slots traversed by one scan.
pub const MAX_SLOTS_PER_SCAN: u64 = 2_048;
/// Maximum records returned by one scan.
pub const MAX_RECORDS_PER_SCAN: usize = 512;

/// Verified Solana event kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum VerifiedSolanaEventKind {
    /// Escrow reached exact funded state.
    Funding = 1,
    /// Claim finalized and revealed the scalar.
    Claim = 2,
    /// Refund finalized.
    Refund = 3,
}

impl VerifiedSolanaEventKind {
    /// Strict persistent code decoding.
    pub fn from_code(code: u8) -> Option<Self> {
        match code {
            1 => Some(Self::Funding),
            2 => Some(Self::Claim),
            3 => Some(Self::Refund),
            _ => None,
        }
    }
}

/// Event already verified at the Solana adapter boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedSolanaEvent {
    /// Settlement binding.
    pub settlement_id: [u8; 32],
    /// Frozen terms binding.
    pub terms_hash: [u8; 32],
    /// Neutral event kind.
    pub kind: VerifiedSolanaEventKind,
    /// Canonical public chain reference.
    pub evidence: EvidenceRefV1,
}

/// Canonical produced-slot anchor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SolanaSlotAnchor {
    /// Solana slot.
    pub slot: u64,
    /// Blockhash for that slot.
    pub blockhash: Digest32,
}

/// Verified-feed failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum VerifiedFeedError {
    /// RPC/store unavailable.
    #[error("verified Solana feed unavailable")]
    Unavailable,
    /// Persisted or supplied evidence invalid.
    #[error("verified Solana feed contains invalid evidence")]
    InvalidEvidence,
    /// Configured bound exceeded.
    #[error("verified Solana feed bound exceeded")]
    BoundsExceeded,
}

/// Synchronous verified feed consumed by Kaystra's synchronous engine.
pub trait VerifiedSolanaFeed {
    /// Frozen chain id.
    fn chain_id(&self) -> ChainId;
    /// Highest finalized observed slot, or no observation yet.
    fn tip(&self) -> Result<Option<u64>, VerifiedFeedError>;
    /// Canonical blockhash for a produced slot. `None` means skipped/unavailable.
    fn block_hash(&self, slot: u64) -> Result<Option<Digest32>, VerifiedFeedError>;
    /// Produced-slot anchors in the inclusive range.
    fn anchors(
        &self,
        from_slot: u64,
        to_slot: u64,
    ) -> Result<Vec<SolanaSlotAnchor>, VerifiedFeedError>;
    /// Verified events in the inclusive range.
    fn events(
        &self,
        from_slot: u64,
        to_slot: u64,
    ) -> Result<Vec<VerifiedSolanaEvent>, VerifiedFeedError>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CursorAnchor {
    slot: u64,
    blockhash: Digest32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CursorState {
    next_slot: u64,
    history: Vec<CursorAnchor>,
}

/// Solana source bound to one settlement and terms hash.
pub struct SolanaKaystraSource<F> {
    feed: F,
    settlement_id: [u8; 32],
    terms_hash: [u8; 32],
    start_slot: u64,
}

impl<F> SolanaKaystraSource<F> {
    /// Construct from slot zero.
    pub fn new(
        feed: F,
        settlement_id: [u8; 32],
        terms_hash: [u8; 32],
    ) -> Result<Self, ChainSourceErrorV1> {
        Self::new_from_slot(feed, settlement_id, terms_hash, 0)
    }

    /// Construct from a known initialization slot.
    pub fn new_from_slot(
        feed: F,
        settlement_id: [u8; 32],
        terms_hash: [u8; 32],
        start_slot: u64,
    ) -> Result<Self, ChainSourceErrorV1> {
        if settlement_id == [0; 32] || terms_hash == [0; 32] {
            return Err(ChainSourceErrorV1::InvalidEvidence);
        }
        Ok(Self {
            feed,
            settlement_id,
            terms_hash,
            start_slot,
        })
    }

    /// Return the backing feed.
    pub fn into_inner(self) -> F {
        self.feed
    }
}

impl<F: VerifiedSolanaFeed> ChainSourceV1 for SolanaKaystraSource<F> {
    fn chain_id(&self) -> ChainId {
        self.feed.chain_id()
    }

    fn genesis_cursor(&self) -> Result<ChainCursorV1, ChainSourceErrorV1> {
        cursor_to_core(&CursorState {
            next_slot: self.start_slot,
            history: Vec::new(),
        })
    }

    fn cursor_at(&self, slot: u64) -> Result<ChainCursorV1, ChainSourceErrorV1> {
        let blockhash = self
            .feed
            .block_hash(slot)
            .map_err(map_feed)?
            .ok_or(ChainSourceErrorV1::InvalidEvidence)?;
        cursor_to_core(&CursorState {
            next_slot: slot
                .checked_add(1)
                .ok_or(ChainSourceErrorV1::BoundsExceeded)?,
            history: vec![CursorAnchor { slot, blockhash }],
        })
    }

    fn scan(
        &self,
        from: &ChainCursorV1,
    ) -> Result<(Vec<ChainRecordV1>, ChainCursorV1), ChainSourceErrorV1> {
        let mut cursor = cursor_from_core(from)?;

        // A slot anchor that changes is a reorg/regression. Return exactly one
        // neutral reorg record and a cursor rewound before that slot.
        for (index, anchor) in cursor.history.iter().enumerate() {
            let current = self.feed.block_hash(anchor.slot).map_err(map_feed)?;
            if current != Some(anchor.blockhash) {
                let invalidated = *anchor;
                cursor.history.truncate(index);
                cursor.next_slot = invalidated.slot;
                return Ok((
                    vec![ChainRecordV1::Reorg {
                        from_height: invalidated.slot,
                        old_anchor: invalidated.blockhash,
                    }],
                    cursor_to_core(&cursor)?,
                ));
            }
        }

        let Some(tip) = self.feed.tip().map_err(map_feed)? else {
            return Ok((Vec::new(), cursor_to_core(&cursor)?));
        };
        if cursor.next_slot > tip {
            return Ok((Vec::new(), cursor_to_core(&cursor)?));
        }

        let last = cursor
            .next_slot
            .saturating_add(MAX_SLOTS_PER_SCAN.saturating_sub(1))
            .min(tip);
        let events = self.feed.events(cursor.next_slot, last).map_err(map_feed)?;
        if events.len() > MAX_RECORDS_PER_SCAN {
            return Err(ChainSourceErrorV1::BoundsExceeded);
        }

        let mut records = Vec::with_capacity(events.len());
        for event in events {
            validate_event(
                &event,
                self.feed.chain_id(),
                &self.settlement_id,
                &self.terms_hash,
                cursor.next_slot,
                last,
            )?;
            let current = self
                .feed
                .block_hash(event.evidence.block_height)
                .map_err(map_feed)?
                .ok_or(ChainSourceErrorV1::InvalidEvidence)?;
            if current != event.evidence.block_anchor {
                return Err(ChainSourceErrorV1::InvalidEvidence);
            }
            records.push(match event.kind {
                VerifiedSolanaEventKind::Funding => ChainRecordV1::Funding {
                    evidence: event.evidence,
                },
                VerifiedSolanaEventKind::Claim => ChainRecordV1::Claim {
                    evidence: event.evidence,
                },
                VerifiedSolanaEventKind::Refund => ChainRecordV1::Refund {
                    evidence: event.evidence,
                },
            });
        }

        let anchors = self
            .feed
            .anchors(cursor.next_slot, last)
            .map_err(map_feed)?;
        validate_anchors(&anchors, cursor.next_slot, last)?;
        for anchor in anchors {
            cursor.history.push(CursorAnchor {
                slot: anchor.slot,
                blockhash: anchor.blockhash,
            });
            if cursor.history.len() > MAX_HISTORY {
                cursor.history.remove(0);
            }
        }
        cursor.next_slot = last
            .checked_add(1)
            .ok_or(ChainSourceErrorV1::BoundsExceeded)?;
        Ok((records, cursor_to_core(&cursor)?))
    }

    fn tip_height(&self) -> Result<u64, ChainSourceErrorV1> {
        Ok(self.feed.tip().map_err(map_feed)?.unwrap_or(0))
    }
}

fn validate_anchors(
    anchors: &[SolanaSlotAnchor],
    from: u64,
    to: u64,
) -> Result<(), ChainSourceErrorV1> {
    let mut previous = None;
    for anchor in anchors {
        if anchor.slot < from
            || anchor.slot > to
            || anchor.blockhash == [0; 32]
            || previous.is_some_and(|slot| slot >= anchor.slot)
        {
            return Err(ChainSourceErrorV1::InvalidEvidence);
        }
        previous = Some(anchor.slot);
    }
    Ok(())
}

fn validate_event(
    event: &VerifiedSolanaEvent,
    chain_id: ChainId,
    settlement_id: &[u8; 32],
    terms_hash: &[u8; 32],
    from_slot: u64,
    to_slot: u64,
) -> Result<(), ChainSourceErrorV1> {
    if &event.settlement_id != settlement_id
        || &event.terms_hash != terms_hash
        || event.evidence.chain_id != chain_id
        || event.evidence.tx_id == [0; 32]
        || event.evidence.block_anchor == [0; 32]
        || event.evidence.block_height < from_slot
        || event.evidence.block_height > to_slot
    {
        return Err(ChainSourceErrorV1::InvalidEvidence);
    }
    Ok(())
}

fn cursor_to_core(cursor: &CursorState) -> Result<ChainCursorV1, ChainSourceErrorV1> {
    let bytes = encode_cursor(cursor)?;
    let (height, anchor) = cursor
        .history
        .last()
        .map(|entry| (entry.slot, entry.blockhash))
        .unwrap_or((0, [0; 32]));
    Ok(ChainCursorV1 {
        bytes,
        height,
        anchor,
    })
}

fn cursor_from_core(core: &ChainCursorV1) -> Result<CursorState, ChainSourceErrorV1> {
    let cursor = decode_cursor(&core.bytes)?;
    let expected = cursor
        .history
        .last()
        .map(|entry| (entry.slot, entry.blockhash))
        .unwrap_or((0, [0; 32]));
    if expected != (core.height, core.anchor) {
        return Err(ChainSourceErrorV1::StaleCursor);
    }
    Ok(cursor)
}

fn encode_cursor(cursor: &CursorState) -> Result<Vec<u8>, ChainSourceErrorV1> {
    if cursor.history.len() > MAX_HISTORY {
        return Err(ChainSourceErrorV1::BoundsExceeded);
    }
    let count =
        u16::try_from(cursor.history.len()).map_err(|_| ChainSourceErrorV1::BoundsExceeded)?;
    let mut output = Vec::with_capacity(20 + cursor.history.len() * 40);
    output.extend_from_slice(CURSOR_MAGIC);
    output.extend_from_slice(&CURSOR_VERSION.to_be_bytes());
    output.extend_from_slice(&cursor.next_slot.to_be_bytes());
    output.extend_from_slice(&count.to_be_bytes());
    for anchor in &cursor.history {
        output.extend_from_slice(&anchor.slot.to_be_bytes());
        output.extend_from_slice(&anchor.blockhash);
    }
    Ok(output)
}

fn decode_cursor(bytes: &[u8]) -> Result<CursorState, ChainSourceErrorV1> {
    if bytes.len() < 20 || &bytes[..8] != CURSOR_MAGIC {
        return Err(ChainSourceErrorV1::StaleCursor);
    }
    if u16::from_be_bytes([bytes[8], bytes[9]]) != CURSOR_VERSION {
        return Err(ChainSourceErrorV1::StaleCursor);
    }
    let mut next = [0; 8];
    next.copy_from_slice(&bytes[10..18]);
    let count = usize::from(u16::from_be_bytes([bytes[18], bytes[19]]));
    if count > MAX_HISTORY || bytes.len() != 20 + count * 40 {
        return Err(ChainSourceErrorV1::StaleCursor);
    }
    let mut history = Vec::with_capacity(count);
    let mut offset = 20;
    for _ in 0..count {
        let mut slot = [0; 8];
        slot.copy_from_slice(&bytes[offset..offset + 8]);
        let mut blockhash = [0; 32];
        blockhash.copy_from_slice(&bytes[offset + 8..offset + 40]);
        if blockhash == [0; 32] {
            return Err(ChainSourceErrorV1::StaleCursor);
        }
        history.push(CursorAnchor {
            slot: u64::from_be_bytes(slot),
            blockhash,
        });
        offset += 40;
    }
    if history.windows(2).any(|pair| pair[0].slot >= pair[1].slot) {
        return Err(ChainSourceErrorV1::StaleCursor);
    }
    Ok(CursorState {
        next_slot: u64::from_be_bytes(next),
        history,
    })
}

fn map_feed(error: VerifiedFeedError) -> ChainSourceErrorV1 {
    match error {
        VerifiedFeedError::Unavailable => ChainSourceErrorV1::Unavailable,
        VerifiedFeedError::InvalidEvidence => ChainSourceErrorV1::InvalidEvidence,
        VerifiedFeedError::BoundsExceeded => ChainSourceErrorV1::BoundsExceeded,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cursor_round_trip_accepts_skipped_slots() {
        let cursor = CursorState {
            next_slot: 12,
            history: vec![
                CursorAnchor {
                    slot: 8,
                    blockhash: [1; 32],
                },
                CursorAnchor {
                    slot: 11,
                    blockhash: [2; 32],
                },
            ],
        };
        assert_eq!(
            decode_cursor(&encode_cursor(&cursor).unwrap()).unwrap(),
            cursor
        );
    }
}
