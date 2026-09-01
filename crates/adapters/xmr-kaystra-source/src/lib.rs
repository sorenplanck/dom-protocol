//! Durable-cursor Monero `ChainSourceV1` implementation for Kaystra.

#![forbid(unsafe_code)]

use kaystra_core::{
    settlement_engine::{ChainCursorV1, ChainRecordV1, ChainSourceErrorV1, ChainSourceV1},
    state::EvidenceRefV1,
    types::ChainId,
};

const CURSOR_MAGIC: &[u8; 8] = b"DOMXMRV2";
const CURSOR_VERSION: u16 = 2;
const MAX_HISTORY: usize = 128;
/// Maximum blocks advanced by one scan.
pub const MAX_BLOCKS_PER_SCAN: u64 = 256;
/// Maximum chain records returned by one scan.
pub const MAX_RECORDS_PER_SCAN: usize = 512;

/// Verified neutral XMR event kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum VerifiedXmrEventKind {
    /// Funding output.
    Funding = 1,
    /// Sweep/claim transaction.
    Claim = 2,
    /// Refund transaction.
    Refund = 3,
}

impl VerifiedXmrEventKind {
    /// Strict integer decoding for persistent stores.
    pub fn from_code(code: u8) -> Option<Self> {
        match code {
            1 => Some(Self::Funding),
            2 => Some(Self::Claim),
            3 => Some(Self::Refund),
            _ => None,
        }
    }
}

/// Event already verified by the XMR adapter boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedXmrEvent {
    /// Settlement binding.
    pub settlement_id: [u8; 32],
    /// Terms binding.
    pub terms_hash: [u8; 32],
    /// Event kind.
    pub kind: VerifiedXmrEventKind,
    /// Public inclusion evidence.
    pub evidence: EvidenceRefV1,
}

/// Canonical block anchor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct XmrBlockAnchor {
    /// Block height.
    pub height: u64,
    /// Canonical hash.
    pub hash: [u8; 32],
}

/// Errors exposed by the durable verified feed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum VerifiedFeedError {
    /// Backing store/RPC unavailable.
    #[error("verified XMR feed unavailable")]
    Unavailable,
    /// Persisted event/header is malformed or inconsistent.
    #[error("verified XMR feed contains invalid evidence")]
    InvalidEvidence,
    /// Requested range exceeds a bound.
    #[error("verified XMR feed bound exceeded")]
    BoundsExceeded,
}

/// Synchronous verified event/header feed used by Kaystra's synchronous engine.
pub trait VerifiedXmrFeed {
    /// Chain identity.
    fn chain_id(&self) -> ChainId;
    /// Canonical tip, or no tip yet.
    fn tip(&self) -> Result<Option<XmrBlockAnchor>, VerifiedFeedError>;
    /// Canonical hash at a height.
    fn block_hash(&self, height: u64) -> Result<Option<[u8; 32]>, VerifiedFeedError>;
    /// Verified events in inclusive height range.
    fn events(
        &self,
        from_height: u64,
        to_height: u64,
    ) -> Result<Vec<VerifiedXmrEvent>, VerifiedFeedError>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CursorAnchor {
    height: u64,
    hash: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CursorState {
    next_height: u64,
    history: Vec<CursorAnchor>,
}

/// Monero chain source bound to exactly one settlement and terms hash.
pub struct XmrKaystraSource<F> {
    feed: F,
    settlement_id: [u8; 32],
    terms_hash: [u8; 32],
    start_height: u64,
}

impl<F> XmrKaystraSource<F> {
    /// Binds a verified feed to one settlement.
    pub fn new(
        feed: F,
        settlement_id: [u8; 32],
        terms_hash: [u8; 32],
    ) -> Result<Self, ChainSourceErrorV1> {
        if settlement_id == [0; 32] || terms_hash == [0; 32] {
            return Err(ChainSourceErrorV1::InvalidEvidence);
        }
        Ok(Self {
            feed,
            settlement_id,
            terms_hash,
            start_height: 0,
        })
    }

    /// Binds a verified feed and starts scanning at a wallet restore height.
    pub fn new_from_height(
        feed: F,
        settlement_id: [u8; 32],
        terms_hash: [u8; 32],
        start_height: u64,
    ) -> Result<Self, ChainSourceErrorV1> {
        if settlement_id == [0; 32] || terms_hash == [0; 32] {
            return Err(ChainSourceErrorV1::InvalidEvidence);
        }
        Ok(Self {
            feed,
            settlement_id,
            terms_hash,
            start_height,
        })
    }

    /// Returns the underlying feed.
    pub fn into_inner(self) -> F {
        self.feed
    }
}

impl<F: VerifiedXmrFeed> ChainSourceV1 for XmrKaystraSource<F> {
    fn chain_id(&self) -> ChainId {
        self.feed.chain_id()
    }

    fn genesis_cursor(&self) -> Result<ChainCursorV1, ChainSourceErrorV1> {
        cursor_to_core(&CursorState {
            next_height: self.start_height,
            history: Vec::new(),
        })
    }

    fn cursor_at(&self, height: u64) -> Result<ChainCursorV1, ChainSourceErrorV1> {
        let hash = self
            .feed
            .block_hash(height)
            .map_err(map_feed)?
            .ok_or(ChainSourceErrorV1::InvalidEvidence)?;
        cursor_to_core(&CursorState {
            next_height: height
                .checked_add(1)
                .ok_or(ChainSourceErrorV1::BoundsExceeded)?,
            history: vec![CursorAnchor { height, hash }],
        })
    }

    fn scan(
        &self,
        from: &ChainCursorV1,
    ) -> Result<(Vec<ChainRecordV1>, ChainCursorV1), ChainSourceErrorV1> {
        let mut cursor = cursor_from_core(from)?;

        // Detect the earliest invalidated anchor retained in the durable cursor.
        for (index, anchor) in cursor.history.iter().enumerate() {
            let current = self.feed.block_hash(anchor.height).map_err(map_feed)?;
            if current != Some(anchor.hash) {
                let invalidated = *anchor;
                cursor.history.truncate(index);
                cursor.next_height = invalidated.height;
                let rewound = cursor_to_core(&cursor)?;
                return Ok((
                    vec![ChainRecordV1::Reorg {
                        from_height: invalidated.height,
                        old_anchor: invalidated.hash,
                    }],
                    rewound,
                ));
            }
        }

        let Some(tip) = self.feed.tip().map_err(map_feed)? else {
            return Ok((Vec::new(), cursor_to_core(&cursor)?));
        };
        if cursor.next_height > tip.height {
            return Ok((Vec::new(), cursor_to_core(&cursor)?));
        }
        let last = cursor
            .next_height
            .saturating_add(MAX_BLOCKS_PER_SCAN.saturating_sub(1))
            .min(tip.height);
        let events = self
            .feed
            .events(cursor.next_height, last)
            .map_err(map_feed)?;
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
                cursor.next_height,
                last,
            )?;
            let expected_anchor = self
                .feed
                .block_hash(event.evidence.block_height)
                .map_err(map_feed)?
                .ok_or(ChainSourceErrorV1::InvalidEvidence)?;
            if expected_anchor != event.evidence.block_anchor {
                return Err(ChainSourceErrorV1::InvalidEvidence);
            }
            records.push(match event.kind {
                VerifiedXmrEventKind::Funding => ChainRecordV1::Funding {
                    evidence: event.evidence,
                },
                VerifiedXmrEventKind::Claim => ChainRecordV1::Claim {
                    evidence: event.evidence,
                },
                VerifiedXmrEventKind::Refund => ChainRecordV1::Refund {
                    evidence: event.evidence,
                },
            });
        }

        for height in cursor.next_height..=last {
            let hash = self
                .feed
                .block_hash(height)
                .map_err(map_feed)?
                .ok_or(ChainSourceErrorV1::InvalidEvidence)?;
            cursor.history.push(CursorAnchor { height, hash });
            if cursor.history.len() > MAX_HISTORY {
                cursor.history.remove(0);
            }
        }
        cursor.next_height = last
            .checked_add(1)
            .ok_or(ChainSourceErrorV1::BoundsExceeded)?;
        Ok((records, cursor_to_core(&cursor)?))
    }

    fn tip_height(&self) -> Result<u64, ChainSourceErrorV1> {
        Ok(self
            .feed
            .tip()
            .map_err(map_feed)?
            .map(|tip| tip.height)
            .unwrap_or(0))
    }
}

fn validate_event(
    event: &VerifiedXmrEvent,
    chain_id: ChainId,
    settlement_id: &[u8; 32],
    terms_hash: &[u8; 32],
    from_height: u64,
    to_height: u64,
) -> Result<(), ChainSourceErrorV1> {
    if &event.settlement_id != settlement_id
        || &event.terms_hash != terms_hash
        || event.evidence.chain_id != chain_id
        || event.evidence.tx_id == [0; 32]
        || event.evidence.block_anchor == [0; 32]
        || event.evidence.block_height < from_height
        || event.evidence.block_height > to_height
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
        .map(|entry| (entry.height, entry.hash))
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
        .map(|entry| (entry.height, entry.hash))
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
    let mut output = Vec::with_capacity(8 + 2 + 8 + 2 + cursor.history.len() * 40);
    output.extend_from_slice(CURSOR_MAGIC);
    output.extend_from_slice(&CURSOR_VERSION.to_be_bytes());
    output.extend_from_slice(&cursor.next_height.to_be_bytes());
    output.extend_from_slice(&count.to_be_bytes());
    for anchor in &cursor.history {
        output.extend_from_slice(&anchor.height.to_be_bytes());
        output.extend_from_slice(&anchor.hash);
    }
    Ok(output)
}

fn decode_cursor(bytes: &[u8]) -> Result<CursorState, ChainSourceErrorV1> {
    if bytes.len() < 20 || &bytes[..8] != CURSOR_MAGIC {
        return Err(ChainSourceErrorV1::StaleCursor);
    }
    let version = u16::from_be_bytes([bytes[8], bytes[9]]);
    if version != CURSOR_VERSION {
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
        let mut height = [0; 8];
        height.copy_from_slice(&bytes[offset..offset + 8]);
        let mut hash = [0; 32];
        hash.copy_from_slice(&bytes[offset + 8..offset + 40]);
        if hash == [0; 32] {
            return Err(ChainSourceErrorV1::StaleCursor);
        }
        history.push(CursorAnchor {
            height: u64::from_be_bytes(height),
            hash,
        });
        offset += 40;
    }
    if history
        .windows(2)
        .any(|pair| pair[0].height >= pair[1].height)
    {
        return Err(ChainSourceErrorV1::StaleCursor);
    }
    Ok(CursorState {
        next_height: u64::from_be_bytes(next),
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
