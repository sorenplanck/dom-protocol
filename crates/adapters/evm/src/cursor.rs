//! Persistable observation cursor (§4.7).
//!
//! The neutral API hands cursors around as opaque bytes
//! ([`counterparty_api::ChainCursor`]). This module defines the only encoding
//! this adapter will ever accept, and decodes it strictly.
//!
//! Layout — fixed width, big-endian, no padding, no optional fields:
//!
//! ```text
//! offset  size  field
//!      0     2  version               (u16)
//!      2     8  chain_id              (u64)
//!     10    20  contract              (address)
//!     30     8  next_from_block       (u64)
//!     38    32  last_seen_block_hash  (bytes32)
//!     70     8  finalized_height      (u64)
//!     78     8  emitted_high_water    (u64)
//!            = 86 bytes
//! ```
//!
//! Strictness rules:
//!
//! - a length other than 0 or [`CURSOR_LEN`] is [`AdapterError::VersionMismatch`];
//! - an unknown `version` is [`AdapterError::VersionMismatch`];
//! - a cursor whose `chain_id` or `contract` does not match the adapter's
//!   configuration is [`AdapterError::StaleCursor`] — it belongs to some other
//!   deployment and must never be silently adopted;
//! - the **empty** cursor ([`counterparty_api::ChainCursor::default`]) is the
//!   one accepted shorthand: it means "start from the configured start block",
//!   with a zero anchor hash so that the first scan performs no reorg check.
//!
//! `emitted_high_water` is the highest block height whose events have already
//! been handed to the caller. It is monotone in the absence of a reorg, and it
//! is clamped down to the common ancestor when a reorg rewinds the cursor. It
//! exists so that a restart can tell "I have already reported up to here" apart
//! from "I have merely scanned up to here".

use counterparty_api::{AdapterError, ChainCursor};

use crate::binding::Cut;
use crate::error::Result;

/// Current cursor version. A bump invalidates persisted cursors on purpose.
pub const CURSOR_VERSION: u16 = 1;

/// Exact encoded length of an [`EvmCursor`].
pub const CURSOR_LEN: usize = 2 + 8 + 20 + 8 + 32 + 8 + 8;

/// Versioned, persistable observation cursor.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct EvmCursor {
    /// Encoding version.
    pub version: u16,
    /// EVM chain id this cursor belongs to.
    pub chain_id: u64,
    /// Contract this cursor belongs to.
    pub contract: [u8; 20],
    /// Next block height to scan (inclusive).
    pub next_from_block: u64,
    /// Hash of `next_from_block - 1`, the anchor a reorg breaks. Zero means
    /// "no anchor yet".
    pub last_seen_block_hash: [u8; 32],
    /// Finalized height observed when this cursor was produced.
    pub finalized_height: u64,
    /// Highest block height whose events were already surfaced.
    pub emitted_high_water: u64,
}

impl EvmCursor {
    /// A fresh cursor for a deployment, anchored at nothing.
    pub fn fresh(chain_id: u64, contract: [u8; 20], start_block: u64) -> Self {
        Self {
            version: CURSOR_VERSION,
            chain_id,
            contract,
            next_from_block: start_block,
            last_seen_block_hash: [0u8; 32],
            finalized_height: 0,
            emitted_high_water: 0,
        }
    }

    /// Height of the last block this cursor claims to have scanned, if any.
    ///
    /// `None` when the cursor sits at the very beginning, or when it carries no
    /// anchor hash (nothing to compare a reorg against).
    pub fn last_seen_height(&self) -> Option<u64> {
        if self.last_seen_block_hash == [0u8; 32] {
            return None;
        }
        self.next_from_block.checked_sub(1)
    }

    /// Canonical encoding.
    pub fn encode(&self) -> ChainCursor {
        let mut v = Vec::with_capacity(CURSOR_LEN);
        v.extend_from_slice(&self.version.to_be_bytes());
        v.extend_from_slice(&self.chain_id.to_be_bytes());
        v.extend_from_slice(&self.contract);
        v.extend_from_slice(&self.next_from_block.to_be_bytes());
        v.extend_from_slice(&self.last_seen_block_hash);
        v.extend_from_slice(&self.finalized_height.to_be_bytes());
        v.extend_from_slice(&self.emitted_high_water.to_be_bytes());
        ChainCursor(v)
    }

    /// Strict decode, bound to the deployment the caller expects.
    ///
    /// See the module header for the exact rejection taxonomy.
    pub fn decode(
        raw: &ChainCursor,
        chain_id: u64,
        contract: &[u8; 20],
        start_block: u64,
    ) -> Result<Self> {
        if raw.0.is_empty() {
            return Ok(Self::fresh(chain_id, *contract, start_block));
        }
        if raw.0.len() != CURSOR_LEN {
            return Err(AdapterError::VersionMismatch);
        }
        let mut c = Cut { b: &raw.0, at: 0 };
        let version = c.take_u16()?;
        if version != CURSOR_VERSION {
            return Err(AdapterError::VersionMismatch);
        }
        let cursor = Self {
            version,
            chain_id: c.take_u64()?,
            contract: c.take20()?,
            next_from_block: c.take_u64()?,
            last_seen_block_hash: c.take32()?,
            finalized_height: c.take_u64()?,
            emitted_high_water: c.take_u64()?,
        };
        // Trailing bytes are impossible given the exact-length check above, but
        // the assertion is kept so the invariant survives a layout change.
        if c.at != raw.0.len() {
            return Err(AdapterError::VersionMismatch);
        }
        if cursor.chain_id != chain_id || &cursor.contract != contract {
            return Err(AdapterError::StaleCursor);
        }
        if cursor.next_from_block < start_block {
            // A cursor pointing before the deployment window is not usable;
            // adopting it silently would re-scan history that cannot contain
            // this contract's logs.
            return Err(AdapterError::StaleCursor);
        }
        Ok(cursor)
    }

    /// Advances past a scanned range, recording the new anchor.
    pub fn advance_to(
        &self,
        scanned_through: u64,
        anchor: [u8; 32],
        finalized_height: u64,
        emitted_through: u64,
    ) -> Self {
        Self {
            version: CURSOR_VERSION,
            chain_id: self.chain_id,
            contract: self.contract,
            next_from_block: scanned_through.saturating_add(1),
            last_seen_block_hash: anchor,
            finalized_height,
            emitted_high_water: self.emitted_high_water.max(emitted_through),
        }
    }

    /// Rewinds after a reorg so that scanning resumes at `next_from_block`.
    ///
    /// `anchor` is the hash of `next_from_block - 1`, or all-zero when there is
    /// nothing to anchor to (a full rewind to the deployment floor).
    ///
    /// `emitted_high_water` is clamped down: everything from `next_from_block`
    /// upwards has been invalidated as a *settlement effect* and will be
    /// replayed. It is **not** clamped for secrets — see [`crate::revealed`].
    pub fn rewind_to(&self, next_from_block: u64, anchor: [u8; 32]) -> Self {
        let last = next_from_block.saturating_sub(1);
        Self {
            version: CURSOR_VERSION,
            chain_id: self.chain_id,
            contract: self.contract,
            next_from_block,
            last_seen_block_hash: anchor,
            finalized_height: self.finalized_height.min(last),
            emitted_high_water: self.emitted_high_water.min(last),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CONTRACT: [u8; 20] = [0xC0; 20];

    fn sample() -> EvmCursor {
        EvmCursor {
            version: CURSOR_VERSION,
            chain_id: 11_155_111,
            contract: CONTRACT,
            next_from_block: 4_242,
            last_seen_block_hash: [0x9A; 32],
            finalized_height: 4_200,
            emitted_high_water: 4_100,
        }
    }

    #[test]
    fn round_trip_is_exact() {
        let c = sample();
        let enc = c.encode();
        assert_eq!(enc.0.len(), CURSOR_LEN);
        assert_eq!(EvmCursor::decode(&enc, 11_155_111, &CONTRACT, 0), Ok(c));
    }

    #[test]
    fn empty_cursor_means_start_block() {
        let got = EvmCursor::decode(&ChainCursor::default(), 5, &CONTRACT, 77);
        assert_eq!(got, Ok(EvmCursor::fresh(5, CONTRACT, 77)));
        assert_eq!(got.map(|c| c.last_seen_height()), Ok(None));
    }

    #[test]
    fn truncation_and_extension_are_rejected() {
        let enc = sample().encode();
        for bad_len in [1usize, CURSOR_LEN - 1, CURSOR_LEN + 1] {
            let mut v = enc.0.clone();
            v.resize(bad_len, 0);
            assert_eq!(
                EvmCursor::decode(&ChainCursor(v), 11_155_111, &CONTRACT, 0),
                Err(AdapterError::VersionMismatch),
                "length {bad_len} must be rejected"
            );
        }
    }

    #[test]
    fn version_bump_is_rejected() {
        let mut enc = sample().encode();
        enc.0[1] = CURSOR_VERSION as u8 + 1;
        assert_eq!(
            EvmCursor::decode(&enc, 11_155_111, &CONTRACT, 0),
            Err(AdapterError::VersionMismatch)
        );
    }

    #[test]
    fn foreign_chain_or_contract_is_stale() {
        let enc = sample().encode();
        assert_eq!(
            EvmCursor::decode(&enc, 1337, &CONTRACT, 0),
            Err(AdapterError::StaleCursor)
        );
        assert_eq!(
            EvmCursor::decode(&enc, 11_155_111, &[0xC1; 20], 0),
            Err(AdapterError::StaleCursor)
        );
    }

    #[test]
    fn cursor_before_the_deployment_window_is_stale() {
        let enc = sample().encode();
        assert_eq!(
            EvmCursor::decode(&enc, 11_155_111, &CONTRACT, 9_000),
            Err(AdapterError::StaleCursor)
        );
    }

    #[test]
    fn advance_and_rewind_behave_monotonically() {
        let c = sample();
        let a = c.advance_to(5_000, [0x11; 32], 5_000, 4_999);
        assert_eq!(a.next_from_block, 5_001);
        assert_eq!(a.emitted_high_water, 4_999);
        // High water never goes backwards on a plain advance.
        let b = a.advance_to(5_100, [0x12; 32], 5_100, 0);
        assert_eq!(b.emitted_high_water, 4_999);
        // ... but a rewind clamps it.
        let r = b.rewind_to(4_501, [0x13; 32]);
        assert_eq!(r.next_from_block, 4_501);
        assert_eq!(r.emitted_high_water, 4_500);
        assert_eq!(r.last_seen_block_hash, [0x13; 32]);
        // A full rewind to the floor carries no anchor.
        let z = b.rewind_to(0, [0u8; 32]);
        assert_eq!(z.next_from_block, 0);
        assert_eq!(z.last_seen_height(), None);
        assert_eq!(z.emitted_high_water, 0);
    }

    #[test]
    fn last_seen_height_needs_an_anchor() {
        let mut c = sample();
        assert_eq!(c.last_seen_height(), Some(4_241));
        c.last_seen_block_hash = [0u8; 32];
        assert_eq!(c.last_seen_height(), None);
    }
}
