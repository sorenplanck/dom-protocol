//! Chain transport — feeding the reconciler from a chain data source.
//!
//! The reconciler ([`crate::reconcile`]) is pure: it consumes a
//! [`CanonicalView`] built from [`ScanBlock`]s and is unaware of where they come
//! from. This module is the thin layer that fetches those blocks and drives one
//! `tip → scan → reconcile` cycle, behind a [`ChainSource`] trait — mirroring the
//! `CanonicalView` decoupling, so the whole path stays testable without a node.
//!
//! ## What's here (wallet-side only)
//! - [`ChainSource`] — abstracts *"give me the scan blocks up to the tip"*.
//! - [`sync`] — the driver: `tip()` → `scan_range(from, tip)` → reconcile.
//! - [`InMemoryChainSource`] — an in-memory fake (mirrors v1's
//!   `InMemoryChainScan`) so the transport and the acceptance scenarios are
//!   exercised end-to-end without a node.
//!
//! ## Deliberately NOT here yet
//! - `RpcChainSource` (a [`ChainSource`] backed by the node's RPC). The node
//!   does not yet expose per-block commitments over REST; adding that endpoint
//!   touches the production node and belongs in its own isolated PR. The trait
//!   signature below is ready for that impl — see the TODO on [`ChainSource`].
//!
//! ## View completeness (first cut = full view "A")
//! The reconciler needs the **full** canonical view `0..=tip` to detect reorgs
//! (an output absent from the view is treated as reorged). So callers pass
//! `from = 0` today. The `from` parameter exists so the future **incremental**
//! path (view "B": `StoreMeta.last_reconciled_tip` + a height-based
//! `rollback_to`, design §4.4) can reuse this same interface unchanged.

use crate::reconcile::{reconcile, CanonicalView, ReconcileReport, ScanBlock};
use crate::store::OutputStore;
use crate::types::BlockRef;
use std::collections::BTreeMap;
use std::convert::Infallible;
use thiserror::Error;

/// A source of canonical chain data for the reconciler.
///
/// Implementations translate some backend (an in-memory fake, or — in a later
/// PR — the node's RPC) into [`ScanBlock`]s and the current tip. The reconciler
/// itself never sees this trait; only [`sync`] does.
///
/// TODO(transport): add `RpcChainSource: ChainSource` backed by the node RPC
/// once the node exposes per-block output/input commitments (own PR; the node
/// is in production). This trait's signature is the contract that impl must meet.
pub trait ChainSource {
    /// Error surfaced by the backend (network, decode, …). The in-memory fake
    /// uses [`Infallible`].
    type Error: std::error::Error + 'static;

    /// The current canonical tip (height + hash).
    fn tip(&self) -> Result<BlockRef, Self::Error>;

    /// Per-block scan data for canonical heights `from..=to`, ascending. For the
    /// full view (first cut) callers pass `from = 0`.
    fn scan_range(&self, from: u64, to: u64) -> Result<Vec<ScanBlock>, Self::Error>;
}

/// Error from a [`sync`] cycle. The reconcile step itself cannot fail, so the
/// only failure is the underlying [`ChainSource`].
#[derive(Debug, Error)]
pub enum SyncError<E: std::error::Error + 'static> {
    /// The chain source failed to provide the tip or the scan range.
    #[error(transparent)]
    Source(#[from] E),
}

/// Drive one reconciliation cycle against `source`: read the tip, fetch the scan
/// blocks `from..=tip`, build the [`CanonicalView`], and reconcile the store.
///
/// `from` is the lowest height to scan. **For correct reorg detection today it
/// must be `0`** (full view) — see the module docs. Returns the
/// [`ReconcileReport`]; propagates any source error as [`SyncError::Source`]
/// without panicking.
pub fn sync<S: ChainSource>(
    store: &mut OutputStore,
    source: &S,
    from: u64,
    now: u64,
) -> Result<ReconcileReport, SyncError<S::Error>> {
    let tip = source.tip()?;
    let blocks = source.scan_range(from, tip.height)?;
    let view = CanonicalView::from_blocks(&blocks);
    Ok(reconcile(store, &view, now))
}

/// In-memory [`ChainSource`] for tests and local tooling — mirrors v1's
/// `InMemoryChainScan` (`dom-wallet/src/restore.rs`). Keyed by height; inserting
/// a block replaces any block already at that height, and [`Self::remove`]
/// models a block leaving the canonical chain (a reorg).
#[derive(Debug, Default, Clone)]
pub struct InMemoryChainSource {
    blocks: BTreeMap<u64, ScanBlock>,
}

impl InMemoryChainSource {
    /// An empty source (no blocks).
    pub fn new() -> Self {
        Self::default()
    }

    /// Build from an iterator of blocks.
    pub fn with_blocks(blocks: impl IntoIterator<Item = ScanBlock>) -> Self {
        let mut s = Self::new();
        for b in blocks {
            s.insert(b);
        }
        s
    }

    /// Insert (or replace) the block at its height.
    pub fn insert(&mut self, block: ScanBlock) {
        self.blocks.insert(block.height, block);
    }

    /// Remove the block at `height` — models it leaving the canonical chain.
    pub fn remove(&mut self, height: u64) -> Option<ScanBlock> {
        self.blocks.remove(&height)
    }

    /// Number of blocks held.
    pub fn len(&self) -> usize {
        self.blocks.len()
    }

    /// Whether the source has no blocks.
    pub fn is_empty(&self) -> bool {
        self.blocks.is_empty()
    }
}

impl ChainSource for InMemoryChainSource {
    type Error = Infallible;

    fn tip(&self) -> Result<BlockRef, Infallible> {
        // Highest height present; genesis-like {0, zero-hash} for an empty chain.
        Ok(self
            .blocks
            .values()
            .next_back()
            .map(|b| BlockRef {
                height: b.height,
                hash: b.hash,
            })
            .unwrap_or(BlockRef {
                height: 0,
                hash: [0u8; 32],
            }))
    }

    fn scan_range(&self, from: u64, to: u64) -> Result<Vec<ScanBlock>, Infallible> {
        Ok(self
            .blocks
            .range(from..=to)
            .map(|(_, b)| b.clone())
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{OutputOrigin, OutputStatus, StoredOutput};

    const C_R: [u8; 33] = [0xC7u8; 33];

    fn empty_block(height: u64) -> ScanBlock {
        ScanBlock {
            height,
            hash: [height as u8; 32],
            output_commitments: vec![],
            input_commitments: vec![],
        }
    }

    fn block_with_output(height: u64, hash_byte: u8, c: [u8; 33]) -> ScanBlock {
        ScanBlock {
            height,
            hash: [hash_byte; 32],
            output_commitments: vec![c],
            input_commitments: vec![],
        }
    }

    fn receive_store() -> OutputStore {
        let mut store = OutputStore::new();
        store
            .insert(StoredOutput::new_unconfirmed(
                C_R,
                500,
                [0x9au8; 32],
                OutputOrigin::ReceiveSlate,
                false,
                None,
                1000,
            ))
            .unwrap();
        store
    }

    #[test]
    fn sync_runs_tip_scan_reconcile_and_confirms() {
        let mut store = receive_store();
        let mut src = InMemoryChainSource::new();
        src.insert(empty_block(0));
        src.insert(empty_block(1));
        src.insert(block_with_output(2, 0x02, C_R));

        let report = sync(&mut store, &src, 0, 1001).unwrap();
        assert_eq!(report.confirmed, 1);
        assert_eq!(report.tip.unwrap().height, 2);
        assert_eq!(store.get(&C_R).unwrap().status, OutputStatus::Confirmed);
    }

    #[test]
    fn sync_marks_spent_when_input_consumed() {
        let mut store = receive_store();
        let mut src = InMemoryChainSource::new();
        src.insert(block_with_output(2, 0x02, C_R));
        sync(&mut store, &src, 0, 1001).unwrap();

        // Block 3 spends c_R.
        src.insert(ScanBlock {
            height: 3,
            hash: [0x03; 32],
            output_commitments: vec![],
            input_commitments: vec![C_R],
        });
        let report = sync(&mut store, &src, 0, 1002).unwrap();
        assert_eq!(report.spent, 1);
        assert_eq!(store.get(&C_R).unwrap().status, OutputStatus::Spent);
    }

    #[test]
    fn sync_reorgs_then_reconfirms_on_remine() {
        let mut store = receive_store();

        // Confirm at block 2.
        let mut src = InMemoryChainSource::with_blocks([
            empty_block(0),
            empty_block(1),
            block_with_output(2, 0x02, C_R),
        ]);
        sync(&mut store, &src, 0, 1001).unwrap();
        assert_eq!(store.get(&C_R).unwrap().status, OutputStatus::Confirmed);

        // Reorg: block 2 leaves the canonical chain (tip falls to 1).
        src.remove(2);
        let report = sync(&mut store, &src, 0, 1002).unwrap();
        assert_eq!(report.reorged, 1);
        let o = store.get(&C_R).unwrap();
        assert_eq!(o.status, OutputStatus::Reorged);
        assert_eq!(*o.blinding, [0x9au8; 32]); // INV-RET via the driver

        // Re-mine at block 2' (different hash).
        src.insert(block_with_output(2, 0xB2, C_R));
        let report = sync(&mut store, &src, 0, 1003).unwrap();
        assert_eq!(report.confirmed, 1);
        assert_eq!(store.get(&C_R).unwrap().status, OutputStatus::Confirmed);
        assert_eq!(
            store.get(&C_R).unwrap().origin_block.unwrap().hash,
            [0xB2; 32]
        );
    }

    #[test]
    fn sync_is_idempotent_on_repeat() {
        let mut store = receive_store();
        let src = InMemoryChainSource::with_blocks([block_with_output(2, 0x02, C_R)]);
        sync(&mut store, &src, 0, 1001).unwrap();
        let report = sync(&mut store, &src, 0, 1002).unwrap();
        assert_eq!(report.confirmed, 0);
        assert_eq!(report.unchanged, 1);
    }

    // A source that always fails — to prove errors propagate without a panic.
    #[derive(Debug, Error)]
    #[error("backend unavailable")]
    struct Boom;

    struct FaultyChainSource;
    impl ChainSource for FaultyChainSource {
        type Error = Boom;
        fn tip(&self) -> Result<BlockRef, Boom> {
            Err(Boom)
        }
        fn scan_range(&self, _: u64, _: u64) -> Result<Vec<ScanBlock>, Boom> {
            Err(Boom)
        }
    }

    #[test]
    fn source_errors_propagate_as_sync_error_without_panic() {
        let mut store = receive_store();
        let err = sync(&mut store, &FaultyChainSource, 0, 1).unwrap_err();
        assert!(matches!(err, SyncError::Source(Boom)));
        // Store untouched on failure.
        assert_eq!(store.get(&C_R).unwrap().status, OutputStatus::Unconfirmed);
    }

    #[test]
    fn empty_source_yields_genesis_tip() {
        let src = InMemoryChainSource::new();
        let tip = src.tip().unwrap();
        assert_eq!(tip.height, 0);
        assert!(src.is_empty());
    }
}
