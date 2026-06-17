//! `WalletV2State` — the top-level persisted wallet state (design §2.3).
//!
//! This is the single unit written to disk (via [`crate::persist`]) through the
//! shared `dom-wallet-crypto` envelope. It owns the balance source of truth (the
//! [`OutputStore`]) plus the wallet's identity and cursors.
//!
//! ## Scope (this sub-step)
//! Fields included now: `schema_version`, `network`, `chain_id`, `keychain`
//! (state only — no derivation logic), `outputs`, and `meta` with
//! `last_reconciled_tip` / `last_reconciled_hash`.
//!
//! Deferred to later sub-steps (gated by `schema_version`):
//! - `pending_slates` — belongs with the slate→store coupling that produces it.
//! - `StoreMeta.canonical_digest` — needs blake2b + the drift-detection wiring.
//! - the keychain **derivation engine** (coinbase by height, receive by index,
//!   restore-from-seed) — only the persisted keychain state lives here for now.

use crate::pending::PendingSlate;
use crate::store::OutputStore;
use crate::transport::{sync, ChainSource, SyncError};
use crate::types::{KeychainV2, Network, StoreMeta};
use crate::ReconcileReport;
use serde::{Deserialize, Serialize};

/// Payload schema version (design §2.3 `schema_version`). An on-disk value this
/// build does not understand is rejected by [`crate::persist::load_wallet_state`].
pub const SCHEMA_VERSION: u16 = 2;

/// The complete wallet v2 state — the persisted payload (design §2.3).
///
/// `Debug` is derived: the secret-bearing fields redact themselves
/// ([`KeychainV2`] redacts the seed; [`crate::StoredOutput`] redacts blindings).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletV2State {
    /// Schema gate for future in-place migration.
    pub schema_version: u16,
    /// Network this wallet belongs to.
    pub network: Network,
    /// Chain identifier (magic XOR genesis); slate replay protection and the
    /// cross-chain guard for backup import.
    pub chain_id: [u8; 32],
    /// Deterministic keychain state (encrypted seed + cursors).
    pub keychain: KeychainV2,
    /// The owned outputs — the balance source of truth.
    pub outputs: OutputStore,
    /// In-flight interactive slates (sender and receiver). Their secrets are
    /// encrypted-at-rest and redacted from `Debug` (see [`crate::pending`]). The
    /// orchestration that fills this is sub-step 7B.
    #[serde(default)]
    pub pending_slates: Vec<PendingSlate>,
    /// Store-level cursors / metadata.
    pub meta: StoreMeta,
}

impl WalletV2State {
    /// A fresh, empty wallet state for `network` / `chain_id` (no seed, no
    /// outputs, zeroed cursors).
    pub fn new(network: Network, chain_id: [u8; 32]) -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            network,
            chain_id,
            keychain: KeychainV2::default(),
            outputs: OutputStore::new(),
            pending_slates: Vec::new(),
            meta: StoreMeta::default(),
        }
    }

    /// Drive one reconciliation cycle against `source` and **advance the
    /// reconciliation cursors** (`meta.last_reconciled_tip` /
    /// `last_reconciled_hash`) to the tip just reconciled.
    ///
    /// This is the state-level counterpart of the free [`crate::sync`]: it
    /// reconciles `self.outputs` and records how far we got, preparing the
    /// incremental sync (view B) of a later sub-step. `from` must be `0` today
    /// (full view) — see [`crate::transport`].
    pub fn sync<S: ChainSource>(
        &mut self,
        source: &S,
        from: u64,
        now: u64,
    ) -> Result<ReconcileReport, SyncError<S::Error>> {
        let report = sync(&mut self.outputs, source, from, now)?;
        if let Some(tip) = report.tip {
            self.meta.last_reconciled_tip = tip.height;
            self.meta.last_reconciled_hash = Some(tip.hash);
        }
        Ok(report)
    }

    /// Reconcile against `source` **only if the store is at least
    /// `stale_threshold` blocks behind the source tip** — otherwise do nothing.
    ///
    /// This guards the expensive full reconcile ([`Self::sync`], which scans
    /// `0..=tip`) behind a cheap `source.tip()` round-trip. It exists for hot
    /// paths — chiefly building a send (R-31(b)): coin selection must never run
    /// against a store that is behind the chain (it would pick spent/immature
    /// inputs the node then rejects), but paying a full-chain scan on *every*
    /// send is unacceptable as height grows. The freshness short-circuit pays one
    /// tip lookup when already current and a full reconcile only when needed.
    ///
    /// `stale_threshold` is the minimum `source_tip - last_reconciled_tip` gap
    /// that triggers a sync; pass `1` to reconcile whenever the source is ahead at
    /// all. Returns `Some(report)` if a reconcile ran (cursors advanced) or `None`
    /// if the store was already fresh (no scan performed). A failed `tip()` lookup
    /// surfaces as [`SyncError::Source`] — the caller can refuse the send rather
    /// than proceed against a possibly-stale store.
    pub fn sync_if_behind<S: ChainSource>(
        &mut self,
        source: &S,
        stale_threshold: u64,
        now: u64,
    ) -> Result<Option<ReconcileReport>, SyncError<S::Error>> {
        let tip = source.tip().map_err(SyncError::Source)?;
        if tip.height.saturating_sub(self.meta.last_reconciled_tip) >= stale_threshold {
            Ok(Some(self.sync(source, 0, now)?))
        } else {
            Ok(None)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reconcile::ScanBlock;
    use crate::transport::InMemoryChainSource;
    use crate::types::{OutputOrigin, OutputStatus, StoredOutput};

    const C_R: [u8; 33] = [0xC7u8; 33];

    fn state_with_receive() -> WalletV2State {
        let mut state = WalletV2State::new(Network::Regtest, [0u8; 32]);
        state
            .outputs
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
        state
    }

    #[test]
    fn sync_advances_meta_cursors_and_reconciles() {
        let mut state = state_with_receive();
        assert_eq!(state.meta.last_reconciled_tip, 0);
        assert_eq!(state.meta.last_reconciled_hash, None);

        let src = InMemoryChainSource::with_blocks([ScanBlock {
            height: 7,
            hash: [0x07u8; 32],
            output_commitments: vec![C_R],
            input_commitments: vec![],
        }]);
        state.sync(&src, 0, 1001).unwrap();

        // Reconcile happened on the inner store…
        assert_eq!(
            state.outputs.get(&C_R).unwrap().status,
            OutputStatus::Confirmed
        );
        // …and the cursors advanced to the reconciled tip.
        assert_eq!(state.meta.last_reconciled_tip, 7);
        assert_eq!(state.meta.last_reconciled_hash, Some([0x07u8; 32]));
    }

    #[test]
    fn sync_if_behind_syncs_when_stale_and_skips_when_fresh() {
        // R-31(b): the freshness short-circuit the send path relies on.
        let mut state = state_with_receive();
        assert_eq!(state.meta.last_reconciled_tip, 0);

        let src = InMemoryChainSource::with_blocks([ScanBlock {
            height: 7,
            hash: [0x07u8; 32],
            output_commitments: vec![C_R],
            input_commitments: vec![],
        }]);

        // Stale store (cursor 0) vs node tip 7 → a reconcile runs and advances
        // the cursor, so coin selection would now see a fresh store.
        let ran = state.sync_if_behind(&src, 1, 1001).expect("tip reachable");
        assert!(ran.is_some(), "stale store must trigger a sync");
        assert_eq!(state.meta.last_reconciled_tip, 7);
        assert_eq!(
            state.outputs.get(&C_R).unwrap().status,
            OutputStatus::Confirmed
        );

        // Fresh store (cursor now 7) vs same node tip 7 → gap 0 < threshold 1,
        // so NO scan happens (the cheap tip check short-circuits).
        let ran_again = state.sync_if_behind(&src, 1, 1002).expect("tip reachable");
        assert!(ran_again.is_none(), "fresh store must skip the sync");
        assert_eq!(state.meta.last_reconciled_tip, 7);
    }

    #[test]
    fn sync_if_behind_threshold_gates_small_gaps() {
        // With a threshold of 3, a 2-block gap is tolerated (no sync); a 3-block
        // gap triggers one.
        let mut state = state_with_receive();
        state.meta.last_reconciled_tip = 5;

        let src5 = InMemoryChainSource::with_blocks([ScanBlock {
            height: 7, // gap = 2 < 3 → skip
            hash: [0x07u8; 32],
            output_commitments: vec![C_R],
            input_commitments: vec![],
        }]);
        assert!(state
            .sync_if_behind(&src5, 3, 1001)
            .expect("tip reachable")
            .is_none());
        assert_eq!(state.meta.last_reconciled_tip, 5, "no sync below threshold");

        let src8 = InMemoryChainSource::with_blocks([ScanBlock {
            height: 8, // gap = 3 >= 3 → sync
            hash: [0x08u8; 32],
            output_commitments: vec![C_R],
            input_commitments: vec![],
        }]);
        assert!(state
            .sync_if_behind(&src8, 3, 1002)
            .expect("tip reachable")
            .is_some());
        assert_eq!(state.meta.last_reconciled_tip, 8, "sync at threshold");
    }

    #[test]
    fn new_starts_empty_with_zeroed_cursors() {
        let state = WalletV2State::new(Network::Testnet, [9u8; 32]);
        assert_eq!(state.schema_version, SCHEMA_VERSION);
        assert_eq!(state.network, Network::Testnet);
        assert!(state.outputs.is_empty());
        assert_eq!(state.meta, StoreMeta::default());
        assert!(state.keychain.seed_bytes.is_none());
    }
}
