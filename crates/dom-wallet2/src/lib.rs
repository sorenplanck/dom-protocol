//! # dom-wallet2 — DOM wallet v2 persistent store
//!
//! Wallet v2 makes the **store the source of truth** for balance. Each owned
//! output is a single [`StoredOutput`] record whose blinding factor is **always
//! persisted** — including the random ones (change / receive-slate). This is the
//! property v1 lacks and the root cause of the WDSF-001/002 fund-loss defects
//! (`docs/WALLET_V2_DESIGN.md`).
//!
//! Rescan in v2 is **reconciliation, not reconstruction**: an output leaves the
//! spendable set only by an explicit state transition ([`OutputStatus`], §3),
//! never by being dropped for not being re-derivable. The retention invariant
//! **INV-RET** guarantees a `Confirmed`/`Spent`/`Reorged` output is never
//! deleted and never loses its blinding.
//!
//! This crate coexists with `dom-wallet` (v1) during the migration; it does
//! **not** depend on v1.
//!
//! ## Implementation status (Phase 2 sub-steps)
//! - 3A: central store types ([`types`]), output state machine ([`state`],
//!   transitions T1–T7 + D1 with INV-RET), and the in-memory store with its
//!   read surface ([`store`]).
//! - 3B: status-only reconciler ([`reconcile`], design §4) — iterates the store
//!   against an abstract [`reconcile::CanonicalView`] and updates status only.
//!   Acceptance suite (WDSF-001/002) lives in `tests/`.
//! - 3C: encrypted on-disk persistence ([`persist`], design §2.1–§2.3) via the
//!   shared `dom-wallet-crypto` envelope, magic `DOM-WALLET-V2\0`, versioned
//!   payload.
//! - 3D: encrypted store export/import ([`backup`], `wallet.dombak`, design
//!   §2.7) — non-destructive merge respecting INV-RET.
//! - Transport: [`transport`] — a `ChainSource` trait + the [`transport::sync`]
//!   driver (`tip → scan → reconcile`) with an in-memory fake. The RPC-backed
//!   source is a documented TODO (RB-WALLET2-RPC-SOURCE; own PR).
//! - **WalletV2State (this code):** [`wallet_state`] — the top-level persisted
//!   state (design §2.3): `network`, `chain_id`, `keychain` (encrypted seed +
//!   cursors, state only), `outputs`, `meta` (`last_reconciled_tip` —
//!   unblocks incremental sync). `WalletV2State::sync` advances those cursors.
//!   Deferred (schema-gated): `pending_slates` (slate→store step),
//!   `canonical_digest`.
//! - Keychain derivation: [`keychain`] — derives the derivable blindings from
//!   the seed via the shared `dom-wallet-keys` (#76): coinbase by height,
//!   receive-request by index, `create_receive_request`, and
//!   `restore_coinbase_from_seed` (recovers ONLY derivable coinbase).
//! - **Pending slates (this code):** [`pending`] — the secure data model for
//!   in-flight interactive slates (design §2.5): `PendingSlate` + `SlateSecrets`
//!   (`Zeroizing`, redacted `Debug`, encrypted-only) + `pending_slates` on
//!   `WalletV2State`. The orchestration (create_send/receive/finalize/cancel
//!   consuming `dom-slate`) is the next sub-step.

pub mod backup;
pub mod keychain;
pub mod pending;
pub mod persist;
pub mod reconcile;
pub mod state;
pub mod store;
pub mod transport;
pub mod types;
pub mod wallet_state;

pub use backup::{export_backup, import_backup, BackupError, BACKUP_MAGIC};
pub use keychain::{
    restore_coinbase_from_seed, KeychainDeriver, KeychainError, ReceiveRequest, RestoreBlock,
};
pub use pending::{PendingSlate, SlateLifecycle, SlateRole, SlateSecrets};
pub use persist::{load_wallet_state, save_wallet_state, PersistError, WALLET_V2_MAGIC};
pub use reconcile::{reconcile, CanonicalView, ReconcileReport, ScanBlock};
pub use state::TransitionError;
pub use store::{MergeReport, OutputStore, StoreError};
pub use transport::{sync, ChainSource, InMemoryChainSource, SyncError};
pub use types::{
    BlockRef, DerivIndex, KeychainV2, Network, OutputOrigin, OutputStatus, StoreMeta, StoredOutput,
};
pub use wallet_state::{WalletV2State, SCHEMA_VERSION};
