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
//! - **3B (this code):** status-only reconciler ([`reconcile`], design §4) —
//!   iterates the store against an abstract [`reconcile::CanonicalView`] and
//!   updates status only. Acceptance suite (WDSF-001/002) lives in `tests/`.
//! - 3C: encrypted on-disk persistence (`wallet.dat`, design §2.1/§5) — pending.
//! - 3D: encrypted store export/import (`wallet.dombak`, design §2.7) — pending.
//! - Transport (node/RPC → `ScanBlock`s): a later layer, deliberately not here.

pub mod reconcile;
pub mod state;
pub mod store;
pub mod types;

pub use reconcile::{reconcile, CanonicalView, ReconcileReport, ScanBlock};
pub use state::TransitionError;
pub use store::{OutputStore, StoreError};
pub use types::{BlockRef, DerivIndex, OutputOrigin, OutputStatus, StoredOutput};
