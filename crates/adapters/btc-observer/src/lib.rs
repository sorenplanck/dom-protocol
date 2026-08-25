//! Bitcoin chain observer and durable store (Annex M v3.2, M.9, M.10).
//!
//! Reorg-aware observation via a durable cursor. Each observed event is
//! applied in a single effect transaction (M.10.3): validate the
//! idempotency key, persist the bounded event, update session state,
//! record evidence refs, advance the cursor, enqueue the outbox — all or
//! nothing. Redelivery of the same key with the same bytes is idempotent;
//! the same key with different bytes is terminal equivocation (M.10.4). A
//! reorg invalidates every derived observation at or above the fork
//! height (M.9.5, property P12).
//!
//! Persists only PUBLIC data (M.10.1): never a key, share, `t`, secnonce
//! or `session_secrand`.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod cursor;
mod events;
mod store;

pub use cursor::BitcoinChainCursorV1;
pub use events::{BitcoinNetworkV1, BitcoinObservedEventV1, BitcoinOutPointV1};
pub use store::{ApplyOutcome, ObserverError, ObserverStore};
