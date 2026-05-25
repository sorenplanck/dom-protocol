//! # dom-store
//!
//! Persistent storage for the DOM node using LMDB.
//!
//! ## Database Layout
//!
//! All data lives in a single LMDB environment with multiple named databases:
//!
//! | DB name         | Key                    | Value                    |
//! |-----------------|------------------------|--------------------------|
//! | `blocks`        | block_hash [32 bytes]  | serialized BlockHeader   |
//! | `block_height`  | height [8 bytes LE]    | block_hash [32 bytes]    |
//! | `chain_tip`     | b"tip"                 | block_hash [32 bytes]    |
//! | `utxos`         | commitment [33 bytes]  | UtxoEntry (serialized)   |
//! | `kernel_index`  | kernel_excess [33 bytes] | block_hash [32 bytes]  |
//! | `peer_addrs`    | ip:port string         | last_seen u64 LE         |
//!
//! ## Atomicity
//!
//! RFC-0007 step 14: atomic state commit.
//! All writes during block processing go into ONE LMDB transaction.
//! If anything fails, the whole transaction is aborted — no partial state.

// unsafe allowed for lmdb API
#![deny(missing_docs)]

pub mod block_store;
pub mod db;
pub mod peer_store;
pub mod utxo;

pub use block_store::BlockStore;
pub use db::{
    DomStore, DB_BLOCKS, DB_BLOCK_BODIES, DB_BLOCK_HEIGHT, DB_CHAIN_TIP, DB_KERNEL_INDEX,
    DB_PEER_ADDRS, DB_UTXOS, LMDB_MAP_FULL_SENTINEL,
};
pub use peer_store::PeerAddr;
pub use utxo::{UtxoEntry, UtxoSet};
