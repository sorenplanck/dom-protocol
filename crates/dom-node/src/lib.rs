//! DOM full node library — ties all crates together.
#![deny(unsafe_code)]

pub mod future_block_queue;
pub mod lock_order;
pub mod metrics;
pub mod miner;
pub mod missing_block_tracker;
pub mod node;
pub mod node_handle;
pub mod orphan_pool;
pub mod peer_scoring;
pub mod pex;
pub mod relay;
pub mod replay_snapshot;
pub mod task_supervisor;
#[cfg(test)]
pub(crate) mod test_dir;
pub mod time_health;
pub mod wallet_helpers;
pub mod wallet_scan;
