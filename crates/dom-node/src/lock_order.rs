//! Runtime lock ordering for node-critical shared state.
//!
//! Canonical acquisition order:
//!
//! 1. ChainState, including canonical DomStore access through ChainState
//! 2. Mempool
//! 3. Wallet
//! 4. Dandelion router
//! 5. Peer registry
//! 6. Missing-block tracker
//! 7. Future-block queue
//! 8. Transaction relay tracker
//!
//! Locks must be acquired in ascending order when more than one runtime
//! lock is held at the same time. Prefer snapshot-then-drop over nesting
//! whenever possible, especially before awaiting a later lock.

#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum RuntimeLock {
    ChainState = 10,
    Mempool = 20,
    Wallet = 30,
    Dandelion = 40,
    PeerRegistry = 50,
    MissingBlocks = 60,
    FutureBlockQueue = 70,
    TxRelay = 80,
}

const _CANONICAL_RUNTIME_LOCK_ORDER: [RuntimeLock; 8] = [
    RuntimeLock::ChainState,
    RuntimeLock::Mempool,
    RuntimeLock::Wallet,
    RuntimeLock::Dandelion,
    RuntimeLock::PeerRegistry,
    RuntimeLock::MissingBlocks,
    RuntimeLock::FutureBlockQueue,
    RuntimeLock::TxRelay,
];

#[track_caller]
pub(crate) fn assert_canonical_order(locks: &[RuntimeLock]) {
    for pair in locks.windows(2) {
        debug_assert!(
            pair[0] < pair[1],
            "runtime lock order violation: {:?} acquired before {:?}",
            pair[0],
            pair[1]
        );
    }
}

#[cfg(test)]
mod tests {
    use super::{assert_canonical_order, RuntimeLock};
    use std::sync::Arc;
    use tokio::sync::{Barrier, Mutex};
    use tokio::time::{timeout, Duration};

    #[test]
    fn runtime_lock_rank_matches_documented_policy() {
        assert_canonical_order(&[
            RuntimeLock::ChainState,
            RuntimeLock::Mempool,
            RuntimeLock::Wallet,
            RuntimeLock::Dandelion,
            RuntimeLock::PeerRegistry,
            RuntimeLock::MissingBlocks,
            RuntimeLock::FutureBlockQueue,
            RuntimeLock::TxRelay,
        ]);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn stress_concurrent_block_processing_order() {
        let chain = Arc::new(Mutex::new(0u64));
        let mempool = Arc::new(Mutex::new(0u64));
        let barrier = Arc::new(Barrier::new(33));
        let mut tasks = Vec::new();

        for _ in 0..32 {
            let chain = chain.clone();
            let mempool = mempool.clone();
            let barrier = barrier.clone();
            tasks.push(tokio::spawn(async move {
                barrier.wait().await;
                assert_canonical_order(&[RuntimeLock::ChainState, RuntimeLock::Mempool]);
                let mut chain = chain.lock().await;
                *chain += 1;
                let mut mempool = mempool.lock().await;
                *mempool += 1;
            }));
        }

        barrier.wait().await;
        timeout(Duration::from_secs(5), async {
            for task in tasks {
                task.await.expect("block processing task panicked");
            }
        })
        .await
        .expect("concurrent block processing lock order deadlocked");

        assert_eq!(*chain.lock().await, 32);
        assert_eq!(*mempool.lock().await, 32);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn stress_ibd_plus_mempool_updates_order() {
        let chain = Arc::new(Mutex::new(0u64));
        let mempool = Arc::new(Mutex::new(0u64));
        let barrier = Arc::new(Barrier::new(3));

        let ibd = {
            let chain = chain.clone();
            let mempool = mempool.clone();
            let barrier = barrier.clone();
            tokio::spawn(async move {
                barrier.wait().await;
                for _ in 0..128 {
                    assert_canonical_order(&[RuntimeLock::ChainState, RuntimeLock::Mempool]);
                    let height = *chain.lock().await;
                    let mut mempool = mempool.lock().await;
                    *mempool = (*mempool).max(height);
                }
            })
        };
        let tx_updates = {
            let chain = chain.clone();
            let mempool = mempool.clone();
            let barrier = barrier.clone();
            tokio::spawn(async move {
                barrier.wait().await;
                for _ in 0..128 {
                    assert_canonical_order(&[RuntimeLock::ChainState, RuntimeLock::Mempool]);
                    let mut chain = chain.lock().await;
                    *chain += 1;
                    let mut mempool = mempool.lock().await;
                    *mempool += 1;
                }
            })
        };

        barrier.wait().await;
        timeout(Duration::from_secs(5), async {
            ibd.await.expect("IBD task panicked");
            tx_updates.await.expect("mempool update task panicked");
        })
        .await
        .expect("IBD plus mempool lock order deadlocked");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn stress_wallet_update_during_reorg_order() {
        let chain = Arc::new(Mutex::new(0u64));
        let mempool = Arc::new(Mutex::new(0u64));
        let wallet = Arc::new(Mutex::new(0u64));
        let barrier = Arc::new(Barrier::new(3));

        let reorg = {
            let chain = chain.clone();
            let mempool = mempool.clone();
            let barrier = barrier.clone();
            tokio::spawn(async move {
                barrier.wait().await;
                for _ in 0..128 {
                    assert_canonical_order(&[RuntimeLock::ChainState, RuntimeLock::Mempool]);
                    let mut chain = chain.lock().await;
                    *chain += 1;
                    let mut mempool = mempool.lock().await;
                    *mempool = 0;
                }
            })
        };
        let wallet_apply = {
            let chain = chain.clone();
            let wallet = wallet.clone();
            let barrier = barrier.clone();
            tokio::spawn(async move {
                barrier.wait().await;
                for _ in 0..128 {
                    assert_canonical_order(&[RuntimeLock::ChainState, RuntimeLock::Wallet]);
                    let height = *chain.lock().await;
                    let mut wallet = wallet.lock().await;
                    *wallet = height;
                }
            })
        };

        barrier.wait().await;
        timeout(Duration::from_secs(5), async {
            reorg.await.expect("reorg task panicked");
            wallet_apply.await.expect("wallet update task panicked");
        })
        .await
        .expect("wallet update during reorg lock order deadlocked");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn stress_shutdown_while_processing_order() {
        let chain = Arc::new(Mutex::new(0u64));
        let mempool = Arc::new(Mutex::new(0u64));
        let peers = Arc::new(Mutex::new(0u64));
        let barrier = Arc::new(Barrier::new(17));
        let mut tasks = Vec::new();

        for _ in 0..16 {
            let chain = chain.clone();
            let mempool = mempool.clone();
            let peers = peers.clone();
            let barrier = barrier.clone();
            tasks.push(tokio::spawn(async move {
                barrier.wait().await;
                assert_canonical_order(&[
                    RuntimeLock::ChainState,
                    RuntimeLock::Mempool,
                    RuntimeLock::PeerRegistry,
                ]);
                let mut chain = chain.lock().await;
                *chain += 1;
                let mut mempool = mempool.lock().await;
                *mempool += 1;
                let mut peers = peers.lock().await;
                *peers += 1;
            }));
        }

        barrier.wait().await;
        timeout(Duration::from_secs(5), async {
            for task in tasks {
                task.abort();
                let _ = task.await;
            }
            let _chain = chain.lock().await;
            let _mempool = mempool.lock().await;
            let _peers = peers.lock().await;
        })
        .await
        .expect("shutdown while processing left locks wedged");
    }
}
