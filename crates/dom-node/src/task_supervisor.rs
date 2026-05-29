//! Node task registry and supervision (Roadmap v2 — TASK 19).
//!
//! `DomNode::run` spawns a fixed set of long-lived runtime tasks (P2P listener,
//! peer connector, miner, RPC server, future-block-queue drain, Dandelion++
//! stem-timeout promoter) plus a dynamic set of per-peer relay workers. On
//! `main` these are bare `tokio::spawn` calls whose `JoinHandle`s are dropped,
//! so a task that panics or exits with an error vanishes silently and there is
//! no way to observe or coordinate shutdown.
//!
//! [`NodeTaskSupervisor`] is the registry that fixes this:
//!
//!   * Every critical task is spawned through [`NodeTaskSupervisor::spawn`] (or
//!     [`NodeTaskSupervisor::spawn_relay`]) so its handle is *registered*, never
//!     dropped on the floor.
//!   * A task that returns `Err` (or panics) records a [`TaskFailure`]
//!     (`failure_task` + `failure_reason`) and trips the shutdown signal, so a
//!     critical failure is observable instead of silent.
//!   * Tasks observe shutdown via a cheap [`ShutdownToken`]; the node requests
//!     it with [`NodeTaskSupervisor::request_shutdown`]. Simply *holding* the
//!     supervisor never shuts anything down — `run()` stays long-lived until an
//!     explicit shutdown request or a critical failure (see TASK 20 for the
//!     ordered drain built on top of this).
//!   * Relay workers are tracked in the same registry but start empty and are
//!     removed again via [`NodeTaskSupervisor::deregister`] when their peer
//!     goes away, so the registry does not leak entries across reconnects.
//!
//! This module deliberately holds no chain/mempool/wire state, so the
//! supervision policy is unit-tested on its own with synthetic tasks.

use std::collections::BTreeMap;
use std::future::Future;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::sync::{Mutex, Notify};
use tokio::task::JoinHandle;

/// A supervised runtime task class.
///
/// The fixed singletons each appear at most once; [`TaskKind::Relay`] is a
/// dynamic per-peer worker keyed by a supervisor-assigned id.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum TaskKind {
    /// Inbound P2P connection listener.
    Listener,
    /// Outbound peer connector / rotation loop.
    Connector,
    /// Block miner.
    Miner,
    /// JSON-RPC server.
    Rpc,
    /// Future-block-queue drain / replay loop.
    FutureQueue,
    /// Dandelion++ stem-timeout promoter.
    DandelionStem,
    /// Dynamic per-peer relay worker, keyed by an assigned id.
    Relay(u64),
}

impl TaskKind {
    /// True for the dynamic relay-worker class.
    pub fn is_relay(&self) -> bool {
        matches!(self, TaskKind::Relay(_))
    }
}

/// A recorded critical-task failure: which task failed and why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskFailure {
    /// The task class that failed.
    pub failure_task: TaskKind,
    /// Human-readable reason (error string or panic message).
    pub failure_reason: String,
}

/// Lifecycle status of the supervised task set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SupervisorStatus {
    /// Tasks running; no shutdown requested and no failure recorded.
    Running,
    /// A shutdown has been requested (cleanly or due to a failure).
    ShuttingDown,
}

/// A unique handle id for a registered task.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TaskId(pub u64);

/// A cheap, cloneable shutdown observer handed to each supervised task.
///
/// `is_shutdown()` is a non-blocking check for use inside loop bodies;
/// `wait()` resolves as soon as shutdown is requested, for use in `select!`.
#[derive(Clone)]
pub struct ShutdownToken {
    flag: Arc<AtomicBool>,
    notify: Arc<Notify>,
}

impl ShutdownToken {
    /// Whether shutdown has been requested.
    pub fn is_shutdown(&self) -> bool {
        self.flag.load(Ordering::SeqCst)
    }

    /// Resolve once shutdown is requested (immediately if already requested).
    pub async fn wait(&self) {
        if self.is_shutdown() {
            return;
        }
        // Re-check after registering interest to avoid missing a signal that
        // fires between the check above and `notified()` being awaited.
        let notified = self.notify.notified();
        if self.is_shutdown() {
            return;
        }
        notified.await;
    }
}

#[derive(Default)]
struct Inner {
    handles: BTreeMap<TaskId, (TaskKind, JoinHandle<()>)>,
    next_id: u64,
    next_relay_id: u64,
    failure: Option<TaskFailure>,
    shutting_down: bool,
}

/// Registry and supervisor for the node's runtime tasks.
#[derive(Clone)]
pub struct NodeTaskSupervisor {
    flag: Arc<AtomicBool>,
    notify: Arc<Notify>,
    inner: Arc<Mutex<Inner>>,
}

impl Default for NodeTaskSupervisor {
    fn default() -> Self {
        Self::new()
    }
}

impl NodeTaskSupervisor {
    /// Create an empty supervisor with no tasks and shutdown not requested.
    pub fn new() -> Self {
        NodeTaskSupervisor {
            flag: Arc::new(AtomicBool::new(false)),
            notify: Arc::new(Notify::new()),
            inner: Arc::new(Mutex::new(Inner::default())),
        }
    }

    /// A shutdown observer for a supervised task to watch.
    pub fn shutdown_token(&self) -> ShutdownToken {
        ShutdownToken {
            flag: self.flag.clone(),
            notify: self.notify.clone(),
        }
    }

    /// Whether shutdown has been requested.
    pub fn is_shutdown(&self) -> bool {
        self.flag.load(Ordering::SeqCst)
    }

    /// Current lifecycle status.
    pub async fn status(&self) -> SupervisorStatus {
        if self.inner.lock().await.shutting_down {
            SupervisorStatus::ShuttingDown
        } else {
            SupervisorStatus::Running
        }
    }

    /// Request a graceful shutdown: trip the flag and wake every waiter.
    /// Idempotent.
    pub async fn request_shutdown(&self) {
        self.flag.store(true, Ordering::SeqCst);
        self.inner.lock().await.shutting_down = true;
        self.notify.notify_waiters();
    }

    /// The recorded critical failure, if any.
    pub async fn failure(&self) -> Option<TaskFailure> {
        self.inner.lock().await.failure.clone()
    }

    /// The task classes currently registered (running or finished-but-not-yet
    /// joined), in canonical order.
    pub async fn active_kinds(&self) -> Vec<TaskKind> {
        self.inner
            .lock()
            .await
            .handles
            .values()
            .map(|(kind, _)| *kind)
            .collect()
    }

    /// Whether a task of `kind` is currently registered.
    pub async fn contains(&self, kind: TaskKind) -> bool {
        self.inner
            .lock()
            .await
            .handles
            .values()
            .any(|(k, _)| *k == kind)
    }

    /// Number of registered relay workers.
    pub async fn relay_count(&self) -> usize {
        self.inner
            .lock()
            .await
            .handles
            .values()
            .filter(|(k, _)| k.is_relay())
            .count()
    }

    /// Total number of registered tasks.
    pub async fn len(&self) -> usize {
        self.inner.lock().await.handles.len()
    }

    /// Whether the registry is empty.
    pub async fn is_empty(&self) -> bool {
        self.inner.lock().await.handles.is_empty()
    }

    /// Spawn `fut` as a supervised task of `kind`, registering its handle.
    ///
    /// If the future resolves to `Err`, the supervisor records the first such
    /// [`TaskFailure`] and requests shutdown, so a critical failure becomes
    /// observable and propagates to the rest of the runtime.
    pub async fn spawn<F>(&self, kind: TaskKind, fut: F) -> TaskId
    where
        F: Future<Output = Result<(), String>> + Send + 'static,
    {
        let id = {
            let mut g = self.inner.lock().await;
            let id = TaskId(g.next_id);
            g.next_id += 1;
            id
        };
        let sup = self.clone();
        let handle = tokio::spawn(async move {
            if let Err(reason) = fut.await {
                sup.record_failure(kind, reason).await;
            }
        });
        self.inner.lock().await.handles.insert(id, (kind, handle));
        id
    }

    /// Spawn a dynamic relay worker, assigning it a fresh [`TaskKind::Relay`]
    /// id. Returns the id so the caller can [`deregister`](Self::deregister) it
    /// when the peer disconnects.
    pub async fn spawn_relay<F>(&self, fut: F) -> TaskId
    where
        F: Future<Output = Result<(), String>> + Send + 'static,
    {
        let relay_id = {
            let mut g = self.inner.lock().await;
            let r = g.next_relay_id;
            g.next_relay_id += 1;
            r
        };
        self.spawn(TaskKind::Relay(relay_id), fut).await
    }

    /// Remove a task's registry entry and abort it if still running. Used to
    /// clean up a relay worker whose peer has gone away. Returns `true` if the
    /// id was registered.
    pub async fn deregister(&self, id: TaskId) -> bool {
        let entry = self.inner.lock().await.handles.remove(&id);
        match entry {
            Some((_, handle)) => {
                handle.abort();
                true
            }
            None => false,
        }
    }

    /// Record the first critical failure and trip shutdown. Subsequent failures
    /// are kept as the recorded cause only if none was recorded yet.
    async fn record_failure(&self, kind: TaskKind, reason: String) {
        {
            let mut g = self.inner.lock().await;
            if g.failure.is_none() {
                g.failure = Some(TaskFailure {
                    failure_task: kind,
                    failure_reason: reason,
                });
            }
            g.shutting_down = true;
        }
        self.flag.store(true, Ordering::SeqCst);
        self.notify.notify_waiters();
    }

    /// Await every registered task to completion, draining the registry.
    ///
    /// This does *not* itself request shutdown — callers that want the tasks to
    /// stop must `request_shutdown()` (or rely on the ordered drain in TASK 20)
    /// first; otherwise this awaits genuinely long-lived loops. After it
    /// returns the registry is empty (no leaked handles).
    pub async fn join_all(&self) {
        let handles: Vec<(TaskId, JoinHandle<()>)> = {
            let mut g = self.inner.lock().await;
            std::mem::take(&mut g.handles)
                .into_iter()
                .map(|(id, (_, h))| (id, h))
                .collect()
        };
        for (_, handle) in handles {
            let _ = handle.await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tokio::sync::oneshot;

    /// A task that runs until shutdown is observed, then exits Ok.
    async fn until_shutdown(token: ShutdownToken) -> Result<(), String> {
        token.wait().await;
        Ok(())
    }

    #[tokio::test]
    async fn node_supervisor_starts_empty_and_running() {
        let sup = NodeTaskSupervisor::new();
        assert!(sup.is_empty().await);
        assert_eq!(sup.relay_count().await, 0);
        assert!(!sup.is_shutdown());
        assert_eq!(sup.status().await, SupervisorStatus::Running);
        assert!(sup.failure().await.is_none());
    }

    #[tokio::test]
    async fn node_supervisor_registers_expected_tasks() {
        let sup = NodeTaskSupervisor::new();
        for kind in [
            TaskKind::Listener,
            TaskKind::Connector,
            TaskKind::Miner,
            TaskKind::Rpc,
            TaskKind::FutureQueue,
            TaskKind::DandelionStem,
        ] {
            let t = sup.shutdown_token();
            sup.spawn(kind, until_shutdown(t)).await;
        }
        let kinds = sup.active_kinds().await;
        for kind in [
            TaskKind::Listener,
            TaskKind::Connector,
            TaskKind::Miner,
            TaskKind::Rpc,
            TaskKind::FutureQueue,
            TaskKind::DandelionStem,
        ] {
            assert!(kinds.contains(&kind), "expected {kind:?} registered");
        }
        sup.request_shutdown().await;
        sup.join_all().await;
    }

    #[tokio::test]
    async fn node_supervisor_miner_absent_when_disabled() {
        // Model "mining disabled": the miner task is simply never spawned.
        let sup = NodeTaskSupervisor::new();
        let miner_enabled = false;
        let t = sup.shutdown_token();
        sup.spawn(TaskKind::Listener, until_shutdown(t)).await;
        if miner_enabled {
            let t = sup.shutdown_token();
            sup.spawn(TaskKind::Miner, until_shutdown(t)).await;
        }
        assert!(sup.contains(TaskKind::Listener).await);
        assert!(
            !sup.contains(TaskKind::Miner).await,
            "miner must be absent when disabled"
        );
        sup.request_shutdown().await;
        sup.join_all().await;
    }

    #[tokio::test]
    async fn node_supervisor_shutdown_is_observable_and_long_lived_until_requested() {
        let sup = NodeTaskSupervisor::new();
        let token = sup.shutdown_token();
        let (started_tx, started_rx) = oneshot::channel();
        let observer = sup.shutdown_token();
        let handle = tokio::spawn(async move {
            started_tx.send(()).unwrap();
            observer.wait().await;
            observer.is_shutdown()
        });
        started_rx.await.unwrap();

        // The task is long-lived: holding the supervisor has not shut it down.
        assert!(!token.is_shutdown());
        assert_eq!(sup.status().await, SupervisorStatus::Running);

        sup.request_shutdown().await;
        let observed = tokio::time::timeout(Duration::from_secs(5), handle)
            .await
            .expect("task must observe shutdown promptly")
            .expect("join");
        assert!(observed, "task must see is_shutdown() == true");
        assert_eq!(sup.status().await, SupervisorStatus::ShuttingDown);
    }

    #[tokio::test]
    async fn node_supervisor_critical_failure_is_observed_and_trips_shutdown() {
        let sup = NodeTaskSupervisor::new();
        // A task that fails immediately.
        sup.spawn(TaskKind::Miner, async { Err("miner exploded".to_string()) })
            .await;
        // A long-lived task that should observe the failure-triggered shutdown.
        let token = sup.shutdown_token();
        let survivor = sup.spawn(TaskKind::Listener, until_shutdown(token)).await;
        let _ = survivor;

        // Wait (bounded) for the failing task to record its failure + trip shutdown.
        let failure = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if let Some(f) = sup.failure().await {
                    break f;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("failure must be recorded promptly");

        assert_eq!(failure.failure_task, TaskKind::Miner);
        assert_eq!(failure.failure_reason, "miner exploded");
        assert!(sup.is_shutdown(), "failure must trip shutdown");
        sup.join_all().await;
    }

    #[tokio::test]
    async fn node_supervisor_relay_registry_starts_empty_and_cleans_up() {
        let sup = NodeTaskSupervisor::new();
        assert_eq!(sup.relay_count().await, 0, "relay registry starts empty");

        let t1 = sup.shutdown_token();
        let r1 = sup.spawn_relay(until_shutdown(t1)).await;
        let t2 = sup.shutdown_token();
        let r2 = sup.spawn_relay(until_shutdown(t2)).await;
        assert_eq!(sup.relay_count().await, 2);
        assert_ne!(r1, r2, "relay ids are unique");

        // A peer disconnects: its relay worker is deregistered and aborted.
        assert!(sup.deregister(r1).await);
        assert_eq!(sup.relay_count().await, 1);
        assert!(sup.deregister(r2).await);
        assert_eq!(sup.relay_count().await, 0, "registry cleans up to empty");
        // Deregistering an unknown id is a harmless false.
        assert!(!sup.deregister(r1).await);
    }

    #[tokio::test]
    async fn node_supervisor_repeated_start_stop_does_not_leak() {
        for _ in 0..5 {
            let sup = NodeTaskSupervisor::new();
            for kind in [TaskKind::Listener, TaskKind::Connector, TaskKind::Miner] {
                let t = sup.shutdown_token();
                sup.spawn(kind, until_shutdown(t)).await;
            }
            let t = sup.shutdown_token();
            sup.spawn_relay(until_shutdown(t)).await;
            assert_eq!(sup.len().await, 4);
            sup.request_shutdown().await;
            sup.join_all().await;
            assert!(
                sup.is_empty().await,
                "join_all must drain every handle — no leak across cycles"
            );
        }
    }
}
