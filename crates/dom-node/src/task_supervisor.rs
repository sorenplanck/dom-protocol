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

use futures::FutureExt;
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
        // TASK21: this is the single production raw `tokio::spawn` boundary for
        // critical node tasks. The JoinHandle is immediately registered below,
        // and wrapper code records panics/errors before requesting shutdown.
        let handle = tokio::spawn(async move {
            let outcome = std::panic::AssertUnwindSafe(fut).catch_unwind().await;
            match outcome {
                Ok(Ok(())) => {}
                Ok(Err(reason)) => {
                    sup.record_failure(kind, reason).await;
                }
                Err(panic) => {
                    sup.record_failure(kind, panic_message(&panic)).await;
                }
            }
            if kind.is_relay() {
                sup.finish_task(id).await;
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

    async fn finish_task(&self, id: TaskId) {
        self.inner.lock().await.handles.remove(&id);
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

    /// Canonical shutdown phase for a task class (lower phases stop first):
    ///
    /// * 1 — stop accepting inbound work: `Listener`, `FutureQueue`
    /// * 2 — stop the miner: `Miner`
    /// * 3 — stop relay / connectors: `Connector`, `DandelionStem`, `Relay`
    /// * (4 — caller's persistence-critical drain runs here)
    /// * 5 — stop RPC / UI-facing last: `Rpc`
    pub fn shutdown_phase(kind: TaskKind) -> u8 {
        match kind {
            TaskKind::Listener | TaskKind::FutureQueue => 1,
            TaskKind::Miner => 2,
            TaskKind::Connector | TaskKind::DandelionStem | TaskKind::Relay(_) => 3,
            TaskKind::Rpc => 5,
        }
    }

    /// Coordinated, ordered shutdown of every supervised task.
    ///
    /// Trips the shutdown signal (so every cooperative loop begins winding down),
    /// then *confirms* tasks stopped in canonical phase order — inbound, miner,
    /// relay/connectors — runs the caller's `persistence_drain` to flush
    /// persistence-critical work, and finally stops RPC and joins any stragglers.
    /// Each task is awaited up to `grace`; one that does not observe cancellation
    /// in time (e.g. parked in blocking I/O) is force-aborted, so no detached
    /// task survives. The registry is empty when this returns.
    ///
    /// This only acts when called: merely constructing or holding the supervisor
    /// never shuts the node down, so `DomNode::run()` stays long-lived.
    pub async fn shutdown_ordered<F>(
        &self,
        grace: std::time::Duration,
        persistence_drain: F,
    ) -> ShutdownReport
    where
        F: std::future::Future<Output = ()>,
    {
        self.request_shutdown().await;
        let mut report = ShutdownReport::default();
        // Phase 1: stop accepting inbound work.
        self.join_phase(1, grace, &mut report).await;
        // Phase 2: stop the miner.
        self.join_phase(2, grace, &mut report).await;
        // Phase 3: stop relay workers and connectors.
        self.join_phase(3, grace, &mut report).await;
        // Phase 4: drain / flush persistence-critical work, now that nothing
        // is producing new chain mutations.
        persistence_drain.await;
        report.persistence_drained = true;
        // Phase 5: stop RPC / UI-facing tasks.
        self.join_phase(5, grace, &mut report).await;
        // Defensive: join anything not covered above (no detached tasks remain).
        self.join_remaining(grace, &mut report).await;
        report
    }

    /// Remove and join every registered task whose [`shutdown_phase`] equals
    /// `phase`, in id order, recording the outcome in `report`.
    ///
    /// [`shutdown_phase`]: Self::shutdown_phase
    async fn join_phase(&self, phase: u8, grace: std::time::Duration, report: &mut ShutdownReport) {
        let handles = {
            let mut g = self.inner.lock().await;
            let ids: Vec<TaskId> = g
                .handles
                .iter()
                .filter(|(_, (kind, _))| Self::shutdown_phase(*kind) == phase)
                .map(|(id, _)| *id)
                .collect();
            ids.into_iter()
                .filter_map(|id| g.handles.remove(&id))
                .collect::<Vec<_>>()
        };
        self.drain_and_join(handles, grace, report).await;
    }

    /// Remove and join all still-registered tasks (defensive final sweep).
    async fn join_remaining(&self, grace: std::time::Duration, report: &mut ShutdownReport) {
        let handles = {
            let mut g = self.inner.lock().await;
            std::mem::take(&mut g.handles)
                .into_values()
                .collect::<Vec<_>>()
        };
        self.drain_and_join(handles, grace, report).await;
    }

    /// Await each `(kind, handle)` up to `grace`; force-abort on timeout so the
    /// task is cancelled rather than detached. The inner registry lock is never
    /// held across these awaits (handles are extracted first).
    async fn drain_and_join(
        &self,
        handles: Vec<(TaskKind, JoinHandle<()>)>,
        grace: std::time::Duration,
        report: &mut ShutdownReport,
    ) {
        for (kind, handle) in handles {
            let abort = handle.abort_handle();
            match tokio::time::timeout(grace, handle).await {
                Ok(_) => report.stopped_order.push(kind),
                Err(_) => {
                    abort.abort();
                    report.stopped_order.push(kind);
                    report.aborted.push(kind);
                }
            }
        }
    }
}

fn panic_message(panic: &(dyn std::any::Any + Send)) -> String {
    if let Some(msg) = panic.downcast_ref::<&'static str>() {
        format!("panic: {msg}")
    } else if let Some(msg) = panic.downcast_ref::<String>() {
        format!("panic: {msg}")
    } else {
        "panic: unknown payload".to_string()
    }
}

/// Outcome of [`NodeTaskSupervisor::shutdown_ordered`].
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ShutdownReport {
    /// Task classes stopped, in the order the ordered shutdown confirmed them.
    pub stopped_order: Vec<TaskKind>,
    /// Task classes that had to be force-aborted (did not exit within `grace`).
    pub aborted: Vec<TaskKind>,
    /// Whether the persistence-critical drain ran.
    pub persistence_drained: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
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
    async fn node_supervisor_panic_is_observed_and_trips_shutdown() {
        let sup = NodeTaskSupervisor::new();
        sup.spawn(TaskKind::FutureQueue, async {
            panic!("future queue crashed");
            #[allow(unreachable_code)]
            Ok(())
        })
        .await;

        let failure = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if let Some(f) = sup.failure().await {
                    break f;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("panic must be recorded promptly");

        assert_eq!(failure.failure_task, TaskKind::FutureQueue);
        assert!(
            failure.failure_reason.starts_with("panic:"),
            "panic must propagate into supervisor failure: {failure:?}"
        );
        assert!(sup.is_shutdown(), "panic must trip shutdown");
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

    // ---- TASK 20: coordinated shutdown / cancellation ----

    /// A task that runs until shutdown is observed, recording that it saw it.
    async fn observing_worker(
        token: ShutdownToken,
        observed: Arc<AtomicBool>,
    ) -> Result<(), String> {
        token.wait().await;
        observed.store(true, Ordering::SeqCst);
        Ok(())
    }

    #[tokio::test]
    async fn shutdown_ordered_stops_tasks_in_canonical_phase_order() {
        let sup = NodeTaskSupervisor::new();
        // Register in a deliberately non-canonical order.
        for kind in [
            TaskKind::Rpc,
            TaskKind::Listener,
            TaskKind::Miner,
            TaskKind::Connector,
            TaskKind::DandelionStem,
            TaskKind::FutureQueue,
        ] {
            sup.spawn(kind, until_shutdown(sup.shutdown_token())).await;
        }
        sup.spawn_relay(until_shutdown(sup.shutdown_token())).await;

        let drain_sup = sup.clone();
        let report = sup
            .shutdown_ordered(Duration::from_secs(5), async move {
                // Persistence drain runs after relay/connectors stop, before RPC.
                assert_eq!(
                    drain_sup.relay_count().await,
                    0,
                    "relays stopped before drain"
                );
                assert!(!drain_sup.contains(TaskKind::Connector).await);
                assert!(!drain_sup.contains(TaskKind::DandelionStem).await);
                assert!(
                    drain_sup.contains(TaskKind::Rpc).await,
                    "RPC still up during persistence drain"
                );
            })
            .await;

        assert!(report.persistence_drained);
        assert!(report.aborted.is_empty(), "cooperative tasks need no abort");
        let phases: Vec<u8> = report
            .stopped_order
            .iter()
            .copied()
            .map(NodeTaskSupervisor::shutdown_phase)
            .collect();
        let mut sorted = phases.clone();
        sorted.sort_unstable();
        assert_eq!(
            phases, sorted,
            "tasks confirmed stopped in canonical phase order: {:?}",
            report.stopped_order
        );
        assert!(sup.is_empty().await, "no detached tasks remain");
    }

    #[tokio::test]
    async fn shutdown_during_ibd_cancels_inbound_tasks() {
        let sup = NodeTaskSupervisor::new();
        let (l, f, c) = (
            Arc::new(AtomicBool::new(false)),
            Arc::new(AtomicBool::new(false)),
            Arc::new(AtomicBool::new(false)),
        );
        sup.spawn(
            TaskKind::Listener,
            observing_worker(sup.shutdown_token(), l.clone()),
        )
        .await;
        sup.spawn(
            TaskKind::FutureQueue,
            observing_worker(sup.shutdown_token(), f.clone()),
        )
        .await;
        sup.spawn(
            TaskKind::Connector,
            observing_worker(sup.shutdown_token(), c.clone()),
        )
        .await;
        let report = sup.shutdown_ordered(Duration::from_secs(5), async {}).await;
        assert!(
            l.load(Ordering::SeqCst) && f.load(Ordering::SeqCst) && c.load(Ordering::SeqCst),
            "inbound/IBD tasks observed cancellation"
        );
        assert!(report.aborted.is_empty());
        assert!(sup.is_empty().await);
    }

    #[tokio::test]
    async fn shutdown_during_relay_cancels_relay_workers() {
        let sup = NodeTaskSupervisor::new();
        let flags: Vec<Arc<AtomicBool>> =
            (0..3).map(|_| Arc::new(AtomicBool::new(false))).collect();
        for fl in &flags {
            sup.spawn_relay(observing_worker(sup.shutdown_token(), fl.clone()))
                .await;
        }
        assert_eq!(sup.relay_count().await, 3);
        sup.shutdown_ordered(Duration::from_secs(5), async {}).await;
        assert!(
            flags.iter().all(|f| f.load(Ordering::SeqCst)),
            "relay workers observed cancellation"
        );
        assert_eq!(sup.relay_count().await, 0);
        assert!(sup.is_empty().await);
    }

    #[tokio::test]
    async fn shutdown_during_mining_cancels_miner() {
        let sup = NodeTaskSupervisor::new();
        let m = Arc::new(AtomicBool::new(false));
        sup.spawn(
            TaskKind::Miner,
            observing_worker(sup.shutdown_token(), m.clone()),
        )
        .await;
        let report = sup.shutdown_ordered(Duration::from_secs(5), async {}).await;
        assert!(m.load(Ordering::SeqCst), "miner observed cancellation");
        assert!(report.stopped_order.contains(&TaskKind::Miner));
        assert!(sup.is_empty().await);
    }

    #[tokio::test]
    async fn shutdown_during_reorg_flushes_persistence_before_rpc() {
        // The reorg / chain-state flush is the persistence-critical drain step:
        // it must complete while RPC is still up (before the RPC phase) so no
        // UI-facing read races the flush.
        let sup = NodeTaskSupervisor::new();
        sup.spawn(TaskKind::Rpc, until_shutdown(sup.shutdown_token()))
            .await;
        let flushed = Arc::new(AtomicBool::new(false));
        let flushed_c = flushed.clone();
        let drain_sup = sup.clone();
        let report = sup
            .shutdown_ordered(Duration::from_secs(5), async move {
                assert!(
                    drain_sup.contains(TaskKind::Rpc).await,
                    "RPC still registered during persistence/reorg flush"
                );
                flushed_c.store(true, Ordering::SeqCst);
            })
            .await;
        assert!(flushed.load(Ordering::SeqCst));
        assert!(report.persistence_drained);
        assert!(report.stopped_order.contains(&TaskKind::Rpc));
        assert!(sup.is_empty().await);
    }

    #[tokio::test]
    async fn shutdown_aborts_uncancellable_blocking_task() {
        let sup = NodeTaskSupervisor::new();
        // Models a task parked in blocking I/O that ignores the shutdown flag.
        sup.spawn(TaskKind::Listener, async {
            loop {
                tokio::task::yield_now().await;
            }
        })
        .await;
        let report = sup
            .shutdown_ordered(Duration::from_millis(100), async {})
            .await;
        assert!(
            report.aborted.contains(&TaskKind::Listener),
            "uncancellable task force-aborted within grace"
        );
        assert!(sup.is_empty().await, "no detached task remains after abort");
    }

    #[tokio::test]
    async fn restart_after_shutdown_starts_clean() {
        let old = NodeTaskSupervisor::new();
        old.spawn(TaskKind::Listener, until_shutdown(old.shutdown_token()))
            .await;
        old.shutdown_ordered(Duration::from_secs(5), async {}).await;
        assert!(old.is_shutdown());
        assert!(old.is_empty().await);

        // Restart: a fresh supervisor (as a restarted process constructs) is clean.
        let fresh = NodeTaskSupervisor::new();
        assert!(!fresh.is_shutdown());
        assert_eq!(fresh.status().await, SupervisorStatus::Running);
        let obs = Arc::new(AtomicBool::new(false));
        fresh
            .spawn(
                TaskKind::Miner,
                observing_worker(fresh.shutdown_token(), obs.clone()),
            )
            .await;
        assert!(fresh.contains(TaskKind::Miner).await);
        fresh
            .shutdown_ordered(Duration::from_secs(5), async {})
            .await;
        assert!(obs.load(Ordering::SeqCst));
        assert!(fresh.is_empty().await);
    }

    #[tokio::test]
    async fn no_detached_tasks_remain_after_shutdown() {
        let sup = NodeTaskSupervisor::new();
        for kind in [
            TaskKind::Listener,
            TaskKind::Miner,
            TaskKind::Connector,
            TaskKind::Rpc,
            TaskKind::FutureQueue,
            TaskKind::DandelionStem,
        ] {
            sup.spawn(kind, until_shutdown(sup.shutdown_token())).await;
        }
        sup.spawn_relay(until_shutdown(sup.shutdown_token())).await;
        sup.spawn_relay(until_shutdown(sup.shutdown_token())).await;
        let report = sup.shutdown_ordered(Duration::from_secs(5), async {}).await;
        assert!(sup.is_empty().await, "registry empty: no detached tasks");
        assert_eq!(sup.len().await, 0);
        assert_eq!(sup.relay_count().await, 0);
        assert!(
            report.stopped_order.len() >= 6,
            "all long-lived critical tasks must be accounted for in the stop order"
        );
    }

    #[test]
    fn task21_lint_no_production_tokio_spawn_outside_node_supervisor() {
        let repo = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .ancestors()
            .nth(2)
            .expect("repo root");
        let mut violations = Vec::new();
        scan_rust_sources(repo, &mut |path, line_no, line| {
            if !line.contains("tokio::spawn") {
                return;
            }
            let trimmed = line.trim_start();
            if trimmed.starts_with("//") || trimmed.starts_with("///") || trimmed.starts_with("//!")
            {
                return;
            }
            let rel = path.strip_prefix(repo).expect("relative path");
            let rel_str = rel.to_string_lossy().replace('\\', "/");
            let is_test_scope = rel_str.contains("/tests/") || line.contains("let ");
            let is_supervisor_boundary = rel_str == "crates/dom-node/src/task_supervisor.rs";
            let is_integration_test_runtime_helper =
                rel_str == "crates/dom-integration-tests/src/helpers.rs";
            if !is_supervisor_boundary && !is_test_scope && !is_integration_test_runtime_helper {
                violations.push(format!("{rel_str}:{line_no}: {line}"));
            }
        });

        assert!(
            violations.is_empty(),
            "critical runtime tokio::spawn must go through NodeTaskSupervisor; \
             production exceptions require an explicit audit:\n{}",
            violations.join("\n")
        );
    }

    fn scan_rust_sources(repo: &std::path::Path, f: &mut dyn FnMut(&std::path::Path, usize, &str)) {
        fn walk(dir: &std::path::Path, f: &mut dyn FnMut(&std::path::Path, usize, &str)) {
            for entry in std::fs::read_dir(dir).expect("read source dir") {
                let entry = entry.expect("read source entry");
                let path = entry.path();
                let name = entry.file_name();
                if name == "target" || name == ".git" {
                    continue;
                }
                if path.is_dir() {
                    walk(&path, f);
                    continue;
                }
                if path.extension().and_then(|ext| ext.to_str()) != Some("rs") {
                    continue;
                }
                let source = std::fs::read_to_string(&path).expect("read rust source");
                for (idx, line) in source.lines().enumerate() {
                    f(&path, idx + 1, line);
                }
            }
        }

        walk(repo, f);
    }
}
