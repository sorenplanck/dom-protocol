//! Supervision for async node tasks.
//!
//! Production Tokio task creation is centralized here. Tasks are inserted into a
//! `JoinSet`, so completion, panics, and cancellations are observed by
//! `DomNode::run`.

use dom_core::DomError;
use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use tokio::sync::mpsc;
use tokio::task::{Id, JoinError, JoinSet};
use tracing::debug;

type BoxedNodeTask = Pin<Box<dyn Future<Output = Result<(), DomError>> + Send + 'static>>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NodeTaskPolicy {
    /// Long-lived service tasks required for node correctness.
    Critical,
    /// Per-peer or finite operational tasks. Normal completion is allowed,
    /// but errors and panics still propagate to the supervisor.
    Operational,
}

struct PendingNodeTask {
    name: String,
    policy: NodeTaskPolicy,
    future: BoxedNodeTask,
}

#[derive(Debug)]
struct NodeTaskOutcome {
    name: String,
    policy: NodeTaskPolicy,
    result: Result<(), DomError>,
}

#[derive(Debug, Clone)]
struct TrackedNodeTask {
    name: String,
    policy: NodeTaskPolicy,
}

/// Cloneable handle used by node services to register supervised work.
#[derive(Clone)]
pub(crate) struct NodeTaskSpawner {
    tx: mpsc::UnboundedSender<PendingNodeTask>,
}

impl NodeTaskSpawner {
    pub(crate) fn spawn_critical<N, F>(&self, name: N, future: F) -> Result<(), DomError>
    where
        N: Into<String>,
        F: Future<Output = Result<(), DomError>> + Send + 'static,
    {
        self.spawn(name, NodeTaskPolicy::Critical, future)
    }

    pub(crate) fn spawn_operational<N, F>(&self, name: N, future: F) -> Result<(), DomError>
    where
        N: Into<String>,
        F: Future<Output = Result<(), DomError>> + Send + 'static,
    {
        self.spawn(name, NodeTaskPolicy::Operational, future)
    }

    fn spawn<N, F>(&self, name: N, policy: NodeTaskPolicy, future: F) -> Result<(), DomError>
    where
        N: Into<String>,
        F: Future<Output = Result<(), DomError>> + Send + 'static,
    {
        let task = PendingNodeTask {
            name: name.into(),
            policy,
            future: Box::pin(future),
        };
        self.tx
            .send(task)
            .map_err(|_| DomError::Internal("node task supervisor stopped".into()))
    }
}

/// Owns the JoinSet for every supervised node task.
pub(crate) struct NodeTaskSupervisor {
    rx: mpsc::UnboundedReceiver<PendingNodeTask>,
    tasks: JoinSet<NodeTaskOutcome>,
    tracked: HashMap<Id, TrackedNodeTask>,
}

impl NodeTaskSupervisor {
    pub(crate) fn new() -> (Self, NodeTaskSpawner) {
        let (tx, rx) = mpsc::unbounded_channel();
        (
            Self {
                rx,
                tasks: JoinSet::new(),
                tracked: HashMap::new(),
            },
            NodeTaskSpawner { tx },
        )
    }

    pub(crate) async fn run_until_failure(mut self) -> Result<(), DomError> {
        loop {
            if self.tasks.is_empty() {
                let Some(task) = self.rx.recv().await else {
                    return Ok(());
                };
                self.spawn_registered(task);
                continue;
            }

            tokio::select! {
                maybe_task = self.rx.recv() => {
                    if let Some(task) = maybe_task {
                        self.spawn_registered(task);
                    }
                }
                maybe_join = self.tasks.join_next_with_id() => {
                    if let Some(joined) = maybe_join {
                        self.handle_task_join(joined)?;
                    }
                }
            }
        }
    }

    fn spawn_registered(&mut self, task: PendingNodeTask) {
        let tracked = TrackedNodeTask {
            name: task.name.clone(),
            policy: task.policy,
        };
        // JoinSet is the only production task-spawn surface in dom-node. The
        // returned task id is recorded before control returns to the monitor.
        let abort = self.tasks.spawn(async move {
            let result = task.future.await;
            NodeTaskOutcome {
                name: task.name,
                policy: task.policy,
                result,
            }
        });
        self.tracked.insert(abort.id(), tracked);
    }

    fn handle_task_join(
        &mut self,
        joined: Result<(Id, NodeTaskOutcome), JoinError>,
    ) -> Result<(), DomError> {
        match joined {
            Ok((id, outcome)) => {
                self.tracked.remove(&id);
                self.handle_task_outcome(outcome)
            }
            Err(join_error) => {
                let tracked = self.tracked.remove(&join_error.id());
                let name = tracked
                    .as_ref()
                    .map(|task| task.name.as_str())
                    .unwrap_or("<unknown>");
                let policy = tracked
                    .as_ref()
                    .map(|task| task.policy)
                    .unwrap_or(NodeTaskPolicy::Critical);
                Err(task_join_failure(policy, name, &join_error))
            }
        }
    }

    fn handle_task_outcome(&self, outcome: NodeTaskOutcome) -> Result<(), DomError> {
        match (outcome.policy, outcome.result) {
            (NodeTaskPolicy::Critical, Ok(())) => Err(DomError::Internal(format!(
                "critical task {} exited unexpectedly",
                outcome.name
            ))),
            (NodeTaskPolicy::Critical, Err(error)) => Err(DomError::Internal(format!(
                "critical task {} failed: {error}",
                outcome.name
            ))),
            (NodeTaskPolicy::Operational, Ok(())) => {
                debug!("operational task {} completed", outcome.name);
                Ok(())
            }
            (NodeTaskPolicy::Operational, Err(error)) => Err(DomError::Internal(format!(
                "operational task {} failed: {error}",
                outcome.name
            ))),
        }
    }
}

fn task_join_failure(policy: NodeTaskPolicy, name: &str, join_error: &JoinError) -> DomError {
    let class = match policy {
        NodeTaskPolicy::Critical => "critical",
        NodeTaskPolicy::Operational => "operational",
    };
    DomError::Internal(format!("{class} task {name} join failure: {join_error}"))
}

#[cfg(test)]
mod tests {
    use super::NodeTaskSupervisor;
    use dom_core::DomError;
    use std::fs;
    use std::path::{Path, PathBuf};

    #[tokio::test]
    async fn critical_task_error_propagates() {
        let (supervisor, spawner) = NodeTaskSupervisor::new();
        spawner
            .spawn_critical("consensus-loop", async {
                Err(DomError::Internal("store failed".into()))
            })
            .expect("register task");

        let err = supervisor
            .run_until_failure()
            .await
            .expect_err("critical task failure must stop supervisor");
        assert!(
            err.to_string()
                .contains("critical task consensus-loop failed"),
            "unexpected error: {err}"
        );
    }

    #[tokio::test]
    async fn critical_task_clean_exit_is_not_ignored() {
        let (supervisor, spawner) = NodeTaskSupervisor::new();
        spawner
            .spawn_critical("p2p-listener", async { Ok(()) })
            .expect("register task");

        let err = supervisor
            .run_until_failure()
            .await
            .expect_err("critical task exit must stop supervisor");
        assert!(
            err.to_string()
                .contains("critical task p2p-listener exited unexpectedly"),
            "unexpected error: {err}"
        );
    }

    #[tokio::test]
    async fn operational_task_panic_is_not_detached() {
        let (supervisor, spawner) = NodeTaskSupervisor::new();
        spawner
            .spawn_operational("peer-session", async {
                panic!("peer task bug");
                #[allow(unreachable_code)]
                Ok(())
            })
            .expect("register task");

        let err = supervisor
            .run_until_failure()
            .await
            .expect_err("operational panic must stop supervisor");
        assert!(
            err.to_string()
                .contains("operational task peer-session join failure"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn production_tokio_spawn_is_confined_to_node_task_supervisor() {
        let repo_root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .ancestors()
            .nth(2)
            .expect("workspace root");
        let mut files = Vec::new();
        collect_rs_files(repo_root, &mut files);

        let mut violations = Vec::new();
        for path in files {
            if is_test_only_path(&path) || path.ends_with("crates/dom-node/src/node_tasks.rs") {
                continue;
            }
            let contents = fs::read_to_string(&path).expect("read source file");
            for (idx, line) in contents.lines().enumerate() {
                let trimmed = line.trim_start();
                if !trimmed.starts_with("//") && trimmed.contains("tokio::spawn(") {
                    violations.push(format!(
                        "{}:{}: {}",
                        path.strip_prefix(repo_root).unwrap_or(&path).display(),
                        idx + 1,
                        trimmed
                    ));
                }
            }
        }

        assert!(
            violations.is_empty(),
            "production tokio::spawn must go through NodeTaskSupervisor:\n{}",
            violations.join("\n")
        );
    }

    fn collect_rs_files(dir: &Path, out: &mut Vec<PathBuf>) {
        let entries = fs::read_dir(dir).expect("read dir");
        for entry in entries {
            let path = entry.expect("dir entry").path();
            if should_skip_dir(&path) {
                continue;
            }
            if path.is_dir() {
                collect_rs_files(&path, out);
            } else if path.extension().and_then(|ext| ext.to_str()) == Some("rs") {
                out.push(path);
            }
        }
    }

    fn should_skip_dir(path: &Path) -> bool {
        matches!(
            path.file_name().and_then(|name| name.to_str()),
            Some(".git" | "target")
        )
    }

    fn is_test_only_path(path: &Path) -> bool {
        let display = path.to_string_lossy();
        display.contains("/tests/")
            || display.contains("/benches/")
            || display.contains("/crates/dom-integration-tests/")
    }
}
