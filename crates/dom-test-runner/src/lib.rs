use anyhow::{anyhow, Context, Result};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::ffi::OsStr;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const RUNNER_ROOT: &str = "target/dom-test-runner";
const LOG_DIR: &str = "logs";
const REPORT_DIR: &str = "reports";
const LATEST_REPORT: &str = "latest-report.txt";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Profile {
    FastCheck,
    Unit,
    Mempool,
    Node,
    Wire,
    Pow,
    Chain,
    Store,
    Wallet,
    WalletApp,
    Integration,
    IntegrationMempool,
    IntegrationNetwork,
    TwoNode,
    Reorg,
    Ibd,
    Full,
    All,
}

impl Profile {
    pub fn name(self) -> &'static str {
        match self {
            Profile::FastCheck => "fast-check",
            Profile::Unit => "unit",
            Profile::Mempool => "mempool",
            Profile::Node => "node",
            Profile::Wire => "wire",
            Profile::Pow => "pow",
            Profile::Chain => "chain",
            Profile::Store => "store",
            Profile::Wallet => "wallet",
            Profile::WalletApp => "wallet-app",
            Profile::Integration => "integration",
            Profile::IntegrationMempool => "integration-mempool",
            Profile::IntegrationNetwork => "integration-network",
            Profile::TwoNode => "two-node",
            Profile::Reorg => "reorg",
            Profile::Ibd => "ibd",
            Profile::Full => "full",
            Profile::All => "all",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StepStatus {
    Pass,
    Fail,
    Skipped,
    Blocked,
}

impl StepStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            StepStatus::Pass => "PASS",
            StepStatus::Fail => "FAIL",
            StepStatus::Skipped => "SKIPPED",
            StepStatus::Blocked => "BLOCKED",
        }
    }
}

#[derive(Debug, Clone)]
pub struct CommandStep {
    pub label: String,
    pub program: String,
    pub args: Vec<String>,
    pub skip_if_missing: Option<PathBuf>,
}

#[derive(Debug, Clone)]
pub struct StepResult {
    pub label: String,
    pub command: String,
    pub status: StepStatus,
    pub exit_code: Option<i32>,
    pub log_path: PathBuf,
    pub duration: Duration,
    pub reason: Option<String>,
}

#[derive(Debug, Clone)]
pub struct RunSummary {
    pub run_name: String,
    pub selected_profile: String,
    pub started_at: String,
    pub finished_at: String,
    pub duration: Duration,
    pub env: Vec<(String, String)>,
    pub steps: Vec<StepResult>,
    pub log_dir: PathBuf,
    pub report_dir: PathBuf,
    pub final_status: StepStatus,
    pub reason: Option<String>,
}

#[derive(Debug, Clone)]
pub struct AffectedSelection {
    pub files: Vec<String>,
    pub profiles: Vec<SelectedProfile>,
}

#[derive(Debug, Clone)]
pub struct SelectedProfile {
    pub profile: Profile,
    pub reason: String,
}

pub fn runner_root(repo_root: &Path) -> PathBuf {
    repo_root.join(RUNNER_ROOT)
}

pub fn detect_repo_root(start: &Path) -> Result<PathBuf> {
    let output = Command::new("git")
        .args(["rev-parse", "--show-toplevel"])
        .current_dir(start)
        .output()
        .with_context(|| format!("failed to invoke git in {}", start.display()))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(anyhow!(
            "not inside a DOM repository: git rev-parse failed from {}: {}",
            start.display(),
            stderr.trim()
        ));
    }
    let root = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if root.is_empty() {
        return Err(anyhow!("git did not return a repository root"));
    }
    Ok(PathBuf::from(root))
}

pub fn default_env() -> Vec<(String, String)> {
    vec![
        ("DOM_NETWORK".into(), "regtest".into()),
        ("DOM_REGTEST_FAST_MINING".into(), "1".into()),
        ("RUST_BACKTRACE".into(), "1".into()),
        ("CARGO_TERM_COLOR".into(), "never".into()),
    ]
}

pub fn system_timestamp_label() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    secs.to_string()
}

pub fn ensure_directories(repo_root: &Path) -> Result<(PathBuf, PathBuf)> {
    let root = runner_root(repo_root);
    let logs = root.join(LOG_DIR);
    let reports = root.join(REPORT_DIR);
    fs::create_dir_all(&logs)?;
    fs::create_dir_all(&reports)?;
    Ok((logs, reports))
}

pub fn clean_runner_data(repo_root: &Path) -> Result<()> {
    let root = runner_root(repo_root);
    if root.exists() {
        fs::remove_dir_all(&root)?;
    }
    Ok(())
}

pub fn write_text_file(path: &Path, contents: &str) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut file = fs::File::create(path)?;
    file.write_all(contents.as_bytes())?;
    Ok(())
}

pub fn changed_files(repo_root: &Path) -> Result<Vec<String>> {
    let mut files = BTreeSet::new();
    for args in [
        vec!["diff", "--name-only"],
        vec!["diff", "--cached", "--name-only"],
    ] {
        let output = Command::new("git")
            .args(args)
            .current_dir(repo_root)
            .output()?;
        if output.status.success() {
            for line in String::from_utf8_lossy(&output.stdout).lines() {
                let trimmed = line.trim();
                if !trimmed.is_empty() {
                    files.insert(trimmed.to_string());
                }
            }
        }
    }

    let origin_exists = Command::new("git")
        .args(["rev-parse", "--verify", "origin/main"])
        .current_dir(repo_root)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);
    if origin_exists {
        let output = Command::new("git")
            .args(["diff", "--name-only", "origin/main...HEAD"])
            .current_dir(repo_root)
            .output()?;
        if output.status.success() {
            for line in String::from_utf8_lossy(&output.stdout).lines() {
                let trimmed = line.trim();
                if !trimmed.is_empty() {
                    files.insert(trimmed.to_string());
                }
            }
        }
    }

    Ok(files.into_iter().collect())
}

fn path_has_prefix(path: &str, prefix: &str) -> bool {
    path == prefix || path.starts_with(prefix)
}

fn push_profile(
    profiles: &mut BTreeMap<Profile, String>,
    profile: Profile,
    reason: impl Into<String>,
) {
    profiles.entry(profile).or_insert_with(|| reason.into());
}

pub fn select_profiles(changed_files: &[String]) -> AffectedSelection {
    if changed_files.is_empty() {
        return AffectedSelection {
            files: Vec::new(),
            profiles: vec![SelectedProfile {
                profile: Profile::FastCheck,
                reason: "No local changes detected; running fast-check only.".into(),
            }],
        };
    }

    let mut profiles: BTreeMap<Profile, String> = BTreeMap::new();
    let mut saw_non_docs = false;
    for file in changed_files {
        if path_has_prefix(file, "crates/dom-mempool/") {
            saw_non_docs = true;
            push_profile(
                &mut profiles,
                Profile::Mempool,
                "dom-mempool changed; validate mempool/node convergence",
            );
            push_profile(
                &mut profiles,
                Profile::IntegrationMempool,
                "mempool behavior affects relay/reorg cleanup",
            );
        } else if path_has_prefix(file, "crates/dom-node/") {
            saw_non_docs = true;
            push_profile(
                &mut profiles,
                Profile::Node,
                "dom-node changed; validate node runtime behavior",
            );
            push_profile(
                &mut profiles,
                Profile::Integration,
                "node changes affect integration replay/convergence",
            );
        } else if path_has_prefix(file, "crates/dom-wire/") {
            saw_non_docs = true;
            push_profile(
                &mut profiles,
                Profile::Wire,
                "dom-wire changed; validate wire encoding and node integration",
            );
            push_profile(
                &mut profiles,
                Profile::IntegrationNetwork,
                "wire changes affect network-level convergence",
            );
        } else if path_has_prefix(file, "crates/dom-pow/") {
            saw_non_docs = true;
            push_profile(
                &mut profiles,
                Profile::Pow,
                "dom-pow changed; validate PoW and miner behavior",
            );
            push_profile(
                &mut profiles,
                Profile::TwoNode,
                "PoW changes affect block production across nodes",
            );
            push_profile(
                &mut profiles,
                Profile::Reorg,
                "PoW changes affect reorg convergence",
            );
        } else if path_has_prefix(file, "crates/dom-chain/") {
            saw_non_docs = true;
            push_profile(
                &mut profiles,
                Profile::Chain,
                "dom-chain changed; validate chain validation and replay",
            );
            push_profile(
                &mut profiles,
                Profile::Ibd,
                "chain changes affect IBD correctness",
            );
            push_profile(
                &mut profiles,
                Profile::Reorg,
                "chain changes affect reorg promotion",
            );
        } else if path_has_prefix(file, "crates/dom-store/") {
            saw_non_docs = true;
            push_profile(
                &mut profiles,
                Profile::Store,
                "dom-store changed; validate persistence and reopen behavior",
            );
            push_profile(
                &mut profiles,
                Profile::Chain,
                "store changes affect chain reopen and integrity",
            );
        } else if path_has_prefix(file, "crates/dom-wallet/") {
            saw_non_docs = true;
            push_profile(
                &mut profiles,
                Profile::Wallet,
                "dom-wallet changed; validate wallet lifecycle and recovery",
            );
        } else if path_has_prefix(file, "crates/dom-wallet-app/") {
            saw_non_docs = true;
            push_profile(
                &mut profiles,
                Profile::WalletApp,
                "dom-wallet-app changed; validate app build and unit coverage",
            );
        } else if path_has_prefix(file, "crates/dom-integration-tests/") {
            saw_non_docs = true;
            push_profile(
                &mut profiles,
                Profile::Integration,
                "integration tests changed; run integration suite",
            );
        } else if path_has_prefix(file, "crates/dom-test-runner/") {
            saw_non_docs = true;
            push_profile(
                &mut profiles,
                Profile::FastCheck,
                "dom-test-runner changed; validate orchestration crate and fast-check",
            );
        } else if path_has_prefix(file, "crates/dom-agent-runner/") {
            saw_non_docs = true;
            push_profile(
                &mut profiles,
                Profile::FastCheck,
                "dom-agent-runner changed; validate orchestration crate and fast-check",
            );
        } else if path_has_prefix(file, ".github/workflows/") {
            saw_non_docs = true;
            push_profile(
                &mut profiles,
                Profile::FastCheck,
                "workflow changes affect the automation build path",
            );
        } else if path_has_prefix(file, "docs/") {
            // docs-only changes do not add profiles by themselves.
        } else {
            saw_non_docs = true;
            push_profile(
                &mut profiles,
                Profile::FastCheck,
                "unclassified change; run the safe baseline",
            );
        }
    }

    if saw_non_docs {
        push_profile(
            &mut profiles,
            Profile::FastCheck,
            "baseline workspace check for all non-doc changes",
        );
    } else {
        push_profile(
            &mut profiles,
            Profile::FastCheck,
            "docs-only change; run the safe baseline",
        );
    }

    let mut selected: Vec<SelectedProfile> = profiles
        .into_iter()
        .map(|(profile, reason)| SelectedProfile { profile, reason })
        .collect();
    if selected.is_empty() {
        selected.push(SelectedProfile {
            profile: Profile::FastCheck,
            reason: "No local changes detected; running fast-check only.".into(),
        });
    }
    AffectedSelection {
        files: changed_files.to_vec(),
        profiles: selected,
    }
}

pub fn explain_selection(selection: &AffectedSelection) -> String {
    let mut out = String::new();
    if selection.files.is_empty() {
        out.push_str("Changed:\n<none>\n\nSelected:\n- fast-check: No local changes detected; running fast-check only.\n");
        return out;
    }
    out.push_str("Changed:\n");
    for file in &selection.files {
        out.push_str(file);
        out.push('\n');
    }
    out.push_str("\nSelected:\n");
    for profile in &selection.profiles {
        out.push_str("- ");
        out.push_str(profile.profile.name());
        out.push_str(": ");
        out.push_str(&profile.reason);
        out.push('\n');
    }
    out
}

pub fn env_map() -> HashMap<String, String> {
    default_env().into_iter().collect()
}

pub fn command_string(program: &str, args: &[String]) -> String {
    let mut s = String::from(program);
    for arg in args {
        s.push(' ');
        if arg.contains(' ') {
            s.push('"');
            s.push_str(arg);
            s.push('"');
        } else {
            s.push_str(arg);
        }
    }
    s
}

pub fn run_command(
    repo_root: &Path,
    logs_dir: &Path,
    step_index: usize,
    command: &CommandStep,
    env: &[(String, String)],
) -> Result<StepResult> {
    let label = command.label.clone();
    if let Some(required_path) = &command.skip_if_missing {
        if !required_path.exists() {
            let log_path =
                logs_dir.join(format!("{}-{}.log", step_index, sanitize_filename(&label)));
            write_text_file(
                &log_path,
                &format!(
                    "SKIPPED: {}\nReason: missing {}\n",
                    command_string(&command.program, &command.args),
                    required_path.display()
                ),
            )?;
            return Ok(StepResult {
                label,
                command: command_string(&command.program, &command.args),
                status: StepStatus::Skipped,
                exit_code: None,
                log_path,
                duration: Duration::from_secs(0),
                reason: Some(format!("missing {}", required_path.display())),
            });
        }
    }

    let log_path = logs_dir.join(format!("{}-{}.log", step_index, sanitize_filename(&label)));
    let start = Instant::now();
    let output = Command::new(&command.program)
        .args(&command.args)
        .current_dir(repo_root)
        .envs(env.iter().cloned())
        .output()
        .with_context(|| format!("failed to execute {}", command.program))?;
    let duration = start.elapsed();
    let mut log = String::new();
    log.push_str(&format!(
        "COMMAND: {}\n",
        command_string(&command.program, &command.args)
    ));
    log.push_str(&format!("STATUS: {}\n", output.status));
    log.push_str("STDOUT:\n");
    log.push_str(&String::from_utf8_lossy(&output.stdout));
    log.push_str("\nSTDERR:\n");
    log.push_str(&String::from_utf8_lossy(&output.stderr));
    write_text_file(&log_path, &log)?;

    let status = if output.status.success() {
        StepStatus::Pass
    } else {
        StepStatus::Fail
    };

    Ok(StepResult {
        label,
        command: command_string(&command.program, &command.args),
        status,
        exit_code: output.status.code(),
        log_path,
        duration,
        reason: if status == StepStatus::Fail {
            Some("command exited non-zero".into())
        } else {
            None
        },
    })
}

fn sanitize_filename(label: &str) -> String {
    label
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
        .collect()
}

fn format_duration(duration: Duration) -> String {
    let secs = duration.as_secs();
    let millis = duration.subsec_millis();
    format!("{secs}.{millis:03}s")
}

pub fn profile_commands(profile: Profile, repo_root: &Path) -> Result<Vec<CommandStep>> {
    let two_node = repo_root.join("crates/dom-integration-tests/tests/two_node.rs");
    let three_node = repo_root.join("crates/dom-integration-tests/tests/three_node.rs");
    let wallet_app_tests = repo_root.join("crates/dom-wallet-app/tests");
    let mut commands = Vec::new();
    match profile {
        Profile::FastCheck => {
            commands.push(CommandStep {
                label: "fast-check".into(),
                program: "cargo".into(),
                args: vec![
                    "check".into(),
                    "-p".into(),
                    "dom-mempool".into(),
                    "-p".into(),
                    "dom-node".into(),
                    "-p".into(),
                    "dom-integration-tests".into(),
                ],
                skip_if_missing: None,
            });
        }
        Profile::Unit => commands.push(CommandStep {
            label: "unit".into(),
            program: "cargo".into(),
            args: vec!["test".into(), "--workspace".into(), "--lib".into()],
            skip_if_missing: None,
        }),
        Profile::Mempool => commands.push(CommandStep {
            label: "mempool".into(),
            program: "cargo".into(),
            args: vec![
                "test".into(),
                "-p".into(),
                "dom-mempool".into(),
                "-p".into(),
                "dom-node".into(),
                "--".into(),
                "--test-threads=1".into(),
            ],
            skip_if_missing: None,
        }),
        Profile::Node => commands.push(CommandStep {
            label: "node".into(),
            program: "cargo".into(),
            args: vec![
                "test".into(),
                "-p".into(),
                "dom-node".into(),
                "--".into(),
                "--test-threads=1".into(),
            ],
            skip_if_missing: None,
        }),
        Profile::Wire => commands.push(CommandStep {
            label: "wire".into(),
            program: "cargo".into(),
            args: vec![
                "test".into(),
                "-p".into(),
                "dom-wire".into(),
                "--".into(),
                "--test-threads=1".into(),
            ],
            skip_if_missing: None,
        }),
        Profile::Pow => {
            commands.push(CommandStep {
                label: "pow-lib".into(),
                program: "cargo".into(),
                args: vec!["test".into(), "-p".into(), "dom-pow".into()],
                skip_if_missing: None,
            });
            commands.push(CommandStep {
                label: "pow-node-miner".into(),
                program: "cargo".into(),
                args: vec![
                    "test".into(),
                    "-p".into(),
                    "dom-node".into(),
                    "miner".into(),
                ],
                skip_if_missing: None,
            });
        }
        Profile::Chain => commands.push(CommandStep {
            label: "chain".into(),
            program: "cargo".into(),
            args: vec![
                "test".into(),
                "-p".into(),
                "dom-chain".into(),
                "--".into(),
                "--test-threads=1".into(),
            ],
            skip_if_missing: None,
        }),
        Profile::Store => commands.push(CommandStep {
            label: "store".into(),
            program: "cargo".into(),
            args: vec![
                "test".into(),
                "-p".into(),
                "dom-store".into(),
                "--".into(),
                "--test-threads=1".into(),
            ],
            skip_if_missing: None,
        }),
        Profile::Wallet => commands.push(CommandStep {
            label: "wallet".into(),
            program: "cargo".into(),
            args: vec![
                "test".into(),
                "-p".into(),
                "dom-wallet".into(),
                "--".into(),
                "--test-threads=1".into(),
            ],
            skip_if_missing: None,
        }),
        Profile::WalletApp => {
            commands.push(CommandStep {
                label: "wallet-app-check".into(),
                program: "cargo".into(),
                args: vec!["check".into(), "-p".into(), "dom-wallet-app".into()],
                skip_if_missing: None,
            });
            commands.push(CommandStep {
                label: "wallet-app-test".into(),
                program: "cargo".into(),
                args: vec![
                    "test".into(),
                    "-p".into(),
                    "dom-wallet-app".into(),
                    "--".into(),
                    "--test-threads=1".into(),
                ],
                skip_if_missing: Some(wallet_app_tests),
            });
        }
        Profile::Integration => commands.push(CommandStep {
            label: "integration".into(),
            program: "cargo".into(),
            args: vec![
                "test".into(),
                "-p".into(),
                "dom-integration-tests".into(),
                "--".into(),
                "--test-threads=1".into(),
            ],
            skip_if_missing: None,
        }),
        Profile::IntegrationMempool => commands.push(CommandStep {
            label: "integration-mempool".into(),
            program: "cargo".into(),
            args: vec![
                "test".into(),
                "-p".into(),
                "dom-integration-tests".into(),
                "--test".into(),
                "mempool_relay".into(),
                "--".into(),
                "--test-threads=1".into(),
            ],
            skip_if_missing: None,
        }),
        Profile::IntegrationNetwork => {
            commands.push(CommandStep {
                label: "integration-network-two-node".into(),
                program: "cargo".into(),
                args: vec![
                    "test".into(),
                    "-p".into(),
                    "dom-integration-tests".into(),
                    "--test".into(),
                    "two_node".into(),
                    "--".into(),
                    "--test-threads=1".into(),
                ],
                skip_if_missing: Some(two_node),
            });
            commands.push(CommandStep {
                label: "integration-network-three-node".into(),
                program: "cargo".into(),
                args: vec![
                    "test".into(),
                    "-p".into(),
                    "dom-integration-tests".into(),
                    "--test".into(),
                    "three_node".into(),
                    "--".into(),
                    "--test-threads=1".into(),
                ],
                skip_if_missing: Some(three_node),
            });
        }
        Profile::TwoNode => commands.push(CommandStep {
            label: "two-node".into(),
            program: "cargo".into(),
            args: vec![
                "test".into(),
                "-p".into(),
                "dom-integration-tests".into(),
                "--test".into(),
                "two_node".into(),
                "--".into(),
                "--test-threads=1".into(),
            ],
            skip_if_missing: Some(two_node),
        }),
        Profile::Reorg => commands.push(CommandStep {
            label: "reorg".into(),
            program: "cargo".into(),
            args: vec![
                "test".into(),
                "-p".into(),
                "dom-integration-tests".into(),
                "--test".into(),
                "reorg".into(),
                "--".into(),
                "--test-threads=1".into(),
            ],
            skip_if_missing: None,
        }),
        Profile::Ibd => commands.push(CommandStep {
            label: "ibd".into(),
            program: "cargo".into(),
            args: vec![
                "test".into(),
                "-p".into(),
                "dom-integration-tests".into(),
                "--test".into(),
                "ibd".into(),
                "--".into(),
                "--test-threads=1".into(),
            ],
            skip_if_missing: None,
        }),
        Profile::Full => {
            commands.push(CommandStep {
                label: "full-check".into(),
                program: "cargo".into(),
                args: vec!["check".into(), "--workspace".into()],
                skip_if_missing: None,
            });
            commands.push(CommandStep {
                label: "full-test".into(),
                program: "cargo".into(),
                args: vec!["test".into(), "--workspace".into()],
                skip_if_missing: None,
            });
            commands.push(CommandStep {
                label: "full-clippy".into(),
                program: "cargo".into(),
                args: vec![
                    "clippy".into(),
                    "--workspace".into(),
                    "--all-targets".into(),
                    "--all-features".into(),
                    "--".into(),
                    "-D".into(),
                    "warnings".into(),
                ],
                skip_if_missing: None,
            });
        }
        Profile::All => {
            commands.push(CommandStep {
                label: "all-check".into(),
                program: "cargo".into(),
                args: vec!["check".into(), "--workspace".into()],
                skip_if_missing: None,
            });
            commands.push(CommandStep {
                label: "all-test".into(),
                program: "cargo".into(),
                args: vec![
                    "test".into(),
                    "--workspace".into(),
                    "--".into(),
                    "--include-ignored".into(),
                    "--test-threads=1".into(),
                ],
                skip_if_missing: None,
            });
            commands.push(CommandStep {
                label: "all-clippy".into(),
                program: "cargo".into(),
                args: vec![
                    "clippy".into(),
                    "--workspace".into(),
                    "--all-targets".into(),
                    "--all-features".into(),
                    "--".into(),
                    "-D".into(),
                    "warnings".into(),
                ],
                skip_if_missing: None,
            });
        }
    }
    Ok(commands)
}

fn unique_crates_for_profile(profile: Profile) -> &'static [&'static str] {
    match profile {
        Profile::FastCheck => &["dom-mempool", "dom-node", "dom-integration-tests"],
        Profile::Unit => &[],
        Profile::Mempool => &["dom-mempool", "dom-node"],
        Profile::Node => &["dom-node"],
        Profile::Wire => &["dom-wire", "dom-node"],
        Profile::Pow => &["dom-pow", "dom-node"],
        Profile::Chain => &["dom-chain"],
        Profile::Store => &["dom-store", "dom-chain", "dom-node"],
        Profile::Wallet => &["dom-wallet", "dom-node"],
        Profile::WalletApp => &["dom-wallet-app"],
        Profile::Integration => &["dom-integration-tests"],
        Profile::IntegrationMempool => &["dom-integration-tests"],
        Profile::IntegrationNetwork => &["dom-integration-tests"],
        Profile::TwoNode => &["dom-integration-tests"],
        Profile::Reorg => &["dom-integration-tests"],
        Profile::Ibd => &["dom-integration-tests"],
        Profile::Full => &["dom-mempool", "dom-node", "dom-integration-tests"],
        Profile::All => &["dom-mempool", "dom-node", "dom-integration-tests"],
    }
}

pub fn affected_crates_for_profiles(profiles: &[SelectedProfile]) -> Vec<String> {
    let mut crates = BTreeSet::new();
    for profile in profiles {
        for krate in unique_crates_for_profile(profile.profile) {
            crates.insert((*krate).to_string());
        }
    }
    crates.into_iter().collect()
}

pub fn command_plan_for_pre_push(
    repo_root: &Path,
    selection: &AffectedSelection,
) -> Result<Vec<CommandStep>> {
    let mut steps = Vec::new();
    let mut seen = BTreeSet::new();
    for profile in &selection.profiles {
        for step in profile_commands(profile.profile, repo_root)? {
            if seen.insert(step.label.clone()) {
                steps.push(step);
            }
        }
    }

    let crates = affected_crates_for_profiles(&selection.profiles);
    for krate in crates {
        let label = format!("check-{krate}");
        if seen.insert(label.clone()) {
            steps.push(CommandStep {
                label,
                program: "cargo".into(),
                args: vec!["check".into(), "-p".into(), krate.clone()],
                skip_if_missing: None,
            });
        }
        let label = format!("clippy-{krate}");
        if seen.insert(label.clone()) {
            steps.push(CommandStep {
                label,
                program: "cargo".into(),
                args: vec![
                    "clippy".into(),
                    "-p".into(),
                    krate.clone(),
                    "--all-targets".into(),
                    "--".into(),
                    "-D".into(),
                    "warnings".into(),
                ],
                skip_if_missing: None,
            });
        }
    }

    Ok(steps)
}

pub fn run_steps(
    repo_root: &Path,
    run_name: &str,
    selected_profile: &str,
    steps: Vec<CommandStep>,
) -> Result<RunSummary> {
    let (logs_dir, reports_dir) = ensure_directories(repo_root)?;
    let env = default_env();
    let started = Instant::now();
    let started_at = system_timestamp_label();
    let mut results = Vec::new();
    for (idx, step) in steps.iter().enumerate() {
        let result = match run_command(repo_root, &logs_dir, idx + 1, step, &env) {
            Ok(result) => result,
            Err(err) => {
                let log_path = logs_dir.join(format!(
                    "{}-{}.log",
                    idx + 1,
                    sanitize_filename(&step.label)
                ));
                let _ = write_text_file(&log_path, &format!("BLOCKED: {}\n", err));
                StepResult {
                    label: step.label.clone(),
                    command: command_string(&step.program, &step.args),
                    status: StepStatus::Blocked,
                    exit_code: None,
                    log_path,
                    duration: Duration::from_secs(0),
                    reason: Some(err.to_string()),
                }
            }
        };
        println!("{}: {}", result.status.as_str(), result.command);
        if let Some(reason) = &result.reason {
            println!("  reason: {reason}");
        }
        println!("  log: {}", result.log_path.display());
        results.push(result);
    }
    let final_status = if results.iter().any(|r| r.status == StepStatus::Fail) {
        StepStatus::Fail
    } else if results.iter().any(|r| r.status == StepStatus::Blocked) {
        StepStatus::Blocked
    } else if results.iter().all(|r| r.status == StepStatus::Skipped) {
        StepStatus::Skipped
    } else {
        StepStatus::Pass
    };
    let duration = started.elapsed();
    let finished_at = system_timestamp_label();
    let summary = RunSummary {
        run_name: run_name.into(),
        selected_profile: selected_profile.into(),
        started_at,
        finished_at,
        duration,
        env,
        steps: results,
        log_dir: logs_dir,
        report_dir: reports_dir.clone(),
        final_status,
        reason: None,
    };
    write_run_report(repo_root, &summary)?;
    Ok(summary)
}

pub fn write_run_report(repo_root: &Path, summary: &RunSummary) -> Result<()> {
    let reports_dir = runner_root(repo_root).join(REPORT_DIR);
    fs::create_dir_all(&reports_dir)?;
    let timestamped = reports_dir.join(format!(
        "{}-{}.txt",
        summary.selected_profile, summary.started_at
    ));
    let latest = reports_dir.join(LATEST_REPORT);
    let mut text = String::new();
    text.push_str(&format!("date/time: {}\n", summary.started_at));
    text.push_str(&format!("selected profile: {}\n", summary.selected_profile));
    text.push_str("environment variables used:\n");
    for (k, v) in &summary.env {
        text.push_str(&format!("  {}={}\n", k, v));
    }
    text.push_str("cargo commands executed:\n");
    for step in &summary.steps {
        text.push_str(&format!("  [{}] {}\n", step.status.as_str(), step.command));
        text.push_str(&format!("    log: {}\n", step.log_path.display()));
        if let Some(reason) = &step.reason {
            text.push_str(&format!("    reason: {}\n", reason));
        }
    }
    text.push_str(&format!(
        "total duration: {}\n",
        format_duration(summary.duration)
    ));
    text.push_str(&format!("logs: {}\n", summary.log_dir.display()));
    text.push_str(&format!(
        "final status: {}\n",
        summary.final_status.as_str()
    ));
    if let Some(reason) = &summary.reason {
        text.push_str(&format!("reason: {}\n", reason));
    }
    write_text_file(&timestamped, &text)?;
    write_text_file(&latest, &text)?;
    Ok(())
}

pub fn latest_report(repo_root: &Path) -> Result<String> {
    let path = runner_root(repo_root).join(REPORT_DIR).join(LATEST_REPORT);
    Ok(fs::read_to_string(path)?)
}

pub fn build_report_only(repo_root: &Path) -> Result<()> {
    let report = latest_report(repo_root)?;
    println!("{report}");
    Ok(())
}

pub fn command_exists(program: &str) -> bool {
    Command::new(program)
        .arg("--version")
        .output()
        .map(|out| out.status.success())
        .unwrap_or(false)
}

pub fn cargo_command_exists() -> bool {
    command_exists("cargo")
}

pub fn git_command_exists() -> bool {
    command_exists("git")
}

pub fn rustc_command_exists() -> bool {
    command_exists("rustc")
}

pub fn list_prompt_files(repo_root: &Path) -> Result<Vec<PathBuf>> {
    let dir = repo_root.join("prompts");
    if !dir.exists() {
        return Ok(Vec::new());
    }
    let mut out = Vec::new();
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.extension() == Some(OsStr::new("txt")) {
            out.push(path);
        }
    }
    out.sort();
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn temp_repo() -> (TempDir, PathBuf) {
        let dir = TempDir::new().unwrap();
        let root = dir.path().to_path_buf();
        fs::create_dir_all(root.join("crates/dom-node")).unwrap();
        fs::create_dir_all(root.join("crates/dom-integration-tests/tests")).unwrap();
        fs::create_dir_all(root.join("target/dom-test-runner")).unwrap();
        (dir, root)
    }

    #[test]
    fn explain_affected_mentions_reasons() {
        let selection = select_profiles(&["crates/dom-node/src/node.rs".into()]);
        let text = explain_selection(&selection);
        assert!(text.contains("dom-node changed"));
        assert!(text.contains("integration"));
    }

    #[test]
    fn affected_maps_mempool_to_relevant_profiles() {
        let selection = select_profiles(&["crates/dom-mempool/src/lib.rs".into()]);
        let names: Vec<&str> = selection
            .profiles
            .iter()
            .map(|p| p.profile.name())
            .collect();
        assert!(names.contains(&"mempool"));
        assert!(names.contains(&"integration-mempool"));
    }

    #[test]
    fn pow_profile_includes_node_miner_test() {
        let root = PathBuf::from("/tmp/dom-test-runner");
        let commands = profile_commands(Profile::Pow, &root).unwrap();
        let joined = commands
            .iter()
            .map(|c| command_string(&c.program, &c.args))
            .collect::<Vec<_>>()
            .join("\n");
        assert!(joined.contains("cargo test -p dom-pow"));
        assert!(joined.contains("cargo test -p dom-node miner"));
    }

    #[test]
    fn detect_repo_root_fails_outside_repo() {
        let dir = TempDir::new().unwrap();
        assert!(detect_repo_root(dir.path()).is_err());
    }

    #[test]
    fn no_changes_runs_fast_check_only() {
        let selection = select_profiles(&[]);
        assert_eq!(selection.profiles.len(), 1);
        assert_eq!(selection.profiles[0].profile, Profile::FastCheck);
    }

    #[test]
    fn clean_only_removes_runner_data() {
        let (_temp, root) = temp_repo();
        let runner = runner_root(&root);
        fs::create_dir_all(&runner).unwrap();
        fs::write(root.join("keep.txt"), "keep").unwrap();
        clean_runner_data(&root).unwrap();
        assert!(!runner.exists());
        assert!(root.join("keep.txt").exists());
    }

    #[test]
    fn report_is_written() {
        let (_temp, root) = temp_repo();
        let summary = RunSummary {
            run_name: "test".into(),
            selected_profile: "fast-check".into(),
            started_at: "123".into(),
            finished_at: "124".into(),
            duration: Duration::from_secs(1),
            env: default_env(),
            steps: vec![StepResult {
                label: "fast-check".into(),
                command: "cargo check".into(),
                status: StepStatus::Pass,
                exit_code: Some(0),
                log_path: root.join("log.txt"),
                duration: Duration::from_secs(1),
                reason: None,
            }],
            log_dir: root.join("logs"),
            report_dir: root.join("reports"),
            final_status: StepStatus::Pass,
            reason: None,
        };
        write_run_report(&root, &summary).unwrap();
        assert!(runner_root(&root)
            .join(REPORT_DIR)
            .join(LATEST_REPORT)
            .exists());
    }
}
