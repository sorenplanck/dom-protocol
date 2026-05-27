use anyhow::{anyhow, Context, Result};
pub use dom_test_runner::changed_files;
use dom_test_runner::{
    command_plan_for_pre_push, detect_repo_root, explain_selection, select_profiles,
    AffectedSelection, Profile,
};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

const RUNNER_ROOT: &str = "target/dom-agent-runner";
const RUNS_DIR: &str = "runs";
const WORKTREES_DIR: &str = "worktrees";
const LATEST_RUN: &str = "latest-run.txt";

#[derive(Debug, Clone)]
pub struct PromptInput {
    pub source_description: String,
    pub content: String,
    pub resolved_path: Option<PathBuf>,
}

#[derive(Debug, Clone)]
pub struct RunPaths {
    pub root: PathBuf,
    pub run_dir: PathBuf,
    pub worktree_dir: PathBuf,
    pub prompt_file: PathBuf,
    pub codex_log: PathBuf,
    pub test_log: PathBuf,
    pub git_status_before: PathBuf,
    pub git_status_after: PathBuf,
    pub changed_files: PathBuf,
    pub staged_files: PathBuf,
    pub commit_file: PathBuf,
    pub remote_head: PathBuf,
    pub final_report: PathBuf,
}

pub fn runner_root(repo_root: &Path) -> PathBuf {
    repo_root.join(RUNNER_ROOT)
}

pub fn ensure_runner_dirs(repo_root: &Path) -> Result<(PathBuf, PathBuf, PathBuf)> {
    let root = runner_root(repo_root);
    let runs = root.join(RUNS_DIR);
    let worktrees = root.join(WORKTREES_DIR);
    fs::create_dir_all(&runs)?;
    fs::create_dir_all(&worktrees)?;
    Ok((root, runs, worktrees))
}

pub fn clean_agent_data(repo_root: &Path) -> Result<()> {
    let root = runner_root(repo_root);
    if root.exists() {
        fs::remove_dir_all(&root)?;
    }
    Ok(())
}

pub fn agent_latest_run(repo_root: &Path) -> Result<String> {
    let path = runner_root(repo_root).join(LATEST_RUN);
    Ok(fs::read_to_string(path)?)
}

pub fn build_or_verify_test_runner(repo_root: &Path) -> Result<PathBuf> {
    let exe_name = if cfg!(windows) {
        "dom-test-runner.exe"
    } else {
        "dom-test-runner"
    };
    let bin = repo_root.join("target").join("release").join(exe_name);
    if bin.exists() {
        return Ok(bin);
    }
    let status = Command::new("cargo")
        .args(["build", "-p", "dom-test-runner", "--release"])
        .current_dir(repo_root)
        .status()
        .context("failed to build dom-test-runner")?;
    if !status.success() {
        return Err(anyhow!("cargo build -p dom-test-runner --release failed"));
    }
    if bin.exists() {
        Ok(bin)
    } else {
        Err(anyhow!(
            "dom-test-runner binary was not produced at {}",
            bin.display()
        ))
    }
}

pub fn codex_available() -> Result<()> {
    let output = Command::new("codex")
        .arg("--version")
        .output()
        .context("failed to execute codex")?;
    if !output.status.success() {
        return Err(anyhow!(
            "codex --version failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    Ok(())
}

pub fn repo_root(start: &Path) -> Result<PathBuf> {
    detect_repo_root(start)
}

pub fn timestamp_label() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    secs.to_string()
}

pub fn read_prompt_file(path: &Path) -> Result<PromptInput> {
    let resolved = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
    let content = fs::read_to_string(&resolved)
        .with_context(|| format!("failed to read prompt file {}", resolved.display()))?;
    if content.trim().is_empty() {
        return Err(anyhow!("prompt file is empty: {}", resolved.display()));
    }
    Ok(PromptInput {
        source_description: format!("prompt file {}", resolved.display()),
        content,
        resolved_path: Some(resolved),
    })
}

pub fn prompt_from_text(text: String) -> Result<PromptInput> {
    if text.trim().is_empty() {
        return Err(anyhow!("prompt is empty"));
    }
    Ok(PromptInput {
        source_description: "inline prompt".into(),
        content: text,
        resolved_path: None,
    })
}

pub fn list_prompts(repo_root: &Path) -> Result<Vec<PathBuf>> {
    let dir = repo_root.join("prompts");
    if !dir.exists() {
        return Ok(Vec::new());
    }
    let mut out = Vec::new();
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) == Some("txt") {
            out.push(path);
        }
    }
    out.sort();
    Ok(out)
}

pub fn show_prompt(path: &Path) -> Result<String> {
    let input = read_prompt_file(path)?;
    Ok(input.content)
}

pub fn create_run_paths(repo_root: &Path, timestamp: &str) -> Result<RunPaths> {
    let (root, runs, worktrees) = ensure_runner_dirs(repo_root)?;
    let run_dir = runs.join(timestamp);
    let worktree_dir = worktrees.join(timestamp);
    fs::create_dir_all(&run_dir)?;
    Ok(RunPaths {
        root,
        run_dir: run_dir.clone(),
        worktree_dir,
        prompt_file: run_dir.join("prompt.txt"),
        codex_log: run_dir.join("codex-output.log"),
        test_log: run_dir.join("test-output.log"),
        git_status_before: run_dir.join("git-status-before.txt"),
        git_status_after: run_dir.join("git-status-after.txt"),
        changed_files: run_dir.join("changed-files.txt"),
        staged_files: run_dir.join("staged-files.txt"),
        commit_file: run_dir.join("commit.txt"),
        remote_head: run_dir.join("remote-head.txt"),
        final_report: run_dir.join("final-report.txt"),
    })
}

pub fn write_text(path: &Path, content: impl AsRef<str>) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut file = fs::File::create(path)?;
    file.write_all(content.as_ref().as_bytes())?;
    Ok(())
}

pub fn command_output_text(output: &std::process::Output) -> String {
    format!(
        "STATUS: {}\nSTDOUT:\n{}\nSTDERR:\n{}\n",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

pub fn git_status_text(repo_root: &Path) -> Result<String> {
    let output = Command::new("git")
        .args(["status", "--short"])
        .current_dir(repo_root)
        .output()?;
    Ok(command_output_text(&output))
}

pub fn git_diff_names(repo_root: &Path) -> Result<String> {
    let output = Command::new("git")
        .args(["diff", "--name-only"])
        .current_dir(repo_root)
        .output()?;
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

pub fn git_diff_cached_names(repo_root: &Path) -> Result<String> {
    let output = Command::new("git")
        .args(["diff", "--cached", "--name-only"])
        .current_dir(repo_root)
        .output()?;
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

pub fn git_head(repo_root: &Path) -> Result<String> {
    let output = Command::new("git")
        .args(["rev-parse", "HEAD"])
        .current_dir(repo_root)
        .output()?;
    if !output.status.success() {
        return Err(anyhow!(
            "git rev-parse HEAD failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

pub fn git_remote_head(repo_root: &Path) -> Result<String> {
    let output = Command::new("git")
        .args(["ls-remote", "origin", "refs/heads/main"])
        .current_dir(repo_root)
        .output()?;
    Ok(command_output_text(&output))
}

pub fn git_remote_origin_exists(repo_root: &Path) -> Result<bool> {
    let output = Command::new("git")
        .args(["remote", "get-url", "origin"])
        .current_dir(repo_root)
        .output()?;
    Ok(output.status.success())
}

pub fn create_isolated_worktree(repo_root: &Path, run_paths: &RunPaths) -> Result<PathBuf> {
    let mut base_ref = "origin/main".to_string();
    let origin_ok = Command::new("git")
        .args(["rev-parse", "--verify", "origin/main"])
        .current_dir(repo_root)
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if !origin_ok {
        base_ref = "HEAD".into();
    }
    let status = Command::new("git")
        .args(["worktree", "add", "--detach"])
        .arg(&run_paths.worktree_dir)
        .arg(&base_ref)
        .current_dir(repo_root)
        .status()
        .with_context(|| {
            format!(
                "failed to create worktree at {}",
                run_paths.worktree_dir.display()
            )
        })?;
    if !status.success() {
        return Err(anyhow!("git worktree add failed"));
    }
    Ok(run_paths.worktree_dir.clone())
}

pub fn run_codex(
    worktree_root: &Path,
    prompt: &PromptInput,
    codex_log: &Path,
) -> Result<std::process::Output> {
    let mut child = Command::new("codex")
        .args([
            "exec",
            "--cd",
            worktree_root
                .to_str()
                .ok_or_else(|| anyhow!("non-utf8 worktree path"))?,
            "--dangerously-bypass-approvals-and-sandbox",
            "--color",
            "never",
            "-",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("failed to spawn codex")?;
    if let Some(stdin) = child.stdin.as_mut() {
        stdin.write_all(prompt.content.as_bytes())?;
    }
    let output = child.wait_with_output()?;
    write_text(
        codex_log,
        format!(
            "PROMPT SOURCE: {}\nRESOLVED PATH: {}\n{}\n",
            prompt.source_description,
            prompt
                .resolved_path
                .as_ref()
                .map(|p| p.display().to_string())
                .unwrap_or_else(|| "<inline>".into()),
            command_output_text(&output)
        ),
    )?;
    Ok(output)
}

pub fn locate_test_runner(repo_root: &Path) -> Result<PathBuf> {
    build_or_verify_test_runner(repo_root)
}

pub fn test_runner_profile_args(profile: &str) -> Vec<String> {
    vec![profile.to_string()]
}

pub fn run_test_runner(
    repo_root: &Path,
    test_runner: &Path,
    profile: &str,
    test_log: &Path,
) -> Result<std::process::Output> {
    let output = Command::new(test_runner)
        .arg(profile)
        .current_dir(repo_root)
        .output()
        .context("failed to run dom-test-runner")?;
    write_text(test_log, command_output_text(&output))?;
    Ok(output)
}

pub fn git_status_short(repo_root: &Path) -> Result<String> {
    let output = Command::new("git")
        .args(["status", "--short"])
        .current_dir(repo_root)
        .output()?;
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

pub fn git_changed_files(repo_root: &Path) -> Result<String> {
    let output = Command::new("git")
        .args(["diff", "--name-only"])
        .current_dir(repo_root)
        .output()?;
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

pub fn git_staged_files(repo_root: &Path) -> Result<String> {
    let output = Command::new("git")
        .args(["diff", "--cached", "--name-only"])
        .current_dir(repo_root)
        .output()?;
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

pub fn stage_files(repo_root: &Path, files: &[String]) -> Result<Vec<String>> {
    let mut staged = Vec::new();
    for file in files {
        if file == "Cargo.lock" {
            continue;
        }
        let status = Command::new("git")
            .args(["add", file])
            .current_dir(repo_root)
            .status()?;
        if status.success() {
            staged.push(file.clone());
        }
    }
    Ok(staged)
}

pub fn commit_changes(repo_root: &Path, message: &str) -> Result<String> {
    let status = Command::new("git")
        .args(["commit", "-m", message])
        .current_dir(repo_root)
        .status()?;
    if !status.success() {
        return Err(anyhow!("git commit failed"));
    }
    git_head(repo_root)
}

pub fn push_changes(repo_root: &Path) -> Result<std::process::Output> {
    let output = Command::new("git")
        .args(["push", "origin", "main"])
        .current_dir(repo_root)
        .output()?;
    Ok(output)
}

pub fn verify_remote_head(repo_root: &Path) -> Result<std::process::Output> {
    let output = Command::new("git")
        .args(["ls-remote", "origin", "refs/heads/main"])
        .current_dir(repo_root)
        .output()?;
    Ok(output)
}

#[allow(clippy::too_many_arguments)]
pub fn write_final_report(
    paths: &RunPaths,
    prompt: &PromptInput,
    initial_head: &str,
    final_local_head: Option<&str>,
    remote_head: Option<&str>,
    changed_files: &[String],
    staged_files: &[String],
    tests_run: &[String],
    status: &str,
    commit_hash: Option<&str>,
    push_status: Option<&str>,
    error: Option<&str>,
) -> Result<()> {
    let mut report = String::new();
    report.push_str(&format!("prompt summary: {}\n", prompt.source_description));
    if let Some(path) = &prompt.resolved_path {
        report.push_str(&format!("prompt path: {}\n", path.display()));
    }
    report.push_str(&format!("initial HEAD: {}\n", initial_head));
    if let Some(head) = final_local_head {
        report.push_str(&format!("final local HEAD: {}\n", head));
    }
    if let Some(head) = remote_head {
        report.push_str(&format!("remote HEAD: {}\n", head));
    }
    report.push_str("changed files:\n");
    for file in changed_files {
        report.push_str(&format!("  {}\n", file));
    }
    report.push_str("staged files:\n");
    for file in staged_files {
        report.push_str(&format!("  {}\n", file));
    }
    report.push_str("tests run:\n");
    for test in tests_run {
        report.push_str(&format!("  {}\n", test));
    }
    report.push_str(&format!("status: {}\n", status));
    if let Some(hash) = commit_hash {
        report.push_str(&format!("commit hash: {}\n", hash));
    }
    if let Some(push) = push_status {
        report.push_str(&format!("push status: {}\n", push));
    }
    if let Some(err) = error {
        report.push_str(&format!("error: {}\n", err));
    }
    write_text(&paths.final_report, &report)?;
    write_text(&paths.root.join(LATEST_RUN), paths.run_dir.display().to_string())?;
    Ok(())
}

pub fn profile_from_name(name: &str) -> Result<Profile> {
    Ok(match name {
        "affected" => Profile::FastCheck,
        "full" => Profile::Full,
        "all" => Profile::All,
        "pre-push" => Profile::FastCheck,
        other => return Err(anyhow!("unsupported profile {other}")),
    })
}

pub fn explain_changed_profiles(files: &[String]) -> String {
    let selection = select_profiles(files);
    explain_selection(&selection)
}

pub fn selected_profiles_for_changed_files(files: &[String]) -> AffectedSelection {
    select_profiles(files)
}

pub fn perform_pre_push_steps(
    repo_root: &Path,
    selection: &AffectedSelection,
) -> Result<Vec<dom_test_runner::CommandStep>> {
    command_plan_for_pre_push(repo_root, selection)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn prompt_validation_rejects_empty() {
        assert!(prompt_from_text("".into()).is_err());
    }

    #[test]
    fn prompt_validation_keeps_multiline_text() {
        let prompt = prompt_from_text("a\nb".into()).unwrap();
        assert!(prompt.content.contains('\n'));
    }

    #[test]
    fn write_final_report_creates_file() {
        let dir = TempDir::new().unwrap();
        let paths = RunPaths {
            root: dir.path().join("target/dom-agent-runner"),
            run_dir: dir.path().join("target/dom-agent-runner/runs/1"),
            worktree_dir: dir.path().join("target/dom-agent-runner/worktrees/1"),
            prompt_file: dir.path().join("target/dom-agent-runner/runs/1/prompt.txt"),
            codex_log: dir
                .path()
                .join("target/dom-agent-runner/runs/1/codex-output.log"),
            test_log: dir
                .path()
                .join("target/dom-agent-runner/runs/1/test-output.log"),
            git_status_before: dir
                .path()
                .join("target/dom-agent-runner/runs/1/git-status-before.txt"),
            git_status_after: dir
                .path()
                .join("target/dom-agent-runner/runs/1/git-status-after.txt"),
            changed_files: dir
                .path()
                .join("target/dom-agent-runner/runs/1/changed-files.txt"),
            staged_files: dir
                .path()
                .join("target/dom-agent-runner/runs/1/staged-files.txt"),
            commit_file: dir.path().join("target/dom-agent-runner/runs/1/commit.txt"),
            remote_head: dir
                .path()
                .join("target/dom-agent-runner/runs/1/remote-head.txt"),
            final_report: dir
                .path()
                .join("target/dom-agent-runner/runs/1/final-report.txt"),
        };
        let prompt = prompt_from_text("hello".into()).unwrap();
        write_final_report(
            &paths,
            &prompt,
            "abc",
            Some("def"),
            Some("remote"),
            &["a.rs".into()],
            &["b.rs".into()],
            &["test".into()],
            "PASS",
            Some("def"),
            Some("pushed"),
            None,
        )
        .unwrap();
        assert!(paths.final_report.exists());
    }
}
