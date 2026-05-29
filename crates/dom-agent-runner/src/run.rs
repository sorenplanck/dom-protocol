//! Orchestration logic for `run`.
//!
//! Sequence (matches the spec):
//!   A. Find repo root & verify tooling.
//!   B. Save initial state.
//!   C. Run Codex CLI with the prompt.
//!   D. Collect changed files; run `dom-test-runner.exe affected` (or chosen
//!      profile) and then `pre-push`.
//!   E. If tests fail: do NOT commit, do NOT push, write report, return error.
//!   F. If tests pass: stage only changed-by-this-task files, commit, and —
//!      if `--push` — push, then verify remote HEAD.
//!   G. Write final report regardless.

use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::SystemTime;

use crate::cli::RunOptions;
use crate::git;
use crate::prompt::{self, PromptSource};
use crate::repo::find_dom_repo_root;
use crate::report;

type R<T> = Result<T, Box<dyn Error>>;

pub fn cmd_run(opts: RunOptions) -> R<()> {
    let cwd = std::env::current_dir()?;
    let root = find_dom_repo_root(&cwd)?;
    println!("[dom-agent-runner] repo: {}", root.path.display());

    // --- Load prompt ------------------------------------------------------
    let loaded = prompt::load(opts.prompt.as_deref(), opts.prompt_file.as_deref())?;
    println!(
        "[dom-agent-runner] prompt source: {}",
        loaded.source.display()
    );

    // --- Prepare run directory -------------------------------------------
    let started = SystemTime::now();
    let (_base, runs_dir) = report::dirs(&root.path);
    let run_dir = report::new_run_dir(&runs_dir, started)?;

    fs::write(run_dir.join("prompt.txt"), &loaded.text)?;
    if let PromptSource::File(p) = &loaded.source {
        fs::write(run_dir.join("prompt-source.txt"), p.display().to_string())?;
    }

    // --- Save initial state ----------------------------------------------
    let initial_head = git::rev_parse_head(&root.path).unwrap_or_default();
    let status_before = git::status_short(&root.path).unwrap_or_default();
    fs::write(run_dir.join("git-status-before.txt"), &status_before)?;

    let dirty_before = !status_before.trim().is_empty();
    if dirty_before {
        println!(
            "[dom-agent-runner] WARNING: worktree is dirty before Codex runs. \
             Pre-existing changes may mix with Codex changes."
        );
    }

    // --- Verify required tools (codex must be installed) -----------------
    if !tool_available("codex", &["--version"]) {
        return Err("codex CLI not found on PATH. Install Codex and re-run."
            .to_string()
            .into());
    }
    let test_runner_exe = resolve_test_runner_exe(&root.path)?;
    println!(
        "[dom-agent-runner] dom-test-runner: {}",
        test_runner_exe.display()
    );

    // --- Run Codex --------------------------------------------------------
    println!("[dom-agent-runner] launching Codex CLI…");
    let codex_log = run_codex(&root.path, &loaded.text, &run_dir)?;
    println!("[dom-agent-runner] codex output: {}", codex_log.display());

    // --- Collect changes after Codex -------------------------------------
    let changed_after = git::changed_files(&root.path).unwrap_or_default();
    fs::write(run_dir.join("changed-files.txt"), changed_after.join("\n"))?;

    // --- Run tests --------------------------------------------------------
    let profile = &opts.profile;
    println!("[dom-agent-runner] running dom-test-runner {profile}…");
    let mut test_log = fs::File::create(run_dir.join("test-output.log"))?;
    let primary_ok = run_test_runner(&test_runner_exe, &root.path, profile, &mut test_log)?;

    // Also pre-push as required by the spec (only if primary passed).
    let pre_push_ok = if primary_ok {
        println!("[dom-agent-runner] running dom-test-runner pre-push…");
        run_test_runner(&test_runner_exe, &root.path, "pre-push", &mut test_log)?
    } else {
        false
    };

    if !primary_ok || !pre_push_ok {
        // No commit, no push.
        write_final_report(
            &run_dir,
            &loaded.source,
            &initial_head,
            None,
            None,
            &changed_after,
            &[],
            primary_ok,
            pre_push_ok,
            false,
            Some(if !primary_ok {
                format!("dom-test-runner {profile} failed")
            } else {
                "dom-test-runner pre-push failed".to_string()
            }),
        )?;
        return Err("validation failed; no commit, no push".into());
    }

    // --- Stage & commit ---------------------------------------------------
    if changed_after.is_empty() {
        println!(
            "[dom-agent-runner] no changes after Codex — nothing to commit. \
             Writing report and stopping."
        );
        write_final_report(
            &run_dir,
            &loaded.source,
            &initial_head,
            None,
            None,
            &changed_after,
            &[],
            true,
            true,
            false,
            Some("no changes detected after Codex".to_string()),
        )?;
        return Ok(());
    }

    let to_stage = filter_safe_files_to_stage(&changed_after);
    fs::write(run_dir.join("staged-files.txt"), to_stage.join("\n"))?;

    println!("[dom-agent-runner] staging {} file(s):", to_stage.len());
    for f in &to_stage {
        println!("    {f}");
    }

    let mut add_args = vec!["add", "--"];
    for f in &to_stage {
        add_args.push(f.as_str());
    }
    let o = git::run(&root.path, &add_args)?;
    if !o.status.success() {
        return Err(format!("git add failed: {}", String::from_utf8_lossy(&o.stderr)).into());
    }

    let commit_msg = compose_commit_message(&loaded.text);
    let o = git::run(&root.path, &["commit", "-m", &commit_msg])?;
    if !o.status.success() {
        let err = String::from_utf8_lossy(&o.stderr).to_string();
        write_final_report(
            &run_dir,
            &loaded.source,
            &initial_head,
            None,
            None,
            &changed_after,
            &to_stage,
            true,
            true,
            false,
            Some(format!("git commit failed: {err}")),
        )?;
        return Err(format!("git commit failed: {err}").into());
    }

    let final_head = git::rev_parse_head(&root.path).ok();
    fs::write(
        run_dir.join("commit.txt"),
        final_head.clone().unwrap_or_default(),
    )?;

    // --- Push -------------------------------------------------------------
    let mut pushed = false;
    let mut remote_head_after: Option<String> = None;
    if opts.push {
        let branch = git::current_branch(&root.path).unwrap_or_else(|_| "main".to_string());
        println!("[dom-agent-runner] pushing to origin/{branch}…");
        let o = git::run(&root.path, &["push", "origin", &branch])?;
        if !o.status.success() {
            let err = String::from_utf8_lossy(&o.stderr).to_string();
            write_final_report(
                &run_dir,
                &loaded.source,
                &initial_head,
                final_head.as_deref(),
                None,
                &changed_after,
                &to_stage,
                true,
                true,
                false,
                Some(format!("git push failed: {err}")),
            )?;
            return Err(format!("git push failed: {err}").into());
        }
        pushed = true;

        // Verify remote HEAD.
        match git::remote_head(&root.path, &branch)? {
            Some(h) => {
                fs::write(run_dir.join("remote-head.txt"), &h)?;
                remote_head_after = Some(h);
            }
            None => {
                return Err(format!(
                    "remote branch '{branch}' has no refs after push (unexpected)"
                )
                .into());
            }
        }
    } else {
        println!(
            "[dom-agent-runner] --push not provided; commit kept local. \
             Run with --push to publish."
        );
    }

    // --- git status after -------------------------------------------------
    let status_after = git::status_short(&root.path).unwrap_or_default();
    fs::write(run_dir.join("git-status-after.txt"), &status_after)?;

    write_final_report(
        &run_dir,
        &loaded.source,
        &initial_head,
        final_head.as_deref(),
        remote_head_after.as_deref(),
        &changed_after,
        &to_stage,
        true,
        true,
        pushed,
        None,
    )?;

    println!("[dom-agent-runner] done. report dir: {}", run_dir.display());
    Ok(())
}

/// `report`
pub fn cmd_report() -> R<()> {
    let cwd = std::env::current_dir()?;
    let root = find_dom_repo_root(&cwd)?;
    let (_base, runs) = report::dirs(&root.path);
    let mut entries: Vec<_> = fs::read_dir(&runs)?
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.is_dir())
        .collect();
    entries.sort();
    let last = entries.last().ok_or("no runs yet")?;
    println!("[dom-agent-runner] latest run: {}", last.display());
    let final_report = last.join("final-report.txt");
    if final_report.is_file() {
        let s = fs::read_to_string(&final_report)?;
        println!("{s}");
    }
    Ok(())
}

/// `clean`
pub fn cmd_clean() -> R<()> {
    let cwd = std::env::current_dir()?;
    let root = find_dom_repo_root(&cwd)?;
    let target = root.path.join("target").join("dom-agent-runner");
    if !target.exists() {
        println!("[dom-agent-runner] nothing to clean");
        return Ok(());
    }
    let canon = target.canonicalize().unwrap_or(target.clone());
    let root_canon = root.path.canonicalize().unwrap_or(root.path.clone());
    if !canon.starts_with(&root_canon) || !canon.ends_with("dom-agent-runner") {
        return Err(format!("refusing unexpected path: {}", canon.display()).into());
    }
    fs::remove_dir_all(&target)?;
    println!("[dom-agent-runner] removed: {}", target.display());
    Ok(())
}

// ============================================================
// helpers
// ============================================================

fn tool_available(bin: &str, args: &[&str]) -> bool {
    Command::new(bin)
        .args(args)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn resolve_test_runner_exe(root: &Path) -> R<PathBuf> {
    let name = if cfg!(target_os = "windows") {
        "dom-test-runner.exe"
    } else {
        "dom-test-runner"
    };
    for p in [
        root.join("target").join("release").join(name),
        root.join("target").join("debug").join(name),
    ] {
        if p.is_file() {
            return Ok(p);
        }
    }
    // Last resort: invoke via `cargo run`. Slower but works on fresh clones.
    println!(
        "[dom-agent-runner] dom-test-runner binary not found; falling back to `cargo run -p dom-test-runner`."
    );
    Ok(PathBuf::from("cargo"))
}

fn run_codex(repo: &Path, prompt_text: &str, run_dir: &Path) -> R<PathBuf> {
    let log_path = run_dir.join("codex-output.log");
    let mut log = fs::File::create(&log_path)?;
    use std::io::Write;
    writeln!(
        log,
        "[dom-agent-runner] launching codex from: {}",
        repo.display()
    )?;

    // Pass the prompt via stdin to support multiline reliably across shells.
    let mut child = Command::new("codex")
        .current_dir(repo)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("failed to spawn codex: {e}"))?;

    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(prompt_text.as_bytes())?;
        stdin.write_all(b"\n")?;
    }

    let out = child.wait_with_output()?;
    log.write_all(b"--- codex stdout ---\n")?;
    log.write_all(&out.stdout)?;
    log.write_all(b"\n--- codex stderr ---\n")?;
    log.write_all(&out.stderr)?;
    writeln!(log, "\nexit: {}", out.status)?;

    if !out.status.success() {
        return Err(format!("codex exited with {}", out.status).into());
    }
    Ok(log_path)
}

fn run_test_runner(exe: &Path, repo: &Path, profile: &str, log: &mut fs::File) -> R<bool> {
    use std::io::Write;
    writeln!(log, "[dom-agent-runner] dom-test-runner {profile}")?;

    let mut cmd = if exe.file_name().and_then(|n| n.to_str()) == Some("cargo") {
        let mut c = Command::new("cargo");
        c.args(["run", "-q", "-p", "dom-test-runner", "--", profile]);
        c
    } else {
        let mut c = Command::new(exe);
        c.arg(profile);
        c
    };
    cmd.current_dir(repo);

    let out = cmd.output()?;
    log.write_all(b"--- stdout ---\n")?;
    log.write_all(&out.stdout)?;
    log.write_all(b"\n--- stderr ---\n")?;
    log.write_all(&out.stderr)?;
    writeln!(log, "\nexit: {}", out.status)?;
    Ok(out.status.success())
}

/// Filter the changed-files list to remove paths we never want to stage
/// (Cargo.lock is conservative; only re-include if absolutely necessary).
pub fn filter_safe_files_to_stage(files: &[String]) -> Vec<String> {
    files.iter().filter(|f| !is_lockfile(f)).cloned().collect()
}

fn is_lockfile(path: &str) -> bool {
    path == "Cargo.lock" || path.ends_with("/Cargo.lock")
}

fn compose_commit_message(prompt_text: &str) -> String {
    // First non-empty trimmed line of the prompt becomes the subject;
    // capped to a reasonable length.
    let subject = prompt_text
        .lines()
        .map(str::trim)
        .find(|l| !l.is_empty())
        .unwrap_or("automated change");
    let mut subject = subject.to_string();
    if subject.len() > 72 {
        subject.truncate(72);
    }
    format!("{subject}\n\nAutomated by dom-agent-runner.\n")
}

#[allow(clippy::too_many_arguments)]
fn write_final_report(
    run_dir: &Path,
    source: &PromptSource,
    initial_head: &str,
    final_head: Option<&str>,
    remote_head: Option<&str>,
    changed: &[String],
    staged: &[String],
    primary_ok: bool,
    pre_push_ok: bool,
    pushed: bool,
    error: Option<String>,
) -> std::io::Result<()> {
    let mut s = String::new();
    s.push_str("dom-agent-runner final report\n");
    s.push_str("=============================\n");
    s.push_str(&format!("run dir:       {}\n", run_dir.display()));
    s.push_str(&format!("prompt source: {}\n", source.display()));
    s.push_str(&format!("initial HEAD:  {initial_head}\n"));
    s.push_str(&format!(
        "final HEAD:    {}\n",
        final_head.unwrap_or("(no commit)")
    ));
    s.push_str(&format!(
        "remote HEAD:   {}\n",
        remote_head.unwrap_or("(not pushed / not verified)")
    ));
    s.push_str(&format!(
        "primary tests: {}\n",
        if primary_ok { "PASS" } else { "FAIL" }
    ));
    s.push_str(&format!(
        "pre-push:      {}\n",
        if pre_push_ok { "PASS" } else { "FAIL" }
    ));
    s.push_str(&format!("pushed:        {pushed}\n"));
    s.push_str("\nchanged files:\n");
    for f in changed {
        s.push_str(&format!("  {f}\n"));
    }
    s.push_str("\nstaged files:\n");
    for f in staged {
        s.push_str(&format!("  {f}\n"));
    }
    if let Some(e) = error {
        s.push_str(&format!("\nerror: {e}\n"));
    }
    fs::write(run_dir.join("final-report.txt"), s)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cargo_lock_is_never_staged_by_default() {
        let files = vec![
            "Cargo.lock".to_string(),
            "crates/dom-mempool/src/lib.rs".to_string(),
        ];
        let kept = filter_safe_files_to_stage(&files);
        assert_eq!(kept, vec!["crates/dom-mempool/src/lib.rs".to_string()]);
    }

    #[test]
    fn nested_cargo_lock_is_filtered() {
        let files = vec!["crates/something/Cargo.lock".to_string()];
        let kept = filter_safe_files_to_stage(&files);
        assert!(kept.is_empty());
    }

    #[test]
    fn commit_message_uses_first_nonempty_line() {
        let m = compose_commit_message("\n\n  add new feature\nmore details\n");
        assert!(m.starts_with("add new feature"));
        assert!(m.contains("dom-agent-runner"));
    }

    #[test]
    fn commit_message_truncates_long_subject() {
        let long = "a".repeat(200);
        let m = compose_commit_message(&long);
        let subject = m.lines().next().unwrap();
        assert!(subject.len() <= 72);
    }
}
