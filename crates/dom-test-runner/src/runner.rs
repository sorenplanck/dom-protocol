//! Command implementations.
//!
//! Each `cmd_*` is invoked by `main.rs`. They build a `RunReport`, write
//! logs, and write the timestamped + latest report.

use std::error::Error;
use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Instant, SystemTime};

use crate::affected::{pre_push_baseline, select_profiles, Selection};
use crate::env::{check_fast_mining, safe_test_env, FastMiningCheck};
use crate::profiles;
use crate::report::{self, RunReport, Status, StepResult};
use crate::repo::find_dom_repo_root;

type R<T> = Result<T, Box<dyn Error>>;

/// `doctor` — check environment.
pub fn cmd_doctor() -> R<()> {
    let cwd = std::env::current_dir()?;
    println!("[dom-test-runner] doctor: starting…");
    let root = find_dom_repo_root(&cwd)?;
    println!("[dom-test-runner] repo root: {}", root.path.display());

    check_tool("git", &["--version"])?;
    check_tool("cargo", &["--version"])?;
    check_tool("rustc", &["--version"])?;

    // Confirm fast-mining guard.
    match check_fast_mining("regtest") {
        FastMiningCheck::Allowed { .. } => {
            println!("[dom-test-runner] fast-mining guard: regtest ALLOWED (expected).");
        }
        FastMiningCheck::Forbidden { reason, .. } => {
            return Err(format!("guard misbehavior: {reason}").into());
        }
    }
    match check_fast_mining("mainnet") {
        FastMiningCheck::Forbidden { .. } => {
            println!(
                "[dom-test-runner] fast-mining guard: mainnet FORBIDDEN (expected fail-closed)."
            );
        }
        _ => return Err("guard FAILED to refuse mainnet fast mining".into()),
    }

    println!("[dom-test-runner] doctor: OK");
    Ok(())
}

fn check_tool(bin: &str, args: &[&str]) -> R<()> {
    let out = Command::new(bin).args(args).output();
    match out {
        Ok(o) if o.status.success() => {
            let v = String::from_utf8_lossy(&o.stdout).trim().to_string();
            println!("[dom-test-runner] {bin}: {v}");
            Ok(())
        }
        Ok(o) => Err(format!(
            "{bin} returned non-zero exit: {}",
            String::from_utf8_lossy(&o.stderr)
        )
        .into()),
        Err(e) => Err(format!("{bin} not found on PATH: {e}").into()),
    }
}

/// `<profile>` — run a single named profile.
pub fn run_profile(name: &str) -> R<()> {
    let cwd = std::env::current_dir()?;
    let root = find_dom_repo_root(&cwd)?;
    let prof = profiles::get(name).ok_or_else(|| format!("unknown profile: {name}"))?;

    let env_map = safe_test_env();
    let started = SystemTime::now();
    let ts = report::timestamp(started);
    let (logs_dir, reports_dir) = report::dirs(&root.path);

    println!("[dom-test-runner] running profile: {}", prof.name);
    let mut steps_out = Vec::new();
    let run_start = Instant::now();

    for step in prof.steps {
        let step_start = Instant::now();
        let label_for_log = format!("{}-{}", prof.name, step.label);
        let (log_path, mut log_file) = report::open_log(&logs_dir, &ts, &label_for_log)?;

        let mut cmd = Command::new("cargo");
        cmd.current_dir(&root.path);
        cmd.args(step.args);
        for (k, v) in &env_map {
            cmd.env(k, v);
        }
        cmd.stdout(Stdio::piped()).stderr(Stdio::piped());

        let result = cmd.spawn();
        let (status, note) = match result {
            Ok(child) => {
                // wait_with_output drains stdout and stderr concurrently;
                // avoids deadlock on long cargo runs filling pipe buffers.
                let out = child.wait_with_output()?;
                let stdout_buf = out.stdout;
                let stderr_buf = out.stderr;
                let exit = out.status;
                writeln!(log_file, "--- stdout ---")?;
                log_file.write_all(&stdout_buf)?;
                writeln!(log_file, "\n--- stderr ---")?;
                log_file.write_all(&stderr_buf)?;
                writeln!(log_file, "\nexit: {exit}")?;

                let combined = String::from_utf8_lossy(&stderr_buf).to_string()
                    + &String::from_utf8_lossy(&stdout_buf);

                if exit.success() {
                    (Status::Pass, None)
                } else if step.tolerate_missing_target
                    && looks_like_missing_test_target(&combined)
                {
                    (
                        Status::Skipped,
                        Some("test target not present in this repo".to_string()),
                    )
                } else {
                    (
                        Status::Fail,
                        Some(format!("cargo exited with {exit}")),
                    )
                }
            }
            Err(e) => {
                writeln!(log_file, "could not spawn cargo: {e}")?;
                (Status::Blocked, Some(format!("spawn error: {e}")))
            }
        };

        // PASS/FAIL line clearly visible on Windows terminal.
        println!(
            "[dom-test-runner] [{}] {} ({} ms)",
            status.as_str(),
            step.label,
            step_start.elapsed().as_millis()
        );
        if status == Status::Fail {
            println!(
                "[dom-test-runner]   -> see log: {}",
                log_path.display()
            );
        }

        steps_out.push(StepResult {
            label: step.label.to_string(),
            status,
            duration_ms: step_start.elapsed().as_millis(),
            log_path: Some(log_path),
            note,
        });
    }

    let total_ms = run_start.elapsed().as_millis();
    let env_vec: Vec<(String, String)> = env_map.into_iter().collect();
    let any_fail = steps_out.iter().any(|s| s.status == Status::Fail);
    let report = RunReport {
        started,
        profile: prof.name.to_string(),
        env: env_vec,
        steps: steps_out,
        total_ms,
    };
    let path = report::write_report(&reports_dir, &report)?;
    println!("[dom-test-runner] report: {}", path.display());

    if any_fail {
        Err(format!("profile '{}' had failures", prof.name).into())
    } else {
        Ok(())
    }
}

/// Detect cargo output for "no test target by that name" so we can
/// SKIP rather than FAIL when an integration test file isn't present.
fn looks_like_missing_test_target(s: &str) -> bool {
    // Cargo's exact wording varies; match a few stable substrings.
    let s = s.to_ascii_lowercase();
    s.contains("no test target") || s.contains("does not exist") && s.contains("--test")
        || s.contains("no such test")
        || s.contains("could not find a test target")
}

/// `affected` and `explain affected`.
pub fn cmd_affected(explain_only: bool) -> R<()> {
    let cwd = std::env::current_dir()?;
    let root = find_dom_repo_root(&cwd)?;
    let changed = collect_changed_files(&root.path)?;

    if changed.is_empty() {
        println!("[dom-test-runner] No local changes detected; running fast-check only.");
        if explain_only {
            return Ok(());
        }
        return run_profile("fast-check");
    }

    let sels = select_profiles(&changed);
    if explain_only {
        explain(&changed, &sels);
        return Ok(());
    }

    if sels.is_empty() {
        println!(
            "[dom-test-runner] {} changed files matched no profile rules; running fast-check.",
            changed.len()
        );
        return run_profile("fast-check");
    }

    // De-duplicate while preserving order.
    let mut seen = std::collections::BTreeSet::new();
    let mut had_failure = false;
    for sel in sels {
        if !seen.insert(sel.profile) {
            continue;
        }
        if let Err(e) = run_profile(sel.profile) {
            had_failure = true;
            eprintln!("[dom-test-runner] {}: {}", sel.profile, e);
        }
    }
    if had_failure {
        return Err("one or more affected profiles failed".into());
    }
    Ok(())
}

fn explain(changed: &[String], sels: &[Selection]) {
    println!("Changed files:");
    for c in changed {
        println!("  {c}");
    }
    println!("\nSelected profiles:");
    if sels.is_empty() {
        println!("  (none — would fall back to fast-check)");
        return;
    }
    for s in sels {
        println!("  - {}: {}", s.profile, s.reason);
    }
}

/// `pre-push` — affected + baseline + relevant integration where needed.
pub fn cmd_pre_push() -> R<()> {
    let cwd = std::env::current_dir()?;
    let root = find_dom_repo_root(&cwd)?;
    let changed = collect_changed_files(&root.path)?;

    let mut combined: Vec<Selection> = pre_push_baseline();
    if !changed.is_empty() {
        combined.extend(select_profiles(&changed));
    }

    let mut seen = std::collections::BTreeSet::new();
    let mut had_failure = false;
    for sel in combined {
        if !seen.insert(sel.profile) {
            continue;
        }
        if let Err(e) = run_profile(sel.profile) {
            had_failure = true;
            eprintln!("[dom-test-runner] {}: {}", sel.profile, e);
        }
    }
    if had_failure {
        Err("pre-push validation failed".into())
    } else {
        Ok(())
    }
}

/// Collect the union of working-tree and staged changes.
pub fn collect_changed_files(repo_root: &std::path::Path) -> R<Vec<String>> {
    let mut files = std::collections::BTreeSet::new();
    for args in [
        vec!["diff", "--name-only"],
        vec!["diff", "--cached", "--name-only"],
    ] {
        let out = Command::new("git")
            .current_dir(repo_root)
            .args(&args)
            .output();
        if let Ok(o) = out {
            if o.status.success() {
                for line in String::from_utf8_lossy(&o.stdout).lines() {
                    let l = line.trim();
                    if !l.is_empty() {
                        // Normalize backslashes from Windows git.
                        files.insert(l.replace('\\', "/"));
                    }
                }
            }
        }
    }
    Ok(files.into_iter().collect())
}

/// `clean` — remove only the runner's own outputs.
pub fn cmd_clean() -> R<()> {
    let cwd = std::env::current_dir()?;
    let root = find_dom_repo_root(&cwd)?;
    let target = root.path.join("target").join("dom-test-runner");
    if target.exists() {
        let canon = target.canonicalize().unwrap_or(target.clone());
        let root_canon = root.path.canonicalize().unwrap_or(root.path.clone());
        // Defense in depth: never delete anything that isn't strictly under
        // <repo>/target/dom-test-runner.
        if !canon.starts_with(&root_canon) || !canon.ends_with("dom-test-runner") {
            return Err(format!(
                "refusing to delete unexpected path: {}",
                canon.display()
            )
            .into());
        }
        fs::remove_dir_all(&target)?;
        println!("[dom-test-runner] removed: {}", target.display());
    } else {
        println!("[dom-test-runner] nothing to clean");
    }
    Ok(())
}

/// `report` — print path to the latest report.
pub fn cmd_report() -> R<()> {
    let cwd = std::env::current_dir()?;
    let root = find_dom_repo_root(&cwd)?;
    let p: PathBuf = root
        .path
        .join("target")
        .join("dom-test-runner")
        .join("reports")
        .join("latest-report.txt");
    if !p.exists() {
        println!("[dom-test-runner] no report yet; run a profile first");
        return Ok(());
    }
    println!("[dom-test-runner] latest report: {}", p.display());
    let contents = fs::read_to_string(&p)?;
    println!("{contents}");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_target_detection_matches_cargo_phrasings() {
        assert!(looks_like_missing_test_target(
            "error: no test target named `mempool_relay`"
        ));
        assert!(looks_like_missing_test_target(
            "Could not find a test target"
        ));
        assert!(looks_like_missing_test_target(
            "the test target `two_node` does not exist; specified via --test"
        ));
        assert!(!looks_like_missing_test_target("test failed"));
        assert!(!looks_like_missing_test_target(
            "compilation failed somewhere"
        ));
    }
}
