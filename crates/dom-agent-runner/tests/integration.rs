//! Integration test for dom-agent-runner safety guards.
//!
//! We do NOT invoke real Codex / real git push here. The goal is to prove
//! the CLI surface refuses bad inputs and that `clean` is scoped to the
//! agent's own target subdir.

use std::fs;
use std::path::PathBuf;
use std::process::Command;

fn binary_path() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_dom-agent-runner"))
}

fn make_fake_repo() -> PathBuf {
    let pid = std::process::id();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root = std::env::temp_dir().join(format!("dar-it-{pid}-{nanos}"));
    fs::create_dir_all(root.join("crates").join("dom-agent-runner").join("src")).unwrap();
    fs::write(
        root.join("Cargo.toml"),
        "[workspace]\nmembers = [\"crates/dom-agent-runner\"]\n",
    )
    .unwrap();
    root
}

#[test]
fn help_works() {
    let bin = binary_path();
    let out = Command::new(&bin).arg("help").output().unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("dom-agent-runner"));
    assert!(stdout.contains("--prompt-file"));
}

#[test]
fn run_without_prompt_is_rejected() {
    let bin = binary_path();
    let root = make_fake_repo();
    let out = Command::new(&bin)
        .args(["run"])
        .current_dir(&root)
        .output()
        .unwrap();
    assert!(!out.status.success());
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn run_with_both_prompts_is_rejected() {
    let bin = binary_path();
    let out = Command::new(&bin)
        .args(["run", "--prompt", "x", "--prompt-file", "y.txt"])
        .output()
        .unwrap();
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("mutually exclusive") || stderr.contains("error"));
}

#[test]
fn clean_only_removes_agent_dir() {
    let bin = binary_path();
    let root = make_fake_repo();

    fs::create_dir_all(root.join("target").join("dom-agent-runner").join("runs")).unwrap();
    fs::write(
        root.join("target")
            .join("dom-agent-runner")
            .join("runs")
            .join("x.txt"),
        "noise",
    )
    .unwrap();
    fs::create_dir_all(root.join("target").join("debug")).unwrap();
    fs::write(root.join("target").join("debug").join("keep.txt"), "keep").unwrap();

    let status = Command::new(&bin)
        .arg("clean")
        .current_dir(&root)
        .status()
        .unwrap();
    assert!(status.success());
    assert!(!root.join("target").join("dom-agent-runner").exists());
    assert!(root.join("target").join("debug").join("keep.txt").exists());

    let _ = fs::remove_dir_all(&root);
}

#[test]
fn outside_repo_fails() {
    let bin = binary_path();
    let pid = std::process::id();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let outside = std::env::temp_dir().join(format!("dar-outside-{pid}-{nanos}"));
    fs::create_dir_all(&outside).unwrap();
    let out = Command::new(&bin)
        .args(["clean"])
        .current_dir(&outside)
        .output()
        .unwrap();
    assert!(!out.status.success());
    let _ = fs::remove_dir_all(&outside);
}
