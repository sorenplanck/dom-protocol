//! `doctor` for the agent runner.

use std::error::Error;
use std::process::Command;

use crate::git;
use crate::repo::find_dom_repo_root;

type R<T> = Result<T, Box<dyn Error>>;

pub fn cmd_doctor() -> R<()> {
    let cwd = std::env::current_dir()?;
    println!("[dom-agent-runner] doctor: starting…");
    let root = find_dom_repo_root(&cwd)?;
    println!("[dom-agent-runner] repo: {}", root.path.display());

    require("git", &["--version"])?;
    require("cargo", &["--version"])?;
    require("rustc", &["--version"])?;

    // Codex CLI. Don't fail the doctor with a confusing error — give the
    // user actionable install hints instead.
    match Command::new("codex").arg("--version").output() {
        Ok(o) if o.status.success() => {
            let v = String::from_utf8_lossy(&o.stdout).trim().to_string();
            println!("[dom-agent-runner] codex: {v}");
        }
        Ok(_) | Err(_) => {
            println!(
                "[dom-agent-runner] codex: NOT FOUND on PATH.\n  \
                 Install Codex CLI on Windows, then:\n  \
                   1. Make sure `codex` is on PATH (open a new terminal).\n  \
                   2. Run `codex --version` to confirm.\n  \
                   3. Authenticate Codex once interactively before using `run`."
            );
        }
    }

    // dom-test-runner — built or buildable from this workspace.
    let exe_release = root.path.join("target").join("release").join(
        if cfg!(target_os = "windows") {
            "dom-test-runner.exe"
        } else {
            "dom-test-runner"
        },
    );
    if exe_release.is_file() {
        println!("[dom-agent-runner] dom-test-runner: {}", exe_release.display());
    } else {
        println!(
            "[dom-agent-runner] dom-test-runner: not built yet ({} missing). \
             Build with: cargo build -p dom-test-runner --release",
            exe_release.display()
        );
    }

    // Git remote + branch.
    match git::run(&root.path, &["remote", "get-url", "origin"]) {
        Ok(o) if o.status.success() => {
            println!(
                "[dom-agent-runner] origin: {}",
                String::from_utf8_lossy(&o.stdout).trim()
            );
        }
        _ => println!("[dom-agent-runner] origin: NOT CONFIGURED"),
    }
    if let Ok(b) = git::current_branch(&root.path) {
        println!("[dom-agent-runner] branch: {b}");
    }
    if let Ok(h) = git::rev_parse_head(&root.path) {
        println!("[dom-agent-runner] HEAD:   {h}");
    }

    // GitHub auth: we only check that ls-remote works against origin.
    // This uses local credentials (helper / ssh / gh) and never asks for
    // a token in this binary.
    match git::remote_head(&root.path, "main") {
        Ok(Some(h)) => println!("[dom-agent-runner] github reachable: remote main = {h}"),
        Ok(None) => println!("[dom-agent-runner] github reachable: no refs/heads/main yet"),
        Err(e) => println!(
            "[dom-agent-runner] github auth NOT verified: {e}\n  \
             hint: configure a credential helper, ssh-agent, or `gh auth login`."
        ),
    }

    println!("[dom-agent-runner] doctor: done");
    Ok(())
}

fn require(bin: &str, args: &[&str]) -> R<()> {
    match Command::new(bin).args(args).output() {
        Ok(o) if o.status.success() => {
            let v = String::from_utf8_lossy(&o.stdout).trim().to_string();
            println!("[dom-agent-runner] {bin}: {v}");
            Ok(())
        }
        Ok(_) | Err(_) => Err(format!(
            "required tool `{bin}` is missing or unusable on PATH"
        )
        .into()),
    }
}
