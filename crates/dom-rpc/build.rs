use std::{env, fs, path::PathBuf, process::Command};

fn main() {
    println!("cargo:rerun-if-env-changed=DOM_BUILD_COMMIT");

    let commit = env::var("DOM_BUILD_COMMIT")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .or_else(git_head_commit)
        // Source archives without Git metadata still expose a non-empty,
        // explicit build identity instead of making the endpoint ambiguous.
        .unwrap_or_else(|| "unknown".to_owned());

    println!("cargo:rustc-env=DOM_RPC_BUILD_COMMIT={commit}");
}

/// Resolve HEAD, registering the Git files that determine it as rerun inputs.
///
/// Emitting `rerun-if-env-changed` above opts this script out of Cargo's
/// default rerun-on-any-change fallback, so without explicit
/// `rerun-if-changed` entries an incremental build after a checkout reuses
/// the previous script output and `/build-info` reports a stale commit —
/// defeating the release-compatibility check the endpoint exists for.
/// Watching `.git/HEAD` covers branch switches, the ref file behind a
/// symbolic HEAD covers new commits on the same branch, and `packed-refs`
/// covers loose refs getting packed.
fn git_head_commit() -> Option<String> {
    let git_dir = git_path(&["rev-parse", "--git-dir"])?;
    // In a linked worktree `--git-dir` is the worktree's private
    // administrative directory (`.git/worktrees/<name>`): HEAD lives there,
    // but branch refs and packed-refs live only in the shared common
    // directory. Joining refs against `--git-dir` would produce paths that
    // never exist, so commits in a worktree would leave /build-info stale.
    let common_dir =
        git_path(&["rev-parse", "--git-common-dir"]).unwrap_or_else(|| git_dir.clone());

    println!("cargo:rerun-if-changed={}", git_dir.join("HEAD").display());
    if let Ok(contents) = fs::read_to_string(git_dir.join("HEAD")) {
        if let Some(reference) = contents.strip_prefix("ref: ") {
            // Deliberately no existence check: with refs packed, the loose
            // ref file is CREATED by the next commit while HEAD and
            // packed-refs both stay unchanged — gating the watcher on
            // existence would leave that commit invisible to Cargo.
            let ref_file = common_dir.join(reference.trim());
            println!("cargo:rerun-if-changed={}", ref_file.display());
        }
    }
    println!(
        "cargo:rerun-if-changed={}",
        common_dir.join("packed-refs").display()
    );

    Command::new("git")
        .args(["rev-parse", "HEAD"])
        .output()
        .ok()
        .filter(|output| output.status.success())
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
}

fn git_path(args: &[&str]) -> Option<PathBuf> {
    Command::new("git")
        .args(args)
        .output()
        .ok()
        .filter(|output| output.status.success())
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .map(|value| PathBuf::from(value.trim()))
        .filter(|value| !value.as_os_str().is_empty())
}
