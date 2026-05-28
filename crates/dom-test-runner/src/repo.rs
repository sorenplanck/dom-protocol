//! Repository-root detection.
//!
//! Walks up from the current working directory looking for a `Cargo.toml`
//! whose `[workspace]` block names `dom-test-runner` as a member. This is
//! a robust signal that we are inside the DOM Protocol workspace and not
//! some unrelated cargo project.

use std::io;
use std::path::{Path, PathBuf};

/// Returned by `find_dom_repo_root`.
#[derive(Debug)]
pub struct RepoRoot {
    pub path: PathBuf,
}

/// Find the DOM Protocol workspace root by walking up from `start`.
///
/// Looks for a `Cargo.toml` containing both `[workspace]` and `dom-test-runner`.
/// This avoids matching arbitrary cargo workspaces that happen to be ancestors.
pub fn find_dom_repo_root(start: &Path) -> io::Result<RepoRoot> {
    let mut current = start
        .canonicalize()
        .unwrap_or_else(|_| start.to_path_buf());

    loop {
        let candidate = current.join("Cargo.toml");
        if candidate.is_file() {
            let contents = std::fs::read_to_string(&candidate).unwrap_or_default();
            if is_dom_workspace_manifest(&contents) {
                return Ok(RepoRoot { path: current });
            }
        }
        match current.parent() {
            Some(parent) => current = parent.to_path_buf(),
            None => break,
        }
    }

    Err(io::Error::new(
        io::ErrorKind::NotFound,
        "not inside the DOM Protocol repository: \
         could not find a Cargo.toml with [workspace] containing 'dom-test-runner'. \
         Run this command from inside a clone of dom-protocol.",
    ))
}

/// Returns true if `contents` looks like the DOM workspace root `Cargo.toml`.
///
/// Heuristic: must contain a `[workspace]` section and reference
/// `dom-test-runner` (as path or name). Kept conservative so unrelated
/// workspaces are never falsely matched.
pub fn is_dom_workspace_manifest(contents: &str) -> bool {
    let has_workspace_section = contents
        .lines()
        .any(|l| l.trim_start().starts_with("[workspace]"));
    let mentions_runner = contents.contains("dom-test-runner");
    has_workspace_section && mentions_runner
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn detects_dom_workspace_manifest() {
        let manifest = r#"
[workspace]
resolver = "2"
members = [
    "crates/dom-core",
    "crates/dom-test-runner",
]
"#;
        assert!(is_dom_workspace_manifest(manifest));
    }

    #[test]
    fn rejects_unrelated_workspace() {
        let manifest = r#"
[workspace]
members = ["crates/foo", "crates/bar"]
"#;
        assert!(!is_dom_workspace_manifest(manifest));
    }

    #[test]
    fn rejects_non_workspace_manifest() {
        let manifest = r#"
[package]
name = "dom-test-runner"
"#;
        assert!(!is_dom_workspace_manifest(manifest));
    }

    #[test]
    fn finds_root_when_present() {
        let tmp = std::env::temp_dir().join(format!("dtr-root-{}", std::process::id()));
        let crates = tmp.join("crates").join("dom-test-runner").join("src");
        fs::create_dir_all(&crates).unwrap();
        fs::write(
            tmp.join("Cargo.toml"),
            r#"[workspace]
members = ["crates/dom-test-runner"]
"#,
        )
        .unwrap();

        let found = find_dom_repo_root(&crates).unwrap();
        assert_eq!(
            found.path.canonicalize().unwrap(),
            tmp.canonicalize().unwrap()
        );

        let _ = fs::remove_dir_all(&tmp);
    }

    #[test]
    fn errors_outside_repo() {
        let tmp = std::env::temp_dir().join(format!("dtr-notrepo-{}", std::process::id()));
        fs::create_dir_all(&tmp).unwrap();
        let err = find_dom_repo_root(&tmp).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::NotFound);
        let _ = fs::remove_dir_all(&tmp);
    }
}
