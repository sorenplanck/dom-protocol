//! Repository-root detection. Same heuristic as in dom-test-runner.
//!
//! We avoid sharing a library crate to keep the two binaries strictly
//! independent and individually portable. The total amount of duplicated
//! code is tiny.

use std::io;
use std::path::{Path, PathBuf};

#[derive(Debug)]
pub struct RepoRoot {
    pub path: PathBuf,
}

pub fn find_dom_repo_root(start: &Path) -> io::Result<RepoRoot> {
    let mut current = start
        .canonicalize()
        .unwrap_or_else(|_| start.to_path_buf());
    loop {
        let candidate = current.join("Cargo.toml");
        if candidate.is_file() {
            let contents = std::fs::read_to_string(&candidate).unwrap_or_default();
            let has_ws = contents
                .lines()
                .any(|l| l.trim_start().starts_with("[workspace]"));
            // Look for either runner: agent or test runner. Both prove this
            // is the DOM workspace.
            let mentions =
                contents.contains("dom-agent-runner") || contents.contains("dom-test-runner");
            if has_ws && mentions {
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
        "not inside the DOM Protocol repository",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn finds_root() {
        let tmp = std::env::temp_dir().join(format!("dar-root-{}", std::process::id()));
        fs::create_dir_all(tmp.join("crates").join("dom-agent-runner").join("src"))
            .unwrap();
        fs::write(
            tmp.join("Cargo.toml"),
            "[workspace]\nmembers = [\"crates/dom-agent-runner\"]\n",
        )
        .unwrap();
        let r = find_dom_repo_root(&tmp).unwrap();
        assert_eq!(
            r.path.canonicalize().unwrap(),
            tmp.canonicalize().unwrap()
        );
        let _ = fs::remove_dir_all(&tmp);
    }

    #[test]
    fn errors_outside_repo() {
        let tmp = std::env::temp_dir().join(format!("dar-no-{}", std::process::id()));
        fs::create_dir_all(&tmp).unwrap();
        assert!(find_dom_repo_root(&tmp).is_err());
        let _ = fs::remove_dir_all(&tmp);
    }
}
