//! Small wrapper over the `git` CLI. We do not store credentials; we rely
//! on whatever auth the user already has configured locally (HTTPS helper,
//! ssh-agent, gh, etc).

use std::path::Path;
use std::process::Command;

pub fn run(repo: &Path, args: &[&str]) -> std::io::Result<std::process::Output> {
    Command::new("git").current_dir(repo).args(args).output()
}

pub fn rev_parse_head(repo: &Path) -> std::io::Result<String> {
    let o = run(repo, &["rev-parse", "HEAD"])?;
    if !o.status.success() {
        return Err(std::io::Error::other(format!(
            "git rev-parse HEAD failed: {}",
            String::from_utf8_lossy(&o.stderr)
        )));
    }
    Ok(String::from_utf8_lossy(&o.stdout).trim().to_string())
}

pub fn status_short(repo: &Path) -> std::io::Result<String> {
    let o = run(repo, &["status", "--short"])?;
    Ok(String::from_utf8_lossy(&o.stdout).to_string())
}

pub fn changed_files(repo: &Path) -> std::io::Result<Vec<String>> {
    let mut out = std::collections::BTreeSet::new();
    for args in [
        vec!["diff", "--name-only"],
        vec!["diff", "--cached", "--name-only"],
    ] {
        let o = run(repo, &args)?;
        if o.status.success() {
            for l in String::from_utf8_lossy(&o.stdout).lines() {
                let t = l.trim();
                if !t.is_empty() {
                    out.insert(t.replace('\\', "/"));
                }
            }
        }
    }
    Ok(out.into_iter().collect())
}

/// `git ls-remote origin refs/heads/main`. Returns the hex SHA, if any.
pub fn remote_head(repo: &Path, branch: &str) -> std::io::Result<Option<String>> {
    let r = format!("refs/heads/{branch}");
    let o = run(repo, &["ls-remote", "origin", &r])?;
    if !o.status.success() {
        return Err(std::io::Error::other(format!(
            "git ls-remote failed: {}",
            String::from_utf8_lossy(&o.stderr)
        )));
    }
    let line = String::from_utf8_lossy(&o.stdout)
        .lines()
        .next()
        .map(|s| s.to_string());
    Ok(line.and_then(|l| l.split_whitespace().next().map(String::from)))
}

/// Current branch (`git rev-parse --abbrev-ref HEAD`), or "HEAD" if detached.
pub fn current_branch(repo: &Path) -> std::io::Result<String> {
    let o = run(repo, &["rev-parse", "--abbrev-ref", "HEAD"])?;
    Ok(String::from_utf8_lossy(&o.stdout).trim().to_string())
}
