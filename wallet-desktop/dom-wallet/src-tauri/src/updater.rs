//! Update mechanism (Principle 5).
//!
//! On startup the app queries the GitHub Releases API and compares the latest
//! tag to the running version. If a newer version exists it surfaces an
//! `update://available` event. Tags containing "MANDATORY" (used for hard
//! forks, e.g. `v0.3.0-MANDATORY-HARD-FORK`) flag the update as mandatory so the
//! UI can show a persistent red banner.
//!
//! This module only CHECKS and reports. It never downloads or executes code
//! (the brief forbids remote code execution); applying an update opens the
//! signed installer through the OS, which the frontend triggers explicitly.

use serde::{Deserialize, Serialize};

use crate::error::{AppError, AppResult};

const RELEASES_LATEST_URL: &str =
    "https://api.github.com/repos/sorenplanck/dom-protocol/releases/latest";

/// Result of an update check, emitted as `update://available` when newer.
#[derive(Clone, Debug, Serialize)]
pub struct UpdateInfo {
    pub current: String,
    pub latest: String,
    pub newer: bool,
    pub mandatory: bool,
    pub changelog: String,
    pub html_url: String,
}

/// Subset of the GitHub Releases JSON we care about.
#[derive(Deserialize)]
struct GhRelease {
    tag_name: String,
    #[serde(default)]
    body: String,
    #[serde(default)]
    html_url: String,
    #[serde(default)]
    draft: bool,
    #[serde(default)]
    prerelease: bool,
}

/// Query GitHub for the latest release and compare to `current_version`.
pub async fn check(current_version: &str) -> AppResult<UpdateInfo> {
    let current = current_version.to_string();
    let release: GhRelease = tokio::task::spawn_blocking(|| {
        reqwest::blocking::Client::new()
            .get(RELEASES_LATEST_URL)
            .header("User-Agent", "dom-wallet")
            .header("Accept", "application/vnd.github+json")
            .timeout(std::time::Duration::from_secs(8))
            .send()
            .and_then(|r| r.error_for_status())
            .and_then(|r| r.json::<GhRelease>())
    })
    .await
    .map_err(|e| AppError::Update(format!("join: {e}")))?
    .map_err(|e| AppError::Update(e.to_string()))?;

    if release.draft || release.prerelease {
        // Don't nag about drafts/prereleases.
        return Ok(UpdateInfo {
            current: current.clone(),
            latest: release.tag_name,
            newer: false,
            mandatory: false,
            changelog: String::new(),
            html_url: release.html_url,
        });
    }

    let latest_norm = normalize_version(&release.tag_name);
    let current_norm = normalize_version(&current);
    let newer = version_gt(&latest_norm, &current_norm);

    // Audit D-06: prefer STRUCTURED release metadata over tag-string heuristics.
    // The release body may contain a fenced block:
    //     ```dom-release
    //     mandatory = true
    //     ```
    // (or a JSON object with a "mandatory" boolean). If present, it is
    // authoritative. Only if absent do we fall back to the legacy tag substring,
    // so existing releases keep working but new ones get a robust signal.
    let mandatory = match parse_structured_mandatory(&release.body) {
        Some(flag) => flag,
        None => release.tag_name.to_ascii_uppercase().contains("MANDATORY"),
    };

    Ok(UpdateInfo {
        current,
        latest: release.tag_name,
        newer,
        mandatory: mandatory && newer,
        changelog: release.body,
        html_url: release.html_url,
    })
}

/// Extract a `mandatory` flag from structured release metadata in the body.
/// Recognizes a fenced ```dom-release block with `mandatory = true|false`, or a
/// JSON object containing `"mandatory": true|false`. Returns `None` if no
/// structured signal is present (caller falls back to the tag heuristic).
fn parse_structured_mandatory(body: &str) -> Option<bool> {
    // Fenced block form.
    if let Some(start) = body.find("```dom-release") {
        let after = &body[start + "```dom-release".len()..];
        if let Some(end) = after.find("```") {
            let block = &after[..end];
            for line in block.lines() {
                let l = line.trim();
                if let Some(rest) = l.strip_prefix("mandatory") {
                    let v = rest.trim_start_matches([' ', '=', ':']).trim();
                    if v.eq_ignore_ascii_case("true") {
                        return Some(true);
                    }
                    if v.eq_ignore_ascii_case("false") {
                        return Some(false);
                    }
                }
            }
        }
    }
    // JSON object form anywhere in the body.
    if let Some(idx) = body.find("\"mandatory\"") {
        let rest = &body[idx + "\"mandatory\"".len()..];
        let rest = rest.trim_start().trim_start_matches(':').trim_start();
        if rest.starts_with("true") {
            return Some(true);
        }
        if rest.starts_with("false") {
            return Some(false);
        }
    }
    None
}

/// Strip a leading `v` and any suffix after the first `-` (e.g.
/// `v0.3.0-MANDATORY-HARD-FORK` → `0.3.0`), then split into numeric parts.
/// Non-numeric components make the whole parse fail (returns an empty vec),
/// rather than silently coercing to 0 (audit D-06), so a malformed tag compares
/// as "not newer" instead of masquerading as version 0.x.
fn normalize_version(tag: &str) -> Vec<u64> {
    let core = tag.trim().trim_start_matches('v');
    let core = core.split('-').next().unwrap_or(core);
    let mut parts = Vec::new();
    for p in core.split('.') {
        match p.parse::<u64>() {
            Ok(n) => parts.push(n),
            Err(_) => return Vec::new(), // malformed → no version
        }
    }
    parts
}

/// Semantic-ish "a > b" over numeric component vectors.
fn version_gt(a: &[u64], b: &[u64]) -> bool {
    let n = a.len().max(b.len());
    for i in 0..n {
        let av = a.get(i).copied().unwrap_or(0);
        let bv = b.get(i).copied().unwrap_or(0);
        if av != bv {
            return av > bv;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_tags() {
        assert_eq!(normalize_version("v0.3.0"), vec![0, 3, 0]);
        assert_eq!(
            normalize_version("v0.3.0-MANDATORY-HARD-FORK"),
            vec![0, 3, 0]
        );
        assert_eq!(normalize_version("1.2"), vec![1, 2]);
    }

    #[test]
    fn malformed_version_parses_empty_not_zero() {
        // Audit D-06: non-numeric components must not silently become 0.
        assert_eq!(normalize_version("vfoo.bar"), Vec::<u64>::new());
        assert_eq!(normalize_version("v1.x.0"), Vec::<u64>::new());
        // A malformed "latest" therefore does not read as newer than a real one.
        assert!(!version_gt(&normalize_version("vbad"), &[0, 1, 0]));
    }

    #[test]
    fn structured_mandatory_overrides_tag() {
        assert_eq!(
            parse_structured_mandatory("notes\n```dom-release\nmandatory = true\n```\nmore"),
            Some(true)
        );
        assert_eq!(
            parse_structured_mandatory("```dom-release\nmandatory: false\n```"),
            Some(false)
        );
        assert_eq!(
            parse_structured_mandatory(r#"{"mandatory": true}"#),
            Some(true)
        );
        assert_eq!(parse_structured_mandatory("just a normal changelog"), None);
    }

    #[test]
    fn version_comparison() {
        assert!(version_gt(&[0, 3, 0], &[0, 2, 9]));
        assert!(version_gt(&[1, 0, 0], &[0, 9, 9]));
        assert!(!version_gt(&[0, 1, 0], &[0, 1, 0]));
        assert!(!version_gt(&[0, 1, 0], &[0, 1, 1]));
        // Shorter vs longer: 0.2 == 0.2.0
        assert!(!version_gt(&[0, 2], &[0, 2, 0]));
        assert!(version_gt(&[0, 2, 1], &[0, 2]));
    }
}
