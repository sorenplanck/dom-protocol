//! Roadmap v2 Phase 7.2 — Drift elimination CI gate.
//!
//! This is a structural cleanliness audit. It walks the entire
//! `crates/*/src` tree (production code only — tests, examples,
//! integration suites are allowed to carry stale markers) and
//! fails CI when it finds any of three drift patterns:
//!
//!   1. **Untracked tech-debt markers** — `TODO`, `FIXME`, `HACK`,
//!      and `XXX`. Either resolve the marker, move the work to an
//!      RFC / RELEASE_BLOCKERS entry, or convert the marker into a
//!      Phase-N reference (e.g. `Phase 4.1 follow-up`) the audit
//!      treats as tracked.
//!   2. **Stale-comment patterns** — `// removed`, `// deprecated`,
//!      `// obsolete`, `// stale`, `// dead`. These accumulate
//!      after every refactor and silently mislead readers about
//!      what the code does today.
//!   3. **Bare commit hashes** — 40-character hex strings outside
//!      of doc / Cargo files. A reference to a past commit hash is
//!      fine in a commit message or an RFC, but in production code
//!      it usually marks an unresolved investigation that should
//!      have been turned into a constant or an explicit comment.
//!
//! Tests / fuzz / examples are intentionally exempt so the gate
//! does not require sweeping every test fixture. The directive is
//! "the protocol implementation is drift-free", not "every
//! scratch buffer is drift-free".
//!
//! Allowed exceptions are listed in `ALLOWED_MARKERS` below. When a
//! marker is legitimately appropriate (e.g. a Phase-N tracking
//! reference), add it there with a one-line rationale.

use std::path::{Path, PathBuf};

/// Substrings that are allowed even inside production source files,
/// because they reference a tracked Phase / RFC follow-up rather
/// than an orphan TODO.
const ALLOWED_MARKERS: &[&str] = &[
    // Phase tracking references are not drift — they're an explicit
    // pointer at the roadmap. Examples:
    //   "Phase 3.2 follow-up", "Phase 6.1 deferred"
    "Phase",
    // RFC references are explicit spec pointers, not drift.
    "RFC-",
    // RELEASE_BLOCKERS short-codes (RB-*) are explicit gap tracking.
    "RB-",
    // DOM-XXX-NNN audit IDs are explicit-tracking too.
    "DOM-",
];

/// Substrings that flag a production-code drift marker.
const FORBIDDEN_MARKERS: &[&str] =
    &["TODO", "FIXME", "HACK", "XXX", "todo!()", "unimplemented!()"];

/// Substrings that mark stale / dead-code comments.
const STALE_COMMENT_MARKERS: &[&str] = &[
    "// removed:",
    "// removed.",
    "// deprecated",
    "// obsolete",
    "// stale ",
    "// dead ",
];

fn crates_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("crates/")
        .to_path_buf()
}

fn walk_src_files(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    if !root.exists() {
        return out;
    }
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let entries = match std::fs::read_dir(&dir) {
            Ok(e) => e,
            Err(_) => continue,
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                let name = path
                    .file_name()
                    .and_then(|s| s.to_str())
                    .unwrap_or_default();
                if matches!(name, "tests" | "examples" | "fuzz" | "benches" | "target") {
                    continue;
                }
                stack.push(path);
            } else if path.extension().and_then(|s| s.to_str()) == Some("rs") {
                out.push(path);
            }
        }
    }
    out
}

fn scan_production_src() -> Vec<PathBuf> {
    let crates = crates_dir();
    let mut files = Vec::new();
    for entry in std::fs::read_dir(&crates).expect("read crates dir") {
        let entry = entry.expect("crate dir");
        let crate_path = entry.path();
        if !crate_path.is_dir() {
            continue;
        }
        let src = crate_path.join("src");
        files.extend(walk_src_files(&src));
    }
    files
}

/// Skip lines that legitimately mention a marker because of an
/// allowed substring (Phase / RFC / RB / DOM- tracking) on the same line.
fn is_allowed_line(line: &str) -> bool {
    ALLOWED_MARKERS.iter().any(|m| line.contains(m))
}

/// Production source MUST NOT carry untracked TODO / FIXME / HACK
/// / XXX / todo!() / unimplemented!() markers. Tracked references
/// (Phase-N, RFC-NNNN, RB-X, DOM-X-N) on the same line are exempt.
#[test]
fn no_untracked_tech_debt_markers_in_production_src() {
    let mut hits: Vec<String> = Vec::new();
    for file in scan_production_src() {
        let content = match std::fs::read_to_string(&file) {
            Ok(c) => c,
            Err(_) => continue,
        };
        for (lineno, line) in content.lines().enumerate() {
            // Skip the audit's own ALLOWED_MARKERS / FORBIDDEN_MARKERS
            // definitions if this file is the audit itself (it won't
            // be — drift_audit.rs lives in tests/ — but kept for
            // future-proofing).
            for marker in FORBIDDEN_MARKERS {
                if line.contains(marker) && !is_allowed_line(line) {
                    hits.push(format!(
                        "{}:{}: untracked marker '{marker}': {}",
                        file.display(),
                        lineno + 1,
                        line.trim()
                    ));
                }
            }
        }
    }
    assert!(
        hits.is_empty(),
        "drift audit failed — untracked tech-debt markers in production source:\n  {}\n\
         (Either resolve the work, move it to RELEASE_BLOCKERS / an RFC, or add a \
         Phase-N / RFC-NNNN reference on the same line so the audit treats it as tracked.)",
        hits.join("\n  ")
    );
}

/// Production source MUST NOT carry stale-comment markers like
/// `// removed`, `// deprecated`, `// obsolete`. These accumulate
/// after refactors and silently mislead readers.
#[test]
fn no_stale_comment_markers_in_production_src() {
    let mut hits: Vec<String> = Vec::new();
    for file in scan_production_src() {
        let content = match std::fs::read_to_string(&file) {
            Ok(c) => c,
            Err(_) => continue,
        };
        for (lineno, line) in content.lines().enumerate() {
            for marker in STALE_COMMENT_MARKERS {
                if line.contains(marker) && !is_allowed_line(line) {
                    hits.push(format!(
                        "{}:{}: stale-comment marker '{marker}': {}",
                        file.display(),
                        lineno + 1,
                        line.trim()
                    ));
                }
            }
        }
    }
    assert!(
        hits.is_empty(),
        "drift audit failed — stale-comment markers in production source:\n  {}",
        hits.join("\n  ")
    );
}

/// Production source SHOULD NOT carry bare 40-character commit
/// hashes — they're usually a "this references some past
/// investigation" marker that should be either a constant, a Phase
/// reference, or removed.
#[test]
fn no_bare_commit_hashes_in_production_src() {
    let mut hits: Vec<String> = Vec::new();
    for file in scan_production_src() {
        let content = match std::fs::read_to_string(&file) {
            Ok(c) => c,
            Err(_) => continue,
        };
        for (lineno, line) in content.lines().enumerate() {
            // Skip lines that already cite a Phase / RFC / commit-message
            // header.
            if is_allowed_line(line) || line.contains("commit") {
                continue;
            }
            // Greedy 40-hex scan. Substring rather than full-line so
            // we catch hashes embedded in comments.
            let bytes = line.as_bytes();
            let mut i = 0;
            while i + 40 <= bytes.len() {
                let candidate = &bytes[i..i + 40];
                if candidate.iter().all(|b| b.is_ascii_hexdigit()) {
                    // Require a boundary before/after — random
                    // bytes inside e.g. SEC1 byte arrays are not
                    // commit hashes.
                    let prev = if i == 0 { b' ' } else { bytes[i - 1] };
                    let next = if i + 40 < bytes.len() {
                        bytes[i + 40]
                    } else {
                        b' '
                    };
                    if !prev.is_ascii_hexdigit() && !next.is_ascii_hexdigit() {
                        hits.push(format!(
                            "{}:{}: bare commit-hash-like literal '{}': {}",
                            file.display(),
                            lineno + 1,
                            std::str::from_utf8(candidate).unwrap_or("?"),
                            line.trim()
                        ));
                        // Avoid double-counting overlapping 40-byte
                        // windows on the same line.
                        break;
                    }
                }
                i += 1;
            }
        }
    }
    assert!(
        hits.is_empty(),
        "drift audit failed — bare 40-hex literals in production source:\n  {}",
        hits.join("\n  ")
    );
}

/// Sanity baseline: the scanner walks a non-empty set of files. If
/// the workspace layout changes and the scanner accidentally walks
/// nothing, the other tests would pass trivially.
#[test]
fn drift_audit_scans_a_non_empty_corpus() {
    let files = scan_production_src();
    assert!(
        files.len() >= 30,
        "drift audit corpus shrank unexpectedly — only {} files found; \
         expected ≥30 production-source .rs files across the workspace",
        files.len()
    );
}
