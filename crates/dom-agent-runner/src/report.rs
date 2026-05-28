//! Per-run report writer for dom-agent-runner.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

/// Returns `(base, runs_dir)` and ensures both exist.
pub fn dirs(repo_root: &Path) -> (PathBuf, PathBuf) {
    let base = repo_root.join("target").join("dom-agent-runner");
    let runs = base.join("runs");
    let _ = fs::create_dir_all(&runs);
    (base, runs)
}

/// Returns the per-run directory and ensures it exists.
pub fn new_run_dir(runs_dir: &Path, started: SystemTime) -> std::io::Result<PathBuf> {
    let ts = timestamp(started);
    let dir = runs_dir.join(ts);
    fs::create_dir_all(&dir)?;
    Ok(dir)
}

pub fn timestamp(now: SystemTime) -> String {
    let secs = now
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let (y, mo, d, h, mi, s) = utc_breakdown(secs);
    format!("{y:04}{mo:02}{d:02}-{h:02}{mi:02}{s:02}")
}

fn utc_breakdown(secs_since_epoch: u64) -> (u32, u32, u32, u32, u32, u32) {
    let z = (secs_since_epoch / 86_400) as i64 + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let year = (if m <= 2 { y + 1 } else { y }) as u32;
    let rem = secs_since_epoch % 86_400;
    let h = (rem / 3600) as u32;
    let mi = ((rem % 3600) / 60) as u32;
    let s = (rem % 60) as u32;
    (year, m, d, h, mi, s)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, UNIX_EPOCH};

    #[test]
    fn timestamp_matches() {
        let ts = timestamp(UNIX_EPOCH + Duration::from_secs(1_705_276_800));
        assert_eq!(ts, "20240115-000000");
    }
}
