//! Run logs and reports.
//!
//! Every command writes:
//!   - one per-step log under `target/dom-test-runner/logs/<ts>-<step>.log`
//!   - a summary report under `target/dom-test-runner/reports/<ts>.txt`
//!   - the same content copied to `reports/latest-report.txt`

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

/// Outcome of a single step.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Status {
    Pass,
    Fail,
    Skipped,
    Blocked,
}

impl Status {
    pub fn as_str(&self) -> &'static str {
        match self {
            Status::Pass => "PASS",
            Status::Fail => "FAIL",
            Status::Skipped => "SKIPPED",
            Status::Blocked => "BLOCKED",
        }
    }
}

/// Recorded result for one step.
#[derive(Debug, Clone)]
pub struct StepResult {
    pub label: String,
    pub status: Status,
    pub duration_ms: u128,
    pub log_path: Option<PathBuf>,
    pub note: Option<String>,
}

/// Whole-run report data.
#[derive(Debug)]
pub struct RunReport {
    pub started: SystemTime,
    pub profile: String,
    pub env: Vec<(String, String)>,
    pub steps: Vec<StepResult>,
    pub total_ms: u128,
}

/// Compute the per-run directories under `<repo_root>/target/dom-test-runner/`.
pub fn dirs(repo_root: &Path) -> (PathBuf, PathBuf) {
    let base = repo_root.join("target").join("dom-test-runner");
    let logs = base.join("logs");
    let reports = base.join("reports");
    let _ = fs::create_dir_all(&logs);
    let _ = fs::create_dir_all(&reports);
    (logs, reports)
}

/// Format a SystemTime as a filesystem-safe timestamp `YYYYMMDD-HHMMSS`.
/// Uses UTC; this avoids platform timezone surprises on Windows/Linux/macOS.
pub fn timestamp(now: SystemTime) -> String {
    let secs = now
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let (y, mo, d, h, mi, s) = utc_breakdown(secs);
    format!("{y:04}{mo:02}{d:02}-{h:02}{mi:02}{s:02}")
}

/// Tiny UTC time breakdown without pulling `chrono`.
/// Algorithm: Howard Hinnant's days-from-civil, public domain.
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

/// Write the final report (and `latest-report.txt`) into `reports_dir`.
/// Returns the path of the timestamped report file.
pub fn write_report(reports_dir: &Path, report: &RunReport) -> std::io::Result<PathBuf> {
    let ts = timestamp(report.started);
    let path = reports_dir.join(format!("{ts}.txt"));
    let mut body = String::new();
    body.push_str("dom-test-runner report\n");
    body.push_str("======================\n");
    body.push_str(&format!("started (UTC): {ts}\n"));
    body.push_str(&format!("profile:       {}\n", report.profile));
    body.push_str(&format!("total ms:      {}\n", report.total_ms));
    body.push_str("env:\n");
    for (k, v) in &report.env {
        body.push_str(&format!("  {k}={v}\n"));
    }
    body.push_str("\nsteps:\n");
    let mut fails = 0;
    let mut skips = 0;
    let mut blocks = 0;
    let mut passes = 0;
    for s in &report.steps {
        body.push_str(&format!(
            "  [{}] {} ({} ms)\n",
            s.status.as_str(),
            s.label,
            s.duration_ms
        ));
        if let Some(p) = &s.log_path {
            body.push_str(&format!("        log: {}\n", p.display()));
        }
        if let Some(n) = &s.note {
            body.push_str(&format!("        note: {n}\n"));
        }
        match s.status {
            Status::Pass => passes += 1,
            Status::Fail => fails += 1,
            Status::Skipped => skips += 1,
            Status::Blocked => blocks += 1,
        }
    }
    body.push_str(&format!(
        "\nsummary: {passes} pass, {fails} fail, {skips} skipped, {blocks} blocked\n"
    ));
    let final_status = if fails > 0 || blocks > 0 { "FAIL" } else { "PASS" };
    body.push_str(&format!("final:   {final_status}\n"));

    fs::write(&path, &body)?;
    let latest = reports_dir.join("latest-report.txt");
    fs::write(&latest, &body)?;
    Ok(path)
}

/// Convenience: open a fresh log file for a step.
pub fn open_log(logs_dir: &Path, ts: &str, label: &str) -> std::io::Result<(PathBuf, fs::File)> {
    let safe = label
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect::<String>();
    let path = logs_dir.join(format!("{ts}-{safe}.log"));
    let mut f = fs::File::create(&path)?;
    writeln!(f, "[dom-test-runner] step: {label}")?;
    writeln!(f, "[dom-test-runner] ts:   {ts}")?;
    Ok((path, f))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    #[test]
    fn timestamp_is_filesystem_safe() {
        // Pick a known epoch second: 2024-01-15 00:00:00 UTC = 1705276800.
        let ts = timestamp(UNIX_EPOCH + Duration::from_secs(1_705_276_800));
        assert_eq!(ts, "20240115-000000");
    }

    #[test]
    fn timestamp_has_no_path_separators() {
        let ts = timestamp(SystemTime::now());
        assert!(!ts.contains('/'));
        assert!(!ts.contains('\\'));
        assert!(!ts.contains(':'));
    }

    #[test]
    fn write_report_creates_both_files() {
        let tmp = std::env::temp_dir().join(format!("dtr-rep-{}", std::process::id()));
        fs::create_dir_all(&tmp).unwrap();
        let report = RunReport {
            started: UNIX_EPOCH + Duration::from_secs(1_705_276_800),
            profile: "fast-check".to_string(),
            env: vec![("DOM_NETWORK".to_string(), "regtest".to_string())],
            steps: vec![StepResult {
                label: "cargo check".to_string(),
                status: Status::Pass,
                duration_ms: 42,
                log_path: None,
                note: None,
            }],
            total_ms: 42,
        };
        let path = write_report(&tmp, &report).unwrap();
        assert!(path.exists());
        assert!(tmp.join("latest-report.txt").exists());
        let contents = fs::read_to_string(&path).unwrap();
        assert!(contents.contains("PASS"));
        assert!(contents.contains("fast-check"));
        assert!(contents.contains("DOM_NETWORK=regtest"));
        let _ = fs::remove_dir_all(&tmp);
    }
}
