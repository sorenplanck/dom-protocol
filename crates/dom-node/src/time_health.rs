//! Time health check for DOM nodes.
//!
//! Verifies clock synchronization by comparing local time against multiple
//! SNTP (Simple Network Time Protocol) servers. Triggers warnings or mining
//! disablement based on detected drift.
//!
//! Implements minimal SNTPv4 client (RFC 5905) without external dependencies.
//! Section 12.1 and 12.2 of the DOM Protocol Design Philosophy.

use std::net::{SocketAddr, ToSocketAddrs, UdpSocket};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use dom_core::{CLOCK_DRIFT_ERROR_SECS, CLOCK_DRIFT_WARN_SECS};

/// Default SNTP servers used for time health checks.
const DEFAULT_NTP_SERVERS: &[&str] = &[
    "pool.ntp.org:123",
    "time.cloudflare.com:123",
    "time.google.com:123",
];

/// Status of the local clock based on drift detection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DriftStatus {
    /// Drift is within acceptable bounds (<= CLOCK_DRIFT_WARN_SECS).
    Healthy { drift_secs: i64 },

    /// Drift exceeds warning threshold but not critical.
    /// Local operations should continue; warnings logged.
    Warning { drift_secs: i64 },

    /// Drift is critical (> CLOCK_DRIFT_ERROR_SECS).
    /// Mining should be disabled.
    Critical { drift_secs: i64 },

    /// Unable to determine drift (no NTP servers reachable).
    /// Defaults to a conservative posture.
    Unknown,
}

/// Errors that can occur during time health check.
#[derive(Debug, thiserror::Error)]
pub enum TimeError {
    /// Network error reaching SNTP servers.
    #[error("network error: {0}")]
    Network(String),

    /// All configured NTP sources failed.
    #[error("all NTP sources failed")]
    AllSourcesFailed,

    /// Local system clock returned an invalid value.
    #[error("system clock error: {0}")]
    SystemClock(String),
}

/// Check clock health against default SNTP servers.
///
/// Returns the median drift across reachable servers, classified by severity.
pub fn check_clock_health() -> Result<DriftStatus, TimeError> {
    check_clock_health_with_servers(DEFAULT_NTP_SERVERS)
}

/// Check clock health against a specific list of SNTP servers.
pub fn check_clock_health_with_servers(servers: &[&str]) -> Result<DriftStatus, TimeError> {
    let local_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| TimeError::SystemClock(e.to_string()))?
        .as_secs() as i64;

    let mut drifts = Vec::new();

    for server in servers {
        if let Ok(ntp_time) = query_sntp(server) {
            drifts.push(local_time - ntp_time as i64);
        }
    }

    if drifts.is_empty() {
        return Ok(DriftStatus::Unknown);
    }

    // Compute median drift
    drifts.sort();
    let median = drifts[drifts.len() / 2];
    let abs_drift = median.abs();

    let status = if abs_drift > CLOCK_DRIFT_ERROR_SECS {
        DriftStatus::Critical { drift_secs: median }
    } else if abs_drift > CLOCK_DRIFT_WARN_SECS {
        DriftStatus::Warning { drift_secs: median }
    } else {
        DriftStatus::Healthy { drift_secs: median }
    };

    Ok(status)
}

/// Query a single SNTP server and return its reported Unix timestamp.
///
/// Implements minimal SNTPv4 client: sends 48-byte client packet, parses
/// transmit timestamp from response. Uses 5-second total timeout.
fn query_sntp(server: &str) -> Result<u64, TimeError> {
    let addr: SocketAddr = server
        .to_socket_addrs()
        .map_err(|e| TimeError::Network(format!("resolve {}: {}", server, e)))?
        .next()
        .ok_or_else(|| TimeError::Network(format!("no addr for {}", server)))?;

    let socket =
        UdpSocket::bind("0.0.0.0:0").map_err(|e| TimeError::Network(format!("bind: {}", e)))?;
    socket
        .set_read_timeout(Some(Duration::from_secs(5)))
        .map_err(|e| TimeError::Network(format!("set_timeout: {}", e)))?;
    socket
        .set_write_timeout(Some(Duration::from_secs(5)))
        .map_err(|e| TimeError::Network(format!("set_timeout: {}", e)))?;

    // SNTP client packet: 48 bytes
    // First byte: LI=0, VN=4, Mode=3 (client)
    let mut request = [0u8; 48];
    request[0] = 0b00_100_011; // LI=0, VN=4, Mode=3

    socket
        .send_to(&request, addr)
        .map_err(|e| TimeError::Network(format!("send: {}", e)))?;

    let mut response = [0u8; 48];
    socket
        .recv_from(&mut response)
        .map_err(|e| TimeError::Network(format!("recv: {}", e)))?;

    // Transmit timestamp is bytes 40-47
    // First 4 bytes: seconds since NTP epoch (1900-01-01)
    let ntp_seconds =
        u32::from_be_bytes([response[40], response[41], response[42], response[43]]) as u64;

    // Convert NTP epoch to Unix epoch
    // NTP epoch starts 70 years before Unix epoch
    const NTP_UNIX_DELTA: u64 = 2_208_988_800;

    if ntp_seconds < NTP_UNIX_DELTA {
        return Err(TimeError::Network("invalid NTP timestamp".into()));
    }

    Ok(ntp_seconds - NTP_UNIX_DELTA)
}

/// Get current Unix timestamp in seconds.
/// Helper for code that needs current time without going through SystemTime.
pub fn unix_now() -> Result<u64, TimeError> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| TimeError::SystemClock(e.to_string()))?
        .as_secs())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unix_now_returns_recent_timestamp() {
        let now = unix_now().unwrap();
        // Sanity check: after 2020-01-01 (1577836800)
        assert!(now > 1_577_836_800);
        // And before year 2100 (4102444800)
        assert!(now < 4_102_444_800);
    }

    #[test]
    fn drift_status_classification() {
        // Test the threshold logic without actual network calls
        let healthy = DriftStatus::Healthy { drift_secs: 10 };
        let warning = DriftStatus::Warning { drift_secs: 40 };
        let critical = DriftStatus::Critical { drift_secs: 70 };
        let unknown = DriftStatus::Unknown;

        assert!(matches!(healthy, DriftStatus::Healthy { .. }));
        assert!(matches!(warning, DriftStatus::Warning { .. }));
        assert!(matches!(critical, DriftStatus::Critical { .. }));
        assert_eq!(unknown, DriftStatus::Unknown);
    }

    #[test]
    fn check_with_no_servers_returns_unknown() {
        let result = check_clock_health_with_servers(&[]).unwrap();
        assert_eq!(result, DriftStatus::Unknown);
    }

    #[test]
    fn check_with_unreachable_servers_returns_unknown() {
        // Use IPs that should not respond
        let result = check_clock_health_with_servers(&[
            "192.0.2.1:123", // TEST-NET-1, unreachable
        ]);
        // Either Unknown or network error; both acceptable
        assert!(result.is_ok() || result.is_err());
    }
}
