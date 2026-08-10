//! Bearer token generation and storage.

use rand::Rng;
use std::path::PathBuf;

/// Generate a cryptographically secure random token (32 bytes hex = 64 chars).
pub fn generate_token() -> String {
    let bytes: [u8; 32] = rand::thread_rng().gen();
    hex::encode(bytes)
}

/// Get the Bearer token from explicit config, environment, or file, or generate new one.
///
/// Order of precedence:
/// 1. Explicit config token, for embedded callers that must not export secrets
/// 2. DOM_RPC_TOKEN env var (standalone-node override)
/// 3. ~/.dom/rpc_token file (fallback)
/// 4. Generate new + save to file + log warning
pub fn get_or_create_token_with_config(
    configured_token: Option<&str>,
) -> Result<String, std::io::Error> {
    if let Some(token) = configured_token {
        let token = token.trim();
        if !token.is_empty() {
            tracing::info!("Using Bearer token from explicit node config");
            return Ok(token.to_string());
        }
    }

    get_or_create_token()
}

/// Get the Bearer token from environment or file, or generate new one.
///
/// Order of precedence:
/// 1. DOM_RPC_TOKEN env var (standalone-node override)
/// 2. ~/.dom/rpc_token file (fallback)
/// 3. Generate new + save to file + log warning
pub fn get_or_create_token() -> Result<String, std::io::Error> {
    // 1. Check env var first
    if let Ok(token) = std::env::var("DOM_RPC_TOKEN") {
        if !token.is_empty() {
            tracing::info!("Using Bearer token from DOM_RPC_TOKEN env var");
            return Ok(token);
        }
    }

    // 2. Try to read from file
    let token_path = token_file_path()?;
    if token_path.exists() {
        match std::fs::read_to_string(&token_path) {
            Ok(token) => {
                let token = token.trim().to_string();
                if !token.is_empty() {
                    tracing::info!("Using Bearer token from {}", token_path.display());
                    return Ok(token);
                }
            }
            Err(e) => {
                tracing::warn!("Failed to read token file {}: {}", token_path.display(), e);
            }
        }
    }

    // 3. Generate new token and save
    let token = generate_token();
    save_token(&token)?;
    tracing::warn!(
        "Generated new Bearer token and saved to {}. Set DOM_RPC_TOKEN env var to override.",
        token_path.display()
    );
    Ok(token)
}

/// Get the path to ~/.dom/rpc_token (cross-platform via `dirs` crate).
///
/// On Unix: $HOME/.dom/rpc_token
/// On Windows: %USERPROFILE%\.dom\rpc_token
fn token_file_path() -> Result<PathBuf, std::io::Error> {
    let home = dirs::home_dir().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "home directory not found (HOME/USERPROFILE unset)",
        )
    })?;
    let dom_dir = home.join(".dom");
    Ok(dom_dir.join("rpc_token"))
}

/// Save token to ~/.dom/rpc_token with owner-only permissions.
fn save_token(token: &str) -> Result<(), std::io::Error> {
    let token_path = token_file_path()?;
    save_token_at(&token_path, token)
}

/// Create a token file without exposing it through the process umask.
fn save_token_at(token_path: &std::path::Path, token: &str) -> Result<(), std::io::Error> {
    let dom_dir = token_path
        .parent()
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "Invalid token path"))?;

    // Create the parent directory before opening the token file.
    std::fs::create_dir_all(dom_dir)?;

    // `create_new` prevents a concurrent replacement and, on Unix, `mode`
    // applies before the file becomes visible. This avoids a write-then-chmod
    // window where a newly generated bearer token inherits a permissive umask.
    #[cfg(unix)]
    {
        use std::{io::Write, os::unix::fs::OpenOptionsExt};
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(token_path)?;
        file.write_all(format!("{token}\n").as_bytes())?;
        file.sync_all()?;
    }

    #[cfg(not(unix))]
    std::fs::write(token_path, format!("{token}\n"))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_token_produces_64_char_hex() {
        let token = generate_token();
        assert_eq!(token.len(), 64);
        assert!(token.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn generate_token_is_random() {
        let t1 = generate_token();
        let t2 = generate_token();
        assert_ne!(t1, t2);
    }

    /// A generated token must be created with owner-only permissions from the
    /// first visible filesystem state, rather than tightened after writing.
    #[cfg(unix)]
    #[test]
    fn save_token_creates_owner_only_file_without_write_chmod_window() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("rpc_token");

        save_token_at(&path, "deadbeef").unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "token must be owner-only at creation");
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "deadbeef\n");
        assert!(save_token_at(&path, "replacement").is_err());
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "deadbeef\n");
    }

    /// SECRET-2 (zeroization) — STATIC-REVIEW NOTE, intentionally ignored.
    ///
    /// The token is handled as a plain `String` throughout: returned by
    /// `get_or_create_token*`, stored in `BearerToken(pub String)`, read from
    /// `DOM_RPC_TOKEN` env (process-global, inherited by children, visible in
    /// /proc/<pid>/environ), and read from file into a `String`. None of these
    /// are zeroized on drop — the secret lingers in freed heap until reuse, and
    /// the env copy lives for the whole process. A `Zeroizing<String>` / secret
    /// wrapper would close this. Behaviorally untestable from outside (we cannot
    /// inspect freed heap deterministically in safe Rust), so this is recorded
    /// as a finding, not a runtime assertion. NOT A BUG FIX (HARD RULE).
    #[test]
    #[ignore = "static-review finding: bearer token (String/env) is never zeroized; no production change here"]
    fn secret_token_not_zeroized_static_note() {}

    /// SECRET-3 (side-channel) — dudect-style NOTE, intentionally ignored.
    ///
    /// The bearer comparison in middleware.rs uses `subtle::ConstantTimeEq`
    /// (`provided.as_bytes().ct_eq(token.0.as_bytes())`) — the CORRECT primitive:
    /// no data-dependent early return for equal-length inputs (token length is
    /// public, so length-mismatch short-circuit leaks nothing secret). A real
    /// dudect timing test over a network/async path is dominated by scheduling
    /// and HTTP jitter (orders of magnitude above the per-byte signal), so it
    /// would be noise, not evidence. We therefore record by review that the
    /// right primitive is in place rather than ship a flaky timing harness.
    #[test]
    #[ignore = "static-review note: bearer compare uses subtle::ct_eq (correct constant-time primitive); dudect over async HTTP would be noise"]
    fn bearer_compare_is_constant_time_static_note() {}
}
