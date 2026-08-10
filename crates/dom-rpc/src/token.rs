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

    // 2. Read from file, or generate + save
    let token_path = token_file_path()?;
    get_or_create_token_at(&token_path)
}

/// File-backed half of [`get_or_create_token`], parameterized over the path so
/// the recovery behavior is testable without touching the real home directory.
fn get_or_create_token_at(token_path: &std::path::Path) -> Result<String, std::io::Error> {
    // A token file can legitimately exist and be empty: a crash or a full disk
    // between `save_token_at`'s `create_new` and its `write_all` leaves zero
    // bytes behind. That state must be repaired here — `save_token_at` alone
    // refuses to touch an existing file (by design, see below), so without
    // this flag every subsequent startup would die on `AlreadyExists` until
    // someone deletes the file by hand.
    let mut repair_existing = false;
    if token_path.exists() {
        match std::fs::read_to_string(token_path) {
            Ok(token) => {
                let token = token.trim().to_string();
                if !token.is_empty() {
                    tracing::info!("Using Bearer token from {}", token_path.display());
                    return Ok(token);
                }
                repair_existing = true;
            }
            Err(e) => {
                tracing::warn!("Failed to read token file {}: {}", token_path.display(), e);
            }
        }
    }

    let token = generate_token();
    if repair_existing {
        let adopted = repair_empty_token_at(token_path, &token)?;
        if adopted == token {
            tracing::warn!(
                "Token file {} existed but was empty (interrupted write?); \
                 replaced it with a newly generated Bearer token.",
                token_path.display()
            );
        } else {
            tracing::info!(
                "Token file {} was repaired by another process while we waited; \
                 using its Bearer token.",
                token_path.display()
            );
        }
        return Ok(adopted);
    }
    save_token_at(token_path, &token)?;
    tracing::warn!(
        "Generated new Bearer token and saved to {}. Set DOM_RPC_TOKEN env var to override.",
        token_path.display()
    );
    Ok(token)
}

/// Repair an observed-empty token file without ever overwriting a live token.
///
/// Two nodes sharing one home directory can both read the empty file and both
/// reach here; a naive rename-over-the-target would let the loser silently
/// replace the winner's freshly persisted token. Instead the repair is built
/// from the two atomic primitives the rest of this module already relies on
/// (MSRV 1.75 — `File::lock` is 1.89+):
///
/// 1. CLAIM — atomically `rename` the empty file aside. Exactly one
///    contender succeeds; a loser sees `NotFound`, re-reads, and either
///    adopts the winner's persisted token or fails closed with the same
///    restart-and-adopt semantics a `save_token_at` race loser already has.
/// 2. RECHECK — read the file we moved. If another process repaired between
///    our empty read and our claim, we just moved a LIVE token aside: restore
///    that token rather than rotating it.
/// 3. PERSIST — write through `save_token_at`'s `create_new` (owner-only from
///    first visible state, never clobbers). If a concurrent creator wins that
///    race, adopt what it persisted.
///
/// No step renames over an existing file, so a valid token can never be
/// clobbered. A crash at any point leaves the token file either valid or
/// absent — and absent heals through the ordinary creation path on the next
/// startup, never wedging it the way the empty file did.
fn repair_empty_token_at(
    token_path: &std::path::Path,
    candidate: &str,
) -> Result<String, std::io::Error> {
    let dom_dir = token_path
        .parent()
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "Invalid token path"))?;

    let mut suffix = [0u8; 8];
    rand::thread_rng().fill(&mut suffix);
    let claimed = dom_dir.join(format!(".rpc_token.repair.{}", hex::encode(suffix)));

    match std::fs::rename(token_path, &claimed) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            // Lost the claim race. If the winner already persisted, adopt.
            if let Ok(raw) = std::fs::read_to_string(token_path) {
                let existing = raw.trim();
                if !existing.is_empty() {
                    return Ok(existing.to_string());
                }
            }
            return Err(std::io::Error::new(
                std::io::ErrorKind::WouldBlock,
                "token repair already in progress in another process; \
                 a restart will adopt its token",
            ));
        }
        Err(e) => return Err(e),
    }

    let moved = std::fs::read_to_string(&claimed)
        .map(|raw| raw.trim().to_string())
        .unwrap_or_default();
    let token = if moved.is_empty() {
        candidate.to_string()
    } else {
        moved
    };

    let result = match save_token_at(token_path, &token) {
        Ok(()) => Ok(token),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            // A concurrent creator (ordinary missing-file path) won the
            // create_new race; adopt what it persisted.
            let raw = std::fs::read_to_string(token_path)?;
            let existing = raw.trim();
            if existing.is_empty() {
                Err(e)
            } else {
                Ok(existing.to_string())
            }
        }
        Err(e) => Err(e),
    };
    // Best-effort: the claimed file is a zero-byte husk (or a token we just
    // restored); removing it keeps repeated repair attempts from accumulating
    // husks under the very disk pressure this path exists to survive.
    let _ = std::fs::remove_file(&claimed);
    result
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

    /// Regression: a zero-byte token file (crash / full disk between
    /// `create_new` and `write_all`) must be repaired on the next startup,
    /// not wedge every startup with `AlreadyExists` until manual deletion.
    #[cfg(unix)]
    #[test]
    fn empty_token_file_is_repaired_on_next_startup() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("rpc_token");
        std::fs::write(&path, "\n").unwrap(); // whitespace-only == no token

        let token = get_or_create_token_at(&path).expect("startup must recover");
        assert_eq!(token.len(), 64);
        assert!(token.chars().all(|c| c.is_ascii_hexdigit()));
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            format!("{token}\n"),
            "repaired file holds the returned token"
        );
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "repaired file must stay owner-only");

        // A second startup reuses the repaired token instead of rotating it.
        assert_eq!(get_or_create_token_at(&path).unwrap(), token);

        // No claim husks left behind by the repair.
        let leftovers: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name() != "rpc_token")
            .collect();
        assert!(leftovers.is_empty(), "unexpected leftovers: {leftovers:?}");
    }

    /// The post-claim recheck: when the repair races a process that already
    /// persisted a token, the moved-aside token must be RESTORED, not
    /// rotated — the winner keeps serving with a token that matches the file.
    #[test]
    fn repair_restores_a_token_persisted_by_a_racing_process() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("rpc_token");
        // Simulates the race: by the time our claim lands, the file the
        // caller observed as empty has been repaired and holds a live token.
        std::fs::write(&path, "cafebabe\n").unwrap();

        let adopted = repair_empty_token_at(&path, "would-be-rotation").unwrap();
        assert_eq!(adopted, "cafebabe");
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "cafebabe\n");
    }

    /// A claim-race loser (the token file is simply gone) must fail closed
    /// with a retriable error, mirroring the pre-existing semantics of losing
    /// the `create_new` race — never wedge, never rotate.
    #[test]
    fn repair_claim_loser_fails_closed_when_no_token_is_persisted_yet() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("rpc_token");
        // No file at all: the claiming winner has moved it and not yet
        // persisted its replacement.
        let err = repair_empty_token_at(&path, "candidate").unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::WouldBlock);
    }

    /// The repair path must never fire for a file that DOES hold a token:
    /// an existing valid token is returned as-is, byte-for-byte.
    #[test]
    fn valid_token_file_is_returned_untouched() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("rpc_token");
        std::fs::write(&path, "deadbeef\n").unwrap();

        assert_eq!(get_or_create_token_at(&path).unwrap(), "deadbeef");
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
