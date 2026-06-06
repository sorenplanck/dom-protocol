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

/// Save token to ~/.dom/rpc_token with 0600 permissions.
fn save_token(token: &str) -> Result<(), std::io::Error> {
    let token_path = token_file_path()?;
    let dom_dir = token_path
        .parent()
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "Invalid token path"))?;

    // Create ~/.dom if it doesn't exist
    std::fs::create_dir_all(dom_dir)?;

    // Write token
    std::fs::write(&token_path, format!("{}\n", token))?;

    // Set permissions to 0600 (owner read/write only)
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&token_path)?.permissions();
        perms.set_mode(0o600);
        std::fs::set_permissions(&token_path, perms)?;
    }

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
}
