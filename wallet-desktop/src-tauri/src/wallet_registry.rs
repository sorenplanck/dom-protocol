//! Desktop glue for the reused `dom_wallet::registry`.
//!
//! The registry itself (the `name → vault location` map, its load/save/resolve
//! logic and security invariants) lives in `dom-wallet` and is REUSED here — no
//! registry logic is reimplemented. This module only answers one app-specific
//! question: *where does `registry.json` live on this OS?*
//!
//! ## Location
//!
//! - **Windows:** `%APPDATA%\DOM Wallet\registry.json`
//!   (`%APPDATA%` is `AppData\Roaming`, so this is
//!   `AppData\Roaming\DOM Wallet\registry.json`).
//! - **macOS:** `~/Library/Application Support/DOM Wallet/registry.json`.
//! - **Linux/other:** `$XDG_CONFIG_HOME/DOM Wallet/registry.json`, or
//!   `~/.config/DOM Wallet/registry.json` when `XDG_CONFIG_HOME` is unset.
//!
//! The registry holds only non-sensitive metadata (see `dom_wallet::registry`);
//! it is NOT a secret store. If it is deleted the user can still locate or
//! restore their wallet — the recovery phrase is the real backup.

use std::path::PathBuf;

use anyhow::{anyhow, Result};

/// Product directory name. Matches `productName` in `tauri.conf.json`.
pub const APP_CONFIG_DIR_NAME: &str = "DOM Wallet";
/// Registry file name inside the app config directory.
pub const REGISTRY_FILE_NAME: &str = "registry.json";

/// Absolute path of the wallet registry for this OS user.
pub fn default_registry_path() -> Result<PathBuf> {
    Ok(app_config_dir()?.join(REGISTRY_FILE_NAME))
}

/// Per-OS application config directory (`<base>/DOM Wallet`).
fn app_config_dir() -> Result<PathBuf> {
    Ok(config_base()?.join(APP_CONFIG_DIR_NAME))
}

#[cfg(windows)]
fn config_base() -> Result<PathBuf> {
    std::env::var_os("APPDATA")
        .map(PathBuf::from)
        .filter(|p| !p.as_os_str().is_empty())
        .ok_or_else(|| anyhow!("APPDATA environment variable is not set"))
}

#[cfg(target_os = "macos")]
fn config_base() -> Result<PathBuf> {
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .filter(|p| !p.as_os_str().is_empty())
        .ok_or_else(|| anyhow!("HOME environment variable is not set"))?;
    Ok(home.join("Library").join("Application Support"))
}

#[cfg(all(unix, not(target_os = "macos")))]
fn config_base() -> Result<PathBuf> {
    if let Some(xdg) = std::env::var_os("XDG_CONFIG_HOME") {
        let p = PathBuf::from(xdg);
        if !p.as_os_str().is_empty() {
            return Ok(p);
        }
    }
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .filter(|p| !p.as_os_str().is_empty())
        .ok_or_else(|| anyhow!("HOME environment variable is not set"))?;
    Ok(home.join(".config"))
}
