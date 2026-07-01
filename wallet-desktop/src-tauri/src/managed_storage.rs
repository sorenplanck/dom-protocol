//! App-managed wallet + node storage layout.
//!
//! Product rule: the user only ever supplies a wallet NAME, a password and the
//! mining toggle. The app decides where everything lives:
//!
//! ```text
//! <base>/                          ("DOM Wallet Data" next to a portable app,
//!   wallets/                        else the per-user application data dir)
//!     <wallet-slug>/
//!       wallet.dom                 encrypted wallet vault (dom_wallet2 file)
//!       node/
//!         node-settings.json       per-wallet NodeSettings (ports, mining, …)
//!         …                        chain/p2p data created by the embedded node
//! ```
//!
//! Every path is derived from a sanitized slug and is verified to stay inside
//! the managed base directory — the renderer never supplies a filesystem path
//! for this flow, and traversal characters are rejected before any I/O.

use std::net::TcpListener;
use std::path::{Component, Path, PathBuf};

use anyhow::{anyhow, Context as _, Result};

use crate::settings::{NetworkKind, NodeSettings};

/// Name of the managed data folder placed next to a portable executable.
pub const PORTABLE_DATA_DIR_NAME: &str = "DOM Wallet Data";
/// Per-user fallback directory name (Windows/macOS conventions).
#[cfg_attr(all(unix, not(target_os = "macos")), allow(dead_code))]
pub const APP_DATA_DIR_NAME: &str = "DOM Wallet";
/// Per-user fallback directory name on Linux (XDG convention).
pub const APP_DATA_DIR_NAME_XDG: &str = "dom-wallet";
/// Vault file name inside each wallet directory (a single dom-wallet2 file).
pub const WALLET_VAULT_NAME: &str = "wallet.dom";
/// Node directory name inside each wallet directory.
pub const NODE_DIR_NAME: &str = "node";
/// Per-wallet node settings file inside the node directory.
pub const NODE_SETTINGS_FILE: &str = "node-settings.json";

/// Longest accepted wallet slug. Keeps paths well under platform limits even
/// when nested inside deep user profile directories.
const MAX_SLUG_LEN: usize = 64;

/// Windows reserved device names — invalid as file/directory stems on Windows
/// regardless of extension, so they are rejected on every platform to keep
/// wallet folders portable across OSes.
const WINDOWS_RESERVED: &[&str] = &[
    "con", "prn", "aux", "nul", "com1", "com2", "com3", "com4", "com5", "com6", "com7", "com8",
    "com9", "lpt1", "lpt2", "lpt3", "lpt4", "lpt5", "lpt6", "lpt7", "lpt8", "lpt9",
];

/// Resolved locations for one managed wallet. All paths are guaranteed to be
/// inside the managed base directory.
#[derive(Clone, Debug)]
pub struct ManagedLayout {
    /// Name as the user typed it (trimmed). Shown in the UI / registry.
    pub display_name: String,
    /// Filesystem-safe directory name derived from `display_name`.
    pub slug: String,
    /// `<base>/wallets/<slug>`
    pub wallet_dir: PathBuf,
    /// `<base>/wallets/<slug>/wallet.dom` — the encrypted vault directory.
    pub vault_path: PathBuf,
    /// `<base>/wallets/<slug>/node` — the embedded node's data dir.
    pub node_dir: PathBuf,
    /// `<base>/wallets/<slug>/node/node-settings.json`
    pub node_config_path: PathBuf,
}

// ── Base directory resolution ─────────────────────────────────────────────────

/// The managed application data base directory.
///
/// Portable-first, per product spec: when the directory containing the
/// executable is writable (portable unzip, dev build), wallets live in a
/// `DOM Wallet Data` folder next to the app. When it is not writable (installed
/// under Program Files / /Applications / /usr), the per-user application data
/// directory is used instead. The user never chooses this.
pub fn resolve_app_data_base_dir() -> Result<PathBuf> {
    if let Some(dir) = portable_base_dir() {
        return Ok(dir);
    }
    user_data_base_dir()
}

/// `<exe dir>/DOM Wallet Data` when the exe dir is writable, else None.
fn portable_base_dir() -> Option<PathBuf> {
    let exe_dir = std::env::current_exe().ok()?.parent()?.to_path_buf();
    let candidate = exe_dir.join(PORTABLE_DATA_DIR_NAME);
    if dir_is_writable(&candidate) {
        Some(candidate)
    } else {
        None
    }
}

/// Probe whether `candidate` exists-or-can-be-created and is writable, by
/// creating it and writing/removing a probe file. Never panics; any failure
/// means "not writable".
fn dir_is_writable(candidate: &Path) -> bool {
    if std::fs::create_dir_all(candidate).is_err() {
        return false;
    }
    let probe = candidate.join(".dom-write-probe");
    match std::fs::write(&probe, b"probe") {
        Ok(()) => {
            let _ = std::fs::remove_file(&probe);
            true
        }
        Err(_) => false,
    }
}

/// Per-user application data directory:
/// Windows `%APPDATA%\DOM Wallet`, macOS `~/Library/Application Support/DOM
/// Wallet`, Linux `$XDG_DATA_HOME/dom-wallet` (or `~/.local/share/dom-wallet`).
fn user_data_base_dir() -> Result<PathBuf> {
    #[cfg(windows)]
    {
        std::env::var_os("APPDATA")
            .map(PathBuf::from)
            .filter(|p| !p.as_os_str().is_empty())
            .map(|p| p.join(APP_DATA_DIR_NAME))
            .ok_or_else(|| anyhow!("APPDATA environment variable is not set"))
    }
    #[cfg(target_os = "macos")]
    {
        std::env::var_os("HOME")
            .map(PathBuf::from)
            .filter(|p| !p.as_os_str().is_empty())
            .map(|h| {
                h.join("Library")
                    .join("Application Support")
                    .join(APP_DATA_DIR_NAME)
            })
            .ok_or_else(|| anyhow!("HOME environment variable is not set"))
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        if let Some(xdg) = std::env::var_os("XDG_DATA_HOME") {
            let p = PathBuf::from(xdg);
            if !p.as_os_str().is_empty() {
                return Ok(p.join(APP_DATA_DIR_NAME_XDG));
            }
        }
        std::env::var_os("HOME")
            .map(PathBuf::from)
            .filter(|p| !p.as_os_str().is_empty())
            .map(|h| h.join(".local").join("share").join(APP_DATA_DIR_NAME_XDG))
            .ok_or_else(|| anyhow!("HOME environment variable is not set"))
    }
    #[cfg(not(any(unix, windows)))]
    {
        Err(anyhow!("unsupported platform for managed wallet storage"))
    }
}

/// `<base>/wallets`
pub fn resolve_wallets_base_dir() -> Result<PathBuf> {
    Ok(resolve_app_data_base_dir()?.join("wallets"))
}

/// `wallets` dir under an explicit base (test seam — all path logic below is
/// parameterized on the base so tests never touch the real user profile).
pub fn wallets_base_dir_in(base: &Path) -> PathBuf {
    base.join("wallets")
}

// ── Name sanitization ─────────────────────────────────────────────────────────

/// Turn a user-supplied wallet name into a filesystem-safe directory slug.
///
/// Rules:
///   * the display name may keep spaces/case; the slug is lowercase;
///   * spaces become `-`; only `[a-z0-9._-]` survive, everything else is
///     dropped;
///   * traversal is impossible by construction (`/`, `\` and `..` can never
///     appear in the output) and explicitly rejected on the input;
///   * empty results, `.`/`..`, Windows-reserved device names, and names
///     longer than [`MAX_SLUG_LEN`] are rejected;
///   * leading/trailing dots and hyphens are trimmed (Windows forbids
///     trailing dots/spaces).
pub fn sanitize_wallet_name(wallet_name: &str) -> Result<String> {
    let trimmed = wallet_name.trim();
    if trimmed.is_empty() {
        return Err(anyhow!("wallet name must not be empty"));
    }
    // Reject obviously hostile input outright instead of silently fixing it,
    // so the UI can tell the user the name is invalid.
    if trimmed.contains('/') || trimmed.contains('\\') || trimmed.contains("..") {
        return Err(anyhow!(
            "wallet name must not contain path separators or \"..\""
        ));
    }
    if trimmed.chars().any(|c| c.is_control()) {
        return Err(anyhow!("wallet name must not contain control characters"));
    }

    let mut slug = String::with_capacity(trimmed.len());
    for c in trimmed.chars() {
        match c {
            ' ' => slug.push('-'),
            c if c.is_ascii_alphanumeric() => slug.push(c.to_ascii_lowercase()),
            '-' | '_' | '.' => slug.push(c),
            // Unicode letters/digits: keep a normalized ASCII-safe subset by
            // dropping them; the display name preserves the original.
            _ => {}
        }
    }
    // Collapse runs of '-' produced by consecutive spaces/dropped chars.
    while slug.contains("--") {
        slug = slug.replace("--", "-");
    }
    let slug = slug.trim_matches(|c| c == '-' || c == '.').to_string();

    if slug.is_empty() {
        return Err(anyhow!(
            "wallet name must contain at least one letter or digit"
        ));
    }
    if slug.len() > MAX_SLUG_LEN {
        return Err(anyhow!("wallet name is too long (max {MAX_SLUG_LEN})"));
    }
    let stem = slug.split('.').next().unwrap_or(&slug);
    if WINDOWS_RESERVED.contains(&stem) {
        return Err(anyhow!("wallet name {trimmed:?} is reserved on Windows"));
    }
    Ok(slug)
}

// ── Per-wallet path resolution ────────────────────────────────────────────────

/// Assert that `path` is `base` itself or a descendant of it. The slug rules
/// already make escapes impossible; this is defense-in-depth before any I/O.
fn ensure_contained(base: &Path, path: &Path) -> Result<()> {
    if !path.starts_with(base) {
        return Err(anyhow!(
            "internal error: resolved path escapes the managed directory"
        ));
    }
    // The joined path must not contain ".." / root components after the base.
    let tail = path.strip_prefix(base).expect("starts_with checked above");
    if tail
        .components()
        .any(|c| !matches!(c, Component::Normal(_)))
    {
        return Err(anyhow!(
            "internal error: resolved path contains non-normal components"
        ));
    }
    Ok(())
}

fn wallet_dir_in(base: &Path, slug: &str) -> Result<PathBuf> {
    let dir = wallets_base_dir_in(base).join(slug);
    ensure_contained(base, &dir)?;
    Ok(dir)
}

/// `<base>/wallets/<slug>` for a user-typed name (sanitizes first).
///
/// Part of the stable managed-storage helper API; commands that already hold a
/// [`ManagedLayout`] use its fields instead of re-resolving.
#[allow(dead_code)]
pub fn resolve_wallet_dir(wallet_name: &str) -> Result<PathBuf> {
    let base = resolve_app_data_base_dir()?;
    wallet_dir_in(&base, &sanitize_wallet_name(wallet_name)?)
}

/// `<base>/wallets/<slug>/wallet.dom` for a user-typed name.
///
/// Part of the stable managed-storage helper API; commands that already hold a
/// [`ManagedLayout`] use its fields instead of re-resolving.
#[allow(dead_code)]
pub fn resolve_wallet_file_path(wallet_name: &str) -> Result<PathBuf> {
    Ok(resolve_wallet_dir(wallet_name)?.join(WALLET_VAULT_NAME))
}

/// `<base>/wallets/<slug>/node` for a user-typed name.
///
/// Part of the stable managed-storage helper API (see
/// [`resolve_wallet_file_path`]).
#[allow(dead_code)]
pub fn resolve_node_dir(wallet_name: &str) -> Result<PathBuf> {
    Ok(resolve_wallet_dir(wallet_name)?.join(NODE_DIR_NAME))
}

/// `<base>/wallets/<slug>/node/node-settings.json` for a user-typed name.
///
/// Part of the stable managed-storage helper API (see
/// [`resolve_wallet_file_path`]).
#[allow(dead_code)]
pub fn resolve_node_config_path(wallet_name: &str) -> Result<PathBuf> {
    Ok(resolve_node_dir(wallet_name)?.join(NODE_SETTINGS_FILE))
}

/// Build the [`ManagedLayout`] for `wallet_name` under an explicit base.
pub fn layout_in(base: &Path, wallet_name: &str) -> Result<ManagedLayout> {
    let display_name = wallet_name.trim().to_string();
    let slug = sanitize_wallet_name(wallet_name)?;
    let wallet_dir = wallet_dir_in(base, &slug)?;
    let node_dir = wallet_dir.join(NODE_DIR_NAME);
    ensure_contained(base, &node_dir)?;
    Ok(ManagedLayout {
        display_name,
        slug,
        vault_path: wallet_dir.join(WALLET_VAULT_NAME),
        node_config_path: node_dir.join(NODE_SETTINGS_FILE),
        wallet_dir,
        node_dir,
    })
}

// ── Port allocation ───────────────────────────────────────────────────────────

/// First port trio tried for a new wallet's node (p2p / metrics / rpc).
const PORT_TRIO_BASE: u16 = 33370;
/// Spacing between candidate trios; leaves room for the three services plus
/// headroom for future per-wallet listeners.
const PORT_TRIO_STEP: u16 = 10;
/// How many trios to probe before giving up.
const PORT_TRIO_ATTEMPTS: u16 = 200;

fn port_is_free_on(host: &str, port: u16) -> bool {
    TcpListener::bind((host, port)).is_ok()
}

/// Allocate a (p2p, metrics, rpc) port trio that is free right now AND not
/// persisted in any other managed wallet's node settings, so two wallets
/// created on the same machine can run their nodes simultaneously later.
pub fn allocate_node_ports(base: &Path) -> Result<(u16, u16, u16)> {
    let reserved = ports_reserved_by_other_wallets(base);
    for attempt in 0..PORT_TRIO_ATTEMPTS {
        let p2p = PORT_TRIO_BASE.saturating_add(attempt.saturating_mul(PORT_TRIO_STEP));
        let metrics = p2p + 1;
        let rpc = p2p + 2;
        if [p2p, metrics, rpc].iter().any(|p| reserved.contains(p)) {
            continue;
        }
        if port_is_free_on("0.0.0.0", p2p)
            && port_is_free_on("127.0.0.1", metrics)
            && port_is_free_on("127.0.0.1", rpc)
        {
            return Ok((p2p, metrics, rpc));
        }
    }
    Err(anyhow!(
        "could not find free local ports for the wallet node; close other applications using ports {PORT_TRIO_BASE}+ and try again"
    ))
}

/// Ports already claimed by sibling wallets' persisted node settings.
fn ports_reserved_by_other_wallets(base: &Path) -> Vec<u16> {
    let mut used = Vec::new();
    let wallets = wallets_base_dir_in(base);
    let Ok(entries) = std::fs::read_dir(&wallets) else {
        return used;
    };
    for entry in entries.flatten() {
        let cfg = entry.path().join(NODE_DIR_NAME).join(NODE_SETTINGS_FILE);
        let Ok(bytes) = std::fs::read(&cfg) else {
            continue;
        };
        let Ok(settings) = serde_json::from_slice::<NodeSettings>(&bytes) else {
            continue;
        };
        for addr in [
            Some(settings.p2p_listen_addr.as_str()),
            Some(settings.rpc_listen_addr.as_str()),
            settings.metrics_listen_addr.as_deref(),
        ]
        .into_iter()
        .flatten()
        {
            if let Some(port) = addr.rsplit(':').next().and_then(|p| p.parse().ok()) {
                used.push(port);
            }
        }
    }
    used
}

// ── Layout creation / loading ─────────────────────────────────────────────────

/// Default per-wallet [`NodeSettings`] for a freshly created wallet.
fn default_node_settings_for(
    layout: &ManagedLayout,
    network: NetworkKind,
    mine: bool,
) -> NodeSettings {
    NodeSettings {
        network,
        data_dir: layout.node_dir.to_string_lossy().into_owned(),
        mine,
        // Mining rewards go to the app-managed miner wallet inside the node
        // dir; no manual path. `NodeSettings::miner_wallet_credentials`
        // derives `<data_dir>/miner-wallet.dom` when this is None.
        miner_wallet_path: None,
        ..NodeSettings::default()
    }
}

/// Create the on-disk layout for a NEW wallet: wallet dir, node dir, and the
/// persisted per-wallet node settings (with conflict-free ports). Fails if a
/// wallet with the same (sanitized) name already exists — never overwrites.
pub fn create_wallet_and_node_layout(
    base: &Path,
    wallet_name: &str,
    network: NetworkKind,
    mine: bool,
) -> Result<(ManagedLayout, NodeSettings)> {
    let layout = layout_in(base, wallet_name)?;
    if layout.wallet_dir.exists() {
        return Err(anyhow!(
            "a wallet named {:?} already exists — choose another name",
            layout.display_name
        ));
    }
    std::fs::create_dir_all(&layout.node_dir).with_context(|| {
        format!(
            "could not create wallet directory {}",
            layout.wallet_dir.display()
        )
    })?;

    let mut settings = default_node_settings_for(&layout, network, mine);
    let (p2p, metrics, rpc) = allocate_node_ports(base)?;
    settings.p2p_listen_addr = format!("0.0.0.0:{p2p}");
    settings.metrics_listen_addr = Some(format!("127.0.0.1:{metrics}"));
    settings.rpc_listen_addr = format!("127.0.0.1:{rpc}");

    save_node_settings(&layout, &settings)?;
    Ok((layout, settings))
}

/// Load the layout + persisted node settings for an EXISTING managed wallet.
///
/// If the wallet predates managed node configs (or the file was deleted), a
/// fresh per-wallet node config is created so opening by name always yields a
/// runnable node. The wallet vault itself must exist.
pub fn load_wallet_node_layout(
    base: &Path,
    wallet_name: &str,
) -> Result<(ManagedLayout, NodeSettings)> {
    let layout = layout_in(base, wallet_name)?;
    // The v2 vault is a single encrypted FILE (v1 was a directory).
    if !layout.vault_path.is_file() {
        return Err(anyhow!(
            "no managed wallet named {:?} was found",
            layout.display_name
        ));
    }
    let settings = match std::fs::read(&layout.node_config_path) {
        Ok(bytes) => serde_json::from_slice::<NodeSettings>(&bytes).with_context(|| {
            format!(
                "corrupt node settings at {}",
                layout.node_config_path.display()
            )
        })?,
        Err(_) => {
            // Missing node config (legacy wallet or deleted file): create one.
            std::fs::create_dir_all(&layout.node_dir)?;
            let mut settings = default_node_settings_for(&layout, NetworkKind::Testnet, false);
            let (p2p, metrics, rpc) = allocate_node_ports(base)?;
            settings.p2p_listen_addr = format!("0.0.0.0:{p2p}");
            settings.metrics_listen_addr = Some(format!("127.0.0.1:{metrics}"));
            settings.rpc_listen_addr = format!("127.0.0.1:{rpc}");
            save_node_settings(&layout, &settings)?;
            settings
        }
    };
    Ok((layout, settings))
}

/// Persist per-wallet node settings (pretty JSON, atomic-ish via temp+rename).
/// The file contains NO secrets: `NodeSettings` has no password field, and the
/// miner wallet key lives in its own permission-restricted file.
pub fn save_node_settings(layout: &ManagedLayout, settings: &NodeSettings) -> Result<()> {
    std::fs::create_dir_all(&layout.node_dir)?;
    let json = serde_json::to_vec_pretty(settings).context("serialize node settings")?;
    let tmp = layout.node_config_path.with_extension("json.tmp");
    std::fs::write(&tmp, &json)
        .with_context(|| format!("write node settings {}", tmp.display()))?;
    std::fs::rename(&tmp, &layout.node_config_path).with_context(|| {
        format!(
            "persist node settings {}",
            layout.node_config_path.display()
        )
    })?;
    Ok(())
}

/// Whether a managed wallet with this (sanitized) name already exists.
pub fn managed_wallet_exists(base: &Path, wallet_name: &str) -> bool {
    match layout_in(base, wallet_name) {
        Ok(layout) => layout.wallet_dir.exists(),
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    // ── auto-backup config persistence (ETAPA 4) ──────────────────────────────

    /// The two auto-backup fields persist through the real writer
    /// (`save_node_settings`) and reload via the same serde path the app uses.
    #[test]
    fn auto_backup_config_persists_in_node_settings() {
        let base = tempdir().unwrap();
        let layout = layout_in(base.path(), "my-wallet").unwrap();

        let settings = NodeSettings {
            auto_backup_enabled: true,
            auto_backup_external_path: Some("/media/usb/backups".to_string()),
            ..NodeSettings::default()
        };
        save_node_settings(&layout, &settings).unwrap();

        // Reload exactly as `load_wallet_node_layout` does (serde over the file).
        let bytes = std::fs::read(&layout.node_config_path).unwrap();
        let reloaded: NodeSettings = serde_json::from_slice(&bytes).unwrap();
        assert!(reloaded.auto_backup_enabled);
        assert_eq!(
            reloaded.auto_backup_external_path.as_deref(),
            Some("/media/usb/backups")
        );

        // The config file carries NO secret (it never should).
        let text = String::from_utf8(bytes).unwrap();
        assert!(!text.to_lowercase().contains("password"));
        assert!(!text.to_lowercase().contains("passphrase"));
    }

    /// A legacy node-settings.json without the new fields still loads (serde
    /// defaults), so existing wallets keep working.
    #[test]
    fn legacy_node_settings_without_auto_backup_fields_defaults() {
        let json = r#"{
            "network": "testnet",
            "seed_peers": [],
            "p2p_listen_addr": "0.0.0.0:33370",
            "rpc_listen_addr": "127.0.0.1:33372",
            "data_dir": "/tmp/x",
            "miner_wallet_path": null,
            "mine": false,
            "metrics_listen_addr": null,
            "log_level": "info"
        }"#;
        let s: NodeSettings = serde_json::from_str(json).unwrap();
        assert!(!s.auto_backup_enabled, "defaults to off");
        assert_eq!(s.auto_backup_external_path, None);
    }

    // ── sanitize_wallet_name ──────────────────────────────────────────────────

    #[test]
    fn sanitize_accepts_normal_names() {
        assert_eq!(sanitize_wallet_name("Carteira 1").unwrap(), "carteira-1");
        assert_eq!(sanitize_wallet_name("  My Wallet  ").unwrap(), "my-wallet");
        assert_eq!(
            sanitize_wallet_name("savings_2024").unwrap(),
            "savings_2024"
        );
    }

    #[test]
    fn sanitize_rejects_empty_and_symbol_only_names() {
        assert!(sanitize_wallet_name("").is_err());
        assert!(sanitize_wallet_name("   ").is_err());
        assert!(sanitize_wallet_name("***").is_err());
        assert!(sanitize_wallet_name("---").is_err());
    }

    #[test]
    fn sanitize_rejects_path_traversal() {
        for bad in [
            "../evil",
            "..",
            "a/../b",
            "/etc/passwd",
            "C:\\Windows",
            "..\\up",
            "a/b",
            "nested\\name",
        ] {
            assert!(
                sanitize_wallet_name(bad).is_err(),
                "{bad:?} must be rejected"
            );
        }
    }

    #[test]
    fn sanitize_rejects_windows_reserved_and_control_chars() {
        for bad in ["CON", "con", "Nul", "com1", "LPT9", "con.wallet"] {
            assert!(
                sanitize_wallet_name(bad).is_err(),
                "{bad:?} must be rejected"
            );
        }
        assert!(sanitize_wallet_name("na\u{0}me").is_err());
        assert!(sanitize_wallet_name("na\nme").is_err());
        // Leading/trailing whitespace (including newlines) is trimmed, not fatal.
        assert_eq!(sanitize_wallet_name("name\n").unwrap(), "name");
    }

    #[test]
    fn sanitize_strips_os_invalid_characters() {
        // Windows-invalid characters are dropped, not kept.
        assert_eq!(
            sanitize_wallet_name("a<b>c:d\"e|f?g*h").unwrap(),
            "abcdefgh"
        );
        // Trailing dots are trimmed (Windows refuses them).
        assert_eq!(sanitize_wallet_name("name.").unwrap(), "name");
    }

    // ── path containment ──────────────────────────────────────────────────────

    #[test]
    fn wallet_paths_stay_inside_base_dir() {
        let base = tempdir().unwrap();
        let layout = layout_in(base.path(), "Carteira 1").unwrap();
        for p in [
            &layout.wallet_dir,
            &layout.vault_path,
            &layout.node_dir,
            &layout.node_config_path,
        ] {
            assert!(
                p.starts_with(base.path()),
                "{} must stay under the managed base",
                p.display()
            );
        }
        assert!(layout.node_dir.starts_with(&layout.wallet_dir));
        assert!(layout.vault_path.starts_with(&layout.wallet_dir));
    }

    #[test]
    fn hostile_names_cannot_escape_base_dir() {
        let base = tempdir().unwrap();
        for bad in ["../escape", "..", "x/../../y", "\\..\\up"] {
            assert!(
                layout_in(base.path(), bad).is_err(),
                "{bad:?} must not resolve to a layout"
            );
        }
    }

    // ── create / load ─────────────────────────────────────────────────────────

    #[test]
    fn create_layout_creates_dirs_and_node_config() {
        let base = tempdir().unwrap();
        let (layout, settings) =
            create_wallet_and_node_layout(base.path(), "Carteira 1", NetworkKind::Regtest, false)
                .unwrap();

        assert!(layout.wallet_dir.is_dir());
        assert!(layout.node_dir.is_dir());
        assert!(layout.node_config_path.is_file());
        assert_eq!(settings.data_dir, layout.node_dir.to_string_lossy());
        assert!(!settings.mine);
        // The vault itself is created by WalletDir::create_from_seed later.
        assert!(!layout.vault_path.exists());
    }

    #[test]
    fn create_layout_rejects_duplicate_names() {
        let base = tempdir().unwrap();
        create_wallet_and_node_layout(base.path(), "Carteira 1", NetworkKind::Regtest, false)
            .unwrap();
        // Same name, different case/spacing → same slug → rejected.
        let err = create_wallet_and_node_layout(
            base.path(),
            "  carteira 1 ",
            NetworkKind::Regtest,
            false,
        )
        .unwrap_err();
        assert!(err.to_string().contains("already exists"), "{err}");
    }

    #[test]
    fn node_config_listens_on_loopback_for_rpc_and_metrics() {
        let base = tempdir().unwrap();
        let (_, settings) =
            create_wallet_and_node_layout(base.path(), "Loopback", NetworkKind::Regtest, false)
                .unwrap();
        assert!(settings.rpc_listen_addr.starts_with("127.0.0.1:"));
        assert!(settings
            .metrics_listen_addr
            .as_deref()
            .unwrap()
            .starts_with("127.0.0.1:"));
    }

    #[test]
    fn sibling_wallets_get_distinct_ports() {
        let base = tempdir().unwrap();
        let (_, a) =
            create_wallet_and_node_layout(base.path(), "A", NetworkKind::Regtest, false).unwrap();
        let (_, b) =
            create_wallet_and_node_layout(base.path(), "B", NetworkKind::Regtest, false).unwrap();
        assert_ne!(a.p2p_listen_addr, b.p2p_listen_addr);
        assert_ne!(a.rpc_listen_addr, b.rpc_listen_addr);
        assert_ne!(a.metrics_listen_addr, b.metrics_listen_addr);
    }

    #[test]
    fn allocate_ports_skips_ports_held_by_running_listeners() {
        let base = tempdir().unwrap();
        // Hold the first candidate p2p port on all interfaces.
        let _holder = TcpListener::bind(("0.0.0.0", PORT_TRIO_BASE));
        let (p2p, metrics, rpc) = allocate_node_ports(base.path()).unwrap();
        if _holder.is_ok() {
            assert_ne!(
                p2p, PORT_TRIO_BASE,
                "allocated trio must skip the held port"
            );
        }
        assert!(port_is_free_on("127.0.0.1", metrics));
        assert!(port_is_free_on("127.0.0.1", rpc));
        assert_ne!(p2p, metrics);
        assert_ne!(metrics, rpc);
    }

    #[test]
    fn load_layout_roundtrips_persisted_settings() {
        let base = tempdir().unwrap();
        let (layout, created) =
            create_wallet_and_node_layout(base.path(), "Round Trip", NetworkKind::Regtest, true)
                .unwrap();
        // Simulate the vault the wallet creation step would add (a v2 file).
        std::fs::write(&layout.vault_path, b"vault").unwrap();

        let (loaded_layout, loaded) = load_wallet_node_layout(base.path(), "round trip").unwrap();
        assert_eq!(loaded_layout.slug, layout.slug);
        assert_eq!(loaded.p2p_listen_addr, created.p2p_listen_addr);
        assert_eq!(loaded.rpc_listen_addr, created.rpc_listen_addr);
        assert!(loaded.mine, "persisted mining choice must be respected");
    }

    #[test]
    fn load_layout_creates_missing_node_config_for_legacy_wallets() {
        let base = tempdir().unwrap();
        let layout = layout_in(base.path(), "Legacy").unwrap();
        // A wallet vault exists (v2 file) but no node config (legacy import).
        std::fs::create_dir_all(&layout.wallet_dir).unwrap();
        std::fs::write(&layout.vault_path, b"vault").unwrap();

        let (_, settings) = load_wallet_node_layout(base.path(), "Legacy").unwrap();
        assert!(layout.node_config_path.is_file());
        assert!(!settings.mine, "legacy wallets must not auto-enable mining");
        assert!(settings.rpc_listen_addr.starts_with("127.0.0.1:"));
    }

    #[test]
    fn load_layout_fails_for_unknown_wallet() {
        let base = tempdir().unwrap();
        let err = load_wallet_node_layout(base.path(), "Ghost").unwrap_err();
        assert!(err.to_string().contains("no managed wallet"), "{err}");
    }

    #[test]
    fn managed_wallet_exists_matches_slug_collisions() {
        let base = tempdir().unwrap();
        assert!(!managed_wallet_exists(base.path(), "Carteira 1"));
        create_wallet_and_node_layout(base.path(), "Carteira 1", NetworkKind::Regtest, false)
            .unwrap();
        assert!(managed_wallet_exists(base.path(), "Carteira 1"));
        assert!(managed_wallet_exists(base.path(), "CARTEIRA   1"));
        assert!(!managed_wallet_exists(base.path(), "Carteira 2"));
        assert!(!managed_wallet_exists(base.path(), "../Carteira 1"));
    }

    #[test]
    fn node_settings_file_contains_no_password_material() {
        let base = tempdir().unwrap();
        let (layout, _) =
            create_wallet_and_node_layout(base.path(), "NoSecrets", NetworkKind::Regtest, true)
                .unwrap();
        let raw = std::fs::read_to_string(&layout.node_config_path).unwrap();
        let lowered = raw.to_lowercase();
        assert!(!lowered.contains("password"));
        assert!(!lowered.contains("seed_phrase"));
        assert!(!lowered.contains("mnemonic"));
    }
}
