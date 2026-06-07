//! Application-level error type.
//!
//! `AppError` is the single error type returned by every Tauri command. It is
//! `serde::Serialize` so the frontend receives a clean, human-readable message
//! (per the brief's ERROR HANDLING rules) — never a Rust `Debug` dump, a stack
//! trace, or a secret. Full technical detail is logged to the Node tab via
//! `tracing`; the UI only ever sees `.user_message()`.

use serde::Serialize;

/// Errors surfaced to the UI. Each variant maps to a calm, actionable message.
#[derive(Debug, thiserror::Error)]
pub enum AppError {
    /// No wallet is currently open / unlocked.
    #[error("no wallet is open")]
    NoWalletOpen,

    /// The wallet is locked; the user must re-enter their password.
    #[error("wallet is locked")]
    WalletLocked,

    /// Password incorrect (create/unlock/verify paths).
    #[error("incorrect password")]
    BadPassword,

    /// Password did not meet the strength policy.
    #[error("weak password: {0}")]
    WeakPassword(String),

    /// The embedded node is not running.
    #[error("node is not running")]
    NodeNotRunning,

    /// The embedded node is already running.
    #[error("node is already running")]
    NodeAlreadyRunning,

    /// A feature that is intentionally deferred to V2 was invoked.
    #[error("not available in V1")]
    NotInV1,

    /// Wallet-crate error (already redacted: dom-wallet never puts secrets in
    /// its error strings).
    #[error("wallet error: {0}")]
    Wallet(String),

    /// Local node RPC failure.
    #[error("node RPC error: {0}")]
    Rpc(String),

    /// Filesystem / IO failure (backups, exports, config).
    #[error("filesystem error: {0}")]
    Io(String),

    /// Configuration / settings problem.
    #[error("configuration error: {0}")]
    Config(String),

    /// Update-check / GitHub Releases failure.
    #[error("update check failed: {0}")]
    Update(String),

    /// Catch-all for orchestration glue (anyhow). The inner string is already
    /// human-facing by construction (we never wrap secrets in anyhow).
    #[error("{0}")]
    Other(String),
}

impl AppError {
    /// The calm, user-facing message shown in the UI. Adds an actionable hint
    /// where the brief prescribes one.
    pub fn user_message(&self) -> String {
        match self {
            AppError::NoWalletOpen => "No wallet is open. Create or recover a wallet first.".into(),
            AppError::WalletLocked => {
                "Your wallet is locked. Enter your password to unlock it.".into()
            }
            AppError::BadPassword => {
                "Wallet password incorrect. Try again or recover from your seed phrase.".into()
            }
            AppError::WeakPassword(why) => format!("Password is too weak: {why}"),
            AppError::NodeNotRunning => {
                "The node is not running. Start it from the Node tab.".into()
            }
            AppError::NodeAlreadyRunning => "The node is already running.".into(),
            AppError::NotInV1 => {
                "This feature arrives in DOM Wallet V2. For now you can mine and receive coinbase \
                 rewards."
                    .into()
            }
            AppError::Wallet(m) => format!("Wallet error: {m}"),
            AppError::Rpc(m) => {
                format!("Cannot reach the local node ({m}). Check the Node tab for details.")
            }
            AppError::Io(m) => format!("Filesystem error: {m}"),
            AppError::Config(m) => format!("Configuration error: {m}"),
            AppError::Update(m) => format!("Could not check for updates: {m}"),
            AppError::Other(m) => m.clone(),
        }
    }
}

/// Serialize as a flat object the frontend can render directly:
/// `{ "kind": "...", "message": "..." }`.
impl Serialize for AppError {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let kind = match self {
            AppError::NoWalletOpen => "no_wallet_open",
            AppError::WalletLocked => "wallet_locked",
            AppError::BadPassword => "bad_password",
            AppError::WeakPassword(_) => "weak_password",
            AppError::NodeNotRunning => "node_not_running",
            AppError::NodeAlreadyRunning => "node_already_running",
            AppError::NotInV1 => "not_in_v1",
            AppError::Wallet(_) => "wallet",
            AppError::Rpc(_) => "rpc",
            AppError::Io(_) => "io",
            AppError::Config(_) => "config",
            AppError::Update(_) => "update",
            AppError::Other(_) => "other",
        };
        let mut s = serializer.serialize_struct("AppError", 2)?;
        s.serialize_field("kind", kind)?;
        s.serialize_field("message", &self.user_message())?;
        s.end()
    }
}

impl From<anyhow::Error> for AppError {
    fn from(e: anyhow::Error) -> Self {
        // The full chain goes to the logs; the UI gets the top-level message.
        tracing::debug!("anyhow error: {e:#}");
        AppError::Other(e.to_string())
    }
}

impl From<std::io::Error> for AppError {
    fn from(e: std::io::Error) -> Self {
        AppError::Io(e.to_string())
    }
}

/// Convenience alias for command results.
pub type AppResult<T> = Result<T, AppError>;
