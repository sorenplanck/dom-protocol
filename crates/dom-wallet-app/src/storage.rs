use dom_wallet::Network;
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::Write;
use std::path::{Path, PathBuf};
use url::Url;

pub const APP_STATE_FILE: &str = "app_state.json";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PersistedAppState {
    pub wallet_dir: Option<PathBuf>,
    pub network: Option<Network>,
    pub node_url: String,
}

impl Default for PersistedAppState {
    fn default() -> Self {
        Self {
            wallet_dir: None,
            network: None,
            node_url: "http://127.0.0.1:33369".to_string(),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum AppStorageError {
    #[error("io: {0}")]
    Io(String),
    #[error("serialization: {0}")]
    Serialization(String),
    #[error("invalid node url: {0}")]
    InvalidNodeUrl(String),
}

pub fn load_or_default(data_dir: &Path) -> Result<PersistedAppState, AppStorageError> {
    let path = data_dir.join(APP_STATE_FILE);
    if !path.exists() {
        return Ok(PersistedAppState::default());
    }

    let bytes = std::fs::read(&path).map_err(|e| AppStorageError::Io(e.to_string()))?;
    let state: PersistedAppState = serde_json::from_slice(&bytes)
        .map_err(|e| AppStorageError::Serialization(e.to_string()))?;
    validate_node_url(&state.node_url)?;
    Ok(state)
}

pub fn save(data_dir: &Path, state: &PersistedAppState) -> Result<(), AppStorageError> {
    std::fs::create_dir_all(data_dir).map_err(|e| AppStorageError::Io(e.to_string()))?;
    validate_node_url(&state.node_url)?;

    let path = data_dir.join(APP_STATE_FILE);
    let temp_path = data_dir.join(format!("{APP_STATE_FILE}.tmp"));
    let json = serde_json::to_vec_pretty(state)
        .map_err(|e| AppStorageError::Serialization(e.to_string()))?;

    {
        let mut file = File::create(&temp_path).map_err(|e| AppStorageError::Io(e.to_string()))?;
        file.write_all(&json)
            .map_err(|e| AppStorageError::Io(e.to_string()))?;
        file.sync_all()
            .map_err(|e| AppStorageError::Io(e.to_string()))?;
    }

    std::fs::rename(&temp_path, &path).map_err(|e| AppStorageError::Io(e.to_string()))?;
    #[cfg(unix)]
    {
        let dir = File::open(data_dir).map_err(|e| AppStorageError::Io(e.to_string()))?;
        dir.sync_all()
            .map_err(|e| AppStorageError::Io(e.to_string()))?;
    }

    Ok(())
}

pub fn default_data_dir() -> PathBuf {
    if let Some(home) = std::env::var_os("HOME") {
        return PathBuf::from(home).join(".dom-wallet-app");
    }
    std::env::current_dir()
        .unwrap_or_else(|_| PathBuf::from("."))
        .join(".dom-wallet-app")
}

fn validate_node_url(node_url: &str) -> Result<(), AppStorageError> {
    let parsed =
        Url::parse(node_url).map_err(|e| AppStorageError::InvalidNodeUrl(e.to_string()))?;
    match parsed.scheme() {
        "http" | "https" => {}
        scheme => {
            return Err(AppStorageError::InvalidNodeUrl(format!(
                "unsupported scheme {scheme}"
            )))
        }
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(AppStorageError::InvalidNodeUrl(
            "userinfo is not allowed in node_url".into(),
        ));
    }
    let Some(host) = parsed.host_str() else {
        return Err(AppStorageError::InvalidNodeUrl("missing host".into()));
    };
    let loopback = match host {
        "localhost" => true,
        _ => host
            .parse::<std::net::IpAddr>()
            .map(|ip| ip.is_loopback())
            .unwrap_or(false),
    };
    if !loopback {
        return Err(AppStorageError::InvalidNodeUrl(format!(
            "host {host} is not loopback"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn load_missing_returns_default() {
        let temp = TempDir::new().unwrap();
        let state = load_or_default(temp.path()).unwrap();
        assert_eq!(state, PersistedAppState::default());
    }

    #[test]
    fn save_then_load_roundtrip() {
        let temp = TempDir::new().unwrap();
        let state = PersistedAppState {
            wallet_dir: Some(temp.path().join("wallet")),
            network: Some(Network::Regtest),
            node_url: "http://127.0.0.1:12345".to_string(),
        };
        save(temp.path(), &state).unwrap();
        let loaded = load_or_default(temp.path()).unwrap();
        assert_eq!(loaded, state);
    }

    #[test]
    fn malformed_json_is_rejected() {
        let temp = TempDir::new().unwrap();
        std::fs::create_dir_all(temp.path()).unwrap();
        std::fs::write(temp.path().join(APP_STATE_FILE), b"{not json").unwrap();
        let err = load_or_default(temp.path()).unwrap_err();
        assert!(matches!(err, AppStorageError::Serialization(_)));
    }

    #[test]
    fn hostile_node_url_scheme_is_rejected() {
        let temp = TempDir::new().unwrap();
        std::fs::create_dir_all(temp.path()).unwrap();
        std::fs::write(
            temp.path().join(APP_STATE_FILE),
            br#"{"wallet_dir":null,"network":null,"node_url":"file:///etc/passwd"}"#,
        )
        .unwrap();
        let err = load_or_default(temp.path()).unwrap_err();
        assert!(matches!(err, AppStorageError::InvalidNodeUrl(_)));
    }

    #[test]
    fn remote_node_url_host_is_rejected() {
        let temp = TempDir::new().unwrap();
        std::fs::create_dir_all(temp.path()).unwrap();
        std::fs::write(
            temp.path().join(APP_STATE_FILE),
            br#"{"wallet_dir":null,"network":null,"node_url":"http://attacker.example:1/"}"#,
        )
        .unwrap();
        let err = load_or_default(temp.path()).unwrap_err();
        assert!(matches!(err, AppStorageError::InvalidNodeUrl(_)));
    }
}
