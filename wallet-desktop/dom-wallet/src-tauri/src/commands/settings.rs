//! V1 settings commands: read/update settings, change password, export backup,
//! and the available-cores hint for the mining-threads slider.

use std::sync::Arc;

use tauri::State;

use super::AppState;
use crate::error::{AppError, AppResult};
use crate::settings::NodeSettings;

/// Return the current settings.
#[tauri::command]
pub async fn settings_get(state: State<'_, Arc<AppState>>) -> AppResult<NodeSettings> {
    Ok(state.settings.read().await.clone())
}

/// Replace settings wholesale (the Settings screen sends the full object).
/// Validates before persisting. Network/port changes require a node restart,
/// which the UI prompts for separately.
#[tauri::command]
pub async fn settings_update(
    state: State<'_, Arc<AppState>>,
    new_settings: NodeSettings,
) -> AppResult<()> {
    new_settings.validate()?;
    {
        let mut s = state.settings.write().await;
        *s = new_settings;
    }
    state.persist_settings().await
}

/// Number of logical cores, for the mining-threads slider max.
#[tauri::command]
pub fn settings_available_cores() -> u32 {
    std::thread::available_parallelism()
        .map(|n| n.get() as u32)
        .unwrap_or(1)
        .max(1)
}

/// Export wallet backup: copy `wallet.dat` and existing timestamped backups to
/// the chosen directory. Does not require unlock (the files are encrypted).
#[tauri::command]
pub async fn settings_export_backup(
    state: State<'_, Arc<AppState>>,
    dest_dir: String,
) -> AppResult<usize> {
    let settings = state.settings.read().await.clone();
    let wallet_dir = settings.wallet_path();
    let dest = std::path::Path::new(&dest_dir);
    std::fs::create_dir_all(dest).map_err(|e| AppError::Io(e.to_string()))?;

    let mut copied = 0usize;

    // The live wallet.dat.
    let dat = wallet_dir.join(dom_wallet::WALLET_DAT_NAME);
    if dat.exists() {
        std::fs::copy(&dat, dest.join(dom_wallet::WALLET_DAT_NAME))
            .map_err(|e| AppError::Io(e.to_string()))?;
        copied += 1;
    }

    // The app's timestamped backups.
    let backup_dir = std::path::Path::new(&settings.backup_dir);
    if backup_dir.exists() {
        for entry in std::fs::read_dir(backup_dir).map_err(|e| AppError::Io(e.to_string()))? {
            let entry = entry.map_err(|e| AppError::Io(e.to_string()))?;
            let name = entry.file_name();
            if name.to_string_lossy().contains(".bak.") {
                std::fs::copy(entry.path(), dest.join(&name))
                    .map_err(|e| AppError::Io(e.to_string()))?;
                copied += 1;
            }
        }
    }

    tracing::info!("exported {copied} wallet file(s) to {dest_dir}");
    Ok(copied)
}

/// Change the wallet password.
///
// VERIFICAR: assinatura assumida — dom-wallet expõe troca de senha?
// A API pública inspecionada (wallet.rs / wallet_dir.rs) não mostra um
// `change_password`/`rekey`. Em vez de inventar uma chamada que não compila —
// ou de fazer um backup inútil antes de uma falha garantida (audit MEDIUM-01) —
// retornamos um erro imediato. A UI desativa este controlo neste build.
#[tauri::command]
pub async fn settings_change_password(
    _state: State<'_, Arc<AppState>>,
    _current_password: String,
    _new_password: String,
) -> AppResult<()> {
    Err(AppError::Other(
        "Changing the password isn't available in this build (needs a dom-wallet rekey API). \
         Your current password still works."
            .into(),
    ))
}
