//! Update-check command (thin wrapper over `crate::updater`).

use crate::error::AppResult;
use crate::updater::{self, UpdateInfo};

#[tauri::command]
pub async fn updates_check() -> AppResult<UpdateInfo> {
    updater::check(env!("CARGO_PKG_VERSION")).await
}
