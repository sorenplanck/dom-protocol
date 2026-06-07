//! V1 log commands for the Node tab (the headline feature).
//!
//! - `logs_snapshot` returns recent buffered lines so the tab can render history
//!   immediately on open.
//! - `logs_subscribe` starts a background task that forwards every new line to
//!   the frontend as a `log://line` event. Started once on app setup; exposed as
//!   a command too so the UI can (re)attach if needed.
//! - `logs_export` writes up to the last 10,000 lines to a chosen `.txt` file.
//!
//! "Clear", "Pause", "Auto-scroll", and level/target filtering are pure
//! frontend concerns (they affect display only, never the backend buffer).

use std::sync::Arc;

use tauri::{Emitter, State};

use super::AppState;
use crate::error::{AppError, AppResult};
use crate::log_capture::{LogLine, BACKEND_BUFFER};

/// Recent buffered log lines (oldest first), capped at `max` (default 1000).
#[tauri::command]
pub async fn logs_snapshot(
    state: State<'_, Arc<AppState>>,
    max: Option<usize>,
) -> AppResult<Vec<LogLine>> {
    let max = max.unwrap_or(1000).min(BACKEND_BUFFER);
    Ok(state.logs.snapshot(max))
}

/// Export the last `max` (default 10,000) lines to `path` as plain text.
#[tauri::command]
pub async fn logs_export(
    state: State<'_, Arc<AppState>>,
    path: String,
    max: Option<usize>,
) -> AppResult<usize> {
    let max = max.unwrap_or(BACKEND_BUFFER).min(BACKEND_BUFFER);
    let lines = state.logs.snapshot(max);
    let mut out = String::with_capacity(lines.len() * 80);
    for l in &lines {
        out.push_str(&format!(
            "{} {:5} {} {}\n",
            l.timestamp, l.level, l.target, l.message
        ));
    }
    std::fs::write(&path, out).map_err(|e| AppError::Io(e.to_string()))?;
    Ok(lines.len())
}

/// Spawn the background forwarder that re-emits each live log line to the UI.
/// Idempotent enough for app setup; safe to call again (a second forwarder is
/// harmless but wasteful, so the UI normally relies on the setup-time one).
pub fn spawn_forwarder(app: tauri::AppHandle, state: Arc<AppState>) {
    let mut rx = state.logs.subscribe();
    tauri::async_runtime::spawn(async move {
        loop {
            match rx.recv().await {
                Ok(line) => {
                    let _ = app.emit("log://line", &line);
                }
                Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                    // The UI fell behind; tell it some lines were skipped.
                    let _ = app.emit(
                        "log://line",
                        &LogLine {
                            timestamp: 0,
                            level: "WARN".into(),
                            target: "dom_wallet::logs".into(),
                            message: format!("(log stream lagged — {n} lines dropped from view)"),
                        },
                    );
                }
                Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
            }
        }
    });
}
