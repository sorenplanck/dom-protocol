//! Background expiry task.
//!
//! Every minute, loads the V2 sidecar, marks any pending slate / descriptor
//! whose deadline passed as expired, and — crucially — releases the reserved
//! inputs of expired SENDER-side slatepack transactions by calling the crate's
//! `cancel_tx` (the authoritative unlock). Receiver-side flows never reserved
//! inputs, so there's nothing to release there.
//!
//! This keeps the "#1 source of wallet bugs" (stuck/locked outputs) correct by
//! delegating the actual unlock to the crate, while the sidecar only tracks the
//! UI-facing state.

use std::sync::Arc;
use std::time::Duration;

use tauri::{AppHandle, Emitter};

use crate::commands::AppState;
use crate::pending::V2Meta;

/// Spawn the periodic expiry sweep.
pub fn spawn(app: AppHandle, state: Arc<AppState>) {
    tauri::async_runtime::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(60));
        loop {
            tick.tick().await;
            if let Err(e) = sweep(&app, &state).await {
                tracing::debug!("expiry sweep error: {e}");
            }
        }
    });
}

async fn sweep(app: &AppHandle, state: &Arc<AppState>) -> anyhow::Result<()> {
    let Some(wallet_dir) = state.wallet.wallet_path().await else {
        return Ok(());
    };
    // Only sweep when unlocked (cancel_tx needs an unlocked wallet).
    if !state.wallet.is_unlocked().await {
        return Ok(());
    }

    let mut meta = V2Meta::load(&wallet_dir);
    let now = now_unix();
    let to_cancel = meta.expire_due(now);
    if to_cancel.is_empty() && !meta_changed(&meta, now) {
        return Ok(());
    }

    // Release reserved inputs for expired sender-side slatepack txs.
    for hash_hex in &to_cancel {
        if let Ok(bytes) = hex::decode(hash_hex) {
            if bytes.len() == 32 {
                let mut h = [0u8; 32];
                h.copy_from_slice(&bytes);
                if let Err(e) = state.wallet.cancel_tracked_tx(h).await {
                    tracing::warn!("failed to release expired tx {hash_hex}: {e}");
                } else {
                    let _ = app.emit(
                        "tx://expired",
                        serde_json::json!({ "tx_id": hash_hex, "reason": "timeout" }),
                    );
                }
            }
        }
    }

    meta.save(&wallet_dir)?;
    let _ = app.emit(
        "wallet://pending_changed",
        serde_json::json!({
            "count": meta.active_pending().count(),
        }),
    );
    Ok(())
}

/// Cheap heuristic to avoid rewriting the sidecar when nothing changed.
fn meta_changed(meta: &V2Meta, now: u64) -> bool {
    meta.receive_descriptors
        .iter()
        .any(|d| d.status == "active" && now >= d.expires_at)
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
