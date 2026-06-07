//! V2 transaction commands (replaces the V1 `not_in_v1` placeholders).
//!
//! Two modes:
//!   * Mode A (Slatepack): async, encrypted, BEGINDOMPACK envelopes.
//!   * Mode B (Simple): direct DOMRR1 receive descriptors.
//!
//! Every command orchestrates the dom-wallet crate (which owns coin selection,
//! output locking, signing, persistence) plus this app's transport modules
//! (slatepack/, descriptor/) and the V2 sidecar (pending/). No crypto or
//! consensus logic is reimplemented. All amounts cross the IPC boundary as DOM
//! strings and are converted to noms here.

use std::sync::Arc;

use serde::{Deserialize, Serialize};
use tauri::{Emitter, State};
use uuid::Uuid;

use super::AppState;
use crate::descriptor::{self, encryption as desc_enc, DescriptorPayload};
use crate::error::{AppError, AppResult};
use crate::pending::{Direction, Mode, PendingRecord, PendingState, StoredDescriptor, V2Meta};
use crate::slatepack::{self, SlateKeypair};

// ── DOM/noms conversion (mirror of frontend format.ts) ───────────────────────

const NOMS_PER_DOM: u64 = 100_000_000;

fn dom_to_noms(dom: &str) -> AppResult<u64> {
    let t = dom.trim();
    if t.is_empty() {
        return Err(AppError::Other("amount is empty".into()));
    }
    let (whole, frac) = match t.split_once('.') {
        Some((w, f)) => (w, f),
        None => (t, ""),
    };
    // Reject empty whole part (".5", "."), over-long fraction, non-digits.
    if whole.is_empty() || frac.len() > 8 {
        return Err(AppError::Other(format!("invalid DOM amount: {dom}")));
    }
    if !whole.chars().all(|c| c.is_ascii_digit())
        || !frac.chars().all(|c| c.is_ascii_digit())
    {
        return Err(AppError::Other(format!("invalid DOM amount: {dom}")));
    }
    let whole_n: u64 = whole.parse().map_err(|_| AppError::Other("amount too large".into()))?;
    let frac_padded = format!("{frac:0<8}");
    let frac_n: u64 = frac_padded.parse().unwrap_or(0);
    whole_n
        .checked_mul(NOMS_PER_DOM)
        .and_then(|x| x.checked_add(frac_n))
        .ok_or_else(|| AppError::Other("amount overflow".into()))
}

/// Parse a DOM amount that must be strictly positive (for sends/receives).
fn parse_positive_noms(dom: &str) -> AppResult<u64> {
    let n = dom_to_noms(dom)?;
    if n == 0 {
        return Err(AppError::Other("amount must be greater than zero".into()));
    }
    Ok(n)
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

async fn chain_height(state: &Arc<AppState>) -> u64 {
    match state.node.endpoints().await {
        Some(ep) => crate::rpc_client::status_view(&ep)
            .await
            .map(|s| s.chain_height)
            .unwrap_or(0),
        None => 0,
    }
}

async fn network_str(state: &Arc<AppState>) -> String {
    state.settings.read().await.network.clone()
}

async fn require_unlocked(state: &Arc<AppState>) -> AppResult<()> {
    if !state.wallet.is_unlocked().await {
        return Err(AppError::WalletLocked);
    }
    state.wallet.touch().await;
    Ok(())
}

async fn wallet_dir(state: &Arc<AppState>) -> AppResult<std::path::PathBuf> {
    state.wallet.wallet_path().await.ok_or(AppError::NoWalletOpen)
}

// ── Response DTOs ─────────────────────────────────────────────────────────────

#[derive(Serialize)]
pub struct SlateCreatedResponse {
    pub slate_id: String,
    pub slatepack: String,
    pub amount_noms: u64,
    pub fee_noms: u64,
    pub expires_at: u64,
}

#[derive(Serialize)]
pub struct SlateReceivedResponse {
    pub slate_id: String,
    pub amount_noms: u64,
    pub response_slatepack: String,
}

#[derive(Serialize)]
pub struct FinalizeResponse {
    pub tx_id: String,
    pub txid_chain: String,
    pub mode: String,
}

#[derive(Serialize)]
pub struct DescriptorCreatedResponse {
    pub descriptor_id: String,
    pub descriptor: String,
    pub amount_noms: u64,
    pub expires_at: u64,
}

#[derive(Serialize)]
pub struct DescriptorInfo {
    pub amount_noms: u64,
    pub fee_min_noms: u64,
    pub fee_max_noms: u64,
    pub network: String,
    pub expires_at: u64,
    pub expired: bool,
}

#[derive(Serialize)]
pub struct PendingTxInfo {
    pub id: String,
    pub mode: String,
    pub direction: String,
    pub amount_noms: u64,
    pub fee_noms: u64,
    pub counterparty_addr: Option<String>,
    pub state: String,
    pub created_at: u64,
    pub expires_at: u64,
}

#[derive(Deserialize)]
pub struct HistoryFilter {
    pub mode: Option<String>,
    pub direction: Option<String>,
}

#[derive(Serialize)]
pub struct TransactionRecord {
    pub id: String,
    pub kind: String,        // "coinbase" | "sent" | "received"
    pub mode: Option<String>,
    pub amount_noms: u64,
    pub state: String,
    pub created_at: u64,
    pub txid: Option<String>,
}

// ── helpers for the sidecar ───────────────────────────────────────────────────

async fn load_meta(state: &Arc<AppState>) -> AppResult<(std::path::PathBuf, V2Meta)> {
    let dir = wallet_dir(state).await?;
    let meta = V2Meta::load(&dir);
    Ok((dir, meta))
}

// ── Mode A — Slatepack commands ───────────────────────────────────────────────

#[tauri::command]
pub async fn slatepack_get_address(state: State<'_, Arc<AppState>>) -> AppResult<String> {
    require_unlocked(&state).await?;
    let (dir, mut meta) = load_meta(&state).await?;
    let net = network_str(&state).await;

    // Reuse the most recent stored address, or mint one if none exists.
    if let Some(last) = meta.slatepack_addresses.last() {
        return Ok(last.address.clone());
    }
    let kp = SlateKeypair::generate();
    let addr = kp.address(&net)?;
    let owner = state.wallet.descriptor_owner_key().await.map_err(AppError::from)?;
    let enc = desc_enc::encrypt_blinding(&owner, kp.secret_bytes())?;
    meta.slatepack_addresses.push(crate::pending::StoredSlateAddress {
        address: addr.clone(),
        secret_key_encrypted: hex::encode(enc),
        created_at: now_unix(),
    });
    meta.save(&dir)?;
    Ok(addr)
}

#[tauri::command]
pub async fn slatepack_generate_new_address(state: State<'_, Arc<AppState>>) -> AppResult<String> {
    require_unlocked(&state).await?;
    let (dir, mut meta) = load_meta(&state).await?;
    let net = network_str(&state).await;
    let kp = SlateKeypair::generate();
    let addr = kp.address(&net)?;
    let owner = state.wallet.descriptor_owner_key().await.map_err(AppError::from)?;
    let enc = desc_enc::encrypt_blinding(&owner, kp.secret_bytes())?;
    meta.slatepack_addresses.push(crate::pending::StoredSlateAddress {
        address: addr.clone(),
        secret_key_encrypted: hex::encode(enc),
        created_at: now_unix(),
    });
    meta.save(&dir)?;
    Ok(addr)
}

#[tauri::command]
pub async fn slatepack_create_send(
    state: State<'_, Arc<AppState>>,
    app: tauri::AppHandle,
    recipient_addr: String,
    amount_dom: String,
    fee_dom: String,
) -> AppResult<SlateCreatedResponse> {
    require_unlocked(&state).await?;
    let net = network_str(&state).await;
    if !slatepack::address::address_matches_network(&recipient_addr, &net) {
        return Err(AppError::Other(
            "Recipient address is not a valid DOM Slatepack address for this network.".into(),
        ));
    }
    let amount = parse_positive_noms(&amount_dom)?;
    let fee = dom_to_noms(&fee_dom)?;
    let height = chain_height(&state).await;

    // Build + reserve via the crate.
    let (slate_bytes, slate_id_bytes) = state
        .wallet
        .slate_create_send(amount, fee, height)
        .await
        .map_err(AppError::from)?;

    // Seal for the recipient → BEGINDOMPACK.
    let envelope = slatepack::seal_slate_for(&recipient_addr, Some(&net), &slate_bytes)?;

    let expiry_hours = state.settings.read().await.tx_slate_expiry_hours.unwrap_or(24);
    let expires_at = now_unix() + (expiry_hours as u64) * 3600;
    let slate_id = Uuid::new_v4().to_string();

    // Record pending (UI metadata only; the crate holds the real reservation).
    let (dir, mut meta) = load_meta(&state).await?;
    meta.pending.push(PendingRecord {
        id: slate_id.clone(),
        mode: Mode::Slatepack,
        direction: Direction::Sent,
        amount_noms: amount,
        fee_noms: fee,
        counterparty_addr: Some(recipient_addr),
        state: PendingState::SlateSent,
        created_at: now_unix(),
        expires_at,
        locked_outputs: vec![],
        tracking_tx_hash: Some(hex::encode(slate_id_bytes)),
    });
    meta.save(&dir)?;

    let _ = app.emit(
        "tx://slate_created",
        serde_json::json!({ "slate_id": slate_id, "amount_noms": amount, "fee_noms": fee }),
    );
    let _ = app.emit("wallet://pending_changed", serde_json::json!({ "count": meta.active_pending().count() }));

    Ok(SlateCreatedResponse {
        slate_id,
        slatepack: envelope,
        amount_noms: amount,
        fee_noms: fee,
        expires_at,
    })
}

#[tauri::command]
pub async fn slatepack_receive(
    state: State<'_, Arc<AppState>>,
    app: tauri::AppHandle,
    slatepack: String,
) -> AppResult<SlateReceivedResponse> {
    require_unlocked(&state).await?;
    let height = chain_height(&state).await;
    let net = network_str(&state).await;

    // Decrypt with our stored keypair(s): try the most recent address secret.
    let (dir, mut meta) = load_meta(&state).await?;
    let owner = state.wallet.descriptor_owner_key().await.map_err(AppError::from)?;
    let slate_bytes = decrypt_with_stored_keys(&meta, &owner, &slatepack)?;

    // Add our output + signature.
    let response_bytes = state
        .wallet
        .slate_receive(&slate_bytes, height)
        .await
        .map_err(AppError::from)?;

    // We respond by sealing back to the SENDER. The sender's address isn't in
    // the slate envelope we received (it was sealed TO us), so for the response
    // we wrap unencrypted in the envelope — the sender opens by structure.
    // (Encryption to the sender requires their address; the UI can capture it.)
    let response_envelope = crate::slatepack::encode::encode_envelope(&response_bytes);

    let slate_id = Uuid::new_v4().to_string();
    meta.pending.push(PendingRecord {
        id: slate_id.clone(),
        mode: Mode::Slatepack,
        direction: Direction::Received,
        amount_noms: 0, // amount is inside the slate; receiver records it on confirm
        fee_noms: 0,
        counterparty_addr: None,
        state: PendingState::SlateReturned,
        created_at: now_unix(),
        expires_at: now_unix() + 24 * 3600,
        locked_outputs: vec![],
        tracking_tx_hash: None,
    });
    meta.save(&dir)?;
    let _ = app.emit("tx://slate_signed", serde_json::json!({ "slate_id": slate_id }));
    let _ = net; // network reserved for future per-network response sealing

    Ok(SlateReceivedResponse {
        slate_id,
        amount_noms: 0,
        response_slatepack: response_envelope,
    })
}

#[tauri::command]
pub async fn slatepack_respond(
    _state: State<'_, Arc<AppState>>,
    _slate_id: String,
) -> AppResult<String> {
    // The response envelope is produced synchronously by `slatepack_receive`.
    // This command exists for API symmetry with the brief; it returns the stored
    // response if a flow ever defers it. For V2 we produce it inline.
    Err(AppError::Other(
        "Response is produced when you process the sender's Slatepack (slatepack_receive).".into(),
    ))
}

#[tauri::command]
pub async fn slatepack_finalize(
    state: State<'_, Arc<AppState>>,
    app: tauri::AppHandle,
    slate_id: String,
    response_slatepack: String,
) -> AppResult<FinalizeResponse> {
    require_unlocked(&state).await?;
    let height = chain_height(&state).await;

    // Fail closed BEFORE broadcasting: require a matching sender-side Slatepack
    // pending record in an expected state. Without this, a malformed invocation
    // could broadcast a transaction with no local accounting, breaking history
    // and cancel. (Audit HIGH-05.)
    {
        let (_dir, meta) = load_meta(&state).await?;
        let rec = meta.pending.iter().find(|p| p.id == slate_id).ok_or_else(|| {
            AppError::Other(
                "No pending transaction matches this slate. Refusing to broadcast.".into(),
            )
        })?;
        if rec.mode != Mode::Slatepack || rec.direction != Direction::Sent {
            return Err(AppError::Other(
                "This pending record is not an outgoing Slatepack transaction.".into(),
            ));
        }
        if !matches!(
            rec.state,
            PendingState::SlateSent | PendingState::SlateReceivedBack
        ) {
            return Err(AppError::Other(format!(
                "Slate is in state {:?}; cannot finalize from here.",
                rec.state
            )));
        }
    }

    // The response envelope from the receiver is not encrypted to us; decode it.
    let response_bytes = crate::slatepack::decode::decode_envelope(&response_slatepack)?;

    let (tx, tx_hash) = state
        .wallet
        .slate_finalize(&response_bytes, height)
        .await
        .map_err(AppError::from)?;

    // Broadcast.
    let ep = state.node.endpoints().await.ok_or(AppError::NodeNotRunning)?;
    let txid = match crate::rpc_client::submit_tx(&ep, tx).await {
        Ok(txid) => {
            let _ = state.wallet.mark_submitted(tx_hash).await;
            txid
        }
        Err(e) => return Err(AppError::Rpc(e.to_string())),
    };

    // Update pending → broadcast. The record is guaranteed to exist (checked
    // above); still guard the mutation defensively.
    let (dir, mut meta) = load_meta(&state).await?;
    match meta.pending.iter_mut().find(|p| p.id == slate_id) {
        Some(p) => {
            p.state = PendingState::Broadcast;
            p.tracking_tx_hash = Some(hex::encode(tx_hash));
        }
        None => {
            tracing::error!("pending record {slate_id} vanished between check and update");
        }
    }
    meta.save(&dir)?;

    let _ = app.emit(
        "tx://broadcast",
        serde_json::json!({ "tx_id": slate_id, "mode": "slatepack", "txid_chain": txid }),
    );
    Ok(FinalizeResponse {
        tx_id: slate_id,
        txid_chain: txid,
        mode: "slatepack".into(),
    })
}

/// Try each stored slatepack keypair secret to open an envelope.
fn decrypt_with_stored_keys(
    meta: &V2Meta,
    owner_key: &[u8; 32],
    envelope: &str,
) -> AppResult<Vec<u8>> {
    for stored in meta.slatepack_addresses.iter().rev() {
        let Ok(enc) = hex::decode(&stored.secret_key_encrypted) else { continue };
        let Ok(secret) = desc_enc::decrypt_blinding(owner_key, &enc) else { continue };
        let kp = SlateKeypair::from_secret(*secret);
        if let Ok(opened) = slatepack::open_slate(&kp, envelope) {
            return Ok(opened.to_vec());
        }
    }
    Err(AppError::Other(
        "Could not decrypt this Slatepack with any of your receive addresses. \
         Make sure it was sent to one of your addresses."
            .into(),
    ))
}

// ── Mode B — Simple commands ──────────────────────────────────────────────────

#[tauri::command]
pub async fn simple_create_receive_request(
    state: State<'_, Arc<AppState>>,
    app: tauri::AppHandle,
    amount_dom: String,
    min_fee_dom: String,
    max_fee_dom: String,
    expiry_hours: u32,
) -> AppResult<DescriptorCreatedResponse> {
    require_unlocked(&state).await?;
    let amount = parse_positive_noms(&amount_dom)?;
    let fee_min = dom_to_noms(&min_fee_dom)?;
    let fee_max = dom_to_noms(&max_fee_dom)?;
    if fee_min > fee_max {
        return Err(AppError::Other(
            "Minimum fee cannot exceed maximum fee.".into(),
        ));
    }
    let net = network_str(&state).await;
    let magic = state.settings.read().await.wallet_network().magic();

    // Ask the crate for a receive request (commitment + blinding).
    let desc = state
        .wallet
        .create_receive_request(amount)
        .await
        .map_err(AppError::from)?;

    let commitment = hex_to_array33(&desc.commitment_hex)?;
    let blinding = hex_to_array32(&desc.blinding_hex)?;

    // Receiver pubkey: a fresh slatepack key (also keys the transport wrap).
    let kp = SlateKeypair::generate();
    let receiver_pub = *kp.public();

    // Transport-wrap the blinding so the SENDER (who holds the descriptor) can
    // recover it to build the spend. Confidentiality vs the channel is Mode A's
    // job; Mode B is for trusted channels (UI warns). See descriptor/mod.rs.
    let wrapped_blinding = desc_enc::wrap_blinding_for_transport(&receiver_pub, &blinding)?;

    let expires_at = now_unix() + (expiry_hours.max(1) as u64) * 3600;
    let payload = DescriptorPayload {
        network_magic: magic,
        amount,
        fee_min,
        fee_max,
        expiry_unix: expires_at,
        commitment,
        receiver_pub,
        wrapped_blinding,
    };
    let encoded = payload.encode();
    let descriptor_id = Uuid::new_v4().to_string();

    let (dir, mut meta) = load_meta(&state).await?;
    meta.receive_descriptors.push(StoredDescriptor {
        id: descriptor_id.clone(),
        encoded: encoded.clone(),
        amount_noms: amount,
        created_at: now_unix(),
        expires_at,
        status: "active".into(),
    });
    meta.pending.push(PendingRecord {
        id: descriptor_id.clone(),
        mode: Mode::Simple,
        direction: Direction::Received,
        amount_noms: amount,
        fee_noms: 0,
        counterparty_addr: None,
        state: PendingState::DescriptorCreated,
        created_at: now_unix(),
        expires_at,
        locked_outputs: vec![],
        tracking_tx_hash: None,
    });
    meta.save(&dir)?;

    let _ = app.emit(
        "tx://descriptor_created",
        serde_json::json!({ "descriptor_id": descriptor_id, "amount_noms": amount, "expires_at": expires_at }),
    );
    let _ = net;

    Ok(DescriptorCreatedResponse {
        descriptor_id,
        descriptor: encoded,
        amount_noms: amount,
        expires_at,
    })
}

#[tauri::command]
pub async fn simple_parse_descriptor(
    state: State<'_, Arc<AppState>>,
    descriptor: String,
) -> AppResult<DescriptorInfo> {
    let payload = DescriptorPayload::decode(&descriptor)?;
    let our_magic = state.settings.read().await.wallet_network().magic();
    if payload.network_magic != our_magic {
        return Err(AppError::Other(
            "Descriptor is for a different network (mainnet vs testnet).".into(),
        ));
    }
    let net = network_str(&state).await;
    Ok(DescriptorInfo {
        amount_noms: payload.amount,
        fee_min_noms: payload.fee_min,
        fee_max_noms: payload.fee_max,
        network: net,
        expires_at: payload.expiry_unix,
        expired: payload.is_expired(now_unix()),
    })
}

#[tauri::command]
pub async fn simple_send_to_descriptor(
    state: State<'_, Arc<AppState>>,
    app: tauri::AppHandle,
    descriptor: String,
    fee_dom: String,
) -> AppResult<FinalizeResponse> {
    require_unlocked(&state).await?;
    let payload = DescriptorPayload::decode(&descriptor)?;
    let our_magic = state.settings.read().await.wallet_network().magic();
    if payload.network_magic != our_magic {
        return Err(AppError::Other(
            "Descriptor is for a different network (mainnet vs testnet).".into(),
        ));
    }
    if payload.is_expired(now_unix()) {
        return Err(AppError::Other(
            "This receive descriptor has expired. Ask the recipient to generate a new one.".into(),
        ));
    }
    let fee = dom_to_noms(&fee_dom)?;
    if fee < payload.fee_min || fee > payload.fee_max {
        return Err(AppError::Other(format!(
            "Fee outside acceptable range. Recipient requested {}-{} noms, you offered {}.",
            payload.fee_min, payload.fee_max, fee
        )));
    }

    // Recover the recipient blinding from the descriptor's transport wrap. The
    // sender legitimately needs it in the clear to build the output it is
    // funding (this is how the crate's build_spend works; see descriptor/mod.rs
    // for the security rationale).
    let blinding = desc_enc::unwrap_blinding_from_transport(&payload.receiver_pub, &payload.wrapped_blinding)?;

    let height = chain_height(&state).await;
    let (tx, tx_hash) = state
        .wallet
        .build_spend_to(&payload.commitment, *blinding, payload.amount, fee, height)
        .await
        .map_err(AppError::from)?;

    // Broadcast.
    let ep = state.node.endpoints().await.ok_or(AppError::NodeNotRunning)?;
    let txid = match crate::rpc_client::submit_tx(&ep, tx).await {
        Ok(txid) => {
            let _ = state.wallet.mark_submitted(tx_hash).await;
            txid
        }
        Err(e) => return Err(AppError::Rpc(e.to_string())),
    };

    // Record the sent tx as a pending → broadcast entry.
    let tx_id = Uuid::new_v4().to_string();
    let (dir, mut meta) = load_meta(&state).await?;
    meta.pending.push(PendingRecord {
        id: tx_id.clone(),
        mode: Mode::Simple,
        direction: Direction::Sent,
        amount_noms: payload.amount,
        fee_noms: fee,
        counterparty_addr: None,
        state: PendingState::Broadcast,
        created_at: now_unix(),
        expires_at: now_unix() + 24 * 3600,
        locked_outputs: vec![],
        tracking_tx_hash: Some(hex::encode(tx_hash)),
    });
    meta.save(&dir)?;

    let _ = app.emit(
        "tx://broadcast",
        serde_json::json!({ "tx_id": tx_id, "mode": "simple", "txid_chain": txid }),
    );
    let _ = app.emit(
        "wallet://pending_changed",
        serde_json::json!({ "count": meta.active_pending().count() }),
    );

    Ok(FinalizeResponse {
        tx_id,
        txid_chain: txid,
        mode: "simple".into(),
    })
}

#[tauri::command]
pub async fn simple_cancel_descriptor(
    state: State<'_, Arc<AppState>>,
    app: tauri::AppHandle,
    descriptor_id: String,
) -> AppResult<()> {
    require_unlocked(&state).await?;
    let (dir, mut meta) = load_meta(&state).await?;
    if let Some(d) = meta.receive_descriptors.iter_mut().find(|d| d.id == descriptor_id) {
        d.status = "expired".into();
    }
    if let Some(p) = meta.pending.iter_mut().find(|p| p.id == descriptor_id) {
        p.state = PendingState::Cancelled;
    }
    meta.save(&dir)?;
    let _ = app.emit("tx://cancelled", serde_json::json!({ "tx_id": descriptor_id, "mode": "simple" }));
    Ok(())
}

// ── Shared commands ───────────────────────────────────────────────────────────

#[tauri::command]
pub async fn cancel_pending_tx(
    state: State<'_, Arc<AppState>>,
    app: tauri::AppHandle,
    tx_id: String,
) -> AppResult<()> {
    require_unlocked(&state).await?;
    let (dir, mut meta) = load_meta(&state).await?;
    let Some(p) = meta.pending.iter_mut().find(|p| p.id == tx_id) else {
        return Err(AppError::Other("pending transaction not found".into()));
    };
    if matches!(p.state, PendingState::Broadcast | PendingState::Confirmed) {
        return Err(AppError::Other(
            "Cannot cancel — transaction is already broadcast and waiting for confirmation.".into(),
        ));
    }
    // Release the crate-level reservation for sender flows.
    if p.direction == Direction::Sent {
        if let Some(h) = &p.tracking_tx_hash {
            if let Ok(bytes) = hex::decode(h) {
                if bytes.len() == 32 {
                    let mut hh = [0u8; 32];
                    hh.copy_from_slice(&bytes);
                    let _ = state.wallet.cancel_tracked_tx(hh).await;
                }
            }
        }
    }
    p.state = PendingState::Cancelled;
    meta.save(&dir)?;
    let _ = app.emit("tx://cancelled", serde_json::json!({ "tx_id": tx_id }));
    let _ = app.emit("wallet://pending_changed", serde_json::json!({ "count": meta.active_pending().count() }));
    Ok(())
}

#[tauri::command]
pub async fn list_pending_txs(state: State<'_, Arc<AppState>>) -> AppResult<Vec<PendingTxInfo>> {
    let (_dir, meta) = load_meta(&state).await?;
    Ok(meta
        .active_pending()
        .map(|p| PendingTxInfo {
            id: p.id.clone(),
            mode: format!("{:?}", p.mode).to_lowercase(),
            direction: format!("{:?}", p.direction).to_lowercase(),
            amount_noms: p.amount_noms,
            fee_noms: p.fee_noms,
            counterparty_addr: p.counterparty_addr.clone(),
            state: format!("{:?}", p.state),
            created_at: p.created_at,
            expires_at: p.expires_at,
        })
        .collect())
}

#[tauri::command]
pub async fn get_full_transaction_history(
    state: State<'_, Arc<AppState>>,
    filter: HistoryFilter,
) -> AppResult<Vec<TransactionRecord>> {
    let (_dir, meta) = load_meta(&state).await?;
    let mut out: Vec<TransactionRecord> = meta
        .pending
        .iter()
        .map(|p| TransactionRecord {
            id: p.id.clone(),
            kind: format!("{:?}", p.direction).to_lowercase(),
            mode: Some(format!("{:?}", p.mode).to_lowercase()),
            amount_noms: p.amount_noms,
            state: format!("{:?}", p.state),
            created_at: p.created_at,
            txid: p.tracking_tx_hash.clone(),
        })
        .collect();

    if let Some(m) = &filter.mode {
        out.retain(|r| r.mode.as_deref() == Some(m.as_str()));
    }
    if let Some(d) = &filter.direction {
        out.retain(|r| r.kind == *d);
    }
    out.sort_by(|a, b| b.created_at.cmp(&a.created_at));
    Ok(out)
}

// ── hex helpers ───────────────────────────────────────────────────────────────

fn hex_to_array33(s: &str) -> AppResult<[u8; 33]> {
    let bytes = hex::decode(s).map_err(|_| AppError::Other("bad commitment hex".into()))?;
    if bytes.len() != 33 {
        return Err(AppError::Other("commitment must be 33 bytes".into()));
    }
    let mut a = [0u8; 33];
    a.copy_from_slice(&bytes);
    Ok(a)
}

fn hex_to_array32(s: &str) -> AppResult<[u8; 32]> {
    let bytes = hex::decode(s).map_err(|_| AppError::Other("bad blinding hex".into()))?;
    if bytes.len() != 32 {
        return Err(AppError::Other("blinding must be 32 bytes".into()));
    }
    let mut a = [0u8; 32];
    a.copy_from_slice(&bytes);
    Ok(a)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dom_to_noms_basic() {
        assert_eq!(dom_to_noms("1").unwrap(), 100_000_000);
        assert_eq!(dom_to_noms("33").unwrap(), 3_300_000_000);
        assert_eq!(dom_to_noms("0.00000001").unwrap(), 1);
        assert_eq!(dom_to_noms("1.5").unwrap(), 150_000_000);
    }

    #[test]
    fn dom_to_noms_rejects_bad() {
        assert!(dom_to_noms("abc").is_err());
        assert!(dom_to_noms("1.234567891").is_err());
    }

    #[test]
    fn dom_to_noms_rejects_empty_whole_and_blank() {
        // Audit MEDIUM-03: ".5", ".", "" must be rejected.
        assert!(dom_to_noms("").is_err());
        assert!(dom_to_noms(".").is_err());
        assert!(dom_to_noms(".5").is_err());
        assert!(dom_to_noms("1.").unwrap() == 100_000_000); // trailing dot = whole only
    }

    #[test]
    fn parse_positive_rejects_zero() {
        // Audit MEDIUM-03: zero-value sends/receives must be refused.
        assert!(parse_positive_noms("0").is_err());
        assert!(parse_positive_noms("0.00000000").is_err());
        assert_eq!(parse_positive_noms("0.00000001").unwrap(), 1);
    }

    #[test]
    fn leading_zeros_ok() {
        assert_eq!(dom_to_noms("0001").unwrap(), 100_000_000);
    }
}
