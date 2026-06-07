// Typed bindings to the Rust Tauri commands. Every backend `#[tauri::command]`
// has exactly one wrapper here, with argument/return types mirroring the Rust
// signatures. The UI never calls `invoke` directly — it goes through these.

import { invoke } from "@tauri-apps/api/core";

// ── Shared types (mirror the Rust serde structs) ────────────────────────────

export interface AppErrorShape {
  kind: string;
  message: string;
}

export interface WalletStatus {
  exists: boolean;
  open: boolean;
  unlocked: boolean;
  network: string | null;
}

export interface CreatedWallet {
  mnemonic: string;
}

export interface BalanceInfo {
  total: number;
  spendable: number;
  confirmed: number;
  immature: number;
}

export interface NodeRunning {
  running: boolean;
  rpc_port: number | null;
  p2p_addr: string | null;
}

export interface NodeStatusView {
  version: number;
  chain_height: number;
  mempool_size: number;
  network: string;
  peer_count: number;
  mining_active: boolean;
  hashrate: number;
  blocks_mined: number;
}

export interface LogLine {
  timestamp: number;
  level: string;
  target: string;
  message: string;
}

export type Theme = "light" | "dark" | "auto";

export interface NodeSettings {
  network: string;
  seed_peers: string[];
  p2p_listen_addr: string;
  rpc_listen_addr: string;
  metrics_listen_addr: string;
  data_dir: string;
  wallet_dir: string;
  backup_dir: string;
  auto_lock_minutes: number | null;
  mining_enabled: boolean;
  mining_threads: number;
  log_level: string;
  theme: Theme;
  // V2 transaction defaults
  default_tx_mode: string;
  tx_slate_expiry_hours: number | null;
  tx_descriptor_expiry_hours: number | null;
  tx_show_advanced_fees: boolean;
  tx_new_address_per_tx: boolean;
}

export interface UpdateInfo {
  current: string;
  latest: string;
  newer: boolean;
  mandatory: boolean;
  changelog: string;
  html_url: string;
}

// ── Error normalisation ──────────────────────────────────────────────────────

/** Tauri rejects with the serialized AppError object; normalise to a string. */
export function errMessage(e: unknown): string {
  if (typeof e === "string") return e;
  if (e && typeof e === "object" && "message" in e) {
    return String((e as AppErrorShape).message);
  }
  return "Something went wrong.";
}

// ── Wallet commands ──────────────────────────────────────────────────────────

export const walletStatus = () => invoke<WalletStatus>("wallet_status");
export const walletCreate = (password: string) =>
  invoke<CreatedWallet>("wallet_create", { password });
export const walletRecover = (password: string, mnemonic: string) =>
  invoke<void>("wallet_recover", { password, mnemonic });
export const walletOpen = (password: string) =>
  invoke<void>("wallet_open", { password });
export const walletUnlock = (password: string) =>
  invoke<void>("wallet_unlock", { password });
export const walletLock = () => invoke<void>("wallet_lock");
export const walletBalance = () => invoke<BalanceInfo>("wallet_balance");
export const walletVerifyPassword = (password: string) =>
  invoke<boolean>("wallet_verify_password", { password });

// ── Node commands ────────────────────────────────────────────────────────────

export const nodeIsRunning = () => invoke<NodeRunning>("node_is_running");
export const nodeStart = (walletPassword: string) =>
  invoke<void>("node_start", { walletPassword });
export const nodeStop = () => invoke<void>("node_stop");
export const nodeRestart = (walletPassword: string) =>
  invoke<void>("node_restart", { walletPassword });
export const nodeStatus = () => invoke<NodeStatusView>("node_status");
export const nodeSetMining = (enabled: boolean, walletPassword: string) =>
  invoke<void>("node_set_mining", { enabled, walletPassword });

// ── Logs commands ────────────────────────────────────────────────────────────

export const logsSnapshot = (max?: number) =>
  invoke<LogLine[]>("logs_snapshot", { max });
export const logsExport = (path: string, max?: number) =>
  invoke<number>("logs_export", { path, max });

// ── Settings commands ────────────────────────────────────────────────────────

export const settingsGet = () => invoke<NodeSettings>("settings_get");
export const settingsUpdate = (newSettings: NodeSettings) =>
  invoke<void>("settings_update", { newSettings });
export const settingsAvailableCores = () =>
  invoke<number>("settings_available_cores");
export const settingsExportBackup = (destDir: string) =>
  invoke<number>("settings_export_backup", { destDir });
export const settingsChangePassword = (
  currentPassword: string,
  newPassword: string,
) => invoke<void>("settings_change_password", { currentPassword, newPassword });

// ── Updates ──────────────────────────────────────────────────────────────────

export const updatesCheck = () => invoke<UpdateInfo>("updates_check");

// ── V2 transaction types ─────────────────────────────────────────────────────

export type TxMode = "slatepack" | "simple";

export interface SlateCreatedResponse {
  slate_id: string;
  slatepack: string;
  amount_noms: number;
  fee_noms: number;
  expires_at: number;
}

export interface SlateReceivedResponse {
  slate_id: string;
  amount_noms: number;
  response_slatepack: string;
}

export interface FinalizeResponse {
  tx_id: string;
  txid_chain: string;
  mode: string;
}

export interface DescriptorCreatedResponse {
  descriptor_id: string;
  descriptor: string;
  amount_noms: number;
  expires_at: number;
}

export interface DescriptorInfo {
  amount_noms: number;
  fee_min_noms: number;
  fee_max_noms: number;
  network: string;
  expires_at: number;
  expired: boolean;
}

export interface PendingTxInfo {
  id: string;
  mode: string;
  direction: string;
  amount_noms: number;
  fee_noms: number;
  counterparty_addr: string | null;
  state: string;
  created_at: number;
  expires_at: number;
}

export interface HistoryFilter {
  mode?: string | null;
  direction?: string | null;
}

export interface TransactionRecord {
  id: string;
  kind: string;
  mode: string | null;
  amount_noms: number;
  state: string;
  created_at: number;
  txid: string | null;
}

// ── V2 — Slatepack (Mode A) ───────────────────────────────────────────────────

export const slatepackGetAddress = () =>
  invoke<string>("slatepack_get_address");
export const slatepackGenerateNewAddress = () =>
  invoke<string>("slatepack_generate_new_address");
export const slatepackCreateSend = (
  recipientAddr: string,
  amountDom: string,
  feeDom: string,
) =>
  invoke<SlateCreatedResponse>("slatepack_create_send", {
    recipientAddr,
    amountDom,
    feeDom,
  });
export const slatepackReceive = (slatepack: string) =>
  invoke<SlateReceivedResponse>("slatepack_receive", { slatepack });
export const slatepackRespond = (slateId: string) =>
  invoke<string>("slatepack_respond", { slateId });
export const slatepackFinalize = (slateId: string, responseSlatepack: string) =>
  invoke<FinalizeResponse>("slatepack_finalize", { slateId, responseSlatepack });

// ── V2 — Simple (Mode B) ──────────────────────────────────────────────────────

export const simpleCreateReceiveRequest = (
  amountDom: string,
  minFeeDom: string,
  maxFeeDom: string,
  expiryHours: number,
) =>
  invoke<DescriptorCreatedResponse>("simple_create_receive_request", {
    amountDom,
    minFeeDom,
    maxFeeDom,
    expiryHours,
  });
export const simpleParseDescriptor = (descriptor: string) =>
  invoke<DescriptorInfo>("simple_parse_descriptor", { descriptor });
export const simpleSendToDescriptor = (descriptor: string, feeDom: string) =>
  invoke<FinalizeResponse>("simple_send_to_descriptor", { descriptor, feeDom });
export const simpleCancelDescriptor = (descriptorId: string) =>
  invoke<void>("simple_cancel_descriptor", { descriptorId });

// ── V2 — shared ───────────────────────────────────────────────────────────────

export const cancelPendingTx = (txId: string) =>
  invoke<void>("cancel_pending_tx", { txId });
export const listPendingTxs = () =>
  invoke<PendingTxInfo[]>("list_pending_txs");
export const getFullTransactionHistory = (filter: HistoryFilter) =>
  invoke<TransactionRecord[]>("get_full_transaction_history", { filter });
