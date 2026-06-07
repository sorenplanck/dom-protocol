// Typed wrappers around Tauri's event system. Each backend event channel has a
// helper that subscribes with the correct payload type and returns the
// unlisten function (callers MUST call it on unmount to avoid leaks).

import { listen, type UnlistenFn } from "@tauri-apps/api/event";
import type { LogLine, NodeStatusView, UpdateInfo } from "./tauri";

export interface NodeStartedPayload {
  rpc_port: number | null;
  p2p_port: number | null;
}
export interface NodeStoppedPayload {
  reason: string;
}
export interface WalletLockedPayload {
  reason: "manual" | "timeout";
}
export interface NewBlockPayload {
  height: number;
  hash: string;
  is_ours: boolean;
  coinbase_value_noms: number;
}
export interface NewCoinbasePayload {
  height: number;
  value_noms: number;
}

export const onLogLine = (cb: (l: LogLine) => void): Promise<UnlistenFn> =>
  listen<LogLine>("log://line", (e) => cb(e.payload));

export const onNodeStatus = (
  cb: (s: NodeStatusView) => void,
): Promise<UnlistenFn> =>
  listen<NodeStatusView>("node://status", (e) => cb(e.payload));

export const onNodeStarted = (
  cb: (p: NodeStartedPayload) => void,
): Promise<UnlistenFn> =>
  listen<NodeStartedPayload>("node://started", (e) => cb(e.payload));

export const onNodeStopped = (
  cb: (p: NodeStoppedPayload) => void,
): Promise<UnlistenFn> =>
  listen<NodeStoppedPayload>("node://stopped", (e) => cb(e.payload));

export const onWalletUnlocked = (cb: () => void): Promise<UnlistenFn> =>
  listen("wallet://unlocked", () => cb());

export const onWalletLocked = (
  cb: (p: WalletLockedPayload) => void,
): Promise<UnlistenFn> =>
  listen<WalletLockedPayload>("wallet://locked", (e) => cb(e.payload));

export const onNewCoinbase = (
  cb: (p: NewCoinbasePayload) => void,
): Promise<UnlistenFn> =>
  listen<NewCoinbasePayload>("wallet://new_coinbase", (e) => cb(e.payload));

export const onUpdateAvailable = (
  cb: (p: UpdateInfo) => void,
): Promise<UnlistenFn> =>
  listen<UpdateInfo>("update://available", (e) => cb(e.payload));

// ── V2 transaction lifecycle events ──────────────────────────────────────────

export interface PendingChangedPayload {
  count: number;
}
export interface TxBroadcastPayload {
  tx_id: string;
  mode: string;
  txid_chain: string;
}
export interface TxConfirmedPayload {
  tx_id: string;
  mode: string;
  txid_chain: string;
  height: number;
  confirmations: number;
}
export interface TxExpiredPayload {
  tx_id: string;
  reason: string;
}

export const onPendingChanged = (
  cb: (p: PendingChangedPayload) => void,
): Promise<UnlistenFn> =>
  listen<PendingChangedPayload>("wallet://pending_changed", (e) => cb(e.payload));

export const onTxBroadcast = (
  cb: (p: TxBroadcastPayload) => void,
): Promise<UnlistenFn> =>
  listen<TxBroadcastPayload>("tx://broadcast", (e) => cb(e.payload));

export const onTxConfirmed = (
  cb: (p: TxConfirmedPayload) => void,
): Promise<UnlistenFn> =>
  listen<TxConfirmedPayload>("tx://confirmed", (e) => cb(e.payload));

export const onTxExpired = (
  cb: (p: TxExpiredPayload) => void,
): Promise<UnlistenFn> =>
  listen<TxExpiredPayload>("tx://expired", (e) => cb(e.payload));
