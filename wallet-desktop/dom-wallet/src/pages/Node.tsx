import { useState } from "react";
import { LogStream } from "../components/LogStream";
import { PasswordInput } from "../components/PasswordInput";
import type { NodeStatusView, NodeRunning } from "../lib/tauri";
import {
  nodeStart,
  nodeStop,
  nodeRestart,
  nodeSetMining,
  errMessage,
} from "../lib/tauri";
import { formatHashrate } from "../lib/format";

interface Props {
  node: NodeRunning | null;
  status: NodeStatusView | null;
  refresh: () => void;
}

/** Actions that touch the node need the wallet password (the node credits
 *  coinbase to the unlocked wallet). We prompt for it just-in-time and never
 *  retain it. */
type PendingAction =
  | { kind: "start" }
  | { kind: "restart" }
  | { kind: "mining"; enabled: boolean }
  | null;

export function NodePage({ node, status, refresh }: Props) {
  const [pending, setPending] = useState<PendingAction>(null);
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  const running = node?.running ?? false;

  const runPending = async () => {
    if (!pending) return;
    setBusy(true);
    setError("");
    try {
      if (pending.kind === "start") await nodeStart(password);
      else if (pending.kind === "restart") await nodeRestart(password);
      else if (pending.kind === "mining") await nodeSetMining(pending.enabled, password);
      setPassword("");
      setPending(null);
      refresh();
    } catch (e) {
      setError(errMessage(e));
    } finally {
      setBusy(false);
    }
  };

  const stop = async () => {
    setBusy(true);
    setError("");
    try {
      await nodeStop();
      refresh();
    } catch (e) {
      setError(errMessage(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div>
      <div className="card reveal">
        <div className="row" style={{ marginBottom: 16 }}>
          <span
            className={`status-badge ${running ? (status?.mining_active ? "mining" : "ok") : "err"}`}
          >
            <span className="dot" /> {running ? "Running" : "Stopped"}
          </span>
          <span style={{ flex: 1 }} />
          {running ? (
            <>
              <button disabled={busy} onClick={stop}>
                Stop
              </button>
              <button disabled={busy} onClick={() => setPending({ kind: "restart" })}>
                Restart
              </button>
            </>
          ) : (
            <button className="primary" disabled={busy} onClick={() => setPending({ kind: "start" })}>
              Start node
            </button>
          )}
        </div>

        <div className="grid-2">
          <div className="kv">
            <span className="k">Network</span>
            <span className="v">{status?.network ?? "—"}</span>
          </div>
          <div className="kv">
            <span className="k">Chain height</span>
            <span className="v mono">{(status?.chain_height ?? 0).toLocaleString()}</span>
          </div>
          <div className="kv">
            <span className="k">Peers</span>
            <span className="v">{running ? (status?.peer_count ?? 0) : "—"}</span>
          </div>
          <div className="kv">
            <span className="k">Hashrate</span>
            <span className="v mono">
              {status?.mining_active ? formatHashrate(status?.hashrate ?? 0) : "—"}
            </span>
          </div>
          <div className="kv">
            <span className="k">Mempool</span>
            <span className="v mono">{status?.mempool_size ?? 0} txs</span>
          </div>
          <div className="kv">
            <span className="k">Mining</span>
            <span className="v row" style={{ justifyContent: "flex-end", gap: 8 }}>
              {status?.mining_active ? "⛏ ON" : "OFF"}
              <button
                disabled={busy || !running}
                onClick={() =>
                  setPending({ kind: "mining", enabled: !(status?.mining_active ?? false) })
                }
              >
                Toggle
              </button>
            </span>
          </div>
        </div>
      </div>

      <div className="card reveal">
        <h2>Live logs</h2>
        <LogStream />
      </div>

      {pending && (
        <div className="center-screen" style={{ position: "fixed", inset: 0, background: "rgba(0,0,0,0.5)", zIndex: 50 }}>
          <div className="panel">
            <h2 style={{ marginBottom: 12 }}>
              {pending.kind === "start"
                ? "Start node"
                : pending.kind === "restart"
                  ? "Restart node"
                  : "Change mining"}
            </h2>
            <p className="muted" style={{ marginBottom: 14 }}>
              Enter your wallet password so the node can credit mined coinbase to your wallet.
            </p>
            <PasswordInput
              value={password}
              onChange={setPassword}
              autoFocus
              onEnter={runPending}
            />
            {error && <p className="error-text" style={{ marginTop: 12 }}>{error}</p>}
            <div className="row" style={{ marginTop: 18 }}>
              <button
                className="ghost"
                onClick={() => {
                  setPending(null);
                  setPassword("");
                  setError("");
                }}
              >
                Cancel
              </button>
              <span style={{ flex: 1 }} />
              <button className="primary" disabled={busy || !password} onClick={runPending}>
                {busy ? "Working…" : "Confirm"}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
