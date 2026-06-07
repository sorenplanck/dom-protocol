import type { PendingTxInfo } from "../lib/tauri";
import { nomsToDom } from "../lib/format";

interface Props {
  tx: PendingTxInfo;
  onCancel: (id: string) => void;
  onShow?: (tx: PendingTxInfo) => void;
}

/** Map a pending state to a colour class + human label. */
function stateView(state: string): { cls: string; label: string } {
  const s = state.toLowerCase();
  if (s.includes("confirm")) return { cls: "ok", label: "Confirmed" };
  if (s.includes("broadcast") || s.includes("finalized"))
    return { cls: "info", label: "Awaiting blockchain confirmation" };
  if (s.includes("expired")) return { cls: "muted", label: "Expired — outputs released" };
  if (s.includes("cancelled")) return { cls: "muted", label: "Cancelled by you" };
  if (s.includes("failed")) return { cls: "err", label: "Failed" };
  return { cls: "warn", label: "Waiting for counterparty" };
}

function timeLeft(expiresAt: number): string {
  const secs = expiresAt - Math.floor(Date.now() / 1000);
  if (secs <= 0) return "expired";
  const h = Math.floor(secs / 3600);
  const m = Math.floor((secs % 3600) / 60);
  return h > 0 ? `${h}h ${m}m` : `${m}m`;
}

export function PendingTxCard({ tx, onCancel, onShow }: Props) {
  const sv = stateView(tx.state);
  const dir = tx.direction === "sent" ? "Sending" : "Receiving";
  const modeLabel = tx.mode === "slatepack" ? "Slatepack" : "Simple Mode";
  const canShow = tx.mode === "slatepack" || tx.direction === "received";

  return (
    <div className="pending-card">
      <div className="row" style={{ alignItems: "flex-start" }}>
        <span className={`status-badge ${sv.cls}`}>
          <span className="dot" />
        </span>
        <div style={{ flex: 1 }}>
          <div style={{ fontWeight: 600 }}>
            {dir} {nomsToDom(tx.amount_noms)} DOM via {modeLabel}
          </div>
          <div className="muted" style={{ fontSize: 13, marginTop: 2 }}>
            {sv.label}
          </div>
          <div className="faint" style={{ fontSize: 12, marginTop: 2 }}>
            Expires in {timeLeft(tx.expires_at)}
            {tx.counterparty_addr ? ` · ${tx.counterparty_addr.slice(0, 16)}…` : ""}
          </div>
        </div>
      </div>
      <div className="row" style={{ marginTop: 10 }}>
        <span style={{ flex: 1 }} />
        {canShow && onShow && (
          <button onClick={() => onShow(tx)}>
            {tx.mode === "slatepack" ? "Show Slatepack" : "Show Descriptor"}
          </button>
        )}
        <button className="danger" onClick={() => onCancel(tx.id)}>
          Cancel
        </button>
      </div>
    </div>
  );
}
