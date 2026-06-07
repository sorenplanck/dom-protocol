import type { TransactionRecord } from "../lib/tauri";
import { nomsToDom, formatDate, shortHex } from "../lib/format";

interface Props {
  tx: TransactionRecord | null;
  onClose: () => void;
}

/** Full transaction details for a history row (both modes + coinbase). */
export function TxDetailsModal({ tx, onClose }: Props) {
  if (!tx) return null;
  const kindLabel =
    tx.kind === "sent" ? "Sent" : tx.kind === "received" ? "Received" : "Coinbase";
  const sign = tx.kind === "sent" ? "-" : "+";
  return (
    <div className="modal-backdrop" onClick={onClose}>
      <div className="modal" onClick={(e) => e.stopPropagation()}>
        <h3>{kindLabel} transaction</h3>
        <div className="kv">
          <span>Amount</span>
          <span className="mono">
            {sign}
            {nomsToDom(tx.amount_noms)} DOM
          </span>
        </div>
        {tx.mode && (
          <div className="kv">
            <span>Mode</span>
            <span>{tx.mode === "slatepack" ? "Slatepack" : "Simple"}</span>
          </div>
        )}
        <div className="kv">
          <span>Status</span>
          <span>{tx.state}</span>
        </div>
        <div className="kv">
          <span>Date</span>
          <span>{formatDate(tx.created_at)}</span>
        </div>
        {tx.txid && (
          <div className="kv">
            <span>Tx ID</span>
            <span className="mono" style={{ fontSize: 12 }}>
              {shortHex(tx.txid)}
            </span>
          </div>
        )}
        <div className="kv">
          <span>Internal ID</span>
          <span className="mono" style={{ fontSize: 12 }}>
            {tx.id.slice(0, 18)}…
          </span>
        </div>
        <div className="row" style={{ marginTop: 16 }}>
          <span style={{ flex: 1 }} />
          <button className="primary" onClick={onClose}>
            Close
          </button>
        </div>
      </div>
    </div>
  );
}
