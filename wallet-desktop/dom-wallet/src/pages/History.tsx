import { useEffect, useState } from "react";
import { nomsToDom, formatDate } from "../lib/format";
import {
  getFullTransactionHistory,
  type TransactionRecord,
} from "../lib/tauri";
import { TxDetailsModal } from "../components/TxDetailsModal";

/** A coinbase record accumulated from `wallet://new_coinbase` events. */
export interface CoinbaseRecord {
  height: number;
  valueNoms: number;
  timestamp: number;
  hash?: string;
}

interface Props {
  records: CoinbaseRecord[];
  chainHeight: number;
}

const COINBASE_MATURITY = 1000;
type Filter = "all" | "slatepack" | "simple" | "coinbase";

export function History({ records, chainHeight }: Props) {
  const [selected, setSelected] = useState<TransactionRecord | null>(null);
  const [txs, setTxs] = useState<TransactionRecord[]>([]);
  const [filter, setFilter] = useState<Filter>("all");

  useEffect(() => {
    getFullTransactionHistory({ mode: null, direction: null })
      .then(setTxs)
      .catch(() => setTxs([]));
  }, []);

  // Coinbase records → unified TransactionRecord shape.
  const coinbase: TransactionRecord[] = records.map((r) => {
    const conf = chainHeight - r.height;
    const mature = conf >= COINBASE_MATURITY;
    return {
      id: `cb-${r.height}`,
      kind: "coinbase",
      mode: null,
      amount_noms: r.valueNoms,
      state: mature ? "Mature" : `${Math.max(conf, 0)}/${COINBASE_MATURITY}`,
      created_at: r.timestamp,
      txid: r.hash ?? null,
    };
  });

  const all = [...txs, ...coinbase].sort((a, b) => b.created_at - a.created_at);
  const shown = all.filter((t) => {
    if (filter === "all") return true;
    if (filter === "coinbase") return t.kind === "coinbase";
    return t.mode === filter;
  });

  const typeIcon = (k: string) =>
    k === "sent" ? "⬆ Sent" : k === "received" ? "⬇ Recv" : "⛏ Coinbase";
  const amountClass = (k: string) =>
    k === "sent" ? "amount-neg" : "amount-pos";
  const amountSign = (k: string) => (k === "sent" ? "-" : "+");

  return (
    <div>
      <div className="card reveal">
        <div className="row" style={{ justifyContent: "space-between" }}>
          <h2>Transaction History</h2>
          <div className="row" style={{ gap: 6 }}>
            {(["all", "slatepack", "simple", "coinbase"] as Filter[]).map((f) => (
              <button
                key={f}
                className={filter === f ? "primary" : ""}
                onClick={() => setFilter(f)}
              >
                {f[0].toUpperCase() + f.slice(1)}
              </button>
            ))}
          </div>
        </div>
        {shown.length === 0 ? (
          <p className="muted">No transactions yet for this filter.</p>
        ) : (
          <table className="history">
            <thead>
              <tr>
                <th>Date</th>
                <th>Type</th>
                <th>Mode</th>
                <th>Amount</th>
                <th>Status</th>
              </tr>
            </thead>
            <tbody>
              {shown.map((t) => (
                <tr key={t.id} onClick={() => setSelected(t)}>
                  <td>{formatDate(t.created_at)}</td>
                  <td>{typeIcon(t.kind)}</td>
                  <td className="muted">
                    {t.mode ? t.mode[0].toUpperCase() + t.mode.slice(1) : "—"}
                  </td>
                  <td className={amountClass(t.kind)}>
                    {amountSign(t.kind)}
                    {nomsToDom(t.amount_noms)}
                  </td>
                  <td className="muted">{t.state}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
        <p className="faint" style={{ marginTop: 12, fontSize: 12 }}>
          Click a row for details.
        </p>
      </div>
      <TxDetailsModal tx={selected} onClose={() => setSelected(null)} />
    </div>
  );
}
