import { useCallback, useEffect, useState } from "react";
import {
  listPendingTxs,
  cancelPendingTx,
  type PendingTxInfo,
} from "../lib/tauri";
import { onPendingChanged } from "../lib/events";
import { PendingTxCard } from "./PendingTxCard";

/** Dashboard widget listing active pending transactions (both modes). */
export function PendingWidget() {
  const [pending, setPending] = useState<PendingTxInfo[]>([]);

  const refresh = useCallback(() => {
    listPendingTxs()
      .then(setPending)
      .catch(() => setPending([]));
  }, []);

  useEffect(() => {
    refresh();
    const un = onPendingChanged(() => refresh());
    return () => {
      un.then((f) => f()).catch(() => {});
    };
  }, [refresh]);

  const cancel = async (id: string) => {
    try {
      await cancelPendingTx(id);
    } catch {
      /* surfaced elsewhere */
    }
    refresh();
  };

  if (pending.length === 0) return null;

  return (
    <div className="card reveal">
      <h2>Pending Transactions — {pending.length} active</h2>
      <div className="col" style={{ gap: 12, marginTop: 8 }}>
        {pending.map((tx) => (
          <PendingTxCard key={tx.id} tx={tx} onCancel={cancel} />
        ))}
      </div>
    </div>
  );
}
