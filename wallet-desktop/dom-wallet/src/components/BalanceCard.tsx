import type { BalanceInfo } from "../lib/tauri";
import { nomsToDom } from "../lib/format";

interface Props {
  balance: BalanceInfo | null;
}

/** Prominent spendable/total/pending balance display (Dashboard). */
export function BalanceCard({ balance }: Props) {
  const spendable = balance?.spendable ?? 0;
  const total = balance?.total ?? 0;
  const immature = balance?.immature ?? 0;

  return (
    <div className="card reveal">
      <h2>Balance</h2>
      <div className="balance-big mono">
        {nomsToDom(spendable)}
        <span className="ticker">DOM</span>
      </div>
      <div style={{ marginTop: 14 }}>
        <div className="kv">
          <span className="k">Total (mature + immature)</span>
          <span className="v mono">{nomsToDom(total)} DOM</span>
        </div>
        <div className="kv">
          <span className="k">Pending mature (immature coinbase)</span>
          <span className="v mono">{nomsToDom(immature)} DOM</span>
        </div>
      </div>
    </div>
  );
}
