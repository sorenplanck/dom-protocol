import { BalanceCard } from "../components/BalanceCard";
import { PendingWidget } from "../components/PendingWidget";
import type { BalanceInfo, NodeStatusView, NodeRunning } from "../lib/tauri";
import { formatHashrate, nomsToDom } from "../lib/format";

interface Props {
  balance: BalanceInfo | null;
  status: NodeStatusView | null;
  node: NodeRunning | null;
  sessionBlocks: number;
  coinbaseHeights: number[];
}

const COINBASE_MATURITY = 1000;

export function Dashboard({
  balance,
  status,
  node,
  sessionBlocks,
  coinbaseHeights,
}: Props) {
  const height = status?.chain_height ?? 0;
  const running = node?.running ?? false;

  // Up to 3 most recent immature coinbases → maturity progress bars.
  const maturing = coinbaseHeights
    .filter((h) => height - h < COINBASE_MATURITY)
    .slice(-3)
    .reverse();

  return (
    <div>
      <div className="grid-2">
        <BalanceCard balance={balance} />

        <div className="card reveal">
          <h2>Node status</h2>
          <div className="kv">
            <span className="k">Network</span>
            <span className="v">{status?.network ?? "—"}</span>
          </div>
          <div className="kv">
            <span className="k">Chain height</span>
            <span className="v mono">{height.toLocaleString()}</span>
          </div>
          <div className="kv">
            <span className="k">Peers</span>
            <span className="v">{running ? `${status?.peer_count ?? 0} connected` : "—"}</span>
          </div>
          <div className="kv">
            <span className="k">Mining</span>
            <span className="v">
              {status?.mining_active
                ? `⛏ Active (${formatHashrate(status?.hashrate ?? 0)})`
                : running
                  ? "Idle"
                  : "—"}
            </span>
          </div>
          <div className="kv">
            <span className="k">Blocks mined</span>
            <span className="v mono">
              {sessionBlocks} this session, {status?.blocks_mined ?? 0} all-time
            </span>
          </div>
          <div className="kv">
            <span className="k">Mempool</span>
            <span className="v mono">{status?.mempool_size ?? 0} txs</span>
          </div>
        </div>
      </div>

      <PendingWidget />

      {maturing.length > 0 && (
        <div className="card reveal">
          <h2>Coinbase maturity</h2>
          {maturing.map((h) => {
            const progress = Math.min(height - h, COINBASE_MATURITY);
            const pct = (progress / COINBASE_MATURITY) * 100;
            return (
              <div key={h} style={{ marginBottom: 16 }}>
                <div className="kv" style={{ paddingBottom: 6 }}>
                  <span className="k mono">
                    Block {h.toLocaleString()} → matures at{" "}
                    {(h + COINBASE_MATURITY).toLocaleString()}
                  </span>
                  <span className="v mono">
                    {progress} / {COINBASE_MATURITY} blocks
                  </span>
                </div>
                <div className="progress">
                  <span style={{ width: `${pct}%` }} />
                </div>
              </div>
            );
          })}
          <p className="faint" style={{ fontSize: 12, marginTop: 4 }}>
            Coinbase rewards become spendable after {COINBASE_MATURITY} confirmations. Each reward
            is {nomsToDom(3_300_000_000)} DOM at the current block subsidy.
          </p>
        </div>
      )}

      {!running && (
        <div className="card reveal">
          <p className="muted">
            Your node is not running. Start it from the <strong>Node</strong> tab to begin syncing
            and mining.
          </p>
        </div>
      )}
    </div>
  );
}
