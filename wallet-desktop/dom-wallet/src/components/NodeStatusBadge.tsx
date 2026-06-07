import type { NodeStatusView } from "../lib/tauri";

interface Props {
  running: boolean;
  status: NodeStatusView | null;
}

/** Compact node state pill used in the top bar and dashboard. */
export function NodeStatusBadge({ running, status }: Props) {
  if (!running) {
    return (
      <span className="status-badge err">
        <span className="dot" /> Node stopped
      </span>
    );
  }
  if (status?.mining_active) {
    return (
      <span className="status-badge mining">
        <span className="dot" /> Mining
      </span>
    );
  }
  return (
    <span className="status-badge ok">
      <span className="dot" /> Running
    </span>
  );
}
