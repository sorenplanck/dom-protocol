import { nomsToDom } from "../lib/format";

interface Props {
  open: boolean;
  amountNoms: number;
  feeNoms: number;
  mode: "slatepack" | "simple";
  recipient?: string;
  busy?: boolean;
  onConfirm: () => void;
  onCancel: () => void;
}

/** "Are you sure?" confirmation before building/broadcasting a send. */
export function ConfirmSendModal({
  open,
  amountNoms,
  feeNoms,
  mode,
  recipient,
  busy,
  onConfirm,
  onCancel,
}: Props) {
  if (!open) return null;
  const total = amountNoms + feeNoms;
  return (
    <div className="modal-backdrop" onClick={onCancel}>
      <div className="modal" onClick={(e) => e.stopPropagation()}>
        <h3>Confirm send</h3>
        <div className="kv">
          <span>Amount</span>
          <span className="mono">{nomsToDom(amountNoms)} DOM</span>
        </div>
        <div className="kv">
          <span>Fee</span>
          <span className="mono">{nomsToDom(feeNoms)} DOM</span>
        </div>
        <div className="kv" style={{ fontWeight: 600 }}>
          <span>Total</span>
          <span className="mono">{nomsToDom(total)} DOM</span>
        </div>
        <div className="kv">
          <span>Mode</span>
          <span>{mode === "slatepack" ? "Slatepack" : "Simple"}</span>
        </div>
        {recipient && (
          <div className="kv">
            <span>Recipient</span>
            <span className="mono" style={{ fontSize: 12 }}>
              {recipient.slice(0, 24)}…
            </span>
          </div>
        )}
        {mode === "slatepack" && (
          <p className="faint" style={{ fontSize: 13 }}>
            This creates a slate to share with the recipient. Your inputs are
            reserved until you finalize, cancel, or it expires.
          </p>
        )}
        <div className="row" style={{ marginTop: 16 }}>
          <span style={{ flex: 1 }} />
          <button onClick={onCancel} disabled={busy}>
            Cancel
          </button>
          <button className="primary" onClick={onConfirm} disabled={busy}>
            {busy ? "Working…" : mode === "slatepack" ? "Create Slate" : "Send Now"}
          </button>
        </div>
      </div>
    </div>
  );
}
