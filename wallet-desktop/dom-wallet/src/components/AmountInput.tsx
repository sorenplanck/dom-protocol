import { nomsToDom } from "../lib/format";

interface Props {
  value: string;
  onChange: (v: string) => void;
  availableNoms?: number | null;
  label?: string;
}

/** DOM amount input. Accepts up to 8 decimals; shows spendable balance. */
export function AmountInput({ value, onChange, availableNoms, label }: Props) {
  const sanitize = (raw: string) => {
    // allow digits and a single dot, max 8 decimals
    let s = raw.replace(/[^0-9.]/g, "");
    const firstDot = s.indexOf(".");
    if (firstDot >= 0) {
      s =
        s.slice(0, firstDot + 1) +
        s.slice(firstDot + 1).replace(/\./g, "").slice(0, 8);
    }
    onChange(s);
  };
  return (
    <div>
      <label>{label ?? "Amount"}</label>
      <div style={{ position: "relative" }}>
        <input
          inputMode="decimal"
          value={value}
          placeholder="0.00000000"
          onChange={(e) => sanitize(e.target.value)}
          style={{ fontFamily: "var(--font-mono)", paddingRight: 52 }}
        />
        <span
          className="faint"
          style={{ position: "absolute", right: 12, top: 10, fontSize: 13 }}
        >
          DOM
        </span>
      </div>
      {availableNoms != null && (
        <div className="faint" style={{ fontSize: 12, marginTop: 6 }}>
          Available: {nomsToDom(availableNoms)} DOM (spendable)
        </div>
      )}
    </div>
  );
}
