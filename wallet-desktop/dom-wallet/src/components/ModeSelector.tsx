import type { TxMode } from "../lib/tauri";

interface Props {
  mode: TxMode;
  onChange: (m: TxMode) => void;
  context: "send" | "receive";
}

/** Radio between Slatepack (Mode A) and Simple (Mode B). */
export function ModeSelector({ mode, onChange, context }: Props) {
  const labels =
    context === "send"
      ? { a: "Recommended", b: "Trusted parties only" }
      : { a: "Address-based", b: "Direct request" };
  return (
    <div className="mode-selector">
      <button
        className={`mode-pill ${mode === "slatepack" ? "active" : ""}`}
        onClick={() => onChange("slatepack")}
      >
        <span className="mode-title">Slatepack</span>
        <span className="mode-sub">{labels.a}</span>
      </button>
      <button
        className={`mode-pill ${mode === "simple" ? "active" : ""}`}
        onClick={() => onChange("simple")}
      >
        <span className="mode-title">Simple</span>
        <span className="mode-sub">{labels.b}</span>
      </button>
    </div>
  );
}
