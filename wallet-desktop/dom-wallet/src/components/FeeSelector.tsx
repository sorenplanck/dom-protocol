import { useState } from "react";

interface Props {
  /** Selected fee in DOM string. */
  value: string;
  onChange: (domString: string) => void;
  showAdvanced?: boolean;
}

const PRESETS: Array<{ id: string; label: string; dom: string }> = [
  { id: "low", label: "Low", dom: "0.001" },
  { id: "standard", label: "Standard", dom: "0.01" },
  { id: "fast", label: "Fast", dom: "0.05" },
];

/** Fee preset selector with optional custom input. */
export function FeeSelector({ value, onChange, showAdvanced = true }: Props) {
  const matchedPreset = PRESETS.find((p) => p.dom === value)?.id ?? "custom";
  const [choice, setChoice] = useState<string>(matchedPreset);

  const pick = (id: string) => {
    setChoice(id);
    const preset = PRESETS.find((p) => p.id === id);
    if (preset) onChange(preset.dom);
  };

  return (
    <div>
      <label>Fee</label>
      <div className="col" style={{ gap: 6 }}>
        {PRESETS.map((p) => (
          <label key={p.id} className="radio-row">
            <input
              type="radio"
              name="fee"
              checked={choice === p.id}
              onChange={() => pick(p.id)}
              style={{ width: "auto" }}
            />
            {p.label} ({p.dom} DOM)
            {p.id === "standard" && <span className="faint"> — recommended</span>}
          </label>
        ))}
        {showAdvanced && (
          <label className="radio-row">
            <input
              type="radio"
              name="fee"
              checked={choice === "custom"}
              onChange={() => setChoice("custom")}
              style={{ width: "auto" }}
            />
            Custom:
            <input
              value={choice === "custom" ? value : ""}
              disabled={choice !== "custom"}
              onChange={(e) => onChange(e.target.value.replace(/[^0-9.]/g, ""))}
              placeholder="0.000"
              style={{ width: 120, marginLeft: 8, fontFamily: "var(--font-mono)" }}
            />
            <span className="faint">DOM</span>
          </label>
        )}
      </div>
    </div>
  );
}
