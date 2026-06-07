import { useMemo } from "react";

interface Props {
  value: string;
  onChange: (v: string) => void;
}

/** Free-form 24-word seed entry (textarea). Validates word count and basic
 *  shape; the authoritative BIP-39 wordlist check happens in the Rust crate on
 *  recover. */
export function SeedPhraseInput({ value, onChange }: Props) {
  const words = useMemo(
    () => value.trim().split(/\s+/).filter(Boolean),
    [value],
  );
  const count = words.length;
  const ok = count === 24;

  return (
    <div>
      <label>Recovery phrase (24 words)</label>
      <textarea
        rows={4}
        value={value}
        placeholder="Enter your 24-word recovery phrase, separated by spaces"
        onChange={(e) => onChange(e.target.value.toLowerCase())}
        style={{ fontFamily: "var(--font-mono)", resize: "vertical" }}
      />
      <div
        className={count === 0 ? "faint" : ok ? "muted" : "error-text"}
        style={{ marginTop: 6, fontSize: 12 }}
      >
        {count} / 24 words
        {count > 0 && !ok && " — a DOM recovery phrase has exactly 24 words"}
      </div>
    </div>
  );
}

/** Exposed for tests + the caller's submit gate. */
export function isLikelyValidPhrase(value: string): boolean {
  return value.trim().split(/\s+/).filter(Boolean).length === 24;
}
