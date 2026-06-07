interface Props {
  value: string;
  onChange: (v: string) => void;
  placeholder?: string;
  label?: string;
}

/** Paste area for an incoming Slatepack or descriptor string.
 *  QR scanning is an optional V2 affordance; webcam scanning is deferred (the
 *  brief marks QRScanner optional), so this offers paste, which always works. */
export function SlatepackInput({ value, onChange, placeholder, label }: Props) {
  return (
    <div>
      {label && <label>{label}</label>}
      <textarea
        rows={4}
        value={value}
        placeholder={placeholder ?? "Paste here…"}
        onChange={(e) => onChange(e.target.value)}
        style={{ fontFamily: "var(--font-mono)", fontSize: 12, resize: "vertical" }}
      />
    </div>
  );
}
