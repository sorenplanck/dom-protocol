import { useState } from "react";

interface Props {
  value: string;
  onChange: (v: string) => void;
  placeholder?: string;
  label?: string;
  autoFocus?: boolean;
  onEnter?: () => void;
}

/** Password field with a show/hide toggle. */
export function PasswordInput({
  value,
  onChange,
  placeholder,
  label,
  autoFocus,
  onEnter,
}: Props) {
  const [show, setShow] = useState(false);
  return (
    <div>
      {label && <label>{label}</label>}
      <div style={{ position: "relative" }}>
        <input
          type={show ? "text" : "password"}
          value={value}
          autoFocus={autoFocus}
          placeholder={placeholder ?? "Password"}
          onChange={(e) => onChange(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === "Enter" && onEnter) onEnter();
          }}
          style={{ paddingRight: 58 }}
        />
        <button
          type="button"
          className="ghost"
          onClick={() => setShow((s) => !s)}
          style={{
            position: "absolute",
            right: 4,
            top: 4,
            bottom: 4,
            padding: "0 10px",
            fontSize: 12,
          }}
        >
          {show ? "Hide" : "Show"}
        </button>
      </div>
    </div>
  );
}
