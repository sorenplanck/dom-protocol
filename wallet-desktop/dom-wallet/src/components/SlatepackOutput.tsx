import { useEffect, useRef, useState } from "react";
import QRCode from "qrcode";

interface Props {
  value: string;
  label?: string;
}

/** Shows a slatepack/descriptor string with copy and QR display. */
export function SlatepackOutput({ value, label }: Props) {
  const [showQr, setShowQr] = useState(false);
  const [copied, setCopied] = useState(false);
  const canvasRef = useRef<HTMLCanvasElement>(null);

  useEffect(() => {
    if (showQr && canvasRef.current) {
      QRCode.toCanvas(canvasRef.current, value, { width: 240, margin: 1 }).catch(
        () => {},
      );
    }
  }, [showQr, value]);

  const copy = async () => {
    try {
      await navigator.clipboard.writeText(value);
    } catch {
      /* clipboard unavailable; user can select the text manually */
    }
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  };

  return (
    <div>
      {label && <label>{label}</label>}
      <div className="slate-box mono">{value}</div>
      <div className="row" style={{ marginTop: 8 }}>
        <button onClick={copy}>{copied ? "Copied ✓" : "📋 Copy"}</button>
        <button onClick={() => setShowQr((q) => !q)}>
          {showQr ? "Hide QR" : "📷 Show QR"}
        </button>
      </div>
      {showQr && (
        <div style={{ marginTop: 12, textAlign: "center" }}>
          <canvas ref={canvasRef} style={{ background: "#fff", borderRadius: 8 }} />
        </div>
      )}
    </div>
  );
}
