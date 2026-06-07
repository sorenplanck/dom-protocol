import { useEffect, useState } from "react";
import {
  slatepackGetAddress,
  slatepackGenerateNewAddress,
  slatepackReceive,
  simpleCreateReceiveRequest,
  settingsGet,
  type TxMode,
  type SlateReceivedResponse,
  type DescriptorCreatedResponse,
} from "../lib/tauri";
import { ModeSelector } from "../components/ModeSelector";
import { AmountInput } from "../components/AmountInput";
import { SlatepackOutput } from "../components/SlatepackOutput";
import { SlatepackInput } from "../components/SlatepackInput";
import { DescriptorOutput } from "../components/DescriptorOutput";

export function Receive() {
  const [mode, setMode] = useState<TxMode>("slatepack");
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    settingsGet()
      .then((s) => setMode((s.default_tx_mode as TxMode) ?? "slatepack"))
      .catch(() => {});
  }, []);

  return (
    <div className="page reveal">
      <h1>Receive DOM</h1>
      <ModeSelector mode={mode} onChange={setMode} context="receive" />
      {error && <div className="alert error">{error}</div>}
      {mode === "slatepack" ? (
        <SlatepackReceive setError={setError} />
      ) : (
        <SimpleReceive setError={setError} />
      )}
    </div>
  );
}

function SlatepackReceive({ setError }: { setError: (e: string | null) => void }) {
  const [address, setAddress] = useState("");
  const [incoming, setIncoming] = useState("");
  const [response, setResponse] = useState<SlateReceivedResponse | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    slatepackGetAddress().then(setAddress).catch((e) => setError(String(e)));
  }, [setError]);

  const regenerate = async () => {
    try {
      setAddress(await slatepackGenerateNewAddress());
    } catch (e) {
      setError(String(e));
    }
  };

  const process = async () => {
    setError(null);
    setBusy(true);
    try {
      setResponse(await slatepackReceive(incoming.trim()));
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="col" style={{ gap: 16 }}>
      <div>
        <label>Your Slatepack address</label>
        {address ? (
          <SlatepackOutput value={address} />
        ) : (
          <p className="faint">Generating…</p>
        )}
        <div className="row" style={{ marginTop: 8 }}>
          <button onClick={regenerate}>🔄 Generate new</button>
        </div>
      </div>
      <hr />
      {response ? (
        <div className="col" style={{ gap: 12 }}>
          <p>Send this response back to the sender:</p>
          <SlatepackOutput value={response.response_slatepack} />
          <div className="alert warn">
            Note: this response is not encrypted to the sender (their address
            isn't part of the slate they sent you), so the slate contents are
            visible to anyone who sees it in transit. Return it over a private
            channel. Your wallet secrets are never in the slate.
          </div>
          <p className="faint">
            The sender finalizes and broadcasts. You'll see the payment in
            History after confirmations.
          </p>
        </div>
      ) : (
        <div className="col" style={{ gap: 12 }}>
          <p className="faint">
            Share your address with the sender. When they send you their
            Slatepack, paste it below:
          </p>
          <SlatepackInput
            value={incoming}
            onChange={setIncoming}
            placeholder="Paste sender's Slatepack…"
          />
          <div className="row">
            <button
              className="primary"
              onClick={process}
              disabled={busy || !incoming.trim()}
            >
              {busy ? "Processing…" : "Process Slate"}
            </button>
          </div>
        </div>
      )}
    </div>
  );
}

const EXPIRY_OPTIONS: Array<{ label: string; hours: number }> = [
  { label: "1 hour", hours: 1 },
  { label: "6 hours", hours: 6 },
  { label: "24 hours", hours: 24 },
  { label: "7 days", hours: 168 },
];

function SimpleReceive({ setError }: { setError: (e: string | null) => void }) {
  const [amount, setAmount] = useState("");
  const [minFee, setMinFee] = useState("0.001");
  const [maxFee, setMaxFee] = useState("0.05");
  const [expiry, setExpiry] = useState(24);
  const [created, setCreated] = useState<DescriptorCreatedResponse | null>(null);
  const [busy, setBusy] = useState(false);

  const generate = async () => {
    setError(null);
    setBusy(true);
    try {
      setCreated(
        await simpleCreateReceiveRequest(amount, minFee, maxFee, expiry),
      );
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  };

  if (created) {
    return (
      <div className="col" style={{ gap: 12 }}>
        <p>Share this descriptor with the sender:</p>
        <DescriptorOutput value={created.descriptor} />
        <p className="faint">
          Expires {new Date(created.expires_at * 1000).toLocaleString()}. When
          the sender broadcasts, you'll see it in History.
        </p>
      </div>
    );
  }

  return (
    <div className="col" style={{ gap: 16 }}>
      <div className="alert warn">
        Simple mode descriptor is NOT encrypted in transit (the embedded
        blinding factor is). Share only over secure channels or with trusted
        parties.
      </div>
      <AmountInput value={amount} onChange={setAmount} label="Expected amount" />
      <div className="row" style={{ gap: 16 }}>
        <div style={{ flex: 1 }}>
          <label>Min fee (DOM)</label>
          <input value={minFee} onChange={(e) => setMinFee(e.target.value)} />
        </div>
        <div style={{ flex: 1 }}>
          <label>Max fee (DOM)</label>
          <input value={maxFee} onChange={(e) => setMaxFee(e.target.value)} />
        </div>
      </div>
      <div>
        <label>Descriptor expiry</label>
        <div className="row" style={{ flexWrap: "wrap", gap: 8 }}>
          {EXPIRY_OPTIONS.map((o) => (
            <button
              key={o.hours}
              className={expiry === o.hours ? "primary" : ""}
              onClick={() => setExpiry(o.hours)}
            >
              {o.label}
            </button>
          ))}
        </div>
      </div>
      <div className="row">
        <button
          className="primary"
          onClick={generate}
          disabled={busy || !amount}
        >
          {busy ? "Generating…" : "Generate Receive Request"}
        </button>
      </div>
    </div>
  );
}
