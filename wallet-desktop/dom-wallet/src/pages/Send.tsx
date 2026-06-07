import { useEffect, useState } from "react";
import {
  walletBalance,
  settingsGet,
  slatepackCreateSend,
  slatepackFinalize,
  simpleParseDescriptor,
  simpleSendToDescriptor,
  type BalanceInfo,
  type TxMode,
  type DescriptorInfo,
  type SlateCreatedResponse,
} from "../lib/tauri";
import { nomsToDom } from "../lib/format";
import { ModeSelector } from "../components/ModeSelector";
import { AmountInput } from "../components/AmountInput";
import { FeeSelector } from "../components/FeeSelector";
import { SlatepackOutput } from "../components/SlatepackOutput";
import { SlatepackInput } from "../components/SlatepackInput";
import { DescriptorInput } from "../components/DescriptorInput";
import { ConfirmSendModal } from "../components/ConfirmSendModal";

export function Send() {
  const [mode, setMode] = useState<TxMode>("slatepack");
  const [balance, setBalance] = useState<BalanceInfo | null>(null);
  const [advancedFees, setAdvancedFees] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    walletBalance().then(setBalance).catch(() => {});
    settingsGet()
      .then((s) => {
        setMode((s.default_tx_mode as TxMode) ?? "slatepack");
        setAdvancedFees(s.tx_show_advanced_fees);
      })
      .catch(() => {});
  }, []);

  return (
    <div className="page reveal">
      <h1>Send DOM</h1>
      <ModeSelector mode={mode} onChange={setMode} context="send" />
      {error && <div className="alert error">{error}</div>}
      {mode === "slatepack" ? (
        <SlatepackSend
          balance={balance}
          advancedFees={advancedFees}
          setError={setError}
          busy={busy}
          setBusy={setBusy}
        />
      ) : (
        <SimpleSend
          balance={balance}
          advancedFees={advancedFees}
          setError={setError}
          busy={busy}
          setBusy={setBusy}
        />
      )}
    </div>
  );
}

interface SubProps {
  balance: BalanceInfo | null;
  advancedFees: boolean;
  setError: (e: string | null) => void;
  busy: boolean;
  setBusy: (b: boolean) => void;
}

function SlatepackSend({ balance, advancedFees, setError, busy, setBusy }: SubProps) {
  const [recipient, setRecipient] = useState("");
  const [amount, setAmount] = useState("");
  const [fee, setFee] = useState("0.01");
  const [confirm, setConfirm] = useState(false);
  const [created, setCreated] = useState<SlateCreatedResponse | null>(null);
  const [response, setResponse] = useState("");
  const [done, setDone] = useState<string | null>(null);

  const submit = async () => {
    setError(null);
    setBusy(true);
    try {
      const res = await slatepackCreateSend(recipient.trim(), amount, fee);
      setCreated(res);
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
      setConfirm(false);
    }
  };

  const finalize = async () => {
    if (!created) return;
    setError(null);
    setBusy(true);
    try {
      const res = await slatepackFinalize(created.slate_id, response.trim());
      setDone(res.txid_chain);
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  };

  if (done) {
    return (
      <div className="alert success">
        Transaction broadcast. Chain txid: <span className="mono">{done}</span>
      </div>
    );
  }

  if (created) {
    return (
      <div className="col" style={{ gap: 16 }}>
        <p>Share this Slatepack with the recipient:</p>
        <SlatepackOutput value={created.slatepack} />
        <p className="faint">
          Slate expires {new Date(created.expires_at * 1000).toLocaleString()}.
          Your inputs are reserved until you finalize or cancel.
        </p>
        <SlatepackInput
          label="Once the recipient sends back their response, paste it to finalize:"
          value={response}
          onChange={setResponse}
          placeholder="Paste response Slatepack…"
        />
        <div className="row">
          <button
            className="primary"
            onClick={finalize}
            disabled={busy || !response.trim()}
          >
            {busy ? "Finalizing…" : "Finalize Transaction"}
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="col" style={{ gap: 16 }}>
      <div>
        <label>Recipient Slatepack address</label>
        <input
          value={recipient}
          placeholder="dom1…"
          onChange={(e) => setRecipient(e.target.value)}
          style={{ fontFamily: "var(--font-mono)" }}
        />
      </div>
      <AmountInput
        value={amount}
        onChange={setAmount}
        availableNoms={balance?.spendable}
      />
      <FeeSelector value={fee} onChange={setFee} showAdvanced={advancedFees} />
      <div className="row">
        <button
          className="primary"
          onClick={() => setConfirm(true)}
          disabled={busy || !recipient.trim() || !amount}
        >
          Create Slate
        </button>
      </div>
      <ConfirmSendModal
        open={confirm}
        amountNoms={Math.round(parseFloat(amount || "0") * 1e8)}
        feeNoms={Math.round(parseFloat(fee || "0") * 1e8)}
        mode="slatepack"
        recipient={recipient}
        busy={busy}
        onConfirm={submit}
        onCancel={() => setConfirm(false)}
      />
    </div>
  );
}

function SimpleSend({ balance, advancedFees, setError, busy, setBusy }: SubProps) {
  const [descriptor, setDescriptor] = useState("");
  const [info, setInfo] = useState<DescriptorInfo | null>(null);
  const [fee, setFee] = useState("0.01");
  const [confirm, setConfirm] = useState(false);
  const [done, setDone] = useState<string | null>(null);

  const parse = async (text: string) => {
    setDescriptor(text);
    setInfo(null);
    if (!text.trim().startsWith("DOMRR1")) return;
    try {
      setInfo(await simpleParseDescriptor(text.trim()));
    } catch (e) {
      setError(String(e));
    }
  };

  const send = async () => {
    setError(null);
    setBusy(true);
    try {
      const res = await simpleSendToDescriptor(descriptor.trim(), fee);
      setDone(res.txid_chain);
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
      setConfirm(false);
    }
  };

  if (done) {
    return (
      <div className="alert success">
        Transaction broadcast. Chain txid: <span className="mono">{done}</span>
      </div>
    );
  }

  return (
    <div className="col" style={{ gap: 16 }}>
      <div className="alert warn">
        Simple mode does not encrypt the descriptor. Use only over secure
        channels or with parties you trust.
      </div>
      <DescriptorInput
        label="Receive Descriptor (from recipient)"
        value={descriptor}
        onChange={parse}
      />
      {info && (
        <div className="parsed">
          <div className="kv">
            <span>Expected amount</span>
            <span className="mono">{nomsToDom(info.amount_noms)} DOM</span>
          </div>
          <div className="kv">
            <span>Fee range</span>
            <span className="mono">
              {nomsToDom(info.fee_min_noms)} – {nomsToDom(info.fee_max_noms)} DOM
            </span>
          </div>
          <div className="kv">
            <span>Network</span>
            <span>{info.network}</span>
          </div>
          <div className="kv">
            <span>Status</span>
            <span>{info.expired ? "Expired" : "Active"}</span>
          </div>
        </div>
      )}
      <FeeSelector value={fee} onChange={setFee} showAdvanced={advancedFees} />
      <AmountInput
        value={info ? nomsToDom(info.amount_noms) : ""}
        onChange={() => {}}
        availableNoms={balance?.spendable}
        label="Amount (from descriptor)"
      />
      <div className="row">
        <button
          className="primary"
          onClick={() => setConfirm(true)}
          disabled={busy || !info || info.expired}
        >
          Send Now
        </button>
      </div>
      <ConfirmSendModal
        open={confirm}
        amountNoms={info?.amount_noms ?? 0}
        feeNoms={Math.round(parseFloat(fee || "0") * 1e8)}
        mode="simple"
        busy={busy}
        onConfirm={send}
        onCancel={() => setConfirm(false)}
      />
    </div>
  );
}
