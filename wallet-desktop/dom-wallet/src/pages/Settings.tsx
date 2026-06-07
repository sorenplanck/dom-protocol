import { useEffect, useState } from "react";
import { open } from "@tauri-apps/plugin-dialog";
import { PasswordInput } from "../components/PasswordInput";
import {
  settingsGet,
  settingsUpdate,
  settingsAvailableCores,
  settingsExportBackup,
  walletVerifyPassword,
  updatesCheck,
  errMessage,
  type NodeSettings,
  type Theme,
} from "../lib/tauri";

interface Props {
  onThemeChange: (t: Theme) => void;
}

const AUTO_LOCK_OPTIONS: Array<{ label: string; value: number | null }> = [
  { label: "5 minutes", value: 5 },
  { label: "15 minutes", value: 15 },
  { label: "30 minutes", value: 30 },
  { label: "60 minutes", value: 60 },
  { label: "Never", value: null },
];

const APP_VERSION = "0.1.0";

export function Settings({ onThemeChange }: Props) {
  const [s, setS] = useState<NodeSettings | null>(null);
  const [cores, setCores] = useState(1);
  const [savedMsg, setSavedMsg] = useState("");
  const [error, setError] = useState("");

  // change-password fields

  // show-seed gate
  const [seedPw, setSeedPw] = useState("");
  const [seedMsg, setSeedMsg] = useState("");

  const [updateMsg, setUpdateMsg] = useState("");

  useEffect(() => {
    settingsGet().then(setS).catch((e) => setError(errMessage(e)));
    settingsAvailableCores().then(setCores).catch(() => setCores(1));
  }, []);

  if (!s) return <div className="muted">Loading settings…</div>;

  const update = (patch: Partial<NodeSettings>) => setS({ ...s, ...patch });

  const persist = async () => {
    setError("");
    setSavedMsg("");
    try {
      await settingsUpdate(s);
      setSavedMsg("Settings saved. Network or port changes take effect after a node restart.");
    } catch (e) {
      setError(errMessage(e));
    }
  };

  const chooseDir = async (key: "data_dir" | "wallet_dir" | "backup_dir") => {
    const dir = await open({ directory: true, multiple: false });
    if (typeof dir === "string") update({ [key]: dir } as Partial<NodeSettings>);
  };

  const doShowSeed = async () => {
    setSeedMsg("");
    try {
      const ok = await walletVerifyPassword(seedPw);
      setSeedPw("");
      if (!ok) {
        setSeedMsg("Incorrect password.");
        return;
      }
      // NOTE: dom-wallet does not re-derive the mnemonic from an opened wallet
      // (the encrypted store keeps seed bytes, not words). The phrase can only
      // be shown at creation time. We tell the user honestly.
      setSeedMsg(
        "Your recovery phrase can only be shown at wallet creation. If you saved it then, keep it safe — it cannot be re-displayed.",
      );
    } catch (e) {
      setSeedMsg(errMessage(e));
    }
  };

  const doExportBackup = async () => {
    setError("");
    try {
      const dir = await open({ directory: true, multiple: false, title: "Choose backup folder" });
      if (typeof dir !== "string") return;
      const n = await settingsExportBackup(dir);
      setSavedMsg(`Exported ${n} wallet file(s).`);
    } catch (e) {
      setError(errMessage(e));
    }
  };

  const doCheckUpdates = async () => {
    setUpdateMsg("Checking…");
    try {
      const info = await updatesCheck();
      setUpdateMsg(
        info.newer
          ? `Update available: ${info.latest}${info.mandatory ? " (MANDATORY)" : ""}.`
          : `You're up to date (${info.current}).`,
      );
    } catch (e) {
      setUpdateMsg(errMessage(e));
    }
  };

  return (
    <div>
      {/* Network */}
      <div className="card reveal">
        <h2>Network</h2>
        <div className="grid-2">
          <div>
            <label>Network</label>
            <select value={s.network} onChange={(e) => update({ network: e.target.value })}>
              <option value="testnet">testnet</option>
              <option value="mainnet">mainnet</option>
              <option value="regtest">regtest (dev)</option>
            </select>
          </div>
          <div>
            <label>Seed peers (comma-separated host:port)</label>
            <input
              value={s.seed_peers.join(", ")}
              onChange={(e) =>
                update({
                  seed_peers: e.target.value
                    .split(",")
                    .map((x) => x.trim())
                    .filter(Boolean),
                })
              }
              placeholder="seed1.dom.network:33370, seed2.dom.network:33370"
            />
          </div>
          <div>
            <label>P2P listen address</label>
            <input value={s.p2p_listen_addr} onChange={(e) => update({ p2p_listen_addr: e.target.value })} />
          </div>
          <div>
            <label>RPC listen address (loopback)</label>
            <input value={s.rpc_listen_addr} onChange={(e) => update({ rpc_listen_addr: e.target.value })} />
          </div>
        </div>
        <p className="faint" style={{ fontSize: 12, marginTop: 10 }}>
          Changing network or ports requires restarting the node.
        </p>
      </div>

      {/* Directories */}
      <div className="card reveal">
        <h2>Storage</h2>
        {(
          [
            ["Data directory", "data_dir"],
            ["Wallet directory", "wallet_dir"],
            ["Backup directory", "backup_dir"],
          ] as Array<[string, "data_dir" | "wallet_dir" | "backup_dir"]>
        ).map(([label, key]) => (
          <div key={key} style={{ marginBottom: 12 }}>
            <label>{label}</label>
            <div className="row">
              <input value={s[key]} readOnly style={{ fontFamily: "var(--font-mono)", fontSize: 12 }} />
              <button onClick={() => chooseDir(key)}>Change</button>
            </div>
          </div>
        ))}
        <button onClick={doExportBackup}>Export wallet backup</button>
      </div>

      {/* Security */}
      <div className="card reveal">
        <h2>Security</h2>
        <div className="grid-2">
          <div>
            <label>Auto-lock timeout</label>
            <select
              value={s.auto_lock_minutes === null ? "never" : String(s.auto_lock_minutes)}
              onChange={(e) =>
                update({
                  auto_lock_minutes: e.target.value === "never" ? null : Number(e.target.value),
                })
              }
            >
              {AUTO_LOCK_OPTIONS.map((o) => (
                <option key={o.label} value={o.value === null ? "never" : String(o.value)}>
                  {o.label}
                </option>
              ))}
            </select>
          </div>
        </div>

        <div style={{ marginTop: 18 }}>
          <label>Change password</label>
          <p className="faint" style={{ fontSize: 13, marginTop: 4 }}>
            Not available in this build — changing the password requires a
            wallet rekey capability that isn't exposed yet. Your current
            password continues to work.
          </p>
        </div>

        <div style={{ marginTop: 18 }}>
          <label>Show recovery phrase</label>
          <div className="warn-box">
            Revealing your recovery phrase exposes full control of your funds. Only do this somewhere
            private.
          </div>
          <div className="row" style={{ maxWidth: 360 }}>
            <PasswordInput value={seedPw} onChange={setSeedPw} placeholder="Confirm password" />
            <button onClick={doShowSeed} disabled={!seedPw}>
              Reveal
            </button>
          </div>
          {seedMsg && <p className="muted" style={{ marginTop: 8, fontSize: 13 }}>{seedMsg}</p>}
        </div>
      </div>

      {/* Mining */}
      <div className="card reveal">
        <h2>Mining</h2>
        <div className="grid-2">
          <div>
            <label>Mining</label>
            <select
              value={s.mining_enabled ? "on" : "off"}
              onChange={(e) => update({ mining_enabled: e.target.value === "on" })}
            >
              <option value="on">Enabled</option>
              <option value="off">Disabled</option>
            </select>
          </div>
          <div>
            <label>Mining threads (1–{cores})</label>
            <input
              type="number"
              min={1}
              max={cores}
              value={s.mining_threads}
              onChange={(e) =>
                update({
                  mining_threads: Math.max(1, Math.min(cores, Number(e.target.value) || 1)),
                })
              }
            />
          </div>
          <div>
            <label>Node log level</label>
            <select value={s.log_level} onChange={(e) => update({ log_level: e.target.value })}>
              {["trace", "debug", "info", "warn", "error"].map((l) => (
                <option key={l} value={l}>
                  {l}
                </option>
              ))}
            </select>
          </div>
        </div>
        <p className="faint" style={{ fontSize: 12, marginTop: 10 }}>
          Toggling mining restarts the node to apply.
        </p>
      </div>

      {/* Transactions (V2) */}
      <div className="card reveal">
        <h2>Transactions</h2>
        <div style={{ maxWidth: 320 }}>
          <label>Default transaction mode</label>
          <select
            value={s.default_tx_mode}
            onChange={(e) => update({ default_tx_mode: e.target.value })}
          >
            <option value="slatepack">Slatepack (recommended)</option>
            <option value="simple">Simple (trusted parties)</option>
          </select>
        </div>
        <div style={{ maxWidth: 320, marginTop: 12 }}>
          <label>Default slate expiry (hours)</label>
          <select
            value={s.tx_slate_expiry_hours ?? 24}
            onChange={(e) =>
              update({ tx_slate_expiry_hours: Number(e.target.value) })
            }
          >
            <option value={1}>1 hour</option>
            <option value={6}>6 hours</option>
            <option value={24}>24 hours</option>
            <option value={168}>7 days</option>
          </select>
        </div>
        <div style={{ maxWidth: 320, marginTop: 12 }}>
          <label>Default receive descriptor expiry (hours)</label>
          <select
            value={s.tx_descriptor_expiry_hours ?? 24}
            onChange={(e) =>
              update({ tx_descriptor_expiry_hours: Number(e.target.value) })
            }
          >
            <option value={1}>1 hour</option>
            <option value={6}>6 hours</option>
            <option value={24}>24 hours</option>
            <option value={168}>7 days</option>
          </select>
        </div>
        <label className="radio-row" style={{ marginTop: 14 }}>
          <input
            type="checkbox"
            checked={s.tx_show_advanced_fees}
            onChange={(e) => update({ tx_show_advanced_fees: e.target.checked })}
            style={{ width: "auto" }}
          />
          Show advanced (custom) fee option
        </label>
        <label className="radio-row" style={{ marginTop: 10 }}>
          <input
            type="checkbox"
            checked={s.tx_new_address_per_tx}
            onChange={(e) => update({ tx_new_address_per_tx: e.target.checked })}
            style={{ width: "auto" }}
          />
          Auto-generate a new Slatepack address per transaction (privacy)
        </label>
      </div>

      {/* Appearance */}
      <div className="card reveal">
        <h2>Appearance</h2>
        <div style={{ maxWidth: 260 }}>
          <label>Theme</label>
          <select
            value={s.theme}
            onChange={(e) => {
              const t = e.target.value as Theme;
              update({ theme: t });
              onThemeChange(t);
            }}
          >
            <option value="dark">Dark</option>
            <option value="light">Light</option>
            <option value="auto">Auto (system)</option>
          </select>
        </div>
      </div>

      {/* Updates + About */}
      <div className="card reveal">
        <h2>About</h2>
        <div className="kv">
          <span className="k">Version</span>
          <span className="v mono">{APP_VERSION}</span>
        </div>
        <div className="kv">
          <span className="k">License</span>
          <span className="v">MIT</span>
        </div>
        <div className="kv">
          <span className="k">Repository</span>
          <span className="v">
            <a
              href="https://github.com/sorenplanck/dom-protocol"
              target="_blank"
              rel="noreferrer"
              style={{ color: "var(--bronze-2)" }}
            >
              sorenplanck/dom-protocol
            </a>
          </span>
        </div>
        <p className="faint" style={{ fontSize: 12, marginTop: 8, fontStyle: "italic" }}>
          &ldquo;Not a store of value. A means of exchange.&rdquo;
        </p>
        <div className="row" style={{ marginTop: 12 }}>
          <button onClick={doCheckUpdates}>Check for updates</button>
          {updateMsg && <span className="muted" style={{ fontSize: 13 }}>{updateMsg}</span>}
        </div>
      </div>

      {/* Save bar */}
      <div className="row" style={{ marginBottom: 30 }}>
        {savedMsg && <span className="muted" style={{ fontSize: 13 }}>{savedMsg}</span>}
        {error && <span className="error-text">{error}</span>}
        <span style={{ flex: 1 }} />
        <button className="primary" onClick={persist}>
          Save settings
        </button>
      </div>
    </div>
  );
}
