import { useCallback, useEffect, useRef, useState } from "react";
import { Onboarding } from "./pages/Onboarding";
import { Dashboard } from "./pages/Dashboard";
import { NodePage } from "./pages/Node";
import { History, type CoinbaseRecord } from "./pages/History";
import { Settings } from "./pages/Settings";
import { Send } from "./pages/Send";
import { Receive } from "./pages/Receive";
import { NodeStatusBadge } from "./components/NodeStatusBadge";
import { UpdateBanner } from "./components/UpdateBanner";
import {
  walletStatus,
  walletBalance,
  walletLock,
  walletUnlock,
  nodeIsRunning,
  settingsGet,
  errMessage,
  type BalanceInfo,
  type NodeStatusView,
  type NodeRunning,
  type UpdateInfo,
  type Theme,
} from "./lib/tauri";
import {
  onNodeStatus,
  onWalletLocked,
  onWalletUnlocked,
  onNewCoinbase,
  onUpdateAvailable,
  onNodeStarted,
  onNodeStopped,
} from "./lib/events";
import logo from "./assets/logo.png";

type Tab = "dashboard" | "node" | "history" | "send" | "receive" | "settings";

const NAV: Array<{ id: Tab; label: string; badge?: string }> = [
  { id: "dashboard", label: "Dashboard" },
  { id: "node", label: "Node" },
  { id: "history", label: "History" },
  { id: "send", label: "Send", badge: "V2" },
  { id: "receive", label: "Receive", badge: "V2" },
  { id: "settings", label: "Settings" },
];

function applyTheme(theme: Theme) {
  const resolved =
    theme === "auto"
      ? window.matchMedia("(prefers-color-scheme: light)").matches
        ? "light"
        : "dark"
      : theme;
  document.documentElement.setAttribute("data-theme", resolved);
}

export default function App() {
  const [phase, setPhase] = useState<"loading" | "onboarding" | "locked" | "ready">("loading");
  const [tab, setTab] = useState<Tab>("dashboard");

  const [balance, setBalance] = useState<BalanceInfo | null>(null);
  const [status, setStatus] = useState<NodeStatusView | null>(null);
  const [node, setNode] = useState<NodeRunning | null>(null);
  const [coinbases, setCoinbases] = useState<CoinbaseRecord[]>([]);
  const [sessionBlocks, setSessionBlocks] = useState(0);
  const [update, setUpdate] = useState<UpdateInfo | null>(null);
  const [updateDismissed, setUpdateDismissed] = useState(false);

  const lockTimer = useRef<number | null>(null);

  // ── bootstrap ──────────────────────────────────────────────────────────
  const bootstrap = useCallback(async () => {
    try {
      const st = await walletStatus();
      const s = await settingsGet();
      applyTheme(s.theme);
      if (!st.exists) {
        setPhase("onboarding");
      } else if (!st.unlocked) {
        setPhase("locked");
      } else {
        setPhase("ready");
      }
      setNode(await nodeIsRunning());
    } catch {
      setPhase("onboarding");
    }
  }, []);

  useEffect(() => {
    void bootstrap();
  }, [bootstrap]);

  // ── refresh helpers ────────────────────────────────────────────────────
  const refreshNode = useCallback(async () => {
    try {
      setNode(await nodeIsRunning());
    } catch {
      /* ignore */
    }
  }, []);

  const refreshBalance = useCallback(async () => {
    try {
      setBalance(await walletBalance());
    } catch {
      /* wallet may be locked; ignore */
    }
  }, []);

  // ── event subscriptions (only when ready) ───────────────────────────────
  useEffect(() => {
    if (phase !== "ready") return;
    const unsubs: Array<Promise<() => void>> = [];

    unsubs.push(onNodeStatus((s) => setStatus(s)));
    unsubs.push(onNodeStarted(() => void refreshNode()));
    unsubs.push(onNodeStopped(() => void refreshNode()));
    unsubs.push(
      onWalletLocked(() => {
        setPhase("locked");
        setBalance(null);
      }),
    );
    unsubs.push(onWalletUnlocked(() => void refreshBalance()));
    unsubs.push(
      onNewCoinbase((p) => {
        setCoinbases((prev) => [
          ...prev,
          { height: p.height, valueNoms: p.value_noms, timestamp: Date.now() },
        ]);
        setSessionBlocks((n) => n + 1);
        void refreshBalance();
      }),
    );
    unsubs.push(
      onUpdateAvailable((u) => {
        setUpdate(u);
        setUpdateDismissed(false);
      }),
    );

    void refreshBalance();
    void refreshNode();
    const bal = window.setInterval(() => void refreshBalance(), 15000);

    return () => {
      window.clearInterval(bal);
      unsubs.forEach((p) => p.then((fn) => fn()).catch(() => {}));
    };
  }, [phase, refreshBalance, refreshNode]);

  // ── activity → reset is handled in backend; we just lock on idle UI too ──
  useEffect(() => {
    if (phase !== "ready") return;
    const reset = () => {
      if (lockTimer.current) window.clearTimeout(lockTimer.current);
    };
    window.addEventListener("mousemove", reset);
    window.addEventListener("keydown", reset);
    return () => {
      window.removeEventListener("mousemove", reset);
      window.removeEventListener("keydown", reset);
    };
  }, [phase]);

  const lock = async () => {
    try {
      await walletLock();
    } finally {
      setPhase("locked");
      setBalance(null);
    }
  };

  if (phase === "loading") {
    return <div className="center-screen muted">Loading…</div>;
  }

  if (phase === "onboarding") {
    return <Onboarding onReady={() => setPhase("ready")} />;
  }

  if (phase === "locked") {
    return <LockScreen onUnlocked={() => setPhase("ready")} />;
  }

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand">
          <img src={logo} alt="DOM" />
          <span className="name">DOM</span>
        </div>
        {NAV.map((n) => (
          <button
            key={n.id}
            className={`nav-item ${tab === n.id ? "active" : ""}`}
            onClick={() => setTab(n.id)}
          >
            {n.label}
            {n.badge && <span className="badge">{n.badge}</span>}
          </button>
        ))}
        <div className="spacer" />
        <NodeStatusBadge running={node?.running ?? false} status={status} />
      </aside>

      <main className="main">
        <div className="topbar">
          <h1 className="title">{NAV.find((n) => n.id === tab)?.label}</h1>
          <div className="actions">
            <button onClick={lock} title="Lock wallet">
              🔒 Lock
            </button>
          </div>
        </div>

        {!updateDismissed && (
          <UpdateBanner update={update} onDismiss={() => setUpdateDismissed(true)} />
        )}

        {tab === "dashboard" && (
          <Dashboard
            balance={balance}
            status={status}
            node={node}
            sessionBlocks={sessionBlocks}
            coinbaseHeights={coinbases.map((c) => c.height)}
          />
        )}
        {tab === "node" && <NodePage node={node} status={status} refresh={refreshNode} />}
        {tab === "history" && (
          <History records={coinbases} chainHeight={status?.chain_height ?? 0} />
        )}
        {tab === "send" && <Send />}
        {tab === "receive" && <Receive />}
        {tab === "settings" && <Settings onThemeChange={applyTheme} />}
      </main>
    </div>
  );
}

/** Minimal lock screen shown when a wallet exists but is locked. */
function LockScreen({ onUnlocked }: { onUnlocked: () => void }) {
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  const unlock = async () => {
    setBusy(true);
    setError("");
    try {
      await walletUnlock(password);
      setPassword("");
      onUnlocked();
    } catch (e) {
      setError(errMessage(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="center-screen">
      <div className="panel reveal">
        <img className="logo" src={logo} alt="DOM" />
        <h2 style={{ textAlign: "center", marginBottom: 18 }}>Wallet locked</h2>
        <input
          type="password"
          autoFocus
          value={password}
          placeholder="Password"
          onChange={(e) => setPassword(e.target.value)}
          onKeyDown={(e) => e.key === "Enter" && unlock()}
        />
        {error && <p className="error-text" style={{ marginTop: 10 }}>{error}</p>}
        <button
          className="primary"
          style={{ width: "100%", marginTop: 16 }}
          disabled={busy || !password}
          onClick={unlock}
        >
          {busy ? "Unlocking…" : "Unlock"}
        </button>
      </div>
    </div>
  );
}
