// App bootstrap + router.
import { api, loadPrefs, savePrefs, toast, humanizeError } from "./api.js";
import { startLogCapture } from "./logbuffer.js";
import * as S from "./screens.js";

const gate = document.getElementById("gate");
const gateBody = document.getElementById("gate-body");
const app = document.getElementById("app");
const screenHost = document.getElementById("screen");

let currentScreen = null;

// ── Theme ─────────────────────────────────────────────────────────────────────
function initTheme() {
  const saved = localStorage.getItem("dom_theme") || "dark";
  document.documentElement.setAttribute("data-theme", saved);
}
document.getElementById("themeToggle").onclick = () => {
  const cur = document.documentElement.getAttribute("data-theme");
  const next = cur === "dark" ? "light" : "dark";
  document.documentElement.setAttribute("data-theme", next);
  localStorage.setItem("dom_theme", next);
};
document.getElementById("lockBtn").onclick = async () => {
  await lockNow();
};

// ── Auto-lock on inactivity ─────────────────────────────────────────────────
// The timer resets on every interaction. On expiry it locks the wallet (ending
// the sensitive backend session) and returns to the unlock screen.
// The duration is configurable in Settings (minutes; 0 = never).
let idleTimer = null;
let idleListenersAttached = false;

function autoLockMinutes() {
  const m = S.settings.current?.auto_lock_minutes;
  return typeof m === "number" ? m : 5; // default 5 min
}

function resetIdleTimer() {
  clearTimeout(idleTimer);
  const mins = autoLockMinutes();
  if (!mins || mins <= 0) return; // "never"
  idleTimer = setTimeout(() => { lockNow(true); }, mins * 60 * 1000);
}

function attachIdleListeners() {
  if (idleListenersAttached) return;
  ["mousemove", "mousedown", "keydown", "click", "wheel", "touchstart"].forEach((ev) =>
    window.addEventListener(ev, resetIdleTimer, { passive: true }));
  idleListenersAttached = true;
}

function stopIdleTimer() {
  clearTimeout(idleTimer);
  idleTimer = null;
}

async function lockNow(byTimeout = false) {
  stopIdleTimer();
  try { await api.walletLock(); } catch {}
  if (currentScreen && currentScreen._cleanup) currentScreen._cleanup();
  if (byTimeout) {
    toast("Wallet locked due to inactivity.");
  }
  // Back to the unlock gate (the wallet stays open, just locked).
  showGate(S.renderUnlock(() => enterApp()));
}

// ── Gate vs app ────────────────────────────────────────────────────────────────
function showGate(node) {
  app.classList.add("hidden");
  gate.classList.remove("hidden");
  gateBody.innerHTML = "";
  gateBody.appendChild(node);
}

function showApp() {
  gate.classList.add("hidden");
  app.classList.remove("hidden");
  navigate("dashboard");
}

// Onboarding sub-router.
function gotoOnboarding(which) {
  const onReady = () => enterApp();
  const go = gotoOnboarding;
  const map = {
    welcome: () => S.renderWelcome(go),
    create: () => S.renderCreate(go, onReady),
    restore: () => S.renderRestore(go, onReady),
    open: () => S.renderOpen(go, onReady),
  };
  showGate(map[which]());
}

// ── Main navigation ─────────────────────────────────────────────────────────────
const screens = {
  dashboard: S.renderDashboard,
  pay: S.renderPay,
  receive: S.renderReceive,
  history: S.renderHistory,
  node: S.renderNode,
  settings: () => S.renderSettings(() => { resetIdleTimer(); }),
};

function navigate(name) {
  if (currentScreen && currentScreen._cleanup) currentScreen._cleanup();
  document.querySelectorAll("#nav button").forEach((b) =>
    b.classList.toggle("active", b.dataset.screen === name));
  const node = screens[name]();
  screenHost.innerHTML = "";
  screenHost.appendChild(node);
  currentScreen = node;
}

document.querySelectorAll("#nav button").forEach((b) =>
  (b.onclick = () => navigate(b.dataset.screen)));

// ── Enter app: start the node, then show dashboard ──────────────────────────────
async function enterApp() {
  showApp();
  attachIdleListeners();
  resetIdleTimer();
  // Auto-start the embedded node with current settings.
  try {
    await api.nodeStart(S.settings.current);
  } catch (e) {
    toast(humanizeError(e), true);
  }
}

// ── Boot ────────────────────────────────────────────────────────────────────────
async function boot() {
  initTheme();
  // Start capturing node logs at boot so the buffer has history even if the
  // Node / Logs tab is opened later.
  await startLogCapture();
  // Load default node settings from the backend, merge saved non-sensitive prefs.
  const defaults = await api.defaultSettings();
  // auto_lock_minutes is a local pref (not part of the backend NodeConfig; the
  // NodeSettings serde ignores extra fields, so loading it alongside is safe).
  S.settings.current = loadPrefs({ ...defaults, auto_lock_minutes: 5 });
  // Mining is an explicit per-session action. A stale saved preference must not
  // make the embedded node start mining when the wallet opens.
  S.settings.current.mine = false;
  savePrefs(S.settings.current);

  const status = await api.walletStatus();
  if (!status.open) {
    gotoOnboarding("welcome");
  } else if (!status.unlocked) {
    showGate(S.renderUnlock(() => enterApp()));
  } else {
    enterApp();
  }
}

boot().catch((e) => {
  gateBody.innerHTML = `<div class="card"><h1>Startup error</h1><p class="err-text">${humanizeError(e)}</p></div>`;
});
