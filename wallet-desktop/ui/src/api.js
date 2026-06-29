// Tauri command bridge + shared helpers for the DOM Wallet UI.
const { invoke } = window.__TAURI__.core;
const { listen } = window.__TAURI__.event;
const { writeText } = window.__TAURI__.clipboardManager;
const dialog = window.__TAURI__.dialog;

export const NOMS_PER_DOM = 100_000_000n;

// ── unit formatting ──────────────────────────────────────────────────────────
// 1 DOM = 100_000_000 noms (8 decimals). Always show "X.XXXXXXXX DOM".
export function nomsToDom(noms) {
  const n = BigInt(noms);
  const whole = n / NOMS_PER_DOM;
  const frac = (n % NOMS_PER_DOM).toString().padStart(8, "0");
  return `${whole.toString()}.${frac}`;
}

// Parse a user-typed DOM amount into noms (BigInt). Throws on bad input.
export function domToNoms(dom) {
  const s = String(dom).trim();
  if (!/^\d+(\.\d{1,8})?$/.test(s)) {
    throw new Error("Enter a valid DOM amount (up to 8 decimals).");
  }
  const [whole, frac = ""] = s.split(".");
  const fracPadded = (frac + "00000000").slice(0, 8);
  return BigInt(whole) * NOMS_PER_DOM + BigInt(fracPadded || "0");
}

// ── thin command wrappers ────────────────────────────────────────────────────
export const api = {
  walletStatus: () => invoke("wallet_status"),
  walletCreate: (path, password, settings, name) =>
    invoke("wallet_create", { path, password, settings, name }),
  walletRestore: (path, password, phrase, settings, name) =>
    invoke("wallet_restore", { path, password, phrase, settings, name }),
  walletOpen: (path, password, name, remember) =>
    invoke("wallet_open", { path, password, name, remember }),
  // Managed flow: the app owns every path. The user supplies only a name, a
  // password and the mining toggle; the backend creates the wallet directory,
  // the encrypted vault AND the per-wallet node (data dir, config, free local
  // ports). Resolves to { phrase, settings }.
  walletCreateManaged: (name, password, mine, network) =>
    invoke("wallet_create_managed", { name, password, mine, network }),
  // Managed restore: same storage rules, plus the recovery phrase (never
  // persisted). Resolves to the per-wallet node settings.
  walletRestoreManaged: (name, password, phrase, mine, network) =>
    invoke("wallet_restore_managed", { name, password, phrase, mine, network }),
  // Duplicate-name pre-check for the create screen.
  walletNameTaken: (name) => invoke("wallet_name_taken", { name }),
  // Non-sensitive managed-storage locations for the Settings screen.
  walletStorageInfo: () => invoke("wallet_storage_info"),
  // Persist node settings next to the open MANAGED wallet (no-op otherwise).
  managedSettingsSave: (settings) =>
    invoke("managed_settings_save", { settings }),
  // Apply + persist the auto-backup config (toggle + optional external folder).
  // Rejects with the reason when enabling an external destination under a weak
  // login password (the seed would leave the machine under that password alone).
  setAutoBackup: (settings) =>
    invoke("set_auto_backup", { settings }),
  // Login-by-name: resolve the vault location from the local registry, then
  // unlock with the password. The renderer never handles a filesystem path.
  // Resolves to the wallet's saved node settings (or null for wallets located
  // outside the managed storage).
  walletOpenByName: (name, password) =>
    invoke("wallet_open_by_name", { name, password }),
  // Non-sensitive list of saved profiles (names + networks only) for the login
  // screen. Never returns a vault path or any secret.
  walletRegistryList: () => invoke("wallet_registry_list"),
  walletLock: () => invoke("wallet_lock"),
  walletUnlock: (password) => invoke("wallet_unlock", { password }),
  walletBalance: () => invoke("wallet_balance"),
  // Slate protocol (person-to-person). Amounts are decimal-string noms (M1:
  // strings avoid the JSON 2^53 precision loss); slates travel as hex.
  slateCreateSend: (amount, fee) =>
    invoke("slate_create_send", { amount: String(amount), fee: String(fee) }),
  slateReceive: (slateHex) => invoke("slate_receive", { slateHex }),
  slateFinalize: (slateHex) => invoke("slate_finalize", { slateHex }),
  walletVerifyPassword: (password) =>
    invoke("wallet_verify_password", { password }),
  makeQrSvg: (data) => invoke("make_qr_svg", { data }),
  // M4: the backend opens the native file dialog itself; the renderer passes
  // only a title + suggested name and never a path. `saveTextFile` resolves to
  // true if saved / false if cancelled; `readTextFile` resolves to the file
  // text or null if cancelled.
  saveTextFile: (title, defaultName, contents) =>
    invoke("save_text_file", { title, defaultName, contents }),
  readTextFile: (title) => invoke("read_text_file", { title }),

  // Encrypted full-backup (.dombak). Like the M4 file commands above, the backend
  // opens the native dialog itself, so the renderer never handles a filesystem
  // path. The passphrase / new password cross IPC only as command arguments and
  // are never logged. `exportBackup` resolves to true if saved / false if the
  // user cancelled the save dialog. `importBackup` restores NON-destructively
  // into a brand-new vault and resolves to the ImportedSummary
  // ({ vault_path, network, outputs, pending_slates, last_reconciled_tip }) or
  // null if the user cancelled either dialog. `targetNetwork` is one of
  // "mainnet" | "testnet" | "regtest" (the backend validates it).
  exportBackup: (passphrase) => invoke("export_backup_cmd", { passphrase }),
  importBackup: (passphrase, newPassword, targetNetwork) =>
    invoke("import_backup_cmd", { passphrase, newPassword, targetNetwork }),

  nodeStart: (settings) => invoke("node_start", { settings }),
  // Start when stopped, restart when running on DIFFERENT settings, no-op when
  // already running on these settings. Used on wallet open/switch so the node
  // always serves the open wallet's own data dir and ports.
  nodeEnsure: (settings) => invoke("node_ensure", { settings }),
  nodeStop: () => invoke("node_stop"),
  nodeRestart: (settings) => invoke("node_restart", { settings }),
  nodeState: () => invoke("node_state"),
  nodeStatus: () => invoke("node_status"),
  nodeMetrics: (addr) => invoke("node_metrics", { addr }),
  sweepMinerRewards: () => invoke("sweep_miner_rewards"),
  defaultSettings: () => invoke("default_settings"),
};

export const events = { listen };

// ── small DOM helpers ─────────────────────────────────────────────────────────
export function el(html) {
  const t = document.createElement("template");
  t.innerHTML = html.trim();
  return t.content.firstElementChild;
}

export async function copy(text) {
  try {
    await writeText(text);
    toast("Copied to clipboard");
  } catch (e) {
    toast("Copy failed: " + e, true);
  }
}

export async function pickSaveFile(title) {
  return dialog.save({ title, filters: [{ name: "DOM wallet", extensions: ["dom"] }] });
}
// Save text through the backend (M4): the native save dialog is opened in Rust
// so the renderer never handles a filesystem path. Returns true if saved.
export async function saveTextViaDialog(title, defaultName, contents) {
  const saved = await api.saveTextFile(title, defaultName, contents);
  if (saved) toast("Saved");
  return saved;
}
export async function pickFolder(title) {
  return dialog.open({ title, directory: true, multiple: false });
}

// ── Tradução de erros técnicos → mensagens amigáveis ─────────────────────────
// The backend returns errors as strings (messages from the DOM crates'
// WalletError / RpcClientError enums). Here we map them to clear, English
// phrases. We never expose a raw stack trace to the user.
const ERROR_RULES = [
  [/insufficient funds/i, "Insufficient funds to complete this transaction."],
  [/coinbase output matures at height (\d+)/i, "These coins are still maturing (available at height $1). Please wait."],
  [/output already spent/i, "This output was already spent."],
  [/(decryption failed|invalid password|password check|decrypt)/i, "Incorrect password."],
  [/wallet is locked/i, "The wallet is locked. Unlock it with your password to continue."],
  [/wallet profile not found/i, "Wallet profile not found. Locate existing wallet, restore, or create a new wallet."],
  [/wallet profile files missing/i, "The saved location for this wallet no longer exists. Use “Locate existing wallet” to find it, or restore from your recovery phrase."],
  [/no wallet open/i, "No wallet is open."],
  [/node not started/i, "The node hasn't started yet. Start it from the Node / Logs tab."],
  [/(connect timeout|read timeout|transport failure|unexpected HTTP)/i, "Couldn't reach the local node. Check that it's running."],
  [/unauthorized request/i, "Authentication with the local node failed (RPC token). Restart the node."],
  [/node rejected request.*409|duplicate/i, "The node rejected it: this transaction is already in the mempool."],
  [/node rejected request/i, "The node rejected the request."],
  [/wallet directory .* is not empty|refusing to overwrite/i, "A wallet already exists there. Choose an empty location."],
  [/invalid seed phrase|from_phrase|bip-?39/i, "Invalid recovery phrase. Check the words and their order."],
  [/invalid slate|slate (serialize|chain_id|already contains|deserialize)/i, "Invalid or corrupted slate. Make sure you pasted the full text, untruncated."],
  [/(commitment must be 33 bytes|blinding must be 32 bytes|decode|hex)/i, "Invalid recipient data. Check the commitment and blinding you pasted."],
  [/OS RNG unavailable/i, "The system random generator failed. Please restart the app."],
  [/network mismatch/i, "The open wallet belongs to a different network. Switch the network back to the wallet's (or open/create a wallet for the selected network)."],
  [/choose a dedicated miner reward wallet before enabling mining/i, "Choose a dedicated miner reward wallet before enabling mining."],
  [/miner reward wallet is invalid or cannot be opened/i, "Miner reward wallet is invalid or cannot be opened."],
  [/invalid amount/i, "Invalid amount. Check the number you entered."],
  [/io error|read wallet directory/i, "Disk read/write error. Check permissions and free space."],
];

function sanitizeErrorMessage(msg) {
  return String(msg || "")
    .replace(/(password|passphrase|mnemonic|recovery phrase|private key|wallet secret|seed)\s*[:=]\s*[^,\s;]+/gi, "$1: [redacted]")
    .replace(/(DOM_WALLET_PASSWORD|DOM_SEED|DOM_MNEMONIC)=([^,\s;]+)/g, "$1=[redacted]")
    .replace(/\s+/g, " ")
    .trim();
}

export function humanizeError(e) {
  // Normalize to a string. Tauri errors usually arrive as strings already.
  let msg = "";
  if (e == null) msg = "";
  else if (typeof e === "string") msg = e;
  else if (e instanceof Error) msg = e.message;
  else if (e && typeof e === "object" && "message" in e) msg = String(e.message);
  else msg = String(e);

  for (const [re, text] of ERROR_RULES) {
    const m = msg.match(re);
    if (m) return text.replace(/\$(\d+)/g, (_, n) => m[+n] ?? "");
  }
  const sanitized = sanitizeErrorMessage(msg);
  if (!sanitized || /\bat .*:\d+:\d+/i.test(sanitized)) {
    return "Something went wrong. Please try again.";
  }
  return sanitized;
}

let toastTimer = null;
export function toast(msg, isErr = false) {
  const t = document.getElementById("toast");
  t.textContent = msg;
  t.className = "show" + (isErr ? " err" : "");
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => (t.className = ""), 3200);
}

// Settings are kept in memory only (sensitive data never touches localStorage).
// Non-sensitive node prefs persist to localStorage so the user doesn't retype.
const PREF_KEY = "dom_wallet_node_prefs";
const NONE_TEXT = " none ";
const DEFAULT_BOOTSTRAP_SEED_PEER = "192.153.57.211:8443";
const LEGACY_BOOTSTRAP_SEED_PEER = "192.153.57.211:33370";

export function normalizeSeedPeers(seedPeers) {
  const raw = Array.isArray(seedPeers)
    ? seedPeers
    : typeof seedPeers === "string"
      ? seedPeers.split(",")
      : [];
  const peers = [];
  for (const value of raw) {
    const trimmed = String(value).trim();
    if (!trimmed) continue;
    const peer = trimmed === LEGACY_BOOTSTRAP_SEED_PEER
      ? DEFAULT_BOOTSTRAP_SEED_PEER
      : trimmed;
    if (!peers.includes(peer)) peers.push(peer);
  }
  return peers;
}

export function normalizeNodePrefs(prefs) {
  const next = {
    ...prefs,
    seed_peers: normalizeSeedPeers(prefs.seed_peers),
  };
  if (typeof next.miner_wallet_path === "string" && !next.miner_wallet_path.trim()) {
    next.miner_wallet_path = null;
  }
  const minerPath = typeof next.miner_wallet_path === "string"
    ? next.miner_wallet_path.trim()
    : "";
  if (!next.mine && /(^|[\\/])\.dom[\\/]node\.dom$/i.test(minerPath)) {
    next.miner_wallet_path = null;
    next.mine = false;
  }
  return next;
}

export function minerWalletDisplay(settings) {
  const path = settings?.miner_wallet_path;
  if (typeof path !== "string" || !path.trim()) return NONE_TEXT;
  if (!settings?.mine && /(^|[\\/])\.dom[\\/]node\.dom$/i.test(path.trim())) return NONE_TEXT;
  return path.trim();
}

export function clearMinerWalletSettings(settings) {
  settings.miner_wallet_path = null;
  settings.mine = false;
  return settings;
}

export function loadPrefs(defaults) {
  try {
    const raw = localStorage.getItem(PREF_KEY);
    if (!raw) return normalizeNodePrefs({ ...defaults });
    const saved = JSON.parse(raw);
    return normalizeNodePrefs({ ...defaults, ...saved });
  } catch {
    return normalizeNodePrefs({ ...defaults });
  }
}
export function savePrefs(prefs) {
  // Strip anything sensitive defensively (there is nothing sensitive here,
  // but make the contract explicit).
  const { password, phrase, ...safe } = normalizeNodePrefs(prefs);
  localStorage.setItem(PREF_KEY, JSON.stringify(safe));
}
