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
  walletCreate: (path, password, settings) =>
    invoke("wallet_create", { path, password, settings }),
  walletRestore: (path, password, phrase, settings) =>
    invoke("wallet_restore", { path, password, phrase, settings }),
  walletOpen: (path, password) => invoke("wallet_open", { path, password }),
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

  nodeStart: (settings) => invoke("node_start", { settings }),
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
  [/invalid amount/i, "Invalid amount. Check the number you entered."],
  [/io error|read wallet directory/i, "Disk read/write error. Check permissions and free space."],
];

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
  // Fallback: never return a raw stack trace.
  return "Something went wrong. Please try again.";
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
export function loadPrefs(defaults) {
  try {
    const raw = localStorage.getItem(PREF_KEY);
    if (!raw) return { ...defaults };
    const saved = JSON.parse(raw);
    return { ...defaults, ...saved };
  } catch {
    return { ...defaults };
  }
}
export function savePrefs(prefs) {
  // Strip anything sensitive defensively (there is nothing sensitive here,
  // but make the contract explicit).
  const { password, phrase, ...safe } = prefs;
  localStorage.setItem(PREF_KEY, JSON.stringify(safe));
}
