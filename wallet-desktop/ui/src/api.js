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
  walletCreateReceive: (amount) => invoke("wallet_create_receive", { amount }),
  walletSend: (recipientCommitmentHex, recipientBlindingHex, amount, fee) =>
    invoke("wallet_send", {
      recipientCommitmentHex,
      recipientBlindingHex,
      amount,
      fee,
    }),
  // Slate protocol (person-to-person). Amounts in noms; slates travel as hex.
  slateCreateSend: (amount, fee) => invoke("slate_create_send", { amount, fee }),
  slateReceive: (slateHex) => invoke("slate_receive", { slateHex }),
  slateFinalize: (slateHex) => invoke("slate_finalize", { slateHex }),
  walletVerifyPassword: (password) =>
    invoke("wallet_verify_password", { password }),
  makeQrSvg: (data) => invoke("make_qr_svg", { data }),
  saveTextFile: (path, contents) => invoke("save_text_file", { path, contents }),
  readTextFile: (path) => invoke("read_text_file", { path }),

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
export async function pickSaveTextFile(title, defaultName) {
  return dialog.save({
    title,
    defaultPath: defaultName,
    filters: [{ name: "Text", extensions: ["txt"] }],
  });
}
// Escolhe um caminho e escreve o conteúdo de texto nele (ciclo completo).
export async function saveTextViaDialog(title, defaultName, contents) {
  const path = await pickSaveTextFile(title, defaultName);
  if (!path) return false;
  await api.saveTextFile(path, contents);
  toast("Arquivo salvo");
  return true;
}
export async function pickFolder(title) {
  return dialog.open({ title, directory: true, multiple: false });
}
export async function pickFile(title) {
  return dialog.open({ title, directory: false, multiple: false });
}

// ── Tradução de erros técnicos → mensagens amigáveis ─────────────────────────
// O backend devolve erros como string (mensagens dos enums WalletError /
// RpcClientError dos crates DOM). Aqui mapeamos para frases claras. O idioma
// segue `lang` (default "pt"). Nunca expomos stack trace cru ao usuário.
const ERROR_RULES = [
  // padrão (regex, case-insensitive) → { pt, en }
  [/insufficient funds/i, {
    pt: "Saldo insuficiente para concluir esta transação.",
    en: "Insufficient funds to complete this transaction.",
  }],
  [/coinbase output matures at height (\d+)/i, {
    pt: "Estas moedas ainda estão maturando (liberadas na altura $1). Aguarde a maturação.",
    en: "These coins are still maturing (available at height $1). Please wait.",
  }],
  [/output already spent/i, {
    pt: "Esta saída já foi gasta.",
    en: "This output was already spent.",
  }],
  [/(decryption failed|invalid password|password check|decrypt)/i, {
    pt: "Senha incorreta.",
    en: "Incorrect password.",
  }],
  [/wallet is locked/i, {
    pt: "A carteira está bloqueada. Desbloqueie com sua senha para continuar.",
    en: "The wallet is locked. Unlock it with your password to continue.",
  }],
  [/no wallet open/i, {
    pt: "Nenhuma carteira aberta.",
    en: "No wallet is open.",
  }],
  [/node not started/i, {
    pt: "O nó ainda não foi iniciado. Inicie o nó na aba Nó / Logs.",
    en: "The node hasn't started yet. Start it from the Node / Logs tab.",
  }],
  [/(connect timeout|read timeout|transport failure|unexpected HTTP)/i, {
    pt: "Não foi possível falar com o nó local. Verifique se ele está em execução.",
    en: "Couldn't reach the local node. Check that it's running.",
  }],
  [/unauthorized request/i, {
    pt: "Falha de autenticação com o nó local (token RPC). Reinicie o nó.",
    en: "Authentication with the local node failed (RPC token). Restart the node.",
  }],
  [/node rejected request.*409|duplicate/i, {
    pt: "O nó recusou: esta transação já está no mempool.",
    en: "The node rejected it: this transaction is already in the mempool.",
  }],
  [/node rejected request/i, {
    pt: "O nó recusou a requisição.",
    en: "The node rejected the request.",
  }],
  [/wallet directory .* is not empty|refusing to overwrite/i, {
    pt: "Já existe uma carteira nesse local. Escolha uma pasta vazia.",
    en: "A wallet already exists there. Choose an empty location.",
  }],
  [/invalid seed phrase|from_phrase|bip-?39/i, {
    pt: "Frase de recuperação inválida. Verifique as palavras e a ordem.",
    en: "Invalid recovery phrase. Check the words and their order.",
  }],
  [/invalid slate|slate (serialize|chain_id|already contains|deserialize)/i, {
    pt: "Slate inválido ou corrompido. Confira se você colou o texto completo, sem cortes.",
    en: "Invalid or corrupted slate. Make sure you pasted the full text, untruncated.",
  }],
  [/(commitment must be 33 bytes|blinding must be 32 bytes|decode|hex)/i, {
    pt: "Dados do destinatário inválidos. Confira o commitment e o blinding copiados.",
    en: "Invalid recipient data. Check the commitment and blinding you pasted.",
  }],
  [/OS RNG unavailable/i, {
    pt: "O gerador de aleatoriedade do sistema falhou. Reinicie o aplicativo.",
    en: "The system random generator failed. Please restart the app.",
  }],
  [/io error|read wallet directory/i, {
    pt: "Erro de leitura/escrita em disco. Verifique permissões e espaço livre.",
    en: "Disk read/write error. Check permissions and free space.",
  }],
];

export function getLang() {
  return localStorage.getItem("dom_lang") || "pt";
}
export function setLang(l) {
  localStorage.setItem("dom_lang", l);
}

export function humanizeError(e, lang = getLang()) {
  // Normaliza para string. Erros do Tauri costumam vir como string já.
  let msg = "";
  if (e == null) msg = "";
  else if (typeof e === "string") msg = e;
  else if (e instanceof Error) msg = e.message;
  else if (e && typeof e === "object" && "message" in e) msg = String(e.message);
  else msg = String(e);

  for (const [re, t] of ERROR_RULES) {
    const m = msg.match(re);
    if (m) {
      let out = t[lang] || t.pt;
      // substitui grupos $1, $2 …
      out = out.replace(/\$(\d+)/g, (_, n) => m[+n] ?? "");
      return out;
    }
  }
  // Fallback: nunca devolve stack trace; devolve frase genérica + dica curta.
  return lang === "en"
    ? "Something went wrong. Please try again."
    : "Algo deu errado. Tente novamente.";
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
