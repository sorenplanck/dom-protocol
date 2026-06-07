// Screen renderers. Each returns an element and wires its own events.
import {
  api, el, copy, toast, nomsToDom, domToNoms,
  pickSaveFile, pickFolder, saveTextViaDialog, savePrefs, humanizeError,
} from "./api.js";
import {
  getLogLines, clearLogs, subscribeLogs, logsToText,
} from "./logbuffer.js";

// Shared, in-memory settings object (single source of truth for node config).
// Sensitive values (passwords/phrases) are NEVER stored here.
export const settings = { current: null };

// Short UI toast messages.
const MSG = {
  walletCreated: "Wallet created",
  walletRestored: "Wallet restored",
  walletOpened: "Wallet opened",
  nodeStarting: "Node starting…",
  nodeStopping: "Node stopping…",
  nodeRestarting: "Node restarting…",
  applyingMining: "Applying mining (restarting node)…",
  settingsApplied: "Settings applied — node restarting",
  logsSaved: "Logs saved",
};
function t(key) {
  return MSG[key] || key;
}

// ── Onboarding: welcome ──────────────────────────────────────────────────────
export function renderWelcome(go) {
  const node = el(`
    <div>
      <h1 class="tc">DOM Wallet</h1>
      <p class="sub tc">Official desktop wallet with an integrated DOM node.</p>
      <div class="card">
        <button class="btn w-full" id="bCreate">Create new wallet</button>
        <div class="btn-row"><button class="btn ghost w-full" id="bRestore">Restore from recovery phrase</button></div>
        <div class="btn-row"><button class="btn ghost w-full" id="bOpen">Open existing wallet</button></div>
      </div>
      <p class="muted tc">Privacy by design · Sovereign by choice</p>
    </div>`);
  node.querySelector("#bCreate").onclick = () => go("create");
  node.querySelector("#bRestore").onclick = () => go("restore");
  node.querySelector("#bOpen").onclick = () => go("open");
  return node;
}

// ── Onboarding: create (generate seed → confirm → set password) ──────────────
export function renderCreate(go, onReady) {
  const node = el(`
    <div>
      <h1>Create wallet</h1>
      <p class="sub">A new 24-word recovery phrase will be generated. Write it down — it is the only way to recover your funds.</p>
      <div class="card">
        <label>Network</label>
        <select id="net">
          <option value="testnet">Testnet</option>
          <option value="mainnet">Mainnet</option>
          <option value="regtest">Regtest (local dev)</option>
        </select>
        <label>Wallet location</label>
        <div class="copyable"><code id="path">— choose a location —</code><button class="btn ghost" id="pick">Choose</button></div>
        <label>Password</label>
        <input type="password" id="pw" placeholder="Encrypts the wallet on disk" />
        <label>Confirm password</label>
        <input type="password" id="pw2" placeholder="Type the password again" />
        <div class="btn-row">
          <button class="btn ghost" id="back">Back</button>
          <button class="btn" id="next" disabled>Generate phrase</button>
        </div>
        <div class="err-text" id="err"></div>
      </div>
    </div>`);

  let path = null;
  // M2: the network is chosen here, at creation, and baked into the wallet.
  // It cannot be changed afterwards (Settings shows it read-only).
  const netEl = node.querySelector("#net");
  netEl.value = settings.current.network;
  netEl.onchange = () => {
    settings.current.network = netEl.value;
    savePrefs(settings.current);
  };
  const refresh = () => {
    node.querySelector("#next").disabled =
      !(path && node.querySelector("#pw").value.length >= 8);
  };
  node.querySelector("#pick").onclick = async () => {
    const p = await pickSaveFile("Save new DOM wallet");
    if (p) { path = p; node.querySelector("#path").textContent = p; refresh(); }
  };
  node.querySelector("#pw").oninput = refresh;
  node.querySelector("#back").onclick = () => go("welcome");
  node.querySelector("#next").onclick = async () => {
    const pw = node.querySelector("#pw").value;
    const pw2 = node.querySelector("#pw2").value;
    const err = node.querySelector("#err");
    if (pw !== pw2) { err.textContent = "Passwords do not match."; return; }
    if (pw.length < 8) { err.textContent = "Use at least 8 characters."; return; }
    err.textContent = "";
    try {
      const phrase = await api.walletCreate(path, pw, settings.current);
      showSeedConfirm(node, phrase, onReady);
    } catch (e) {
      err.textContent = humanizeError(e);
    }
  };
  return node;
}

// Force the user to view, then re-type-confirm a few random words.
function showSeedConfirm(container, phrase, onReady) {
  const words = phrase.trim().split(/\s+/);
  const grid = words.map((w, i) =>
    `<div class="seed-word"><span class="i">${i + 1}</span>${w}</div>`).join("");

  container.innerHTML = "";
  container.appendChild(el(`
    <div>
      <h1>Your recovery phrase</h1>
      <div class="warn-box">Write these ${words.length} words on paper, in order. Anyone with this phrase can take your funds. It will not be shown again.</div>
      <div class="warn-box warn-box-err">⚠ No one from DOM will ever ask for your recovery phrase. Never share it, type it on websites, or send it in a message. Keep it offline.</div>
      <div class="card"><div class="seed-grid">${grid}</div>
        <div class="btn-row"><button class="btn" id="wrote">I wrote down my phrase</button></div>
      </div>
    </div>`));

  container.querySelector("#wrote").onclick = () => {
    // Ask the user to confirm 3 random positions.
    const idxs = pickThree(words.length);
    container.innerHTML = "";
    container.appendChild(el(`
      <div>
        <h1>Confirm your phrase</h1>
        <p class="sub">Type the requested words to confirm you saved them.</p>
        <div class="card">
          ${idxs.map((i) => `
            <label>Word #${i + 1}</label>
            <input type="text" data-idx="${i}" autocomplete="off" spellcheck="false" />`).join("")}
          <div class="btn-row"><button class="btn" id="confirm">Confirm and open wallet</button></div>
          <div class="err-text" id="cerr"></div>
        </div>
      </div>`));
    container.querySelector("#confirm").onclick = () => {
      const inputs = [...container.querySelectorAll("input[data-idx]")];
      const ok = inputs.every((inp) =>
        inp.value.trim().toLowerCase() === words[+inp.dataset.idx].toLowerCase());
      if (!ok) { container.querySelector("#cerr").textContent = "Words do not match. Check your written copy."; return; }
      toast(t("walletCreated"));
      // L7: best-effort scrub of the phrase from the renderer. JS cannot
      // zeroize, but dropping the words and clearing the typed inputs lets the
      // GC reclaim the strings and removes them from the DOM.
      for (let i = 0; i < words.length; i++) words[i] = "";
      inputs.forEach((inp) => { inp.value = ""; });
      onReady();
    };
  };
}

function pickThree(n) {
  const s = new Set();
  while (s.size < Math.min(3, n)) s.add(Math.floor(Math.random() * n));
  return [...s].sort((a, b) => a - b);
}

// ── Onboarding: restore ──────────────────────────────────────────────────────
export function renderRestore(go, onReady) {
  const node = el(`
    <div>
      <h1>Restore wallet</h1>
      <p class="sub">Enter your BIP-39 recovery phrase, choose where to save it, and set a new password.</p>
      <div class="card">
        <label>Recovery phrase</label>
        <textarea id="phrase" placeholder="word1 word2 word3 ..."></textarea>
        <label>Network</label>
        <select id="net">
          <option value="testnet">Testnet</option>
          <option value="mainnet">Mainnet</option>
          <option value="regtest">Regtest (local dev)</option>
        </select>
        <label>Wallet location</label>
        <div class="copyable"><code id="path">— choose a location —</code><button class="btn ghost" id="pick">Choose</button></div>
        <label>New password</label>
        <input type="password" id="pw" />
        <label>Confirm password</label>
        <input type="password" id="pw2" />
        <div class="btn-row">
          <button class="btn ghost" id="back">Back</button>
          <button class="btn" id="go">Restore</button>
        </div>
        <div class="err-text" id="err"></div>
      </div>
    </div>`);
  let path = null;
  // M2: network is chosen at restore time and baked into the wallet.
  const netEl = node.querySelector("#net");
  netEl.value = settings.current.network;
  netEl.onchange = () => {
    settings.current.network = netEl.value;
    savePrefs(settings.current);
  };
  node.querySelector("#pick").onclick = async () => {
    const p = await pickSaveFile("Save restored DOM wallet");
    if (p) { path = p; node.querySelector("#path").textContent = p; }
  };
  node.querySelector("#back").onclick = () => go("welcome");
  node.querySelector("#go").onclick = async () => {
    const err = node.querySelector("#err");
    const phrase = node.querySelector("#phrase").value.trim();
    const pw = node.querySelector("#pw").value;
    const pw2 = node.querySelector("#pw2").value;
    if (!path) { err.textContent = "Choose the wallet location."; return; }
    if (pw.length < 8) { err.textContent = "Use at least 8 characters."; return; }
    // L1: confirm the password so a typo can't lock the restored wallet.
    if (pw !== pw2) { err.textContent = "Passwords do not match."; return; }
    try {
      await api.walletRestore(path, pw, phrase, settings.current);
      node.querySelector("#phrase").value = "";
      toast(t("walletRestored"));
      onReady();
    } catch (e) { err.textContent = humanizeError(e); }
  };
  return node;
}

// ── Onboarding: open existing ────────────────────────────────────────────────
export function renderOpen(go, onReady) {
  const node = el(`
    <div>
      <h1>Open wallet</h1>
      <div class="card">
        <label>Wallet folder (.dom directory)</label>
        <div class="copyable"><code id="path">— choose —</code><button class="btn ghost" id="pick">Choose</button></div>
        <label>Password</label>
        <input type="password" id="pw" />
        <div class="btn-row">
          <button class="btn ghost" id="back">Back</button>
          <button class="btn" id="go">Open</button>
        </div>
        <div class="err-text" id="err"></div>
      </div>
    </div>`);
  let path = null;
  node.querySelector("#pick").onclick = async () => {
    const p = await pickFolder("Open DOM wallet");
    if (p) { path = p; node.querySelector("#path").textContent = p; }
  };
  node.querySelector("#back").onclick = () => go("welcome");
  node.querySelector("#go").onclick = async () => {
    const err = node.querySelector("#err");
    if (!path) { err.textContent = "Choose a wallet."; return; }
    try {
      await api.walletOpen(path, node.querySelector("#pw").value);
      toast(t("walletOpened"));
      onReady();
    } catch (e) { err.textContent = humanizeError(e); }
  };
  return node;
}

// ── Unlock (wallet open but locked) ──────────────────────────────────────────
export function renderUnlock(onReady) {
  const node = el(`
    <div>
      <h1>Unlock</h1>
      <div class="card">
        <label>Password</label>
        <input type="password" id="pw" autofocus />
        <div class="btn-row"><button class="btn" id="go">Unlock</button></div>
        <div class="err-text" id="err"></div>
      </div>
    </div>`);
  const submit = async () => {
    try { await api.walletUnlock(node.querySelector("#pw").value); onReady(); }
    catch (e) { node.querySelector("#err").textContent = humanizeError(e); }
  };
  node.querySelector("#go").onclick = submit;
  node.querySelector("#pw").onkeydown = (e) => { if (e.key === "Enter") submit(); };
  return node;
}

// ── Dashboard ────────────────────────────────────────────────────────────────
export function renderDashboard() {
  const node = el(`
    <div class="screen">
      <h1>Dashboard</h1>
      <p class="sub">Your balance and the state of your integrated node.</p>
      <div class="card hidden sync-banner" id="syncBanner">
        <span class="pill pill-bare">
          <span class="dot busy"></span>
          <span id="syncText" class="c-warn">Syncing…</span>
        </span>
        <p class="muted mt6">The node is still downloading the chain. Your balance is only reliable after sync — coins that haven't appeared yet may show up once it completes.</p>
      </div>
      <div class="card">
        <div class="balance-main"><span id="balTotal">—</span><span class="unit">DOM</span></div>
        <div class="balance-sub">
          <div><div class="k">Spendable</div><div class="v" id="balSpend">—</div></div>
          <div><div class="k">Pending (immature)</div><div class="v pending" id="balImm">—</div></div>
        </div>
      </div>
      <div class="row">
        <div class="card"><div class="k stat-mini-label">Chain height</div><div class="balance-main fs26"><span id="height">—</span></div></div>
        <div class="card"><div class="k stat-mini-label">Network</div><div class="balance-main fs26"><span id="net">—</span></div></div>
        <div class="card"><div class="k stat-mini-label">Peers</div><div class="balance-main fs26"><span id="peers">—</span></div></div>
      </div>
      <div class="card">
        <span class="pill"><span class="dot" id="nodeDot"></span><span id="nodeState">node: unknown</span></span>
        <span class="pill ml8"><span class="dot" id="mineDot"></span><span id="mineState">mining: —</span></span>
      </div>
    </div>`);
  // IBD state between reads
  node._sync = { lastHeight: null, stableTicks: 0, synced: false };
  refreshDashboard(node);
  const timer = setInterval(() => refreshDashboard(node), 5000);
  node._cleanup = () => clearInterval(timer);
  return node;
}

async function refreshDashboard(node) {
  let peers = 0;
  let height;
  try {
    const st = await api.nodeStatus();
    if (st.chain_height !== undefined) {
      height = st.chain_height;
      node.querySelector("#height").textContent = st.chain_height;
    }
    if (st.network) node.querySelector("#net").textContent = st.network;
    setNodePill(node, st.state);
  } catch {}
  try {
    const m = await api.nodeMetrics(settings.current.metrics_listen_addr || "127.0.0.1:33371");
    peers = m.peer_count;
    node.querySelector("#peers").textContent = m.peer_count;
    const md = node.querySelector("#mineDot"); const ms = node.querySelector("#mineState");
    md.className = "dot " + (m.mining_active ? "on" : "off");
    ms.textContent = "mining: " + (m.mining_active ? "active" : "off");
  } catch {}

  // Sync heuristic (IBD). The node does not expose an estimated NETWORK height,
  // so we cannot know the true tip (L3). To avoid claiming "synced" too eagerly,
  // we keep the syncing banner until the local height has been completely stable
  // for a long, clearly-idle window AND at least one peer is connected. A brief
  // mid-IBD stall (a slow peer) no longer flips us to "synced". With no peers we
  // never consider ourselves synced.
  const STABLE_TICKS_FOR_SYNCED = 6; // ~30s at the 5s dashboard refresh
  const s = node._sync;
  const banner = node.querySelector("#syncBanner");
  const syncText = node.querySelector("#syncText");
  if (height !== undefined) {
    if (s.lastHeight !== null && height > s.lastHeight) {
      s.stableTicks = 0;
      s.synced = false;
    } else if (s.lastHeight !== null && height === s.lastHeight) {
      s.stableTicks += 1;
      if (s.stableTicks >= STABLE_TICKS_FOR_SYNCED && peers > 0) s.synced = true;
    }
    if (peers === 0) s.synced = false;
    s.lastHeight = height;
  }
  if (height !== undefined && !s.synced) {
    banner.classList.remove("hidden");
    syncText.textContent = `Syncing… (height ${height}${peers ? `, ${peers} peers` : ", no peers yet"})`;
  } else {
    banner.classList.add("hidden");
  }

  // Balance: always shown, but the banner warns it may be incomplete during IBD.
  try {
    const bal = await api.walletBalance();
    node.querySelector("#balTotal").textContent = nomsToDom(bal.total);
    node.querySelector("#balSpend").textContent = nomsToDom(bal.spendable);
    node.querySelector("#balImm").textContent = nomsToDom(bal.immature);
  } catch { /* node may not be ready yet */ }
}

function setNodePill(node, state) {
  const dot = node.querySelector("#nodeDot"); const lbl = node.querySelector("#nodeState");
  if (!dot) return;
  const map = { running: "on", stopped: "off", starting: "busy", stopping: "busy" };
  const labels = { running: "running", stopped: "stopped", starting: "starting", stopping: "stopping" };
  dot.className = "dot " + (map[state] || "");
  lbl.textContent = "node: " + (labels[state] || state || "unknown");
}

// ── Pay (payer side): Send (step 1) + Finalize (step 3) ───────────────────────
// Interactive slate flow (Mimblewimble): unlike Bitcoin, the payer acts in TWO
// steps, with the recipient responding in between.
export function renderPay() {
  const node = el(`
    <div class="screen">
      <h1>Pay DOM</h1>
      <p class="sub">Payment is interactive: you create a slate, the recipient responds, and you finalize. Two exchanges — unlike Bitcoin's address model.</p>
      <div class="card">
        <div class="btn-row mt0">
          <button class="btn" id="tabSend">1 · Send</button>
          <button class="btn ghost" id="tabFinal">3 · Finalize</button>
        </div>
      </div>
      <div id="payBody"></div>
    </div>`);

  const body = node.querySelector("#payBody");
  const tabSend = node.querySelector("#tabSend");
  const tabFinal = node.querySelector("#tabFinal");
  const show = (which) => {
    tabSend.className = which === "send" ? "btn" : "btn ghost";
    tabFinal.className = which === "final" ? "btn" : "btn ghost";
    body.innerHTML = "";
    body.appendChild(which === "send" ? paySendStep() : payFinalizeStep());
  };
  tabSend.onclick = () => show("send");
  tabFinal.onclick = () => show("final");
  show("send");
  return node;
}

// Step 1 — SENDER creates the slate.
function paySendStep() {
  const node = el(`
    <div>
      <div class="card" id="form">
        <h2>Step 1 · Create send slate</h2>
        <label>Amount (DOM)</label>
        <input type="text" id="amt" placeholder="0.00000000" />
        <label>Fee (DOM)</label>
        <input type="text" id="fee" value="0.00100000" />
        <div class="btn-row"><button class="btn" id="create">Generate slate</button></div>
        <div class="err-text" id="err"></div>
        <p class="muted mt10" id="avail"></p>
      </div>
      <div class="card hidden" id="result">
        <div class="warn-box">The payment is NOT complete yet. Send this slate to the recipient; they will respond with a slate for you to <b>Finalize</b> (step 3).</div>
        <div class="qr-wrap">
          <div class="qr-box" id="qr"></div>
          <div class="flex1-min260">
            <label>Slate (send to the recipient)</label>
            <div class="copyable"><code id="slate"></code><button class="btn ghost" id="copySlate">Copy</button></div>
            <div class="btn-row"><button class="btn ghost" id="saveSlate">Save as file</button></div>
          </div>
        </div>
      </div>
    </div>`);

  api.walletBalance().then((b) =>
    node.querySelector("#avail").textContent = `Spendable: ${nomsToDom(b.spendable)} DOM`).catch(() => {});

  node.querySelector("#create").onclick = async () => {
    const err = node.querySelector("#err"); err.textContent = "";
    try {
      const amount = domToNoms(node.querySelector("#amt").value);
      const fee = domToNoms(node.querySelector("#fee").value);
      if (amount <= 0n) {
        err.textContent = "Amount must be greater than zero.";
        return;
      }
      const bal = await api.walletBalance();
      if (amount + fee > BigInt(bal.spendable)) {
        err.textContent = "Amount + fee exceed the spendable balance."; return;
      }
      // M1: pass BigInt noms straight through — the api layer stringifies them,
      // avoiding the Number() 2^53 precision loss.
      const slateHex = await api.slateCreateSend(amount, fee);
      await showSlateResult(node, slateHex);
    } catch (e) { err.textContent = humanizeError(e); }
  };
  return node;
}

// Step 3 — SENDER finalizes the responded slate and submits it to the node.
function payFinalizeStep() {
  const node = el(`
    <div>
      <div class="card" id="form">
        <h2>Step 3 · Finalize and broadcast</h2>
        <p class="muted">Paste here the slate the recipient returned (their response to step 2).</p>
        <label>Responded slate</label>
        <textarea id="slateIn" placeholder="paste the recipient's slate (hex)…" spellcheck="false"></textarea>
        <div class="btn-row">
          <button class="btn ghost" id="load">Load from file</button>
          <button class="btn" id="finalize">Finalize and send</button>
        </div>
        <div class="err-text" id="err"></div>
      </div>
    </div>`);

  node.querySelector("#load").onclick = async () => {
    const text = await loadTextFile("Load responded slate");
    if (text) node.querySelector("#slateIn").value = text.trim();
  };
  node.querySelector("#finalize").onclick = async () => {
    const err = node.querySelector("#err"); err.textContent = "";
    const slateHex = node.querySelector("#slateIn").value.trim();
    if (!slateHex) { err.textContent = "Paste the responded slate."; return; }
    const btn = node.querySelector("#finalize"); btn.disabled = true;
    try {
      const hash = await api.slateFinalize(slateHex);
      toast("Transaction sent to the network: " + hash.slice(0, 16) + "…");
      node.querySelector("#slateIn").value = "";
    } catch (e) { err.textContent = humanizeError(e); }
    finally { btn.disabled = false; }
  };
  return node;
}

// ── Receive (recipient side): step 2 of the slate ────────────────────────────
export function renderReceive() {
  const node = el(`
    <div class="screen">
      <h1>Receive DOM</h1>
      <p class="sub">Receiving is interactive: import the slate the sender gave you, respond, and return the responded slate to them. The sender finalizes (step 3) to complete it.</p>
      <div class="card" id="form">
        <h2>Step 2 · Respond to the sender's slate</h2>
        <label>Slate received from the sender</label>
        <textarea id="slateIn" placeholder="paste the slate (hex) the sender gave you…" spellcheck="false"></textarea>
        <div class="btn-row">
          <button class="btn ghost" id="load">Load from file</button>
          <button class="btn" id="respond">Respond to slate</button>
        </div>
        <div class="err-text" id="err"></div>
      </div>
      <div class="card hidden" id="result">
        <div class="warn-box">Return this slate to the sender. They will finalize and broadcast the transaction.</div>
        <div class="qr-wrap">
          <div class="qr-box" id="qr"></div>
          <div class="flex1-min260">
            <label>Responded slate (return to the sender)</label>
            <div class="copyable"><code id="slate"></code><button class="btn ghost" id="copySlate">Copy</button></div>
            <div class="btn-row"><button class="btn ghost" id="saveSlate">Save as file</button></div>
          </div>
        </div>
      </div>
    </div>`);

  node.querySelector("#load").onclick = async () => {
    const text = await loadTextFile("Load sender's slate");
    if (text) node.querySelector("#slateIn").value = text.trim();
  };
  node.querySelector("#respond").onclick = async () => {
    const err = node.querySelector("#err"); err.textContent = "";
    const slateHex = node.querySelector("#slateIn").value.trim();
    if (!slateHex) { err.textContent = "Paste the received slate."; return; }
    const btn = node.querySelector("#respond"); btn.disabled = true;
    try {
      const responded = await api.slateReceive(slateHex);
      await showSlateResult(node, responded);
    } catch (e) { err.textContent = humanizeError(e); }
    finally { btn.disabled = false; }
  };
  return node;
}

// Shared helper: fill the result card with the slate (text + QR) and wire the
// Copy / Save buttons. The QR is only generated if the slate fits (QR has a
// capacity limit); large slates show just the text + file.
async function showSlateResult(node, slateHex) {
  node.querySelector("#slate").textContent = slateHex;
  node.querySelector("#result").classList.remove("hidden");
  node.querySelector("#copySlate").onclick = () => copy(slateHex);
  node.querySelector("#saveSlate").onclick = () =>
    saveTextViaDialog("Save slate", "slate.txt", slateHex);
  const qr = node.querySelector("#qr");
  try {
    const svg = await api.makeQrSvg(slateHex);
    qr.innerHTML = svg;
  } catch {
    // Slate larger than the QR capacity — guide the user to text/file.
    qr.innerHTML = `<div class="muted qr-fallback">Slate too large for a QR code. Use the copyable text or save it as a file.</div>`;
  }
}

// Load text from a user-chosen file (to import a slate).
// M4: the native dialog is opened in the backend; here we only pass the title.
// Returns the text, or null if the user cancelled.
async function loadTextFile(title) {
  try {
    return await api.readTextFile(title);
  } catch (e) {
    toast(humanizeError(e), true);
    return null;
  }
}

// ── History ──────────────────────────────────────────────────────────────────
export function renderHistory() {
  const node = el(`
    <div class="screen">
      <h1>History</h1>
      <p class="sub">Transactions recorded by this wallet.</p>
      <div class="card" id="list">
        <p class="muted">History is read from the wallet journal. Sent transactions appear here after they are submitted; receipts and coinbase appear once the node scans the chain.</p>
      </div>
    </div>`);
  return node;
}

// ── Node / Logs ──────────────────────────────────────────────────────────────
export function renderNode() {
  const node = el(`
    <div class="screen">
      <h1>Node / Logs</h1>
      <p class="sub">Your integrated DOM node and its live output.</p>
      <div class="card">
        <div class="stat-grid">
          <div class="stat"><div class="k">State</div><div class="v" id="nState">—</div></div>
          <div class="stat"><div class="k">Height</div><div class="v" id="nHeight">—</div></div>
          <div class="stat"><div class="k">Peers</div><div class="v" id="nPeers">—</div></div>
          <div class="stat"><div class="k">Mempool</div><div class="v" id="nMem">—</div></div>
          <div class="stat"><div class="k">Mining</div><div class="v" id="nMine">—</div></div>
          <div class="stat"><div class="k">Blocks mined</div><div class="v" id="nBlocks">—</div></div>
        </div>
        <div class="btn-row">
          <button class="btn" id="bStart">Start</button>
          <button class="btn ghost" id="bStop">Stop</button>
          <button class="btn ghost" id="bRestart">Restart</button>
          <button class="btn ghost" id="bSweep">Sweep rewards</button>
          <label class="check ml-auto"><input type="checkbox" id="mineToggle" /><span>Mine</span></label>
        </div>
      </div>
      <div class="card">
        <h2>Live logs</h2>
        <div class="log-toolbar">
          <select id="lvl">
            <option value="">All levels</option>
            <option>ERROR</option><option>WARN</option><option>INFO</option><option>DEBUG</option><option>TRACE</option>
          </select>
          <input type="text" id="filter" placeholder="filter text…" />
          <label class="check"><input type="checkbox" id="autoscroll" checked /><span>Auto-scroll</span></label>
          <button class="btn ghost" id="save">Save logs</button>
          <button class="btn ghost ml-auto" id="clear">Clear</button>
        </div>
        <div class="log-console" id="console"></div>
      </div>
    </div>`);

  const consoleEl = node.querySelector("#console");
  const lvlEl = node.querySelector("#lvl");
  const filterEl = node.querySelector("#filter");
  const autoEl = node.querySelector("#autoscroll");
  // Cap the number of DOM nodes kept in the console (H2). The in-memory ring
  // buffer keeps more lines for "Save logs"; the live view only needs a window.
  const MAX_DOM_LINES = 1000;

  const matches = (l) => {
    const lvl = lvlEl.value;
    const f = filterEl.value.toLowerCase();
    return (!lvl || l.level === lvl) &&
      (!f || (l.message + l.target).toLowerCase().includes(f));
  };

  // Full redraw — only on mount, filter/level change, or reset. NOT per line.
  const fullRender = () => {
    consoleEl.innerHTML = getLogLines().filter(matches).map(fmtLine).join("");
    if (autoEl.checked) consoleEl.scrollTop = consoleEl.scrollHeight;
  };

  // Incremental append, batched via requestAnimationFrame so a burst of lines
  // costs one DOM mutation instead of one full re-render per line (H2).
  let pending = [];
  let raf = 0;
  const flush = () => {
    raf = 0;
    const html = pending.filter(matches).map(fmtLine).join("");
    pending = [];
    if (!html) return;
    consoleEl.insertAdjacentHTML("beforeend", html);
    let extra = consoleEl.childElementCount - MAX_DOM_LINES;
    while (extra-- > 0 && consoleEl.firstElementChild) consoleEl.firstElementChild.remove();
    if (autoEl.checked) consoleEl.scrollTop = consoleEl.scrollHeight;
  };
  const onLog = (line) => {
    if (line == null) { fullRender(); return; } // null = reset/clear
    pending.push(line);
    if (!raf) raf = requestAnimationFrame(flush);
  };

  // Show the lines already captured (even if the tab is opened after the node
  // started), then append each new line as it arrives.
  fullRender();
  const unsub = subscribeLogs(onLog);

  lvlEl.onchange = fullRender;
  filterEl.oninput = fullRender;
  node.querySelector("#clear").onclick = () => { clearLogs(); }; // notifies null → fullRender

  node.querySelector("#save").onclick = async () => {
    const lvl = node.querySelector("#lvl").value;
    const f = node.querySelector("#filter").value;
    const text = logsToText(f, lvl);
    if (!text) { toast("No logs to save.", true); return; }
    const stamp = new Date().toISOString().replace(/[:.]/g, "-");
    try {
      const saved = await api.saveTextFile(
        "Save node logs",
        `dom-node-logs-${stamp}.txt`,
        text);
      if (saved) toast(t("logsSaved"));
    } catch (e) { toast(humanizeError(e), true); }
  };

  node.querySelector("#bStart").onclick = async () => {
    try { await api.nodeStart(settings.current); toast(t("nodeStarting")); }
    catch (e) { toast(humanizeError(e), true); }
  };
  node.querySelector("#bStop").onclick = async () => {
    try { await api.nodeStop(); toast(t("nodeStopping")); } catch (e) { toast(humanizeError(e), true); }
  };
  node.querySelector("#bRestart").onclick = async () => {
    try { await api.nodeRestart(settings.current); toast(t("nodeRestarting")); }
    catch (e) { toast(humanizeError(e), true); }
  };
  node.querySelector("#bSweep").onclick = async () => {
    const btn = node.querySelector("#bSweep"); btn.disabled = true;
    try {
      const tx = await api.sweepMinerRewards();
      if (tx) {
        toast("Rewards swept to your wallet: " + tx.slice(0, 16) + "…");
      } else {
        toast("Nothing matured to sweep yet.");
      }
    } catch (e) { toast(humanizeError(e), true); }
    finally { btn.disabled = false; }
  };
  const mineToggle = node.querySelector("#mineToggle");
  mineToggle.checked = !!settings.current.mine;
  mineToggle.onchange = async () => {
    settings.current.mine = mineToggle.checked;
    savePrefs(settings.current);
    try { await api.nodeRestart(settings.current); toast(t("applyingMining")); }
    catch (e) { toast(humanizeError(e), true); }
  };

  const labels = { running: "running", stopped: "stopped", starting: "starting", stopping: "stopping" };
  const refresh = async () => {
    try {
      const st = await api.nodeStatus();
      node.querySelector("#nState").textContent = labels[st.state] || st.state || "—";
      if (st.chain_height !== undefined) node.querySelector("#nHeight").textContent = st.chain_height;
      if (st.mempool_size !== undefined) node.querySelector("#nMem").textContent = st.mempool_size;
    } catch {}
    try {
      const m = await api.nodeMetrics(settings.current.metrics_listen_addr || "127.0.0.1:33371");
      node.querySelector("#nPeers").textContent = m.peer_count;
      node.querySelector("#nMem").textContent = m.mempool_size;
      node.querySelector("#nMine").textContent = m.mining_active ? "active" : "off";
      node.querySelector("#nBlocks").textContent = m.blocks_mined;
    } catch {}
  };
  refresh();
  const timer = setInterval(refresh, 4000);
  node._cleanup = () => {
    clearInterval(timer);
    unsub();
    if (raf) cancelAnimationFrame(raf);
  };
  return node;
}

function fmtLine(l) {
  const ts = new Date(l.ts_ms).toLocaleTimeString();
  const esc = (s) => String(s).replace(/[&<>]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;" }[c]));
  const tgt = l.target.split("::")[0];
  return `<div class="log-line"><span class="t">${ts}</span><span class="lvl ${l.level}">${l.level}</span><span class="tgt">${esc(tgt)}</span><span class="msg">${esc(l.message)}</span></div>`;
}

// ── Settings ─────────────────────────────────────────────────────────────────
export function renderSettings(onApply) {
  const s = settings.current;
  const node = el(`
    <div class="screen">
      <h1>Settings</h1>
      <p class="sub">Node network, ports and data location. Changes take effect when the node starts/restarts.</p>
      <div class="card">
        <label>Network</label>
        <select id="network" disabled>
          <option value="testnet">Testnet</option>
          <option value="mainnet">Mainnet</option>
          <option value="regtest">Regtest (local dev)</option>
        </select>
        <p class="muted mt4">The network is fixed by the open wallet and cannot be changed here. To use another network, create or restore a wallet for it.</p>
        <label>Seed peers (host:port, comma-separated)</label>
        <input type="text" id="seeds" placeholder="1.2.3.4:33370, 5.6.7.8:33370" />
        <div class="row">
          <div class="flex1"><label>P2P listen</label><input type="text" id="p2p" /></div>
          <div class="flex1"><label>RPC listen</label><input type="text" id="rpc" /></div>
        </div>
        <div class="row">
          <div class="flex1"><label>Metrics listen</label><input type="text" id="metrics" /></div>
          <div class="flex1"><label>Log level</label>
            <select id="log"><option>info</option><option>debug</option><option>warn</option><option>error</option><option>trace</option></select>
          </div>
        </div>
        <label>Data directory</label>
        <div class="copyable"><code id="data"></code><button class="btn ghost" id="pickData">Change</button></div>
        <label>Miner reward wallet (.dom, optional)</label>
        <div class="copyable"><code id="miner"></code><button class="btn ghost" id="pickMiner">Choose</button></div>
        <p class="muted mt4">Leave blank to let the app use a dedicated mining wallet (created automatically in the data directory). Your personal wallet is never used for mining and its password is never shared with the node.</p>
        <div class="check"><input type="checkbox" id="mine" /><label>Mine on this node</label></div>
        <div class="btn-row"><button class="btn" id="apply">Save and apply</button></div>
      </div>
      <div class="card">
        <h2>Access</h2>
        <div class="row">
          <div class="flex1">
            <label>Auto-lock on inactivity</label>
            <select id="autolock">
              <option value="1">1 minute</option>
              <option value="5">5 minutes</option>
              <option value="15">15 minutes</option>
              <option value="30">30 minutes</option>
              <option value="0">Never</option>
            </select>
          </div>
        </div>
      </div>
      <div class="card">
        <h2>Security</h2>
        <p class="muted">Showing the recovery phrase is not possible after creation — by design, DOM wallets store the seed as encrypted bytes, not as recoverable words. Keep your written backup safe. <strong>No one from DOM will ever ask for your recovery phrase.</strong></p>
        <div class="btn-row"><button class="btn danger" id="lock">Lock wallet now</button></div>
      </div>
    </div>`);

  node.querySelector("#network").value = s.network;
  node.querySelector("#seeds").value = (s.seed_peers || []).join(", ");
  node.querySelector("#p2p").value = s.p2p_listen_addr;
  node.querySelector("#rpc").value = s.rpc_listen_addr;
  node.querySelector("#metrics").value = s.metrics_listen_addr || "";
  node.querySelector("#log").value = s.log_level;
  node.querySelector("#data").textContent = s.data_dir;
  node.querySelector("#miner").textContent = s.miner_wallet_path || "— none —";
  node.querySelector("#mine").checked = !!s.mine;
  node.querySelector("#autolock").value = String(
    typeof s.auto_lock_minutes === "number" ? s.auto_lock_minutes : 5);

  node.querySelector("#pickData").onclick = async () => {
    const dir = await window.__TAURI__.dialog.open({ directory: true, multiple: false });
    // L11: persist immediately so the choice survives navigating away without
    // clicking "Apply".
    if (dir) { s.data_dir = dir; node.querySelector("#data").textContent = dir; savePrefs(s); }
  };
  node.querySelector("#pickMiner").onclick = async () => {
    const f = await pickSaveFile("Choose miner wallet (.dom)");
    if (f) { s.miner_wallet_path = f; node.querySelector("#miner").textContent = f; savePrefs(s); }
  };
  node.querySelector("#lock").onclick = async () => { await api.walletLock(); location.reload(); };

  // Auto-lock applies immediately (no node restart needed).
  node.querySelector("#autolock").onchange = (e) => {
    s.auto_lock_minutes = parseInt(e.target.value, 10);
    savePrefs(s);
    onApply(); // restart the inactivity timer with the new value
  };

  node.querySelector("#apply").onclick = async () => {
    // Network stays fixed to the open wallet (M2); the disabled select keeps it.
    s.seed_peers = node.querySelector("#seeds").value.split(",").map((x) => x.trim()).filter(Boolean);
    s.p2p_listen_addr = node.querySelector("#p2p").value.trim();
    s.rpc_listen_addr = node.querySelector("#rpc").value.trim();
    const met = node.querySelector("#metrics").value.trim();
    s.metrics_listen_addr = met || null;
    s.log_level = node.querySelector("#log").value;
    s.mine = node.querySelector("#mine").checked;
    savePrefs(s);
    onApply();
    try { await api.nodeRestart(s); toast(t("settingsApplied")); }
    catch (e) { toast(humanizeError(e), true); }
  };
  return node;
}
