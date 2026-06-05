// Screen renderers. Each returns an element and wires its own events.
import {
  api, el, copy, toast, nomsToDom, domToNoms,
  pickSaveFile, pickFile, pickSaveTextFile, saveTextViaDialog, savePrefs, humanizeError, getLang, setLang,
} from "./api.js";
import {
  getLogLines, clearLogs, subscribeLogs, logsToText,
} from "./logbuffer.js";

// Shared, in-memory settings object (single source of truth for node config).
// Sensitive values (passwords/phrases) are NEVER stored here.
export const settings = { current: null };

// Pequeno dicionário de mensagens da UI (pt/en). Para textos curtos de toast.
const MSG = {
  walletCreated: { pt: "Carteira criada", en: "Wallet created" },
  walletRestored: { pt: "Carteira restaurada", en: "Wallet restored" },
  walletOpened: { pt: "Carteira aberta", en: "Wallet opened" },
  txSubmitted: { pt: "Transação enviada: ", en: "Transaction submitted: " },
  nodeStarting: { pt: "Iniciando o nó…", en: "Node starting…" },
  nodeStopping: { pt: "Parando o nó…", en: "Node stopping…" },
  nodeRestarting: { pt: "Reiniciando o nó…", en: "Node restarting…" },
  applyingMining: { pt: "Aplicando mineração (reiniciando o nó)…", en: "Applying mining (restarting node)…" },
  settingsApplied: { pt: "Configurações aplicadas — reiniciando o nó", en: "Settings applied — node restarting" },
  logsSaved: { pt: "Logs salvos", en: "Logs saved" },
};
function t(key) {
  const m = MSG[key];
  if (!m) return key;
  return m[getLang()] || m.pt;
}

// ── Onboarding: welcome ──────────────────────────────────────────────────────
export function renderWelcome(go) {
  const node = el(`
    <div>
      <h1 style="text-align:center">DOM Wallet</h1>
      <p class="sub" style="text-align:center">Carteira desktop oficial com nó DOM integrado.</p>
      <div class="card">
        <button class="btn" id="bCreate" style="width:100%">Criar nova carteira</button>
        <div class="btn-row"><button class="btn ghost" id="bRestore" style="width:100%">Restaurar de frase de recuperação</button></div>
        <div class="btn-row"><button class="btn ghost" id="bOpen" style="width:100%">Abrir carteira existente</button></div>
      </div>
      <p class="muted" style="text-align:center">Privacy by design · Sovereign by choice</p>
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
      <h1>Criar carteira</h1>
      <p class="sub">Uma nova frase de recuperação de 24 palavras será gerada. Anote-a — é a única forma de recuperar seus fundos.</p>
      <div class="card">
        <label>Local da carteira</label>
        <div class="copyable"><code id="path">— escolha um local —</code><button class="btn ghost" id="pick">Escolher</button></div>
        <label>Senha</label>
        <input type="password" id="pw" placeholder="Encrypts the wallet on disk" />
        <label>Confirmar senha</label>
        <input type="password" id="pw2" placeholder="Re-enter password" />
        <div class="btn-row">
          <button class="btn ghost" id="back">Voltar</button>
          <button class="btn" id="next" disabled>Gerar frase</button>
        </div>
        <div class="err-text" id="err"></div>
      </div>
    </div>`);

  let path = null;
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
      <h1>Sua frase de recuperação</h1>
      <div class="warn-box">Anote estas ${words.length} palavras em papel, na ordem. Quem tiver esta frase pode levar seus fundos. Ela não será mostrada de novo.</div>
      <div class="warn-box" style="border-color:var(--err);color:var(--err)">⚠ Ninguém da DOM vai pedir sua frase de recuperação. Nunca compartilhe, digite em sites, ou envie por mensagem. Guarde-a offline.</div>
      <div class="card"><div class="seed-grid">${grid}</div>
        <div class="btn-row"><button class="btn" id="wrote">Anotei minha frase</button></div>
      </div>
    </div>`));

  container.querySelector("#wrote").onclick = () => {
    // Ask the user to confirm 3 random positions.
    const idxs = pickThree(words.length);
    container.innerHTML = "";
    container.appendChild(el(`
      <div>
        <h1>Confirme sua frase</h1>
        <p class="sub">Digite as palavras pedidas para confirmar que você as salvou.</p>
        <div class="card">
          ${idxs.map((i) => `
            <label>Palavra #${i + 1}</label>
            <input type="text" data-idx="${i}" autocomplete="off" spellcheck="false" />`).join("")}
          <div class="btn-row"><button class="btn" id="confirm">Confirmar e abrir carteira</button></div>
          <div class="err-text" id="cerr"></div>
        </div>
      </div>`));
    container.querySelector("#confirm").onclick = () => {
      const inputs = [...container.querySelectorAll("input[data-idx]")];
      const ok = inputs.every((inp) =>
        inp.value.trim().toLowerCase() === words[+inp.dataset.idx].toLowerCase());
      if (!ok) { container.querySelector("#cerr").textContent = "Words do not match. Check your written copy."; return; }
      toast(t("walletCreated"));
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
      <h1>Restaurar carteira</h1>
      <p class="sub">Digite sua frase de recuperação BIP-39, escolha onde salvar e uma nova senha.</p>
      <div class="card">
        <label>Frase de recuperação</label>
        <textarea id="phrase" placeholder="word1 word2 word3 ..."></textarea>
        <label>Local da carteira</label>
        <div class="copyable"><code id="path">— escolha um local —</code><button class="btn ghost" id="pick">Escolher</button></div>
        <label>Nova senha</label>
        <input type="password" id="pw" />
        <div class="btn-row">
          <button class="btn ghost" id="back">Voltar</button>
          <button class="btn" id="go">Restaurar</button>
        </div>
        <div class="err-text" id="err"></div>
      </div>
    </div>`);
  let path = null;
  node.querySelector("#pick").onclick = async () => {
    const p = await pickSaveFile("Save restored DOM wallet");
    if (p) { path = p; node.querySelector("#path").textContent = p; }
  };
  node.querySelector("#back").onclick = () => go("welcome");
  node.querySelector("#go").onclick = async () => {
    const err = node.querySelector("#err");
    const phrase = node.querySelector("#phrase").value.trim();
    const pw = node.querySelector("#pw").value;
    if (!path) { err.textContent = "Choose a wallet location."; return; }
    if (pw.length < 8) { err.textContent = "Use at least 8 characters."; return; }
    try {
      await api.walletRestore(path, pw, phrase, settings.current);
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
      <h1>Abrir carteira</h1>
      <div class="card">
        <label>Arquivo da carteira (diretório .dom)</label>
        <div class="copyable"><code id="path">— escolher —</code><button class="btn ghost" id="pick">Escolher</button></div>
        <label>Senha</label>
        <input type="password" id="pw" />
        <div class="btn-row">
          <button class="btn ghost" id="back">Voltar</button>
          <button class="btn" id="go">Abrir</button>
        </div>
        <div class="err-text" id="err"></div>
      </div>
    </div>`);
  let path = null;
  node.querySelector("#pick").onclick = async () => {
    const p = await pickFile("Open DOM wallet");
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
      <h1>Desbloquear</h1>
      <div class="card">
        <label>Senha</label>
        <input type="password" id="pw" autofocus />
        <div class="btn-row"><button class="btn" id="go">Desbloquear</button></div>
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
      <p class="sub">Seu saldo e o estado do seu nó integrado.</p>
      <div class="card hidden" id="syncBanner" style="border-color:var(--warn);background:rgba(212,162,74,0.10)">
        <span class="pill" style="background:transparent;border:none">
          <span class="dot busy"></span>
          <span id="syncText" style="color:var(--warn)">Sincronizando…</span>
        </span>
        <p class="muted" style="margin-top:6px">O nó ainda está baixando a cadeia. Seu saldo só é confiável após a sincronização — moedas que ainda não apareceram podem surgir ao concluir.</p>
      </div>
      <div class="card">
        <div class="balance-main"><span id="balTotal">—</span><span class="unit">DOM</span></div>
        <div class="balance-sub">
          <div><div class="k">Gastável</div><div class="v" id="balSpend">—</div></div>
          <div><div class="k">Pendente (imaturo)</div><div class="v pending" id="balImm">—</div></div>
        </div>
      </div>
      <div class="row">
        <div class="card"><div class="k" style="color:var(--text-2);font-size:11px;text-transform:uppercase">Altura da cadeia</div><div class="balance-main" style="font-size:26px"><span id="height">—</span></div></div>
        <div class="card"><div class="k" style="color:var(--text-2);font-size:11px;text-transform:uppercase">Rede</div><div class="balance-main" style="font-size:26px"><span id="net">—</span></div></div>
        <div class="card"><div class="k" style="color:var(--text-2);font-size:11px;text-transform:uppercase">Peers</div><div class="balance-main" style="font-size:26px"><span id="peers">—</span></div></div>
      </div>
      <div class="card">
        <span class="pill"><span class="dot" id="nodeDot"></span><span id="nodeState">nó: desconhecido</span></span>
        <span class="pill" style="margin-left:8px"><span class="dot" id="mineDot"></span><span id="mineState">mineração: —</span></span>
      </div>
    </div>`);
  // estado de IBD entre leituras
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
    ms.textContent = "mineração: " + (m.mining_active ? "ativa" : "desligada");
  } catch {}

  // Heurística de sincronização (IBD): sem uma "altura da rede" exposta pela
  // API, consideramos sincronizando enquanto a altura cresce entre leituras.
  // Quando a altura para de subir por algumas leituras com peers conectados,
  // marcamos como sincronizado.
  const s = node._sync;
  const banner = node.querySelector("#syncBanner");
  const syncText = node.querySelector("#syncText");
  if (height !== undefined) {
    if (s.lastHeight !== null && height > s.lastHeight) {
      s.stableTicks = 0;
      s.synced = false;
    } else if (s.lastHeight !== null && height === s.lastHeight) {
      s.stableTicks += 1;
      // 2 leituras estáveis (~10s) com peers ⇒ provavelmente na ponta da cadeia.
      if (s.stableTicks >= 2 && peers > 0) s.synced = true;
    }
    s.lastHeight = height;
  }
  // Sem peers e altura baixa: certamente ainda não sincronizou.
  if (height !== undefined && !s.synced) {
    banner.classList.remove("hidden");
    syncText.textContent = `Sincronizando… (altura ${height}${peers ? `, ${peers} peers` : ", sem peers ainda"})`;
  } else {
    banner.classList.add("hidden");
  }

  // Saldo: sempre mostramos, mas o banner avisa que pode estar incompleto no IBD.
  try {
    const bal = await api.walletBalance();
    node.querySelector("#balTotal").textContent = nomsToDom(bal.total);
    node.querySelector("#balSpend").textContent = nomsToDom(bal.spendable);
    node.querySelector("#balImm").textContent = nomsToDom(bal.immature);
  } catch { /* nó pode não estar pronto ainda */ }
}

function setNodePill(node, state) {
  const dot = node.querySelector("#nodeDot"); const lbl = node.querySelector("#nodeState");
  if (!dot) return;
  const map = { running: "on", stopped: "off", starting: "busy", stopping: "busy" };
  const labels = { running: "rodando", stopped: "parado", starting: "iniciando", stopping: "parando" };
  dot.className = "dot " + (map[state] || "");
  lbl.textContent = "nó: " + (labels[state] || state || "desconhecido");
}

// ── Send ─────────────────────────────────────────────────────────────────────
// ── Pagar (lado de quem paga): Enviar (passo 1) + Finalizar (passo 3) ─────────
// Fluxo slate interativo (Mimblewimble): diferente de Bitcoin, são DOIS passos
// de quem paga, com o destinatário respondendo no meio.
export function renderPay() {
  const node = el(`
    <div class="screen">
      <h1>Pagar DOM</h1>
      <p class="sub">Pagamento é interativo: você cria um slate, o destinatário responde, e você finaliza. São duas trocas — diferente do modelo de endereço do Bitcoin.</p>
      <div class="card">
        <div class="btn-row" style="margin-top:0">
          <button class="btn" id="tabSend">1 · Enviar</button>
          <button class="btn ghost" id="tabFinal">3 · Finalizar</button>
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

// Passo 1 — REMETENTE cria o slate.
function paySendStep() {
  const node = el(`
    <div>
      <div class="card" id="form">
        <h2>Passo 1 · Criar slate de envio</h2>
        <label>Valor (DOM)</label>
        <input type="text" id="amt" placeholder="0.00000000" />
        <label>Taxa (DOM)</label>
        <input type="text" id="fee" value="0.00100000" />
        <div class="btn-row"><button class="btn" id="create">Gerar slate</button></div>
        <div class="err-text" id="err"></div>
        <p class="muted" id="avail" style="margin-top:10px"></p>
      </div>
      <div class="card hidden" id="result">
        <div class="warn-box">O envio ainda NÃO está completo. Mande este slate ao destinatário; ele responderá com um slate para você <b>Finalizar</b> (passo 3).</div>
        <div class="qr-wrap">
          <div class="qr-box" id="qr"></div>
          <div style="flex:1;min-width:260px">
            <label>Slate (envie ao destinatário)</label>
            <div class="copyable"><code id="slate"></code><button class="btn ghost" id="copySlate">Copiar</button></div>
            <div class="btn-row"><button class="btn ghost" id="saveSlate">Salvar como arquivo</button></div>
          </div>
        </div>
      </div>
    </div>`);

  api.walletBalance().then((b) =>
    node.querySelector("#avail").textContent = `Gastável: ${nomsToDom(b.spendable)} DOM`).catch(() => {});

  node.querySelector("#create").onclick = async () => {
    const err = node.querySelector("#err"); err.textContent = "";
    try {
      const amount = domToNoms(node.querySelector("#amt").value);
      const fee = domToNoms(node.querySelector("#fee").value);
      if (amount <= 0n) {
        err.textContent = "O valor deve ser maior que zero.";
        return;
      }
      const bal = await api.walletBalance();
      if (amount + fee > BigInt(bal.spendable)) {
        err.textContent = "Valor + taxa excedem o saldo gastável."; return;
      }
      const slateHex = await api.slateCreateSend(Number(amount), Number(fee));
      await showSlateResult(node, slateHex);
    } catch (e) { err.textContent = humanizeError(e); }
  };
  return node;
}

// Passo 3 — REMETENTE finaliza o slate respondido e submete ao nó.
function payFinalizeStep() {
  const node = el(`
    <div>
      <div class="card" id="form">
        <h2>Passo 3 · Finalizar e enviar à rede</h2>
        <p class="muted">Cole aqui o slate que o destinatário devolveu (resposta ao passo 2).</p>
        <label>Slate respondido</label>
        <textarea id="slateIn" placeholder="cole o slate (hex) do destinatário…" spellcheck="false"></textarea>
        <div class="btn-row">
          <button class="btn ghost" id="load">Carregar de arquivo</button>
          <button class="btn" id="finalize">Finalizar e enviar</button>
        </div>
        <div class="err-text" id="err"></div>
      </div>
    </div>`);

  node.querySelector("#load").onclick = async () => {
    const text = await loadTextFile("Carregar slate respondido");
    if (text) node.querySelector("#slateIn").value = text.trim();
  };
  node.querySelector("#finalize").onclick = async () => {
    const err = node.querySelector("#err"); err.textContent = "";
    const slateHex = node.querySelector("#slateIn").value.trim();
    if (!slateHex) { err.textContent = "Cole o slate respondido."; return; }
    const btn = node.querySelector("#finalize"); btn.disabled = true;
    try {
      const hash = await api.slateFinalize(slateHex);
      toast((getLang() === "en" ? "Transaction sent to the network: " : "Transação enviada à rede: ") + hash.slice(0, 16) + "…");
      node.querySelector("#slateIn").value = "";
    } catch (e) { err.textContent = humanizeError(e); }
    finally { btn.disabled = false; }
  };
  return node;
}

// ── Receber (lado de quem recebe): passo 2 do slate ──────────────────────────
export function renderReceive() {
  const node = el(`
    <div class="screen">
      <h1>Receber DOM</h1>
      <p class="sub">Receber é interativo: importe o slate que o remetente te enviou, responda, e devolva o slate respondido a ele. O remetente finaliza (passo 3) para concluir.</p>
      <div class="card" id="form">
        <h2>Passo 2 · Responder ao slate do remetente</h2>
        <label>Slate recebido do remetente</label>
        <textarea id="slateIn" placeholder="cole o slate (hex) que o remetente te enviou…" spellcheck="false"></textarea>
        <div class="btn-row">
          <button class="btn ghost" id="load">Carregar de arquivo</button>
          <button class="btn" id="respond">Responder slate</button>
        </div>
        <div class="err-text" id="err"></div>
      </div>
      <div class="card hidden" id="result">
        <div class="warn-box">Devolva este slate ao remetente. Ele vai finalizar e enviar a transação à rede.</div>
        <div class="qr-wrap">
          <div class="qr-box" id="qr"></div>
          <div style="flex:1;min-width:260px">
            <label>Slate respondido (devolva ao remetente)</label>
            <div class="copyable"><code id="slate"></code><button class="btn ghost" id="copySlate">Copiar</button></div>
            <div class="btn-row"><button class="btn ghost" id="saveSlate">Salvar como arquivo</button></div>
          </div>
        </div>
      </div>
    </div>`);

  node.querySelector("#load").onclick = async () => {
    const text = await loadTextFile("Carregar slate do remetente");
    if (text) node.querySelector("#slateIn").value = text.trim();
  };
  node.querySelector("#respond").onclick = async () => {
    const err = node.querySelector("#err"); err.textContent = "";
    const slateHex = node.querySelector("#slateIn").value.trim();
    if (!slateHex) { err.textContent = "Cole o slate recebido."; return; }
    const btn = node.querySelector("#respond"); btn.disabled = true;
    try {
      const responded = await api.slateReceive(slateHex);
      await showSlateResult(node, responded);
    } catch (e) { err.textContent = humanizeError(e); }
    finally { btn.disabled = false; }
  };
  return node;
}

// Helper compartilhado: preenche o card de resultado com o slate (texto+QR) e
// liga os botões Copiar / Salvar. QR só é gerado se o slate couber (QR tem
// limite de capacidade); slates grandes mostram só o texto + arquivo.
async function showSlateResult(node, slateHex) {
  node.querySelector("#slate").textContent = slateHex;
  node.querySelector("#result").classList.remove("hidden");
  node.querySelector("#copySlate").onclick = () => copy(slateHex);
  node.querySelector("#saveSlate").onclick = () =>
    saveTextViaDialog("Salvar slate", "slate.txt", slateHex);
  const qr = node.querySelector("#qr");
  try {
    const svg = await api.makeQrSvg(slateHex);
    qr.innerHTML = svg;
  } catch {
    // Slate maior que a capacidade do QR — orientar a usar texto/arquivo.
    qr.innerHTML = `<div class="muted" style="padding:20px;max-width:200px">Slate grande demais para QR. Use o texto copiável ou salve como arquivo.</div>`;
  }
}

// Carrega texto de um arquivo escolhido pelo usuário (para importar slate).
async function loadTextFile(title) {
  const path = await pickFile(title);
  if (!path) return null;
  try {
    return await api.readTextFile(path);
  } catch (e) {
    toast(humanizeError(e), true);
    return null;
  }
}

// ── History ──────────────────────────────────────────────────────────────────
export function renderHistory() {
  const node = el(`
    <div class="screen">
      <h1>Histórico</h1>
      <p class="sub">Transações registradas por esta carteira.</p>
      <div class="card" id="list">
        <p class="muted">O histórico é lido do journal da carteira. Transações enviadas aparecem aqui após serem submetidas; recebimentos e coinbase aparecem depois que o nó varre a cadeia.</p>
      </div>
    </div>`);
  return node;
}

// ── Node / Logs ──────────────────────────────────────────────────────────────
export function renderNode() {
  const node = el(`
    <div class="screen">
      <h1>Nó / Logs</h1>
      <p class="sub">Seu nó DOM integrado e a saída ao vivo dele.</p>
      <div class="card">
        <div class="stat-grid">
          <div class="stat"><div class="k">Estado</div><div class="v" id="nState">—</div></div>
          <div class="stat"><div class="k">Altura</div><div class="v" id="nHeight">—</div></div>
          <div class="stat"><div class="k">Peers</div><div class="v" id="nPeers">—</div></div>
          <div class="stat"><div class="k">Mempool</div><div class="v" id="nMem">—</div></div>
          <div class="stat"><div class="k">Mineração</div><div class="v" id="nMine">—</div></div>
          <div class="stat"><div class="k">Blocos minerados</div><div class="v" id="nBlocks">—</div></div>
        </div>
        <div class="btn-row">
          <button class="btn" id="bStart">Iniciar</button>
          <button class="btn ghost" id="bStop">Parar</button>
          <button class="btn ghost" id="bRestart">Reiniciar</button>
          <button class="btn ghost" id="bSweep">Recolher recompensas</button>
          <label class="check" style="margin-left:auto"><input type="checkbox" id="mineToggle" /><span>Minerar</span></label>
        </div>
      </div>
      <div class="card">
        <h2>Logs ao vivo</h2>
        <div class="log-toolbar">
          <select id="lvl">
            <option value="">Todos os níveis</option>
            <option>ERROR</option><option>WARN</option><option>INFO</option><option>DEBUG</option><option>TRACE</option>
          </select>
          <input type="text" id="filter" placeholder="filtrar texto…" />
          <label class="check"><input type="checkbox" id="autoscroll" checked /><span>Rolagem automática</span></label>
          <button class="btn ghost" id="save">Salvar logs</button>
          <button class="btn ghost" id="clear" style="margin-left:auto">Limpar</button>
        </div>
        <div class="log-console" id="console"></div>
      </div>
    </div>`);

  const consoleEl = node.querySelector("#console");

  const render = () => {
    const lvl = node.querySelector("#lvl").value;
    const f = node.querySelector("#filter").value.toLowerCase();
    const visible = getLogLines().filter((l) =>
      (!lvl || l.level === lvl) &&
      (!f || (l.message + l.target).toLowerCase().includes(f)));
    consoleEl.innerHTML = visible.map(fmtLine).join("");
    if (node.querySelector("#autoscroll").checked) consoleEl.scrollTop = consoleEl.scrollHeight;
  };

  // Mostra imediatamente as últimas N linhas já capturadas (mesmo abrindo a
  // aba depois de o nó ter iniciado), e re-renderiza a cada nova linha.
  render();
  const unsub = subscribeLogs(render);

  node.querySelector("#lvl").onchange = render;
  node.querySelector("#filter").oninput = render;
  node.querySelector("#clear").onclick = () => { clearLogs(); render(); };

  node.querySelector("#save").onclick = async () => {
    const lvl = node.querySelector("#lvl").value;
    const f = node.querySelector("#filter").value;
    const text = logsToText(f, lvl);
    if (!text) { toast(getLang() === "en" ? "No logs to save." : "Nenhum log para salvar.", true); return; }
    const stamp = new Date().toISOString().replace(/[:.]/g, "-");
    const path = await pickSaveTextFile(
      getLang() === "en" ? "Save node logs" : "Salvar logs do nó",
      `dom-node-logs-${stamp}.txt`);
    if (!path) return;
    try { await api.saveTextFile(path, text); toast(t("logsSaved")); }
    catch (e) { toast(humanizeError(e), true); }
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
        toast((getLang() === "en" ? "Rewards swept to your wallet: " : "Recompensas recolhidas: ") + tx.slice(0, 16) + "…");
      } else {
        toast(getLang() === "en" ? "Nothing matured to sweep yet." : "Nada maduro para recolher ainda.");
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

  const labels = { running: "rodando", stopped: "parado", starting: "iniciando", stopping: "parando" };
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
      node.querySelector("#nMine").textContent = m.mining_active ? "ativa" : "desligada";
      node.querySelector("#nBlocks").textContent = m.blocks_mined;
    } catch {}
  };
  refresh();
  const timer = setInterval(refresh, 4000);
  node._cleanup = () => { clearInterval(timer); unsub(); };
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
      <h1>Configurações</h1>
      <p class="sub">Rede do nó, portas e local de dados. As mudanças entram em vigor ao iniciar/reiniciar o nó.</p>
      <div class="card">
        <label>Rede</label>
        <select id="network">
          <option value="testnet">Testnet</option>
          <option value="mainnet">Mainnet</option>
          <option value="regtest">Regtest (dev local)</option>
        </select>
        <label>Seed peers (host:porta, separados por vírgula)</label>
        <input type="text" id="seeds" placeholder="1.2.3.4:33370, 5.6.7.8:33370" />
        <div class="row">
          <div style="flex:1"><label>P2P listen</label><input type="text" id="p2p" /></div>
          <div style="flex:1"><label>RPC listen</label><input type="text" id="rpc" /></div>
        </div>
        <div class="row">
          <div style="flex:1"><label>Metrics listen</label><input type="text" id="metrics" /></div>
          <div style="flex:1"><label>Nível de log</label>
            <select id="log"><option>info</option><option>debug</option><option>warn</option><option>error</option><option>trace</option></select>
          </div>
        </div>
        <label>Diretório de dados</label>
        <div class="copyable"><code id="data"></code><button class="btn ghost" id="pickData">Alterar</button></div>
        <label>Carteira de recompensa do minerador (.dom, opcional)</label>
        <div class="copyable"><code id="miner"></code><button class="btn ghost" id="pickMiner">Escolher</button></div>
        <p class="muted" style="margin-top:4px">Deixe em branco para o app usar uma carteira de mineração dedicada (criada automaticamente na pasta de dados). Sua carteira pessoal não é usada para minerar e a senha dela nunca é compartilhada com o nó.</p>
        <div class="check"><input type="checkbox" id="mine" /><label>Minerar neste nó</label></div>
        <div class="btn-row"><button class="btn" id="apply">Salvar e aplicar</button></div>
      </div>
      <div class="card">
        <h2>Acesso</h2>
        <div class="row">
          <div style="flex:1">
            <label>Bloqueio automático por inatividade</label>
            <select id="autolock">
              <option value="1">1 minuto</option>
              <option value="5">5 minutos</option>
              <option value="15">15 minutos</option>
              <option value="30">30 minutos</option>
              <option value="0">Nunca</option>
            </select>
          </div>
          <div style="flex:1">
            <label>Idioma das mensagens</label>
            <select id="lang">
              <option value="pt">Português</option>
              <option value="en">English</option>
            </select>
          </div>
        </div>
      </div>
      <div class="card">
        <h2>Segurança</h2>
        <p class="muted">Mostrar a frase de recuperação não é possível após a criação — por design, as carteiras DOM guardam o seed em bytes cifrados, não como palavras recuperáveis. Mantenha seu backup escrito em segurança. <strong>Ninguém da DOM vai pedir sua frase de recuperação.</strong></p>
        <div class="btn-row"><button class="btn danger" id="lock">Bloquear carteira agora</button></div>
      </div>
    </div>`);

  node.querySelector("#network").value = s.network;
  node.querySelector("#seeds").value = (s.seed_peers || []).join(", ");
  node.querySelector("#p2p").value = s.p2p_listen_addr;
  node.querySelector("#rpc").value = s.rpc_listen_addr;
  node.querySelector("#metrics").value = s.metrics_listen_addr || "";
  node.querySelector("#log").value = s.log_level;
  node.querySelector("#data").textContent = s.data_dir;
  node.querySelector("#miner").textContent = s.miner_wallet_path || "— nenhuma —";
  node.querySelector("#mine").checked = !!s.mine;
  node.querySelector("#autolock").value = String(
    typeof s.auto_lock_minutes === "number" ? s.auto_lock_minutes : 5);
  node.querySelector("#lang").value = getLang();

  node.querySelector("#pickData").onclick = async () => {
    const dir = await window.__TAURI__.dialog.open({ directory: true, multiple: false });
    if (dir) { s.data_dir = dir; node.querySelector("#data").textContent = dir; }
  };
  node.querySelector("#pickMiner").onclick = async () => {
    const f = await pickSaveFile("Escolher carteira do minerador (.dom)");
    if (f) { s.miner_wallet_path = f; node.querySelector("#miner").textContent = f; }
  };
  node.querySelector("#lock").onclick = async () => { await api.walletLock(); location.reload(); };

  // Auto-lock e idioma aplicam na hora (não exigem reinício do nó).
  node.querySelector("#autolock").onchange = (e) => {
    s.auto_lock_minutes = parseInt(e.target.value, 10);
    savePrefs(s);
    onApply(); // reinicia o timer de inatividade com o novo valor
  };
  node.querySelector("#lang").onchange = (e) => {
    setLang(e.target.value);
    toast(e.target.value === "en" ? "Language set to English" : "Idioma definido para Português");
  };

  node.querySelector("#apply").onclick = async () => {
    s.network = node.querySelector("#network").value;
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
