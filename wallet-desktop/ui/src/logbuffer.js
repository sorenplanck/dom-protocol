// Buffer compartilhado de logs do nó.
//
// O backend já transmite cada linha como evento "node-log" (e mantém um buffer
// bounded próprio). Aqui guardamos um espelho em memória no frontend para que a
// aba Nó / Logs mostre as últimas N linhas mesmo se for aberta DEPOIS de o nó
// já ter iniciado — sem isso, o usuário só veria o que chega após abrir a aba.
//
// O listener é registrado UMA vez no boot (startLogCapture), não a cada render
// da aba.

import { events } from "./api.js";

const MAX = 5000;
const lines = [];
const subscribers = new Set();
let started = false;

export function getLogLines() {
  return lines;
}

export function clearLogs() {
  lines.length = 0;
  notify();
}

export function subscribeLogs(fn) {
  subscribers.add(fn);
  return () => subscribers.delete(fn);
}

function notify() {
  for (const fn of subscribers) {
    try { fn(); } catch {}
  }
}

// Registra o listener global uma única vez.
export async function startLogCapture() {
  if (started) return;
  started = true;
  await events.listen("node-log", (e) => {
    lines.push(e.payload);
    if (lines.length > MAX) lines.shift();
    notify();
  });
}

// Serializa o buffer atual para texto (para o botão "Salvar logs").
export function logsToText(filter = "", level = "") {
  const f = filter.toLowerCase();
  return lines
    .filter((l) =>
      (!level || l.level === level) &&
      (!f || (l.message + l.target).toLowerCase().includes(f)))
    .map((l) => {
      const t = new Date(l.ts_ms).toISOString();
      return `${t} ${l.level.padEnd(5)} ${l.target}  ${l.message}`;
    })
    .join("\n");
}
