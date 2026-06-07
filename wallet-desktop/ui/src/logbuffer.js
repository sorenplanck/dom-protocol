// Shared node-log buffer.
//
// The backend already streams each line as a "node-log" event (and keeps its
// own bounded buffer). Here we keep an in-memory mirror in the frontend so the
// Node / Logs tab can show the last N lines even if it is opened AFTER the node
// has started — without this, the user would only see lines arriving after the
// tab is opened.
//
// The listener is registered ONCE at boot (startLogCapture), not on every tab
// render.

import { events } from "./api.js";

const MAX = 5000;
// Ring buffer (H2): fixed-size array + head/count instead of push()/shift().
// shift() is O(n) and, combined with a full re-render per line, made the log
// console O(n²). Here append is O(1) and subscribers receive only the new line.
const ring = new Array(MAX);
let head = 0; // index of the next write slot
let count = 0; // number of valid entries (<= MAX)
const subscribers = new Set();
let started = false;

function pushLine(line) {
  ring[head] = line;
  head = (head + 1) % MAX;
  if (count < MAX) count += 1;
}

// Ordered snapshot, oldest → newest. O(n); only called on a full re-render
// (mount / filter change) and by logsToText — never per incoming line.
export function getLogLines() {
  const out = new Array(count);
  const start = (head - count + MAX) % MAX;
  for (let i = 0; i < count; i++) out[i] = ring[(start + i) % MAX];
  return out;
}

export function clearLogs() {
  head = 0;
  count = 0;
  notify(null); // null = full reset; subscribers do a full re-render
}

export function subscribeLogs(fn) {
  subscribers.add(fn);
  return () => subscribers.delete(fn);
}

// `line` is the newly-appended LogLine, or null to signal a reset/full redraw.
function notify(line) {
  for (const fn of subscribers) {
    try { fn(line); } catch {}
  }
}

// Registra o listener global uma única vez.
export async function startLogCapture() {
  if (started) return;
  started = true;
  await events.listen("node-log", (e) => {
    pushLine(e.payload);
    notify(e.payload);
  });
}

// Serialize the current buffer to text (for the "Save logs" button).
export function logsToText(filter = "", level = "") {
  const f = filter.toLowerCase();
  return getLogLines()
    .filter((l) =>
      (!level || l.level === level) &&
      (!f || (l.message + l.target).toLowerCase().includes(f)))
    .map((l) => {
      const t = new Date(l.ts_ms).toISOString();
      return `${t} ${l.level.padEnd(5)} ${l.target}  ${l.message}`;
    })
    .join("\n");
}
