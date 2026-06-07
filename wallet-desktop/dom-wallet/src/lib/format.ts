// Unit + display helpers. UNITS — DO NOT CHANGE:
//   1 DOM = 100,000,000 noms (8 decimals). Ticker: DOM.
//   Display format: "X.XXXXXXXX DOM" always (8 decimals, zero-padded).

export const NOMS_PER_DOM = 100_000_000n;
export const DECIMALS = 8;

/** Format an integer noms amount as a fixed 8-decimal DOM string (no ticker). */
export function nomsToDom(noms: number | bigint): string {
  const n = typeof noms === "bigint" ? noms : BigInt(Math.trunc(noms));
  const neg = n < 0n;
  const abs = neg ? -n : n;
  const whole = abs / NOMS_PER_DOM;
  const frac = abs % NOMS_PER_DOM;
  const fracStr = frac.toString().padStart(DECIMALS, "0");
  return `${neg ? "-" : ""}${whole.toString()}.${fracStr}`;
}

/** Format with the DOM ticker, e.g. "33.00000000 DOM". */
export function nomsToDomLabel(noms: number | bigint): string {
  return `${nomsToDom(noms)} DOM`;
}

/** Parse a DOM string ("33.5") into integer noms. Throws on malformed input. */
export function domToNoms(dom: string): bigint {
  const trimmed = dom.trim();
  if (!/^\d+(\.\d{0,8})?$/.test(trimmed)) {
    throw new Error(`invalid DOM amount: ${dom}`);
  }
  const [whole, frac = ""] = trimmed.split(".");
  const fracPadded = frac.padEnd(DECIMALS, "0");
  return BigInt(whole) * NOMS_PER_DOM + BigInt(fracPadded || "0");
}

/** Hashrate like 612 H/s, 1.2 kH/s, 3.4 MH/s. */
export function formatHashrate(hps: number): string {
  if (!isFinite(hps) || hps <= 0) return "0 H/s";
  const units = ["H/s", "kH/s", "MH/s", "GH/s"];
  let v = hps;
  let i = 0;
  while (v >= 1000 && i < units.length - 1) {
    v /= 1000;
    i += 1;
  }
  return `${i === 0 ? Math.round(v) : v.toFixed(1)} ${units[i]}`;
}

/** Unix-ms timestamp → local "HH:MM:SS". */
export function formatLogTime(ms: number): string {
  const d = new Date(ms);
  const p = (n: number) => n.toString().padStart(2, "0");
  return `${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`;
}

/** Unix-ms or Date → "YYYY-MM-DD". */
export function formatDate(ts: number | Date): string {
  const d = ts instanceof Date ? ts : new Date(ts);
  const p = (n: number) => n.toString().padStart(2, "0");
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}`;
}

/** Truncate a hex string for compact display: "ab12…cd34". */
export function shortHex(hex: string, head = 6, tail = 4): string {
  if (hex.length <= head + tail + 1) return hex;
  return `${hex.slice(0, head)}…${hex.slice(-tail)}`;
}
