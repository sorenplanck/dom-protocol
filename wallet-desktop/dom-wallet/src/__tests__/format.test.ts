import { describe, it, expect } from "vitest";
import {
  nomsToDom,
  nomsToDomLabel,
  domToNoms,
  formatHashrate,
  shortHex,
  formatDate,
} from "../lib/format";

describe("noms ↔ DOM conversion", () => {
  it("formats whole DOM with 8 decimals", () => {
    expect(nomsToDom(100_000_000)).toBe("1.00000000");
    expect(nomsToDom(3_300_000_000)).toBe("33.00000000");
  });

  it("formats fractional amounts", () => {
    expect(nomsToDom(150_000_000)).toBe("1.50000000");
    expect(nomsToDom(1)).toBe("0.00000001");
    expect(nomsToDom(0)).toBe("0.00000000");
  });

  it("adds the ticker", () => {
    expect(nomsToDomLabel(3_300_000_000)).toBe("33.00000000 DOM");
  });

  it("parses DOM strings to noms", () => {
    expect(domToNoms("1")).toBe(100_000_000n);
    expect(domToNoms("33")).toBe(3_300_000_000n);
    expect(domToNoms("1.5")).toBe(150_000_000n);
    expect(domToNoms("0.00000001")).toBe(1n);
  });

  it("rejects malformed DOM strings", () => {
    expect(() => domToNoms("abc")).toThrow();
    expect(() => domToNoms("1.234567891")).toThrow(); // >8 decimals
  });

  it("round-trips", () => {
    for (const n of [0n, 1n, 100_000_000n, 3_300_000_000n, 99_999_999n]) {
      expect(domToNoms(nomsToDom(n))).toBe(n);
    }
  });
});

describe("formatHashrate", () => {
  it("scales units", () => {
    expect(formatHashrate(0)).toBe("0 H/s");
    expect(formatHashrate(612)).toBe("612 H/s");
    expect(formatHashrate(1500)).toBe("1.5 kH/s");
    expect(formatHashrate(3_400_000)).toBe("3.4 MH/s");
  });
});

describe("shortHex", () => {
  it("truncates long hex", () => {
    expect(shortHex("abcdef1234567890", 6, 4)).toBe("abcdef…7890");
  });
  it("leaves short hex alone", () => {
    expect(shortHex("abc")).toBe("abc");
  });
});

describe("formatDate", () => {
  it("formats YYYY-MM-DD", () => {
    const d = new Date(2026, 5, 6); // June 6 2026 (month is 0-indexed)
    expect(formatDate(d)).toBe("2026-06-06");
  });
});
