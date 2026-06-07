import { describe, it, expect, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import { SeedPhraseDisplay } from "../components/SeedPhraseDisplay";
import { isLikelyValidPhrase } from "../components/SeedPhraseInput";
import { NodeStatusBadge } from "../components/NodeStatusBadge";
import { BalanceCard } from "../components/BalanceCard";

// Tauri APIs aren't available in jsdom; the components under test here don't
// call them, but mocking keeps imports safe if that changes.
vi.mock("@tauri-apps/api/core", () => ({ invoke: vi.fn() }));
vi.mock("@tauri-apps/api/event", () => ({ listen: vi.fn() }));

describe("SeedPhraseDisplay", () => {
  it("renders all 24 numbered words", () => {
    const phrase = Array.from({ length: 24 }, (_, i) => `word${i + 1}`).join(" ");
    render(<SeedPhraseDisplay phrase={phrase} />);
    expect(screen.getByText("word1")).toBeInTheDocument();
    expect(screen.getByText("word24")).toBeInTheDocument();
  });
});

describe("isLikelyValidPhrase", () => {
  it("accepts exactly 24 words", () => {
    const ok = Array.from({ length: 24 }, () => "abandon").join(" ");
    expect(isLikelyValidPhrase(ok)).toBe(true);
  });
  it("rejects other word counts", () => {
    expect(isLikelyValidPhrase("abandon abandon")).toBe(false);
    expect(isLikelyValidPhrase("")).toBe(false);
    const tooMany = Array.from({ length: 25 }, () => "abandon").join(" ");
    expect(isLikelyValidPhrase(tooMany)).toBe(false);
  });
  it("tolerates extra whitespace", () => {
    const ok = Array.from({ length: 24 }, () => "abandon").join("   ");
    expect(isLikelyValidPhrase(`  ${ok}  `)).toBe(true);
  });
});

describe("NodeStatusBadge", () => {
  it("shows stopped when not running", () => {
    render(<NodeStatusBadge running={false} status={null} />);
    expect(screen.getByText(/Node stopped/)).toBeInTheDocument();
  });
  it("shows mining when active", () => {
    render(
      <NodeStatusBadge
        running
        status={{
          version: 1,
          chain_height: 1,
          mempool_size: 0,
          network: "testnet",
          peer_count: 3,
          mining_active: true,
          hashrate: 100,
          blocks_mined: 1,
        }}
      />,
    );
    expect(screen.getByText(/Mining/)).toBeInTheDocument();
  });
});

describe("BalanceCard", () => {
  it("renders spendable balance prominently", () => {
    render(
      <BalanceCard
        balance={{ total: 3_300_000_000, spendable: 100_000_000, confirmed: 100_000_000, immature: 3_200_000_000 }}
      />,
    );
    expect(screen.getByText("1.00000000")).toBeInTheDocument();
    // total + immature shown with ticker
    expect(screen.getByText("33.00000000 DOM")).toBeInTheDocument();
  });
  it("handles null balance as zero", () => {
    render(<BalanceCard balance={null} />);
    expect(screen.getByText("0.00000000")).toBeInTheDocument();
  });
});
