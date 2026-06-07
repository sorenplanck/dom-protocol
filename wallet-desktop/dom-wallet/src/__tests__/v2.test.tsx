import { describe, it, expect, vi } from "vitest";
import { render, screen, fireEvent } from "@testing-library/react";

vi.mock("@tauri-apps/api/core", () => ({ invoke: vi.fn() }));
vi.mock("@tauri-apps/api/event", () => ({ listen: vi.fn(() => Promise.resolve(() => {})) }));
// qrcode touches canvas, unavailable in jsdom — stub it.
vi.mock("qrcode", () => ({ default: { toCanvas: vi.fn(() => Promise.resolve()) } }));

import { ModeSelector } from "../components/ModeSelector";
import { AmountInput } from "../components/AmountInput";
import { FeeSelector } from "../components/FeeSelector";
import { PendingTxCard } from "../components/PendingTxCard";
import { ConfirmSendModal } from "../components/ConfirmSendModal";
import type { PendingTxInfo } from "../lib/tauri";

describe("ModeSelector", () => {
  it("switches mode on click", () => {
    const onChange = vi.fn();
    render(<ModeSelector mode="slatepack" onChange={onChange} context="send" />);
    fireEvent.click(screen.getByText("Simple"));
    expect(onChange).toHaveBeenCalledWith("simple");
  });

  it("shows context-specific subtitles", () => {
    render(<ModeSelector mode="slatepack" onChange={() => {}} context="receive" />);
    expect(screen.getByText("Address-based")).toBeInTheDocument();
    expect(screen.getByText("Direct request")).toBeInTheDocument();
  });
});

describe("AmountInput", () => {
  it("sanitizes to max 8 decimals and rejects letters", () => {
    const onChange = vi.fn();
    render(<AmountInput value="" onChange={onChange} />);
    const input = screen.getByPlaceholderText("0.00000000");
    fireEvent.change(input, { target: { value: "12a.3456789999" } });
    // letters stripped, decimals capped at 8
    expect(onChange).toHaveBeenCalledWith("12.34567899");
  });

  it("shows spendable balance when provided", () => {
    render(<AmountInput value="" onChange={() => {}} availableNoms={3_300_000_000} />);
    expect(screen.getByText(/Available:/)).toBeInTheDocument();
  });
});

describe("FeeSelector", () => {
  it("emits the preset DOM value on selection", () => {
    const onChange = vi.fn();
    render(<FeeSelector value="0.01" onChange={onChange} />);
    fireEvent.click(screen.getByText(/Fast/));
    expect(onChange).toHaveBeenCalledWith("0.05");
  });
});

describe("PendingTxCard", () => {
  const tx: PendingTxInfo = {
    id: "p1",
    mode: "slatepack",
    direction: "sent",
    amount_noms: 3_300_000_000,
    fee_noms: 1_000_000,
    counterparty_addr: "dom1abcdef0123456789",
    state: "SlateSent",
    created_at: 0,
    expires_at: Math.floor(Date.now() / 1000) + 7200,
  };

  it("renders amount, mode, and waiting state", () => {
    render(<PendingTxCard tx={tx} onCancel={() => {}} />);
    expect(screen.getByText(/Sending/)).toBeInTheDocument();
    expect(screen.getByText(/Slatepack/)).toBeInTheDocument();
    expect(screen.getByText(/Waiting for counterparty/)).toBeInTheDocument();
  });

  it("calls onCancel with the tx id", () => {
    const onCancel = vi.fn();
    render(<PendingTxCard tx={tx} onCancel={onCancel} />);
    fireEvent.click(screen.getByText("Cancel"));
    expect(onCancel).toHaveBeenCalledWith("p1");
  });
});

describe("ConfirmSendModal", () => {
  it("renders nothing when closed", () => {
    const { container } = render(
      <ConfirmSendModal
        open={false}
        amountNoms={1}
        feeNoms={1}
        mode="slatepack"
        onConfirm={() => {}}
        onCancel={() => {}}
      />,
    );
    expect(container.firstChild).toBeNull();
  });

  it("shows total and confirms", () => {
    const onConfirm = vi.fn();
    render(
      <ConfirmSendModal
        open
        amountNoms={3_300_000_000}
        feeNoms={1_000_000}
        mode="slatepack"
        onConfirm={onConfirm}
        onCancel={() => {}}
      />,
    );
    expect(screen.getByText("Confirm send")).toBeInTheDocument();
    fireEvent.click(screen.getByText("Create Slate"));
    expect(onConfirm).toHaveBeenCalled();
  });
});
