import test from "node:test";
import assert from "node:assert/strict";

import { BridgeState, NativeBridgeUnavailableError, createNativeBridge } from "../bridge.js";

test("native bridge initializes through the Rust probe and becomes ready", async () => {
  const calls = [];
  const bridge = createNativeBridge(async (command, args) => {
    calls.push({ command, args });
    if (command === "native_bridge_status") return { bridge: "ready", app_version: "0.3.0" };
    return { command };
  });

  assert.equal(bridge.state, BridgeState.INITIALIZING);
  assert.deepEqual(await bridge.initialize(), { bridge: "ready", app_version: "0.3.0" });
  assert.equal(bridge.state, BridgeState.READY);
  assert.deepEqual(calls, [{ command: "native_bridge_status", args: undefined }]);
});

test("failed native probe enters failed state without a production browser fallback", async () => {
  const bridge = createNativeBridge(async () => { throw new Error("IPC unavailable"); });
  await assert.rejects(bridge.initialize(), NativeBridgeUnavailableError);
  assert.equal(bridge.state, BridgeState.FAILED);
});

test("all four initial actions call the injected native invoke implementation", async () => {
  const calls = [];
  const bridge = createNativeBridge(async (command, args) => {
    calls.push({ command, args });
    if (command === "native_bridge_status") return { bridge: "ready", app_version: "0.3.0" };
    return { reached_native: true };
  });

  for (const [command, args] of [
    ["wallet_create_recoverable", { path: "/test/create", password: "redacted" }],
    ["wallet_restore_from_mnemonic", { path: "/test/restore", password: "redacted", mnemonic: "redacted" }],
    ["wallet_open", { path: "/test/open" }],
    ["wallet_unlock", { password: "redacted" }],
  ]) assert.deepEqual(await bridge.invoke(command, args), { reached_native: true });

  assert.deepEqual(calls.map(({ command }) => command), [
    "native_bridge_status",
    "wallet_create_recoverable",
    "wallet_restore_from_mnemonic",
    "wallet_open",
    "wallet_unlock",
  ]);
});

test("production bridge source has no global Tauri detection or no-op adapter", async () => {
  const source = await (await import("node:fs/promises")).readFile(new URL("../bridge.js", import.meta.url), "utf8");
  assert.equal(source.includes("@tauri-apps/api/core"), true);
  assert.equal(source.includes("window.__TAURI__"), false);
  assert.equal(source.includes("window.__TAURI_INTERNALS__"), false);
  assert.equal(source.includes("developmentMock"), false);
  assert.equal(source.includes("browser stub"), false);
});
