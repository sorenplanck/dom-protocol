import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";

const root = new URL("../", import.meta.url);
const source = async (name) => readFile(new URL(name, root), "utf8");

test("DOM visual shell preserves all Wallet journeys including mining", async () => {
  const html = await source("index.html");
  for (const screen of ["access", "welcome", "create", "restore", "locate", "unlock", "dashboard", "send", "receive", "history", "mining", "node", "backup", "settings"]) {
    assert.equal(html.includes(`data-screen-contract="${screen}"`), true, `missing ${screen}`);
  }
  assert.equal(html.includes("remote HTTP endpoint"), false);
  assert.equal(html.includes("Embedded node settings"), false);
  assert.equal(html.includes("Sender Address v1"), false);
  assert.equal(html.includes("Receiver Address v1"), false);
  assert.equal(html.includes("Testnet"), false);
  assert.equal(html.includes("Regtest"), false);
  assert.equal(html.includes('name="network"'), false);
  assert.equal(html.includes('name="node_data"'), false);
  assert.equal(html.includes('name="listen_address"'), false);
  assert.equal(html.includes('name="remote_endpoint"'), false);
  assert.equal(html.includes("Mainnet only"), true);
  for (const panel of ["create-form", "restore-form", "open-form"]) {
    assert.equal(html.includes(`data-gate-panel="${panel}"`), true, `missing gate target ${panel}`);
    assert.equal(html.includes(`id="${panel}"`), true, `missing gate panel ${panel}`);
  }
});

test("mining UI is explicit, measured and never starts from navigation", async () => {
  const [html, js] = await Promise.all([source("index.html"), source("main.js")]);
  for (const id of ["mining-enabled", "mining-threads", "mining-address", "mining-hashrate", "mining-height", "mining-peers", "mining-accepted", "mining-start", "mining-stop"]) {
    assert.equal(html.includes(`id="${id}"`), true, `missing mining control ${id}`);
  }
  assert.equal(html.includes('id="mining-enabled" type="checkbox" checked'), false);
  assert.equal(html.includes('id="mining-start" class="btn" type="button" disabled'), true);
  assert.equal(js.includes('invoke("mining_start", { confirmed: true })'), true);
  assert.equal(js.includes('selectScreen(button.dataset.screen);\n  if (button.dataset.screen === "mining") invoke("mining_start"'), false);
});

test("manual payment UI exposes Slate v4 exchange without address-only transfer", async () => {
  const [html, js] = await Promise.all([source("index.html"), source("main.js")]);
  assert.equal(html.includes("Create Slate v4 request"), true);
  assert.equal(html.includes("Create receiver response"), true);
  assert.equal(js.includes("DOMSLATE4."), true);
  for (const forbidden of ["sender_address", "receiver_address", "Slate v3", "DOMSLATE3."]) {
    assert.equal(html.includes(forbidden) || js.includes(forbidden), false, `reachable legacy shortcut ${forbidden}`);
  }
});

test("production protocol and secret boundaries are explicit", async () => {
  const [html, js, registry] = await Promise.all([
    source("index.html"),
    source("main.js"),
    readFile(new URL("../../src-tauri/src/lib.rs", import.meta.url), "utf8"),
  ]);
  for (const command of ["embedded_node_start", "embedded_node_stop", "wallet_address_validate", "transaction_reconcile_submission"]) {
    assert.equal(js.includes(`"${command}"`) || registry.includes(command), true);
  }
  assert.equal(js.includes("DOMSLATE4."), true);
  assert.equal(js.includes("integerNoms"), true);
  assert.equal(html.includes("recovery-confirm-password"), true);
  assert.equal(html.includes("endpoint_url"), false);
});

test("DOM visual tokens preserve the validated dark bronze desktop geometry", async () => {
  const css = await source("styles.css");
  for (const token of ["--bg-0:#0c0807", "--bronze-3:#c89a63", "width:220px", "max-width:880px", "width:120px", "border-radius:var(--radius)"]) {
    assert.equal(css.includes(token), true, `missing visual token ${token}`);
  }
  assert.equal(css.includes("@media (max-width:700px)"), true);
  assert.equal(css.includes(":focus-visible"), true);
});

test("presentation adapter does not create browser persistence or a second lifecycle", async () => {
  const [js, bridge] = await Promise.all([source("main.js"), source("bridge.js")]);
  for (const forbidden of ["localStorage", "sessionStorage", "indexedDB", "fetch(", "eval(", "new Function"]) assert.equal(js.includes(forbidden), false);
  assert.equal(js.includes("window.__TAURI__"), false);
  assert.equal(bridge.includes("@tauri-apps/api/core"), true);
  assert.equal(js.includes("enterApp"), true);
  assert.equal(js.includes("enterGate"), true);
});
