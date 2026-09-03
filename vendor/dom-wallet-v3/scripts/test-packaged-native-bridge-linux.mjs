#!/usr/bin/env node

import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { cp, mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { basename, dirname, resolve } from "node:path";

const binary = process.argv[2] ? resolve(process.argv[2]) : undefined;
if (!binary) throw new Error("usage: test-packaged-native-bridge-linux.mjs <packaged-binary>");
if (!process.env.DISPLAY) throw new Error("DISPLAY is required (use xvfb-run in CI)");
const synchronizationAttemptLimit = Number.parseInt(
  process.env.PACKAGED_SYNC_ATTEMPTS ?? "120",
  10,
);
const requireBlockAdvance = process.env.PACKAGED_REQUIRE_BLOCK_ADVANCE === "1";
const forceNetworkStatusFallback = process.env.PACKAGED_FORCE_NETWORK_STATUS_FALLBACK === "1";
const forceUiNetworkStatusFallback = process.env.PACKAGED_FORCE_UI_NETWORK_STATUS_FALLBACK === "1";
const MAINNET_CHAIN_ID = "f9831fadabc8a4234beab35fbb6327e84581645f33e9f75ed2ea78e8bcf1165b";
const MAINNET_GENESIS_HASH = "182e10af28e7ec072f462e6044f580dc9dd8c866cb78dfc293bbfaee4e9325ce";
if (!Number.isSafeInteger(synchronizationAttemptLimit) || synchronizationAttemptLimit < 1) {
  throw new Error("PACKAGED_SYNC_ATTEMPTS must be a positive integer");
}

const port = 9515 + (process.pid % 1000);
const endpoint = `http://127.0.0.1:${port}`;
const profile = await mkdtemp(`${tmpdir()}/dom-wallet-bridge-e2e-`);
if (process.env.PACKAGED_NODE_FIXTURE) {
  await cp(
    resolve(process.env.PACKAGED_NODE_FIXTURE),
    `${profile}/data/org.domprotocol.wallet.v3/mainnet/node`,
    { recursive: true },
  );
}
const driverPath = process.env.WEBKIT_WEBDRIVER
  ? `${dirname(process.env.WEBKIT_WEBDRIVER)}:${process.env.PATH}`
  : process.env.PATH;
const driver = spawn(process.env.TAURI_DRIVER ?? "tauri-driver", [`--port=${port}`, `--native-port=${port + 1}`], {
  env: {
    ...process.env,
    HOME: profile,
    XDG_CONFIG_HOME: `${profile}/config`,
    XDG_DATA_HOME: `${profile}/data`,
    XDG_CACHE_HOME: `${profile}/cache`,
    TAURI_WEBVIEW_AUTOMATION: "true",
    RUST_BACKTRACE: "1",
    RUST_LOG: "info",
    PATH: driverPath,
  },
  stdio: ["ignore", "pipe", "pipe"],
});

let driverOutput = "";
driver.stdout.on("data", (chunk) => { driverOutput += chunk; });
driver.stderr.on("data", (chunk) => { driverOutput += chunk; });

const request = async (path, body, options = {}) => {
  const response = await fetch(`${endpoint}${path}`, {
    method: body === undefined ? "GET" : "POST",
    headers: { "content-type": "application/json" },
    body: body === undefined ? undefined : JSON.stringify(body),
    ...options,
  });
  const result = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(`WebDriver ${response.status}: ${JSON.stringify(result)}`);
  return result.value;
};

const waitForDriver = async () => {
  for (let attempt = 0; attempt < 100; attempt += 1) {
    if (driver.exitCode !== null) throw new Error(`tauri-driver exited early: ${driverOutput}`);
    try { await request("/status"); return; } catch { await new Promise((done) => setTimeout(done, 100)); }
  }
  throw new Error(`WebKitWebDriver did not start: ${driverOutput}`);
};

let sessionId;
try {
  await waitForDriver();
  const created = await request("/session", {
    capabilities: { alwaysMatch: { "tauri:options": { application: binary } } },
  });
  sessionId = created.sessionId ?? created.capabilities?.sessionId;
  if (!sessionId) {
    const sessions = await request("/sessions");
    sessionId = sessions?.at(-1)?.id;
  }
  assert.ok(sessionId, "WebDriver session was not created");
  // Individual UI gates enforce their own tighter deadlines. Keep the driver
  // deadline above the longest gate so its domain-specific failure wins.
  await request(`/session/${sessionId}/timeouts`, { script: 300_000 });

  const execute = (script, args = []) => request(`/session/${sessionId}/execute/sync`, { script, args });
  const screenshotDirectory = process.env.PACKAGED_SCREENSHOT_DIR
    ? resolve(process.env.PACKAGED_SCREENSHOT_DIR)
    : undefined;
  const screenshot = async (name) => {
    if (!screenshotDirectory) return;
    await mkdir(screenshotDirectory, { recursive: true });
    const encoded = await request(`/session/${sessionId}/screenshot`);
    await writeFile(`${screenshotDirectory}/${name}.png`, Buffer.from(encoded, "base64"));
  };
  for (let attempt = 0; attempt < 200; attempt += 1) {
    const ready = await execute("return document.readyState === 'complete' && document.documentElement.dataset.nativeBridge === 'READY'").catch(() => false);
    if (ready) break;
    if (attempt === 199) throw new Error("packaged bridge did not reach READY");
    await new Promise((done) => setTimeout(done, 100));
  }

  const runtime = await execute(`return {
    title: document.title,
    status: document.getElementById("status")?.textContent,
    bridgeState: document.documentElement.dataset.nativeBridge,
    globalTauri: typeof window.__TAURI__,
    internals: typeof window.__TAURI_INTERNALS__
  }`);
  assert.equal(runtime.bridgeState, "READY");
  assert.equal(runtime.globalTauri, "undefined");
  assert.equal(runtime.internals, "object");
  assert.match(runtime.status, /^Application state:/);
  assert.doesNotMatch(runtime.status, /Native desktop command bridge is unavailable/i);
  await screenshot("initial-bridge-ready");

  const probe = await execute("return window.__TAURI_INTERNALS__.invoke('native_bridge_status')");
  assert.equal(probe.bridge, "ready");
  assert.equal(probe.app_version, "0.3.2");
  assert.ok(Array.isArray(probe.command_names));
  assert.ok(probe.command_names.includes("native_bridge_status"));

  const nativeResult = async (command, args) => execute(`
    return window.__TAURI_INTERNALS__.invoke(arguments[0], arguments[1])
      .then((value) => ({ reachedNative: true, ok: true, value }))
      .catch((error) => ({ reachedNative: true, ok: false, error }));
  `, [command, args]);
  const isCanonicalHash = (value) => typeof value === "string" && /^[0-9a-f]{64}$/i.test(value);
  const hasCoherentSyncProgress = (value) => {
    if (
      value?.state !== "READY"
      || value.last_error !== null
      || !Number.isSafeInteger(value.cursor_height)
      || !Number.isSafeInteger(value.canonical_height)
      || value.cursor_height < 0
      || value.cursor_height > value.canonical_height
      || !isCanonicalHash(value.cursor_hash)
      || !isCanonicalHash(value.canonical_hash)
    ) return false;
    if (value.synchronized) {
      return value.cursor_height === value.canonical_height
        && value.cursor_hash === value.canonical_hash;
    }
    // During IBD the canonical tip can advance faster than the wallet scan.
    // A positive, bounded cursor proves the self-healing worker is following.
    return value.cursor_height > 0 && value.cursor_height < value.canonical_height;
  };
  let observedUiNetworkStatus;
  const readLiveNetworkStatus = async () => {
    const network = forceNetworkStatusFallback || forceUiNetworkStatusFallback
      ? { reachedNative: true, ok: false, error: { retryable: true } }
      : await nativeResult("node_network_status", {});
    if (network.ok) return { ...network, source: "node_network_status" };

    const node = forceUiNetworkStatusFallback
      ? { reachedNative: true, ok: false, error: { retryable: true } }
      : await nativeResult("embedded_node_status", {});
    if (!node.ok) {
      if (!requireBlockAdvance && observedUiNetworkStatus) {
        return {
          reachedNative: true,
          ok: true,
          source: "authenticated_ui_live_status",
          value: observedUiNetworkStatus,
        };
      }
      return network;
    }
    assert.equal(node.value.network, "MAINNET");
    assert.equal(node.value.chain_id, MAINNET_CHAIN_ID);
    assert.equal(node.value.genesis_hash, MAINNET_GENESIS_HASH);
    assert.match(node.value.canonical_tip_hash, /^[0-9a-f]{64}$/i);
    assert.ok(
      Number.isSafeInteger(node.value.canonical_tip_height)
        && node.value.canonical_tip_height >= 0,
      "embedded node returned an invalid live Mainnet tip",
    );
    return {
      reachedNative: true,
      ok: true,
      source: "embedded_node_status",
      value: {
        network: node.value.network,
        chain_id: node.value.chain_id,
        genesis_hash: node.value.genesis_hash,
        canonical_height: node.value.canonical_tip_height,
        ready: node.value.ready,
      },
    };
  };
  const actions = {
    create: await nativeResult("wallet_create_recoverable", { path: "", password: "" }),
    restore: await nativeResult("wallet_restore_from_mnemonic", { path: "", password: "", mnemonic: "" }),
    locate: await nativeResult("wallet_open", { path: `${profile}/missing-wallet` }),
    unlock: await nativeResult("wallet_unlock", { password: "" }),
  };
  for (const [name, result] of Object.entries(actions)) {
    assert.equal(result.reachedNative, true, `${name} did not reach native IPC`);
    assert.equal(result.ok, false, `${name} unexpectedly accepted invalid test input`);
    assert.notEqual(result.error, undefined, `${name} did not return a native domain error`);
    assert.doesNotMatch(JSON.stringify(result.error), /Native desktop command bridge is unavailable/i);
  }

  const unlockResponse = await execute(`
    const form = document.getElementById("unlock-form");
    form.querySelector('input[name="password"]').value = "invalid-test-only";
    form.requestSubmit();
    return new Promise((resolve, reject) => {
      let attempts = 0;
      const poll = () => {
        const value = document.getElementById("status").textContent;
        if (!value.startsWith("Application state:")) return resolve(value);
        if (attempts++ > 100) return reject(new Error("unlock UI did not receive a native response"));
        setTimeout(poll, 50);
      };
      poll();
    });
  `);
  assert.doesNotMatch(unlockResponse, /Native desktop command bridge is unavailable/i);
  await screenshot("unlock-native-response");

  const panels = await execute(`
    const result = {};
    for (const [name, panel] of [["create", "create-form"], ["restore", "restore-form"], ["locate", "open-form"]]) {
      document.querySelector('[data-gate-panel="' + panel + '"]').click();
      result[name] = !document.getElementById(panel).hidden;
    }
    return result;
  `);
  assert.deepEqual(panels, { create: true, restore: true, locate: true });

  const walletName = "packaged-mainnet-wallet";
  const testPassword = "packaged-mainnet-test-only";
  await execute(`
    document.querySelector('[data-gate-panel="create-form"]').click();
    const form = document.getElementById("create-form");
    form.querySelector('input[name="name"]').value = arguments[0];
    form.querySelector('input[name="password"]').value = arguments[1];
    form.requestSubmit();
    return new Promise((resolve, reject) => {
      let attempts = 0;
      const poll = () => {
        const ceremony = document.getElementById("recovery-ceremony");
        if (!ceremony.hidden && document.getElementById("recovery-phrase").textContent.trim()) return resolve(true);
        if (attempts++ > 1_000) return reject(new Error("wallet creation did not reach recovery confirmation"));
        setTimeout(poll, 100);
      };
      poll();
    });
  `, [walletName, testPassword]);

  await execute(`
    const confirmed = document.getElementById("recovery-confirmed");
    confirmed.checked = true;
    confirmed.dispatchEvent(new Event("change", { bubbles: true }));
    document.getElementById("recovery-confirm-password").value = arguments[0];
    document.getElementById("recovery-complete").click();
    return new Promise((resolve, reject) => {
      let attempts = 0;
      const poll = () => {
        const value = document.getElementById("status").textContent;
        if (/Recovery phrase confirmed/i.test(value)) return resolve(value);
        if (attempts++ > 300) return reject(new Error("recovery confirmation did not complete"));
        setTimeout(poll, 100);
      };
      poll();
    });
  `, [testPassword]);
  const phraseCleared = await execute("return document.getElementById('recovery-phrase').textContent === ''");
  assert.equal(phraseCleared, true, "recovery phrase remained in the DOM after confirmation");

  await execute(`
    const form = document.getElementById("unlock-form");
    form.querySelector('input[name="password"]').value = arguments[0];
    form.requestSubmit();
    return new Promise((resolve, reject) => {
      let attempts = 0;
      const poll = () => {
        if (!document.getElementById("app").classList.contains("hidden")) return resolve(true);
        if (attempts++ > 300) return reject(new Error("packaged wallet did not unlock"));
        setTimeout(poll, 100);
      };
      poll();
    });
  `, [testPassword]);

  const productSurface = await execute(`return {
    networkSelectors: document.querySelectorAll('[name="network"], [name="chain"], [name="node_data"], [name="listen_address"], [name="remote_endpoint"], [name="server_address"], [name="seed"], [name="port"], [name="backend"]').length,
    miningPage: Boolean(document.querySelector('[data-screen="mining"]') && document.getElementById("mining")),
    senderAddressFields: document.querySelectorAll('[name="sender_address"], #sender-address').length,
    receiverAddressFields: document.querySelectorAll('[name="receiver_address"], #receiver-address').length,
    slateV4: document.getElementById("transactions").textContent.includes("Slate v4"),
    settingsMainnet: document.getElementById("diagnostics").textContent.includes("Mainnet")
  }`);
  assert.deepEqual(productSurface, {
    networkSelectors: 0,
    miningPage: true,
    senderAddressFields: 0,
    receiverAddressFields: 0,
    slateV4: true,
    settingsMainnet: true,
  });

  let peerStatus;
  for (let attempt = 0; attempt < synchronizationAttemptLimit; attempt += 1) {
    const result = await nativeResult("node_peer_status", {});
    if (!result.ok) throw new Error("packaged peer diagnostics failed");
    peerStatus = result.value;
    if (peerStatus.total_connected_peers > 0) break;
    await new Promise((done) => setTimeout(done, 500));
  }
  assert.ok(peerStatus.total_connected_peers > 0, "packaged node did not register a Mainnet peer");

  // Node startup and the first wallet scan are asynchronous. A live peer may
  // advance the fresh local chain before this gate observes it, so require a
  // coherent cursor at the actual canonical height instead of assuming zero.
  let initialSyncStatus;
  for (let attempt = 0; attempt < synchronizationAttemptLimit; attempt += 1) {
    const syncStart = await nativeResult("wallet_sync_start", {});
    if (!syncStart.ok && syncStart.error?.retryable !== true) {
      throw new Error(`packaged initial synchronization failed: ${JSON.stringify(syncStart.error)}`);
    }
    initialSyncStatus = await nativeResult("wallet_sync_status", {});
    if (!initialSyncStatus.ok) throw new Error("packaged initial synchronization diagnostics failed");
    if (hasCoherentSyncProgress(initialSyncStatus.value)) break;
    await new Promise((done) => setTimeout(done, 500));
  }
  assert.ok(initialSyncStatus, "packaged initial synchronization status was not observed");
  assert.ok(
    hasCoherentSyncProgress(initialSyncStatus.value),
    `packaged initial synchronization made no coherent progress: ${JSON.stringify(initialSyncStatus.value)}`,
  );

  const liveDashboard = await execute(`
    document.querySelector('[data-screen="dashboard"]').click();
    return new Promise((resolve, reject) => {
      let attempts = 0;
      const poll = () => {
        const badge = document.getElementById("network-identity").textContent;
        const synchronization = document.getElementById("sync-status").textContent;
        if (/MAINNET · SYNCHRONIZING/.test(badge) && /Synchronizing \\d+ \\/ \\d+ \\(\\d+%\\)/.test(synchronization)) {
          return resolve({ badge, synchronization });
        }
        if (attempts++ > 300) return reject(new Error(
          "dashboard did not render live synchronization state: " + JSON.stringify({ badge, synchronization })
        ));
        setTimeout(poll, 100);
      };
      poll();
    });
  `);
  assert.match(liveDashboard.badge, /^MAINNET · SYNCHRONIZING$/);
  assert.match(liveDashboard.synchronization, /^Synchronizing \d+ \/ \d+ \(\d+%\)$/);
  await execute("document.getElementById('toast').classList.remove('show')");
  await new Promise((done) => setTimeout(done, 350));
  await screenshot("dashboard-live-sync");
  const nodeScreen = await execute(`
    document.querySelector('[data-screen="node"]').click();
    return new Promise((resolve, reject) => {
      let attempts = 0;
      const poll = () => {
        const text = document.getElementById("node-status").textContent;
        if (
          /Lifecycle: SYNCHRONIZING/.test(text)
          && /Local height: \\d+/.test(text)
          && /Highest peer height: \\d+/.test(text)
          && /Connected peers: [1-9]\\d*/.test(text)
        ) return resolve(text);
        if (attempts++ > 300) return reject(new Error("node screen did not render live data: " + text));
        setTimeout(poll, 100);
      };
      poll();
    });
  `);
  assert.doesNotMatch(nodeScreen, /CORE_NOT_READY/);
  await new Promise((done) => setTimeout(done, 350));
  await screenshot("node-live-sync");
  const miningScreen = await execute(`
    document.querySelector('[data-screen="mining"]').click();
    return new Promise((resolve, reject) => {
      let attempts = 0;
      const poll = () => {
        const state = document.getElementById("mining-status").textContent;
        const warning = document.getElementById("mining-warning").textContent;
        const startDisabled = document.getElementById("mining-start").disabled;
        if (state === "SYNCHRONIZING" && /Synchronizing \\d+ \\/ \\d+/.test(warning) && startDisabled) {
          return resolve({ state, warning, startDisabled });
        }
        if (attempts++ > 300) return reject(new Error(
          "mining screen did not enforce live node readiness: " + JSON.stringify({ state, warning, startDisabled })
        ));
        setTimeout(poll, 100);
      };
      poll();
    });
  `);
  assert.equal(miningScreen.startDisabled, true);
  await new Promise((done) => setTimeout(done, 350));
  await screenshot("mining-live-sync");
  const settingsScreen = await execute(`
    document.querySelector('[data-screen="diagnostics"]').click();
    return new Promise((resolve, reject) => {
      let attempts = 0;
      const poll = () => {
        const value = {
          chainId: document.getElementById("settings-chain-id").textContent,
          genesis: document.getElementById("settings-genesis").textContent,
          peers: document.getElementById("settings-peer-count").textContent,
          heights: document.getElementById("settings-heights").textContent,
          updateMode: document.getElementById("update-mode").textContent,
          walletVersion: document.getElementById("update-wallet-version").textContent,
        };
        if (
          /^[0-9a-f]{64}$/i.test(value.chainId)
          && /^[0-9a-f]{64}$/i.test(value.genesis)
          && /^[1-9]\\d*$/.test(value.peers)
          && /^\\d+ \\/ \\d+$/.test(value.heights)
          && value.updateMode !== "Checking"
          && /^\\d+\\.\\d+\\.\\d+$/.test(value.walletVersion)
        ) return resolve(value);
        if (attempts++ > 300) return reject(new Error(
          "settings screen did not render live data: " + JSON.stringify(value)
        ));
        setTimeout(poll, 100);
      };
      poll();
    });
  `);
  assert.doesNotMatch(JSON.stringify(settingsScreen), /undefined|null/);
  assert.equal(settingsScreen.chainId, MAINNET_CHAIN_ID);
  assert.equal(settingsScreen.genesis, MAINNET_GENESIS_HASH);
  const settingsHeights = /^(\d+) \/ (\d+)$/.exec(settingsScreen.heights);
  assert.ok(settingsHeights, "settings did not expose numeric cursor and canonical heights");
  observedUiNetworkStatus = {
    network: "MAINNET",
    chain_id: settingsScreen.chainId,
    genesis_hash: settingsScreen.genesis,
    canonical_height: Number(settingsHeights[2]),
    ready: false,
  };
  await new Promise((done) => setTimeout(done, 350));
  await screenshot("settings-live-data");
  const historyScreen = await execute(`
    document.querySelector('[data-screen="history"]').click();
    return new Promise((resolve, reject) => {
      let attempts = 0;
      const poll = () => {
        const text = document.getElementById("history-output").textContent;
        if (text === "No transactions recorded.") return resolve(text);
        if (attempts++ > 300) return reject(new Error("empty history state remained stale: " + text));
        setTimeout(poll, 100);
      };
      poll();
    });
  `);
  assert.equal(historyScreen, "No transactions recorded.");
  await new Promise((done) => setTimeout(done, 350));
  await screenshot("history-empty-state");
  await execute("document.querySelector('[data-screen=\"dashboard\"]').click()");

  let networkStatus;
  for (let attempt = 0; attempt < synchronizationAttemptLimit; attempt += 1) {
    networkStatus = await readLiveNetworkStatus();
    if (networkStatus.ok) break;
    await new Promise((done) => setTimeout(done, 250));
  }
  if (!networkStatus?.ok) {
    throw new Error(`packaged network diagnostics failed: ${JSON.stringify(networkStatus?.error)}`);
  }
  let advancedDashboard;
  if (requireBlockAdvance) {
    for (let attempt = 0; attempt < synchronizationAttemptLimit; attempt += 1) {
      networkStatus = await readLiveNetworkStatus();
      if (networkStatus.ok && networkStatus.value.canonical_height > 0) break;
      await new Promise((done) => setTimeout(done, 500));
    }
    assert.ok(
      networkStatus?.ok && networkStatus.value.canonical_height > 0,
      `packaged Mainnet node did not download a real block: ${JSON.stringify(networkStatus)}`,
    );
    advancedDashboard = await execute(`
      document.querySelector('[data-screen="dashboard"]').click();
      return new Promise((resolve, reject) => {
        let attempts = 0;
        const poll = () => {
          const canonicalHeight = document.getElementById("canonical-height").textContent;
          const synchronization = document.getElementById("sync-status").textContent;
          if (/^[1-9]\\d*$/.test(canonicalHeight) && /Synchronizing \\d+ \\/ \\d+/.test(synchronization)) {
            return resolve({ canonicalHeight, synchronization });
          }
          if (attempts++ > 600) return reject(new Error(
            "dashboard did not render an advancing real tip: " + JSON.stringify({ canonicalHeight, synchronization })
          ));
          setTimeout(poll, 100);
        };
        poll();
      });
    `);
    await new Promise((done) => setTimeout(done, 350));
    await screenshot("dashboard-real-block-advance");
  }
  assert.equal(networkStatus.value.network, "MAINNET");
  assert.ok(
    Number.isSafeInteger(networkStatus.value.canonical_height)
      && networkStatus.value.canonical_height >= 0,
    "packaged node returned an invalid Mainnet tip",
  );
  let syncStatus;
  for (let attempt = 0; attempt < synchronizationAttemptLimit; attempt += 1) {
    const syncStart = await nativeResult("wallet_sync_start", {});
    if (!syncStart.ok && syncStart.error?.retryable !== true) {
      throw new Error(`packaged synchronization failed: ${JSON.stringify(syncStart.error)}`);
    }
    syncStatus = await nativeResult("wallet_sync_status", {});
    if (!syncStatus.ok) throw new Error("packaged synchronization diagnostics failed");
    if (hasCoherentSyncProgress(syncStatus.value)) break;
    await new Promise((done) => setTimeout(done, 500));
  }
  assert.ok(syncStatus, "packaged synchronization status was not observed");
  assert.ok(
    hasCoherentSyncProgress(syncStatus.value),
    `packaged synchronization made no coherent progress: ${JSON.stringify(syncStatus.value)}`,
  );

  const miningConfig = await nativeResult("mining_config_get", {});
  if (!miningConfig.ok) throw new Error("packaged mining configuration failed");
  const enabledMining = await nativeResult("mining_config_set", {
    enabled: true,
    cpuThreads: miningConfig.value.cpu_threads,
  });
  if (!enabledMining.ok) throw new Error("packaged mining controls remained blocked by the cursor");
  const miningStatus = await nativeResult("mining_status", {});
  if (!miningStatus.ok) throw new Error("packaged mining diagnostics failed");
  assert.equal(miningStatus.value.status, "READY");
  assert.equal(miningStatus.value.enabled, true);
  assert.equal(miningStatus.value.running, false);
  assert.equal(miningStatus.value.hash_attempts, 0);
  assert.equal(miningStatus.value.accepted_blocks, 0);
  const unconfirmedStart = await nativeResult("mining_start", { confirmed: false });
  assert.equal(unconfirmedStart.ok, false);
  assert.equal(unconfirmedStart.error.code, "MINING_CONFIRMATION_REQUIRED");
  if (requireBlockAdvance) {
    const blockedStart = await nativeResult("mining_start", { confirmed: true });
    assert.equal(blockedStart.ok, false);
    assert.ok(
      ["EMBEDDED_NODE_NOT_READY", "CURSOR_INITIALIZATION_FAILED"].includes(blockedStart.error.code),
      `mining did not fail closed during IBD: ${JSON.stringify(blockedStart.error)}`,
    );
  }
  const stoppedMining = await nativeResult("mining_stop", {});
  if (!stoppedMining.ok) throw new Error("packaged mining stop control failed");
  assert.equal(stoppedMining.value.running, false);
  assert.equal(stoppedMining.value.hash_attempts, 0);
  const walletBeforeBackup = await nativeResult("wallet_summary", {});
  if (!walletBeforeBackup.ok) throw new Error("packaged wallet summary before backup failed");
  const lifecycleUi = await execute(`
    document.getElementById("lock").click();
    return new Promise((resolve, reject) => {
      let attempts = 0;
      const poll = () => {
        if (!document.getElementById("gate").classList.contains("hidden")) return resolve("LOCKED");
        if (attempts++ > 300) return reject(new Error("wallet lock did not return to the access gate"));
        setTimeout(poll, 100);
      };
      poll();
    });
  `);
  assert.equal(lifecycleUi, "LOCKED");
  await execute(`
    const form = document.getElementById("unlock-form");
    form.querySelector('input[name="password"]').value = arguments[0];
    form.requestSubmit();
    return new Promise((resolve, reject) => {
      let attempts = 0;
      const poll = () => {
        if (!document.getElementById("app").classList.contains("hidden")) return resolve("UNLOCKED");
        if (attempts++ > 300) return reject(new Error("wallet did not unlock after UI lock"));
        setTimeout(poll, 100);
      };
      poll();
    });
  `, [testPassword]);
  const backupPath = `${profile}/wallet-backup.dom`;
  const restoredWalletName = "packaged-restored-wallet";
  const backupPassword = "packaged-backup-password-only";
  const restoredPassword = "packaged-restored-password-only";
  const backupUi = await execute(`
    document.querySelector('[data-screen="backup"]').click();
    const exportForm = document.getElementById("backup-export-form");
    exportForm.querySelector('input[name="destination"]').value = arguments[0];
    exportForm.querySelector('input[name="backup_password"]').value = arguments[1];
    exportForm.requestSubmit();
    return new Promise((resolve, reject) => {
      let attempts = 0;
      const poll = () => {
        const message = document.getElementById("status").textContent;
        if (/Encrypted backup created/.test(message)) return resolve(message);
        if (attempts++ > 600) return reject(new Error("backup export UI failed: " + message));
        setTimeout(poll, 100);
      };
      poll();
    });
  `, [backupPath, backupPassword]);
  assert.match(backupUi, /Encrypted backup created/);
  const restoreUi = await execute(`
    window.confirm = () => true;
    const form = document.getElementById("backup-import-form");
    form.querySelector('input[name="backup_path"]').value = arguments[0];
    form.querySelector('input[name="name"]').value = arguments[1];
    form.querySelector('input[name="backup_password"]').value = arguments[2];
    form.querySelector('input[name="password"]').value = arguments[3];
    form.requestSubmit();
    return new Promise((resolve, reject) => {
      let attempts = 0;
      const poll = () => {
        const message = document.getElementById("status").textContent;
        const gateVisible = !document.getElementById("gate").classList.contains("hidden");
        if (gateVisible && /Encrypted backup imported in locked state/.test(message)) return resolve(message);
        if (attempts++ > 1_200) return reject(new Error("backup import UI failed: " + message));
        setTimeout(poll, 100);
      };
      poll();
    });
  `, [backupPath, restoredWalletName, backupPassword, restoredPassword]);
  assert.match(restoreUi, /Encrypted backup imported in locked state/);
  await execute(`
    const form = document.getElementById("unlock-form");
    form.querySelector('input[name="password"]').value = arguments[0];
    form.requestSubmit();
    return new Promise((resolve, reject) => {
      let attempts = 0;
      const poll = () => {
        if (!document.getElementById("app").classList.contains("hidden")) return resolve(true);
        if (attempts++ > 600) return reject(new Error("restored backup did not unlock"));
        setTimeout(poll, 100);
      };
      poll();
    });
  `, [restoredPassword]);
  const walletAfterBackup = await nativeResult("wallet_summary", {});
  if (!walletAfterBackup.ok) throw new Error("packaged restored wallet summary failed");
  assert.equal(walletAfterBackup.value.wallet_id, walletBeforeBackup.value.wallet_id);
  assert.deepEqual(walletAfterBackup.value.balance, walletBeforeBackup.value.balance);
  await execute("document.querySelector('[data-screen=\"backup\"]').click()");
  await new Promise((done) => setTimeout(done, 350));
  await screenshot("backup-round-trip");
  // Shutdown closes the native webview, so WebDriver may correctly lose the
  // session before it can deliver the command reply.
  await nativeResult("application_shutdown", {}).catch(() => undefined);

  process.stdout.write(`${JSON.stringify({
    packagedBinary: basename(binary),
    bridge: probe,
    runtime,
    actions: Object.fromEntries(Object.entries(actions).map(([name, value]) => [name, value.reachedNative])),
    productSurface,
    liveDashboard,
    nodeScreen,
    miningScreen,
    settingsScreen,
    historyScreen,
    advancedDashboard,
    mainnet: {
      networkStatusSource: networkStatus.source,
      connectedPeers: peerStatus.total_connected_peers,
      bootstrapPhase: peerStatus.bootstrap_phase,
      canonicalHeight: syncStatus.value.canonical_height,
      cursorHeight: syncStatus.value.cursor_height,
      synchronized: syncStatus.value.synchronized,
      applicationState: syncStatus.value.state,
      lastError: syncStatus.value.last_error,
    },
    mining: {
      status: miningStatus.value.status,
      running: miningStatus.value.running,
      hashAttempts: miningStatus.value.hash_attempts,
      acceptedBlocks: miningStatus.value.accepted_blocks,
    },
    lifecycle: lifecycleUi,
    backup: {
      exported: /Encrypted backup created/.test(backupUi),
      imported: /Encrypted backup imported/.test(restoreUi),
      walletIdPreserved: walletAfterBackup.value.wallet_id === walletBeforeBackup.value.wallet_id,
      balancePreserved: JSON.stringify(walletAfterBackup.value.balance) === JSON.stringify(walletBeforeBackup.value.balance),
    },
  }, null, 2)}\n`);
} finally {
  if (sessionId) await request(`/session/${sessionId}`, undefined, { method: "DELETE" }).catch(() => {});
  driver.kill("SIGTERM");
  await Promise.race([
    new Promise((done) => driver.once("exit", done)),
    new Promise((done) => setTimeout(done, 2_000)),
  ]);
  if (driver.exitCode === null) {
    driver.kill("SIGKILL");
    await new Promise((done) => driver.once("exit", done));
  }
  await rm(profile, { recursive: true, force: true, maxRetries: 10, retryDelay: 200 });
}
