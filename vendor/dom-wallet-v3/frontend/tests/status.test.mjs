import test from "node:test";
import assert from "node:assert/strict";
import {
  chainSourcePresentation,
  chainSourceTlsWarning,
  formatDomFromNoms,
  liveStatusProjection,
  miningPresentation,
  nodeStatusText,
  remoteTipAlertPresentation,
  restoreReadinessPresentation,
  restoreScanPresentation,
  synchronizationPresentation,
} from "../status.js";

test("frontend source contains no durable browser storage access", async () => {
  const source = await (await import("node:fs/promises")).readFile(new URL("../main.js", import.meta.url), "utf8");
  assert.equal(source.includes("localStorage"), false);
  assert.equal(source.includes("sessionStorage"), false);
  assert.equal(source.includes("indexedDB"), false);
});

test("dashboard refreshes live IBD progress every fifteen seconds", async () => {
  const source = await (await import("node:fs/promises")).readFile(new URL("../main.js", import.meta.url), "utf8");
  assert.equal(source.includes('invoke("embedded_node_status")'), true);
  assert.equal(source.includes("liveStatusProjection(summary, node, network, peers, synchronization)"), true);
  assert.equal(source.includes("let latestEmbeddedNodeStatus;"), true);
  assert.equal(source.includes('lifecycle: "STALE"'), true);
  assert.equal(source.includes(": [refreshSummary(), refreshNode(), refreshMining()]"), true);
  assert.equal(source.includes("? [refreshOnboardingNode()]"), true);
  assert.equal(source.includes("await Promise.allSettled(tasks)"), true);
  assert.equal(source.includes("setTimeout(refresh, gateVisible ? 5000 : 15000)"), true);
  assert.equal(source.includes('lifecycle: "STALE"'), true);
  assert.equal(source.includes('ready: false'), true);
});

test("dashboard badge cannot report READY while a peer is ahead", () => {
  const result = synchronizationPresentation(
    { canonical_height: 1_008 },
    { highest_known_peer_height: 6_684, total_connected_peers: 1 },
    { synchronized: false, cursor_height: 1_008, last_error: null },
  );
  assert.deepEqual(result, {
    badgeState: "SYNCHRONIZING",
    message: "Synchronizing 1008 / 6684 (15%)",
    localHeight: 1_008,
    peerHeight: 6_684,
    progress: 15,
  });
});

test("dashboard reports READY only when canonical height and cursor are synchronized", () => {
  const result = synchronizationPresentation(
    { canonical_height: 6_684 },
    { highest_known_peer_height: 6_684, total_connected_peers: 1 },
    { synchronized: true, cursor_height: 6_684, last_error: null },
  );
  assert.equal(result.badgeState, "READY");
  assert.equal(result.message, "Wallet synchronized at height 6684");
});

test("dashboard exposes a synchronization error instead of READY", () => {
  const result = synchronizationPresentation(
    { canonical_height: 20 },
    { highest_known_peer_height: 20, total_connected_peers: 1 },
    { synchronized: false, cursor_height: 19, last_error: "CURSOR_HASH_MISMATCH" },
  );
  assert.equal(result.badgeState, "ATTENTION");
  assert.equal(result.message, "CURSOR_HASH_MISMATCH");
});

test("regression_c5_frontend_renders_every_authoritative_state_without_local_height_fallback", () => {
  const render = (lifecycle, local, peer, connected, synchronized = false) =>
    synchronizationPresentation(
      { canonical_height: local, lifecycle, status_message: `state:${lifecycle}` },
      { highest_known_peer_height: peer, total_connected_peers: connected },
      { synchronized, cursor_height: local, last_error: null },
    );

  assert.equal(render("STOPPED", 0, undefined, 0).badgeState, "STOPPED");
  assert.equal(render("STARTING", 0, undefined, 0).badgeState, "STARTING");
  assert.equal(render("WAITING_FOR_PEERS", 9, undefined, 0).badgeState, "WAITING_FOR_PEERS");
  const unknown = render("UNKNOWN_PEER_HEIGHT", 9, undefined, 1);
  assert.equal(unknown.badgeState, "UNKNOWN_PEER_HEIGHT");
  assert.equal(unknown.peerHeight, null);
  assert.equal(render("CONNECTED_AT_GENESIS", 0, 0, 1).badgeState, "CONNECTED_AT_GENESIS");
  assert.equal(render("SYNCHRONIZING", 9, 10, 1).badgeState, "SYNCHRONIZING");
  assert.equal(render("READY", 10, 10, 1, true).badgeState, "READY");
  assert.equal(render("STALE", 10, 10, 1).badgeState, "STALE");
  assert.equal(render("FAILED", 10, 10, 1).badgeState, "FAILED");
});

test("dashboard preserves live node identity when peer or wallet status is transiently unavailable", () => {
  const result = liveStatusProjection(
    { cursor_height: 0 },
    {
      canonical_tip_height: 1,
      connected_peers: 1,
      highest_known_peer_height: 6_706,
      chain_id: "chain",
      genesis_hash: "genesis",
      bootstrap_phase: "CONNECTED",
    },
    undefined,
    undefined,
    undefined,
  );
  assert.equal(result.chainId, "chain");
  assert.equal(result.genesisHash, "genesis");
  assert.equal(result.canonicalHeight, 1);
  assert.equal(result.connectedPeers, 1);
  assert.equal(result.badgeState, "SYNCHRONIZING");
  assert.equal(result.message, "Synchronizing 1 / 6706 (0%)");
});

test("mining controls remain disabled until the real node is ready", () => {
  const result = miningPresentation(
    { status: "READY", enabled: true, running: false, current_height: 0 },
    { lifecycle: "SYNCHRONIZING", ready: false, status_message: "Synchronizing 0 / 6684 (0%)" },
  );
  assert.deepEqual(result, {
    status: "SYNCHRONIZING",
    canStart: false,
    warning: "Synchronizing 0 / 6684 (0%)",
  });
});

test("mining waiting for synchronization is not an idle miner the user must restart", () => {
  const ready = { lifecycle: "READY", ready: true, status_message: null };
  const waiting = miningPresentation(
    {
      status: "WAITING_FOR_SYNCHRONIZATION",
      enabled: true,
      running: false,
      current_height: 10_191,
    },
    ready,
  );
  // The worker is alive and resumes by itself, so Start must stay disabled —
  // offering it would read as "mining is off" and the backend rejects it as
  // MINING_RUNNING anyway.
  assert.equal(waiting.status, "WAITING_FOR_SYNCHRONIZATION");
  assert.equal(waiting.canStart, false);

  // A genuinely stopped miner at the same height can still be started.
  const stopped = miningPresentation(
    { status: "READY", enabled: true, running: false, current_height: 10_191 },
    ready,
  );
  assert.equal(stopped.canStart, true);
});

test("node status text exposes live heights and progress", () => {
  const text = nodeStatusText({
    status_message: "Synchronizing 1008 / 6684 (15%)",
    lifecycle: "SYNCHRONIZING",
    network: "MAINNET",
    canonical_tip_height: 1_008,
    highest_known_peer_height: 6_684,
    synchronization_progress_percent: 15,
    connected_peers: 1,
    bootstrap_phase: "CONNECTED",
    canonical_tip_hash: "abcd",
    error_code: null,
  });
  assert.match(text, /Local height: 1008/);
  assert.match(text, /Highest peer height: 6684/);
  assert.match(text, /Synchronization: 15%/);
  assert.doesNotMatch(text, /CORE_NOT_READY/);
});

test("regression_restore_submit_is_enabled_in_every_node_state", () => {
  const states = [
    { network: "MAINNET", lifecycle: "READY", ready: true, canonical_tip_height: 5_241, highest_known_peer_height: 0, connected_peers: 0 },
    { network: "MAINNET", lifecycle: "SYNCHRONIZING", ready: false, canonical_tip_height: 5_241, highest_known_peer_height: 8_009, connected_peers: 2 },
    { network: "MAINNET", lifecycle: "READY", ready: true, canonical_tip_height: 8_009, highest_known_peer_height: 8_009, connected_peers: 2 },
    { network: "MAINNET", lifecycle: "STARTING", ready: false, canonical_tip_height: 0, highest_known_peer_height: 0, connected_peers: 0 },
    { network: "MAINNET", lifecycle: "FAILED", ready: false, canonical_tip_height: 0, highest_known_peer_height: 0, connected_peers: 0 },
    undefined,
  ];
  for (const node of states) {
    assert.equal(restoreReadinessPresentation(node).submitEnabled, true);
  }
});

test("onboarding restore panel keeps informational Mainnet status without gating submit", () => {
  const discovering = restoreReadinessPresentation({
    network: "MAINNET",
    lifecycle: "READY",
    ready: true,
    canonical_tip_height: 5_241,
    highest_known_peer_height: 0,
    connected_peers: 0,
  });
  assert.deepEqual(discovering, {
    submitEnabled: true,
    badge: "DISCOVERING",
    message: "Discovering Mainnet peers at local height 5241.",
    localHeight: 5_241,
    peerHeight: null,
    connectedPeers: 0,
    progress: 0,
  });

  const syncing = restoreReadinessPresentation({
    network: "MAINNET",
    lifecycle: "SYNCHRONIZING",
    ready: false,
    canonical_tip_height: 5_241,
    highest_known_peer_height: 8_009,
    connected_peers: 2,
  });
  assert.equal(syncing.submitEnabled, true);
  assert.equal(syncing.badge, "SYNCHRONIZING");
  assert.equal(syncing.message, "Synchronizing 5241 / 8009 (65%).");

  const ready = restoreReadinessPresentation({
    network: "MAINNET",
    lifecycle: "READY",
    ready: true,
    canonical_tip_height: 8_009,
    highest_known_peer_height: 8_009,
    connected_peers: 2,
  });
  assert.equal(ready.submitEnabled, true);
  assert.equal(ready.badge, "READY");
  assert.equal(ready.progress, 100);
});

test("DOM balances use the canonical 100,000,000 noms denomination", () => {
  assert.equal(formatDomFromNoms(0), "0.00000000 DOM");
  assert.equal(formatDomFromNoms(100_000_000), "1.00000000 DOM");
  assert.equal(formatDomFromNoms(3_300_000_000), "33.00000000 DOM");
  assert.equal(formatDomFromNoms(Number.MAX_SAFE_INTEGER + 1), "Unavailable");
});

test("settings expose separate fail-closed Wallet and node update states", async () => {
  const { readFile } = await import("node:fs/promises");
  const [html, js, rust] = await Promise.all([
    readFile(new URL("../index.html", import.meta.url), "utf8"),
    readFile(new URL("../main.js", import.meta.url), "utf8"),
    readFile(new URL("../../src-tauri/src/lib.rs", import.meta.url), "utf8"),
  ]);
  for (const marker of ["update-wallet-state", "update-signing-state", "updates-check", "updates-download", "updates-apply", "automatic-updates"]) {
    assert.equal(html.includes(marker), true);
  }
  for (const removed of ["update-node-state", "update-peer-state", "Check node now"]) {
    assert.equal(html.includes(removed), false);
  }
  assert.equal(js.includes('"Scheduled · signing unavailable"'), true);
  for (const command of ["get_build_info", "update_status", "check_updates_now", "download_update_now", "apply_update_now", "automatic_updates_set"]) {
    assert.equal(rust.includes(command), true);
  }
  const registry = rust.slice(rust.indexOf("macro_rules! wallet_command_registry"), rust.indexOf("macro_rules! define_command_names"));
  assert.equal(registry.includes("check_node_now"), false);
  assert.equal(js.includes("bridge.command_names.includes(command)"), true);
  assert.equal(js.includes("localStorage"), false);
  assert.equal(js.includes("sessionStorage"), false);
});

test("production adapter maps each recovery and backup command without a mock", async () => {
  const { readFile } = await import("node:fs/promises");
  const [source, bridge] = await Promise.all([
    readFile(new URL("../main.js", import.meta.url), "utf8"),
    readFile(new URL("../bridge.js", import.meta.url), "utf8"),
  ]);
  assert.equal((source.match(/"application_status"/g) ?? []).length > 0, true);
  assert.equal(source.includes("const developmentMock"), false);
  assert.equal(source.includes("fake balance"), false);
  assert.equal(source.includes("window.__TAURI__"), false);
  assert.equal(bridge.includes('@tauri-apps/api/core'), true);
  assert.equal(bridge.includes("window.__TAURI__"), false);
  for (const command of [
    "wallet_create_recoverable", "wallet_recovery_phrase_confirm",
    "wallet_restore_from_mnemonic", "wallet_backup_export", "wallet_backup_import"
  ]) assert.equal(source.includes(`"${command}"`), true);
});

test("regression_a2_gate_exposes_close_switch_and_no_raw_path_open", async () => {
  const { readFile } = await import("node:fs/promises");
  const [html, source] = await Promise.all([
    readFile(new URL("../index.html", import.meta.url), "utf8"),
    readFile(new URL("../main.js", import.meta.url), "utf8"),
  ]);
  assert.equal(html.includes('id="gate-close-wallet"'), true);
  assert.equal(source.includes('invoke("wallet_close")'), true);
  assert.equal(source.includes('invoke("wallet_open",'), false);
  assert.equal(source.includes('"wallet_open"'), false);
});

test("recovery and backup inputs are transient and use no browser persistence", async () => {
  const { readFile } = await import("node:fs/promises");
  const [html, js] = await Promise.all([
    readFile(new URL("../index.html", import.meta.url), "utf8"),
    readFile(new URL("../main.js", import.meta.url), "utf8")
  ]);
  for (const id of [
    "restore-form", "restore-submit", "onboarding-node-message", "onboarding-node-progress",
    "backup-export-form", "backup-import-form", "recovery-ceremony"
  ]) assert.equal(html.includes(`id="${id}"`), true);
  assert.equal(html.includes('name="mnemonic"'), true);
  assert.equal(js.includes("clearPhrase"), true);
  assert.equal(js.includes("textarea[name=\"mnemonic\"]"), true);
  assert.equal(js.includes('byId("restore-submit").disabled = !presentation.submitEnabled'), true);
  assert.equal(js.includes('invoke("embedded_node_status")'), true);
  assert.equal(js.includes("localStorage"), false);
});

test("regression_m7_frontend_clears_phrase_and_exposes_no_persistent_secret_state", async () => {
  const { readFile } = await import("node:fs/promises");
  const source = await readFile(new URL("../main.js", import.meta.url), "utf8");
  assert.equal(source.includes('byId("recovery-phrase").textContent = "";'), true);
  assert.equal(source.includes("phrasePending = false;"), true);
  assert.equal(source.includes('invoke("wallet_recovery_phrase_resume"'), true);
  assert.equal(source.includes('await invoke("wallet_lock")'), true);
  assert.equal(source.includes('created.mnemonic = "";'), true);
  assert.equal(source.includes('ceremony.mnemonic = "";'), true);
  assert.equal(source.includes("localStorage"), false);
  assert.equal(source.includes("sessionStorage"), false);
});

test("manual slate controls use only the production invoke adapter and clear pasted text", async () => {
  const { readFile } = await import("node:fs/promises");
  const [source, registry] = await Promise.all([
    readFile(new URL("../main.js", import.meta.url), "utf8"),
    readFile(new URL("../../src-tauri/src/lib.rs", import.meta.url), "utf8"),
  ]);
  for (const command of [
    "transaction_fee_estimate", "transaction_send_create", "slate_request_export",
    "slate_request_import", "slate_response_create", "slate_response_export",
    "slate_response_import", "slate_summary_redacted", "transaction_finalize",
    "transaction_submit", "transaction_retry_submission", "transaction_reconcile_submission", "transaction_cancel", "slate_cancel",
    "transaction_list", "transaction_detail_redacted"
  ]) assert.equal(source.includes(`"${command}"`) || registry.includes(command), true);
  assert.equal(source.includes("clearSecretForms"), true);
  assert.equal(source.includes("/wallet/spend"), false);
});

test("pending payment history exposes age and cancellation that releases the reserved input", async () => {
  const { readFile } = await import("node:fs/promises");
  const [js, registry] = await Promise.all([
    readFile(new URL("../main.js", import.meta.url), "utf8"),
    readFile(new URL("../../src-tauri/src/lib.rs", import.meta.url), "utf8"),
  ]);
  assert.equal(registry.includes("slate_cancel"), true);
  assert.equal(js.includes('invoke("slate_cancel"'), true);
  assert.equal(js.includes("blocks old"), true);
  assert.equal(js.includes("seconds old"), true);
  assert.equal(js.includes("entire reserved input will return"), true);
  assert.equal(js.includes("wallet rescan will not reserve it again"), true);
});

test("expired Slate presentation distinguishes safe auto-cancel from finalized risk", async () => {
  const { readFile } = await import("node:fs/promises");
  const js = await readFile(new URL("../main.js", import.meta.url), "utf8");
  assert.equal(js.includes("EXPIRED_BEFORE_FINALIZATION"), true);
  assert.equal(js.includes("cancelled automatically and its input is available again"), true);
  assert.equal(js.includes("Awaiting broadcast/confirmation"), true);
  assert.equal(js.includes("never cancelled automatically"), true);
  assert.equal(js.includes("counterparty may still broadcast it"), true);
  assert.equal(js.includes("double spend"), true);
});

test("QR exchange stays local, uses canonical native frames, and releases camera state", async () => {
  const { readFile } = await import("node:fs/promises");
  const [source, registry] = await Promise.all([
    readFile(new URL("../main.js", import.meta.url), "utf8"),
    readFile(new URL("../../src-tauri/src/lib.rs", import.meta.url), "utf8"),
  ]);
  for (const command of ["slate_qr_encode", "slate_qr_decode_frame", "slate_qr_reassembly_status", "slate_qr_reassembly_clear"]) {
    assert.equal(source.includes(`"${command}"`) || registry.includes(command), true);
  }
  assert.equal(source.includes("slateId: requiredReceiveId()"), true);
  assert.equal(source.includes("Receiver response frame"), true);
  assert.equal(source.includes("setInterval(() =>"), true);
  assert.equal(source.includes("Single canonical QR frame requires no animation"), false);
  assert.equal(source.includes("QrScanner"), true);
  assert.equal(source.includes("stopScanner"), true);
  assert.equal(source.includes("fetch("), false);
  assert.equal(source.includes("localStorage"), false);
});

test("restore scan presentation reports block progress and partial balance", () => {
  const result = restoreScanPresentation({
    seed_restore_in_progress: true,
    cursor_height: 1_200,
    tip_height: 8_000,
    scan_progress_percent: 15,
    partial_balance: 250_000_000,
  });
  assert.equal(result.active, true);
  assert.equal(result.message, "Restored — scanning block 1200 of 8000 (15%)");
  assert.equal(result.progress, 15);
  assert.equal(result.cursorHeight, 1_200);
  assert.equal(result.tipHeight, 8_000);
  assert.equal(result.partialBalanceText, "Partial balance: 2.50000000 DOM");
});

test("restore scan presentation derives progress when percent is missing", () => {
  const result = restoreScanPresentation({
    seed_restore_in_progress: true,
    cursor_height: 2_000,
    tip_height: 8_000,
    partial_balance: { confirmed: 0 },
  });
  assert.equal(result.progress, 25);
  assert.equal(result.message, "Restored — scanning block 2000 of 8000 (25%)");
  assert.equal(result.partialBalanceText, "Partial balance: 0.00000000 DOM");
});

test("restore scan presentation handles an unknown tip and missing balance", () => {
  const result = restoreScanPresentation({
    seed_restore_in_progress: true,
    cursor_height: 42,
  });
  assert.equal(result.active, true);
  assert.equal(result.message, "Restored — scanning block 42");
  assert.equal(result.partialBalanceText, "Partial balance: unavailable");
});

test("regression_restore_scan_presentation_is_inactive_after_seed_restore_completes", () => {
  const result = restoreScanPresentation({
    seed_restore_in_progress: false,
    cursor_height: 8_000,
    tip_height: 8_000,
    partial_balance: 250_000_000,
  });
  assert.equal(result.active, false);
  assert.equal(result.message, null);
  assert.equal(result.partialBalanceText, null);
  assert.equal(restoreScanPresentation(undefined).active, false);
});

test("remote tip regression raises a persistent alert presentation", () => {
  const alert = remoteTipAlertPresentation({ remote_tip_alert: true });
  assert.equal(alert.active, true);
  assert.match(alert.message, /regressed or is inconsistent/);
  assert.deepEqual(remoteTipAlertPresentation({ remote_tip_alert: false }), { active: false, message: null });
  assert.equal(remoteTipAlertPresentation(undefined).active, false);
});

test("chain source TLS warning triggers only for cleartext non-local URLs", () => {
  assert.equal(chainSourceTlsWarning("https://node.example:8443"), false);
  assert.equal(chainSourceTlsWarning("http://localhost:8080"), false);
  assert.equal(chainSourceTlsWarning("http://127.0.0.1:8080"), false);
  assert.equal(chainSourceTlsWarning("http://[::1]:8080"), false);
  assert.equal(chainSourceTlsWarning("http://node.example:8080"), true);
  assert.equal(chainSourceTlsWarning("not a url"), true);
  assert.equal(chainSourceTlsWarning(""), false);
  assert.equal(chainSourceTlsWarning(undefined), false);
});

test("chain source presentation defaults to embedded and flags cleartext remote", () => {
  const embedded = chainSourcePresentation({ source: "EMBEDDED", base_url: null, has_bearer_token: false, tls_warning: false });
  assert.equal(embedded.source, "EMBEDDED");
  assert.equal(embedded.tlsWarning, false);
  assert.match(embedded.message, /Local full node/);

  const remote = chainSourcePresentation({ source: "REMOTE", base_url: "http://node.example:8080", has_bearer_token: true, tls_warning: false });
  assert.equal(remote.source, "REMOTE");
  assert.equal(remote.hasBearerToken, true);
  assert.equal(remote.tlsWarning, true);
  assert.match(remote.message, /Remote node \(fast\): http:\/\/node\.example:8080/);

  assert.equal(chainSourcePresentation(undefined).source, "EMBEDDED");
  assert.equal(chainSourcePresentation({ source: "REMOTE", base_url: "https://node.example", has_bearer_token: false, tls_warning: false }).tlsWarning, false);
});

test("restore flow returns immediately and polls the background scan", async () => {
  const { readFile } = await import("node:fs/promises");
  const [html, js] = await Promise.all([
    readFile(new URL("../index.html", import.meta.url), "utf8"),
    readFile(new URL("../main.js", import.meta.url), "utf8"),
  ]);
  for (const id of ["restore-progress", "restore-progress-message", "restore-progress-bar", "restore-progress-balance"]) {
    assert.equal(html.includes(`id="${id}"`), true, `missing ${id}`);
  }
  assert.equal(html.includes('id="restore-submit" class="btn" type="submit" disabled'), false);
  assert.equal(js.includes("restoreScanPresentation"), true);
  assert.equal(js.includes('invoke("wallet_sync_status")'), true);
  assert.equal(js.includes("result?.scanning === true"), true);
  assert.equal(js.includes("beginRestoreScanPolling"), true);
  assert.equal(js.includes("stopRestoreScanPolling"), true);
  assert.equal(js.includes("owned_outputs"), false);
});

test("chain source panel persists through the typed bridge without echoing the token", async () => {
  const { readFile } = await import("node:fs/promises");
  const [html, js] = await Promise.all([
    readFile(new URL("../index.html", import.meta.url), "utf8"),
    readFile(new URL("../main.js", import.meta.url), "utf8"),
  ]);
  for (const id of ["chain-source-form", "chain-source-url", "chain-source-token", "chain-source-tls-warning", "chain-source-current", "settings-chain-source", "settings-chain-source-warning"]) {
    assert.equal(html.includes(`id="${id}"`), true, `missing ${id}`);
  }
  assert.equal(html.includes('data-gate-panel="chain-source-form"'), true);
  assert.equal(html.includes('value="EMBEDDED" checked'), true);
  assert.equal(html.includes('id="chain-source-token" name="bearer_token" type="password"'), true);
  assert.equal(js.includes('"chain_source_get"'), true);
  assert.equal(js.includes('"chain_source_set"'), true);
  assert.equal(js.includes("chainSourceTlsWarning"), true);
  assert.equal(js.includes("DEFAULT_REMOTE_NODE_URL"), true);
  assert.equal(js.includes('byId("chain-source-token").value ='), false);
});

test("remote tip alert banners exist on the gate and in the application shell", async () => {
  const { readFile } = await import("node:fs/promises");
  const [html, js] = await Promise.all([
    readFile(new URL("../index.html", import.meta.url), "utf8"),
    readFile(new URL("../main.js", import.meta.url), "utf8"),
  ]);
  assert.equal(html.includes('id="remote-tip-alert"'), true);
  assert.equal(html.includes('id="gate-remote-tip-alert"'), true);
  assert.equal(js.includes("remoteTipAlertPresentation"), true);
  assert.equal(js.includes("remoteTipAlertMessage"), true);
});
