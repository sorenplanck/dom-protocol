import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";

test("release workflow provides pinned experimental dry-run packaging", async () => {
  const workflow = await readFile(new URL("../../.github/workflows/release-wallet.yml", import.meta.url), "utf8");
  for (const required of [
    "wallet-v*", "workflow_dispatch", "default: false",
    "ubuntu-24.04", "windows-2022", "macos-14", "x86_64-unknown-linux-gnu",
    "x86_64-pc-windows-msvc", "aarch64-apple-darwin", "appimage,deb,rpm",
    "nsis,msi", "dmg,app", "npm test --prefix frontend", "cargo metadata --locked",
    "--locked", "cargo audit", "cargo deny check", "actionlint_1.7.7_linux_amd64.tar.gz",
    "git rev-parse \"${GITHUB_REF}^{commit}\"",
    "target/${{ matrix.target }}/release/bundle",
    "Install Linux validation dependencies",
    "Test native bridge in packaged Linux application", "webkit2gtk-driver", "xvfb-run -a",
    "scripts/test-packaged-native-bridge-linux.mjs", "tauri-driver --version 2.0.6",
    "TAURI_VERSION", "test \"$VERSION\" = \"$TAURI_VERSION\"",
    "\"createUpdaterArtifacts\":true", "--no-sign",
  ]) assert.equal(workflow.includes(required), true, `missing ${required}`);

  const actionRefs = [...workflow.matchAll(/uses:\s+[^@\s]+@([^\s]+)/g)].map((match) => match[1]);
  assert.ok(actionRefs.length >= 8);
  assert.equal(actionRefs.every((ref) => /^[0-9a-f]{40}$/.test(ref)), true);
  for (const forbidden of [
    "TAURI_SIGNING_PRIVATE_KEY",
    "TAURI_SIGNING_PRIVATE_KEY_PASSWORD",
    "gh release create",
    "contents: write",
  ]) assert.equal(workflow.includes(forbidden), false, `release secret or publisher leaked into CI: ${forbidden}`);
  assert.equal(workflow.includes("release: published"), false);
  assert.equal(workflow.includes("release: created"), false);
  assert.equal(workflow.includes("/home/"), false);
  assert.equal(workflow.includes("dom-wallet-v1"), false);
  assert.equal(workflow.includes("dom-wallet-v2"), false);
});

test("stabilization workflow validates and packages without a release path", async () => {
  const workflow = await readFile(new URL("../../.github/workflows/stabilize-wallet.yml", import.meta.url), "utf8");
  for (const required of [
    "stabilize/wallet-v0.2.0", "cargo fmt --all --check",
    "cargo check --workspace --all-targets --locked",
    "cargo clippy --workspace --all-targets --locked -- -D warnings",
    "cargo test --workspace --all-targets --locked -- --test-threads=1",
    "cargo audit", "cargo deny check", "appimage,deb", "nsis,msi", "dmg,app",
    "Smoke test installed Linux application", "scripts/test-packaged-native-bridge-linux.mjs",
    "contents: read", "Build unsigned installers without publishing",
    "Preserve validated installers", "actions/upload-artifact@",
  ]) assert.equal(workflow.includes(required), true, `missing ${required}`);

  const actionRefs = [...workflow.matchAll(/uses:\s+[^@\s]+@([^\s]+)/g)].map((match) => match[1]);
  assert.ok(actionRefs.length >= 7);
  assert.equal(actionRefs.every((ref) => /^[0-9a-f]{40}$/.test(ref)), true);
  for (const forbidden of ["git tag", "gh release", "contents: write", "tags:"]) {
    assert.equal(workflow.includes(forbidden), false, `release-capable token ${forbidden}`);
  }
  assert.equal(workflow.includes("needs: validate"), false, "package feedback must run in parallel");
});

test("Tauri resolves the frontend build from both supported CLI contexts", async () => {
  const config = JSON.parse(await readFile(new URL("../../src-tauri/tauri.conf.json", import.meta.url), "utf8"));
  assert.equal(config.build.beforeBuildCommand, "node build.mjs");
  const workspaceBuild = await readFile(new URL("../../build.mjs", import.meta.url), "utf8");
  assert.match(workspaceBuild, /process\.env\.ComSpec \?\? "cmd\.exe"/);
  assert.match(workspaceBuild, /\["\/d", "\/s", "\/c", "npm --prefix frontend run build"\]/);
  assert.match(workspaceBuild, /\["--prefix", "frontend", "run", "build"\]/);
  assert.equal(config.build.frontendDist, "../frontend/dist");
  assert.deepEqual(config.bundle.icon, ["../frontend/assets/dom-coin.png", "icons/icon.ico"]);
  assert.equal(
    config.plugins.updater.pubkey,
    "dW50cnVzdGVkIGNvbW1lbnQ6IG1pbmlzaWduIHB1YmxpYyBrZXkgNzQxOTdBOTVDQTMwOUNGMApSV1R3bkRES2xYb1pkRzNvYlZSaUxQZlZSSHIxN0UwRmoyR044SVoyckJraXBSWnZJSVc2UExKMwo=",
    "updater must pin the primary DOM release key (Minisign ID 74197A95CA309CF0)",
  );
  assert.equal(
    Buffer.from(config.plugins.updater.pubkey, "base64").toString("utf8"),
    "untrusted comment: minisign public key 74197A95CA309CF0\nRWTwnDDKlXoZdG3obVRiLPfVRHr17E0Fj2GN8IZ2rBkipRZvIIW6PLJ3\n",
    "pinned updater key must decode to the canonical Minisign public key file",
  );
  assert.equal(config.plugins.updater.endpoints.every((endpoint) => endpoint.startsWith("https://")), true);
  assert.equal(config.bundle.createUpdaterArtifacts, true);
  const ico = await readFile(new URL("../../src-tauri/icons/icon.ico", import.meta.url));
  assert.deepEqual([...ico.subarray(0, 4)], [0, 0, 1, 0]);
});

test("release builds use the Windows GUI subsystem without a console window", async () => {
  const entrypoint = await readFile(new URL("../../src-tauri/src/main.rs", import.meta.url), "utf8");
  assert.match(
    entrypoint,
    /^#!\[cfg_attr\(not\(debug_assertions\), windows_subsystem = "windows"\)\]/,
  );
});
