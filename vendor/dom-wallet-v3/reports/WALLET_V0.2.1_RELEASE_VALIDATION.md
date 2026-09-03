# DOM Wallet V3 v0.2.1 Release Validation

Date: 2026-07-23  
Branch: `stabilize/wallet-v0.2.0`  
Release commit: `4e88c4a3ab66c735d601d57961125e83fdb66f3d`  
Tag: `wallet-v0.2.1`  
Release: <https://github.com/sorenplanck/dom-wallet-v3/releases/tag/wallet-v0.2.1>

## Publication status

The GitHub release is public as an experimental prerelease. It contains six
installable artifacts, `SHA256SUMS.txt`, and its detached Minisign signature.
No automatic-update feed or `latest.json` was published.

The checksum signature was verified after downloading every release asset back
from GitHub. It is valid under the pinned primary production key with key ID
`74197A95CA309CF0`. Every downloaded installer matched its signed SHA-256.

## Platform evidence

### Windows x86_64

Status: **CONFIRMED**

Run:
<https://github.com/sorenplanck/dom-wallet-v3/actions/runs/30056681197>

- managed sidecar sequence and missing-manifest application boundaries passed;
- production trust-root seam remained compile-time only;
- Windows runtime ACL and reparse-point rejection passed;
- atomic pointer promotion, data backup, and rollback passed;
- the real pinned `dom-node` process started with the Windows PE stack budget,
  reported identity, stopped, promoted, and rolled back;
- MSI and NSIS were built and family-checked;
- MSI was installed, opened, and uninstalled;
- NSIS was installed, opened, and uninstalled.

The Windows sidecar is stored in versioned directories. Promotion changes
authenticated state rather than overwriting the executable currently in use.

### Linux x86_64

Status: **CONFIRMED**

Job:
<https://github.com/sorenplanck/dom-wallet-v3/actions/runs/30056657194/job/89378603348>

- Debian package and AppImage were built and family-checked;
- the Debian package was extracted as an installed filesystem;
- the packaged native application opened under Xvfb/WebKitWebDriver;
- the native bridge smoke test passed;
- artifacts were uploaded successfully.

### macOS Apple Silicon

Status: **CONFIRMED FOR BUILD**

Job:
<https://github.com/sorenplanck/dom-wallet-v3/actions/runs/30056657194/job/89378587298>

- `.app` and `.dmg` were built and family-checked;
- artifacts were uploaded successfully.

An actual signed/notarized installation and launch on a user Mac was not
performed. The macOS artifact remains an experimental unsigned package.

## Signed artifact hashes

```text
93fed6044a3cc634e906ac9f5f030c14a6edf82855c6da7aaf3570a0a9d6379e  DOM-Wallet-V3_0.2.1_aarch64.app.tar.gz
cda91b86fe4ecf63bdfaacdc505ae8315a4d0f4c4efd0d08d46cd6749dd2f539  DOM-Wallet-V3_0.2.1_aarch64.dmg
04ecf95584e7b463112d7edcfc103bf8a861e80219f6fcff3239b73db37efd21  DOM-Wallet-V3_0.2.1_amd64.AppImage
bf559ce3ea8ca19e1f5019735c0fd5e2edc8368192399b8228f771a55d27a4d9  DOM-Wallet-V3_0.2.1_amd64.deb
5cbe38a3761dfb8eaf23ce0da96daf9e182a5e923a65b81617ef092d74ae2041  DOM-Wallet-V3_0.2.1_x64-setup.exe
107bb9a0a370b69e48647f6cb6a3cfc76ea611f4cfca596807d6f66d70b311c2  DOM-Wallet-V3_0.2.1_x64_en-US.msi
```

## Source and consensus pins

- Wallet release commit:
  `4e88c4a3ab66c735d601d57961125e83fdb66f3d`
- Managed sidecar crate revision:
  `ab45a2944f22fe00f9b12984354f0d5d7cdd229a`
- Embedded DOM Protocol revision:
  `28ba3cefc9fbc913f126336482662528c68a7d8c`

The embedded revision contains the ASERT rescue and equal-height fork
divergence fixes. No consensus constant was changed in the Wallet repository.

## Release-channel limitations

- The release is a manual experimental prerelease.
- The Tauri automatic-update feed remains unpublished and fail-closed.
- Node-only updates remain opt-in/experimental until a signed operational node
  feed is published.
- The release does not contain Apple notarization or Windows Authenticode
  evidence. Minisign authenticates the signed checksum document and therefore
  the exact installer bytes, but it does not replace operating-system code
  signing.
- The complete repeated two-wallet installed E2E, live reorg journey, and
  prolonged soak gates from the broader stabilization plan remain incomplete.

## Final classification

Artifact construction, Windows installed-package lifecycle, Linux packaged
smoke, macOS bundle construction, publication integrity, and detached checksum
authentication are **CONFIRMED**.

The release is suitable only for **EXPERIMENTAL DISTRIBUTION**. The overall
production-readiness classification remains **NOT READY** until the outstanding
installed E2E, live-network, notarization/code-signing, and soak gates have
concrete evidence.
