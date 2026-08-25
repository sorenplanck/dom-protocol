# Portable Platform CI and Phase 1 Evidence

Status: **CORRECTED EVIDENCE RUN PASSED ON ALL REQUIRED PLATFORMS**

## Purpose

Two workflows have intentionally different purposes:

- `.github/workflows/phase1-platform-evidence.yml` is the NAR-DC-P1-006
  section 5.2 evidence workflow. It performs only the six required read-only
  commands, uploads no artifact, and runs on `phase1-evidence` and `main`.
- `.github/workflows/portable-platforms.yml` validates and packages the
  fail-closed native shell on `main`. Its artifact upload makes it ineligible
  as section 5.2 evidence.

The matrix contains:

- `windows-latest` for Windows x86-64;
- `macos-latest` for macOS ARM64; and
- `macos-15-intel` for macOS x86-64.

The workflow does not implement or emulate the Linux-only retained filesystem
capability. Unsupported production runtime paths remain unavailable and fail
closed. The native shell exposes no contract, funding, signing, networking,
storage, mainnet, Phase 2, or real-funds operation.

## Reproducible inputs

The repository pins Rust `1.96.1` in `rust-toolchain.toml`. Each runner records
its complete Rust, Cargo, operating-system, and architecture identities.

Third-party actions use immutable Git commit SHAs. The evidence workflow uses
only the first two actions below:

| Action | Commit |
| --- | --- |
| `actions/checkout` | `d23441a48e516b6c34aea4fa41551a30e30af803` |
| `dtolnay/rust-toolchain` | `4360b52568e2003a75bf9bc1d59f33a8e3fc893c` |
| `actions/upload-artifact` | `330a01c490aca151604b8cf639adc76d48f6c5d4` |

The workspace and both lockfiles resolve `dom-adaptor` and `dom-crypto` from
the official public repository at the immutable revision
`6f2b230ebbec390040dbf0bff110efaf4bb0f101`. No tracked path override,
floating branch, or unpublished revision is permitted.

## Validation commands

Every evidence-matrix leg runs:

```text
cargo metadata --locked --format-version 1
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo check --workspace --all-targets --all-features --locked
cargo test --workspace --all-features --locked --no-run
cargo test --workspace --all-features --locked
```

No validation step uses `continue-on-error`, and matrix fail-fast is disabled
so each platform produces an independent result.

The native-artifact workflow additionally builds and packages the fail-closed
shell. That extra activity is outside the evidence workflow.

## First native evidence execution

GitHub Actions run `31347544587` executed commit
`da557491e58c1c4bdd906983c25c7fb64a78e6fc` on all three required hosted
runners. Locked metadata and formatting passed on every runner. Clippy failed
with `-D warnings` because the canonical authenticated-record machinery is
consumed by the Linux-only runtime and therefore appeared unused when that
runtime was normatively absent on Windows and macOS. The later commands were
skipped after Clippy failed.

The correction keeps the canonical parser and validation source compiled on
portable targets while acknowledging only the expected `dead_code` and
`unused_imports` reachability diagnostics inside that module. It does not add
a non-Linux runtime, fallback filesystem access, emulation, or network side
effect.

## Corrected evidence execution

GitHub Actions run `31349273622` executed correction commit
`0b55aa9d2ba62ac023de94efa126451b82eec311` with the required read-only
workflow. Every command completed successfully in all three matrix legs:

| Platform | Job | Result |
| --- | --- | --- |
| Windows x86-64 | `93336938146` | Pass |
| macOS ARM64 | `93336938079` | Pass |
| macOS x86-64 | `93336938102` | Pass |

The run used no secret, artifact upload, cache write, package, release,
deployment, or remote mutation. Its result is evidence for portable
compilation and tests only; it does not establish a non-Linux production
runtime.

## Native validation artifacts outside the evidence gate

The Windows job uploads the unsigned native executable and its SHA-256 file:

```text
dom-contracts-windows-x86_64.exe
dom-contracts-windows-x86_64.exe.sha256
```

Each macOS job archives the unsigned native executable and uploads the archive
with its SHA-256 file:

```text
dom-contracts-macos-arm64.tar.gz
dom-contracts-macos-arm64.tar.gz.sha256
dom-contracts-macos-x86_64.tar.gz
dom-contracts-macos-x86_64.tar.gz.sha256
```

Artifacts are retained for 14 days. Uploading these validation artifacts does
not create a GitHub Release, publish a package, sign code, notarize code, or
authorize production use.

## Security boundary

The workflow has only `contents: read` permission and checkout credentials are
not persisted. It references no repository secret, performs no deployment,
modifies no remote, and builds no mainnet-enabled configuration.

After inspection of the corrected run, platform status is:

```text
WINDOWS_X86_64 = PASS
MACOS_ARM64 = PASS
MACOS_X86_64 = PASS
PHASE1_EVIDENCE_RERUN = PASS
PRODUCTION = NOT_AUTHORIZED
MAINNET = DISABLED
PHASE2 = NOT_AUTHORIZED
REAL_FUNDS = PROHIBITED
```
