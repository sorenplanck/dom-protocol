# DOM Test Runner — Windows portable .exe

`dom-test-runner.exe` is a small, dependency-free Rust binary that runs the
right DOM Protocol test profile for a given change without making the user
remember which `cargo test -p ...` incantation to type.

## What it is

- A workspace member crate: `crates/dom-test-runner`
- Compiles to a single portable `dom-test-runner.exe` on Windows
- Zero external runtime dependencies (std only) — easy to audit, fast to build
- Reads your changed files (`git diff`) and selects the right test profiles

## What it is NOT

- It does **not** weaken mainnet / testnet PoW
- It does **not** mine real chains
- It does **not** install software, change global settings, or store secrets

## Build locally

From the repository root:

```
cargo build -p dom-test-runner --release
```

The binary will be at:

```
target/release/dom-test-runner.exe        (Windows)
target/release/dom-test-runner            (Linux/macOS)
```

## Run

```
target\release\dom-test-runner.exe doctor
target\release\dom-test-runner.exe affected
target\release\dom-test-runner.exe explain affected
target\release\dom-test-runner.exe pre-push
target\release\dom-test-runner.exe fast-check
target\release\dom-test-runner.exe full
target\release\dom-test-runner.exe all
target\release\dom-test-runner.exe help
```

Per-profile examples: `mempool`, `node`, `wire`, `pow`, `chain`, `store`,
`wallet`, `wallet-app`, `integration`, `integration-mempool`,
`integration-network`, `two-node`, `reorg`, `ibd`.

## Automatic test selection (`affected`)

`dom-test-runner.exe affected` inspects `git diff` and `git diff --cached`
and runs only the test profiles that match the changed files. Example:

| Changed crate                  | Profiles triggered                                  |
| ------------------------------ | --------------------------------------------------- |
| `crates/dom-mempool/**`        | `mempool`, `integration-mempool`                    |
| `crates/dom-node/**`           | `node`, `integration`                               |
| `crates/dom-wire/**`           | `wire`, `integration-network`                       |
| `crates/dom-pow/**`            | `pow`, `two-node`, `reorg`                          |
| `crates/dom-chain/**`          | `chain`, `ibd`, `reorg`                             |
| `crates/dom-store/**`          | `store`, `chain`                                    |
| `crates/dom-wallet/**`         | `wallet`                                            |
| `crates/dom-wallet-app/**`     | `wallet-app` only (no heavy network tests alone)    |
| `crates/dom-integration-tests/**` | `integration`                                    |
| `.github/workflows/**`         | `fast-check`                                        |
| `docs/**` (only)               | `fast-check`                                        |

If no files match any rule the runner falls back to `fast-check`. Use
`explain affected` to print *why* each profile was picked.

## Regtest / devtest fast mining

Every test profile is run with these environment variables set:

```
DOM_NETWORK=regtest
DOM_REGTEST_FAST_MINING=1
RUST_BACKTRACE=1
```

These signal intent. The DOM node / miner code is responsible for honoring
the regtest fast-mining path on its side. **The runner itself cannot bypass
mainnet/testnet PoW** — it only ever asks for `regtest`.

`DOM_REGTEST_FAST_MINING=1` MUST be ignored outside `regtest` / `devtest` /
`cfg(test)`. The runner's own `env::check_fast_mining` enforces this and is
tested. The corresponding node-side guard is a separate batch (Part 1).

## Logs and reports

Every run writes:

```
target/dom-test-runner/logs/<ts>-<step>.log     — full cargo stdout/stderr
target/dom-test-runner/reports/<ts>.txt         — summary report
target/dom-test-runner/reports/latest-report.txt — latest summary (overwritten)
```

Each report includes the timestamp, profile, environment variables, exact
cargo commands run, PASS / FAIL / SKIPPED / BLOCKED per step, total
duration, and the path to the per-step log.

## `clean`

Deletes only `target/dom-test-runner/`. It refuses to touch anything else.

## Download from GitHub Actions

The workflow `.github/workflows/windows-test-runner.yml` builds
`dom-test-runner.exe` on `windows-latest` and uploads it as the artifact
`DOM-Test-Runner-Windows-Portable`.

1. Push your branch to GitHub.
2. Open Actions → Windows Test Runner → run (or wait for the auto-trigger).
3. Open the run → scroll to *Artifacts* → download
   `DOM-Test-Runner-Windows-Portable`.

## Honest reporting

If a profile contains integration tests that don't yet exist in the
repository (e.g. `two_node.rs`), the runner reports them as `SKIPPED (test
target not present)` instead of failing. This is intentional and visible in
the report so missing coverage is not silently masked.

If a profile fails because of an environment problem, you'll see `BLOCKED`
with the spawn error. The runner never fakes success.
