# Windows Test Runner

`dom-test-runner.exe` is the portable Windows validation tool for DOM Protocol development.

## Build

```bash
cargo build -p dom-test-runner --release
```

## Run

```bash
target/release/dom-test-runner.exe doctor
target/release/dom-test-runner.exe affected
target/release/dom-test-runner.exe pre-push
target/release/dom-test-runner.exe full
target/release/dom-test-runner.exe all
```

## Fast Mining

The runner sets safe test-mode environment variables internally:

- `DOM_NETWORK=regtest`
- `DOM_REGTEST_FAST_MINING=1`
- `RUST_BACKTRACE=1`

The fast-mining path is explicit and isolated. It is only intended for test/regtest-style validation and does not weaken mainnet or testnet PoW.

## Logs and Reports

Every run writes logs and reports under:

- `target/dom-test-runner/logs/`
- `target/dom-test-runner/reports/`
- `target/dom-test-runner/reports/latest-report.txt`

## GitHub Actions Artifact

The Windows workflow uploads the portable binary as:

- `DOM-Test-Runner-Windows-Portable`

Download the artifact from the workflow run, then unpack `dom-test-runner.exe` alongside this document if included.
