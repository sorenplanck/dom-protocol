# Live node lifecycle runbook

The `dom-wallet-live-e2e` binary has two explicit modes. `cargo test` does not execute it.

Required configuration names are `DOM_LIVE_E2E_RPC_URL`, `DOM_LIVE_E2E_NETWORK`, `DOM_LIVE_E2E_CHAIN_ID`, `DOM_LIVE_E2E_GENESIS_HASH`, `DOM_LIVE_E2E_WALLET_A_DIR`, `DOM_LIVE_E2E_WALLET_A_PASSWORD_FILE`, `DOM_LIVE_E2E_WALLET_B_DIR`, `DOM_LIVE_E2E_WALLET_B_PASSWORD_FILE`, and `DOM_LIVE_E2E_AMOUNT_NOMS`. The runner prints missing names only. It never prints values, passwords, tokens, raw slates, QR content, private contexts, or finalized bytes.

Password files must be regular files and, on Unix, must not grant group or other permissions. Wallet paths and protected files must remain outside the repository.

Run the real non-mutating preflight first:

```text
DOM_LIVE_E2E_MODE=PREFLIGHT cargo run -p dom-wallet-core --bin dom-wallet-live-e2e
```

`PREFLIGHT` validates protected password files, probes health and chain identity,
exercises bounded scan/ancestry/kernel/transaction-lookup capabilities, opens and
synchronizes both wallets, calculates the deterministic backend funding/fee
result without creating a transaction, and observes tip progression. It prints
only redacted PASS/FAIL state. It cannot reserve inputs, allocate outputs,
construct slates, finalize, submit, or retry.

Only a passing preflight can continue in `EXECUTE`, which also requires the
exact acknowledgement:

```text
DOM_LIVE_E2E_MODE=EXECUTE
DOM_LIVE_E2E_ENABLE=I_UNDERSTAND_THIS_SUBMITS_A_LIVE_DOM_TRANSACTION
```

`EXECUTE` always repeats the complete preflight before it reaches the existing
transaction engine. Missing funding stops before reservation. Missing observed
tip progression stops before transaction construction with
`BLOCK_PRODUCER_REQUIRED`. It never starts or configures a miner. Once
execution is eligible, it uses the existing text slate exchange, submits only
persisted finalized bytes, observes mempool evidence when present, waits for
scan-based kernel confirmation, reconciles both wallets, closes/reopens both,
and resynchronizes.

Wallet B must already exist before preflight. Confirmation polling may be
bounded through `DOM_LIVE_E2E_CONFIRMATION_TIMEOUT_SECS` and
`DOM_LIVE_E2E_POLL_INTERVAL_SECS`.
