# dom-interopd — operations runbook

Written for the Stage 13 requirement-by-requirement audit. Every claim below
names the code that enforces it; nothing here is aspiration. The daemon is
fail-closed by construction: when a section says "the daemon refuses", that
refusal is the specified behaviour, printed and exit-coded, not an error to
work around.

## 1. What the operator runs

```text
dom-interopd self-check [--json]     # environment and artifact self-check
dom-interopd run --state-dir PATH [--create]
```

`run` refuses a debug-profile or otherwise incomplete artifact before parsing
anything (`require_operational_artifact_v1`, `main.rs`). Merely selecting the
`production` Cargo feature does not make an artifact operational.

### Secrets — one pass on standard input, never on the command line

The V3 secret stream is read once from stdin, in this exact order
(`PRODUCTION_USAGE_V1`, `main.rs`):

```text
DOM-INTEROPD-SECRETS-V3
<bearer token>
<upstream Relay signing secret: 64 lowercase hex>
<downstream Relay signing secret: 64 lowercase hex>
<Contracts identity passphrase>
<DOM wallet passphrase>
<Bitcoin participant secret: 64 lowercase hex>
<route-secret seal key: 64 lowercase hex>
<refund-arming credential: 64 lowercase hex>
<local EVM signing secret: 64 lowercase hex>
upstream_f6_hsm_credentials=<count, then that many 64-hex lines>
downstream_f6_hsm_credentials=<count, then that many 64-hex lines>
```

No secret is ever a flag, an environment variable or a file path; nothing
echoes them (I6 guard: every `eprintln!` in the binary is inventoried).

### Known limits are printed at startup

Before driving a route, `run` prints one `known limit:` line per entry of
`PRODUCTION_KNOWN_LIMITS_V1` (`production_run.rs:311`). Today that names the
Bitcoin claim-materialization refusal, the EVM reextraction refusal, the
Solana and Monero route-shape refusals and the extended chain-services
refusal. An operator reading the startup output knows exactly which paths
refuse by policy.

## 2. State directory — the unit of operation, backup and restore

The state directory is a capability: the daemon opens it exactly once per
stage of the ordered provisioning journal. Fixed names, all pinned in
`production_config.rs`:

```text
bootstrap-create-v1.conf … bootstrap-create-v10.conf   (config family)
bootstrap-reopen-v1.conf … bootstrap-reopen-v10.conf
node.v1                          production-relay-network.v1
inputs/registry.sqlite3          state/route.sqlite3
refund-arming.v1.sqlite3
solana-actuator.v1.sqlite3       (created only by a route whose admitted
xmr-actuator.v1.sqlite3           shape carries that leg)
```

Wallet stores pin their parent directory to owner-only `0700` at creation and
the envelope audit refuses any other mode (`audit_parent_authority`,
dom-wallet; commit 1a35bab). SQLite stores validate their sidecar journals on
open (`validate_sqlite_sidecar`, `production_refund_arming.rs`), refusing a
foreign or displaced journal.

### Backup

Back up the state directory as a whole, cold (daemon stopped): every store is
a file under it, and the config digests bind them together. The Contracts
Store additionally has an authenticated canonical backup format
(`dom-scriptless-store/src/canonical/backup.rs`) whose restore path
(`canonical/restore.rs`) verifies an authenticated restore-transaction
manifest — a tampered or truncated backup refuses instead of half-loading.
The wallet has its own sealed backup (`dom-wallet/src/backup.rs`, exercised
by `shield_backup_fix005.rs`; V2 chain-id binding by
`shield_backup_chain_id_fix026.rs`).

### Restore and restart semantics

Reopen is the restore path: `run` without `--create` reopens every store from
its exact journaled prefix or refuses (`prepare_open_resumed_production`,
session store). The crash matrix is executed, not assumed
(`dom-interopd/tests/simulation.rs` + store/vault/solver crash suites):

- crash after broadcast → reopen reconciles the SAME transaction once —
  economically idempotent, no duplicate effect
  (`claim_cli_is_terminal_and_reopen_is_economically_idempotent`);
- crash after a timer-event commit → redelivery is detected as duplicate and
  the route refunds;
- store mid-write SIGKILL → `dom-store` crash-consistency suites;
- relay database loss → `f6-engine` relay-loss suite + the route-transport
  recovery path (`authenticate_recovery`/`reconstruct`).

Operator rule: never edit a store file. If a store refuses to open, that is
the tamper/corruption detector working; restore the cold backup.

## 3. Credential and key rotation

Rotation is epoch-based provisioning, not in-place mutation:

- **Refund-arming authority**: `refund_arming_authority_epoch` (config V9,
  `production_config.rs:1227`) identifies the provisioned refund authority
  configuration; a new credential is a new epoch through the create path.
- **Registry rollback floor**: `registry_minimum_epoch` must be non-zero
  (`production_config.rs:677`) and the registry refuses any document below
  it — a rolled-back registry is refused, not silently accepted.
- **F6 HSM credentials**: the V3 secret stream carries explicit
  upstream/downstream credential lists with counts; rotation is a new stream
  on the next start. No credential persists outside its sealed store.
- **Route leases**: `lease_duration_ms` / `renew_before_ms` /
  `dispatch_lease_ms` are validated together (`production_config.rs:740-752`);
  degenerate combinations refuse at config load.

## 4. Upgrades and rollback — fail-closed

- The config family match in `production_config.rs` has **no wildcard arm**:
  a V(n+1) document cannot be written with a V(n) header, and an unknown
  family refuses at load.
- `Cargo.lock` digest is verified unchanged by `ci_local.sh` around the
  production gates; the release surface is pinned by
  `check-release-surface.sh` and `check-relay-fault-surface.sh`.
- Durable rollback floors: the authenticated composition anchor carries a
  rollback floor (`production_relay_stage12.rs:178`); the supervisor treats
  clock zero/rollback as refusal (`supervisor.rs:43`); the registry epoch
  floor is §3. Rolling back to an older store or registry **refuses**.

## 5. Limits and DoS posture

Every externally-fed surface is bounded by named constants, closed at compile
time: `MAX_ROUTE_TRANSPORT_PAYLOAD_BYTES` (= the Relay's own
`MAX_PAYLOAD_BYTES`), `MAX_FRAMED_DSC1_BYTES_V2`,
`MAX_ROUTE_FRAME_CHUNK_BYTES_V2`, `MAX_ROUTE_FRAME_COUNT` (route-transport);
`MAX_PROOF_BYTES = 256 KiB` (xmr-dleq-sigma); the EVM observer's hostile-RPC
paging fix (adversarial audit A-08); fuzzing evidence on the two Bitcoin
parsers (41.9M + 1.02M executions, zero findings, Stage 11). The relay
refuses unregistered message kinds for every role (D-019/D-029 closed
registry).

## 6. Observability, metrics and alerting

The daemon deliberately exposes **no network metrics endpoint**: a metrics
listener on a custody daemon is attack surface, and nothing here may bind a
port that the route does not require. Observability is:

1. **stderr** — startup known-limits, refusals, and terminal errors; under
   systemd this is journald, and alerting is a journal match on
   `known limit:`, `refus`, or a non-zero exit.
2. **exit code** — the process is its own health check: `SUCCESS` only on a
   terminal route outcome; any refusal is `FAILURE` with the reason printed.
3. **durable journals** — the ordered provisioning journal and the per-store
   SQLite journals are the auditable record; `self-check --json` gives a
   machine-readable environment report.

A future metrics surface, if ever wanted, is an operator decision that must
be ratified; it is not assumed here.

## 7. What this runbook deliberately does not cover

Sepolia execution (operator credentials + explicit order;
`docs/SEPOLIA-RUNBOOK.md` and the f3/f4 workflows), Signet (cancelled by
operator decision — the BTC leg validates on regtest only), and the
Solana/Monero route shapes (refused at counterparty selection until their
composition chain exists; the refusal is printed at startup, §1).
