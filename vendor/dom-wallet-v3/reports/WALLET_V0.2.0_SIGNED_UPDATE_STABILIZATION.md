# DOM Wallet V3 signed update stabilization

Status: **NOT READY**

Date: 2026-07-23

Branch: `stabilize/wallet-v0.2.0`

No tag, GitHub Release or installer publication was created during this update
stabilization work. Publication remains explicitly blocked pending owner
confirmation and completion of the node RPC identity contract.

## Implemented architecture

### Wallet updater

- Official Tauri v2 updater plugin fixed at `2.10.1`.
- HTTPS stable feed on GitHub Releases.
- Tauri Minisign artifact verification plus detached DOM metadata signature,
  SHA-256 and byte-length verification.
- SemVer, stable channel, draft/prerelease, expiry, network, schema, target,
  architecture, URL host and HTTPS/443 checks.
- Redirects stop outside the approved origin allowlist or after five hops.
- Startup check with bounded jitter, hourly Rust backend timer, resume check and
  manual check.
- Single-flight concurrency guard.
- Critical Slate safe-point before installation.
- Ordered application shutdown, persistence and restart path.
- Missing production public key fails closed and remains non-fatal to normal
  Wallet use.

### Node updater and manager

- Separate Wallet and node manifest decisions and state machines.
- Compatible node-only decision never changes the Wallet version.
- Incompatible RPC, P2P, storage, network, chain or genesis contract produces
  `WALLET_UPDATE_REQUIRED`.
- Versioned runtime directories, restricted Unix permissions, digest validation,
  traversal/symlink rejection, same-filesystem staging and atomic promotion.
- Active and previous revision metadata with monotonic sequence and temporary
  rejected-revision state.
- Node update success is impossible before the old PID exits, ports are
  released, the new PID differs, authenticated identity matches, health reaches
  READY, the canonical height-plus-hash cursor validates and peers are present.
- Failed startup, handshake or health performs rollback and mandatory restart of
  the previous identity.

The existing in-process node remains the functional bootstrap/recovery path.
Production sidecar activation is deliberately blocked by the RPC limitation
below; this report does not claim that the application already runs the managed
sidecar.

### Peer manifest updater

- Separate signed payload that cannot carry a command or binary.
- Mainnet, chain ID, genesis, time window and monotonic sequence validation.
- Public-routability filtering and stable `SocketAddr` deduplication.
- Priority order starts with `168.100.9.70:8443`, then
  `168.100.9.70:33369`.
- `168.100.8.144:33369` is retained as an independent compiled emergency relay.
- Authenticated crash-safe cache can be used offline; tampered identity is
  rejected.

Remote peer fetching and live injection into the running node are not activated
until the production public key and complete sidecar identity contract exist.
The UI therefore reports fallback/pending state instead of claiming a remote
manifest was applied.

## DOM Protocol evidence and blocker

Inspected branch: `sorenplanck/dom-protocol` `release/mainnet`

Inspected immutable commit:
`28ba3cefc9fbc913f126336482662528c68a7d8c`

Confirmed in source:

- Bearer-protected `/wallet/balance`, `/chain/scan` and `/build-info`;
- loopback-only Bearer-protected `POST /shutdown`;
- `202 Accepted` graceful shutdown through `DomNode::request_shutdown()`;
- ordered task-supervisor drain;
- RPC tests for authentication, build info and shutdown.

Current `/build-info` returns only:

```json
{"commit":"<build-commit>"}
```

That proves the running revision but not the complete identity required by the
node-only updater. It must additionally report node version, network, chain ID,
genesis hash, RPC protocol version, P2P protocol version and storage schema
version. Until then, `NodeRpcIdentityCapabilities::permits_node_only_update()`
returns false.

The Wallet's consensus and embedded-node crates are pinned to the immutable
published Mainnet revision
`28ba3cefc9fbc913f126336482662528c68a7d8c`. Direct ancestry checks prove that
this revision includes `065e484` (the Mainnet ASERT rescue at height 4849) and
`5fad708` (equal-height fork divergence recovery). The complete workspace,
embedded-node lifecycle tests and wallet integration tests pass against this
exact revision. The embedded path uses `EmbeddedWalletCoreApi` directly and
does not call the newly Bearer-protected HTTP wallet endpoints.

## Commits and push

- `dfc34f2` `fix(network): add alternate Mainnet bootstrap endpoint on 8443`
- `bd79752` `fix(windows): hide release console window`
- `37ec731` `feat(updater): add signed update policy core`
- `2de85ce` `feat(node-manager): add atomic promotion and rollback`
- `9b0c972` `fix(network): retain independent Mainnet relay fallback`
- `8abe063` `feat(updater): add signed hourly Wallet update checks`
- `bb2f394` `feat(ui): expose separate signed update channels`
- `e450f45` `feat(network): cache signed Mainnet peer manifests`
- `394d82f` `ci(release): gate signed update feed publication`
- `0da7bb0` `docs(updater): document signing and recovery procedure`
- `c9291ea` `docs(stabilization): record signed updater evidence`
- `4d851ea` `fix(updater): keep unsigned packages fail-closed and runnable`

Every listed commit was pushed to
`origin/stabilize/wallet-v0.2.0` after focused validation.

## Principal files changed

- `crates/dom-wallet-updater/{Cargo.toml,src/lib.rs}`: signed feed policy,
  scheduling, state machines, managed node runtime, promotion and rollback.
- `crates/dom-wallet-embedded-core/src/lib.rs`: prioritized Mainnet bootstrap,
  fallback, deduplication and connection-state logging.
- `src-tauri/{Cargo.toml,tauri.conf.json,src/lib.rs,src/main.rs}`: official
  updater integration, commands, lifecycle scheduling and Windows GUI
  subsystem.
- `frontend/{index.html,main.js}`: separate Wallet, node and peer update state.
- `frontend/tests/{status.test.mjs,release-workflow.test.mjs}`: UI and protected
  release-workflow contracts.
- `.github/workflows/release-wallet.yml`: non-publishing stabilization gate and
  protected future signed publication.
- `docs/AUTOMATIC_UPDATES.md` and
  `docs/dom-protocol-node-release.yml.example`: trust, recovery and independent
  node-release procedure.

## Reproduced defects, root causes and corrections

- Networks that reject TCP `33369` could exhaust the only direct relay before
  reaching a usable endpoint. The compiled Mainnet order now prioritizes
  `168.100.9.70:8443`, retains `168.100.9.70:33369` and the independent relay,
  logs each transition, deduplicates by `SocketAddr` and remains in discovery
  while an endpoint is still untried.
- Release Windows builds opened a console because the Rust entry point did not
  select the Windows GUI subsystem. The release-only
  `windows_subsystem = "windows"` attribute removes that CMD window without
  hiding the console in debug builds.
- A single application update channel could not safely express peer-only,
  compatible node-only and coordinated Wallet changes. The implementation now
  has three independent signed decisions and two unambiguous binary update state
  machines.
- The official updater plugin required a `pubkey` member while deserializing its
  Tauri configuration, before the protected build-time key override runs.
  Omitting the member let packaging succeed but made the installed application
  exit before opening a window. Stabilization config now supplies a parseable
  empty value; production still overrides it from `DOM_UPDATE_PUBLIC_KEY`, and
  an empty value cannot check or install an update.
- The installed smoke waited for a live peer before persisting the absent
  genesis cursor, allowing IBD lock contention to race the height-zero gate. It
  now proves canonical height-plus-hash at genesis first, then connects and
  reconciles peers. Only explicitly retryable responses are retried and the
  bounded test still requires synchronized state.
- Replacing a running node executable could leave the old process active or
  claim success before compatibility was proven. The managed runtime contract
  requires old-PID exit, port release, atomic promotion, a different PID,
  authenticated identity, READY, cursor and peer checks before success; failure
  rolls back to the previous identity.
- The inspected DOM Protocol `/build-info` proves only its commit. This is an
  upstream contract gap, not bypassed locally: production node-only activation
  remains fail-closed until the complete identity is available.

## Tests and commands

Passed:

- Full locked workspace gate:
  `cargo fmt --all --check`,
  `cargo check --workspace --all-targets --locked`,
  `cargo clippy --workspace --all-targets --locked -- -D warnings` and
  `cargo test --workspace --all-targets --locked -- --test-threads=1`.
  - 278 passed, 0 failed and 2 explicitly ignored live-network gates.
- `cargo test -p dom-wallet-updater --locked -- --test-threads=1`
  - 21 passed, 0 failed.
- `cargo test -p dom-wallet-tauri-shell --locked -- --test-threads=1`
  - 11 passed, 0 failed, 1 ignored live gate.
- `cargo test -p dom-wallet-embedded-core --locked bootstrap -- --test-threads=1`
  - 4 passed, 0 failed.
- Clippy with `-D warnings` for updater, Tauri shell and embedded core.
- `cargo fmt --all --check`.
- Frontend test suite: 20 passed, 0 failed.
- Frontend typecheck and production build.
- Extracted-package Linux WebDriver smoke passed after the updater configuration
  repair:
  - native bridge `READY`;
  - invalid onboarding actions reached native Rust and were rejected;
  - Wallet create, recovery confirmation and unlock succeeded;
  - one Mainnet peer connected;
  - canonical height and cursor were both `0`, with equal hashes;
  - application and mining state were `READY`, with no worker running.
- `cargo audit` completed without a blocking vulnerability. It reported 15
  allowed warnings from transitive GTK3/GLib and legacy macro/Unicode crates;
  these remain tracked dependency risks rather than hidden failures.
- `cargo deny check` passed: advisories, bans, licenses and sources all `ok`
  under the repository policy.
- Pinned `actionlint 1.7.7` with verified archive checksum.
- Local package command:
  `cargo tauri build --bundles deb -- --locked`.
- Current-tree Debian package:
  `target/release/bundle/deb/DOM Wallet V3_0.2.0_amd64.deb`.
  - size: 9,271,478 bytes;
  - SHA-256:
    `e0d750b9ecf710a2f588881cfbfc4059d45630b5ee7a9ccd9bd7ba9817503d36`;
  - metadata: package `dom-wallet-v3`, version `0.2.0`, architecture `amd64`.
  - no `.sig` was generated, as required for a non-publishing stabilization
    build.

Deterministic updater coverage includes newer/equal/older/invalid SemVer,
expiry, signatures, hash, size, origin, platform, architecture, channel,
node compatibility, monotonic sequence, critical Slate deferral, stop/restart,
PID change, handshake mismatch, READY/cursor/peer gates, automatic rollback,
runtime traversal, staging, atomic promotion, peer routability, deduplication,
authenticated offline cache, hourly/resume scheduling and concurrent checks.

## Build and signing configuration

The public key is intentionally not fabricated. Production builds require the
non-secret protected variable:

- `DOM_UPDATE_PUBLIC_KEY`

The protected release environment requires:

- `TAURI_SIGNING_PRIVATE_KEY`
- `TAURI_SIGNING_PRIVATE_KEY_PASSWORD`
- `SIGNED_UPDATER_RELEASES_ENABLED=true` only after explicit authorization.

Local/stabilization packaging has `createUpdaterArtifacts=false`; it does not
need signing secrets and cannot publish a live update. Authorized tag packaging
overrides it to true and fails if signing inputs or `.sig` artifacts are absent.
The release publish job also requires the protected production environment and
explicit enablement.

## Data-preservation evidence

Updater state contains no Wallet secret. The node runtime lives outside the
Wallet and chain directories. Node promotion only renames a verified staging
directory and changes authenticated runtime metadata. The tested lifecycle
requires Wallet journal/cursor persistence before node stop and validates the
same canonical cursor after restart. Failure returns to the previous node
identity. Full Wallet installation targets application files, not Wallet,
chain, cursor, history or configuration data, and the Wallet returns locked
after process restart.

## Gate status

| Gate | Status |
|---|---|
| Startup/hourly/resume/manual scheduling | PASS |
| Signed newer stable Wallet policy | PASS |
| Official Tauri artifact signature verification | PASS (code/tests) |
| Hash, size, origin and redirect policy | PASS |
| Safe-point and ordered Wallet shutdown | PASS (deterministic) |
| Separate Wallet/node/peer states in UI | PASS |
| Versioned node runtime and atomic promotion | PASS (filesystem tests) |
| Mandatory new PID after node replacement | PASS (backend contract test) |
| Handshake/READY/cursor/peers before success | PASS (backend contract test) |
| Automatic previous-node rollback | PASS (backend contract test) |
| Authenticated peer cache and compiled fallback | PASS |
| Production signing public key configured | BLOCKED |
| Remote peer feed applied to a live node | BLOCKED |
| Complete RPC identity from actual sidecar | FAIL — `/build-info` is partial |
| Real node-only N to N+1 process E2E | BLOCKED |
| Real rollback N+2 to N+1 process E2E | BLOCKED |
| Real signed full Wallet update/restart E2E | BLOCKED |
| Cross-platform signed update installation | BLOCKED |
| Current Linux `.deb` build without publication | PASS |
| New tag or release during stabilization | PASS — none created |

## Residual risks

1. Activating node-only update with the current partial `/build-info` would
   weaken the required compatibility proof, so it remains disabled.
2. A production Minisign public key has not been supplied.
3. Remote peer feed download/live injection is not complete.
4. The release workflow still requires end-to-end manifest generation and
   atomic draft-to-public evidence before production enablement.
5. Actual sidecar process E2E and cross-platform signed installer restart have
   not been demonstrated.

## Final classification

**NOT READY**

The implemented policy, state machines, UI, crash-safe runtime primitives,
fallback networking and future release gates are validated. The Wallet must not
be published until the owner confirms the complete DOM Protocol RPC identity,
the Wallet pins and tests that immutable revision, production signing material
is configured, and real node-only/rollback/full-update E2E passes.
