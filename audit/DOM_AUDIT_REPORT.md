# DOM Protocol Security Audit Report

## 1. Executive Summary

This audit reviewed the DOM Protocol pre-mainnet repository under the supplied DOM audit operating rules. The work was read-only against the local workspace; no local project files were edited. The requested report file is being added through GitHub only after explicit authorization to create `audit/DOM_AUDIT_REPORT.md`.

Overall recommendation: **Not ready for mainnet** until the confirmed dynamic/runtime findings below are reviewed and remediated, especially IBD lock handling and wallet behavior on mined reorgs.

The audit prioritized dynamic behavior, concurrency, IBD/reorg, mempool, Dandelion++, runtime arithmetic, hostile parsers, storage/recovery, wallet safety, and RPC/config exposure.

## 2. Scope Reviewed

Crates and areas reviewed:

- Consensus / chain: `crates/dom-consensus`, `crates/dom-chain`
- Cryptography: `crates/dom-crypto`
- PoW / ASERT: `crates/dom-pow`
- Node runtime / mining / relay / IBD / locks: `crates/dom-node`
- Wire / P2P: `crates/dom-wire`
- Mempool: `crates/dom-mempool`
- Storage: `crates/dom-store`
- Wallet: `crates/dom-wallet`
- RPC: `crates/dom-rpc`
- Test/fuzz/integration coverage: `crates/*/tests`, `crates/*/fuzz`, `crates/dom-integration-tests`

Mandatory knowledge base read:

- `audit/00_MASTER_INDEX`
- `audit/01_PROTOCOL_OVERVIEW.md`
- `audit/02_CONSENSUS_INVARIANTS.md`
- `audit/03_CRYPTOGRAPHIC_ASSUMPTIONS.md`
- `audit/04_THREAT_MODEL.md`
- `audit/05_ATTACK_SURFACES.md`
- `audit/06_AUDIT_CHECKLIST.md`
- `audit/07_FORBIDDEN_FILES.md`
- `audit/08_VALIDATION_COMMANDS.md`
- `audit/09_KNOWN_RISKS.md`
- `audit/10_REPORT_TEMPLATE.md`

Note: the master index exists as `audit/00_MASTER_INDEX` without `.md`.

## 3. Methodology

Methods used:

- Repository recon and crate/test/fuzz mapping.
- Threat-model-based review using the DOM audit KB.
- Static source review of runtime paths prioritized by the prompt.
- Lock acquisition and `.await` review in `dom-node`.
- Review of IBD, reorg, wallet apply/rollback, mining finalization, relay and Dandelion++ paths.
- Review of hostile parser bounds and trailing-byte rejection in `dom-wire` and `dom-serialization`.
- Review of storage atomicity/recovery paths in `dom-store` and `dom-chain`.
- High-risk searches:
  - `rg "unwrap\(|expect\(|panic!\(|todo!\(|unimplemented!\("`
  - `rg "bypass|skip|insecure|debug|test_only|allow_invalid|disable_validation"`
  - `rg "unsafe"`

Limitations:

- The execution environment was read-only, including `/tmp`.
- Cargo commands requiring target artifacts could not run.
- Network/localhost integration tests could not be executed in this sandbox.
- Findings below are based on source review and command attempts, not on newly executed dynamic tests.

## 4. Findings Summary

| ID | Severity | Area | Touches Consensus | Title | Status |
|----|----------|------|-------------------|-------|--------|
| DOM-AUDIT-001 | High | Node / IBD / Concurrency | No direct consensus rule change | IBD holds `chain` lock across async calls and can self-deadlock | Confirmed |
| DOM-AUDIT-002 | Medium | Wallet / Reorg / Miner | No | Mined reorg path skips wallet rollback/apply | Confirmed |
| DOM-AUDIT-003 | Medium | Mempool / DoS | No | Single eviction can leave mempool above weight limit | Confirmed |
| DOM-AUDIT-004 | Medium | RPC / DoS | No | Public `/mempool` pagination can overflow `page * limit` | Confirmed |
| DOM-AUDIT-005 | Medium | Wallet / RPC | No | Wallet spend rollback can fail when wallet is busy | Confirmed |
| DOM-AUDIT-006 | Low | RPC / Config | No | `/status` hardcodes `network: "mainnet"` | Confirmed |

Severity count:

- Critical: 0
- High: 1
- Medium: 4
- Low: 1
- Informational: 0

## 5. Detailed Findings

### DOM-AUDIT-001 - IBD Holds `chain` Lock Across Async Calls And Can Self-Deadlock

Severity: High  
Area: Node / IBD / Concurrency  
Touches consensus: No direct consensus rule change  
Status: Confirmed

#### Affected Files

- `crates/dom-node/src/node.rs:2437`
- `crates/dom-node/src/node.rs:2479`
- `crates/dom-node/src/node.rs:2481`
- `crates/dom-node/src/node.rs:2520`
- `crates/dom-node/src/node.rs:2142`
- `crates/dom-node/src/node.rs:2146`

#### Description

In `resume_ibd_block_sync`, the code enters a block that acquires `let mut c = chain.lock().await;`, calls `c.connect_block(...)`, and then, while still inside the same lexical scope, calls:

- `purge_mempool_confirmed_inputs(chain, &runtime.mempool, &txs_for_scan).await?`
- `wallet_arc.lock().await`

`purge_mempool_confirmed_inputs` then calls `persist_mempool_state(chain, mempool).await`, and `persist_mempool_state` itself performs `let chain = chain.lock().await;`.

Because Tokio mutexes are non-reentrant, this can self-deadlock: the same task still holds the `chain` guard and awaits a function that tries to acquire `chain` again.

This also violates the documented lock discipline in `crates/dom-node/src/lock_order.rs`, which requires avoiding chain lock retention across later async lock acquisition.

#### Impact

A peer participating in IBD/resume can trigger a liveness failure in the node's IBD task when a best-chain block with confirmed transaction inputs reaches this path. The node can stall sync progress and potentially remain behind the network.

This does not appear to allow invalid block acceptance, but it can deny service to sync and recovery.

#### Exploitability

Realistic during IBD/resume if the synced block contains non-coinbase transactions whose inputs require mempool purging. The exact dynamic reproduction should be added as a regression test once patching is authorized.

#### Evidence

Relevant flow:

- `node.rs:2437`: `let mut c = chain.lock().await;`
- `node.rs:2479`: calls `purge_mempool_confirmed_inputs(...).await?` before the chain guard scope ends.
- `node.rs:2146`: `persist_mempool_state` calls `chain.lock().await`.

#### Recommended Fix

Do not hold `chain` across any `.await` that may acquire `chain`, `mempool`, or `wallet`. Capture `connect_result`, `height`, and scan data while holding `chain`, then drop the guard before mempool reconciliation and wallet application.

#### Validation Required

- Add a targeted async regression test for resumed IBD with a non-coinbase transaction while the mempool contains the spent input.
- Run:
  - `cargo test -p dom-node`
  - `cargo test -p dom-integration-tests --test ibd`
  - `cargo test --workspace`

### DOM-AUDIT-002 - Mined Reorg Path Skips Wallet Rollback/Apply

Severity: Medium  
Area: Wallet / Reorg / Miner  
Touches consensus: No  
Status: Confirmed

#### Affected Files

- `crates/dom-node/src/miner.rs:304`
- `crates/dom-node/src/miner.rs:351`
- `crates/dom-node/src/node.rs:3398`

#### Description

`finalize_mined_block` handles `ConnectResult::Reorg(_)` by logging and continuing mempool reconciliation, but it explicitly skips wallet canonical apply:

`Skipping wallet canonical apply for mined reorg block ... rollback hooks remain explicit follow-up work`

The relay path does handle reorg wallet behavior by rolling back to `delta.common_ancestor_height` and applying connected blocks. The miner path diverges from the relay/IBD wallet behavior.

#### Impact

If a locally mined block causes a heavier known-tip reorg, the canonical chain state can change while the wallet continues to reflect the old branch. This can show wrong balances, stale pending state, or incorrect spendability until some later manual or recovery action.

#### Exploitability

Less common than normal relay reorgs, but plausible under mining/relay races or simultaneous block discovery. It is exactly the kind of dynamic concurrency case static consensus validation does not prove safe.

#### Evidence

- `crates/dom-node/src/miner.rs:304` handles `ConnectResult::Reorg(_)`.
- `crates/dom-node/src/miner.rs:351` logs that wallet apply is skipped.
- `crates/dom-node/src/node.rs:3398` shows the relay path does perform wallet rollback/apply for reorgs.

#### Recommended Fix

Mirror the relay path for `ConnectResult::Reorg(delta)` in `finalize_mined_block`: rollback wallet to the common ancestor and apply each connected block from `delta.connected_blocks`.

#### Validation Required

- Add miner-path reorg wallet regression coverage.
- Run:
  - `cargo test -p dom-node`
  - `cargo test -p dom-wallet`
  - `cargo test -p dom-integration-tests --test reorg`

### DOM-AUDIT-003 - Mempool Weight Cap Can Be Exceeded After Single Eviction

Severity: Medium  
Area: Mempool / DoS  
Touches consensus: No  
Status: Confirmed

#### Affected Files

- `crates/dom-mempool/src/lib.rs:257`
- `crates/dom-mempool/src/lib.rs:310`

#### Description

When inserting a new transaction, the mempool checks:

`if self.total_weight + entry.weight as u64 > self.max_weight { self.evict_lowest_fee(entry.fee_rate)?; }`

Only one transaction is evicted. If the incoming transaction is larger than the evicted transaction by enough weight, `total_weight` can remain above `max_weight` after insertion.

#### Impact

A peer/API client able to submit valid high-fee transactions can push memory use above the configured mempool policy. This is not consensus-critical, but it weakens DoS resistance.

#### Exploitability

Requires valid transactions and fees high enough to evict lower-fee entries. This makes it costed but still relevant for a peer-facing mempool.

#### Evidence

- `crates/dom-mempool/src/lib.rs:257`: single eviction trigger.
- `crates/dom-mempool/src/lib.rs:310`: `evict_lowest_fee` removes at most one entry.
- `crates/dom-mempool/src/lib.rs:266`: insertion proceeds without rechecking cap.

#### Recommended Fix

Evict in a loop until the new transaction fits, or reject when sufficient eviction is impossible. Recheck `total_weight + entry.weight <= max_weight` before insertion.

#### Validation Required

- Add adversarial mempool test where one large high-fee tx replaces multiple smaller low-fee txs.
- Run:
  - `cargo test -p dom-mempool`
  - `cargo test -p dom-test-vectors --test resource_exhaustion`

### DOM-AUDIT-004 - Public RPC Mempool Pagination Can Overflow

Severity: Medium  
Area: RPC / DoS  
Touches consensus: No  
Status: Confirmed

#### Affected Files

- `crates/dom-rpc/src/lib.rs:344`
- `crates/dom-rpc/src/lib.rs:356`

#### Description

The public `/mempool` endpoint computes:

`skip(page * limit)`

`page` is user-controlled query input and `limit` is clamped only after parsing. In debug/dev profiles, workspace `overflow-checks = true`; in release, integer overflow behavior can differ unless explicitly guarded. A very large `page` can panic or wrap depending build settings.

#### Impact

An unauthenticated HTTP request can cause denial of service or incorrect pagination behavior if RPC is exposed.

#### Exploitability

High if RPC is exposed to untrusted clients. The endpoint is public and does not require bearer auth.

#### Evidence

- `crates/dom-rpc/src/lib.rs:344`: public mempool handler.
- `crates/dom-rpc/src/lib.rs:356`: unchecked `page * limit`.

#### Recommended Fix

Use `page.checked_mul(limit)` and return a client error on overflow, or use explicit saturation with a documented maximum page.

#### Validation Required

- Add RPC unit test for `page=usize::MAX`.
- Run:
  - `cargo test -p dom-rpc`

### DOM-AUDIT-005 - Wallet Spend Rollback Can Fail When Wallet Is Busy

Severity: Medium  
Area: Wallet / RPC  
Touches consensus: No  
Status: Confirmed

#### Affected Files

- `crates/dom-node/src/node_handle.rs:14`
- `crates/dom-node/src/node_handle.rs:19`
- `crates/dom-node/src/node_handle.rs:253`
- `crates/dom-node/src/node_handle.rs:282`
- `crates/dom-node/src/node_handle.rs:291`

#### Description

`wallet_spend` builds a wallet transaction while holding the wallet lock, then releases it before mempool admission. If mempool or chain access fails, `rollback_failed_wallet_spend` attempts to cancel the pending wallet transaction using `wallet_arc.try_lock()`.

If the wallet is busy at that exact moment, rollback fails and the reservation may remain pending.

#### Impact

Funds can remain reserved even though the transaction was not accepted into the mempool. This can cause user-visible balance lockup and require later reconciliation or manual cancellation.

#### Exploitability

Requires concurrent wallet activity or lock contention while RPC spend admission fails due to mempool/chain busy. This is plausible under load or adversarial RPC timing.

#### Evidence

- `crates/dom-node/src/node_handle.rs:19`: rollback uses `try_lock`.
- `crates/dom-node/src/node_handle.rs:253`: wallet lock used for build and released.
- `crates/dom-node/src/node_handle.rs:282`: rollback on mempool busy.
- `crates/dom-node/src/node_handle.rs:291`: rollback on chain busy.

#### Recommended Fix

Make spend build, mempool admission, and rollback an atomic workflow from the wallet lifecycle perspective. If asynchronous waiting is not acceptable in the RPC handler, persist a mandatory rollback/reconcile marker rather than best-effort `try_lock`.

#### Validation Required

- Add test that forces wallet busy during rollback and verifies reservation recovery.
- Run:
  - `cargo test -p dom-node node_handle`
  - `cargo test -p dom-wallet`

### DOM-AUDIT-006 - RPC Status Hardcodes Mainnet

Severity: Low  
Area: RPC / Config  
Touches consensus: No  
Status: Confirmed

#### Affected Files

- `crates/dom-rpc/src/lib.rs:335`
- `crates/dom-rpc/src/lib.rs:340`

#### Description

`/status` returns `network: "mainnet"` unconditionally.

#### Impact

Operators and automation can misclassify testnet/regtest nodes as mainnet. This is especially risky in pre-mainnet deployments where confusion between networks is a known audit surface.

#### Exploitability

Low direct exploitability, but high operational confusion potential.

#### Evidence

- `crates/dom-rpc/src/lib.rs:340`: hardcoded network string.

#### Recommended Fix

Expose the actual network through `NodeHandle` and return it from the node configuration.

#### Validation Required

- Add RPC status tests for mainnet/testnet/regtest.
- Run:
  - `cargo test -p dom-rpc`
  - `cargo test -p dom-node`

## Confirmed Clean / No Finding Areas

- `dom-wire` message payload parsers reviewed showed explicit caps and trailing-byte rejection for major payloads.
- `dom-serialization::Reader` uses bounded `read_vec`, bounded `read_list`, checked position arithmetic, and `finish()` trailing-byte rejection.
- `dom-store::commit_block` writes header/body/height/tip/UTXO/kernel changes in one LMDB write transaction and maps `MapFull` distinctly.
- `dom-store::apply_reorg` performs touched state updates in one LMDB transaction.
- Wallet seed generation uses BIP-39 24-word generation for new wallets and `Zeroizing` wrappers for phrase/seed material.
- Wallet storage uses ChaCha20Poly1305, fresh salt/nonce, temp-file write, file fsync, atomic rename, and parent directory fsync on Unix.
- `cargo fmt --check` passed.

## Suspicious / Needs Dynamic Reproduction

- IBD loops ignore non-Headers messages while waiting for Headers. This is bounded by connection/idle behavior, but should be stress-tested for peer-driven long waits.
- Dandelion++ stem timeout promotion depends on the transaction still being in mempool; if mempool eviction removes it, the transaction is dropped from fluff promotion. This may be expected policy, but should be tested under flood/eviction.
- `dom-node/src/relay/dandelion.rs` appears to be an older standalone Dandelion router separate from `dom-wire/src/dandelion.rs`. No direct runtime use was confirmed in this pass, but duplicate implementations are a maintenance risk.

## 6. Consensus Impact Assessment

No code was changed during the audit. The confirmed findings do not directly weaken consensus validity rules such as block validation, PoW, range proof verification, kernel signature validation, supply/emission, or UTXO mutation.

However:

- DOM-AUDIT-001 affects IBD liveness and may prevent a node from reaching canonical chain state.
- DOM-AUDIT-002 affects wallet state during a valid reorg caused by local mining.

## 7. Cryptography Impact Assessment

No confirmed cryptographic bypass was found in this pass. The reviewed code paths continue to rely on real validation rather than stubs for commitments, range proofs, kernel signatures, hashing, and canonical serialization.

Residual risk remains because full dynamic tests and fuzz targets could not be run in this environment.

## 8. Mempool/Reorg/Double-Spend Assessment

Mempool admission uses chain-view validation and conflict detection. Same-block child spend policy appears represented in tests and comments.

Confirmed risks:

- Mempool weight cap can be exceeded after a single eviction.
- IBD lock handling can deadlock during mempool purge.
- Mined reorg path does not mirror relay/IBD wallet reorg behavior.

## 9. Wallet Safety Assessment

Wallet seed, encrypted storage, WAL-style journal, rollback, and canonical block apply paths were reviewed.

Confirmed risks:

- RPC spend rollback can fail if wallet is busy.
- Wallet state diverges on mined reorg path.

## 10. P2P/DoS Assessment

P2P parser caps and handshake timeouts are present. Orphan pool and future block queue are bounded.

Confirmed DoS risks:

- IBD self-deadlock.
- RPC pagination overflow.
- Mempool cap bypass by insufficient eviction.

## 11. Validation Evidence

Commands run successfully:

```bash
cargo fmt --check
git diff --check
git status --short
git diff --stat
git log --oneline -n 10
```

Results:

```text
cargo fmt --check: passed
git diff --check: passed
git status --short: empty before report authorization
git diff --stat: empty before report authorization
git log --oneline -n 10: succeeded
```

Commands attempted but blocked by read-only filesystem:

```bash
cargo build --workspace
CARGO_TARGET_DIR=/tmp/dom-target cargo build --workspace
CARGO_TARGET_DIR=/tmp/dom-target cargo test -p dom-pow
CARGO_TARGET_DIR=/tmp/dom-target cargo test -p dom-consensus
CARGO_TARGET_DIR=/tmp/dom-target cargo clippy --workspace --all-targets -- -D warnings
```

Failure summary:

```text
error: failed to open: /root/dom/target/debug/.cargo-build-lock
Caused by: Read-only file system (os error 30)

error: Read-only file system (os error 30) at path "/tmp/dom-target..."
```

This is environmental, not a protocol logic failure.

## 12. Files Changed

This report creation is the only authorized file change:

- `audit/DOM_AUDIT_REPORT.md` - audit report requested and explicitly authorized by the user.

No local workspace file was edited because the environment was read-only.

## 13. Forbidden File Compliance

No forbidden consensus, cryptographic, genesis, difficulty, wallet logic, mempool, P2P, chain, storage, or test file was modified.

The user explicitly authorized creating:

```text
audit/DOM_AUDIT_REPORT.md
```

## 14. Remaining Risks

Required follow-up outside read-only sandbox:

- Run full workspace validation.
- Run targeted IBD/reorg/miner/wallet integration tests.
- Add dynamic regression tests for DOM-AUDIT-001 through DOM-AUDIT-005 before patching.
- Run localhost integration tests outside sandbox because bind failures in sandbox are environmental.
- Run fuzz targets for `dom-wire`, `dom-serialization`, `dom-consensus`, and `dom-crypto` if available.

## 15. Final Recommendation

**Not ready for mainnet.**

The static consensus invariants appear intentionally hardened, but dynamic runtime issues remain in IBD/concurrency, wallet reorg handling, mempool resource limits, and public RPC DoS handling. These should be fixed and validated before any mainnet readiness claim.

Last local pre-report workspace proof:

```text
git status --short: <empty>
```
