# G0 Common-Wallet Regtest Decision

Status: implemented and reproducible in the F7 laboratory  
Wallet baseline: `1868e61bc39eca223d794348d70e48668ad06708`
(`wallet-v0.3.2`)  
Pinned DOM protocol laboratory checkpoint: `6a295fddf4e6a3afd6cf0f3fdb1e3a636a2f3d71`
(`feat/dom-contracts`)

## Problem

The wallet had individually tested production adapters, but no permanent test
proved the Master specification section 15.7 sequence over two real DOM nodes:
ordinary coin selection and change, current public Slate exchange, independent
final-byte verification by both participants, mempool-before-mine, canonical
confirmation, scanner ownership recovery, full restart/rescan, and a recipient
spend. The production send path also always emitted a PLAIN kernel even though
the pinned DOM protocol already provided the canonical satisfied
`HEIGHT_LOCKED` cover policy required by sections 15.8 and 16.2.

Running the complete sequence exposed four additional integration gaps:

1. an explicit non-mainnet seed populated Core's seed list while
   `min_outbound = 0` prevented the connector from ever dialing it;
2. live wallet operations and one incremental scan path used the backend's
   startup tip instead of the current validated identity;
3. only the sender retained and verified finalized transaction bytes, so the
   recipient could not satisfy the bilateral pre-broadcast verification rule;
4. the scanner rejected an exact locally created pending change/receive output
   when the same commitment first appeared on chain, because canonical
   recovery metadata did not exist yet.

## Context and authority

The implementation follows the normative G0 and G-COVER requirements in
`DOM-Scriptless-Contracts-Master-v1.0`, sections 15.7, 15.8, and 16.2. It uses
the currently documented manual production flow from
`docs/MANUAL_SLATE_EXCHANGE.md`: sender request export, recipient import and
response, sender response import and finalization. The test substitutes those
real API names for the illustrative names in the Master skeleton.

The DOM revision is pinned because it is the repository revision that supplies
the canonical `CoverLockPolicyV1`, `ValidatedChainSnapshotV1`, existing Slate
`lock_height` field, HEIGHT_LOCKED transaction builder/verifier behavior, real
node mempool, scanner, and canonical node miner. No cryptographic primitive,
consensus rule, wire field, transaction encoding, or proof implementation is
copied into the wallet.

## Decision

1. Preserve `transaction_send_create` as the byte-compatible PLAIN ordinary
   send API. Add `transaction_send_create_with_cover` as the explicit R0 entry
   point. It evaluates the canonical policy with `OsRng` before Slate bytes or
   signatures exist and reports `HeightLocked`, rollout non-selection, or the
   genesis-only PLAIN fallback explicitly.
2. Extend the recovery-capable sender builder with a lock-height parameter.
   The builder still calls DOM's canonical `build_send_recoverable`; it sets the
   already canonical public Slate `lock_height` before serialization or any
   participant signature. DOM's responder/finalizer then chooses and signs the
   canonical PLAIN or HEIGHT_LOCKED kernel.
3. Refresh the backend chain identity at every height-sensitive operation.
   Wallet/network/genesis matching remains exact; Mainnet additionally retains
   the frozen Mainnet identity check. Testnet and regtest are permitted only
   when their attached backend identity matches exactly.
4. Add public-only finalized-byte export and recipient verify/import methods.
   Verification requires canonical decode/re-encode equality, exact inputs,
   outputs, order, offset, fee, lock, aggregate excess and recovery capsules
   from the recipient's persisted response, followed by DOM's normal consensus
   transaction verifier. A second import is idempotent only for identical
   bytes; substitution fails closed.
5. When canonical recovery finds an existing output without recovery metadata,
   adopt it only if it is `PendingIncoming` and commitment, value, account,
   stored blinding and lack of reservation all match exactly. The scanner then
   adds the chain height/hash/position metadata and confirmed state. Any other
   collision remains `ConflictingOutput`.
6. Configure non-mainnet `min_outbound` to the deduplicated explicit seed
   count. A seedless private regtest remains isolated with zero outbound peers.
7. Keep funding coinbase construction separate from ordinary transactions.
   The wallet miner provisions Alice only. Every tested transfer enters the
   real mempool and is selected by `dom_node::miner::mine_one_block`; no miner
   transaction builder creates or inserts an ordinary transaction.

## Alternatives considered

- A synthetic chain source, mock node, direct database output insertion, or
  direct block transaction construction was rejected because each would make
  G0 non-authoritative.
- Reimplementing the HEIGHT_LOCKED builder or signing transcript in the wallet
  was rejected because DOM already owns those consensus and cryptographic
  rules.
- Mutating finalized bytes after signing was rejected because it would violate
  canonical encoding and participant signature binding.
- Treating every existing commitment as canonical was rejected because it
  could convert corrupt or substituted local state into spendable ownership.
- Mapping scanner persistence failures to a generic error was retained at the
  adapter boundary, but `WalletService` now preserves the concrete redacted
  recovery error when the failing sink owns it, making fail-closed diagnosis
  reproducible without exposing secrets.

## Invariants

- No seed, mnemonic, password, blinding, nonce, private share, or credential
  crosses the public final-transaction exchange or test evidence output.
- Both participants verify the same byte-identical canonical transaction
  before submission.
- A cover lock is nonzero and no greater than the current validated canonical
  height. The wallet never silently chooses a future cover height.
- PLAIN and HEIGHT_LOCKED transfers share coin selection, change, fee,
  Recovery Capsule, Slate, verifier, submission, scanner, and confirmation
  paths.
- Mainnet identity validation is not weakened.
- A pending local output becomes confirmed only through authenticated capsule
  recovery plus exact private/public binding and canonical chain evidence.
- Seedless regtest never gains an implicit public peer; explicit seeds activate
  only their requested outbound connector slots.

## Compatibility and security impact

Ordinary callers continue to use PLAIN transactions without an API or encoding
change. HEIGHT_LOCKED uses an existing active DOM kernel feature and canonical
serialization; it adds no Scriptless marker, session identifier, memo, tag,
endpoint, or fee class. Wallet state schema and transaction wire formats are
unchanged. The new recipient record contains only public finalized chain bytes
inside the already encrypted wallet generation.

The laboratory implements R0 mechanics, not G-COVER Mainnet completion. R1-R4
rollout telemetry, a stable default-on release, 90 consecutive days, 1,000
ordinary confirmed kernels, health thresholds, and the held-out classifier are
external release evidence and remain mandatory before R5/Mainnet Scriptless
funding. This limitation does not weaken or bypass the gate.

## Evidence and tests

`crates/dom-wallet-core/tests/g0_regtest.rs` creates disposable datadirs and
executes:

1. two independent embedded DOM regtest nodes and wallets;
2. wallet-owned recovery coinbase funding and real maturity;
3. Alice-to-Bob PLAIN Slate exchange and bilateral exact-byte verification;
4. observation in both real mempools before canonical block inclusion;
5. normal scanner balances and exact sender change accounting;
6. shutdown/restart of both nodes and wallets plus genesis rescans with equal
   balances and transaction state;
7. Bob spending the recovered recipient output back to Alice;
8. an ordinary satisfied HEIGHT_LOCKED transfer through the same APIs and its
   inclusion in the next block without artificial delay.

The test emits a bounded `G0_PUBLIC_EVIDENCE` section containing only commits,
chain ID, test-binary SHA-256, public transaction bytes/IDs, inclusion heights,
fees and public results. Disposable wallet and node directories are removed by
the test. Capture complete evidence with:

```sh
mkdir -p reports/G0
CARGO_BUILD_JOBS=2 cargo test -p dom-wallet-core --test g0_regtest -- --nocapture \
  2>&1 | tee reports/G0/g0-regtest.log
sha256sum reports/G0/g0-regtest.log
```

Focused checks for the pending-output fail-closed behavior and explicit peer
activation are part of the relevant crate test suites. The complete local
verification sequence is:

```sh
cargo fmt --all -- --check
CARGO_BUILD_JOBS=2 cargo test -p dom-wallet-core-recovery
CARGO_BUILD_JOBS=2 cargo test -p dom-wallet-core-restore
CARGO_BUILD_JOBS=2 cargo test -p dom-wallet-embedded-core explicit_local_peers_remain_available_for_regtest
CARGO_BUILD_JOBS=2 cargo test -p dom-wallet-core --test g0_regtest -- --nocapture
CARGO_BUILD_JOBS=2 cargo clippy -p dom-wallet-core-recovery -p dom-wallet-core-restore \
  -p dom-wallet-embedded-core -p dom-wallet-core --tests -- -D warnings
```
