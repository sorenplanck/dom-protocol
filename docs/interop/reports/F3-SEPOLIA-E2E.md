# F3 Ethereum-Sepolia E2E — Execution Evidence

```text
Date:        2026-08-11 (run 2026-08-11T13:26:40Z .. 15:17:42Z UTC, 111m02s)
Driver:      scripts/sepolia.sh -> scripts/sepolia_deploy.sh, scripts/sepolia_e2e.sh
Network:     Ethereum Sepolia, chain id 11155111 (public)
Account:     0xD797af65Db28d51E43760Ae7a4B168bA8cc2Bd0f
Tooling:     forge 1.7.1, cast 1.7.1, rustc 1.96.1,
             OpenZeppelin v5.1.0, forge-std v1.9.6, Python 3.12.3
Endpoint:    a public Sepolia JSON-RPC endpoint serving the `finalized` tag
             (no provider credential is recorded anywhere in this evidence)
Scope:       the EVM leg of G-F3, executed against a public network. This
             report DECLARES NO GATE PASS. Adjudication is the operator's,
             per CLAUDE.md §4.
```

## What the gate asks for

Foundation Document v0.14, §"F3 — EVM leg (first real counterparty)":

> Gate G-F3: first real DOM(dom-sim)↔EVM E2E on testnet, BOTH directions,
> with `t` extracted from a real on-chain `Claimed` and refund via a real
> deadline; report with tx hashes.

Every clause of that sentence is addressed below. One thing in this report
is NOT from that sentence — the ERC-20 leg — and it is marked as such
wherever it appears.

## Code identity of the run

The run executed `HEAD` plus two uncommitted script modifications. Recording
this precisely matters more than presenting a tidy commit: the evidence must
name the bytes that ran.

```text
HEAD at run time     a80021f93c6e834ceee83d76aa57b2ef5035c994
scripts/sepolia.sh       blob d120cb2e87f8b90c198cff5480e9f86a37dc23be
scripts/sepolia_e2e.sh   blob e5578f44951bc8b4b9d97669b412ca18651370ed
```

Those two blobs were committed, unchanged, as `7b6d4b0` — the commit that
was EXECUTED on chain. This report is a later, separate commit that
incorporates the evidence, so the two are never conflated. `git rev-parse
7b6d4b0:scripts/sepolia.sh` reproduces the blob hash above, which is what
ties this evidence to the source.

## Contracts

Deployed from this tree; the recorded addresses in the candidate-reuse list
supplied to the executor (`0x961D…f3E5`, `0x95Aa…8C7a`) carry **no code on
Sepolia** — `eth_getCode` returns `0x` for both — so reuse was refused and a
clean deployment was made.

```text
ConditionLockV2       0x27bbff9ad075ca82946e61c86c7b83be102caa33
  runtime codehash    0x33c4df043837e30e9e0ff5a71db933849fad94b22c0885734d7f940db8ed5737
  deploy tx           0x09a035cf6590b00de8e5b19c59ccb6da544a12b3a4ee8d7cf5bc33a9404f7cc1

ConditionLockERC20V2  0x6c6c1319979ebcdab9a11c0e569f840a6db3cfbf
  runtime codehash    0x1f1a01cfccb4dab95e9dbb7054a653d6a6c9968f05fdfc0558e8d357909d796e
  deploy tx           0xa8989ffcb1c3cb2b276287efe2a07e3022b9f9acf8ef3f07dd628e01f4d3c722

both in block         11466024
  block hash          0xd0e0dedf3838b629934fdbc287326a8f7e2a4e2a31ead1499619e2a76d32b804
  canonical           yes
  finality observed   #11466048 0xd89edf6e02de5619ba0a1050aceb935f0d65516e34741de055f4b595a4f79715
```

Both runtime codehashes equal the codehashes this tree builds. That equality
is checked before any flow runs, and re-checked independently after the run
(see "Independent revalidation").

## The five settlement flows

Amount locked per flow: 1 wei (1 token unit on the ERC-20 leg). The funder is
also the beneficiary, so the locked value returns and gas is the entire cost.

### `dom_to_evm` — direction 0, settled by claim

```text
lockId    0x03768ba83d589a6cb97ca5261c6a5e6d1a44bd1ecda6b3f3e2560341eafc5085
binding   0x97b60c5868a078a9bde224b4297dbb407e00f818b971f10f9a7466239bb16c5e
open      0x99f0345f8d26082befa464f5e569221d3a32cdfc6a4c09fc9a8e346547a7e000  block 11466491
          block hash 0xc68cf41f98edf61db77606430a14ac3f599f2a71a399d8dc70dc89b3674a97aa
claim     0x5b2c7875ca749e848fa32d4a22ecb4670b8e85dd3cef5377940f8e6792d27b06  block 11466493
          block hash 0x68d63f1fd940b19026cf26b6db0e41bf87c80b6b5cb02a564eb5ee31f332399e
```

### `evm_to_dom` — direction 1, settled by claim

```text
lockId    0xd401110d6cfce562a9571712ba3a70a9652eb90fab0108a56fddce6a758ee22e
binding   0xe037f889068d30182ea17db716ef7c4d084b3683bed102a9b2adbeb79562ea7e
open      0x44f4624a4ac6809f940bd8ceedefcdbdd6189d980adb80b9d0c2082f03f7f5df  block 11466494
          block hash 0x5db5325d6674599b5cccb902773ed2243cec64c2c3d1472a4e110423856d8feb
claim     0x70d3c39a4fa6080e255bd87e9e27e3830688ea1d3d68081909ac66165dc2a2e9  block 11466496
          block hash 0x0222d6a2c3835a5f505231ffcde9494f1f85b236e621511ee2348e5e3ebfb066
```

**Both directions, and why the pair proves it.** On the EVM leg the two
directions are the same three calls; what differs is `LockTerms.direction`,
which is bound into `binding` and therefore into `lockId`. The two flows
above carry different `binding` and different `lockId` values for otherwise
identical terms. That difference is the proof that the direction really was
carried into the on-chain commitment, rather than being a label in a report.

### `refund` — opened, real deadline waited out, refunded

```text
lockId    0x12d68c2db723fd365fcbc133d311399eb36af87d444acce04a3a6aec2d6d5eeb
deadline  1786455324 (UNIX, TimelockDomain::Timestamp)
open      0xb258be45010762302ee810cec2285de2379c62ead5ce9db57263ce5e5f79cc0f  block 11466497
refund    0x628cc9599519be8d72060e02e173db561b07aca7741574ffd38a99120705b86a  block 11466516
```

Nineteen blocks separate the open from the refund — roughly four minutes of
the chain's own clock. No clock was moved: `evm_increaseTime` does not exist
on a public network, and the run paid the wait. This is also why the harness
test `anvil_refund_by_deadline` is deliberately absent from the harness phase
below: it drives `evm_increaseTime`, and the refund is covered here instead.

### ERC-20 leg — `erc20_dom_to_evm` and `erc20_refund`

> **PROVENANCE.** The v0.14 gate text quoted above does not mention the
> ERC-20 variant. These two flows exist because the operator instructed and
> ratified their inclusion on 2026-08-11. They are an ADDITION to the gate's
> published criterion, not a derivation from it. G-F3 as written is settled
> by the three flows above; what follows is extra coverage.

Token fixture, deployed by the settlement phase (not by `script/Deploy.s.sol`,
which deploys only the two contracts the codehash check binds to this tree):

```text
MockERC20 (test/mocks/HostileTokens.sol:MockERC20)
  address           0x9412Eb267d2C361Eee10d8ec3Ac8D2355223bA7E
  runtime codehash  0x51134382a208031d3f693689722e9a4418015d8db323080f3c37594f42755dfa
  deploy            0x6a6e69a64eb78256571a2bb621e930a8fa4b63ecfc6f0fc30ab7e467e2ac877a  block 11466518
  mint              0xf95895d2f0a84575e42d00bc0fbe4eaafbbe8cad86233749d328969fbfe8b14e  block 11466519
```

The plain, well-behaved baseline was used deliberately: this run is evidence
that the settlement works against a token that behaves. Misbehaviour is the
adversarial Foundry suite's job, and repeating it here would prove nothing new.

```text
erc20_dom_to_evm — direction 0, settled by claim
  lockId   0x57441085f8fd3890f396412ef443771564168a7be93de2058e0e016ef5e39eca
  approve  0xfc7f64a0f28a0af5b982c5a7ba1d4f253400b9871cf3e1b6157ff702ab7064fb  block 11466520
  open     0x0cb7246656afb522eceaed4c31dac9accb80fd6ae1d6cc20d0c75233e92dbd21  block 11466521
  claim    0xd9c41549aacd37238151cd6c1fcb72cf08bad0feff6083a83a9dc5cde7f90e09  block 11466523

erc20_refund — direction 1, settled by refund after a real deadline
  lockId   0x5a4d464f51a8d3e4f08279baea5d846d4c2bdcfaa98e61ca365c63a13e0e939b
  deadline 1786455660
  approve  0x50472aaa8ae5fc5c4e99350b164df3694f788ae2c1e8f225c4e78abb3fde8385  block 11466524
  open     0xc672760ab7af80332c81dcecd42a83cc63e0e12b813b51a2ff8f4d97ff6844f9  block 11466526
  refund   0x519dd75124c7ad159121ce91fc867846b33474849ea6b085a46d472de253b4b4  block 11466544
```

The ERC-20 `open` carries no ETH — that contract reverts `ValueMismatch` on
any value — and pulls the amount through `transferFrom` under the same capped
`balanceOf` probe the payout path uses. Between the two flows the ERC-20
variant is exercised on both direction values and on both settlement paths.

## Withdrawing the pull credits

```text
native  credit 6 -> 0   0xd7592217555cf013483c08beaf37fb7f114f2c9be4ecbb18806acd40d7d05b84  block 11466546
erc20   credit 2 -> 0   0x930c2c4d6ce0a7197b39f1fe8cc9113991a6cda01313f7d067ff6dcc61e6c5b9  block 11466548
```

These two transactions exist because of a real failure, recorded here rather
than smoothed over. See "The first run, and why it failed".

## Finality

Every step above carries `finalizedCoversBlock: true` together with the
finalized head number and hash read at the moment of that observation. The
observation covering the last settlement block was `#11466572`. The claim
"finalized ≥ this block" is therefore re-checkable against the chain at any
later time, since the finalized head only moves forward.

The `finalized` tag was required before anything was spent and re-required
mid-run; A4-EVM has no fallback and no "N confirmations" substitute.

## The f3-harness phase

Both named integration tests ran against this same public endpoint and this
same deployment, and both passed:

```text
anvil_evm_to_dom_direction   ran: true   passed: true   (2176.95s)
anvil_dom_to_evm_direction   ran: true   passed: true   (2129.99s)
```

Three separate things are asserted per test, because none implies the others:
that the test *started* (its `test <name> ...` line appears), that libtest's
own summary says `1 passed; 0 failed; 0 ignored`, and that the harness's skip
marker `SKIPPED — NOTHING WAS VERIFIED` is absent. A test that returns early
still prints `ok`; the marker is how it says it did nothing.

**`t` extracted from a real on-chain `Claimed`.** Each test reads the revealed
scalar out of a finalized log via the adapter's own event observer and cursor,
and asserts it comes back byte-identical to the scalar the flow committed to:

```text
t extracted from   a real on-chain Claimed log (value redacted)
PayoutDeferred     none (native push delivered at the pinned limit)
```

The scalar itself is deliberately written to no evidence file. It is public on
chain, which is the only place it is a fact rather than a copy.

## The first run, and why it failed

A first public run on the same day reached the harness phase and failed there.
It is recorded because the fix changed what the settlement phase does.

```text
assertion `left == right` failed: a pushed native payout books no pull credit
  left:  [.., 3]
  right: [.., 0]
  at crates/f3-harness/tests/e2e_anvil.rs:1353
```

**Cause.** `claim` and `refund` pay the beneficiary optimistically and fall
back to booking a credit when the payout call is not given enough gas to push.
The settlement flows are driven by `cast send`, which sizes a transaction from
`eth_estimateGas`, and an estimator-chosen limit lands on the deferral every
time — `ConditionLockERC20V2` documents the same cliff for its own payout
path. Each settled flow therefore left 1 wei of credit. Three native flows,
3 wei. The contract was working exactly as designed: an unprovable delivery
becomes a claimable credit rather than a lie.

It broke the harness because line 1353 reads `pendingWithdrawals` as an
ABSOLUTE value, while its companion assertion two lines above (no
`PayoutDeferred` in the harness's own block range) is correctly scoped. The
absolute read only ever passed on a contract with no history.

**Fix.** The settlement phase now withdraws its own pull credits before
handing the contracts to the harness. The assertion was NOT touched, and it
keeps its full force: if the harness's own payout defers, the credit it reads
is 1, not 0, and it still fails. The 6 wei withdrawn above is 3 from the
failed run plus 3 from this one — the earlier credit was still there, which
independently confirms the diagnosis.

**Standing finding, not fixed here.** The assertion at
`crates/f3-harness/tests/e2e_anvil.rs:1353` is fragile by construction: it
will fail on any reused contract carrying credit from earlier activity. Every
other credit assertion in that same file (lines 2616/2627, 2886/2925) uses the
`credit_before` / `credit_after` delta pattern, which is the faithful
expression of what the assertion names. Converting line 1353 to that pattern
is a change to a gate test and is left for the operator to direct.

## Independent revalidation

The gate script writes its own evidence and then checks it. That was not
accepted as proof. Every claim was re-read from the chain with fresh JSON-RPC
calls and compared against the evidence file:

```text
107 checks, 0 failures
REVALIDATION: PASS — every claim re-read from the chain agrees
```

What is re-checked, per transaction: the receipt exists, its status is 1, its
block number and block hash match the evidence, the block at that height
fetched *independently* is the block the receipt names (a reorg since the run
would surface here), and the transaction is among that block's transactions.
Beyond that: `eth_chainId` is 11155111, both contracts still carry code, both
runtime codehashes recomputed over live `eth_getCode` match what this tree
builds, the current finalized head covers the highest step block, both
directions carry their declared `direction` value, both ERC-20 flows name a
token address rather than the zero address, and both harness tests are
recorded as having run AND passed.

The checker was itself tested against the failed run's evidence, where it
correctly reported 10 problems including the absent settlement evidence and
the `result: FAIL`. A checker that only knows how to say PASS is worth nothing.

## Secret scan

```text
the funding private key, whole working tree      0 occurrences
the funding private key, artefacts only          0 occurrences
72 distinct 64-hex tokens in the evidence        none is the funding key
private-key-shaped assignments in tracked files  none
URLs recorded in evidence                        none
contracts/broadcast, contracts/cache             absent (purged by the exit trap)
```

A first pass of this scan used `\b[0-9a-f]{64}\b`, which cannot match after a
`0x` prefix and reported a vacuous zero. The figures above are from the
corrected pass; the token count is the proof it now matches something.

Two residues are recorded rather than papered over, both pre-existing and
documented in the runbook §8: `cast` 1.7.1 has no environment form of
`--private-key`, so the key appears in the argument vector of the short-lived
signing processes; and an RPC URL that embeds a provider credential must be
treated as a credential itself. This run used an endpoint with no credential
in its path.

## Raw event logs

Read back from the chain with `cast receipt --json` after the run, not copied
from the script's own output. Event signatures resolved by `cast keccak`:

```text
Claimed(bytes32,bytes32,address,uint256)    topic0 0xca7668936817898f2bde507192f5845d33b460b40fa8206ba5e3869637a03e19
Refunded(bytes32,bytes32,address,uint256)   topic0 0x6c5895acb60b66e78106939eaaa3976db6325f801ff434fe24ff7cb0a6795a5f
PayoutDeferred(address,address,uint256)     topic0 0x1182782c307f5070cb912ad1a2b6b545dd40e5e5873d5b0eac7927f69a323c29
Withdrawal(address,address,address,uint256) topic0 0x342e7ff505a8a0364cd0dc2ff195c315e43bce86b204846ecd36913e117b109e
```

The three `Claimed` logs, by indexed topic — `lockId`, `binding`, `beneficiary`.
The fourth word (the log's `data`) is the revealed scalar `t`; it is
deliberately not transcribed here, for the reason given above. It is readable
by anyone at these transactions, which is the point.

```text
dom_to_evm        contract 0x27bbff9a…caa33
  topics  lockId  0x03768ba83d589a6cb97ca5261c6a5e6d1a44bd1ecda6b3f3e2560341eafc5085
          binding 0x97b60c5868a078a9bde224b4297dbb407e00f818b971f10f9a7466239bb16c5e
          benef.  0x…d797af65db28d51e43760ae7a4b168ba8cc2bd0f
  data            the revealed scalar (public on chain, not copied here)

evm_to_dom        contract 0x27bbff9a…caa33
  topics  lockId  0xd401110d6cfce562a9571712ba3a70a9652eb90fab0108a56fddce6a758ee22e
          binding 0xe037f889068d30182ea17db716ef7c4d084b3683bed102a9b2adbeb79562ea7e

erc20_dom_to_evm  contract 0x6c6c1319…cfbf
  topics  lockId  0x57441085f8fd3890f396412ef443771564168a7be93de2058e0e016ef5e39eca
          binding 0x5dafaae82530609fb44b4f8a78b69496da0c57de6f68bb6e71e4b2f43fddbb44
```

The two `Refunded` logs carry the refund flows' own `lockId` and `binding` with
`amount = 1`, on `0x27bbff9a…caa33` and `0x6c6c1319…cfbf` respectively.

### The logs that confirm the run-1 diagnosis

Every `claim` and every `refund` above emitted a **second** log:

```text
PayoutDeferred(to=0x…d797af65…bd0f, asset=0x00…00,                 amount=1)   native flows
PayoutDeferred(to=0x…d797af65…bd0f, asset=0x9412eb…ba7e,           amount=1)   ERC-20 flows
```

That is the primary, on-chain confirmation of the cause described above: the
payouts driven by `cast send` took the deferral branch and booked a credit,
one unit each. The diagnosis was reached by reading the contract and the test,
and these logs settle it as fact rather than inference.

The two withdrawals close the loop with the matching amounts:

```text
Withdrawal(account=0x…bd0f, asset=0x00…00,       to=0x…bd0f, amount=6)
Withdrawal(account=0x…bd0f, asset=0x9412eb…ba7e, to=0x…bd0f, amount=2)
  preceded by an ERC-20 Transfer of 2 from 0x6c6c1319…cfbf to the account
```

Six on the native contract is three from the failed first run plus three from
this one; two on the ERC-20 contract is this run's two flows. The arithmetic
closes on chain, with no appeal to the script's own accounting.

## Persistence, cursors and reconciliation

The gate asks for observation by events and cursors, and for persistence and
reconciliation. What backs those claims in this tree:

- **Cursor** (`crates/adapters/evm/src/cursor.rs`). An 86-byte, fixed-width,
  versioned encoding carrying `next_from_block`, the anchor block hash,
  `finalized_height` and `emitted_high_water`. It is decoded strictly and bound
  to a deployment: a cursor from another `chain_id` or another contract is
  `StaleCursor`, never silently adopted. `emitted_high_water` exists so a
  restart can tell "already reported up to here" apart from "merely scanned up
  to here" — which is what makes a resume idempotent rather than a replay.
- **Observation** (`adapter.rs::observe_blocking`, `scan`). Reorg detection runs
  BEFORE any scan, so the observer never builds on an orphaned anchor. Logs are
  paged, sorted and deduplicated before interpretation, because an endpoint may
  legally answer out of order and a proxy may answer twice. The cursor advances
  only past whole blocks.
- **Finality** (`finality.rs`). The only source is
  `eth_getBlockByNumber("finalized")`. There is no fallback, and
  `min_confirmations` is reported as `0` in the declared capabilities precisely
  so that nobody reads a confirmation policy that does not exist. The gate is
  applied twice: the scan window is clamped to the finalized height, and each
  block is re-checked before its events are surfaced.
- **Reveal survives reorg** (`revealed.rs`). The registry of revealed scalars is
  append-only by construction — no `remove`, no `clear`, and the reorg path
  cannot reach it. A reorg invalidates the settlement effect but cannot
  un-publish `t`; treating the scalar as secret again would be a security
  fiction while the counterparty spends it on the other leg.

**Reconciliation, as this run actually exercised it.** The first run died in the
harness phase. The second run re-read `artifacts/sepolia/deploy.json`, fetched
the live runtime codehash of both recorded addresses, compared them against the
contracts this tree builds, and only then reused the deployment — no contract
was redeployed. No funding, claim or refund was duplicated: the account's nonce
advanced by exactly 39 across both runs, which is the transaction count the two
plans sum to. This is a real resume over a public chain, and it is recorded as
what it was — a recovery from a genuine failure, not a scripted crash-restore
scenario. The designed crash/restore scenarios live in the Anvil suite
(`scripts/e2e_anvil.sh`).

## What this establishes, and what it does not

It establishes the **EVM** side end to end against a real public network: real
bytecode whose codehash is tied to this tree, real transactions, real logs,
real finality, real deadlines.

The DOM side ran against `dom-sim`. **`dom-sim` is not the DOM.** It confers
no network compatibility, and substituting the real DOM node is a separate,
later phase with its own eligibility gate. Nothing in this report may be read
as evidence about the real DOM network.

## Adjudication

Per CLAUDE.md §4, the executor prepares evidence and never self-ratifies.
At the time this report was written, the state was:

```text
G-F3 = PROPOSED PASS — AWAITING OPERATOR ADJUDICATION
```

### Later note (2026-08-11) — the adjudication has since been granted

The proposal above was ADJUDICATED by the operator on 2026-08-11. This note
is appended after the fact; the report's original text above is left
unchanged and stands as the record of what was known when it was written.

```text
G-F3 = PASS — OPERATOR ADJUDICATED
F3   = COMPLETED
```

Recorded as decision **D-025** in
`docs/normative/DOM-Interop-Foundation-Document-v0.15.md` §12.1, with the
closure package in `docs/reports/F3-CLOSURE.md`, on executed code
`7b6d4b0614ca25894c1cf6125e089908e003f39d` and evidence HEAD
`9afaea8cb186f7639763515f2af176f7892a061c`.
