# F3 CLOSURE REPORT — G-F3 OPERATOR ADJUDICATION

```text
Gate:              G-F3 (Foundation Document §7, "F3 — EVM leg")
Decision:          G-F3 = PASS
Phase:             F3 = COMPLETED
Adjudicator:       Soren Planck (operator and ratification authority)
Adjudication date: 2026-08-11
Decision record:   D-025, Foundation Document v0.15 §12.1
Executed code:     7b6d4b0614ca25894c1cf6125e089908e003f39d
                   tree 278d5e9a141583f44e43740612ac8c8616de6f6e
Evidence HEAD:     9afaea8cb186f7639763515f2af176f7892a061c
                   tree 4b80f9c0350591480b9dcbbdd6df77e4dcce5059
Network:           Ethereum Sepolia, chain id 11155111 (public)
Execution window:  2026-08-11T13:26:40Z .. 2026-08-11T15:17:42Z (111m02s)
```

This report records an adjudication the operator has already granted. It
does not propose, defer or qualify it. The execution evidence it rests on
is `docs/reports/F3-SEPOLIA-E2E.md` and the artefact set under
`artifacts/sepolia/`, both committed at the Evidence HEAD above.

## 1. The gate criterion, verbatim

Foundation Document §7, "F3 — EVM leg (first real counterparty)":

> Gate G-F3: first real DOM(dom-sim)↔EVM E2E on testnet, BOTH directions,
> with `t` extracted from a real on-chain `Claimed` and refund via a real
> deadline; report with tx hashes.

## 2. Requirement → evidence → result

| # | Requirement (§7 G-F3) | Evidence | Result |
|---|---|---|---|
| 1 | Real testnet | `eth_chainId` = 11155111 re-read from the chain during independent revalidation; `gate.json.network.chainId` = 11155111 | **PASS** |
| 2 | DOM(dom-sim)↔EVM end to end | `f3-harness` tests `anvil_dom_to_evm_direction` and `anvil_evm_to_dom_direction` executed against this deployment and this public endpoint; `gate.json.e2eEvidence.harness` records `ran: true, passed: true` for both and `skipped: false` | **PASS** |
| 3 | BOTH directions | `dom_to_evm` carries `direction = 0`, `evm_to_dom` carries `direction = 1`; each yields a distinct `binding` and a distinct `lockId` for otherwise identical terms, so the direction is committed on chain and not merely labelled in a report | **PASS** |
| 4 | `t` extracted from a real on-chain `Claimed` | each harness test reads the revealed scalar out of a finalized `Claimed` log through the EVM adapter's own event observer and cursor, and asserts byte-identity with the scalar the flow committed to; `scalarRevealedOnChain = true` on all three claim flows | **PASS** |
| 5 | Refund via a real deadline | `refund` flow: `open` at block 11466497, `refund` at block 11466516 — nineteen blocks of the chain's own clock. `evm_increaseTime` does not exist on a public network; the run paid the wait | **PASS** |
| 6 | Report with tx hashes | §3–§6 below, plus `artifacts/sepolia/{gate,e2e,deploy}.json` and the raw logs re-read with `cast receipt --json` | **PASS** |

No row of this table is `PROPOSED PASS`.

## 3. Contracts and code identity

```text
ConditionLockV2       0x27bbff9ad075ca82946e61c86c7b83be102caa33
  runtime codehash    0x33c4df043837e30e9e0ff5a71db933849fad94b22c0885734d7f940db8ed5737
  deploy tx           0x09a035cf6590b00de8e5b19c59ccb6da544a12b3a4ee8d7cf5bc33a9404f7cc1

ConditionLockERC20V2  0x6c6c1319979ebcdab9a11c0e569f840a6db3cfbf
  runtime codehash    0x1f1a01cfccb4dab95e9dbb7054a653d6a6c9968f05fdfc0558e8d357909d796e
  deploy tx           0xa8989ffcb1c3cb2b276287efe2a07e3022b9f9acf8ef3f07dd628e01f4d3c722

both deployed in      block 11466024
  block hash          0xd0e0dedf3838b629934fdbc287326a8f7e2a4e2a31ead1499619e2a76d32b804
  finality observed   #11466048 0xd89edf6e02de5619ba0a1050aceb935f0d65516e34741de055f4b595a4f79715
```

Both live runtime codehashes equal the codehashes this tree builds
(`gate.json.deployment.expectedRuntimeCodehashFromThisTree`). The equality
is checked before any flow runs and re-checked independently afterwards
over live `eth_getCode`.

**Code identity of the run.** The run executed the tree at
`a80021f93c6e834ceee83d76aa57b2ef5035c994` plus two then-uncommitted driver
scripts. Those two blobs were committed unchanged as `7b6d4b0` — the
Executed code anchor — and they survive byte-identical at the Evidence
HEAD:

```text
scripts/sepolia.sh       blob d120cb2e87f8b90c198cff5480e9f86a37dc23be
scripts/sepolia_e2e.sh   blob e5578f44951bc8b4b9d97669b412ca18651370ed
```

The F3 surface of the executed tree — `contracts/`, `crates/adapters/evm`,
`crates/f3-harness`, `crates/kaystra-core`, `crates/store`,
`crates/counterparty-api`, `crates/dom-leg`, `crates/dom-vault`,
`crates/adapters/dom-sim`, `Cargo.toml`, `Cargo.lock`,
`rust-toolchain.toml` — is byte-identical to the same paths at the Evidence
HEAD. `git diff a80021f 9afaea8` over those paths is empty. The only code
difference between the two commits is in `crates/adapters/btc-evidence`,
which belongs to F5 and which F3 does not exercise.

## 4. Settlement flows — native ETH

Amount locked per flow: 1 wei. The funder is also the beneficiary, so the
locked value returns and gas is the entire cost. Every step below carries
`receipt.status = 1`, `canonical = true` and `finalizedCoversBlock = true`.

### `dom_to_evm` — direction 0, settled by claim

```text
lockId    0x03768ba83d589a6cb97ca5261c6a5e6d1a44bd1ecda6b3f3e2560341eafc5085
binding   0x97b60c5868a078a9bde224b4297dbb407e00f818b971f10f9a7466239bb16c5e
termsHash 0xb3d784297ca5107603f9eeb59edea6999097c1b7e50ab6c367424148c5cfd1fa
sessionId 0xff07e4665ef7c84cced2c8f27114d3265664eb8c61109a44e9d8990e04832dbf
open      0x99f0345f8d26082befa464f5e569221d3a32cdfc6a4c09fc9a8e346547a7e000
          block 11466491  0xc68cf41f98edf61db77606430a14ac3f599f2a71a399d8dc70dc89b3674a97aa
claim     0x5b2c7875ca749e848fa32d4a22ecb4670b8e85dd3cef5377940f8e6792d27b06
          block 11466493  0x68d63f1fd940b19026cf26b6db0e41bf87c80b6b5cb02a564eb5ee31f332399e
```

### `evm_to_dom` — direction 1, settled by claim

```text
lockId    0xd401110d6cfce562a9571712ba3a70a9652eb90fab0108a56fddce6a758ee22e
binding   0xe037f889068d30182ea17db716ef7c4d084b3683bed102a9b2adbeb79562ea7e
termsHash 0x1f28f96ff562913960c7409280f1511cb9011d6c8f39e7e9983a5e4631806f04
sessionId 0x18bc5382720e02dc616e885551a0c252ca7f369633bfd70e85fc5c018f71ae00
open      0x44f4624a4ac6809f940bd8ceedefcdbdd6189d980adb80b9d0c2082f03f7f5df
          block 11466494  0x5db5325d6674599b5cccb902773ed2243cec64c2c3d1472a4e110423856d8feb
claim     0x70d3c39a4fa6080e255bd87e9e27e3830688ea1d3d68081909ac66165dc2a2e9
          block 11466496  0x0222d6a2c3835a5f505231ffcde9494f1f85b236e621511ee2348e5e3ebfb066
```

### `refund` — real deadline waited out

```text
lockId    0x12d68c2db723fd365fcbc133d311399eb36af87d444acce04a3a6aec2d6d5eeb
binding   0xf89f7f430459cc1d0bd66b880582417c90d19125e27a1e7d77c1502e7cf84e21
deadline  1786455324 (UNIX, TimelockDomain::Timestamp)
open      0xb258be45010762302ee810cec2285de2379c62ead5ce9db57263ce5e5f79cc0f
          block 11466497  0x71c2b2ca40f6f0176c8e32052a8579028914e1dd4db1b8c209b17c32fa607f61
refund    0x628cc9599519be8d72060e02e173db561b07aca7741574ffd38a99120705b86a
          block 11466516  0x7f87c6294d9ce9bd8633b5b5fc54819348a8e7078b727d9c5ae90a8806cff698
```

## 5. Settlement flows — ERC-20

The §7 gate text does not mention the ERC-20 variant. These two flows are an
ADDITION to the published criterion, instructed and ratified by the operator
on 2026-08-11 and recorded as such by D-025. G-F3 as written is settled by
the three native flows in §4; what follows is additional coverage.

Token fixture (`test/mocks/HostileTokens.sol:MockERC20`, the well-behaved
baseline — misbehaviour is the adversarial Foundry suite's job):

```text
MockERC20         0x9412Eb267d2C361Eee10d8ec3Ac8D2355223bA7E
  runtime codehash 0x51134382a208031d3f693689722e9a4418015d8db323080f3c37594f42755dfa
  deploy           0x6a6e69a64eb78256571a2bb621e930a8fa4b63ecfc6f0fc30ab7e467e2ac877a  block 11466518
  mint             0xf95895d2f0a84575e42d00bc0fbe4eaafbbe8cad86233749d328969fbfe8b14e  block 11466519
```

```text
erc20_dom_to_evm — direction 0, settled by claim
  lockId   0x57441085f8fd3890f396412ef443771564168a7be93de2058e0e016ef5e39eca
  binding  0x5dafaae82530609fb44b4f8a78b69496da0c57de6f68bb6e71e4b2f43fddbb44
  approve  0xfc7f64a0f28a0af5b982c5a7ba1d4f253400b9871cf3e1b6157ff702ab7064fb  block 11466520
  open     0x0cb7246656afb522eceaed4c31dac9accb80fd6ae1d6cc20d0c75233e92dbd21  block 11466521
  claim    0xd9c41549aacd37238151cd6c1fcb72cf08bad0feff6083a83a9dc5cde7f90e09  block 11466523

erc20_refund — direction 1, settled by refund after a real deadline
  lockId   0x5a4d464f51a8d3e4f08279baea5d846d4c2bdcfaa98e61ca365c63a13e0e939b
  binding  0xb47d536b0cbb2754c18b3e0cb57bcd315ce5f68c9517481b601332ca66fd9338
  deadline 1786455660
  approve  0x50472aaa8ae5fc5c4e99350b164df3694f788ae2c1e8f225c4e78abb3fde8385  block 11466524
  open     0xc672760ab7af80332c81dcecd42a83cc63e0e12b813b51a2ff8f4d97ff6844f9  block 11466526
  refund   0x519dd75124c7ad159121ce91fc867846b33474849ea6b085a46d472de253b4b4  block 11466544
```

Between the two flows the ERC-20 variant is exercised on both direction
values and on both settlement paths.

## 6. Events, deferred payouts and withdrawals

Event signatures resolved by `cast keccak`; the logs themselves re-read from
the chain with `cast receipt --json` rather than copied from the driver's
output.

```text
Claimed(bytes32,bytes32,address,uint256)    topic0 0xca7668936817898f2bde507192f5845d33b460b40fa8206ba5e3869637a03e19
Refunded(bytes32,bytes32,address,uint256)   topic0 0x6c5895acb60b66e78106939eaaa3976db6325f801ff434fe24ff7cb0a6795a5f
PayoutDeferred(address,address,uint256)     topic0 0x1182782c307f5070cb912ad1a2b6b545dd40e5e5873d5b0eac7927f69a323c29
Withdrawal(address,address,address,uint256) topic0 0x342e7ff505a8a0364cd0dc2ff195c315e43bce86b204846ecd36913e117b109e
```

Three `Claimed` logs were emitted, indexed by `lockId`, `binding` and
`beneficiary`. **The revealed scalar in each log's data word is deliberately
not transcribed into this repository.** It is public on chain, which is the
only place it is a fact rather than a copy; the harness reads it from there.

Every claim and every refund also emitted `PayoutDeferred` with amount 1:
the payout transactions were sized by `eth_estimateGas`, which lands on the
D-002 pull-fallback branch, so each settlement booked a credit instead of
pushing. This is the contract behaving exactly as D-002 specifies — an
unprovable delivery becomes a claimable credit, and the settlement, including
the emission of `Claimed(t)`, is never blocked by the payout.

```text
withdraw native  0xd7592217555cf013483c08beaf37fb7f114f2c9be4ecbb18806acd40d7d05b84  block 11466546  credit 6 -> 0
withdraw erc20   0x930c2c4d6ce0a7197b39f1fe8cc9113991a6cda01313f7d067ff6dcc61e6c5b9  block 11466548  credit 2 -> 0
```

Six on the native contract is three from an earlier failed run plus three
from this one; two on the ERC-20 contract is this run's two flows. The
arithmetic closes on chain, with no appeal to the driver's own accounting.

## 7. Finality

The only finality source is `eth_getBlockByNumber("finalized")`. There is no
confirmation-count fallback, and the EVM adapter reports `min_confirmations`
as `0` in its declared capabilities precisely so that nobody reads a
confirmation policy that does not exist. The gate is applied twice: the scan
window is clamped to the finalized height, and each block is re-checked
before its events are surfaced.

Every step carries `finalizedCoversBlock: true` together with the finalized
head read at that moment. The observation covering the last settlement block
was:

```text
finalized head  #11466572  0xfc093188dcc1d8b9b2ebfe4100f99e59025b8607c0d3dccf3cb78be137ad8631
```

Because the finalized head only moves forward, "finalized ≥ this block" stays
re-checkable against the chain at any later time.

## 8. Independent revalidation

The gate driver writes its own evidence and then checks it. That was not
accepted as proof. Every claim was re-read from the chain with fresh
JSON-RPC calls and compared against the evidence file:

```text
107 checks, 0 failures
REVALIDATION: PASS — every claim re-read from the chain agrees
```

Per transaction: the receipt exists, its status is 1, its block number and
block hash match the evidence, the block at that height fetched
independently is the block the receipt names (a reorg since the run would
surface here), and the transaction is among that block's transactions.
Beyond that: `eth_chainId` is 11155111, both contracts still carry code,
both runtime codehashes recomputed over live `eth_getCode` match what this
tree builds, the finalized head covers the highest step block, both
directions carry their declared `direction` value, both ERC-20 flows name a
token address rather than the zero address, and both harness tests are
recorded as having run AND passed.

The checker was itself tested against a failed run's evidence, where it
correctly reported ten problems including the absent settlement evidence and
`result: FAIL`. A checker that only knows how to say PASS is worth nothing.

## 9. Secret scan

```text
the funding private key, whole working tree      0 occurrences
the funding private key, artefacts only          0 occurrences
72 distinct 64-hex tokens in the evidence        none is the funding key
private-key-shaped assignments in tracked files  none
URLs recorded in evidence                        none carrying a credential
contracts/broadcast, contracts/cache             absent (purged by the exit trap)
```

A first pass of this scan used `\b[0-9a-f]{64}\b`, which cannot match after a
`0x` prefix and reported a vacuous zero. The figures above are from the
corrected pass; the token count is the proof it now matches something.

## 10. The DOM side of this gate

The DOM leg of F3 ran on `dom-sim`.

`dom-sim` is the project's testable DOM-chain stand-in, authorised for F3 by
the Foundation Document §4.5: a height/advance/submit/confirmations/
inject_reorg/scan surface that reproduces the chain behaviour the settlement
engine depends on, including injectable reorg. The cryptography executed over
it is never simulated — it is the real `dom-adaptor` at the pinned rev
`eb6aa1ca59226bc316e3aace5ee0e279e5a154c2`, and the DOM-side signatures the
F1 suites produce are verified by the DOM's own normal, unaltered verifier.

Two boundaries are stated so that neither is inferred away:

- `dom-sim` is not the DOM network and confers no network compatibility.
  Nothing in this report may be read as evidence about the real DOM network.
- Substituting the real DOM node — real builder, RPC, mempool, verifier and
  scanner — is F7's deliverable, under its own eligibility gate. G-F3 neither
  performs nor anticipates it.

## 11. Limitations recorded, not converted into PASS

1. **`crates/f3-harness/tests/e2e_anvil.rs:1353`** reads `pendingWithdrawals`
   as an ABSOLUTE value, while every other credit assertion in that file
   (lines 2616/2627, 2886/2925) uses the `credit_before` / `credit_after`
   delta pattern. The absolute read only passes on a contract with no
   history. The settlement phase now drains its own pull credits before
   handing the contracts to the harness, so the assertion holds and keeps
   its full force — but it remains fragile by construction on any reused
   deployment. Converting it to the delta pattern is a change to a gate test
   and is left for the operator to direct. It is NOT a defect in the EVM leg
   or in the contracts.
2. **`cargo clippy --workspace --all-targets --all-features --locked
   -- -D warnings`** currently fails on `crates/f4-harness/tests/e2e_anvil.rs`
   (`clippy::clone_on_copy`). That file lives behind the `rpc-http` feature
   and is not compiled by `scripts/ci_local.sh` or by `ci.yml`, which run
   clippy without `--all-features`. This is an F4-surface finding; it does
   not touch the F3 code path and does not bear on this adjudication. It is
   recorded here so it is not lost, and it belongs to the G-F4 work.

Both items are pre-existing. Neither was introduced by this closure, and
neither is corrected by it.

## 12. Effect on the gate sequence

```text
G-F0  PASS  (docs/reports/F0-CLOSURE.md, waiver R-001 lifted)
G-F1  PASS  (docs/reports/F1-CLOSURE.md)
G-F2  PASS  (docs/reports/F2-CLOSURE.md)
G-F3  PASS  (this report; D-025)          <- adjudicated 2026-08-11
G-F4  the first mandatory gate still open
G-F5  IN PROGRESS (public-signet leg outstanding)
G-F6  EVIDENCE COMPLETE — adjudication deferred
G-F7  BLOCKED BY EXTERNAL DEPENDENCY
G-F8  NOT STARTED
```

G-F4 must be re-validated against the current HEAD before it can be
adjudicated: D-024 binds the accepted material evidence to head `9c04d363`,
and paths D-024 protects (`crates/f4-harness`, `crates/kaystra-core`,
`crates/store`) have moved since. This closure neither promotes nor
anticipates G-F4, G-F5, G-F6, G-F7 or G-F8.

## 13. Adjudication

```text
G-F3 PASS — OPERATOR ADJUDICATED
F3 = COMPLETED
```

Adjudicated by Soren Planck on 2026-08-11, on the evidence of executed code
`7b6d4b0614ca25894c1cf6125e089908e003f39d` and Evidence HEAD
`9afaea8cb186f7639763515f2af176f7892a061c`, recorded as decision D-025 in
Foundation Document v0.15 §12.1.

## 14. Declarations

```text
DOM_SIM_IS_REAL_DOM=false
DOM_SCRIPTLESS_TOUCHED=false
DOM_CORE_TOUCHED=false
DOM_CONTRACTS_TOUCHED=false
DOM_WALLET_TOUCHED=false
MAINNET_USED=false
NEW_TRANSACTIONS_BROADCAST_BY_THIS_CLOSURE=false
PRODUCTION_CODE_MODIFIED_BY_THIS_CLOSURE=false
```
