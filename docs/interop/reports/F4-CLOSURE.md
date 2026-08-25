# F4 CLOSURE REPORT — G-F4 OPERATOR ADJUDICATION

```text
Phase:             F4 — economic assurance (solver bond, slash, compensation)
Gate:              G-F4 (Foundation Document §7; F4 Engineering
                   Specification v1.0.2 §12, as amended by D-024)
Decision:          G-F4 = PASS
Phase state:       F4 = COMPLETED
Next required gate: G-F5
Adjudicator:       Soren Planck (operator and ratification authority)
Adjudication date: 2026-08-11
Decision record:   D-026, Foundation Document v0.16 §12.1
Tested commit:     593364b9d11cdb0843c5d732a9446a105d451860
                   tree aa2153821272910cabf7553b99328a370ae79920
Closing run:       workflow_dispatch 31521948686, job 93880878036
                   (.github/workflows/f4-sepolia.yml), head_branch main
Network:           Ethereum Sepolia, chain id 11155111 (public)
```

This report records an adjudication the operator has already granted. It
does not propose, defer or qualify it. Section 1 is the run that binds the
gate to the current head; section 2 preserves the earlier accepted evidence
as history, exactly as D-024 requires.

## 1. The closing run — bound to the current head

Workflow run **31521948686**, job **93880878036**, dispatched by the
operator on 2026-08-11 (18:17:29Z → 18:54:47Z), conclusion **success**.

```text
head_branch   main
head_sha      593364b9d11cdb0843c5d732a9446a105d451860
tree_id       aa2153821272910cabf7553b99328a370ae79920
event         workflow_dispatch
test          sepolia_slash_compensates_without_any_privileged_action
              1 passed; 0 failed; 0 ignored — 2176.23s
terminal      Compensated
verdict       VERDICT: G-F4 SEPOLIA SLASH PASS
```

**Why this run closes the gate and the earlier one could not.** D-024 binds
the accepted material evidence to head `9c04d363` and states that any later
modification to `uspe`, `f4-model`, `f4-harness`, `store`, `adapter-evm`,
`ConditionLockV2` or an interface F4 consumes invalidates that binding. Such
modifications had occurred. This run was executed on `593364b`, which was
`origin/main` at dispatch time and remains so; `git diff 593364b..origin/main`
over every D-024-protected path is empty. `main == tested HEAD` therefore
holds, literally and at the time of writing.

### The four on-chain transactions

Contract `0x90f462d6c40049005e613234baece24b190587eb` (`ConditionLockV2`).
Before anything was spent, the driver executed
`== verifying the runtime bytecode at 0x90f462… against this tree ==`; the
check fails closed, and the run proceeded, so the live runtime codehash
equals the codehash this tree builds.

| step | transaction |
|------|-------------|
| bond open — solver collateral locked | `0x0f032a371e92b785e8a515fd5019a8ab4e2243105f14b9976be3c0edac6d43cf` |
| settlement open | `0xcbe3100438b0d71f9361a5a7adc903bf02b670e103ae6ec3e4db7f32766f6f5c` |
| settlement claim — obligation outcome, `t` becomes public | `0x3208d6fddb20a4a9a964378705115f7d3103ed688bcafd3d5de3804506e307f6` |
| bond slash — compensation executed | `0x6f49e283f9c5cd6826d4296e86059815172ae9ce770c4d06ed50502d31819c67` |

Executing account: `0xD797af65Db28d51E43760Ae7a4B168bA8cc2Bd0f`, balance
`316907728751182622` wei at start. The settlement claim line is annotated by
the driver itself with `(t is now public)` — the revealed scalar is not
transcribed into this repository, because it is a fact on chain and a copy
in a file is not what makes it one.

### Finality — applied twice, no confirmation-count substitute

The only finality source is the `finalized` tag. The run gated on it twice
and waited real epochs both times:

```text
finality wait 1/2 (bond open + settlement claim)
  finalized  #11467899 >= 11467883
finality wait 2/2 (the slash)
  finalized  #11467993 >= 11467965
```

The second wait consumed 1110 s of its 2400 s bound before the finalized head
advanced. No clock was moved and no confirmation count was accepted in place
of finality. A live single-block `eth_getLogs` probe
(`[11467745,11467745]: ok, 0 logs`) confirmed the paging shape the adapter
uses against the endpoint actually in service.

### Terminal state and the absence of privileged action

The terminal is `Compensated`, recovered from the durable `0xF401` journal —
the machine's own terminal, not a log line. The test that produced it is named
for the property it proves: `sepolia_slash_compensates_without_any_privileged_action`.
It passed, with `privilegedActions = 0`. Nothing in the flow used an owner, an
admin, a guardian, a pause or an upgrade path, because the contracts expose
none (I2, enforced by `scripts/guards.sh`).

### Evidence artifact

```text
artifact name    f4-sepolia-evidence
artifact id      9114597700
size             19188 bytes, 9 files
SHA-256          e646f63e42f7c0433e8699dd7c6a3efc365155a5732bbebb85891e94ada88e00
retention        until 2026-11-09T18:17:30Z
run-scoped files f4-slash-evidence.json
                 f4-slash-20260811T181817Z.log
```

The ZIP also carries files from the earlier G-F3 execution
(`tested-code-identity.txt`, `deploy.json`, `e2e.json`, `gate.json`,
`independent-revalidation.txt`, `run.log`, `secret-scan.txt`), because the
workflow uploads the whole `artifacts/sepolia` directory. **Those seven files
are G-F3 history and are NOT the identity of this F4 run.** The identity of
this run is the pair of `f4-slash-*` files plus the workflow run's own
immutable metadata, which binds `head_sha` and `tree_id` to `593364b` /
`aa215382`.

### Verification performed for this closure, and its limits

Verified:

- the tested commit exists and its **complete tree hash is
  `aa2153821272910cabf7553b99328a370ae79920`**, identical to the `tree_id`
  the run's immutable metadata records;
- `origin/main` equals the tested commit; no D-024-protected path has moved
  since;
- the run's `conclusion` is `success`, its `event` is `workflow_dispatch`,
  its `head_branch` is `main`;
- the artifact SHA-256 agrees across **two independent immutable sources** —
  the Actions API `digest` field on artifact 9114597700, and the
  `SHA256 digest of uploaded artifact zip is …` line the upload step printed
  into the job log;
- the four transaction hashes, the verdict line, the terminal, the finality
  observations, the codehash-verification step and the test result, all read
  from the job log of job 93880878036;
- commit authorship and committer are `Soren Planck <sorenplanck@tutamail.com>`.

Not verified from the closing environment, and recorded rather than implied:

- the **inner contents** of the artifact ZIP (`f4-slash-evidence.json` and
  its receipts, block hashes and canonicality fields) could not be read: the
  Actions artifact download resolves to an Azure blob host that the executing
  environment's network policy refuses (`403 CONNECT`). The artifact's
  identity is nevertheless pinned by the doubly-confirmed SHA-256 above;
- an **independent on-chain re-read** of the four receipts was not performed
  from this environment, because every public Sepolia JSON-RPC endpoint is
  refused by the same network policy. The finality and receipt assertions
  rest on the run itself, which executed against an endpoint serving the
  `finalized` tag and fails closed otherwise.

Neither limit is a gap in the run; both are limits of the environment that
wrote this report, and they are stated so that no reader mistakes second-hand
confirmation for first-hand re-verification.

## 2. Earlier accepted evidence — preserved as history

Workflow run **31431363791** (`f4-sepolia`, 2026-08-10 20:55→21:34Z, head
`9c04d363`, artifact 9080416151, artifact SHA-256
`d6a4733b063a910f06eef9ae112f9624084acd7ee54a6c19c556b4e50ee5fbb9`),
conclusion **success**, same verdict line. Its four transactions:

| step | transaction |
|------|-------------|
| bond open | `0x17630548fdf903ab26dd3ae278fc1897557ce62dd9a96c10582ba1a62ab70479` |
| settlement open | `0x0681c36945f65fefcc9ca1c576a55686dfb1f63f9ffd8efec36a16313ba58714` |
| settlement claim | `0xd05ac0308e85d248be1f50eebfc34372ab4857d5a81693e96a88b920f05b164e` |
| bond slash | `0xa13b73f73293e7eaee17ba2f50f5b6fb961c431bd2d2636094b55d77fcc3d4fe` |

D-024 accepted this evidence as material and instructed that it not be
repeated out of generic doubt. It remains on the record. It does not close
the current head — that is section 1's role — and it is not superseded,
deleted or rewritten.

The failed attempts that preceded it are also part of the record: runs died
on an `eth_getLogs` range cap the driver mispaged at 512 blocks. The
diagnostic probe measured the cap live and the fix set `page_size: 8`, the
constant F3 already used. Nothing was loosened; the fix changed the request
shape, not one assertion.

## 3. Local proof standing behind the same code

All fifteen suites were re-executed from zero at the tested HEAD
`593364b`, every one exiting 0, with no mandatory skip:

| command | exit | duration |
|---|---:|---:|
| `cargo fmt --all -- --check` | 0 | 2 s |
| `cargo clippy --workspace --all-targets --all-features --locked -- -D warnings` | 0 | 26 s |
| `cargo test --workspace --locked` | 0 | 120 s |
| `cargo test --workspace --all-targets --all-features --locked` | 0 | 127 s |
| `cargo test --doc --workspace --all-features --locked` | 0 | 1 s |
| `cargo test -p uspe --locked` | 0 | 4 s |
| `cargo run -p f4-model --release --locked` | 0 | 4 s |
| `cargo run -p f2-model --release --locked` | 0 | 2 s |
| `cargo run -p f6-model --release --locked` | 0 | 2 s |
| `cargo test -p store --features failpoints --locked` | 0 | 2 s |
| `cargo test -p f4-harness --features rpc-http --locked` | 0 | 11 s |
| `cargo test -p f3-harness --features rpc-http --locked` | 0 | 4 s |
| `PROPTEST_CASES=2000 cargo test -p kaystra-core --test state_properties --locked` | 0 | 99 s |
| `python3 scripts/verify_terms_vectors.py` | 0 | 0 s |
| `./scripts/guards.sh` | 0 | 1 s |

The clippy line is worth naming: F4 specification §19 requires that exact
profile, and it had been failing on a `clippy::clone_on_copy` in
`crates/f4-harness/tests/e2e_anvil.rs` that no gate compiled, because neither
`ci.yml` nor `scripts/ci_local.sh` builds `f4-harness` with `rpc-http` and
both run clippy without `--all-features`. Commit `593364b` removed the
redundant clone on a `Copy` policy; the semantics of the check are unchanged,
and the profile now exits 0.

### The economic invariants, proven exhaustively

`f4-model` explores the REAL `uspe` transition function — not a re-model —
and reports:

```text
reachable worlds explored: 18
machine states covered: 11/11
HOLDS   coverage: every state of the machine is reachable
HOLDS   NO_DOUBLE_COMPENSATION
HOLDS   NO_RELEASE_AND_SLASH
HOLDS   TIMEOUT_SAFE
HOLDS   AG compensated_total <= compensation_cap
HOLDS   AG certificate.terms == obligation.terms
HOLDS   AG recorded_outcome in {Released, Compensated}
HOLDS   AG accepted_transition -> PersistState(next) first
HOLDS   AG terminal -> AX unchanged
result: PASS
```

The three named gate invariants are there by name. `AG recorded_outcome in
{Released, Compensated}` is the mutual exclusivity of the terminals;
`AG compensated_total <= compensation_cap` is the cap; `AG certificate.terms
== obligation.terms` is the refusal of a divergent `terms_hash`;
`AG accepted_transition -> PersistState(next) first` is persist-before-effect,
which is what makes crash-at-any-transition recoverable.

### Division of proof between testnet and local suites

| requirement | where it is proven |
|---|---|
| NO_DOUBLE_COMPENSATION, NO_RELEASE_AND_SLASH, TIMEOUT_SAFE | `f4-model`, exhaustive over the production machine |
| SETTLED / REFUNDED / COMPENSATED mutually exclusive | `f4-model` (`AG recorded_outcome`), `crates/uspe` |
| compensation never above the cap | `f4-model` (`AG compensated_total <= cap`); over-cap refused at adapter construction, before any transaction, in the Anvil scenario |
| divergent `terms_hash` refused | `f4-model` (`AG certificate.terms`), `crates/uspe` (`TermsMismatch`), Anvil wrong-terms scenario |
| invalid / late / reorg-affected evidence refused | `crates/f4-harness/tests/evidence.rs`; a reorg across the claim is UNDECIDABLE, never a verdict |
| crash/restart safe at every transition | `crates/f4-harness/tests/journal.rs` over kind `0xF401`; Anvil slash path with a crash at every transition |
| release by a third party and by timeout | Anvil adversarial suite (permissionless refund; uncertified collateral released on timeout) |
| refusals produce no transaction, no journal line, no state change | Anvil scenario `anvil_cap_and_binding_refusals_touch_nothing`: sender nonce, `LockOpened` count, contract code and contract balance all unchanged; revision re-proved from the file alone |
| **compensation on a public testnet with no privileged action** | **run 31521948686, section 1** |

Over-cap and wrong-terms belong to the local and Anvil adversarial
regression, which is green. What the Foundation requires *on testnet* is the
compensation executed without any privileged action, and section 1 is that
proof.

## 4. What F4 does not claim

- No new cryptographic primitive (I15): the evidence path consumes the same
  revealed-scalar discipline F3 proved; verification authority stays with the
  pinned backend.
- Exposure-coverage pricing internals (haircut tables, volatility inputs)
  remain the F4 policy's evolvable domain (spec §8) and are not frozen here.
- Bond asset diversity remains the recorded A5/A6 remainder.
- Nothing about F5, F6, F7 or F8 is promoted by this closure.

## 5. Effect on the gate sequence

```text
G-F0  PASS  (docs/reports/F0-CLOSURE.md, waiver R-001 lifted)
G-F1  PASS  (docs/reports/F1-CLOSURE.md)
G-F2  PASS  (docs/reports/F2-CLOSURE.md)
G-F3  PASS  (docs/reports/F3-CLOSURE.md; D-025)
G-F4  PASS  (this report; D-026)            <- adjudicated 2026-08-11
G-F5  NEXT REQUIRED GATE — IN PROGRESS; Annex M v3.2 M.15.2 outstanding
      (public-signet leg has no closure report)
G-F6  EVIDENCE COMPLETE — adjudication deferred; of its three blocking
      gates, G-F3 and G-F4 are now closed and G-F5 remains
G-F7  BLOCKED BY EXTERNAL DEPENDENCY (Scriptless Phases 2–6, DOM side)
G-F8  NOT STARTED
```

D-024's curative disposition is now spent by its own terms: the current head
was re-submitted to the F4 regressions, clean worktree and `main == tested
HEAD` held, and the gate is adjudicated. The disposition set no precedent for
ignoring phase order, and none is taken from it.

## 6. Adjudication

```text
G-F4 PASS — OPERATOR ADJUDICATED
F4 = COMPLETED
NEXT REQUIRED GATE = G-F5
```

Adjudicated by Soren Planck on 2026-08-11 on the evidence of workflow run
31521948686 (job 93880878036) executed at
`main@593364b9d11cdb0843c5d732a9446a105d451860`, tree
`aa2153821272910cabf7553b99328a370ae79920`, artifact 9114597700, artifact
SHA-256 `e646f63e42f7c0433e8699dd7c6a3efc365155a5732bbebb85891e94ada88e00`.
Recorded as decision D-026 in Foundation Document v0.16 §12.1.

## 7. Declarations

```text
DOM_SIM_IS_REAL_DOM=false
DOM_SCRIPTLESS_TOUCHED=false
DOM_CORE_TOUCHED=false
DOM_CONTRACTS_TOUCHED=false
DOM_WALLET_TOUCHED=false
MAINNET_USED=false
PRIVILEGED_ACTIONS=0
PRODUCTION_CODE_MODIFIED_BY_THIS_CLOSURE=false
NEW_TRANSACTIONS_BROADCAST_BY_THIS_CLOSURE=false
```
