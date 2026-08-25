# F3 ↔ F5 Reconciliation Plan

**Branch:** `feat/f3-f5-reconcile` (based on current `main`).
**Status:** Phase A landed on the branch; Phase B pending an architecture
decision by the operator.

## The core finding

`feat/f3-evm-leg` branched from `9c1778c` ("motor F2 v0.5"), **72 commits
behind `main`**. Since then `main` closed G-F2 with the normative F2 §24
rewrite and shipped all of F5. The two lines diverge in ways that are NOT
a mechanical merge:

| Component | `main` (trunk: F1/F2/F5) | `feat/f3-evm-leg` |
|---|---|---|
| F2 engine (`kaystra-core`) | **F2 §24 v1.0**: `SettlementEngine`, `ChainSourceV1`, `EffectSinkV1`, `ingest.rs`/`settlement_engine.rs`/`store_port.rs`/`terms.rs`/`types.rs` | superseded **v0.5**: `Engine`, `ChainPort`, `Journal`, `InMemoryJournal` |
| `store` | SQLite (rusqlite) — F1/F2 + F5's `btc-vault`/`btc-observer` build on it | from-scratch file-journal (`engine.rs`/`journal.rs`/`lock.rs`/`crc32.rs`) |
| dom-adaptor pin | `a1825639` (F1/F2/F5 all validated on it) | `180b731` (older) |
| `guards.sh` | ~150 lines (I2/I6/I14 + F5 guards + I14-ALLOW) | 1847 lines (mechanical I1..I15) |

`main`'s F2 §24 engine is the **ratified G-F2 = PASS** substrate. F3's
engine and file-journal store are superseded by it. Therefore the
reconciliation brings the F3 **EVM leg forward onto `main`**, it does not
carry F3's engine/store backward.

## What decouples cleanly (Phase A — DONE on the branch)

The bulk of the F3 value has **zero dependency on the F2 engine** and
ported cleanly:

- **`crates/adapters/evm`** (8566 lines: ABI, RPC, evidence, binding,
  mock, reorg, finality, attest, cursor). Depends only on
  `counterparty-api` + `k256`/`sha3`/`serde_json`/`ureq`. Builds on `main`
  and **87 tests pass**. (Only fix needed: `license.workspace` →
  `license-file.workspace` to match `main`'s manifest convention.)
- **`contracts/`** full suite (`ConditionLockV2` + `Core` + `ERC20` +
  `LockBinding` + the Foundry tests/invariants + `Deploy.s.sol`).
  **184 Foundry tests pass** (170 unit/fuzz + 14 invariant), verified with
  OZ `v5.1.0` / forge-std `v1.9.6` and solc `0.8.24`.
- **Scripts + runbook**: `scripts/{e2e_anvil,sepolia,sepolia_deploy,
  sepolia_e2e}.sh`, `docs/SEPOLIA-RUNBOOK.md`. The Anvil E2E ran green
  (11/11 scenarios) on the F3 branch.
- **CI**: the `contracts` job switched from the single-file Node compile
  to Foundry (`forge fmt/build/test/coverage`) + the independent Node
  ecrecover check — exactly the "F3: replace with forge test" TODO that
  was already in `main`'s workflow.

Kept from `main` unchanged: the SQLite `store`, the F2 §24 `kaystra-core`,
the `a1825639` pin, and the F5 stack.

## What remains (Phase B — needs the operator's steer)

Only **`crates/f3-harness`** (~4000 lines: `port`/`seam`/`routes`/
`evm_sim`/`gas`/`timelock`/`outbox`) is coupled to the superseded v0.5
engine (`ChainPort`/`Journal`). It is the G-F3 gate integration: it
composes the engine + `adapter-evm` + `dom-leg` + `dom-sim` and proves the
wiring. Bringing it onto `main` requires re-expressing that glue against
`main`'s `SettlementEngine`/`ChainSourceV1`/`EffectSinkV1` — a genuine
port, not a merge. Options:

- **B1 — Port the harness onto `main`'s F2 §24 engine** (recommended).
  The EVM adapter, contracts and E2E are already forward; this rewrites
  only the ~2000 lines of harness glue so G-F3 drives the ratified engine.
  Highest fidelity; most work.
- **B2 — Vendor a minimal v0.5 engine shim** used only by `f3-harness`.
  Fast, but forks the settlement state machine — two engines in one repo,
  which the project's neutrality/one-authority rules discourage.
- **B3 — Land Phase A now; schedule the harness port as its own unit.**
  The EVM leg substrate is on `main` and green; G-F3's turnkey harness
  and the Sepolia close-out follow in a dedicated pass.

`guards.sh` reconciliation rides with Phase B: adopt F3's I1..I15
mechanical battery (a superset of `main`'s I2/I6/I14) or extend `main`'s
with F3's EVM-specific invariants — decided once the harness lands.

## Phase B design finding — the ported gate must be re-conceived, not translated

A full read of `f3-harness` against `main`'s ratified §24 engine turned up a
**structural** obstacle that a mechanical port cannot get past, and that
changes what G-F3 asserts. It is recorded here so the choice is made with
eyes open, not discovered mid-rewrite.

**How the v0.5 gate is wired.** In `feat/f3-evm-leg`, `EvmChainPort`
*implements* `kaystra_core::ChainPort`, and the gate composes it as
`Engine::start(lock_id, policy, port, InMemoryJournal::default())`. That is:
**the v0.5 engine drives the EVM leg as its own chain** — it observes the
EVM `ConditionLockV2` (funding/claim/refund), and `submit_funding` /
`submit_refund` act on the EVM leg. The DOM leg (`DomSimPort =
f2_harness::SimPort`) is the *auxiliary*, driven by the routes/seam, not by
the engine. The central G-F3 claim — *"the EVM leg settles end to end through
the frozen engine, driven only by finalized observations"* — is a claim
about the engine driving the **EVM** leg.

**Why that cannot be carried onto `main`.** `main`'s §24
`SettlementEngine::open()` (`settlement_engine.rs:255-261`) binds its
`ChainSourceV1` to **`terms.dom_leg`**: it rejects the source unless
`chain.chain_id() == terms.dom_leg.chain_id`, and rejects the settlement
unless `terms.dom_leg.deadline` is `TimelockSpec::BlockHeight` (else
`UnsupportedTimelockDomain`). The EVM leg is the **counterparty** leg
(`LegRole`), and its timelock is `TimelockDomain::Timestamp`. So the ratified
§24 engine **structurally models the DOM leg and only the DOM leg**; it
cannot be made to drive the EVM leg without editing the engine — and the
engine is ratified G-F2 = PASS and must not be touched (D-… / neutrality).

**What this forces.** Under §24 there is exactly one admissible composition
(call it **B-DOM**): the engine drives the **DOM leg** (dom-sim, BlockHeight,
`f2-harness`'s `SimSettlementChain` + `SimEffectSink`, already on `main` and
green for G-F2), and the **EVM leg is the counterparty** — observed by
`adapter-evm`, its finalized `Claimed(t)` feeding the DOM claim consumption
(`Effect::RequestClaimConsumption` + the routes/seam). This is the actual DOM
Interop topology (DOM is the authority; EVM is a counterparty chain), and it
is the only shape that keeps a single ratified settlement engine.

**What changes, and what does not.** No security check is dropped. Every
route validation survives verbatim — finality before fact, `0 < t < n`,
`address(t·G) == adaptorAddress`, `binding`/`lockId` re-derivation, `t` opens
the pre-signature's `T`, the four timelock margins, and the adapt-vs-extract
asymmetry (EVM→DOM never calls `extract`). What changes is the **subject of
the engine-driven end-to-end claim**: on `main` the engine settles the DOM
leg and the EVM leg is settled through the adapter + routes, not "through the
engine." G-F3's wording, its gate script, and the harness's engine-facing
glue (`EvmChainPort`'s `ChainPort` impl; `outbox.rs`, which is built on the
v0.5 `Journal`/`InMemoryJournal` that do not exist on `main`) are rewritten
against this shape. The engine-independent 90% of `f3-harness` (routes, seam,
timelock, error, gas, shared, evm_sim broadcasters) ports unchanged.

This is not a decision the executor may take alone: it re-words a gate the
authority ratifies. Options B1/B2/B3 above still stand; **B1 now means
"implement B-DOM"**, and it is the recommended path precisely because it is
the only one that neither forks the engine (B2) nor leaves G-F3's substrate
half-expressed (B3). Ratification of the re-worded gate claim is the
operator's, per M.16.1 / the one-authority rule.

## The real blocker — no export path for the revealed adaptor secret

> **Correction.** An earlier revision of this section blamed the divergent
> `dom-adaptor` pin and proposed re-pinning `a1825639 → 180b731` ("P1"). That
> was wrong on both facts and is retracted here. `180b731` is the **older**
> pin: `b8e10c1` moved `main` *from* it *to* `a1825639` on 2026-08-10 as a §9.2
> ratification event, and `feat/f3-evm-leg` carries `180b731` only because it
> branched on 2026-08-06, before that event. Re-pinning to `180b731` would be a
> regression that also drops `from_session_authority` (the very API the F1
> vault needed), and it would not unblock anything — see below.

Implementing B-DOM was carried up to the point of building. The engine-facing
glue ported cleanly (the `store`-backed idempotent outbox, the EVM-leg driver,
the DOM leg reused from `f2-harness`). The blocker is in the harness's
`routes`/`seam`, and it is **not** the pin:

`main`'s `dom-leg` states it (`round.rs:830-836`):

> **PIN BLOCKER**: `AdaptorSecret` … and the `SecretScalar` it wraps expose no
> bytes. The DOM leg can prove it extracted the right `t` by comparing the
> public POINT, but CANNOT deliver `t` as `RevealedSecretBytes` to the other
> leg.

and `feat/f3-evm-leg`'s own `dom-leg/src/crypto.rs` confirms the **same** thing
holds at `180b731`: *"`AdaptorSecret` deliberately exposes no byte export, and
neither does `dom_crypto::SecretScalar`: at the pinned rev there is no public
path from a verified extraction to the 32 bytes of `t`."* That branch did not
get the bytes from a different pin — it **recomputes** them as
`t = s_final + (n−1)·ŝ` via `dom_crypto::secret_scalar_mul_add_assign`, after
the authority's `extract` has verified, accepting the result only if `t·G`
matches both the extracted and the committed point. `a1825639` is `180b731`
plus one additive commit with "no cryptographic change", so that technique
works identically on the current pin.

So the two F3 directions split like this, on `a1825639`:

- **EVM→DOM is feasible today.** `t` arrives from a finalized on-chain
  `Claimed` log as bytes and `AdaptorSecret::from_be_bytes` exists, so the DOM
  pre-signature can be *adapted*. Only `routes`/`seam` need re-expressing
  against `main`'s typed `dom-leg`.
- **DOM→EVM needs an export path.** It must *extract* `t` and hand it to the
  EVM leg as `claim(lockId, t)` calldata — 32 bytes. Neither pin offers one.

### The correct problem, and how it is being closed

The requirement is not "which revision" but: **the DOM authority must offer a
blessed path from a verified extraction to the 32 bytes of `t`.** That scalar
is public by construction — it is `s − ŝ` over two already-published
signatures, so any observer can compute it — and delivering it is precisely
what an adaptor-signature swap exists to do.

Two ways to satisfy it:

- **A — Recompute in `dom-leg` (no upstream change).** Port
  `feat/f3-evm-leg`'s `crypto.rs` onto `a1825639`. Nothing ratified moves.
  Cost: the interop repo performs scalar arithmetic to recover secret material.
  Even using the DOM's own primitive with a double point cross-check, it puts
  adaptor arithmetic in a second place — weaker against I15.
- **B — Add the export upstream (chosen).** Patch `dom-protocol` with an
  additive API that ties the byte export to a fully verified extraction, keep
  `SecretScalar` sealed, re-run conformance, pin forward and ratify — the same
  §9.2 procedure `b8e10c1` already executed. This keeps the adaptor arithmetic
  in exactly one place and makes the interop requirement an **explicit, tested
  guarantee upstream**, so a future revision cannot silently withdraw it.

**Option B is in flight** as patch **P1** in `docs/patches/dom-protocol/`.
It adds `AdaptorPreSignatureV1::extract_revealed_secret_be_bytes` and
`dom_crypto::scriptless_extract_adaptor_secret_be_bytes`; the existing
`extract` delegates to the same verification and the same extraction, so the
export path can never check less than the sealed one. `SecretScalar` gains no
accessor. Applying it upstream and moving the pin remain the operator's acts.

### Where this leaves Phase B

The engine-facing B-DOM port is real and is preserved off-branch (the
`store`-backed outbox, the EVM-leg driver, the reused DOM leg); it is not
committed because the crate cannot compile against `main`'s `dom-leg` until
the export path exists. The branch stands at **Phase A, green.** Once P1 is
applied and the pin moves forward, `routes`/`seam` are re-expressed against
`main`'s `dom-leg` and both F3 directions land.

No pin is moved, and no gate is re-worded, by this document.

## Governance

No decision is ratified by this document. The pin stays `a1825639` unless
the operator chooses to move it (a new decision). Bringing the EVM leg
forward touches no ratified F2/F5 artifact; `SettlementEngine` and the
SQLite store are unchanged.
