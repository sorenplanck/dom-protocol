# DOM Scriptless — Phase Status (Phases 2–5)

Date: 2026-08-10
Branch: `feat/dom-protocol-g1-closed-cycle-property`
Scope: what is implemented and unit-tested, and what remains for the regtest
gates (G2–G5).

Phase 2 of `DOM-Scriptless-Cronograma-Implementacao-v1.md` is "the hard piece":
risk HIGH, weeks-to-a-month, gated by G2 in regtest. This file records the
deliverables that could be built and unit-tested here, and marks precisely what
still needs a running node.

## Deliverable status

| # | Deliverable | State | Where |
| --- | --- | --- | --- |
| 2.1 | Joint blinding — each party publishes `R_i = r_i*G` + §4.2 PoK; `C = v*H + Σ R_i` (§4.3), scalar sum never formed (§1.2) | **Session layer done** | `collaborative_output.rs`, gate via `share_pop.rs` |
| 2.2 | Collaborative Bulletproof over the real FFI (`tau_x`/`t_one`/`t_two`, `n_commits=2`) | **Done** — public per-participant driver (§5.4/§5.5) over the internal rounds | `collaborative_range_proof.rs`, `bulletproof_mpc.rs` |
| 2.3 | Deterministic canonical decoy capsule | **Done** | `decoy_capsule.rs` |
| 2.4 | PoK of the partial commitment `C_j` | **Done** | `partial_commitment_pop.rs` |

## What was closed in this pass

- **2.3** — the decoy capsule is framed byte-identically to a real recovery
  capsule (`01 00 || nonce[12] || 50 00 || body[80]`), fixed by bilateral
  commit-reveal, derived deterministically from the signing share and session
  id so a restart cannot re-roll (closing the grinding channel), with
  equivocation and mirrored contributions failing closed. Six unit tests.
- **2.4** — the missing proof of knowledge of `r_j` behind each `C_j`, the
  Mimblewimble rogue-key gap. The blinding secret is a type distinct from the
  signing share; the challenge binds the statement, participant index, exact
  share, and nonce commitment. Six unit tests including the cancelling-share
  attack.
- **2.1 enforcement** — `verify_all_partial_commitments_v1` requires one valid
  opening proof per participant before the joint-blinding aggregate is trusted;
  summing to the target alone is not a defense. Missing, duplicate,
  out-of-range, and misindexed proofs fail closed.

## What remains, and why it is not here

- **Driver session layer (2.1) — DONE.** `collaborative_output.rs` implements
  the spec §4.2/§4.3 flow: each party publishes `R_i = r_i*G` with the §4.2
  share PoK (`share_pop.rs`, tag `DOM:scriptless-share-pop:v1`), every proof is
  validated, and `C = v*H + Σ R_i` is formed by point addition without ever
  taking the scalar sum (§1.2). This is the admission gate the driver needed;
  the earlier "PoK vs Pedersen" blocker was a misreading of which layer the
  proof lives in and is resolved (see `DRIVER-BLOCKER-POK-PEDERSEN.md`).
- **Driver Bulletproof round layer (2.2) — DONE.**
  `collaborative_range_proof.rs` exposes the §5.5 API method for method
  (`CollaborativeRangeProof`, `LocalBpSecrets`, `AggregateBpRound1/2`,
  `RangeProof739`) over the ratified backend phases, driving the §5.4 rounds:
  0A commit-reveal (`PendingCommonNonce`, reveals only accepted with the full
  commitment vector), 0B round-1 share commitments enforced at aggregation,
  round-1 `T1/T2` and round-2 `tau_x` aggregation, and finalization with the
  §5.4 exit checks (backend success, exactly 739 bytes, the existing
  `verify_with_extra_commit`, the statement's agreed commitment). The blinding
  injection unifies the layers: `LocalBpSecrets` fails closed unless the
  injected §4.2 share opens the statement's exact `commitment_shares[i]`
  (§5.1's `blinds_i = [r_i, -r_i]`). Every stage is take-once — a duplicate
  call fails closed without destroying material it did not consume. Five
  tests, including the full two-party choreography verified by the exact
  consensus call shape with the raw 96-byte capsule as `extra_commit`. Note
  for the §3.4 freeze: the 0B commitment is bound under the pre-existing
  `DOM:scriptless-bp-round1-commit:v1` (statement-hash context, strictly
  stronger binding) while §5.4 names the registered
  `DOM:scriptless-nonce-commit:v1` with purpose `"bp-r1"`; the divergence is
  recorded, not silently rewritten.
- **The per-`r_j` contribution transport** (2.1): exchanging `R_i`, the PoKs,
  and the common-nonce commit-reveal across a real E2E channel (§5.4 roda 0A,
  no coordinator sees plaintext) belongs to the Phase 3 transport, which is not
  yet wired to a network.
- **G2 exit gate**: two independent wallets construct and publish a shared
  output; consensus accepts it; it measures 872 bytes on the wire; no isolated
  participant can spend it. This requires a running regtest node and the wallet
  build, which this environment does not provide. It is the same class of gate
  as G0 (`DC-P1-G017`), which has never executed.

## Phase 3 — Session, transport, and state

Phase 3 makes the choreography survive crash, restart, and a slow counterparty.
Deliverables 1, 2, and 4 are pure logic and are implemented and unit-tested in
`contract_session.rs`; deliverable 3 and gate G3 need the store and a node.

| # | Deliverable | State | Where |
| --- | --- | --- | --- |
| 3.1 | Versioned off-chain contract envelope (session id, roles, transcript, anti-replay) | **Done** | `contract_session.rs` |
| 3.2 | Contract state machine, per-transition transcript evidence, restart resume | **Done** | `contract_session.rs` |
| 3.3 | Atomic persistence of finalized bytes | Pending | Contracts store (retained-capability fs) |
| 3.4 | Deadline policy derived in block height, not arbitrary | **Done** | `contract_session.rs` |

### Phase 3 — what remains, and why it is not here

- **3.3 atomic persistence**: the finalized-bytes-are-authority pattern is the
  Contracts store's job — its Linux retained-capability filesystem is where
  atomic rename and crash-prefix classification already live. Wiring the
  contract state checkpoints through that store is store-side work, not a pure
  adaptor concern.
- **G3 interruption matrix**: an interruption test at every protocol step,
  proving each cut either advances correctly or aborts releasing reserves with
  no lost funds and no wedged input. Like G2 and G0, this needs the store's
  process-death harness and a running node.

The state machine is built so that this gate is reachable: every transition is
ordered and transcript-bound, abort is always available from a non-terminal
stage, and `resume()` reconstructs the exact state from a durable checkpoint —
which is what an interruption test exercises once the durable layer exists.

## Phases 4 and 5 — Funding, refund, and conditional claim

Phase 4 makes money enter only after a guaranteed exit exists; Phase 5 adds the
conditional claim complementary to the timeout refund. The pure-logic gates are
implemented and unit-tested in `funding_authority.rs` and `contract_session.rs`;
the transaction construction, the fee ladder under a live relay, and the G4/G5
gates are node-side.

| # | Deliverable | State | Where |
| --- | --- | --- | --- |
| 4.1 | Inviolable order: funding authorized only after refund presigned | **Done** (typestate) | `funding_authority.rs` |
| 4.2 | Bilateral backup gate before any funding (C2 consequence) | **Done** | `funding_authority.rs` |
| 4.3 | Escalating-fee refund ladder | Pending | node/relay |
| 5.1/5.2 | Adaptor claim shifted by `T`; observer extracts `t`, checks `t*G == T` | Present since Phase 1 | `adaptor.rs` |
| 5.3 | Claim floor: minimum margin `H_refund − claim_height` | **Done** | `contract_session.rs` |
| G4/G5 | Simulated abandonment / full two-terminal cycle in regtest | Pending | node |

### Phases 4/5 — what remains, and why it is not here

- **4.3 fee ladder**: Mimblewimble has no RBF and the fee is frozen in the
  signed message, so a refund can age below the relay minimum. The remedy is a
  ladder of refunds at escalating fees — real signed transactions broadcast
  under a real relay policy, node-side.
- **G4**: simulated abandonment at every step; nobody loses funds, or the refund
  unlocks at `H_refund` and is accepted first try, reproducing O-03 over the
  shared output. Needs regtest.
- **G5**: full cycle with both terminals — the happy path with byte-verified
  extraction, and the refund without revelation — plus an adversarial
  near-deadline claim. Needs regtest.
- **Dandelion++ interaction** (part of 5.3): studying the stem-phase timing of
  the `t` reveal is analysis, not code; the claim-floor margin is the code part
  and is done.

The adaptor mechanics the claim relies on — `presign`/`adapt`/`extract` and the
`t*G == T` check — have existed since Phase 1 (`adaptor.rs`), covered by the
SCAD0 vectors and the closed-cycle property test.

## Cycle closure — what this development cycle delivered

This cycle went beyond adding deliverables: every module written in it was
audited source-first against the master specification, and the audit found real
defects that are now fixed. The full record is in
`docs/scriptless/AUDIT-SELF-WRITTEN-MODULES.md`.

**Output-correctness fixes** (these would have broken a real shared output):

- the collaborative proof bound a 32-byte `extra_commit` while consensus verifies
  with the raw 96-byte capsule — the shared output would have been rejected;
- the aggregate folded the value into `commitment_shares[0]` instead of the §4.2
  pure `R_i` with `C = v·H + Σ R_i` (§4.3).

**Protocol-order fixes** (adjudicated to the master specification):

- funding is authorized from `ClaimPresigned`, after the refund is co-signed AND
  the claim adaptor is pre-signed (§7.2 steps 5/7-8/9, §7.3), not from
  `RefundPresigned`;
- abort releasing reserves is confined to the pre-funding stages (§9.3); a funded
  contract exits only through the claim or the refund;
- the claim floor uses a distinct claim confirmation margin, strictly smaller
  than the refund placement margin, so the safe claim window is non-empty.

**Protocol-hygiene fixes:**

- §8.5 idempotence/equivocation: typed `Equivocation`/`Replay`/`SequenceGap`/
  `ForkedTranscript`, an idempotent `DuplicateAck`, and a `FailedClosed` terminal
  that preserves the equivocation evidence;
- the decoy capsule derives its framing from the DOM capsule constants instead of
  magic numbers, so it cannot silently diverge and break §1.3;
- `docs/HASH_DOMAINS.md` now exists as the §3.4 registry (PROPOSED; the freeze is
  gated on G0).

**What remains is node-side, by construction.** Every pure-logic deliverable that
can be built and unit-tested without a running node is built and unit-tested. The
remaining items — G0, G2, G3, G4, G5, atomic persistence (3.3), the fee ladder
(4.3), the per-`r_i` transport, and the `DomainTag` freeze — all require a
running node, a real relay, or the G0 hash registry, and are enumerated with
their exact steps in `docs/scriptless/REGTEST-GATES.md`.

## Machine-readable status

```text
PHASE2_2_1_JOINT_BLINDING = SESSION_LAYER_DONE_SPEC_4_2_4_3
PHASE2_2_2_COLLABORATIVE_BP = DONE_PUBLIC_DRIVER_SPEC_5_4_5_5
PHASE2_2_3_DECOY_CAPSULE = DONE
PHASE2_2_4_PARTIAL_COMMITMENT_POK = DONE
PHASE2_G2_REGTEST_GATE = PENDING_RUNNING_NODE
PHASE3_3_1_CONTRACT_ENVELOPE = DONE
PHASE3_3_2_STATE_MACHINE = DONE_INCLUDING_8_5_EQUIVOCATION_AND_FAILED_CLOSED
PHASE3_3_3_ATOMIC_PERSISTENCE = PENDING_CONTRACTS_STORE
PHASE3_3_4_DEADLINE_POLICY = DONE
PHASE3_G3_INTERRUPTION_MATRIX = PENDING_RUNNING_NODE
PHASE4_4_1_FUNDING_ORDER = DONE_GATED_FROM_CLAIMPRESIGNED_SPEC_7_2_7_3
PHASE4_4_2_BILATERAL_BACKUP = DONE
PHASE4_4_3_FEE_LADDER = PENDING_RELAY
PHASE4_G4_ABANDONMENT_MATRIX = PENDING_RUNNING_NODE
PHASE5_5_1_5_2_ADAPTOR_CLAIM = PRESENT_SINCE_PHASE1
PHASE5_5_3_CLAIM_FLOOR = DONE_DISTINCT_CLAIM_CONFIRMATION_MARGIN
PHASE5_G5_TWO_TERMINAL_CYCLE = PENDING_RUNNING_NODE
SELF_AUDIT = COMPLETE_SEE_AUDIT-SELF-WRITTEN-MODULES
HASH_DOMAIN_REGISTRY = CREATED_PROPOSED_FREEZE_GATED_ON_G0
PRODUCTION = NOT_AUTHORIZED
MAINNET = DISABLED
REAL_FUNDS = PROHIBITED
```
