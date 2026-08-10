# Phases 2 and 3 — Status

Date: 2026-08-10
Branch: `feat/dom-protocol-g1-closed-cycle-property`
Scope: what is implemented and unit-tested, and what remains for the regtest
gates (G2, G3).

Phase 2 of `DOM-Scriptless-Cronograma-Implementacao-v1.md` is "the hard piece":
risk HIGH, weeks-to-a-month, gated by G2 in regtest. This file records the
deliverables that could be built and unit-tested here, and marks precisely what
still needs a running node.

## Deliverable status

| # | Deliverable | State | Where |
| --- | --- | --- | --- |
| 2.1 | Joint blinding — each party contributes `r_j`, nobody learns the sum | Component done; transport pending | `bulletproof_mpc.rs` (shares + aggregate), enforcement in `partial_commitment_pop.rs` |
| 2.2 | Collaborative Bulletproof over the real FFI (`tau_x`/`t_one`/`t_two`, `n_commits=2`) | Runs end to end internally, verified by the real DOM verifier | `bulletproof_mpc.rs` |
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

- **The per-`r_j` contribution transport** (2.1): exchanging the blinding
  contributions and commit-reveal across the wire belongs to the Phase 3
  session and transport layer, which does not exist yet.
- **Public MPC orchestration surface** (2.2): the round-1/round-2/finalize
  functions are `pub(crate)` and driven only by a test harness. A downstream
  driver should thread the partial-commitment PoK gate into round-1 admission
  so a share without a valid opening proof is rejected before the output is
  built.
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

## Machine-readable status

```text
PHASE2_2_1_JOINT_BLINDING = COMPONENT_DONE_TRANSPORT_PENDING
PHASE2_2_2_COLLABORATIVE_BP = INTERNAL_END_TO_END_DONE_PUBLIC_DRIVER_PENDING
PHASE2_2_3_DECOY_CAPSULE = DONE
PHASE2_2_4_PARTIAL_COMMITMENT_POK = DONE
PHASE2_G2_REGTEST_GATE = PENDING_RUNNING_NODE
PHASE3_3_1_CONTRACT_ENVELOPE = DONE
PHASE3_3_2_STATE_MACHINE = DONE
PHASE3_3_3_ATOMIC_PERSISTENCE = PENDING_CONTRACTS_STORE
PHASE3_3_4_DEADLINE_POLICY = DONE
PHASE3_G3_INTERRUPTION_MATRIX = PENDING_RUNNING_NODE
PRODUCTION = NOT_AUTHORIZED
MAINNET = DISABLED
REAL_FUNDS = PROHIBITED
```
