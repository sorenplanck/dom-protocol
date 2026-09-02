# F7 Common-Wallet Claim/Refund Payout Handoff Decision

Status: laboratory implementation decision  
Wallet baseline: `dom-wallet-v3` 0.3.2  
DOM authority before the combined overlay: `dom-protocol`
`6a295fddf4e6a3afd6cf0f3fdb1e3a636a2f3d71`

## Problem

The real DOM claim and refund transactions spend the same collaborative
2-of-2 confidential output. Each has one ordinary Wallet V3-owned beneficiary
output, while both participants still need public transaction-offset and local
kernel-signing contributions. Wallet V3 previously had no durable way to
construct or export those components outside an ordinary Slate transfer.

Generating the output in a transient harness is unsafe. A crash could replace
its blinding, proof, offset or recovery coordinate, producing a different
template after a refund was pre-signed. Exporting the payout blinding to solve
that problem would violate the Master secret-domain boundary.

## Context

For participant `i`, Wallet V3 owns a payout blinding `p_i` and a public
transaction-offset contribution `o_i`. It may derive only:

```text
e_i = p_i - o_i
```

The Scriptless lifecycle owns that same participant's shared-output blinding
share `r_i`. The authoritative DOM adaptor derives the participant-local
shared-output spend contribution:

```text
y_i = e_i - r_i = p_i - o_i - r_i
```

No wallet or harness operation may reconstruct the aggregate shared-output
blinding, expose any scalar, or duplicate the pinned DOM scalar arithmetic.

Template binding cannot happen before public payout components exist because
the authoritative template hash commits to those exact components. Signing
cannot happen after mere component export because the wallet must authenticate
the real template object and its frozen role, shared input, output, fee, lock
height, chain and session first.

## Decision

Wallet V3 implements a monotonic durable handoff for each `(session_id, role)`:

1. `scriptless_payout_prepare` burns a `SelfTransfer` recovery coordinate and
   persists a role-specific reservation before generating public material.
2. For the beneficiary, the official `RecoverableOutputBuilder` creates one
   normal Wallet V3 output with a Recovery Capsule v1 and canonical range
   proof. Beneficiary Claim and Refund use different coordinates even when
   their payout values are equal. A non-beneficiary uses explicit value zero,
   creates no output at all, and burns no recovery coordinate.
3. The pinned Slate arithmetic derives `e_i = p_i - o_i`; the pinned
   `SigningShareV1` validates it and exposes only `e_i*G`.
4. Exact canonical output bytes, public offset, public excess point, private
   `e_i` and output blinding are committed atomically in encrypted wallet
   state.
5. `scriptless_payout_prepare_kernel_excess_point` accepts the real opaque
   `SessionBlindingShareCapabilityV1`, verifies its complete DOM binding, and
   persists the binding digest and roster position as `SESSION_BOUND` before
   returning public-only `E_i - R_i`. No signing share is constructed or
   consumed on this pre-template path.
6. `scriptless_payout_export` accepts only `SESSION_BOUND` and commits
   `COMPONENTS_EXPOSED` before returning the exact public objects. Restart,
   retry, full rescan and reorg can only return the persisted bytes and public
   composed point. A changed DOM binding fails closed.
7. In the single-source combined overlay, template binding accepts the actual
   `ScriptlessTransactionTemplateV1`, not a caller-supplied hash. Wallet V3
   verifies the template's role, shared input commitment, exact payout output,
   frozen participant/offset roster position, complete ordered two-party offset
   and composed-excess point sets, aggregate offset/excess, shape, fee, lock
   height, chain and session, then persists the authoritative template hash,
   participant position and complete ordered public decomposition.
8. Only a `TEMPLATE_BOUND` reservation can create the non-serializable signing
   capability. Its sole composition operation accepts the matching opaque
   `SessionBlindingShareCapabilityV1`, invokes its authoritative
   `compose_shared_output_spend_signing_share_v1(e_i)` operation internally,
   and returns another opaque `SigningShareV1`.

The common wallet does not create the collaborative proof, funding output,
adaptor pre-signature, final signature, nonce, transcript, template, session
authorization or transaction. Those remain in the real DOM authorities.

## Durable lifecycle and failure behavior

```text
RESERVED -> PREPARED -> SESSION_BOUND -> COMPONENTS_EXPOSED -> TEMPLATE_BOUND
    |           |              |                   |                  |
    +-----------+--------------+                   +------------------+-> ABANDONED_RETAINED
       CANCELLED (only before public point)                             (no release)
```

- Identical `(session_id, role)` requests are idempotent. Changed frozen terms
  under that key fail closed.
- Claim requires lock height zero. Refund requires a nonzero future lock height
  when first prepared. Restart does not invalidate an already-prepared refund
  merely because the tip later reaches its lock.
- The real node fee policy is queried for exactly one shared input, the frozen
  aggregate payout-output count and one kernel before creating a new record.
- A value-zero request is a signer contribution, not a zero-valued output. It
  persists a fresh nonzero offset and `e_i = -offset_i`, exports `outputs=[]`,
  and never changes wallet balance. Constructing a confidential output with
  value zero is forbidden by this API.
- `PREPARED` may be explicitly cancelled because no component has left Wallet
  V3. The output/private material is erased, but its recovery coordinate and
  tombstone are retained permanently.
- `SESSION_BOUND` persists DOM's digest over chain, session, ordered roster,
  direction, participant index, nonzero terms, capsule and `R_i` before the
  first public `E_i-R_i` point is returned. Wallet V3 does not duplicate
  `terms_hash`; exact digest equality is the retry/restart authority.
- Wallet V3 accepts only DOM's final capsule-bound session capability. The
  provisional durable capability used to derive the deterministic decoy
  commit--reveal contribution cannot preview a payout kernel point, bind a
  template or compose a signing share. The selected Store must atomically bind
  the same encrypted primary and backup `r_i` record to the completed canonical
  capsule before this lifecycle can enter `SESSION_BOUND`.
- Once components are exposed, there is no local release edge. Abandonment
  retains output/private material until authenticated chain/session evidence
  proves a terminal. A caller-provided status, timeout or missing transaction
  is not release authority.
- Scanner adoption verifies the same recovery capsule, commitment, value,
  account and private blinding. A rewind reconstructs or rebinds the exact
  local output before encrypted state is committed.
- Claim and Refund never share a reservation, output ID, recovery coordinate,
  output commitment, offset or encrypted `e_i`.

## Alternatives considered

### Build payout outputs in the Interop harness

Rejected. The harness does not own Wallet V3 recovery coordinates, encrypted
generations, seed-derived recovery root, scanner adoption or spending evidence.

### Reuse one payout output for Claim and Refund

Rejected. It couples mutually exclusive transaction templates to one random
secret and one recovery coordinate, complicates restart/reconciliation and
violates the explicit role separation needed for pre-signed refund safety.

### Bind a caller-provided template hash

Rejected. A hash without the actual typed template does not prove role,
shared input, output membership, fee, lock or canonical DOM construction.

### Expose `e_i` through a callback or byte accessor

Rejected. A generic callback is equivalent to exporting wallet key material.
The final overlay exposes only one named opaque composition operation.

### Implement `e_i-r_i` inside Wallet V3

Rejected. Scalar semantics and zero handling are owned by pinned `dom-adaptor`.
Duplicating them creates a second cryptographic dialect.

## Invariants

1. A reservation is unique by `(session_id, Claim|Refund)`.
2. Beneficiary Claim and Refund for one session have distinct burned
   coordinates and output records; non-beneficiary contributions have neither.
3. Every exported output is a canonical, self-recovered Recovery Capsule v1
   output built by the official Wallet V3 path.
4. Re-export is byte-identical and object-identical after restart or scanner
   reconstruction.
5. The public offset is canonical and nonzero; aggregate offset arithmetic is
   performed only by the DOM authority and may legitimately produce zero.
6. Persisted `e_i` and `p_i` never enter public DTOs, serialization, `Debug`,
   errors or logs.
7. The shared-output share `r_i` is never persisted by the common wallet.
8. Only a real, verified and durably bound template can authorize opaque
   `e_i-r_i` composition.
9. Template role, shared commitment, output, fee, lock, shape, chain and
   session must all match the reservation.
10. No exposed reservation can be cancelled or silently regenerated.
11. No Scriptless metadata is added to DOM consensus objects or wire encoding.
12. Full scan/restart/reorg never converts a retained payout into a different
    output or makes its private material disappear while it remains required.
13. Concatenating both participants' payout vectors yields the exact frozen
    aggregate output count and at least one real positive-value output.
14. The aggregate positive payouts plus the one kernel fee equal the shared
    output value; a no-output signer gains or loses no wallet funds.
15. Participant position is the canonical position in the frozen two-entry
    roster and is independent of output position. A no-output signer therefore
    keeps its participant/offset position even though it has no output index.
16. Each wallet verifies that its persisted offset and locally composed excess
    point occupy its canonical roster slot. DOM's authoritative aggregates of
    both complete ordered sets must equal the template offset and kernel
    excess, preventing coordinator omission or substitution.
17. The complete DOM session-share binding is durable before either a
    beneficiary or no-output participant releases its public composed point;
    changing only `terms_hash` changes the digest and is rejected.

## Compatibility and security impact

The encrypted Wallet V3 schema gains a default-empty payout reservation list,
so existing generations deserialize unchanged. Ordinary Slate send, receive,
scanner, submission, proof and consensus paths are not modified. Payout
outputs are ordinary recoverable DOM outputs and can later be recognized and
spent through the same wallet scanner and spend path after canonical
confirmation.

The record contains secret payout material and is protected by the existing
authenticated encrypted generation. Custom `Debug` implementations redact the
record and private context. The public handoff contains only normal DOM objects,
chain/session binding, offset and public keys.

Fail-closed retention after exposure can preserve an unusable output record
longer than necessary if external orchestration aborts. That is an explicit
availability tradeoff until DOM provides a consumed, authenticated,
session-bound terminal token; it does not weaken fund safety.

## Tests and reproducible validation

The focused recovery test proves that payout construction uses the official
recoverable `SelfTransfer` path, validates its range proof and capsule, parses
the public offset and `e_i*G`, proves the no-output contribution is exactly
`e_i=-offset_i` through the pinned Slate arithmetic, rejects a wrong recovery
domain and redacts secret-bearing debug output. Domain tests prove Claim/Refund
coordinate separation, duplicate-role rejection and exact local-output
restoration. A focused reorg test removes a confirmed beneficiary projection,
reconstructs its exact retained commitment/value/blinding, and proves the
no-output signer still creates no wallet output.

The embedded-regtest test prepares Claim and Refund for one session across a
beneficiary wallet and a no-output signer, verifies exactly one aggregate
positive output, the shared-value payout-plus-fee equation, distinct canonical
beneficiary outputs, unchanged no-output wallet balance, exact
retransmission, cancellation only before exposure, durable DOM session binding,
exact public point reproduction after share rehydration and wallet restart,
whole-history rescan reconstruction, and fail-closed abandonment. The
combined-overlay test
additionally binds real DOM templates and exercises the opaque `e_i-r_i`
operation after the authoritative DOM worktree is frozen.

The focused in-memory `SharedBlindingVaultV1` is a unit-test boundary only. It
is not accepted as F7 durability evidence. The combined gate must create,
capsule-bind, restart and reopen each participant's share through the real
filesystem-backed `ContractsNonceVaultV1` before Wallet V3 previews or signs
either Claim or Refund.

```bash
CARGO_BUILD_JOBS=2 cargo test -p dom-wallet-core-recovery \
  scriptless_payout_uses_recoverable_self_transfer_and_opaque_excess

CARGO_BUILD_JOBS=2 cargo test -p dom-wallet-domain \
  scriptless_claim_and_refund_payouts_are_distinct_and_reorg_restorable

CARGO_BUILD_JOBS=2 cargo test -p dom-wallet-core \
  scriptless_reorg_restores_payout_and_preserves_no_output_signer_contribution

CARGO_BUILD_JOBS=2 cargo test -p dom-wallet-core --test g0_regtest \
  f7_scriptless_payouts_are_distinct_restart_safe_and_fail_closed \
  -- --nocapture

cargo fmt --all -- --check
CARGO_BUILD_JOBS=2 cargo clippy -p dom-wallet-core -p dom-wallet-core-recovery \
  -p dom-wallet-core-restore -p dom-wallet-domain --all-targets -- -D warnings
```

These commands must use the final single-source DOM overlay recorded in the F7
evidence manifest. No result from a mixed DOM source graph is acceptance
evidence.
