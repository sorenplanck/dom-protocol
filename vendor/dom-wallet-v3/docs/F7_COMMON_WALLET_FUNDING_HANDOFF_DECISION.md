# F7 Common-Wallet Funding Handoff Decision

Status: laboratory implementation decision  
Wallet baseline: `dom-wallet-v3` 0.3.2  
DOM authority laboratory checkpoint: `dom-protocol` `6a295fddf4e6a3afd6cf0f3fdb1e3a636a2f3d71`

## Problem

The real DOM Scriptless funding transaction needs ordinary wallet inputs,
recoverable change, a public offset allocation, and the corresponding local
kernel-excess contribution. Wallet V3 previously offered those properties only
inside the interactive Slate send flow. The F7 transaction lifecycle cannot use
that Slate as a substitute because the shared output and collaborative proof
belong to the independent Scriptless session.

The missing boundary also created a fund-safety risk: selecting an input in the
Scriptless store without reserving it in the common wallet would allow a normal
send to select the same output after a restart or concurrent request.

## Context

The Master specification requires the funding transaction to be an unchanged
DOM transaction, prohibits reconstruction of the aggregate shared blinding,
requires durable state before exposure, and delegates cryptography and
consensus to pinned DOM authorities. The authoritative F7 lifecycle accepts
canonical `TransactionInput` values, ordinary change `TransactionOutput`
values, one unsigned kernel, and one public transaction offset.

For participant `i`, the common wallet owns only:

```text
e_i = change_blinding_i - sum(input_blindings_i) - offset_i
```

The Scriptless layer owns the participant's shared-output share `r_i`. The
authoritative composition is participant-local:

```text
x_i = r_i + e_i mod n
```

No component may construct or export `sum(r_i)`.

## Decision

Wallet V3 now provides a narrow monotonic funding handoff:

1. `scriptless_funding_prepare` atomically reserves confirmed spendable UTXOs
   and, when needed, burns a recovery `Change` coordinate before construction.
   The request also freezes the exact canonical collaborative-output
   commitment that funding must create.
2. The existing recovery-capable DOM output builder creates exact change and
   its proof envelope. The pinned Slate scalar authority computes `e_i` and the
   pinned `dom-adaptor::SigningShareV1` validates and owns it opaquely.
3. Exact public inputs, change output bytes, offset, and `e_i*G` are persisted
   in the same encrypted wallet generation as the private context.
4. `scriptless_funding_prepare_kernel_excess_point` accepts the real opaque
   `SessionBlindingShareCapabilityV1`, verifies its complete DOM binding, and
   persists that binding digest and roster position as `SESSION_BOUND` before
   returning the public-only `R_i + E_i` point. It never constructs a signing
   share on this pre-template path.
5. `scriptless_funding_export` accepts only `SESSION_BOUND`, persists
   `EXPORTED` before returning public objects, and reconstructs the same
   objects after restart. A changed DOM binding, including a change only to
   `terms_hash`, fails closed against the persisted digest.
6. The combined F7 overlay binds the actual typed DOM funding template and
   persists its authoritative hash, canonical participant position and the
   complete ordered two-entry public offset and kernel-excess point sets.
7. Only that bound reservation can produce a short-lived, non-serializable
   capability. Its only operation accepts the matching opaque
   `SessionBlindingShareCapabilityV1` and invokes the authoritative
   participant-local `r_i + e_i` composition. It has no raw scalar accessor,
   generic callback, `Debug`, `Clone`, or serialization implementation.
8. The common wallet does not implement scalar addition, Schnorr signing,
   adaptor signing, nonce management, collaborative Bulletproofs, template
   hashing, offset aggregation, point aggregation, or consensus.

The non-paying participant still contributes to the two-party kernel. Its
explicit `local_debit_noms = 0` request selects no input, creates no change,
burns no recovery coordinate, generates a fresh canonical nonzero public
offset `o_i`, and persists the opaque contribution `e_i = -o_i`. This is not a
mock input or a fee subsidy: the payer's `local_debit_noms` alone includes the
shared-output value and the full funding fee. The aggregate template remains
required to contain at least one real input and the one real shared output.

Normally both participants receive the same frozen aggregate input/output
counts. A zero-debit reservation may also encode its strictly local input count
as zero without becoming invalid, but that local description is never evidence
of a valid aggregate transaction. Typed-template binding independently requires
the real funding template to contain at least one aggregate input, exactly one
shared output, and the globally frozen shape.

`expected_output_count` always includes that one global shared output exactly
once. A payer with no change therefore requires count one, a payer with one
ordinary change output requires count two, and a zero-debit participant accepts
the same aggregate count without claiming or adding another shared output.

`local_debit_noms` is fixed by the Scriptless terms. Across funding
participants its sum must equal the shared output value plus the single funding
fee. The wallet checks the frozen aggregate shape against the real node fee
policy. The authoritative `ScriptlessTransactionTemplateV1` remains responsible
for the complete public balance equation and transaction verification.

## Reservation and failure semantics

The durable lifecycle is monotonic:

```text
RESERVED -> PREPARED -> SESSION_BOUND -> EXPORTED -> TEMPLATE_BOUND
    |           |              |            |              |
    +-----------+--------------+            +--------------+-> ABANDONED_RETAINED
       CANCELLED (only before public point)                         (no release)
```

- `RESERVED` already excludes every selected output from ordinary coin
  selection. A crash before construction resumes by `session_id`.
- `PREPARED` contains exact components but nothing has left the wallet. An
  explicit cancellation may release inputs, erase the private contribution,
  remove unconfirmed change, and retain the burned-coordinate tombstone.
- `SESSION_BOUND` contains the complete DOM binding digest and canonical
  participant position. The digest commits to chain, session, ordered roster,
  direction, participant index, nonzero terms, capsule and `R_i`; it is durable
  before Wallet V3 returns `R_i + E_i`. This is already exposure and therefore
  has no cancellation/release edge.
- `EXPORTED` may only retransmit the exact persisted components. Cancellation
  cannot release its inputs.
- `TEMPLATE_BOUND` authenticates the real DOM role, shared output, fee,
  PLAIN/lock-zero kernel, global shape, local membership, aggregate offset,
  aggregate excess, chain, session and participant roster position before any
  opaque signing share can be composed. The accepted ordered public
  decomposition is retained beside the template hash for exact retries.
- `ABANDONED_RETAINED` records operator abandonment but remains reserved until
  authoritative chain/session reconciliation proves an economic terminal.
- A confirmed spend clears the output-level reservation because the output is
  no longer selectable. A reorg that makes it unspent restores the reservation
  and reconstructs pending change from encrypted context.
- A whole-history rescan may temporarily remove the wallet-local UUID for an
  input above the rewind point. The reservation remains authoritative by its
  canonical commitment; each scanner batch rebinds a rediscovered local record
  and marks it unavailable before committing that batch.

Requests are idempotent by the 32-byte Scriptless `session_id`. Identical terms
resume the existing reservation; different terms under the same ID fail
closed. Wallet V3's existing single-writer lock and generation compare-and-swap
protect process concurrency, while the session key prevents logical duplicate
selection inside one writer.

The laboratory intentionally has no API that releases an exposed reservation
merely because an untrusted caller says the off-chain contract aborted. The
current DOM `ContractStateV1` can reach the pre-funding `Aborted` terminal but
does not yet return a consumed, session-bound terminal authority that the
common wallet can authenticate. Until that narrow authority exists, an exposed
but unpublished reservation remains `ABANDONED_RETAINED`; this can require
operator reconciliation, but it cannot create a double spend. The combined F7
funding path therefore keeps exposed inputs reserved unless canonical scanner
evidence proves their spend/reorg lifecycle.

## Shared-blinding custody ordering

The canonical recovery capsule cannot be named when `r_i` is first generated:
its deterministic decoy contribution is derived from that same secret share,
and the final capsule exists only after bilateral commit--reveal. Requiring the
final capsule hash in the initial seal operation would therefore be circular.

The combined overlay must use DOM's two-stage custody authority:

1. generate and durably seal a fresh share under the complete provisional
   chain/session/roster/direction/participant/terms identity;
2. use the provisional capability only to obtain `R_i` and the deterministic
   decoy commit--reveal contribution;
3. combine the canonical capsule, then have the selected Store atomically
   compare-and-swap the same encrypted primary and backup record to the exact
   capsule-bound identity; and
4. only then obtain `SessionBlindingShareCapabilityV1` for PoK, collaborative
   proof, wallet kernel-point preview, template binding or scalar composition.

Wallet V3 never accepts the provisional capability. Its first interaction is
with the final capsule-bound capability, whose complete DOM binding digest is
persisted before `R_i + E_i` is returned. This preserves the anti-grinding
share across the transition without importing, regenerating or rebinding raw
scalar bytes in the wallet or harness.

## Alternatives considered

### Reuse an ordinary Slate as the funding template

Rejected. A normal receiver output is not the verified collaborative shared
output, and mutating a finalized Slate transaction would invalidate its balance
and signatures.

### Let the specialized Scriptless store select wallet UTXOs

Rejected. It cannot participate in the common wallet's encrypted generation,
coin selection, recovery metadata, writer lock, or restart reconciliation and
would permit double selection.

### Export input/change blindings to the orchestrator

Rejected. Raw wallet secrets are unnecessary. The public transaction objects
and an opaque participant-local signing capability are sufficient.

### Implement scalar composition or transaction validation in Wallet V3

Rejected. Those operations already belong to pinned DOM cryptographic,
Scriptless, serialization, and consensus authorities. Duplicating them would
create a second dialect.

### Point the wallet permanently at a dirty F7 worktree

Rejected. The wallet remains pinned to the immutable DOM revision. The final
laboratory uses one controlled overlay only after the authoritative DOM changes
are frozen into a local commit.

## Invariants

1. A selected input belongs to at most one active wallet reservation.
2. No active reserved input is returned by ordinary wallet coin selection,
   including after restart.
3. No cancellation releases an input after public component exposure.
4. Re-export is object- and byte-identical to the persisted first export.
5. Change uses the ordinary Wallet V3 recovery capsule, proof type, verifier,
   scanner, and spending-secret persistence.
6. The wallet contribution `e_i` never appears in a public DTO, serialized
   handoff, log, `Debug`, or error.
7. The shared-output share `r_i` never enters common-wallet persistence.
8. Only `dom-adaptor` may combine `r_i` and `e_i`; only for the same participant.
9. The transaction offset and excess public key are public DOM transaction
   material and reveal no spend scalar.
10. No Scriptless marker, session ID, or metadata is added to DOM L1 objects.
11. An untrusted/corrupt persisted component must pass exact canonical decode,
    change range-proof verification, scalar/point parsing, and encrypted/public
    key agreement before re-export.
12. A reorg never makes an exposed funding input silently spendable.
13. Off-chain abort cannot release exposed inputs without a consumed,
    session-bound DOM terminal authority; no caller-provided boolean or status
    string is accepted as equivalent evidence.
14. A zero-debit signer has no selected input, change, wallet output or
    recovery coordinate and its wallet balance is invariant across the
    handoff.
15. The exact shared-output commitment is persisted before component exposure;
    a same-session request naming another commitment fails closed.
16. The sum of explicit participant debits equals shared-output value plus the
    one funding fee; the zero-debit participant is never assigned that fee.
17. Both ordered public offset contributions and both ordered local composed
    excess points are checked: the wallet's slot must match its persisted
    component, and the authoritative DOM aggregates must equal the template
    offset and kernel excess. A coordinator cannot omit or replace a signer.
18. The complete DOM shared-share binding digest is durable before the first
    public composed point. Wallet V3 does not maintain a parallel terms dialect:
    it requires nonzero terms and exact digest equality on every retry.

## Compatibility and security impact

The change is additive. Ordinary Slate sends keep their current selection,
change, signing, serialization, and submission paths. The common-wallet
funding record is a default-empty field in the encrypted Wallet V3 state, so
existing state reads continue to work. No consensus, wire, genesis, mempool,
scanner, proof, signature, or transaction encoding changes.

The new record is included in Wallet V3 encrypted generations and backups. It
contains the ordinary wallet excess contribution and optional change blinding,
so custom `Debug` implementations redact the full context and all amounts.
Backups do not contain a reusable funding authorization; the independent
Scriptless store still owns refund-before-funding authority and nonce
tombstones.

The capability alone cannot sign: the authoritative Scriptless signer still
requires the participant's shared-output share, exact template/session
context, accepted nonce round, and durable one-shot nonce-vault permit.

The conservative exposed-abort rule may retain an input longer than necessary
until DOM publishes the authenticated terminal seam. This is an explicit
availability limitation, not a relaxation of fund safety or a blocker for the
combined funding transaction path.

## Combined-overlay integration contract

The combined F7 harness must use one Cargo source identity for `dom-adaptor`
across Wallet V3, DOM Contracts, and DOM Interop. A path overlay to an
uncommitted worktree is suitable only while developing the isolated lab. The
reproducible evidence run must first freeze the authoritative DOM worktree into
one local commit, record that commit in the evidence manifest, and apply the
same overlay to every workspace member. Mixing the immutable wallet pin with a
second `dom-adaptor` source would create distinct Rust types even if the source
text were identical and is not an acceptable integration.

For funding participants `A` and `B`, the driver performs the following exact
public composition, without handling any scalar bytes:

1. Prepare both wallets against the same chain ID, Scriptless session ID,
   exact shared-output commitment, funding fee, expected aggregate input count,
   and expected aggregate output count.
2. Freeze participant ordering and concatenate each participant's canonical
   inputs and ordinary change outputs in that order. Insert exactly one
   `VerifiedSharedOutputV1` at the route's frozen output position.
3. Require the actual aggregate input and output counts to equal, rather than
   merely fit below, the terms frozen before either wallet exposes material.
4. Supply the complete ordered two-entry public offset set. Each wallet checks
   that its roster slot equals its persisted `offset_i`; the authoritative DOM
   offset helper validates/aggregates the set, and the result must equal the
   template offset. The mathematically valid aggregate may be zero.
5. Give each wallet only that participant's durable opaque shared-output
   capability. Before template construction, Wallet V3 verifies its complete
   DOM binding, persists the DOM binding digest, and asks the DOM authority for
   the public-only `R_i + E_i` preview. No `SigningShareV1` is constructed or
   consumed at this stage.
6. Supply the complete ordered two-entry public points returned by those
   previews. Each wallet checks its local slot, the authoritative DOM point
   aggregation must equal the kernel excess, and the kernel must be canonical
   PLAIN with the negotiated fee, lock zero and all-zero signature placeholder.
7. Call `ScriptlessTransactionTemplateV1::funding`. Its real structure,
   range-proof, and balance checks must succeed before opening a signing round.
8. Bind that exact typed template in both wallets, then obtain the
   post-template funding capabilities. Each accepts only its already-bound
   session capability and invokes DOM's opaque `r_i + e_i` composition; no raw
   share or generic callback exists.
9. Fully construct and durably persist the refund and claim paths, including
   the refund signature and all nonce-vault tombstones required by the Master
   ordering, before issuing or consuming `FundingAuthorizationV1`.
10. Sign only the exact frozen template/transcript. Finalization must consume
   the authorization, pass the complete DOM verifier, persist the canonical
   transaction bytes before submission, and retransmit only byte-identical
   bytes after restart.

The composed share is key material, not signing authority. It may enter only
the production signer entry that consumes the accepted session authority and
cross-checks chain ID, session ID, local participant, two-entry roster,
purpose, template hash, kernel-message digest, and transcript before a
nonce-vault stage can begin. A generic Schnorr signer, caller-constructed
session context, or a second session using the same reservation is forbidden.
The wallet reservation ID and public components must be retained beside the
Scriptless store's session record so the driver can reject any cross-session
or cross-participant capability substitution before composition.

The DOM equation confirmed for this boundary is:

```text
outputs - inputs = kernel_excess + aggregate_offset*G + fee*H
e_i             = change_i - sum(inputs_i) - offset_i
x_i             = r_i + e_i
kernel_excess   = sum(x_i*G)
aggregate_offset = sum(offset_i) mod n
```

There is no additional funding subtraction term. The driver may compare public
points and canonical objects, but it must never receive `r_i`, `e_i`, `x_i`, a
wallet input blinding, an output blinding, a seed, or a nonce as bytes.

Claim and refund use a different local equation. For a participant allocation
of payout blinding `p_i` and transaction offset `o_i`, its kernel contribution
is `y_i = p_i - r_i - o_i`. This operation must remain a narrowly named,
opaque `dom-adaptor` authority; neither Wallet V3 nor the combined harness may
reimplement scalar subtraction. Likewise, public offset aggregation belongs to
the DOM authority rather than duplicated test arithmetic. The authoritative F7
DOM worktree now supplies both narrowly named opaque share compositions, the
public-only funding/spend point previews and canonical offset aggregation. The
final evidence run must consume those APIs through one frozen local DOM commit;
the immutable wallet base pin alone does not contain them.

An exposed reservation has deliberately no release edge in this contract. The
combined harness records `ABANDONED_RETAINED` on an off-chain failure and keeps
the inputs unavailable. A future release operation requires a consumed,
session-bound, authenticated DOM terminal token; a route-state enum, operator
flag, transaction absence, timeout, or unauthenticated RPC response is not
equivalent authority.

## Tests and reproducible validation

The real embedded-regtest test funds a recovery wallet through canonical
coinbase blocks, asks the real node fee policy, reserves production wallet
outputs, constructs canonical change, checks same-session retry, rejects
double selection, cancels only before exposure, re-exports identical objects,
restarts the full node and wallet, performs a real whole-history scanner replay,
rebinds the source by canonical commitment, rehydrates the same DOM session
share through its vault, reproduces the exact public composed kernel point, and
proves exposed abandonment retains the reservation. A second real wallet
on the same regtest chain contributes no input or output, preserves a zero
balance, proves its public contribution is exactly `e_i=-offset_i` through the
pinned Slate arithmetic, and re-exports its exact `offset_i`/`e_i*G` after
restart and rescan. The test also proves that a capability with the same public
share point but a different `terms_hash` is rejected by exact DOM binding
digest comparison.
The aggregate assertions require the payer's real inputs plus the shared
output to match the frozen shape and require the payer debit alone to equal the
shared value plus fee. A focused reorg test
rewinds a spent funding input and confirmed change, then verifies restoration
of the input reservation and pending recoverable change.

The in-memory `SharedBlindingVaultV1` used by focused Wallet unit tests is only
a type-boundary fixture. It is not durable F7 evidence and must not satisfy the
gate. The combined F7 evidence run must exercise the same pending-to-capsule
transition, restart import and backup acknowledgement through the real
filesystem-backed `ContractsNonceVaultV1`, then pass its final capability into
these Wallet bindings.

```bash
CARGO_BUILD_JOBS=2 cargo test -p dom-wallet-core --test g0_regtest \
  f7_common_wallet_reservation_is_restart_safe_idempotent_and_fail_closed \
  -- --nocapture

CARGO_BUILD_JOBS=2 cargo test -p dom-wallet-core \
  scriptless_reorg_restores_input_reservation_and_pending_change_from_encrypted_context

CARGO_BUILD_JOBS=2 cargo check -p dom-wallet-core --tests
cargo fmt --all -- --check
CARGO_BUILD_JOBS=2 cargo clippy -p dom-wallet-core -p dom-wallet-core-recovery \
  -p dom-wallet-domain --all-targets -- -D warnings
```

Final composition and full signed funding validation must run in the combined
F7 overlay after the authoritative `dom-adaptor` lifecycle and participant-
local composition API are frozen into the laboratory commit. That overlay is a
build integration step, not permission to substitute a mock or export a raw
scalar.
