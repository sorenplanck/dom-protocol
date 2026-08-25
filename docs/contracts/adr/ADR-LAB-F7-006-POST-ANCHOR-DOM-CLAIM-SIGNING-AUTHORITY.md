# ADR-LAB-F7-006: Durable post-anchor DOM claim-signing authority

Status: laboratory candidate, pending ratification

## Problem

The pre-funding Scriptless lifecycle prepares refund safety and freezes the
claim template, but F7/M.8 forbids acquiring claim-signing nonces before both
real funding anchors pass the frozen timing/finality policy. A descriptive M.8
result or a process-local boolean does not survive restart and cannot prevent a
second signer from replaying stale anchor evidence.

The legacy `ClaimSigning -> ClaimPrepared` ancestry remains authoritative for
the older pre-signature-first profile. Reusing that economic phase after
funding would conflate two causally different operations and would weaken the
pre-funding refund gate.

## Context

The Contracts SessionStore already owns the authenticated session history,
exact operational funding commit, global DSC1 journal, and canonical DOM
signing-session bindings. The Store-free `f7-anchor-authority` leaf owns the
complete real DOM/Bitcoin evidence validation and is the sole constructor of
`VerifiedF7AnchorAuthorizationV1`. M.8 policy terms are frozen before funding;
anchors are a separate post-confirmation evidence object and must not mutate
those terms. Interop components must never persist the adaptor secret `t`.

## Decision

The laboratory adds an immutable, versioned record family with domain
`DOM:contracts-post-anchor-claim-signing-authorization:v1` and magic
`DOMSPAC1`:

1. `Issued` binds session, settlement, frozen terms and M.8 policy, exact M.8
   anchor-evidence digest, authenticated DOM chain, exact DOM and Bitcoin
   funding transaction identifiers, confidential shared-output commitment,
   both proven confirmation depths, claim template, round-start transcript,
   adaptor point, exact `FundingConfirmed` revision/digest, the M.8
   funding-gate digest, M.8 funding-issuance digest, funding-commit digest, and
   a fresh claim issuance identifier.
2. `Consumed` repeats every binding and names the exact `Issued` digest as its
   predecessor.
3. The only issuance entrypoint consumes one non-forgeable, non-cloneable
   `VerifiedF7AnchorAuthorizationV1` by value. There is no raw digest request
   API or generic validator trait. The Store exact-compares every DOM binding
   against its M.8 gate/issuance/commit, then fsyncs and rereads `Issued` before
   returning a process-bound `ClaimSigningAuthorizationV1`.
4. The Store fsyncs and rereads `Consumed` before returning
   `ConsumedClaimSigningAuthorizationV1`. Only the consumed capability can
   enter the F7 signer or post-anchor DSC1 transport boundary.
5. Crash recovery takes only the retained Contracts session identifier and
   rehydrates the same immutable issuance or consumption. It does not accept
   caller-shaped evidence or mint another identifier, revision, or
   authorization.
6. The canonical economic head remains `FundingConfirmed` while the additive
   claim-signing journal advances. Generic post-anchor signing messages are
   rejected unless the exact durable `Issued -> Consumed` chain exists.
7. After the exact two commitments, two reveals, and two partial signatures are
   durable, the Store can reconstruct the aggregate Claim adaptor
   pre-signature from those authenticated public artifacts. It replays the
   canonical six-message prefix, verifies both commitment openings and both
   partial equations with the pinned DOM helpers, aggregates the partials, and
   verifies the resulting adaptor equation. It then fsyncs and rereads a
   `DOMSPPS1` record in the distinct
   `DOM:contracts-post-anchor-claim-pre-signature:v1` domain before returning a
   non-cloneable `AuthenticatedPostAnchorClaimPreSignatureV1`. The record binds
   the issuance, consumption, signing-session binding, round binding, roster,
   round predecessor, reveal transcript, terminal revision/digest/transcript,
   and exact canonical 162-byte pre-signature. Exact retry and process restart
   reopen the same bytes; a five-message prefix, changed predecessor, changed
   binding, changed artifact, or conflicting retained record fails closed.

The additive F7 funding profile freezes the M.8 policy digest, claim template,
and adaptor point before funding but contains no claim pre-signature. The
legacy pre-signature-first funding gate remains byte-for-byte separate and is
not eligible for this M.8 flow.

The Store uses distinct retained gate and issuance magics and the DOM-owned
`M8T2` authorization type. Its post-sign commit is also a distinct M.8 record
that binds the exact M.8 issuance digest before it embeds the artifact and
consumption records. Startup recovery, post-sign persistence, and audit select
exactly one profile. Finding both profiles, a legacy issuance/commit behind an
M.8 gate, an M.8 issuance/commit behind a legacy gate, or claim-signing
evidence in the pre-anchor M.8 journal quarantines the Store.

## Alternatives considered

- Reuse `ClaimSigning`/`ClaimPrepared` after funding. Rejected because those
  phases are pre-funding safety ancestry and cannot express M.8 causality.
- Accept a caller-supplied anchor digest or scanner DTO. Rejected because it
  would allow an unverified value to cross the nonce boundary. Only the
  concrete Store-free full validator can mint the consumed capability.
- Persist or derive `t`. Rejected by Foundation v0.18 I1 and Annex M.10; the
  secret owner must resupply `t`, and the claim path verifies `tG = T`.
- Mutate frozen policy terms with anchor data. Rejected because the M.8
  two-phase model binds anchors as separate evidence.
- Keep the aggregate pre-signature only in the signer process. Rejected because
  a crash after both one-shot partials are durably accepted cannot safely reopen
  either nonce or recompute a partial. The aggregate is reproducible from the
  retained public partials and must be committed before it becomes a DOM-leg
  capability.

## Invariants

- No claim nonce or signature is available before durable consumption.
- An issuance is unique per Contracts session and cannot be cloned, encoded,
  or constructed by a caller.
- Restart resumes the same issuance/consumption digests; exact duplicate
  requests are idempotent only through explicit resume APIs.
- Changed session, settlement, terms, M.8 policy, anchor digest, chain, either
  funding transaction identifier, shared output, confirmation depth, template,
  transcript, adaptor point, M.8 gate/issuance, funding commit, or session
  projection fails closed.
- The bound session revision is an authenticated `FundingConfirmed` revision
  whose profile-tagged M.8 funding issuance and operational funding commit are
  complete. A legacy pre-signature-first issuance is never accepted.
- Reorg projection changes make the process-local authority stale. A caller
  cannot substitute new anchors under an old issuance.
- The global DSC1 sender sequence space is preserved; no purpose-scoped
  sequence namespace is created.
- The post-anchor signing predecessor is exactly the transcript frozen by the
  consumed anchor authorization. A later transcript with only a greater
  revision is not an equivalent authority.
- Aggregate reconstruction neither opens a nonce reservation nor accepts a
  caller-provided partial, signing key, transaction, transcript, or adaptor
  point. All inputs come from authenticated immutable Store records.
- The aggregate artifact exists only after the complete six-message canonical
  prefix and is byte-identical across retry and restart. It cannot turn a
  partial prefix into signing authority.
- No persisted record contains `t`, a nonce scalar, signing share, seed, or
  private transport key.

## Compatibility and security impact

The record and APIs are additive. Legacy funding-gate records and
pre-signature-first tests retain their exact encoding and semantics. The new
opaque capabilities expose only public binding digests and public points. They
have no `Clone`, `Copy`, `Debug`, equality, or codec implementation.

The Store does not parse anchors itself. The Store-free F7 authority owns
canonical anchor parsing, authenticated real-chain validation and M.8 policy
evaluation; the Contracts Store consumes its linear result and owns durable
exact binding and causal ordering.

## Tests proving the decision

The focused Store suite must prove:

- issuance is impossible before `FundingConfirmed` or without the complete
  operational funding commit;
- issuance, restart resume, consumption, and consumed restart resume preserve
  exact identifiers and record digests;
- a concurrent or repeated issuance/consume has one winner;
- every persisted binding mutation, stale revision, reorg projection, record
  tamper, and cross-session replay fails closed; a raw caller-built request
  does not exist in the production API;
- crash after issuance persistence and after consumption persistence converges
  to the matching explicit resume boundary;
- the aggregate pre-signature codec is exact and tamper-evident, exact
  reconstruction is idempotent, a five-message gap and predecessor drift are
  rejected, and a crash immediately after immutable publication reopens the
  byte-identical record without fresh signing;
- claim signing/DSC1 messages are rejected before consumption and accepted
  only for the exact claim template/adaptor point afterward;
- the legacy pre-funding funding gate remains unchanged; and
- no persisted bytes contain the adaptor secret or private nonce material.
