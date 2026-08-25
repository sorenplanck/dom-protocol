# ADR-LAB-F7-007: Durable Signing-Prefix Continuation

Status: laboratory candidate for F7 external testing

## Problem

The retained Contracts session journal can authenticate every canonical DSC1
signing prefix from zero through six messages. Before this decision, the safe
signer could resume a claimed nonce only from the fresh derivation authority,
which is unavailable after the first accepted commitment. A process crash could
therefore strand a durable nonce commitment, reveal, or partial even though the
session journal and Nonce Vault retained all authoritative state.

## Context

The two participants compute one stage before the corresponding messages are
fully acknowledged. At a crash boundary the Nonce Vault may legitimately be one
public stage ahead of the accepted session prefix. Recovery must distinguish
that state from a gap, equivocation, wrong participant, wrong purpose, or wrong
session. It must not create a new reservation, derive a replacement nonce, or
re-sign a partial.

## Decision

The DOM adaptor defines an additive restart-only authority that is a different
Rust type from the fresh derivation authority. The vault-backed signer derives
the canonical reservation-context binding internally and submits an opaque
lookup-recovery request to the Contracts custody implementation. Callers cannot
provide a lookup candidate or binding digest.

The signer returns only a stage-typed recovered state:

- pre-derivation;
- after the exact spent commitment;
- after the exact spent reveal;
- terminal exact partial authorized; or
- terminal abort before any public material for the empty prefix.

For an artifact spent before its DSC1 acknowledgement, the signer submits a
second opaque request to the Contracts Nonce Vault. The vault returns only a
non-exporting spent descriptor. The signer binds its authenticated identity,
stage, and digest to the ordinary one-shot resend request before exact bytes can
leave the vault. If the message already exists in the accepted prefix, its
outbound digest must equal the recovered descriptor.

The complete six-message ClaimAdaptor prefix remains subject to the separate
Store-owned aggregate reconstruction record described by ADR-LAB-F7-006.

## Alternatives considered

1. Relax the fresh derivation authority after replay. Rejected because it would
   make a second fresh reservation/nonces possible after public evidence.
2. Let the caller enumerate or trial the two retained lookups. Rejected because
   a wrong trial can abandon another participant's custody record and creates a
   caller-controlled authority surface.
3. Recompute or re-sign missing output after restart. Rejected because it would
   violate one-shot nonce custody and byte-identical retransmission.
4. Persist a parallel signing transcript namespace. Rejected because DSC1 uses
   one global sender sequence and transcript ancestry per session.

## Invariants

- The restart authority cannot enter `claim_fresh`.
- Lookup selection is exact, opaque, and performed by retained custody.
- `RetryNotFound` is abandoned durably and never falls back to a fresh claim.
- A recovered vault stage must be causally compatible with the exact canonical
  accepted prefix and local protocol position.
- Spent artifacts are recovered by session, participant, purpose, context
  binding, lookup, and closed stage; no caller supplies the outbound digest.
- Exact accepted duplicates are idempotent; differing bytes, gaps, reorder, or
  equivocation fail closed.
- No raw nonce, signing share, lookup, binding authority, or secret adaptor
  scalar is exposed by the continuation API.

## Compatibility and security impact

The decision is additive. It changes no consensus rule, transaction encoding,
DSC1 wire format, sequence rule, transcript rule, or cryptographic primitive.
The ordinary fresh and same-process signer APIs remain unchanged. Contracts
implements the two new recovery traits against the existing retained session
store and canonical Nonce Vault rather than adding another nonce authority.

## Tests

The DOM adaptor tests every canonical prefix cut from zero through six, rejects
gap, invalid-signature, and same-sequence divergent messages, proves the
restart authority is one-shot, and proves it cannot be followed by a fresh
derivation authority. Contracts focused tests cover exact lookup recovery,
wrong session/purpose/participant/binding/lookup rejection, restart reopen, and
byte-identical resend. The six-message ClaimAdaptor artifact tests additionally
cover codec exactness, tamper, five-message gaps, crash after immutable publish,
and idempotent reopen.
