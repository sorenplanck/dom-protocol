# ADR-F7-LAB: Bitcoin Route-Secret Binding and Delayed Extraction

Status: laboratory implementation decision  
Scope: F7 real-DOM integration only  
Normative authority: DOM Interop Foundation v0.18 and Annex M v3.3

## Problem

The existing F5 harness selected a deterministic test adaptor scalar inside
the Bitcoin builder. That is sufficient for the closed F5 Bitcoin gate, but it
cannot prove an F7 route: DOM and Bitcoin must commit to the same public point
`T = tG`, and a claim on either leg must make the very same scalar available to
the opposite leg. The old public result deliberately returned only `tG`, so a
confirmed Bitcoin-first claim could not feed the verified scalar into the DOM
claim path.

## Context

Annex M requires MuSig2 adaptor signing, exact final-signature verification,
extraction against the committed point, durable one-shot nonce custody, and
real Bitcoin evidence. A Bitcoin txid does not commit to witness data, so a
txid-only extraction API could accept a different key-path signature for the
same non-witness transaction. The additive F7 M.8 model also requires the
post-confirmation funding-anchor capability before nonce generation.

`counterparty_api::RevealedSecretBytes` is the existing redacted boundary for
a scalar that is public only after a claim. It suppresses `Debug` output and is
already consumed by the route and USPE layers.

## Decision

The F7 Bitcoin claim path now:

1. prepares the complete durable two-party adaptor pre-signature from only
   the public `AdaptorPointBytes`; it neither receives nor reconstructs `t`;
2. accepts only an `AnchoredCrossChainWindowV1` minted by the M.8
   policy/anchor validator;
3. enters both durable signer rounds through `ClaimRound::prepare_after_m8`;
4. returns a linear prepared claim rather than broadcastable transaction
   bytes and exposes a strict public-only durable continuation encoding, so a
   restart cannot authorize a second nonce attempt and no claim can be
   broadcast before a real route reveal;
5. adapts only when canonical chain evidence from either leg supplies a
   `RevealedSecretBytes`, independently deriving `tG` and rejecting a scalar
   that does not open the prepared route's frozen `T`;
6. emits the fully signed transaction and a non-secret extraction context;
7. binds that context to a domain-separated BLAKE2b-256 digest of the complete
   canonical transaction, including its witness;
8. extracts only from byte-identical scanner-returned transaction bytes, after
   canonical decode/re-encode and BIP340 verification; and
9. delegates scalar extraction and `tG == T` to the pinned Bitcoin crypto
   backend.

The continuation contains the frozen route identities, funding outpoint,
canonical unsigned claim, template/sighash binding, adaptor point, aggregate
key, public adaptor pre-signature and public extraction descriptors. Its
domain-separated digest, strict canonical decoder and caller-supplied route
expectations reject truncation, mutation and cross-route import. A signed
claim restart continuation must contain the exact same non-witness
transaction and a valid final BIP340 signature. It cannot cause a new nonce
reservation.

The secret owner supplies `t` locally at the adaptation boundary. Interop,
the adapters, nonce vaults, Store, Keystone/USPE and evidence packages never
persist it. After restart the owner may re-supply the same scalar, which is
accepted only after recomputing and comparing `tG` with the frozen `T`; if the
owner cannot re-supply it, the safe supported outcome is the already-armed
refund path, not reconstruction from Interop storage. The public prepared
continuation is sufficient to resume that same attempt; it never reconstructs
the secret or signing nonce.

The F5 fixed-key helpers remain unchanged compatibility surfaces. They are not
eligible entry points for F7.

## Alternatives considered

### Return the scalar from the existing F5 builder

Rejected. That builder adapts immediately using an internally selected test
secret and has no proof that the transaction was observed on chain. Returning
the scalar there would erase the evidence boundary.

### Bind extraction only to the txid

Rejected. Bitcoin txids exclude witness bytes. A claim signature is the
evidence from which the adaptor scalar is extracted.

### Reimplement adaptor extraction in the route harness

Rejected. The pinned `btc-crypto` backend already verifies BIP340, extracts,
rejects non-canonical scalars, and checks `tG == T`.

### Pass the secret as a command-line argument

Rejected. Command lines are observable through process inspection and are
commonly captured in logs. The F7 API keeps the value in memory inside the
redacted route type.

## Invariants

- DOM and Bitcoin receive exactly the same public adaptor point.
- A malformed adaptor point fails before any nonce reservation.
- A different route's scalar fails before transaction construction or
  broadcast; the already one-shot preparation remains durably consumed.
- M.8 terms mismatch fails before nonce reservation.
- The scalar is not printed, serialized into a report, or included in a
  diagnostic value.
- The scalar is never written to an Interop database, keystore, artifact,
  route record or evidence package; only `T` and public pre-signature context
  are durable.
- Restart never derives or recovers `t`; it accepts an owner-supplied value
  only when `tG == T`, otherwise it remains fail-closed/refundable.
- Restart imports the byte-identical public prepared continuation and cannot
  reserve or substitute another claim nonce.
- A modified continuation or one bound to another settlement, session, terms
  hash, funding outpoint or adaptor point fails closed before adaptation.
- Extraction requires complete byte-identical canonical transaction evidence;
  txid equality alone is insufficient.
- The final signature is independently BIP340-verified before extraction.
- Only the pinned backend implements adapt/extract and `tG == T`.
- F5 behavior and vectors remain byte-compatible.

## Compatibility and security impact

The change is additive. No Bitcoin transaction, witness, sighash, Taproot,
network, or evidence encoding changes. The new context and restart
continuation contain only public pre-signature/session data and digests; they
contain no secret nonce or scalar. Requiring exact witness-bearing bytes
prevents extraction from ambiguous or late evidence and makes a cross-route
replay fail closed.

## Tests

```bash
CARGO_BUILD_JOBS=2 cargo test -p f5-e2e --test f7_route_secret -- --nocapture
```

The tests prove the M.8-gated durable claim is prepared without `t`, survives
a public-continuation restart, the same route scalar later adapts it, and
extraction occurs only from confirmed exact bytes. They also prove a modified
witness, a modified continuation, cross-route continuation import and a scalar
revealed by another route are rejected, and inspect the retained nonce
databases to prove that the route scalar bytes were never persisted.
