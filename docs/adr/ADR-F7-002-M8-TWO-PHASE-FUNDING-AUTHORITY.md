# ADR-F7-002: M.8 Two-Phase Funding Authority

- Status: F7 laboratory candidate
- Date: 2026-08-13
- Scope: off-chain `dom-adaptor` operational authorization only
- Consensus, wire, transaction encoding, cryptography, and genesis impact: none

## Problem

The existing DOM Scriptless funding authority implements the legacy
pre-signed-claim profile. Its canonical `OperationalFundingAuthorizationBindingV1`
requires a nonzero hash of a verified claim adaptor pre-signature before the
funding signature can be created.

Interop M.8 requires two phases instead:

1. freeze policy, templates, adaptor point, refund, collaborative proof, and
   backup evidence before funding;
2. obtain real confirmation anchors for both funded legs and validate the M.8
   inequality before allocating claim nonces or producing the claim adaptor
   pre-signature.

Requiring the legacy claim pre-signature in phase one would make the M.8 order
causally impossible. Removing it from the legacy binding would weaken and
silently reinterpret an already-deployed profile.

## Context

`M8TimingPolicyV1::policy_digest()` in DOM Interop is the canonical digest of
the complete immutable two-leg timing/finality policy, including its anchor
rules. `M8FundingAnchorsV1::evidence_digest()` is post-confirmation evidence;
it cannot exist before funding and is not a pre-funding input. DOM consumes
these values as opaque nonzero public digests and does not reimplement their
Interop encoding.

The existing transaction builder, collaborative Bulletproof statement,
Schnorr finalizer, consensus verifier, and canonical transaction codec remain
the cryptographic and transaction authorities.

## Decision

Add a separate, explicitly profile-tagged M.8 authority family:

- `OperationalM8FundingAuthorizationBindingV1`;
- `DurableOperationalM8FundingIssuanceV1`;
- `OperationalM8FundingAuthorizationV1` and its private-construction import
  capability;
- `OperationalM8FundingAuthorizationStoreV1`;
- `VerifiedM8FundingTransactionV1` and the profile-specific persistence
  capability/sink;
- `authorize_funding_m8_v1`,
  `resume_funding_m8_authorization_v1`, and `finalize_funding_m8`.

The canonical binding has magic `DOMF7M8A`, version `1`, profile tag `M8T2`,
and exact length 400 bytes. It authenticates:

- chain ID, session ID, ready-to-fund transcript, and economic terms;
- exact shared-output commitment and collaborative-Bulletproof statement;
- exact funding and claim template hashes;
- the canonical 33-byte claim adaptor point;
- the complete M.8 timing/finality policy digest;
- exact signed refund transaction hash;
- bilateral backup receipt hash.

It contains neither claim pre-signature evidence nor funding-anchor evidence.
Those are inputs to the separate post-anchor claim-signing authority.

## Alternatives considered

### Relax the legacy binding

Rejected. Accepting a zero or optional legacy claim pre-signature hash changes
the meaning of existing canonical bytes and permits downgrade/profile
confusion.

### Add post-confirmation anchor evidence to the funding binding

Rejected. The evidence cannot exist until funding confirms. Requiring it would
create a causal cycle; accepting a placeholder would be fail-open.

### Add a second independent “anchor policy” digest

Rejected. The canonical M.8 timing-policy digest already commits both legs'
timing, finality, and anchor rules. The other canonical M.8 digest authenticates
observed anchors after confirmation, not another pre-funding policy. Inventing
a second digest would create an unowned interface.

### Use one enum-backed authorization and one sink

Rejected for this additive laboratory seam. It would change the return type or
semantics of existing legacy accessors. Separate opaque types preserve source
and byte compatibility and make cross-profile substitution unrepresentable.

## Invariants

1. Every binding field is nonzero and exact.
2. The shared commitment passes the existing canonical commitment parser.
3. The adaptor point passes the existing canonical compressed public-key
   parser; infinity, malformed, uncompressed, and non-curve encodings fail.
4. The funding template creates the shared output exactly once and matches the
   BP chain, session, statement, and aggregate commitment.
5. Issue and resume reconstruct byte-identical bindings and unsigned template
   evidence.
6. Resume imports the same immutable issuance digest and revision; it never
   creates a second issuance.
7. Legacy and M.8 authorization, verified transaction, import capability, and
   persistence types are distinct.
8. `VerifiedM8FundingTransactionV1` has no direct transaction or byte accessor;
   exact bytes cross the API only through an explicit consuming handoff to a
   caller-selected profile-specific persistence sink.
9. The sink trait is a composition boundary, not an attestation of a specific
   trusted implementation. The production composition must select the
   Contracts Store, which must atomically persist exact bytes and consume the
   exact issuance before exposing broadcast authority.
10. Claim nonce allocation and pre-signature production remain outside this
    capability and occur only after real anchor validation.

## Compatibility and security impact

The legacy `DOMF7OPA` bytes, constructors, methods, Store trait, finalizer, and
persistence sink are unchanged. Legacy zero claim-pre-signature hashes still
fail closed. The new types are additive and off-chain. They do not change DOM
consensus, transaction serialization, RPC, P2P wire format, cryptographic
challenges, genesis, or mempool policy.

The explicit magic, version, profile tag, distinct Rust types, exact issuance
comparison, and separate sink let a conforming Store detect and reject replay
or substitution between the legacy and M.8 profiles. They do not authenticate
an arbitrary downstream implementation of the public sink trait; production
security depends on selecting the Contracts Store. The M.8 policy digest
prevents timing-policy substitution, while the exact adaptor point and
claim-template hash prevent a later claim from changing the agreed route.

## Tests

The `dom-adaptor` unit and external API tests prove:

- legacy authorization still rejects a zero claim pre-signature hash before
  calling the Store;
- M.8 funding issues, finalizes, verifies, and persists without any claim nonce
  or pre-signature input;
- all binding fields, magic, version, profile tag, and exact encoded length;
- malformed/zero adaptor points and zero policy digests fail closed;
- policy substitution changes the binding and is rejected on resume;
- crash/resume imports the same issuance digest and revision without reissue;
- consumed issuance cannot resume;
- downstream Contracts can implement the public Store and persistence traits
  while one-shot capability constructors remain private.

Reproducible commands:

```bash
CARGO_BUILD_JOBS=2 cargo test -p dom-adaptor m8_ -- --nocapture
CARGO_BUILD_JOBS=2 cargo test -p dom-adaptor --test m8_two_phase_funding_api
CARGO_BUILD_JOBS=2 cargo clippy -p dom-adaptor --all-targets -- -D warnings
```
