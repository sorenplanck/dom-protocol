# ADR-F7-LAB: Official Wallet V3 Composition Boundary

- Status: laboratory decision
- Date: 2026-08-13
- DOM commit: `6a295fddf4e6a3afd6cf0f3fdb1e3a636a2f3d71`
- Wallet V3 commit: `ba2de03e70b625ca401b1bc4de3cfb91202ec2d3`

## Problem

The F7 route runner must queue a real DOM claim, but accepting generic canonical
transaction bytes would let a caller bypass the official wallet reservation and
template-binding path. Conversely, adding DOM consensus, adaptor, wallet or
secret-custody dependencies directly to the cross-chain runner would violate
D-005 and duplicate existing authority.

## Context

Wallet V3 already provides durable funding and payout reservations, canonical
public component export, exact template binding and opaque signing handoffs. The
frozen DOM adaptor already provides the only canonical transaction templates,
adaptor finalizer and complete verifier. Contracts provides the retained shared
blinding, collaborative Bulletproof, signing-nonce, session and identity stores.

## Decision

Add the feature-gated `dom-leg::f7_wallet` composition boundary. It is the only
Interop module permitted to name both Wallet V3 and DOM authority types. For a
claim it:

1. requires two official `WalletService` instances;
2. binds both durable payout reservations to one exact canonical claim template;
3. obtains both opaque Wallet V3 signing handoffs and checks their public keys
   against the frozen ordered participant set;
4. retains the resulting purpose-bound shares opaquely until they are consumed
   by the concrete `ContractsNonceVaultV1`/`VaultBackedSignerV1` composition,
   without exporting scalar bytes;
5. accepts only the exact retained adaptor pre-signature and already-public
   route scalar for finalization; and
6. returns a closed `F7VerifiedDomClaimArtifactV1` with no public constructor,
   codec, clone or mutable byte access.

The runner consumes that closed type. It cannot queue a caller-created generic
DOM claim artifact. DOM funding and refund broadcast bytes remain owned by the
Contracts session store and its linear capabilities.

## Alternatives considered

- Let the runner accept canonical DOM bytes: rejected because canonical syntax
  does not prove Wallet V3 reservation/template authority.
- Add Wallet V3 and DOM dependencies directly to `f7-runner`: rejected by D-005
  and because it would broaden the cross-chain state machine into secret
  custody.
- Copy wallet arithmetic or signing into Interop: rejected because the frozen
  authorities already implement it and duplicate cryptography is forbidden.

## Invariants

- No raw wallet excess, shared blinding, signing nonce, seed or key crosses the
  composition boundary.
- Both wallets bind the identical chain, session, shared output, template and
  ordered two-party participant set.
- Claim bytes exist only after the frozen adaptor verifies the pre-signature,
  `T = tG`, final signature and complete DOM transaction.
- The runner receives no constructor capable of relabeling generic DOM bytes as
  a wallet-authorized claim.
- Contracts production vaults and stores remain the only durable secret and
  signing authorities.

The production composition is concrete, not generic: one retained
`ContractsSessionStoreV1`, two distinct filesystem-backed
`ContractsNonceVaultV1` instances, and two independent
`ContractsTransportIdentityStoreV1` keystores. The chain signing authority is
derived through `TrustedChainIdV1::from_authenticated_genesis` and must equal
the real adapter's frozen chain identity. Evidence-only constructors and
in-memory vaults are absent from this boundary.

## Compatibility and security impact

This is additive and does not change DOM consensus, wire, transaction encoding,
wallet database formats, Contracts record formats or D-005. It deliberately
adds a compile-time dependency from `dom-leg` to the frozen Wallet V3 checkpoint
and concrete Contracts composition crates. `f7-runner` depends only on the
closed high-level `dom-leg` result.

## Tests

The combined gate must prove two-wallet binding, swapped participant rejection,
cross-session/template rejection, restart-safe wallet reservations, canonical
claim finalization, byte-identical dispatch, scanner confirmation and rejection
of generic or mismatched DOM artifacts. Wallet V3's focused F7 suite at the
frozen checkpoint is a prerequisite, not a substitute for this combined gate.
