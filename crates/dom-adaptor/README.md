# dom-adaptor

> [!WARNING]
> This crate is experimental, has not completed an independent external
> security audit, and is not authorized for production or real funds.

`dom-adaptor` is the integrated Phase 1 G1a/G1b semantic boundary for DOM Scriptless
Contracts. Its production code depends on `dom-crypto` for every cryptographic
primitive, does not depend directly on `k256`, and does not depend on Wallet,
storage, witness, transport, or application crates.

The current implementation provides:

- ratified closed `PurposeV1`, `DirectionV1`, and `SigningPhaseV1` registries;
- validated immutable `SessionContextV1` with exact canonical encoding;
- the ratified secret two-nonce KDF through DOM's authoritative hash and scalar boundaries;
- opaque pre-authorization and authorized one-shot nonce-pair ownership;
- participant-bound partial signing, verification, and aggregation;
- a vault-backed recovery surface whose abort operations consume every live
  signer state and whose restore status is delegated read-only;
- exact restart resend by public `PermitIdV1`, closed artifact kind, and trusted
  adaptor outbound digest, returning only a canonical typed artifact;
- closed, versioned Funding, Claim Adaptor, and Refund purposes;
- canonical fixed-width commitment, reveal, partial-signature, and adaptor
  pre-signature payloads;
- frozen tagged commitment and collective binding transcripts;
- pre-signature verification, adaptation, and extraction through a narrow
  arithmetic API owned by `dom-crypto`;
- final verification through DOM's unchanged Schnorr verifier.

The repository includes signed input fixtures and a separately implemented,
pre-comparison reference set whose 311 recorded intermediates are checked by a
crate-local test adapter. Those vectors are public and insecure test material;
they do not authorize production use or replace external security review.

This crate also defines the storage-independent G1b lifecycle, permit, and
one-shot signer contracts. Durable persistence belongs to the independent DOM
Contracts application and must not be implemented by the ordinary DOM Wallet.
The public permit ID is only a restart lookup key: it carries no live export
capability and authorizes nothing by itself. `VaultBackedSignerV1` exposes no
vault extraction, mutable vault accessor, trait-object plugin boundary, or raw
resend output. A concrete vault must reopen and validate its retained spent
authority before returning an exact resend candidate.

Neither G1a nor G1b is unilaterally adjudicated by this crate, and production
remains unauthorized until every applicable gate has executed evidence. This
recovery revision also requires separate review, public commitment, and a new
DOM Contracts dependency pin before NAR-DC-P1-003 recovery conformance can be
treated as closed.
