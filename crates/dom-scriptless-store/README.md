# DOM Scriptless Store

This crate exposes fail-closed structural parsers and authenticated canonical
record foundations for the ratified V1 Nonce Vault lifecycle.

Authenticated construction and validation cover:

- `NonceIdentityV1`, using `dom-adaptor::PurposeV1` as the only purpose
  registry and rejecting `Sponsor` under strict Phase 1 policy;
- `SessionClaimV1` and `AttemptRecordV1`;
- immutable `ExposureRecordV1` versions and predecessor identifiers;
- `TombstoneV1` structural fields and storage digests, plus collision-free
  partial-consumption record relationships; and
- predecessor-linked journal envelope and payload codecs for Reserve through
  Burned, with a stateful verifier for the authority-independent lifecycle.

Every storage digest is delegated to
`dom_scriptless_crypto::authoritative_storage_hash_v1` with its assigned
`StorageHashDomainV1`. The adaptor permit outbound digest remains a separate
domain from the Contracts exposure-storage outbound digest.

Structural parsers remain available for quarantine and bounded inspection.
They do not authenticate retained digest fields or grant lifecycle authority.
Authenticated restore construction, filesystem transaction orchestration,
secret-object ownership, export capabilities, and a `NonceVaultV1`
implementation are not provided by this foundation. A reviewed
single-reservation experiment is retained in Git history only and is absent
from the module graph. It must not be treated as a production path or runtime
evidence.

`AbortConsumed` and ordinary `Burned` require retained root, lock, active
generation, object-header, identity, revision, and complete-envelope authority.
That live authority is not implemented here. Consequently, the production API
exports no active-secret evidence type or constructor, accepts no caller claim
of secret presence or absence, and the minimal journal verifier rejects those
terminal entries with `LiveStoreAuthorityRequired`. Parsing their canonical
bytes is quarantine inspection only and cannot authorize deletion or export.

## Legacy quarantine

The historical source files `src/codec.rs`, `src/error.rs`, `src/model.rs`, and
`src/vault.rs` describe unpublished experimental evidence. They are not
declared as Rust modules, are absent from the crate's public API, and cannot be
enabled by a Cargo feature. In particular, this crate does not open, interpret,
rewrite, or migrate the following development-only magics:

- `DOMNVLR1`
- `DOMNVTM1`
- `DOMNVRS1`
- `DOMNVRE1`
- `DOMNVSC1`
- `DOMNVE01`
- `DOMNVRP1`

Encountering those bytes in a future production opener must quarantine the
store. An offline migration tool would require separate normative authority;
none exists in this crate.
