# ADR-P1-001 DOM Conformance

Status: **DOM CODE CONFORMS FOR CROSS-REPOSITORY REVIEW — GATES OPEN**  
Reviewed head: `3fad0af8f193e21ca9c1f3e662d86cabc602112a`

## Conformance map

| ADR requirement | DOM implementation | Current evidence | Status |
|---|---|---|---|
| Single semantic authority | `messages.rs`, `context.rs`, `permit.rs`, `nonce_vault.rs` | closed-registry tests and source audit | implemented |
| Canonical KDF and DOM backend | `dom-crypto/src/scriptless.rs`; `dom_crypto::blake2b_256_tagged` | KDF mutation tests and prior 311-field evidence | implemented; independent integrated rerun pending |
| Exact `NonceSecretRecordV1` | `nonce_secret_record.rs` | exact 387/882-byte roundtrips, all-prefix truncation, extension, scalar and binding negatives | implemented |
| 252-byte record versus capability | `ExposurePermitBindingV1`; associated Wallet permit | parser tests and default API compile-fail probes | implemented |
| Internal CSPRNG identifiers | `VaultBackedSignerV1::reserve` | source and runtime lifecycle test | implemented |
| No caller receipt/Boolean/raw permit | `NonceVaultV1` | public API review and compile-fail probes | implemented |
| Commitment/reveal/partial order | signer type states | full evidence-only lifecycle test | implemented |
| Partial-attempt marker before open | `SecretOpenStageV1::PartialAttempt` and trait contract | Wallet conformance required | DOM contract implemented |
| One-shot no-copy ownership bridge | seal/import capabilities | capability forge/reuse compile-fail tests | DOM contract implemented |
| Exact persisted retry | `resend_exported(PermitIdV1)` | Wallet implementation/fault evidence required | contract only |
| Static concrete Wallet composition | generic associated types, no trait object in DOM | Wallet composition review required | pending cross-repository evidence |
| Ordinary Wallet isolation | no Wallet dependency in `dom-adaptor` | DOM dependency audit | DOM side satisfied; Wallet runtime pending |

## Public production surface

`NonceVaultV1` has associated `Error`, `ReservationHandle`,
`ExposurePermit`, and `ExportedArtifact`. `export` returns the Wallet-owned
private exported type. Only `dom-adaptor` constructs `AuthorizedExposureV1`.
The secret seal and import capability constructors are crate-private and each
capability is consumed by value.

The production high-level signer accepts public protocol intent, a validated
context, and a Wallet-owned signing share reference. It does not accept nonce
bytes, auxiliary randomness, permit bytes, receipts, witness keys, storage
success, or bypass flags.

## Dependency audit

- `crates/dom-adaptor/Cargo.toml` has no direct `k256` dependency.
- `dom-adaptor` has no Wallet, storage, witness, transport, or application
  dependency.
- `dom-crypto` remains the authoritative owner of secp256k1 arithmetic and the
  only wide scalar reduction.
- The `scriptless-integrated` backend feature excludes deterministic auxiliary
  randomness; deterministic constructors remain under `test-helpers`.

## Open conformance evidence

Wallet compilation against this exact DOM head, production composition review,
complete process-death matrix, independent integrated review, long fuzz and
sanitizer campaigns, Windows/macOS execution, operational policy ratification,
and publication/pinning remain open. This report does not approve either gate.

