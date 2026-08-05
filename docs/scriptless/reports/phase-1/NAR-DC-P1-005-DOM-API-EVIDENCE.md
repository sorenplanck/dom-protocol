# NAR-DC-P1-005 DOM API Evidence

## Status and authority

This report records the DOM-side implementation evidence for the signed and
ratified NAR-DC-P1-005 reservation-runtime boundary. The implementation branch
started from ratification commit
`e8e08ae0f3048992855a35af315dba22b8f009b7`.

This evidence does not adjudicate G1A, G1B, consolidated G1, publication,
production, mainnet, Phase 2, or real-funds use. No consensus, existing wire,
kernel-verifier, persisted-block, Wallet, or DL2P behavior was changed.

## Implementation commits

| Commit | Subject | Evidence |
|---|---|---|
| `5606ab7aefd2f8d60f4ca917bcffd7b9b146ef74` | `feat(scriptless): bind live vault reservation runtime API` | Introduces the live handle GAT boundary, distinct request/permit identifiers, request custody, canonical operation inputs, bound prepared exposure, consumed resend request, authenticated DSC1 round owner, and vault-backed signer integration. |
| `3279a6065488e730b352164e5e18cf1cb3f76fea` | `fix(scriptless): harden signing round authority` | Makes signing-round bootstrap opaque, authenticates before equivocation handling, rejects sequence regression, verifies accepted partial equations, and makes resend authority one-shot. |
| `0cccb84e42727354d5cffe73a03c467a8fe06f9b` | `fix(scriptless): validate live post-export projections` | Verifies the live handle stage and spent permit projection after commitment and reveal export, and retains the lifetime-unique session identifier with prepared reservation custody. |

## Implemented boundary

- `NonceVaultV1` owns the storage-independent lifecycle contract and uses live
  reservation-handle associated types rather than detached caller assertions.
- `ReservationRequestLookupV1`, `PermitIdV1`, `NonceIdentityV1`, and
  `ProcessComputationBindingIdV1` are distinct closed identifiers.
- `PreparedExposureV1` is created from a vault-issued persistence permit and is
  validated before the Store accepts it.
- `ResendRequestV1` is consumed by value and the Store returns its own
  `Self::ExportedArtifact` projection.
- Cancellation consumes the live handle and accepts no caller-supplied
  lifecycle state.
- The DSC1 parser accepts the exact fixed envelope plus bounded payload,
  authenticates through the DOM Schnorr boundary, and recognizes only message
  kinds `0x0c`, `0x0d`, and `0x0e` for commitment, reveal, and partial signing.
- Opaque signing-round bootstrap and stage authorities enforce ordered barriers,
  per-sender sequence monotonicity, duplicate identity, equivocation rejection,
  and participant-bound partial verification.
- Commitment and reveal completion validate both the live post-export stage and
  the Store's spent permit/kind/outbound-digest projection before advancing.

Primary implementation paths:

- `crates/dom-adaptor/src/nonce_vault.rs`
- `crates/dom-adaptor/src/reservation_binding.rs`
- `crates/dom-adaptor/src/signing_round.rs`
- `crates/dom-adaptor/src/vault_operation.rs`
- `crates/dom-adaptor/src/vault_signer.rs`

## Executed validation

The following commands were executed at
`0cccb84e42727354d5cffe73a03c467a8fe06f9b`; every command returned exit code
`0`.

| Command | Result |
|---|---|
| `cargo check -p dom-adaptor --locked` | Passed with no warnings. |
| `cargo test -p dom-adaptor --locked` | Passed: 35 unit tests, 4 adaptor integration tests, 7 transcript integration tests, 3 freeze-probe tests, and 14 compile-fail documentation tests; 63 total, 0 failed. |
| `cargo clippy -p dom-adaptor --all-targets --locked -- -D warnings` | Passed with warnings denied. |
| `cargo fmt --all -- --check` | Passed. |
| `git diff --check` | Passed. |

The executed suite includes the frozen eight-vector SCAD0 path, all 311 frozen
independent intermediate comparisons, closed registry and parser checks,
authenticated signing-round barriers, participant-bound partial validation,
one-shot authorization compile failures, and real DOM verifier coverage already
owned by `dom-adaptor`.

## Remaining gates and blockers

- A concrete DOM Contracts Store implementation has not yet been compiled or
  executed against this revised trait. Cross-repository lifecycle conformance is
  therefore pending.
- End-to-end restart evidence must demonstrate trusted retention and
  rehydration of the nonce identity before post-restart resend. The DOM API
  fails closed when this custody evidence is absent; the downstream Store must
  prove exact-byte recovery without recomputation.
- The Linux Store filesystem/runtime capability profile, crash matrix, and
  durable resend evidence are downstream Store responsibilities and were not
  executed by this DOM-only branch.
- Windows and macOS runtime evidence was not executed here.
- Publication of these commits to the authoritative DOM remote and a consumable
  immutable dependency pin remain coordinator-controlled gates.
- No external security audit was performed.

Accordingly, this branch is a DOM API candidate for cross-repository
conformance review. It is not independent evidence that G1A, G1B, or Phase 1 is
approved.

## Prohibited-operation confirmation

No push, merge, rebase, release, publication, production activation, real-funds
authorization, official-repository modification, DOM Wallet integration, or
DL2P import was performed by this implementation tranche.
