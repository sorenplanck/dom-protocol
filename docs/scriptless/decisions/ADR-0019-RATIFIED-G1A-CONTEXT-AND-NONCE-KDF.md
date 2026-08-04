# ADR-0019 — Ratified G1a context registries and secret two-nonce KDF

Status: **ACCEPTED**

## Context

ADR-0018 correctly stopped production nonce derivation because no authorized
source assigned byte values to `DirectionV1`, the signing phase subregistry,
or the complete canonical context. The operator subsequently ratified
NAR-001 with the DOM release Minisign key. The detached signature verifies
against key ID `74197A95CA309CF0`, and the signed KAT V2 input fixture verifies
with the same authority.

Ratification freezes normative inputs. It does not independently validate the
implementation and does not approve G1a.

## Evidence

- **RATIFIED NORMATIVE RECORD:**
  `docs/scriptless/source-guides/normative/amendments/NAR-001-normative-assignment-record.en.md`
  has SHA-256
  `eee087c808aeb4e6e745a5311d17ca5a63c5b5e5568218d20b1cbcdd7b6206dc`.
- **DETACHED RATIFICATION:** the adjacent `.minisig` verifies with DOM release
  public key `RWTwnDDKlXoZdG3obVRiLPfVRHr17E0Fj2GN8IZ2rBkipRZvIIW6PLJ3`.
- **SIGNED INPUT FIXTURE:**
  `test-vectors/scriptless/two-nonce/kat_inputs_v2.en.json` has SHA-256
  `55642208968863a7b2c4773a82d9774f95f2a3b604b80a876d0bf031396b2a7d`
  and its adjacent signature verifies with the same key.
- **AUTHORITATIVE DOM CODE:**
  `crates/dom-crypto/src/hash.rs::blake2b_256_tagged` and
  `crates/dom-crypto/src/scriptless.rs::scalar_from_wide_be` own the tagged
  hash and constant-time wide reduction boundaries.

## Decision

### Closed registries

`PurposeV1` remains the closed registry accepted by ADR-0018:

| Byte | Name |
|---:|---|
| `0x01` | `Refund` |
| `0x02` | `ClaimAdaptor` |
| `0x03` | `Funding` |
| `0x04` | `Sponsor` (codec only; strict Phase 1 rejects it) |

`DirectionV1` is closed and role-stable:

| Byte | Name |
|---:|---|
| `0x01` | `Initiator` |
| `0x02` | `Responder` |

`SigningPhaseV1` is a closed signing-only `u16` subregistry encoded little
endian:

| Value | Bytes | Name |
|---:|---|---|
| `0x0100` | `00 01` | `SigNonceCommit` |
| `0x0101` | `01 01` | `SigNonceReveal` |
| `0x0102` | `02 01` | `SigBinding` |
| `0x0103` | `03 01` | `SigPartial` |
| `0x0104` | `04 01` | `SigAdapt` |
| `0x0105` | `05 01` | `SigExtract` |

All unknown values fail closed. `Created=0x0000` remains valid only in the base
session registry and is rejected by `SigningPhaseV1`.

### Canonical context

`SessionContextV1` uses the exact NAR-001 field order, integer endianness,
conditional adaptor encoding, participant count range, roster ordering,
secret/public-key correspondence, and purpose/adaptor grammar. It is built
only by a validating constructor, stores private fields, and exposes immutable
accessors. Its encoder is infallible after construction. Its decoder is
bounded by the ratified maximum of 16 participants and re-runs semantic
validation against the trusted local chain ID and signing share.

### Secret two-nonce derivation

The only V1 tags are:

```text
DOM:scriptless-secret-nonce-aux:v1
DOM:scriptless-secret-nonce-seed:v1
DOM:scriptless-secret-nonce-wide:v1
```

The KDF is exactly NAR-001 section 7: canonical signing-share bytes are XORed
with the auxiliary-randomness mask, the masked share and canonical context
form the seed input, and two 64-byte values are expanded with index bytes
`0x01` and `0x02` plus half bytes `0x00` and `0x01`. Wide values are reduced
by `dom_crypto::scalar_from_wide_be`. A zero result discards the whole pair and
increments the context retry counter with checked arithmetic while retaining
the same owned auxiliary randomness. No retry is available after public
material exists.

Production auxiliary randomness comes only from `OsRng`. Deterministic
auxiliary input is private to the crate's unit-test configuration and is not a
release API.

All hash and scalar intermediates are protected by RAII zeroization. The
opaque nonce pair and its authorized form deliberately implement no cloning,
copying, debugging, display, equality, ordering, or generic serialization.
Partial signing consumes the authorized pair.

### Arithmetic and verifier ownership

`dom-adaptor` does not depend on `k256`. Protocol-specific point addition,
partial signing, partial aggregation, wide reduction, adaptation, extraction,
and final verification delegate to narrow functions owned by `dom-crypto`.
The final 65-byte signature continues through the unchanged DOM verifier.

## Alternatives considered

- Retain the ADR-0018 stop after valid ratification: rejected because the
  missing assignments now exist and verify.
- Implement a parallel hash, point parser, scalar library, or verifier inside
  `dom-adaptor`: rejected because DOM already owns those authorities.
- Allow application-supplied auxiliary randomness in production: rejected
  because NAR-001 requires operating-system randomness owned by the derivation
  boundary.
- Expose raw reusable nonce scalars to the Wallet: rejected because G1b needs
  commitments and one-shot authorization, not raw nonce reuse capability.

## Consequences

The prior normative code blocker is removed. G1a production code and
implementation-generated tests can now cover canonical contexts, the secret
KDF, one-shot partial signing, aggregation, adaptation, extraction, and real
DOM verification.

G1a remains open until independent outputs are committed before comparison,
all intermediate bytes match, and the required independent cryptographic and
zeroization review completes. G1b remains independently required for durable
consume-before-export authorization.

## Compatibility

These are private Scriptless V1 types and off-chain transcripts. This decision
does not modify consensus, existing transaction or block serialization,
persisted blocks, genesis, network magic, PoW, or the DOM verifier.

## Risks

- The stable permit constructor is a contract boundary, not persistence. G1b
  integration must prove it is reachable only after durable authorization.
- Implementation-generated vectors are correlated evidence and cannot close
  the independent-vector requirement.
- Compiler-visible zeroization and constant-time behavior require independent
  review in addition to source-level RAII guards.
