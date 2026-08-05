# Phase 1 DOM Integration Inputs

Status: **RECORDED — LOCAL INTEGRATION ONLY**  
Date: 2026-08-04

## Authority

The integration is based on ratified commit
`76915842465f89867b045c9016d532dc3538ac2d` and exact ADR-P1-001 content hash
`e35c39e74f9af61e19ecda8e1ca503f37a7fc04c6e2a0f40f5d96bf6a20d1596`.
The detached signature and complete normative manifest were verified by
[`INTEGRATION-PREFLIGHT.md`](INTEGRATION-PREFLIGHT.md).

## Deliberately imported trails

| Trail | Reviewed candidate head | Merge base with coordinator | Imported scope |
|---|---|---|---|
| G1a DOM | `f821937a8ff1712d5f9bafd58f152b82073538f2` | `a37f0bbeeb7c0ee5579154ae64476e8374d1dabb` | canonical cryptography, KDF, context, codecs, verifier integration, tests, fuzz targets, quarantine |
| G1a report | `60c0a8d2e692c11a7aa95c568339a25912f94a5a` | same G1a trail | historical evidence only; no gate was inherited as approved |
| G1b DOM | `ec9e99661c52f4e09609603261455c09e1d615a7` | `a37f0bbeeb7c0ee5579154ae64476e8374d1dabb` | storage-independent lifecycle types, canonical permit record, consume-before-export contract |

No branch was merged or rebased. Code/test commits were applied individually,
and conflicts in `Cargo.toml`, `lib.rs`, and the README were resolved under
ADR-P1-001 rather than with an automatic side selection.

## Reconciliation decisions

- `PurposeV1` is owned only by `messages.rs`.
- `ExposureKindV1` is owned only by `permit.rs`.
- `ExposurePermitBindingV1` is the sole production 252-byte persisted-record
  parser/encoder. The historical G1a permit helper is test/evidence-only.
- `NonceVaultV1` has Wallet-owned associated handle, permit, and exported
  artifact types. It accepts no caller receipt, witness result, storage result,
  permit bytes, or authorization Boolean.
- `VaultBackedSignerV1<V>` owns the only default-build local sequence:
  reserve, commitment export, reveal export, and one partial export.
- Reservation and request identifiers are allocated internally through the OS
  CSPRNG. The application supplies `ReservationIntentV1`, not durable IDs.
- Secret plaintext crosses the trusted Wallet boundary only through
  non-cloneable, signer-created seal/import capabilities.

## Excluded inputs

No official untracked file, DL2P material, absolute path dependency, Wallet
implementation, witness transport, consensus encoding, existing transaction
wire, block format, or release configuration was imported into the DOM branch.

