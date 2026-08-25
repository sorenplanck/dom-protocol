# NAR-DC-P1-004 Ratification Evidence

This record binds the imported live Nonce Vault layout and runtime closure
record to the operator's established Minisign public identity. It records
local integrity and signature verification; it does not approve G1B, G1,
production, mainnet, Phase 2, publication, or real-funds use.

## Imported artifacts

| Artifact | SHA-256 |
|---|---|
| `docs/specifications/normative/NAR-DC-P1-004-live-store-layout-and-runtime-closure.en.md` | `2f9eadb08080844ade7dacfa117a71948ee8a365841fff860d69fe734c42b510` |
| `docs/specifications/normative/NAR-DC-P1-004-live-store-layout-and-runtime-closure.en.md.minisig` | `95b507dc8c922608a8b1da0e85d287eb001144de3ed80cf3440e83033ae6276e` |

Both imported files were compared byte for byte with the operator-provided
artifacts before this record was written.

## Signature verification

Public key:

```text
RWTwnDDKlXoZdG3obVRiLPfVRHr17E0Fj2GN8IZ2rBkipRZvIIW6PLJ3
```

Command, executed from the repository root:

```sh
minisign -Vm docs/specifications/normative/NAR-DC-P1-004-live-store-layout-and-runtime-closure.en.md \
  -x docs/specifications/normative/NAR-DC-P1-004-live-store-layout-and-runtime-closure.en.md.minisig \
  -P RWTwnDDKlXoZdG3obVRiLPfVRHr17E0Fj2GN8IZ2rBkipRZvIIW6PLJ3
```

Result: exit code `0`; signature and trusted-comment signature verified.

Trusted comment:

```text
timestamp:1785950137 file:NAR-DC-P1-004-live-store-layout-and-runtime-closure.en.md hashed
```

The trusted timestamp converts to `2026-08-05T14:15:37-03:00` in the project
operator's configured timezone.

## Independent review

The frozen record was independently reviewed before ratification. The final
binding/API review and the final ratification audit both reported `PASS` with
zero findings. Their private local evidence hashes are:

| Review | SHA-256 |
|---|---|
| Binding/API design review | `3017035dc0e05e2e542d8c33735f8e14945ff4d78f388ae8ce7102415e6a006b` |
| Final ratification audit | `d6643e797ae2b43338d377f077448ac76fb48b08aea285f5fb7da24eae624ed0` |

These review reports contain machine-local provenance and are not imported
into the repository.

## Effect

The signed SHA-256 above is the ratified byte sequence for the Phase 1B live
store layouts, operation inputs, transcript transitions, retained-handle
runtime contract, retry ownership, exact persistence order, recovery behavior,
and explicit evidence obligations assigned by the record. Implementation,
test, platform, publication, external-audit, Phase 2, production, mainnet, and
real-funds gates remain separate and fail closed.
