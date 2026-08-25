# NAR-DC-P1-001 Ratification Evidence

This record binds the imported omnibus Phase 1 gap assignment to the operator's
established Minisign public identity. It records local integrity and signature
verification; it does not approve G1A, G1B, Phase 2, production, or mainnet.

## Imported artifacts

| Artifact | SHA-256 |
|---|---|
| `docs/specifications/normative/NAR-DC-P1-001-omnibus-gap-closure.en.md` | `88586449d577038ac98e9463250821ed9b3d1e6c94f5b11abfaf036a93eec655` |
| `docs/specifications/normative/NAR-DC-P1-001-omnibus-gap-closure.en.md.minisig` | `2f19ec266f05e440cb5de2b91bc4295b93b2629170adbf6d020505ebb2311ffc` |

Both imported files were compared byte for byte with the operator-provided
artifacts before this record was written.

## Signature verification

Public key:

```text
RWTwnDDKlXoZdG3obVRiLPfVRHr17E0Fj2GN8IZ2rBkipRZvIIW6PLJ3
```

Command, executed from the repository root:

```sh
minisign -Vm docs/specifications/normative/NAR-DC-P1-001-omnibus-gap-closure.en.md \
  -x docs/specifications/normative/NAR-DC-P1-001-omnibus-gap-closure.en.md.minisig \
  -P RWTwnDDKlXoZdG3obVRiLPfVRHr17E0Fj2GN8IZ2rBkipRZvIIW6PLJ3
```

Result: exit code `0`; signature and trusted-comment signature verified.

Trusted comment:

```text
timestamp:1785904289 file:NAR-DC-P1-001-omnibus-gap-closure.en.md hashed
```

The trusted timestamp converts to `2026-08-05T01:31:29-03:00` in the project
operator's configured timezone.

## Effect

The decisions explicitly assigned by NAR-DC-P1-001 are ratified inputs for the
Phase 1 implementation. Engineering, evidence, platform, publication,
independent-audit, Phase 2, production, and mainnet gates remain separate and
fail closed until their objective criteria are satisfied.
