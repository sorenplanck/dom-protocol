# NAR-DC-P1-003 Ratification Evidence

This record binds the imported Nonce Vault request, export, and recovery
binding record to the operator's established Minisign public identity. It
records local integrity and signature verification; it does not approve G1B,
G1, production, mainnet, Phase 2, publication, or real-funds use.

## Imported artifacts

| Artifact | SHA-256 |
|---|---|
| `docs/specifications/normative/NAR-DC-P1-003-vault-request-and-recovery-binding.en.md` | `082c855782c71a0f61e85828eaac75440a434d5c05d8357e569592a816db05ef` |
| `docs/specifications/normative/NAR-DC-P1-003-vault-request-and-recovery-binding.en.md.minisig` | `9b7145949fa379901c6b295703c095245126fb86737c24b0bd9bb9efc5004a73` |

Both imported files were compared byte for byte with the operator-provided
artifacts before this record was written.

## Signature verification

Public key:

```text
RWTwnDDKlXoZdG3obVRiLPfVRHr17E0Fj2GN8IZ2rBkipRZvIIW6PLJ3
```

Command, executed from the repository root:

```sh
minisign -Vm docs/specifications/normative/NAR-DC-P1-003-vault-request-and-recovery-binding.en.md \
  -x docs/specifications/normative/NAR-DC-P1-003-vault-request-and-recovery-binding.en.md.minisig \
  -P RWTwnDDKlXoZdG3obVRiLPfVRHr17E0Fj2GN8IZ2rBkipRZvIIW6PLJ3
```

Result: exit code `0`; signature and trusted-comment signature verified.

Trusted comment:

```text
timestamp:1785928426 file:NAR-DC-P1-003-vault-request-and-recovery-binding.en.md hashed
```

The trusted timestamp converts to `2026-08-05T08:13:46-03:00` in the project
operator's configured timezone.

## Effect

The signed SHA-256 above is the ratified byte sequence for the Phase 1B
request, export, resend, abort, and restore bindings assigned by the record.
The document's embedded pre-signature warning remains useful provenance, but
the detached valid signature is the controlling ratification evidence.
Implementation, test, platform, publication, external-audit, Phase 2,
production, mainnet, and real-funds gates remain separate and fail closed.
