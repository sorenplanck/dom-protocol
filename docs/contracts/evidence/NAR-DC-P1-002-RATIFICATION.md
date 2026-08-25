# NAR-DC-P1-002 Ratification Evidence

This record binds the imported storage-persistence closure record to the
operator's established Minisign public identity. It records local integrity
and signature verification; it does not approve G1B, production, mainnet,
Phase 2, publication, or real-funds use.

## Imported artifacts

| Artifact | SHA-256 |
|---|---|
| `docs/specifications/normative/NAR-DC-P1-002-storage-persistence-closure.en.md` | `719a121c11f4b7f8ea016668bfaa05a3e4d03d3a510df31e3495fb9698560e84` |
| `docs/specifications/normative/NAR-DC-P1-002-storage-persistence-closure.en.md.minisig` | `f6b4bff51a13715b85e8f686a61c3bbb8b372496f15bfe716316c55209efb7b2` |

Both imported files were compared byte for byte with the operator-provided
artifacts before this record was written.

## Signature verification

Public key:

```text
RWTwnDDKlXoZdG3obVRiLPfVRHr17E0Fj2GN8IZ2rBkipRZvIIW6PLJ3
```

Command, executed from the repository root:

```sh
minisign -Vm docs/specifications/normative/NAR-DC-P1-002-storage-persistence-closure.en.md \
  -x docs/specifications/normative/NAR-DC-P1-002-storage-persistence-closure.en.md.minisig \
  -P RWTwnDDKlXoZdG3obVRiLPfVRHr17E0Fj2GN8IZ2rBkipRZvIIW6PLJ3
```

Result: exit code `0`; signature and trusted-comment signature verified.

Trusted comment:

```text
timestamp:1785908534 file:NAR-DC-P1-002-storage-persistence-closure.en.md hashed
```

The trusted timestamp converts to `2026-08-05T02:42:14-03:00` in the project
operator's configured timezone.

## Review history and effect

Earlier unsigned drafts were rejected during independent review and have no
normative effect. The signed SHA-256 above is the independently reviewed byte
sequence that closes the assigned Phase 1B persistence inputs. Engineering,
test, platform, publication, external-audit, Phase 2, production, and mainnet
gates remain separate and fail closed.
