# NAR-DC-P1-006 Ratification Evidence

This record binds the imported final runtime-authority, platform, and evidence
publication closure to the operator's established Minisign public identity. It
records local integrity and signature verification; it does not approve G1A,
G1B, consolidated G1, production, mainnet, Phase 2, publication, or real-funds
use.

## Imported artifacts

| Artifact | SHA-256 |
|---|---|
| `docs/specifications/normative/NAR-DC-P1-006-final-runtime-authority-platform-and-evidence-publication-closure.en.md` | `2aa9ec803167f866737375ffbfeca082f98bd1dc9efbefa06c073131bd215a23` |
| `docs/specifications/normative/NAR-DC-P1-006-final-runtime-authority-platform-and-evidence-publication-closure.en.md.minisig` | `2ae0f6368261348419284fe294e6837b8ee7ba5a6de5d5be5ea732cec10d5897` |

Both imported files were compared byte for byte with the operator-provided
artifacts before this record was written. Both comparisons returned exit code
`0`.

## Signature verification

Public key:

```text
RWTwnDDKlXoZdG3obVRiLPfVRHr17E0Fj2GN8IZ2rBkipRZvIIW6PLJ3
```

Command, executed from the repository root:

```sh
minisign -Vm docs/specifications/normative/NAR-DC-P1-006-final-runtime-authority-platform-and-evidence-publication-closure.en.md \
  -x docs/specifications/normative/NAR-DC-P1-006-final-runtime-authority-platform-and-evidence-publication-closure.en.md.minisig \
  -P RWTwnDDKlXoZdG3obVRiLPfVRHr17E0Fj2GN8IZ2rBkipRZvIIW6PLJ3
```

Result: exit code `0`; signature and trusted-comment signature verified.

Trusted comment:

```text
timestamp:1785962701 file:NAR-DC-P1-006-final-runtime-authority-platform-and-evidence-publication-closure.en.md hashed
```

The trusted timestamp converts to `2026-08-05T17:45:01-03:00` in the project
operator's configured timezone.

## Effect

The signed byte sequence is the ratified assignment for:

- the static accepted signing-session authority;
- one atomic retained reservation snapshot;
- Store-owned exact resend recovery identity;
- the Linux-only Phase 1 vault runtime;
- portable Windows/macOS evidence without a durability runtime; and
- the narrowly conditional remote operations stated by the signed record.

This local mission does not exercise the remote-operation authority. No push,
merge, release, package publication, evidence-branch publication, or remote
mutation is performed by importing this record.

Implementation, test execution, independent review, public dependency pinning,
platform evidence, external audit, Phase 2, production, mainnet, and real-funds
gates remain separate and fail closed.
