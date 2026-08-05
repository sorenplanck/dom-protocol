# NAR-DC-P1-006 Ratification Evidence

This record binds the imported final runtime-authority, platform, and evidence
publication closure to the operator's established Minisign public identity. It
records local byte identity and signature verification only. It does not approve
G1A, G1B, consolidated G1, Phase 2, production, mainnet, real funds, a release,
or a package publication.

## Imported artifacts

| Artifact | SHA-256 |
|---|---|
| `docs/scriptless/source-guides/normative/amendments/NAR-DC-P1-006-final-runtime-authority-platform-and-evidence-publication-closure.en.md` | `2aa9ec803167f866737375ffbfeca082f98bd1dc9efbefa06c073131bd215a23` |
| `docs/scriptless/source-guides/normative/amendments/NAR-DC-P1-006-final-runtime-authority-platform-and-evidence-publication-closure.en.md.minisig` | `2ae0f6368261348419284fe294e6837b8ee7ba5a6de5d5be5ea732cec10d5897` |

Both imported files were compared byte for byte with the operator-provided
artifacts before this record was written.

## Signature verification

Public key:

```text
RWTwnDDKlXoZdG3obVRiLPfVRHr17E0Fj2GN8IZ2rBkipRZvIIW6PLJ3
```

Key ID:

```text
74197A95CA309CF0
```

Command, executed from the repository root:

```sh
minisign -V \
  -P RWTwnDDKlXoZdG3obVRiLPfVRHr17E0Fj2GN8IZ2rBkipRZvIIW6PLJ3 \
  -m docs/scriptless/source-guides/normative/amendments/NAR-DC-P1-006-final-runtime-authority-platform-and-evidence-publication-closure.en.md \
  -x docs/scriptless/source-guides/normative/amendments/NAR-DC-P1-006-final-runtime-authority-platform-and-evidence-publication-closure.en.md.minisig
```

Result: exit code `0`; signature and trusted-comment signature verified.

Trusted comment:

```text
timestamp:1785962701 file:NAR-DC-P1-006-final-runtime-authority-platform-and-evidence-publication-closure.en.md hashed
```

The trusted timestamp converts to `2026-08-05T17:45:01-03:00` in the project
operator's configured timezone.

## Ratification effect

The signed byte sequence is the controlling assignment for:

- the statically selected accepted signing-session authority;
- the Store-owned atomic reservation snapshot;
- Store-owned spent-artifact recovery and restart resend binding;
- the Linux-only Phase 1 runtime profile; and
- only the narrowly conditional remote evidence operations stated by the
  signed record.

The source document's embedded pre-signature status line is part of the signed
bytes and was not edited. The verified detached signature supplies the
ratification condition described by its own section 1 and section 10.

Implementation, conformance tests, independent review, publication, dependency
pinning, hosted platform evidence, Phase 2, production, mainnet, and real-funds
gates remain separate and fail closed.
