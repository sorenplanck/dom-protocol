# NAR-DC-P1-005 Ratification Evidence

This record binds the imported reservation-runtime and Linux-capability closure
to the operator's established Minisign public identity. It records local
integrity and signature verification; it does not approve G1A, G1B, G1,
production, mainnet, Phase 2, publication, or real-funds use.

## Imported artifacts

| Artifact | SHA-256 |
|---|---|
| `docs/scriptless/source-guides/normative/amendments/NAR-DC-P1-005-reservation-runtime-and-linux-capability-closure.en.md` | `4f5582a17426ed5b03d6aa37d6c2fc9cfe564985ec3614d0d4a30fed8ae2d635` |
| `docs/scriptless/source-guides/normative/amendments/NAR-DC-P1-005-reservation-runtime-and-linux-capability-closure.en.md.minisig` | `c12a8d65040b03ef507c4309c9c4bf655437bcd9c5c982e9f9a36a04dce90b83` |

Both imported files were compared byte for byte with the operator-provided
artifacts before this record was written.

## Signature verification

Public key:

```text
RWTwnDDKlXoZdG3obVRiLPfVRHr17E0Fj2GN8IZ2rBkipRZvIIW6PLJ3
```

Command, executed from the repository root:

```sh
minisign -Vm docs/scriptless/source-guides/normative/amendments/NAR-DC-P1-005-reservation-runtime-and-linux-capability-closure.en.md \
  -x docs/scriptless/source-guides/normative/amendments/NAR-DC-P1-005-reservation-runtime-and-linux-capability-closure.en.md.minisig \
  -P RWTwnDDKlXoZdG3obVRiLPfVRHr17E0Fj2GN8IZ2rBkipRZvIIW6PLJ3
```

Result: exit code `0`; signature and trusted-comment signature verified.

Trusted comment:

```text
timestamp:1785954170 file:NAR-DC-P1-005-reservation-runtime-and-linux-capability-closure.en.md hashed
```

The trusted timestamp converts to `2026-08-05T15:22:50-03:00` in the project
operator's configured timezone.

## Effect

The signed byte sequence is the ratified assignment for the revised
`dom-adaptor` reservation, accepted-state, resend, prepared-artifact,
cancellation, and Store-conformance boundary. Implementation, tests,
publication, Phase 2, production, mainnet, and real-funds gates remain separate
and fail closed.
