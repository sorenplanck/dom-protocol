# NAR-DC-P1-007 Ratification Evidence

This record binds the imported phase-state, two-party roster, and funding
authority closure to the operator's established Minisign public identity. It
records local integrity and signature verification; it does not approve G1A,
G1B, consolidated G1, production, mainnet, Phase 2, publication, or real-funds
use.

## Imported artifacts

| Artifact | SHA-256 |
|---|---|
| `docs/specifications/normative/NAR-DC-P1-007-phase-state-participant-and-funding-authority-closure.en.md` | `101ff5e9f3981b47ec038c1772bcc4a6f8849c7f9774a9e1f624fc0880d578e0` |
| `docs/specifications/normative/NAR-DC-P1-007-phase-state-participant-and-funding-authority-closure.en.md.minisig` | `4aaa810503858f8447694f8106ba90c6e99b64f3f8a30423eb5ff82e2ab2dc23` |

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
minisign -Vm docs/specifications/normative/NAR-DC-P1-007-phase-state-participant-and-funding-authority-closure.en.md \
  -x docs/specifications/normative/NAR-DC-P1-007-phase-state-participant-and-funding-authority-closure.en.md.minisig \
  -P RWTwnDDKlXoZdG3obVRiLPfVRHr17E0Fj2GN8IZ2rBkipRZvIIW6PLJ3
```

Result: exit code `0`; signature and trusted-comment signature verified.

The signature carries the prehashed algorithm identifier `ED` and key ID
`74197A95CA309CF0`, matching the algorithm and identity of NAR-DC-P1-001
through NAR-DC-P1-006.

Trusted comment:

```text
timestamp:1786479118 file:NAR-DC-P1-007-phase-state-participant-and-funding-authority-closure.en.md hashed
```

The trusted timestamp converts to `2026-08-11T17:11:58-03:00` in the project
operator's configured timezone.

## Effect

The signed byte sequence is the ratified assignment for:

- the closed participant cardinality of the strict V1 contract profile, fixed
  at exactly two distinct participants, with `n`-of-`n` outside V1;
- the canonical directed phase-transition table, fixed at exactly 22 unique
  directed edges, removing the two §9.2 shortcuts and making `RefundSigning`,
  `ClaimSigning`, `RefundBroadcast` and the refund terminal `Refunded`
  reachable; and
- the recorded status of the funding-authorisation surface as a model rather
  than production authority, together with the four properties production
  requires before that status may change.

The record resolves an internal divergence between Master Specification §9.1
and §9.2 by adjudication recorded against those documents. It does not amend,
replace, or reissue the Master Specification v1.0 R1 or the Implementation
Schedule v1, and it does not change the dependency pin.

Ratification assigns normative meaning only. It does not attest that any
implementation, test, or evidence exists, and it authorises no state-machine,
funding, adaptor, Bulletproof, claim, envelope, SDK, or G-UX1 code.

Conformance of the ratified bytes is enforced mechanically by
`scripts/check-normative-adjudication.sh`, which fails unless the canonical
table declares exactly the 22 adjudicated edges, neither removed shortcut
appears, every previously unreachable phase has an entry edge, and the
participant cardinality is declared as exactly two distinct participants.

Implementation, test execution, independent review, platform evidence, external
audit, Phase 2, production, mainnet, and real-funds gates remain separate and
fail closed.
