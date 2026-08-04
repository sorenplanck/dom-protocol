# Phase 1 Ratification Verification

Date: 2026-08-04

## Verification boundary

This report covers only the signed artifacts present in the G1a worktree. It
does not make claims about G1b artifacts maintained on other branches.

## Verification key

- Minisign public key: `RWTwnDDKlXoZdG3obVRiLPfVRHr17E0Fj2GN8IZ2rBkipRZvIIW6PLJ3`
- Key ID reported by Minisign: `74197A95CA309CF0`

## Verified artifacts

| Artifact | SHA-256 | Detached-signature result |
|---|---|---|
| `docs/scriptless/source-guides/normative/amendments/NAR-001-normative-assignment-record.en.md` | `eee087c808aeb4e6e745a5311d17ca5a63c5b5e5568218d20b1cbcdd7b6206dc` | valid |
| `docs/scriptless/source-guides/normative/amendments/NAR-002-phase-1-omnibus-normative-closure.en.md` | `b726c2e576833f843d0065a1e823e649ab9e7e28fd9cfedb0e6e06e6b1be87f5` | valid; trusted timestamp `1785878139` |
| `test-vectors/scriptless/two-nonce/kat_inputs_v2.en.json` | `55642208968863a7b2c4773a82d9774f95f2a3b604b80a876d0bf031396b2a7d` | valid |

The NAR-002 document and detached signature were copied byte for byte from
coordinator commit `04fb4c86ce6107d41c97094af0c33021eda3a019`. `cmp --silent`
confirmed identity with the coordinator copies before implementation work.

## Provenance statement

The detached signatures authenticate the exact local bytes under the recorded
DOM release Minisign key. The normative manifest records those bytes by
SHA-256. No signed byte was reformatted or edited.
