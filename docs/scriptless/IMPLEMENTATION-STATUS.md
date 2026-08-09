# Implementation status

This document supersedes the version carried on the ratified governance
lineage at `76915842465f89867b045c9016d532dc3538ac2d` (`7691584`). That
version was written before the G1a implementation existed and described
`dom-adaptor` as a skeleton that was "compilable, with no cryptographic
API", with G1a "not started / not approved". Both statements are now
stale on this lineage, so the file is replaced rather than transported.
The rest of the ratified corpus is transported byte-identical; this is
the single deliberate exception.

Status is reported for this repository's axis at
`6f2b230ebbec390040dbf0bff110efaf4bb0f101`.

| Component | Status |
|---|---|
| Isolation and baseline | prepared; final validation recorded in the bootstrap report |
| `dom-adaptor` crate | implements the G1a cryptography (see below) |
| SCAD0 | eight vectors imported byte for byte; origin and hash recorded |
| [G1a — pure cryptography](phase-1a/GATE-G1A.md) | **APPROVED at `6f2b230ebbec390040dbf0bff110efaf4bb0f101`** |
| [G1b — vault and rollback](phase-1b/GATE-G1B.md) | **not approved** in this repository's axis; its 26 checklist items remain open |
| Wallet V3 integration | not started |
| Production | **prohibited** until G1a and G1b are both formally approved |

## What `dom-adaptor` implements

The crate is no longer a skeleton. It carries the G1a cryptographic
surface:

- adaptor pre-signatures
- the canonical transcript
- the two-nonce scheme
- share proof of possession (PoP)
- the collaborative Bulletproof boundary
- the Nonce Vault trait seam

## SCAD0 vectors

The eight SCAD0 vectors are imported byte for byte. The extract is
`test-vectors/scriptless/scad0/DOM_SCAD0_8_VETORES_2026-08-03.txt`,
sha256
`e99ad8a32edc3db52941e6729c032893d2b864ab995821debf574468b7beaa4b`,
listed in `test-vectors/scriptless/MANIFEST.sha256` and carrying the
expected eight `VECTOR_BEGIN` records.

## G1b is open

G1b is not approved here. All 26 items of
[`GATE-G1B.md`](phase-1b/GATE-G1B.md) are open. `scripts/scriptless/phase1-gate.sh`
reports Phase 1 as NOT APPROVED for exactly this reason, and will keep
doing so until those items are closed and formally approved.

## Scope of the G1a approval

Approving G1a does **not** approve G1b, does **not** approve Phase 1,
does **not** authorise production activation, and does **not** authorise
use with real funds.

No consensus, wire, serialization or persisted-state change was made.
