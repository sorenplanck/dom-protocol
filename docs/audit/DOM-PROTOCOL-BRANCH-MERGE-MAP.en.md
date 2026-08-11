# DOM Protocol — Branch and Merge Map

Canonical branch: `release/mainnet` @ `7698225`
Non-canonical: `main` @ `6df2393` (release is +72 / -14 relative to main)
Date: 2026-08-11

## Integration reality

| Line | Ahead of `release/mainnet` | Behind | Carries `dom-adaptor` |
| --- | --- | --- | --- |
| `feat/dom-contracts` (this work, ex `g1-closed-cycle-property`) | 51 | **0** | yes — 29 `src` files |
| `feat/scriptless-*`, `feat/dom-protocol-phase1-*`, `g1a-*` | varies | varies | yes — 20 `src` files |
| `feat/phase-1-integrated`, `evidence/share-pop-*` | varies | varies | yes — 17 |
| `release/mainnet` | — | — | **no** |
| `main` | — | — | **no** |

**Key fact: `release/mainnet` is a direct ancestor of `feat/dom-contracts`
(0 commits behind).** Integrating the Scriptless work into the official branch
is therefore a **fast-forward with zero conflicts**, not a merge. This was
verified locally: the fast-forwarded tree builds (`cargo build --workspace
--locked`, exit 0) and the `dom-adaptor` suite passes (exit 0), yielding 30
crates with `dom-adaptor` present.

## Anchor refs (never advanced, never deleted)

| Ref | Points at | Purpose |
| --- | --- | --- |
| `pin/contracts-p1` | `6f2b230` | Keeps the revision pinned by `sorenplanck/dom-contracts` permanently reachable. Tags are not used, by coordinator instruction. |

## Commits of record

| Commit | In `release/mainnet` | Meaning |
| --- | --- | --- |
| `7698225` | tip | frozen SCAD0 adaptor vectors |
| `19c191f` | yes | height-locked kernel construction |
| `76597c6` | yes | RPC height-lock exposure |
| `6f2b230` | **no** | the Contracts pin — anchored by `pin/contracts-p1` |

`fa2f3e7`, `767788b`, `b4847f2`, `abb5731`, `479912b` are **not objects in this
repository**; they belong to another repository or do not exist.

## Open integration decision

Fast-forwarding `release/mainnet` to `feat/dom-contracts` is the single action
that converts every `DSC-*` requirement from `IMPLEMENTED_UNVERIFIED` to
integrated. It is a push to the official mainnet branch and is therefore held
pending explicit coordinator authorisation.
