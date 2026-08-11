# DOM Protocol — Execution Backlog (dependency order)

Derived from the canonical audit. Ordered so that each item unblocks the next.

## Resolved during the audit

| ID | Item | Outcome |
| --- | --- | --- |
| INT-3 | Contracts pin `6f2b230` sustained only by mutable feature branches | **RESOLVED** — anchor ref `pin/contracts-p1` pushed; `DEPENDENCY-PIN.md` records it |
| A-1 | G-UX1 addendum absent | **RESOLVED** — supplied, SHA-256 verified, installed |

## Executable now (no external dependency)

| ID | Item | Status |
| --- | --- | --- |
| INT-2 | Fast-forward `release/mainnet` to `feat/dom-contracts` | **prepared and verified locally**; awaits authorisation to push |
| BL-1 | Remaining audit artefacts (requirements matrix, gaps, evidence, ownership) | in progress |

## Blocked — needs a running node (coordinator environment)

| ID | Item |
| --- | --- |
| `DSC-G0` | ordinary 1→1 regtest transfer, restart/rescan, recipient spend |
| `DSC-G2` | two wallets publish an accepted shared output, 872 bytes on the wire |
| `DSC-G3` | interruption matrix at every protocol step |
| `DSC-G4` | abandonment matrix; refund accepted at first valid height |
| `DSC-G5` | two-terminal cycle with byte-verified extraction |
| `DSC-F3` | atomic write under crash (persist → tombstone → commit → fsync) |
| `DSC-F5` | fee ladder under a live relay |

## Blocked — scope outside this repository

| ID | Item |
| --- | --- |
| `SET-F6` | RFQ/Quote/Selection/Relay — 0 files here; `479912b` not an object here |
| `F4-POLICY` | USPE exposure and bond policy — 0 files here |
| Keystone | coordination layer — 0 files here |
| Routing | `DOM → X`, `X → DOM`, `X → DOM → Y` — no routing layer exists |

## Blocked — calendar

| ID | Item |
| --- | --- |
| `G-COVER` | ≥90 consecutive days default-on and ≥1,000 confirmed ordinary height-locked kernels. Cannot be simulated. |

## The largest single gap

`UX-G-UX1` is a **STOP-SHIP** gate whose sixteen criteria govern an
application/SDK layer that does not exist here: 10 criteria `MISSING`, 6
`PARTIAL` on supporting primitives only. Completing every cryptographic phase
does not shorten this path. See the canonical audit §9.
