# DOM Protocol — Workstream Ownership

One owner per bounded workstream; one branch per workstream; only the
integration owner merges. Interfaces are frozen before parallel work begins.

| Workstream | Scope | Branch | Owner | State |
| --- | --- | --- | --- | --- |
| Audit and integration | audit artefacts, branch reconciliation, pin anchoring | `feat/dom-contracts` | integration owner | active |
| Pin anchoring | keeping pinned revisions reachable | `pin/contracts-p1` (anchor, never advanced) | integration owner | done |
| Node gates | `DSC-G0`, `G2`–`G5`, crash matrix, fee ladder | coordinator environment | coordinator | blocked (hardware) |
| Cover-traffic campaign | `G-COVER`, height-locked default-on rollout | wallet repository | wallet owner | not started (calendar) |
| UX/SDK layer | `UX-G-UX1`, SDK, persistent executor, Keystone tolerance | not created | unassigned | missing (largest gap) |
| Settlement layer | `SET-F6`, `F4-POLICY`, routing, chain adapters | other repository | unassigned | outside this repository |

## Frozen interfaces

Before any parallel work on the Scriptless crate, these are frozen and must not
be changed without coordinator ratification:

- the `DomainTag` closed registry and `docs/HASH_DOMAINS.md` (§3.4 freeze);
- `BpStatementV1` byte layout and the 739-byte proof (§5.2);
- the recovery/decoy capsule framing, 96 bytes (§1.3 indistinguishability);
- the contract stage registry and its ordering (§7.2/§9.1);
- the pinned revision `6f2b230` and its anchor ref.

## Boundary rules

- DOM Contracts is a separate product from the DOM Wallet; no wallet code is
  written by this workstream.
- The Scriptless L1 scope stays 2-of-2 funding, adaptor claim and absolute
  timelock refund. Routing semantics never enter DOM L1 wire formats.
- No Scriptless marker, session id or protocol metadata on the private on-chain
  path.
