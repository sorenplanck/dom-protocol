# DOM Protocol — Normative Gaps and Blockers

| ID | Type | Statement | Minimum action |
| --- | --- | --- | --- |
| `BLOCKED_PERMISSION/INTEGRATION` | authorisation | The fast-forward of `release/mainnet` to `feat/dom-contracts` was **blocked by the environment's permission classifier**, not by git. The FF is verified: 0 commits behind, clean workspace build, passing suite. | Coordinator pushes `feat/dom-contracts:release/mainnet`, or grants the permission. This single action moves every `DSC-*` requirement to integrated. |
| `BLOCKED_EXTERNAL/NODE` | hardware | `DSC-G0`, `G2`, `G3`, `G4`, `G5`, atomic-write crash matrix, fee ladder | Run in the coordinator environment (`docs/scriptless/REGTEST-GATES.md`). |
| `BLOCKED_EXTERNAL/G-COVER` | calendar | ≥90 consecutive days, ≥1,000 confirmed ordinary height-locked kernels | Start the wallet-side default-on campaign; cannot be simulated. |
| `MISSING/UX-LAYER` | scope, STOP-SHIP | `UX-G-UX1`: 10 of 16 criteria have no implementation because the SDK/executor/Keystone layer does not exist here | A product-layer programme, not a set of fixes. |
| `MISSING/SETTLEMENT` | other repository | `SET-F6`, `F4-POLICY`, Keystone, routing: 0 files; `479912b` not an object here | Audit against their own repository. |
| `OPEN/TAG-POLICY` | recorded | Tags are forbidden by coordinator instruction; anchor refs are used instead (`pin/contracts-p1`). Tag pushes are also rejected by this environment. | None — policy recorded. |

## Route and centrality statement (required by the goal)

`DOM → X`, `X → DOM` and `X → DOM → Y` are **`MISSING`** in this repository: no
routing layer exists. Consequently **no direct `X → Y` bypass exists** — there
is nothing here that could bypass DOM. DOM centrality is not violated; it is
simply not yet exercised at this layer.
