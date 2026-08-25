# F0 CLOSURE REPORT — Foundation

```text
Phase:               F0 — Foundation (no protocol code)
Gate:                G-F0 = VECTORS_GREEN + IP_SIGNED + LICENSES_DECIDED
Foundation Document: docs/normative/DOM-Interop-Foundation-Document-v0.5.md
Waiver lifted:       R-001 (G-F0 = WAIVER FOR F1, 2026-08-09)
Date:                2026-08-10
Authority:           operator decisions of 2026-08-10, recorded in the
                     project chat and ratified as D-009, D-010, D-011
```

F0 was executed out of order by design: the technical deliverables
(workspace, CI, conformance, guards) landed with F1/F2 under the R-001
waiver, while the three foundation decisions stayed open. This report
closes the gate by adjudicating each component of its formula.

## 1. VECTORS_GREEN — satisfied

The CI `dom-conformance` job runs the dom-adaptor's OWN suite at the
pinned rev `a1825639154dcc9d89be098079112e9cb975940e` (84 tests +
doctests, including the 311-intermediate comparison), then `dom-leg`
(25 tests) and `dom-vault` (42 tests) against the real crate. All green
on `main` at the F2 closure (run for commit `f6f977e`, conclusion:
success). The grep-gates for I2/I6/I14/§4.2 plus the F1/F2 guards are
7/7 PASS.

## 2. IP_SIGNED — satisfied

`docs/legal/IP-DECLARATION.md`: Soren Planck declares sole authorship of
all copyrightable material in `sorenplanck/Dom-interop` and
`sorenplanck/dom-protocol` (including tool-assisted work adopted as his
own), owns all IP in it, and requires a recorded IP assignment from any
future contributor before their first merge. Ratified by operator order
recorded in the project chat (2026-08-10).

## 3. LICENSES_DECIDED — satisfied (D-010)

The definitive licensing plan, superseding the provisional half of
D-007 while keeping its mechanics:

- **Until F8** (integration into the DOM v2): proprietary, privately
  hosted (GitHub private repository). `LICENSE` = all rights reserved,
  SPDX `UNLICENSED`, `publish = false`.
- **At F8**: the code merges into the DOM v2 and adopts the DOM
  protocol's **MIT** license (verified: `sorenplanck/dom-protocol`
  carries MIT, copyright Soren Planck — the identical rights holder, so
  the conversion is a unilateral act with no third-party consent
  needed).
- **Keystone BUSL** relicensing/rewrite: deferred to F5 as a dependency
  of that phase (recorded in D-010), not a G-F0 blocker.

## 4. The three open items of the waiver

| Item | Resolution |
|---|---|
| A1 — product name | D-009: no standalone name or brand; DOM ecosystem component, integrated into the DOM v2 at F8. "DOM Interop" is only the descriptive repository name. |
| A2 — definitive license | D-010, above. |
| A12 — dyn-compat of the async adapter trait | D-011: native `async fn` + static dispatch; closed enum wrapper if F3/F5 ever need uniform handling; `#[async_trait]` rejected. Full rationale and F1/F2 evidence in `docs/adr/ADR-A12-async-trait-dispatch.md`. |

## 5. Adjudication

```text
G-F0 = PASS (2026-08-10)
```

All three components of the gate formula are satisfied and the R-001
waiver is lifted (registry record R-002). F0 no longer blocks F3.
Starting F3 remains a separate operator decision and is NOT taken by
this report.
