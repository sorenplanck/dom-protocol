# Post-mortems

Incident write-ups for DOM Protocol consensus and network failures.

Each document records, for one incident:

1. the **triggering condition**
2. the **invariant that failed** — which assumption turned out to be wrong
3. **why the existing test suite did not detect it**
4. the **regression evidence** added afterwards
5. **where the system remains fragile** — open weaknesses in that area

The fifth section exists so that contributors can choose work by known failure
boundary rather than by feature area. If you are looking for something
consequential to work on, those sections are the honest list.

## Incidents

| Date | Incident | Fix | Class |
|---|---|---|---|
| 2026-07-21 | [Difficulty collapse and stall](2026-07-21-difficulty-collapse.md) | `065e484` | Consensus — hard fork at height 4849 |
| 2026-07-22 | [Equal-height fork divergence](2026-07-22-equal-height-fork-divergence.md) | `5fad708` | Chain selection — no fork risk |

## A note on scope

These are written after the fact by the maintainer, from logs, commits and test
runs. They are not independent audits. Where a claim can be checked against the
repository, the commit is cited so it can be checked; where something is a
judgement about why a gap existed, it is stated as such.

Corrections are welcome as issues or pull requests. If a post-mortem overstates
what a fix accomplished, that is a bug in the document and worth reporting like
any other.
