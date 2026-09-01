# Cumulative history

- V1: RPC quorum, evidence and zeroized primitives.
- V2: revealed-secret mapping, sweep port and local E2E.
- V3: confirmation quorum and idempotent delivery.
- V4: SQLite durability and sidecar boundary.
- V5: real 252-bit `sigma_fun` DLEQ construction.
- V6: corrected/curated production path, authenticated live sidecar, exact raw
  transaction verification, real `adapter-dom-real` hook and Kaystra E2E.
- V6.1: V6 made to build and pass the DOM gates. Seven compilation and lint
  defects repaired, an invalid patch file regenerated, a latent `crates/store`
  defect the package exposed fixed, 38 adversarial tests added across the seven
  crates that had none, and the two real production blockers measured against
  the branch and written down in `docs/RATIFICATION_SHEET.md`.

Obsolete V1–V5 parallel engines are intentionally not auto-installed. Their
security properties are retained in the curated V6 components.
