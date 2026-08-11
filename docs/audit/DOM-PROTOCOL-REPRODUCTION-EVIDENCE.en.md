# DOM Protocol — Reproduction Evidence

Every claim in this audit set is bound to a command whose output was observed at
the commit named. Evidence not reproduced here is marked as such rather than
inferred from a report.

## Environment

Repository `/workspace/dom-protocol`, remote `sorenplanck/dom-protocol`.
Toolchain: `rust-toolchain.toml` — stable, with `rustfmt` and `clippy`.
Audit line `feat/dom-contracts`. Canonical branch `release/mainnet` @ `7698225`.

## Audit-infrastructure repair

| Command | Observed |
| --- | --- |
| `git rev-parse --is-shallow-repository` | `true` — clone was shallow |
| `git log --oneline \| wc -l` (before) | 34 |
| `git config --get-all remote.origin.fetch` (before) | `+refs/heads/main:refs/remotes/origin/main` — only `main` visible |
| `git fetch --unshallow --tags` | 636 commits on `main`; 148 remote branches; tags recovered |

## Document authority

`sha256sum` on each installed normative document, compared to the digests fixed
by the goal. All four match: Mestra `5ad366d6…`, Cronograma `cfee4487…`,
Relatório `5431ca38…`, Adendo G-UX1 `98453889…`.

## Integration verification

| Command | Observed |
| --- | --- |
| `git merge-base --is-ancestor origin/release/mainnet feat/dom-contracts` | success — FF possible |
| `git rev-list --count origin/release/mainnet..HEAD` / reverse | 51 ahead / **0 behind** |
| `cargo build --workspace --locked` (on FF tree) | `BUILD_EXIT=0` |
| `cargo test -p dom-adaptor` (on FF tree) | `TEST_EXIT=0` |
| `git ls-tree -d --name-only HEAD crates/` | 30 crates, `dom-adaptor` present |

## Suite results reproduced on the audit line

| Scope | Result |
| --- | --- |
| `dom-adaptor` full suite | 202 passed, 0 failed (includes the 739-byte collaborative proof over 2/3/16 participants, verified through `range_proof_verify_with_extra_commit`) |
| `dom-scriptless-store` + `dom-scriptless-crypto` (dom-contracts) | 262 passed, 0 failed |
| `phase1-gate.sh` with `PHASE1_GATE_RUN_TESTS=1` (dom-contracts) | PASS — 0 failed, 12 ignored, 18 compile-fail doctests ≥ 17 |

## Not reproduced (and why)

| Item | Reason |
| --- | --- |
| `DSC-G0`, `G2`, `G3`, `G4`, `G5` | require running regtest nodes and two wallets |
| atomic write under crash (§10.5) | requires the store's process-death harness |
| fee ladder | requires a live relay |
| `G-COVER` | calendar-bound; ≥90 days, ≥1,000 confirmed kernels |
| `UX-01…16` | the application layer they govern does not exist here |

## Defect found in the repository's own gate

`scripts/phase1-gate.sh` (dom-contracts) counted compile-fail doctests from only
the **first** `Doc-tests` section of the workspace output. Once a crate sorting
before `dom-scriptless-store` with zero doctests entered the workspace
(`dom-scriptless-chain-adapter`), the count read 0 and the gate failed while the
store's 17 doctests were in fact executing. Repaired to sum every section
(18 ≥ 17). The gate was not relaxed; it now measures what it claims to measure.
