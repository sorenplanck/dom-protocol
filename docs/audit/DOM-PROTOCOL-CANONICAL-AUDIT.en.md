# DOM Protocol — Canonical Audit (Read-Only Phase)

Audited repository: `/workspace/dom-protocol`
Remote: `https://github.com/sorenplanck/dom-protocol` (confirmed)
Audit HEAD: `791d3bcef5b0abc3d5c56f5a2ada19084abf9840`
(branch `feat/dom-protocol-g1-closed-cycle-property`)
**Canonical integration branch: `origin/release/mainnet` @ `7698225`**
(identified by the coordinator as the official branch; `main` @ `6df2393` is
*not* the integration target)
Date: 2026-08-11

> **Correction notice.** The first pass of this audit was computed against
> `main`. The coordinator identified `release/mainnet` as the official branch
> mid-audit, and the reachability analysis was redone against it. Findings A-2
> and A-3 below were **produced against the wrong branch and are retracted**;
> the corrected results are recorded in their place. This is logged rather than
> silently edited, because an audit that hides its own correction is worth no
> more than the reports it exists to check.

This document reports **repository truth established by direct inspection**, not
by trusting any prior report or agent summary. Every claim below is backed by a
command whose output was observed at the commits named here.

---

## 0. Audit-infrastructure defects found and repaired (non-destructive)

The repository as delivered **could not support the required archaeology**:

| Defect | Evidence | Repair |
| --- | --- | --- |
| Shallow clone | `git rev-parse --is-shallow-repository` = `true`; only **34** commits reachable | `git fetch --unshallow` → **636** commits on `main` |
| Fetch refspec restricted to `main` | `remote.origin.fetch` = `+refs/heads/main:refs/remotes/origin/main` — every other remote branch invisible | refspec broadened to `+refs/heads/*:refs/remotes/origin/*` |
| No tags | `git tag` empty | tags fetched (`v1.0.0`, `v2.0.1`, `wallet-v2*`, `pre-bp-migration-main`, …) |

No destructive operation was used: no `reset --hard`, no `clean`, no history
rewrite, no force-push, no branch deletion. Only additive fetches and one
read-side config change.

**Consequence for prior reporting:** any status produced in this environment
*before* this repair was computed against 34 commits and a single visible
branch. Such statuses cannot have been complete, regardless of their confidence.

---

## 1. Authority documents — hash verification

The goal supplies expected SHA-256 values. Verified directly:

| Document | Expected SHA-256 | Found | Verdict |
| --- | --- | --- | --- |
| `DOM-Scriptless-Contracts-Especificacao-Mestra-v1.0.docx` | `5ad366d6…dd6b5` | `5ad366d6b5c01c88bc88d4e9c016b447c32f24fbc24a32fa8b6946d7ff5dd6b5` | **MATCH** |
| `DOM-Scriptless-Cronograma-Implementacao-v1.md` | `cfee4487…95e48` | `cfee44873007390f1e19ea95ec5da66e860373a882c32af51ace985fde495e48` | **MATCH** |
| `DOM-Scriptless-Relatorio-Consolidado-v1.md` | `5431ca38…35acb` | `5431ca3894c42ffbee86cd719d4bb0e70ec8ddfb21b33895e889372fa5335acb` | **MATCH** |
| `DOM-Scriptless-Adendo-P1-UX-DevEx-G-UX1-v1.0` | `98453889…ecb2d` | *not present* | **ABSENT** |

All three present documents are byte-identical to the supplied baseline, at
`docs/scriptless/source-guides/normative/`.

**Finding A-1 — `BLOCKED_EXTERNAL`.** The UX/DevEx addendum defining gate
`UX-G-UX1` is **not in this repository**. Every UX-01…UX-16 criterion is
therefore unauditable here: the authority text is unavailable. No UX-G-UX1
status may be asserted — positively or negatively — until the document is
supplied.

---

## 2. HEADLINE FINDING — the Scriptless implementation is not integrated

**`crates/dom-adaptor` is ABSENT from the canonical branch `release/mainnet`,
and also from `main`.** This finding survived the branch correction.

Evidence:

```
git cat-file -e origin/release/mainnet:crates/dom-adaptor → fails (absent)
git cat-file -e origin/main:crates/dom-adaptor            → fails (absent)
git ls-tree -d --name-only origin/release/mainnet crates/ → 29 crates, no dom-adaptor
```

Both branches carry the DOM node/chain product (`dom-consensus`, `dom-core`,
`dom-crypto`, `dom-node`, `dom-slate`, `dom-store`, `dom-rpc`, `dom-wallet`, …).
Neither contains **any** of the DOM Scriptless Contracts implementation.

The entire body of work for `DSC-F1` … `DSC-F6` — the adaptor crate, the
collaborative Bulletproof driver, the contract session state machine, the
funding-authority typestate, the joint-blinding session layer, the decoy
capsule, the frozen hash-domain registry — exists **only on feature branches**.

### 2.0 The work exists, and it is substantial

This must be stated precisely, because "absent from the release branch" is not
"missing". **25 remote branches carry `crates/dom-adaptor`.** Ranked by source
files under `crates/dom-adaptor/src`:

| Branch | Date | `src` files |
| --- | --- | --- |
| `feat/dom-protocol-g1-closed-cycle-property` | 2026-08-10 | **29** |
| `feat/scriptless-session-authority-entry` | 2026-08-10 | 20 |
| `feat/scriptless-revealed-adaptor-secret-export` | 2026-08-10 | 20 |
| `feat/dom-protocol-phase1-closure` | 2026-08-10 | 20 |
| `feat/dom-protocol-phase1-governance` | 2026-08-09 | 20 |
| `feat/dom-protocol-g1a-*` (4 branches) | 2026-08-09 | 20 |
| `feat/dom-protocol-g0-baseline` | 2026-08-09 | 20 |
| `feat/dom-adaptor-p1-005-*`, `p1-009-*` | 2026-08-05…07 | 20 |
| `feat/phase-1-integrated`, `evidence/share-pop-*` | 2026-08-05 | 17 |
| `feat/phase-1-g1a-implementation` | 2026-08-04 | 9 |
| `feat/phase-3-snv-contract` | 2026-08-04 | 2 |

`feat/dom-protocol-g1-closed-cycle-property` is the **most advanced line** by a
clear margin (29 files against 20 in the next tier), and is the branch this
audit runs from. The additional modules over the 20-file tier are the Phase 2–5
pure-logic deliverables: the joint-blinding session layer, the public
collaborative-range-proof driver, the frozen `DomainTag` registry, the chain
projection, the CPFP fee-bump calculator, and the contract/funding state
machines.

**So the correct characterisation is an integration gap, not an absence of
work.** A large, tested implementation exists; no part of it has reached the
official release line.

### 2.1 Status consequence

The goal defines `VERIFIED_COMPLETE` as requiring that an implementation "is
reachable from the intended integration branch." Since no Scriptless code is
reachable from `main`:

> **No `DSC-*` requirement can currently hold status `VERIFIED_COMPLETE`.**

The highest status any Scriptless requirement can hold today is
`IMPLEMENTED_UNVERIFIED` or `PARTIAL`, pending integration. This is an
integration-state fact and is independent of the quality of the code or of the
tests that pass on the branches.

### 2.2 Correction of prior reporting in this environment

Earlier status messages in this working session described Scriptless phase
deliverables as "closed" or "done". Those statements were true in a narrower
sense — implemented and passing tests **on the working branch** — but they did
**not** establish integration into `main`, and they were produced while the
repository was shallow and single-branch. Against this goal's vocabulary they
overstate completion. This audit supersedes them.

---

## 3. Branch and commit archaeology

**148 remote branches** exist. The audit HEAD branch stands **122 commits ahead
of and 14 commits behind** `origin/main`.

### 3.1 Discovery leads from the goal (§6.1)

Reachability is reported against the **canonical branch `release/mainnet`**.

| Lead | Exists here? | In `release/mainnet`? | In `main`? | Subject |
| --- | --- | --- | --- | --- |
| `19c191f` | yes | **YES** | no | `feat(tx): build height-locked kernels` |
| `76597c6` | yes | **YES** | no | `feat(rpc): expose kernel height locks` |
| `7698225` | yes | **YES — it is the branch tip** | no | `test(consensus): freeze SCAD0 adaptor vectors` |
| `6f2b230` | yes | **no** | no | `fix(crypto): allow the FFI-shaped argument count on the MPC rounds` |
| `fa2f3e7` | **no** | — | not an object in this repository |
| `767788b` | **no** | — | not an object in this repository |
| `b4847f2` | **no** | — | not an object in this repository |
| `abb5731` | **no** | — | not an object in this repository |
| `479912b` | **no** | — | not an object in this repository |

All five named lead branches exist:
`feat/dom-adaptor-p1-005-composition-seam`,
`feat/dom-adaptor-p1-009-partial-resend`,
`feat/phase-3-snv-contract`,
`feat/phase-1-dom-adaptor`,
`test/phase-1-independent-evidence`.

**Finding A-2 — RETRACTED.** The first pass asserted that `19c191f` and
`76597c6` were missing from the shipping branch. Against the canonical branch
`release/mainnet` **both are present**. Height-locked kernel construction and
its RPC surface are on the official branch. The `DSC-F5` refund substrate and
the `G-COVER` prerequisite are therefore satisfied at the protocol layer; what
remains for `G-COVER` is the wallet-side default-on campaign and the calendar,
not a missing capability.

**Finding A-3 — RETRACTED.** `7698225` is not merely present on the canonical
branch — **it is the branch tip**. The frozen SCAD0 adaptor vectors are the
current head of `release/mainnet`. The `DSC-F1` canonical-vector requirement is
satisfied on the integration branch.

**Finding A-4 — CONFIRMED, critical, cross-repository.** The pin consumed by
`sorenplanck/dom-contracts` is `6f2b230`, and that commit is reachable from
**neither `release/mainnet` nor `main`**. The Contracts product is pinned to a
*feature-branch* revision of the protocol. A branch is not a durable
distribution point: it can be rebased, renamed or deleted, and the pinned tree
would then be unresolvable. This pin requires either integration of `6f2b230`
into `release/mainnet`, or an immutable tag that preserves it.

**Finding A-6 — branch divergence.** `release/mainnet` is **72 commits ahead of
and 14 commits behind** `main`. The two have genuinely diverged: `main` carries
14 commits the official branch lacks. Which of those 14 belong on the release
line is a governance question, not an audit conclusion.

---

## 4. Product-scope reality check

The goal describes a DOM-centred multichain settlement product
(`X → DOM → Y`) with an RFQ/Quote/Selection/Relay layer (`SET-F6`), a USPE
bond/exposure policy (`F4-POLICY`), Keystone coordination, and chain adapters.

Searched `origin/main` for every identifying token:

| Token | Files in `main` |
| --- | --- |
| `Kaystra` | 0 |
| `USPE` | 0 |
| `Keystone` | 0 |
| `RfqV1` | 0 |
| `QuoteV1` | 0 |
| `RelayEnvelope` | 0 |
| `f6-model` | 0 |
| `DL2P` | 1 (mention only) |

**Finding A-5 — scope.** The settlement layer described by the goal **does not
exist in this repository, in any form**, and `479912b` (its claimed step-1
commit) is not an object here. `SET-F6`, `F4-POLICY`, Keystone coordination,
chain adapters and the routing model are therefore classified
`MISSING (different product boundary)` for `sorenplanck/dom-protocol` — not
`DOCUMENTED_ONLY`, because their specifications are also absent here.

This repository is the **DOM protocol node plus the Scriptless L1 primitive**.
The settlement layer, if it exists, lives elsewhere and must be audited against
its own repository before any status can be asserted.

**Consequence for the route question the goal asks to answer explicitly:**
`DOM → X`, `X → DOM` and `X → DOM → Y` route support is `MISSING` here, and
there is correspondingly **no direct `X → Y` bypass in this repository** — no
routing layer of any kind exists to bypass anything. DOM centrality is not
violated here; it is simply not yet exercised.

---

## 5. What `main` actually contains

29 crates forming the DOM node and wallet stack. The Scriptless-relevant
capabilities present on `main`:

- `dom-crypto` — canonical `blake2b_256_tagged` (BLAKE2b-256, framing
  `len_u16_le || tag || data`), Pedersen commitments, range proofs, the
  vendored Bulletproof FFI;
- `dom-consensus` — transaction validation including `validate_lock_heights`
  (RFC-0010 §7 semantics: `TemporarilyInvalid` iff `lock_height > current`);
- `dom-slate` — the interactive slate builder, including
  `build_send_with_lock_height`;
- `dom-node`, `dom-mempool`, `dom-store`, `dom-rpc` — the running node surface.

The ordinary-transfer substrate that `DSC-F0`/`G0` is meant to exercise is
present on `main`. The Scriptless layer built on top of it is not.

---

## 6. Immediate integration backlog (dependency order)

Derived strictly from the findings above:

1. **INT-1 (critical).** Reconcile the audit branch with `main`: it is 14
   commits behind and 122 ahead. Merge `main` in, resolve, re-run the full
   suite, then integrate.
2. **INT-2 (critical).** Integrate `crates/dom-adaptor` into `main`, or record
   an explicit ratified decision that the Scriptless crate ships from a branch.
   Until then no `DSC-*` requirement can reach `VERIFIED_COMPLETE`.
3. **INT-3 (critical).** Resolve the `6f2b230` pin: integrate it into `main` or
   create an immutable tag, so `dom-contracts` does not depend on a mutable ref.
4. **INT-4 (high).** Integrate `19c191f` + `76597c6` (height-locked kernels and
   their RPC surface) into `main` — prerequisite for `DSC-F5` refunds and for
   starting the `G-COVER` calendar.
5. **INT-5 (high).** Integrate `7698225` (frozen SCAD0 adaptor vectors) so the
   `DSC-F1` canonical vectors exist on the integration branch.
6. **INT-6 (blocked).** `UX-G-UX1` — supply the missing addendum
   (`98453889…ecb2d`) before any UX criterion is audited.

---

## 7. Blockers requiring a decision (work stops only here)

| ID | Type | Statement |
| --- | --- | --- |
| `BLOCKED_EXTERNAL/UX-DOC` | missing authority | The G-UX1 addendum is absent; UX-01…UX-16 are unauditable. |
| `BLOCKED_EXTERNAL/SET-REPO` | wrong repository | `SET-F6`, `F4-POLICY`, Keystone and routing are absent here; auditing them requires their repository. |
| `BLOCKED_NORMATIVE/PIN` | ratification | Whether `dom-contracts` may pin a feature-branch revision, or `6f2b230` must be tagged/integrated, is a coordinator decision. |
| `BLOCKED_EXTERNAL/G0` | node required | `DSC-G0` (ordinary 1→1 regtest transfer, restart/rescan, recipient spend) needs two running regtest nodes; unavailable in this environment. |
| `BLOCKED_EXTERNAL/G-COVER` | calendar | ≥90 consecutive days and ≥1,000 confirmed ordinary height-locked kernels. Cannot be simulated. |

---

## 8. Method note

Percentages are deliberately not reported. A single number would obscure the
central fact of this audit: a large volume of implemented, tested code exists
on branches, and essentially none of it is integrated. Counting "done" work
without the integration axis is exactly the error this audit exists to correct.

```text
AUDIT_PHASE = READ_ONLY_COMPLETE
REPOSITORY = sorenplanck/dom-protocol
CANONICAL_BRANCH = release/mainnet @ 7698225
NON_CANONICAL = main @ 6df2393 (release is +72/-14 vs main)
SHALLOW_REPAIRED = YES (34 -> 636 commits, 1 -> 148 branches)
BASELINE_DOCS = 3_OF_4_HASH_MATCH (UX addendum absent)
DOM_ADAPTOR_IN_CANONICAL_BRANCH = NO
DOM_ADAPTOR_ON_FEATURE_BRANCHES = YES (25 branches; leader has 29 src files)
GAP_TYPE = INTEGRATION_NOT_ABSENCE
DSC_VERIFIED_COMPLETE_COUNT = 0 (integration axis unmet)
HEIGHT_LOCKED_KERNELS_IN_CANONICAL = YES (19c191f, 76597c6)
SCAD0_VECTORS_IN_CANONICAL = YES (7698225 is the tip)
CONTRACTS_PIN_6f2b230_IN_CANONICAL = NO (critical)
SETTLEMENT_LAYER_PRESENT = NO (different product boundary)
DIRECT_X_TO_Y_BYPASS = NONE (no routing layer exists here)
```
