# Audit — Self-Written Scriptless Modules vs the Master Specification

Date: 2026-08-10
Branch: `feat/dom-protocol-g1-closed-cycle-property`
Scope: every module authored in this development cycle, audited source-first
against `DOM-Scriptless-Contracts-Especificacao-Mestra-v1.0` and
`DOM-Scriptless-Cronograma-Implementacao-v1`.

The crypto-core modules were audited directly; the three protocol-logic modules
written by inference (`decoy_capsule`, `contract_session`, `funding_authority`)
were audited against the spec section by section. Every finding below was
verified against the actual code and the exact spec text before being recorded.

## Result summary

The crypto core is spec-faithful. The real divergences were concentrated in the
three inference-written modules, as expected. Four were fixed in place; two are
design decisions left for adjudication; the rest are lower-severity divergences
recorded here.

## Fixed (spec-grounded, verified, tested)

| # | Module | Divergence | Spec | Commit |
| --- | --- | --- | --- | --- |
| F1 | `contract_session` | `Funded → Aborted` permitted, "releasing reserves" — after funding the value is on-chain; §9.3 forbids abort pretending the contract never existed. Abort now reachable only from pre-funding stages. | §9.3 (mestra:817-819) | `771cc12` |
| F2 | `decoy_capsule` | Capsule framing (version=1, ct-len=80, nonce=12, body=80) hardcoded as magic numbers. Now imported from `RECOVERY_VERSION`/`RECOVERY_NONCE_SIZE`/`RECOVERY_CIPHERTEXT_SIZE` so the decoy cannot silently diverge from the real capsule and break §1.3. | Cronograma A.2 (:1291); §1.3 | `771cc12` |
| F3 | `funding_authority` | Doc overclaimed both gates "un-bypassable at the type level" and the backup token "carries no data a caller can forge"; in fact `authorize` ignored the token and the backup is not bound to the contract's shares. Doc corrected to the real bounded guarantee; `authorize` now consumes the token (rejects a sub-bilateral count). | §7.3 (mestra:547) | `771cc12` |
| F0a | `bulletproof_mpc`/`crypto` | 32-byte `extra_commit` could not equal the raw 96-byte capsule consensus verifies against — the shared output would fail consensus. Now binds the raw bytes. | §5.2, §1.3 | `1bc7fb6` |
| F0b | `bulletproof_mpc` | Aggregate folded the value into `commitment_shares[0]` instead of pure `R_i` with `C = v·H + Σ R_i`. Now pure shares + value term in the check. | §4.2, §4.3, §1.2 | `d57cb28` |

## Awaiting adjudication (design decisions, not auto-changed)

### A1 — Funding order: claim adaptor before or after funding?

- **Master spec §7.2/§7.3** orders the claim adaptor pre-signature (step 7) and
  `ReadyToFund` persistence (step 8) **before** funding authorization (step 9),
  and the §7.3 gate transitions from `Phase::ClaimPrepared`.
- **Cronograma** sequences funding in **Fase 4** and the conditional claim in
  **Fase 5** — funding before the claim adaptor.

These two master documents conflict on the ordering. `funding_authority`
currently authorizes from `RefundPresigned` (the schedule's order) and does not
require the claim adaptor pre-signature. The divergence is documented in the
module; resolving it (which document governs) is your call. The full §7.3 gate
(`FundingGateEvidence` with the eight template/refund/adaptor/backup hashes, CAS,
fsync, tombstones) is node-side integration regardless.

### A2 — Claim safety margin value

`contract_session::claim_floor_height` subtracts the **same** `total_margin_blocks`
used to place the refund, so the floor equals `funding_height` and the safe claim
window is empty (`claim_is_safe` is false for every real claim, since a claim can
only be published after funding confirms). The fix requires a **distinct, smaller**
claim margin (`claim_margin < total_margin`) leaving a non-empty window
`(funding, refund_lock − claim_margin]`. The exact value depends on the
Dandelion++ stem-timing study (Cronograma Fase 5) and is deliberately not fixed.
Documented in place; the formula/API change is left for your decision.

## Lower-severity divergences (recorded, not changed)

- **`contract_session` §8.5 anti-replay is partial.** The logical key is
  `(sender, sequence)` + transcript binding; `session_id` is not part of the
  in-state key (mitigated by the session-unique initial transcript), equivocation
  (same key, different bytes) is not detected/latched, and there is no
  `FailedClosed` terminal that preserves evidence. Some of this belongs to the
  store/transport layer; the module advertises "anti-replay" and should either
  scope that claim or add the fail-closed hook. (§8.5 mestra:718-725)
- **`contract_session` contract transcript is a separate construction, not §8.4.**
  Tag `DOM:scriptless-contract-transition:v1` and a single stage byte, vs §8.4's
  `DOM:scriptless-transcript:v1` and `accepted_phase_u16_le`. Defensible as a
  distinct contract-level transcript (the envelope is a sanctioned "formato
  próprio", Cronograma 3.1), but it must not be conflated with the §8 message
  transcript.
- **`contract_session` domain tags not in the §3.4 frozen registry.**
  `…-contract-transition:v1` and `…-contract-envelope:v1` are ad-hoc literals;
  §3.4 mandates a closed `DomainTag` registry. Either register them or the closed
  enum is not yet enforced in this crate.
- **Error taxonomy.** Both `decoy_capsule` and `contract_session` map
  equivocation to a generic `InvalidContext` rather than a dedicated
  `Equivocation` classification (behavior is correct and fails closed; only the
  typed error diverges). (§13 taxonomy)
- **`funding_authority` refund-first guarantee is bounded.** `RefundPresigned`
  attests message acceptance, not a valid, durably-stored, spendable refund
  (invariant mestra:181). The durability/spendability checks are node-side and
  documented as out of scope in the module.

## Verified clean (no divergence)

- **`collaborative_output`** — §4.2 PoK context order, §4.3 `C = v·H + Σ R_i` by
  point addition (never the scalar sum, §1.2), identity rejection, ascending-order
  and no-duplicate enforcement all match the spec.
- **`partial_commitment_pop`** — a cryptographically sound Schnorr PoK (nonce
  commitment, statement/participant/share/nonce-bound challenge, canonical checks,
  per-participant presence set). Note: it is **non-normative and redundant** with
  the spec's §4.2 `share_pop.rs` (different tag and context); the normative
  joint-blinding gate is `collaborative_output` over `share_pop`.
- **`decoy_capsule`** — framing byte-matches the real capsule; deterministic and
  anti-grinding (derived from share ‖ session); commit-before-reveal and
  equivocation fail closed; per-share recovery concerns of §12.2 do not apply
  (this is the C2 canonical decoy, not a decryptable capsule).
- **`funding_authority`** — no L2/DL2P metadata leak (A-01); refund is
  absolute/height-based and unbypassable in the ordering; the backup ack-set
  validation (missing/duplicate/out-of-range/mismatched) fails closed.
- **`bulletproof_bp` extra_commit fix** — `&[u8]` threaded through
  round1/round2/finalize with correct null guards; the state stores owned bytes;
  §5.2/§1.3 citations accurate.

```text
CRYPTO_CORE = SPEC_FAITHFUL
FIXED = POST_FUNDING_ABORT + DECOY_CONSTANTS + FUNDING_GATE_HONESTY + EXTRA_COMMIT + AGGREGATE_PURE_R_I
ADJUDICATE = FUNDING_ORDER_MESTRA_VS_CRONOGRAMA + CLAIM_SAFETY_MARGIN_VALUE
NON_NORMATIVE = PARTIAL_COMMITMENT_POP_REDUNDANT_WITH_SHARE_POP
PRODUCTION = NOT_AUTHORIZED
```
