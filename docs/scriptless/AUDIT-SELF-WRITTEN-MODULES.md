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

## Adjudicated

### A1 — Funding order: claim adaptor before funding (RESOLVED per master spec §7.2/§7.3)

- **Master spec §7.2/§7.3** orders the claim adaptor pre-signature (step 7) and
  `ReadyToFund` persistence (step 8) **before** funding authorization (step 9),
  and the §7.3 gate transitions from `ClaimPrepared`.
- **Cronograma** sequences funding in **Fase 4** and the conditional claim in
  **Fase 5**.

**Adjudicated to follow the master spec §7.2/§7.3.** Implemented (commit in this
cycle): a `ClaimPresigned` stage was inserted in `ContractStageV1` between
`RefundPresigned` and `Funded`, with the forward path
`RefundPresigned → ClaimPresigned → Funded` (abort reachable from every
pre-funding stage including `ClaimPresigned`, §9.3). `FundingAuthorizationV1::authorize`
now transitions from `ClaimPresigned`, not `RefundPresigned`, so funding cannot
be authorized before the refund is co-signed AND the claim adaptor is pre-signed.
The cryptographic checks the full §7.3 gate performs at that stage (template
hashes, refund final-and-spendable, adaptor pre-signature verification, ready
acks, durable tombstones, `FundingGateEvidence` binding) remain node-side.

### A2 — Claim safety margin (RESOLVED: distinct claim confirmation margin)

`contract_session::claim_floor_height` subtracted the **same** `total_margin_blocks`
used to place the refund, so the floor equalled `funding_height` and the safe
claim window was empty (`claim_is_safe` false for every real claim).

**Adjudicated to follow the claim confirmation margin.** `RefundDeadlinePolicyV1`
now carries a distinct `claim_confirmation_blocks` — the buffer the adaptor claim
needs, once published, to reach a reorg-safe depth before the refund could unlock
and race it (§7.2 step 10's confirmation policy; §7.5). The constructor enforces
`claim_confirmation_blocks < total_margin_blocks` (the refund placement margin),
so `claim_floor = refund_lock − claim_confirmation_blocks` is strictly above
funding and the safe window `(funding, floor]` is non-empty. `claim_is_safe` now
returns true for a real post-funding claim inside the window. The concrete value
remains an operator input from the Dandelion++ stem-timing study (Cronograma
Fase 5); the structure that makes the window well-formed is now enforced.

## Awaiting adjudication (design decisions, not auto-changed)

_None outstanding from this audit._ The lower-severity divergences below are
recorded for a future pass.

## Lower-severity divergences — addressed

- **§8.5 taxonomy and equivocation — FIXED.** `apply` now implements the §8.5
  contract: the logical key includes `session_id` (bound on the first envelope
  and enforced thereafter); identical bytes under an already-accepted key return
  `ContractApplyOutcomeV1::DuplicateAck` with no side effect re-executed;
  different bytes under one key raise `AdaptorError::Equivocation`, latch the
  session into the new `ContractStageV1::FailedClosed` terminal (§9.1
  `FailedClosed`), and preserve `EquivocationEvidenceV1` (key + both conflicting
  digests). `Replay`, `SequenceGap`, and `ForkedTranscript` are now distinct
  typed errors instead of one generic `InvalidContext`. Note: the duplicate-
  detection memory is deliberately not durable — after a resume, a repeat of the
  last pre-crash message is classified by sequence/transcript rather than by
  digest.
- **§3.4 tag registry — CREATED.** `docs/HASH_DOMAINS.md` did not exist; §3.4
  requires it as the single registry from which the closed `DomainTag` enum is
  generated. It now records all 31 live tags, separating the 14 in the spec's
  normative table from the 17 that are in use and still need ratification, plus
  the KDF/AEAD labels. The registry is explicitly marked **PROPOSED, not frozen**:
  §3.4 forbids freezing until G0 locates the canonical DOM BLAKE2b and exposes a
  byte-identical adapter. Generating the enum and replacing the string literals
  is listed there as pending work gated on G0.
- **Contract transcript is a separate construction, not §8.4** — unchanged and
  documented. Tag `DOM:scriptless-contract-transition:v1` with a stage byte, vs
  §8.4's `DOM:scriptless-transcript:v1` with `accepted_phase_u16_le`. Defensible
  as a distinct contract-level transcript (the envelope is a sanctioned "formato
  próprio", Cronograma 3.1) and now registered in `docs/HASH_DOMAINS.md`; it must
  not be conflated with the §8 message transcript.
- **`funding_authority` refund-first guarantee is bounded** — unchanged and
  documented. `ClaimPresigned` attests message acceptance, not a valid, durably
  stored, spendable refund plus a verified adaptor pre-signature (invariant
  mestra:181, §7.3). Those checks are node-side and scoped out in the module doc.

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
ADJUDICATED = FUNDING_ORDER_FOLLOWS_MESTRA_7_2_7_3 (ClaimPresigned gate) + CLAIM_CONFIRMATION_MARGIN_DISTINCT
ADJUDICATE_REMAINING = NONE
MINOR_DIVERGENCES = EQUIVOCATION_TAXONOMY_FIXED + TAG_REGISTRY_CREATED_PROPOSED
TAG_FREEZE_BLOCKED_BY = G0_CANONICAL_BLAKE2B_ADAPTER
NON_NORMATIVE = PARTIAL_COMMITMENT_POP_REDUNDANT_WITH_SHARE_POP
PRODUCTION = NOT_AUTHORIZED
```
