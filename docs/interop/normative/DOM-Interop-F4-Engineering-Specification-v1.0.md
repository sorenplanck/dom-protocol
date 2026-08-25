> **Normative status: DECIDED** (operator ratification, 2026-08-10,
> recorded in the project chat: "Aprovado"; decision D-017 in the
> Foundation Document v0.8 §12.1).
> This document is the English-language normative execution authority for
> Phase 4 (F4) of DOM Interop. Prepared by the executor under the
> route-(a) decision (the specification is written and ratified before
> items 2–4 are coded) and ratified by the operator per the one-authority
> rule (M.16.1 discipline).

DOM INTEROP — PHASE 4

Engineering Specification of the Minimal USPE v1.0

```text
Document:             DOM-Interop-F4-Engineering-Specification-v1.0
Version:              1.0.2 (erratum E-1 in §3.1; D-024 amendment note
                      in §12; file name stays v1.0)
Date:                 2026-08-10
Authority:            operator ratification in the DOM Interop project chat
Phase:                F4 — Minimal USPE (economic assurance)
Gate:                 G-F4
Normative status:     DECIDED FOR IMPLEMENTATION (D-017, 2026-08-10)
Target repository:    https://github.com/sorenplanck/Dom-interop.git
Integration branch:   main
Base documents:       DOM-Interop-Foundation-Document-v0.7.md (§3.4, §7 F4)
                      DOM-Interop-F2-Engineering-Specification-v1.0.md
Prior dependencies:   G-F0/G-F1/G-F2 = PASS; F3 ConditionLockV2 suite green;
                      f4-model step 1 executed (docs/reports/F4-STEP1-MODEL-CHECKER.md)
Parallelism:          F4 runs parallel to F3/F5 (Foundation Document §7)
```

This document consolidates the Phase 4 programming decisions into one
executable specification. It does not alter DOM consensus, dom-protocol or
the ratified F2 engine, and it does not authorize starting F6+.

The goal of F4 is the minimal USPE: a pure assurance machine that turns a
failed, protected obligation into a verifiable economic consequence —
release or slash of a bond — executed **exclusively through cryptography
and timelocks**. There is no operator, arbiter, committee or admin key
anywhere in the design (I12), and every claim in this specification is
adjudicated by an exhaustive model checker that already runs in CI.

---

## 1. Terminal outcome of Phase 4

Phase 4 is complete only when all of the following are true at once:

 1. the assurance objects of §5 are frozen, canonically encoded and
    vector-tested;
 2. the state machine of §6 is the production `uspe::assurance_transition`
    and matches the normative table byte-for-byte;
 3. bonds are custodied by the ratified `ConditionLockV2` exactly as §7
    describes — no new custody contract exists;
 4. the `EvidenceVerifier` of §8 accepts only the evidence class of the
    active policy, verified by the owning chain adapter (I9);
 5. every assurance decision is persisted before any external effect,
    riding the F2 store discipline (§9);
 6. the f4-model checker reports nine properties `HOLDS` over the real
    machine and stays wired in CI (§10);
 7. the adversarial suite of §11 is green;
 8. the exact G-F4 criterion of §12 is met, including a compensation
    executed on a public testnet with no privileged action, and the
    operator has ratified the closure.

## 2. Consolidated decisions

D-F4.1 **Route (a)** — this specification precedes the code of items 2–4
       (operator, 2026-08-10).
D-F4.2 **Bond venue v1 = EVM** — bonds live in `ConditionLockV2`
       (native or ERC-20 variant). This partially resolves OPEN A6: venue
       is decided; accepted assets and sizing remain A5/A6 economics and
       do not block G-F4. The DOM venue arrives when Scriptless matures.
D-F4.3 **No new custody code** — release and slash are the audited
       `refund` and `claim` paths of `ConditionLockCoreV2`. F4 writes no
       Solidity.
D-F4.4 **Evidence class v1 = revealed-scalar claim** (§8). Other evidence
       rules are declared in the policy enum but unimplemented arms are a
       refusal, never a stub that succeeds (I13).
D-F4.5 **`CollateralDeadlineExpired` is normative.** The F4 step-1 model
       checker proved the §3.4 machine as originally drawn strands
       collateral in `BondLocking` (TIMEOUT_SAFE violation). The
       corrective event and arm
       `(BondLocking, CollateralDeadlineExpired) → (ReleasePending, [AuthorizeRelease])`
       — already executed on main and re-proven — are adopted by this
       specification as part of the normative machine. Evidence:
       `docs/reports/F4-STEP1-MODEL-CHECKER.md`.
D-F4.6 **The machine decides; adapters verify; the pin extracts.** The
       USPE never parses chain bytes (I9) and never re-implements
       adaptor arithmetic (I15): scalar evidence reaches it already
       verified through the same authority-blessed byte export ratified
       by D-016.

## 3. Architectural boundaries

### 3.1 Permitted dependencies

```text
uspe                 -> counterparty-api, kaystra-core (frozen F2
                        types + codec discipline), blake2
                        (workspace-pinned =0.10.6), thiserror   [E-1]
f4-model             -> uspe                                  (unchanged)
f4-harness (dev)     -> uspe, store, counterparty-api,
                        adapters/evm (feature-gated rpc), f2-harness
adapters/evm         -> (unchanged; gains no uspe dependency)
```

> **Erratum E-1 (2026-08-10, executor; patch level, reported in chat).**
> As ratified, this list read `uspe -> counterparty-api, thiserror
> (unchanged)`, which contradicts §5 ("concrete field types reuse the
> frozen F2 vocabulary (kaystra-core types)") and §5.2 (a BLAKE2
> digest). The §5 content is the substantive normative choice — one
> definition of every type, never a divergent copy — so §3.1 is
> corrected to match it. The dependency direction is acyclic
> (`kaystra-core` does not import `uspe`) and §4 still holds: no new
> external crate enters the workspace (`blake2 =0.10.6` and dev-only
> `proptest =1.7.0` are already pinned members of it).

### 3.2 Hard rules

 1. `uspe` imports no chain adapter, no dom-adaptor type and no store: the
    transition function stays pure and table-driven.
 2. No component of F4 holds, derives or transports key material (I1) or
    the settlement secret `t` beyond the moment of the slash call — and
    the `t` used by a slash is already public by construction (revealed on
    chain by the counterparty's own claim).
 3. The bond beneficiary executes the slash; anyone may execute the
    release after the deadline. There is no third role (I12).
 4. Unimplemented policy arms refuse with a named error (I13); no
    `unwrap`/`expect` on untrusted input, caps before allocation (I14).
 5. Amount arithmetic is `u128` checked/saturating; the cap check is in
    the machine (already proven) AND at bond opening (§7.3).

## 4. Rust dependencies frozen for F4

No new external crate. `uspe` keeps exactly `counterparty-api` +
`thiserror`; the harness reuses workspace-pinned `store`, `tempfile` and
the existing adapters. Any addition is a specification change.

## 5. Normative assurance objects

Concrete field types reuse the frozen F2 vocabulary (`kaystra-core`
types) and the neutral `counterparty-api` types. New identifiers are
32-byte newtypes in `uspe`.

### 5.1 AssurancePolicyV1

```rust
pub struct PolicyId(pub [u8; 32]);

pub enum EvidenceRuleV1 {
    /// Valid failure evidence is a FINALIZED `Claimed` of a bound
    /// settlement leg revealing the canonical scalar for `adaptor_point`.
    RevealedScalarClaim { adaptor_point: AdaptorPointBytes },
}

pub enum TerminalPolicyV1 {
    /// No accepted evidence within the deadline => the bond releases.
    ConservativeRelease,
}

pub struct AssurancePolicyV1 {
    pub policy_id: PolicyId,
    pub version: u32,                       // = 1
    pub protected_settlement: SettlementId, // one obligation per policy (v1)
    pub terms_hash: Digest32,               // binding to the obligation
    pub bond_chain_id: CounterpartyChainId,
    pub bond_asset: AssetId,
    pub required_collateral: u128,
    pub compensation_cap: u128,             // >= any slashable amount
    pub collateral_deadline: TimelockSpec,  // BondLocking exit (D-F4.5)
    pub claim_deadline: TimelockSpec,       // ClaimWindow exit
    pub evidence_deadline: TimelockSpec,    // EvidenceVerification exit
    pub bond_release_deadline: TimelockSpec,// on-chain refund gate (§7.2)
    pub evidence_rule: EvidenceRuleV1,
    pub terminal_policy: TerminalPolicyV1,
}
```

Deadlines keep the adapter's unit (`TimelockSpec` height OR timestamp per
the bond chain's domain) and are **never silently converted** — the same
A4 rule the settlement engine obeys. For the EVM venue every deadline is
`Timestamp`.

### 5.2 Canonical encoding and binding

`AssurancePolicyV1` gets a canonical byte encoding under the same codec
discipline as `SettlementTermsV1` (F2 spec §6.2): fixed field order,
version word first, `u8` tags for enums, length caps enforced before
allocation, decode(encode(x)) == x proven by vectors and property tests.

`assurance_policy_hash` — the already-frozen `Option<Digest32>` field of
`SettlementTermsV1` — is defined as the BLAKE2 digest of that canonical
encoding. A settlement is protected **iff** its terms carry the hash of
the active policy; a policy whose `terms_hash` diverges from the
settlement's real terms hash is invalid at construction.

### 5.3 AssuranceCertificateV1

```rust
pub struct CertificateId(pub [u8; 32]);

pub struct AssuranceCertificateV1 {
    pub certificate_id: CertificateId,   // digest of the fields below
    pub settlement_id: SettlementId,
    pub terms_hash: Digest32,            // divergence invalidates
    pub policy_id: PolicyId,
    pub bond_lock_id: Digest32,          // ConditionLockV2 lockId
    pub collateral_evidence: EvidenceRefV1, // the LockOpened ref; no evidence, no issuance
    pub issued_at_revision: u64,         // journal revision at issuance
    pub expires_at: TimelockSpec,        // = bond_release_deadline
}
```

The certificate's only origin is the `IssueCertificate` effect of the
machine, which itself only fires on `CollateralVerified` with a matching
`terms_hash` — proven exhaustively. The certificate is data, not
authority: possessing it grants nothing the chain does not already
enforce.

## 6. Normative state machine

The production function is `uspe::assurance_transition` as merged on main
(commit `552f755` lineage), including D-F4.5. States, events, effects and
errors are frozen as implemented; this table is the normative shape and
the code must continue to match it byte-for-byte:

```text
#  From                  Event                          To                    Effects (after PersistState)
 1 BondRequired          BondLockObserved               BondLocking           —
 2 BondLocking           CollateralVerified(=terms)     Protected             IssueCertificate
 3 BondLocking           CollateralVerified(≠terms)     — TermsMismatch       —
 4 BondLocking           CollateralDeadlineExpired      ReleasePending        AuthorizeRelease
 5 Protected             ObligationSettled              ReleasePending        AuthorizeRelease
 6 Protected             ObligationFailed               ClaimWindow           —
 7 ClaimWindow           ClaimWindowExpired             ReleasePending        AuthorizeRelease
 8 ClaimWindow           CompensationClaimed(=terms)    EvidenceVerification  —
 9 ClaimWindow           CompensationClaimed(≠terms)    — TermsMismatch       —
10 EvidenceVerification  EvidenceVerified{true}         Slashed               ExecuteSlash
11 EvidenceVerification  EvidenceVerified{false}        ClaimRejected         —
12 EvidenceVerification  EvidenceDeadlineExpired        ClaimRejected         —
13 ClaimRejected         ReleaseConfirmed               Released              RecordEconomicOutcome(Released)
14 ClaimRejected         ObligationSettled              ClaimRejected         AuthorizeRelease (tolerated order)
15 ReleasePending        ReleaseConfirmed               Released              RecordEconomicOutcome(Released)
16 Slashed               CompensationConfirmed(≤cap)    Compensated           RecordEconomicOutcome(Compensated)
17 Slashed               CompensationConfirmed(>cap)    — CompensationExceedsCap —
—  any terminal          any event                      — TerminalState       —
—  anything else                                        — IllegalEvent        —
```

Terminals: `NotRequired`, `Released`, `Compensated`. `PersistState(next)`
is always the first effect of every accepted transition.

## 7. Bond custody — BondAdapter over ConditionLockV2

### 7.1 Trait

```rust
pub trait BondAdapter {
    /// Submit the collateral lock. Idempotent by lock id.
    fn submit_bond(&mut self, policy: &AssurancePolicyV1) -> Result<BroadcastOutcome, Error>;
    /// Execute the release spend (permissionless refund after deadline).
    fn submit_release(&mut self, bond_lock_id: &Digest32) -> Result<BroadcastOutcome, Error>;
    /// Execute the slash spend with the REVEALED scalar (beneficiary claim).
    fn submit_slash(&mut self, bond_lock_id: &Digest32, revealed: &RevealedSecretBytes)
        -> Result<BroadcastOutcome, Error>;
    /// Observe bond-chain events from a cursor (LockOpened/Claimed/Refunded).
    fn observe(&mut self, cursor: &ChainCursor) -> Result<Observation, Error>;
}
```

Lock / release / slash are **exactly** `open`, `refund` and `claim` of the
deployed `ConditionLockCoreV2` — the F3-audited paths, unchanged.

### 7.2 Bond lock geometry

| Bond lock parameter        | Bond value                                       |
|----------------------------|--------------------------------------------------|
| `termsHash` (LockTerms)    | the protected obligation's `terms_hash`          |
| `sessionId` (LockTerms)    | the obligation's `session_id`                    |
| `beneficiary` (LockTerms)  | the protected party (only address able to slash) |
| `adaptorAddress` (LockTerms) | `address(T)` for the policy's `adaptor_point`  |
| `amount` (LockTerms)       | `required_collateral`, and `<= compensation_cap` |
| `deadline` (LockTerms)     | `bond_release_deadline`                          |
| funder (bound in `lockId`) | the solver — `msg.sender` of `open`, anti-squat  |

Deadline geometry (REQUIREMENT):

```text
collateral_deadline < obligation deadlines < claim_deadline
                    < evidence_deadline < bond_release_deadline
```

so the protected party always holds a live claim path for the full claim
and evidence windows, and the solver always recovers the bond by pure
timeout when no valid claim lands. The gap between `evidence_deadline`
and `bond_release_deadline` is the slash-execution margin and MUST cover
the bond chain's worst-case inclusion delay under the frozen finality
policy — the contract's `claim` reverts at the deadline, so a margin of
zero would let time steal an authorized slash. On-chain TIMEOUT_SAFE (permissionless
`refund`) therefore mirrors machine TIMEOUT_SAFE (rows 4, 7, 12) — the
two clocks can disagree only in the direction that favors release, never
in the direction that strands or double-pays.

### 7.3 Effect mapping

| Machine effect              | On-chain action                                     |
|-----------------------------|-----------------------------------------------------|
| `IssueCertificate`          | none (data record; §5.3)                            |
| `AuthorizeRelease`          | mark release eligible; `refund` after the deadline  |
| `ExecuteSlash`              | `claim(bond_lock_id, t)` by the beneficiary         |
| `RecordEconomicOutcome`     | none (terminal bookkeeping)                         |

`CompensationConfirmed.amount` is read from the finalized
`Claimed`/payout evidence, never assumed; the machine's cap check then
adjudicates it. Opening a bond with `amount > compensation_cap` is
refused by the adapter before any transaction is built.

## 8. EvidenceVerifier v1 — revealed-scalar claim

```rust
pub trait EvidenceVerifier {
    /// Raw, chain-verified observation -> VerifiedOutcome for the machine.
    fn verify(&self, policy: &AssurancePolicyV1, observation: &ObservedEvent)
        -> Result<VerifiedOutcome, Error>;
}
```

For `EvidenceRuleV1::RevealedScalarClaim`, evidence is valid **iff** all
of the following hold, and each check names its refusal:

 1. the observation is a `Claimed` event of a **bound** settlement leg
    (binding recomputed from the policy's terms — I9: only the owning
    chain adapter interprets its receipts/logs);
 2. it is FINALIZED under the leg's frozen finality policy (A4); a reorg
    that invalidates it invalidates the evidence, not the publicity of
    `t` (I11);
 3. the revealed scalar is canonical (`0 < t < n`, the pin's predicate —
    I15) and `address(t·G)` equals the policy's adaptor address;
 4. the claim occurred within the policy's evidence window.

`EvidenceVerified{valid: true}` reaches the machine only from this path.
Anything else — malformed, unbound, unfinalized, late — is
`valid: false` or a refusal, and by rows 11–12 converges to release.
Verification failure can never slash (proven: late/invalid evidence
cannot reach `Slashed`).

## 9. Persistence and delivery

Assurance state rides the ratified F2 store discipline, not a new one:

 1. journal kind `0xF401` under the neutral `store` crate; the journal
    frame is the canonical encoding of (event, next state, effects);
 2. `PersistState` first-effect rule == persist-before-external-effect;
    the commit is atomic and crash-rollback-safe (F2 C0–C6 shapes);
 3. outbox entries for `AuthorizeRelease`/`ExecuteSlash` carry
    deterministic effect ids; redelivery is byte-identical or fatal
    equivocation (I7);
 4. at-least-once delivery is assumed HOSTILE: the machine itself was
    proven safe under unbounded redelivery with no dedup layer, so the
    outbox's dedup is an optimization, never a safety dependency.

## 10. Adjudication (already wired)

`crates/f4-model` is the standing adjudicator of this specification: nine
properties (`coverage`, `NO_DOUBLE_COMPENSATION`, `NO_RELEASE_AND_SLASH`,
`TIMEOUT_SAFE`, cap, certificate binding, outcome domain, persist-first,
terminal immutability) checked to a fixpoint over the REAL machine, exit
1 on violation, running in the `f2-adjudication` CI job. Any change to
`uspe` that breaks a property turns main red. The falsifiability controls
(injected violations must be reported; all 11 states must be reached)
are part of the normative surface and may not be weakened.

## 11. Adversarial suite for F4

Beyond §10, the F4 harness must demonstrate, with the real store and the
real contract on a local node: crash at every transition; duplicate and
reordered delivery of every event; late evidence after rejection and
after each terminal; wrong-terms collateral and claims; over-cap
compensation refused end-to-end; reorg of the bond chain across the
`Claimed` evidence; equivocating redelivery fatal; secret scan of every
artifact, log and database file (the slash scalar is public by
construction, but no OTHER secret may appear anywhere — I1/I6).

## 12. Exact G-F4 criterion

G-F4 = PASS only when every item below holds, evidenced in a closure
report, and the operator ratifies:

 1. `NO_DOUBLE_COMPENSATION`, `NO_RELEASE_AND_SLASH` and `TIMEOUT_SAFE`
    demonstrated by the f4-model fixpoint AND by the E2E harness;
 2. full release path on a real node: bond opened, obligation settled,
    `refund` after deadline by a third party (permissionless), machine at
    `Released`;
 3. full slash path on a public testnet (Sepolia, reusing the F3
    workflow): bond opened, obligation failure, counterparty's own claim
    reveals `t` on chain, evidence verified, `claim(bond_lock_id, t)`
    executed by the protected party, machine at `Compensated` — **no
    privileged action anywhere**, report with tx hashes;
 4. cap and binding refusals exercised on the real contract (over-cap
    open refused; wrong-terms certificate/claim refused);
 5. workspace green: fmt, clippy, full test suite, guards, CI 5/5;
 6. F6+ not started; clean worktree; main == tested HEAD.

> **D-024 amendment (operator decision, 2026-08-11 — express; the
> original item-6 text above is HISTORICAL and preserved verbatim).**
> The "F6+ not started" condition was a build-order guard. The corpus
> shows F6 began before G-F4's formal adjudication, and no prior waiver
> exists; that occurrence stays on record as a historical deviation and
> is not retroactively declared compliant. D-024 grants a ONE-TIME
> curative disposition, strictly limited: the existence of the already
> published F6 work does not, by itself, bar the future adjudication of
> G-F4; the CURRENT head must be re-submitted to the full F4
> regressions; clean worktree and `main == tested HEAD` remain
> mandatory; any later modification to `uspe`, `f4-model`,
> `f4-harness`, `store`, `adapter-evm`, `ConditionLockV2` or any
> interface F4 consumes invalidates the binding and requires a new
> regression. The disposition sets no precedent for ignoring phase
> order, does not promote or anticipate G-F6, and G-F6 stays deferred
> until G-F3, G-F4 and G-F5 are formally PASS. Full text: Foundation
> Document v0.14 §12.1, D-024.

## 13. Build order

```text
1. AssurancePolicyV1 / AssuranceCertificateV1 + canonical codec + vectors
2. Policy/certificate property tests (roundtrip, caps, binding)
3. BondAdapter over ConditionLockV2 in the EVM adapter surface
4. EvidenceVerifier v1 (revealed-scalar) over the ratified extract path
5. f4-harness: store-backed assurance journal + outbox (kind 0xF401)
6. Adversarial suite (§11) on Anvil
7. G-F4 E2E: release path on Anvil; slash path on Sepolia (F3 workflow)
8. Closure report + operator ratification
```

Steps 1–2 have no chain dependency and start immediately upon
ratification of this document; steps 3–7 reuse the F3 infrastructure.

## 14. Final declaration of authority

Order of precedence for F4: (1) the invariants of the Foundation
Document; (2) this specification once ratified; (3) the ratified F2
specification for everything the USPE inherits (store, outbox, A4); (4)
the audited ConditionLockV2 sources as the sole custody authority; (5)
prototype code only as historical evidence. Divergence between this
document and the Foundation Document's §3.4 sketch resolves in favor of
this document upon ratification (it is the §3.4 objects made concrete,
plus the D-F4.5 correction proven necessary by exhaustive search).
