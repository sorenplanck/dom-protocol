# NAR-DC-P1-007 — Phase State Table, Two-Party Roster, and Funding Authority Closure

Status: **PROPOSED / UNSIGNED / NOT NORMATIVE**

Date: 2026-08-11

Project: DOM Contracts / DOM Scriptless Contracts Phase 1

Scope: the closed participant cardinality for the strict V1 contract profile;
the canonical directed phase-transition table, resolving the divergence between
Master Specification §9.1 and §9.2; and the recorded non-authority status of the
current funding-authorization model.

This record does not approve G1A, G1B, consolidated G1, Phase 2, production,
mainnet, real funds, a release, a package publication, or an external security
audit. It assigns normative meaning only; it does not attest that any
implementation, test, or evidence exists.

## 1. Authority and ratification effect

This record supplements the following signed records:

| Record | SHA-256 |
|---|---|
| `NAR-DC-P1-001-omnibus-gap-closure.en.md` | `88586449d577038ac98e9463250821ed9b3d1e6c94f5b11abfaf036a93eec655` |
| `NAR-DC-P1-002-storage-persistence-closure.en.md` | `719a121c11f4b7f8ea016668bfaa05a3e4d03d3a510df31e3495fb9698560e84` |
| `NAR-DC-P1-003-vault-request-and-recovery-binding.en.md` | `082c855782c71a0f61e85828eaac75440a434d5c05d8357e569592a816db05ef` |
| `NAR-DC-P1-004-live-store-layout-and-runtime-closure.en.md` | `2f9eadb08080844ade7dacfa117a71948ee8a365841fff860d69fe734c42b510` |
| `NAR-DC-P1-005-reservation-runtime-and-linux-capability-closure.en.md` | `4f5582a17426ed5b03d6aa37d6c2fc9cfe564985ec3614d0d4a30fed8ae2d635` |
| `NAR-DC-P1-006-final-runtime-authority-platform-and-evidence-publication-closure.en.md` | `2aa9ec803167f866737375ffbfeca082f98bd1dc9efbefa06c073131bd215a23` |

The detached signature must verify with the established project operator
Minisign public key:

```text
RWTwnDDKlXoZdG3obVRiLPfVRHr17E0Fj2GN8IZ2rBkipRZvIIW6PLJ3
key ID 74197A95CA309CF0
```

Unsigned bytes grant no authority. After valid detached signature and exact
byte-for-byte import, this record supersedes only the two §9.2 rows named
explicitly in §3.3.

This record does not amend, replace, or reissue the DOM Scriptless Contracts
Master Specification v1.0 R1 or the Implementation Schedule v1. Those documents
remain exactly as signed and hashed. Where this record resolves an internal
divergence in the Master Specification, it does so as an adjudication recorded
against it, never as an edit of it.

No canonical persisted record, cryptographic primitive, hash domain, KDF,
Purpose registry, Direction registry, SigningPhase registry, consensus rule,
existing DOM wire byte, transaction encoding, kernel verifier, genesis value,
network magic, PoW rule, budget number, timeout, retry limit, retention period,
or dependency pin is changed by this record. The §9.1 phase discriminants are
unchanged.

## 2. Participant cardinality closure

### 2.1 Problem closed

The Master Specification fixes the strict two-party profile in four places:

- Controle do documento, "Escopo de produção V1": *"2-de-2; funding, claim,
  refund absoluto; adaptor Schnorr; output compartilhado; wallet e storage"*;
- decision A-03: *"O primeiro release de produção suporta estritamente 2-de-2"*,
  with the consequence *"n-de-n só entra numa V1.x após testes por n"*;
- §1.4, which lists `2-de-2` as `Suportada` and `n-de-n` as `V1.x, após gate por
  n`, on the reasoning that *"sucesso com duas partes não prova
  segurança/robustez para cada n"*; and
- §7, "Contrato 2-de-2", whose objects are defined as *"dois participantes e
  shares de blinding"*.

The Implementation Schedule v1 states the same boundary: *"Escopo: V1 estrito —
2-de-2"*.

None of those passages is expressed as a checkable cardinality rule on the
participant set itself. A roster validator that rejects only fewer than two
participants and duplicates satisfies §4.1's ordering and duplicate rules while
still admitting three or more participants, which no V1 gate covers.

### 2.2 Decision

For Phase 1 and the strict V1 contract profile, the canonical participant set is
closed at exactly two distinct participants.

A conforming participant-set constructor accepts a candidate roster if and only
if both of the following hold:

1. the roster contains exactly two participant identities; and
2. those two identities are distinct.

It refuses, fail-closed and without constructing a participant set:

- fewer than two identities;
- more than two identities; and
- any repeated identity, including a roster of exactly two equal identities.

The three refusals are distinct normative outcomes and must be distinguishable
in the refusal taxonomy. A validator whose only cardinality refusal is "too few"
does not conform to this section.

### 2.3 Scope boundary

`n`-of-`n` for any `n` greater than two is outside V1. This record grants no
authority to admit it. Per A-03 and §1.4, each `n` greater than two requires its
own protocol, denial-of-service, dropout, distribution, and FFI gate before it
may be enabled in a later V1.x, and `m`-of-`n` remains FUTURE pending an audited
threshold scheme and distributed key generation.

Ordering, role separation, and duplicate rejection under §4.1 remain exactly as
specified and are not relaxed by this section.

## 3. Canonical phase transition table

### 3.1 Problem closed

§9.1 defines the closed phase registry with frozen `#[repr(u16)]`
discriminants, including:

```text
RefundSigning   =  90
ClaimSigning    = 110
RefundBroadcast = 180
```

§9.2 publishes the transition table. As published, it contains no row whose
destination is `RefundSigning`, `ClaimSigning`, or `RefundBroadcast`. Instead it
publishes two rows that bypass the first two:

```text
TemplatesCommitted --(refund completo)--------> RefundSigned
RefundSigned       --(adaptor pre-signature)--> ClaimPrepared
```

and it publishes `RefundBroadcast -> Refunded` without publishing any row
entering `RefundBroadcast`.

Implemented literally and as a closed table, the consequence is that all three
phases are unreachable and the refund terminal `Refunded` cannot be reached at
all. That contradicts §7.2, whose safe order requires signing and verifying the
refund in full before funding is authorised, and §11.2, which requires an
eligible refund to be broadcast and rebroadcast after its height. It also
contradicts the Implementation Schedule's Phase 5 exit gate, which requires
*"os **dois** terminais obrigatórios"* — the claim path and the refund path — to
complete.

This is a divergence internal to the Master Specification between §9.1 and §9.2.
It is resolved here by adjudication, in favour of §9.1's registry and §7.2's
ordering, because a phase registry that declares a phase and a table that can
never enter it cannot both be correct, and the refund terminal is a financial
safety requirement under §14.2 I-F1.

### 3.2 Decision

The canonical directed phase-transition table for Phase 1 and the strict V1
contract profile contains **exactly 22 unique directed edges**:

```text
 1  Created              -> TermsCommitted
 2  TermsCommitted       -> SharesCommitted
 3  SharesCommitted      -> SharesRevealed
 4  SharesRevealed       -> BpCommonCommitted
 5  BpCommonCommitted    -> BpCommonEstablished
 6  BpCommonEstablished  -> BpNonceCommitted
 7  BpNonceCommitted     -> BpRound1Complete
 8  BpRound1Complete     -> BpRound2Complete
 9  BpRound2Complete     -> OutputFinalized
10  OutputFinalized      -> TemplatesCommitted
11  TemplatesCommitted   -> RefundSigning
12  RefundSigning        -> RefundSigned
13  RefundSigned         -> ClaimSigning
14  ClaimSigning         -> ClaimPrepared
15  ClaimPrepared        -> FundingAuthorized
16  FundingAuthorized    -> FundingBroadcast
17  FundingBroadcast     -> FundingConfirmed
18  FundingConfirmed     -> ClaimBroadcast
19  FundingConfirmed     -> RefundEligible
20  ClaimBroadcast       -> Settled
21  RefundEligible       -> RefundBroadcast
22  RefundBroadcast      -> Refunded
```

### 3.3 Exact difference from the published §9.2 table

Removed, and forbidden to reintroduce:

```text
TemplatesCommitted -> RefundSigned      (shortcut over RefundSigning)
RefundSigned       -> ClaimPrepared     (shortcut over ClaimSigning)
```

Added:

```text
TemplatesCommitted -> RefundSigning
RefundSigning      -> RefundSigned
RefundSigned       -> ClaimSigning
ClaimSigning       -> ClaimPrepared
RefundEligible     -> RefundBroadcast
```

Retained unchanged from §9.2, including the row that was already published but
previously unreachable:

```text
RefundBroadcast    -> Refunded
```

Every other §9.2 row is retained exactly as published. The preconditions §9.2
attaches to each retained row are unchanged; the four signing edges and the
refund-broadcast edge inherit the preconditions of the phases they connect.

### 3.4 Closure rules

- The table is closed at exactly 22 unique directed edges. No further edge may
  be added, removed, widened, narrowed, or inferred without a new signed record.
- No shortcut edge may coexist with the path it bypasses.
- Every edge strictly increases the §9.1 discriminant of its origin phase. This
  preserves §9.1's monotonic-advance rule; the reversible chain projection of
  §10.1 and §11.1 remains the only category a reorg may rewrite, and it is not a
  phase transition.
- `Aborted` (250) and `FailedClosed` (255) are not reachable through this table.
  They are entered through the §9.3 abort disposition and the fail-closed rules,
  not through a published transition row, and this record adds no edge into
  them.
- A conforming implementation exposes the closed edge set as data that can be
  enumerated and compared, so that conformance is machine-checkable rather than
  asserted.

## 4. Funding-authorization model status

### 4.1 Governing requirements

§7.3 requires that `FundingAuthorization` be *"consumível uma única vez"* and
that *"Broadcast não deve aceitar diretamente bytes de funding sem esse token"*.
§7.2 steps 8 and 9 require `ReadyToFund` to be persisted with compare-and-swap
and `fsync` before funding may be authorised or broadcast. §10.3 defines the
compare-and-swap guard, §10.5 the persist-before-send ordering, and §14.2 I-F1
states that funding is never authorised without a final, persisted refund.
G-UX1 §9 UX-08 and UX-16 make the same property a stop-ship acceptance
criterion and forbid any production build from offering a bypass.

### 4.2 Recorded findings

The following are recorded as normative findings about the current model. They
describe status; they assign no implementation.

1. **`ReadyToFundChecksV1` public Booleans are `MODEL_ONLY`.** A structure of
   public `bool` fields standing for "the adaptor pre-signature was verified",
   "the local and remote ready acknowledgements arrived", "the nonce tombstones
   are durable", and "the `ReadyToFund` record was committed and synced" is a
   caller assertion, not a verification. §7.3 requires those facts to be
   established by the boundaries that own them. A caller can set every field to
   `true` without any of the underlying work having occurred, so the structure
   models the gate rather than enforcing it.

2. **A non-`Clone`, non-`Copy` `FundingAuthorizationV1` does not prove one-time
   issuance.** Linearity in the Rust type system prevents duplicating one value
   inside one process. It does not prevent the issuing routine from being called
   twice for the same session, nor issuance surviving a crash and being repeated
   after restart, nor two concurrent processes each obtaining one. One-time
   issuance is a durable property of the store, not of a move.

3. **A `Clone`/`Copy` `BroadcastAuthorizationV1` is incompatible with production
   authority.** If the value that authorises broadcast can be copied, the
   single-use property §7.3 requires is lost at exactly the point it matters:
   the authority to put funding on the network. Consuming the funding
   authorisation to produce a duplicable broadcast payload reintroduces the
   capability that consumption was meant to retire.

### 4.3 Production requirements

Before any funding-authorisation surface may be treated as production authority,
all of the following are required:

- **Opaque, verifier-issued capabilities.** Each delegated check is represented
  by a capability that only the boundary owning that check can issue, with no
  public constructor, no public field, no byte codec, and no equality or
  ordering that would allow forgery or comparison-based reconstruction.
- **Atomic durable compare-and-swap.** Issuance is a single atomic transition of
  the durable session record under the §10.3 compare-and-swap guard, committed
  and synced per §7.2 step 8 and §10.5 before the authority exists.
- **One-time issuance across concurrency and restart.** The store refuses a
  second issuance for the same session under process duplication, concurrent
  restore, crash between commit and use, and backup or journal merge. A replayed
  or resurrected authorisation fails closed.
- **A non-duplicable broadcast capability.** The value that authorises broadcast
  is linear and retired on use, and cannot be cloned, copied, serialised,
  reconstructed from its fields, or reissued from a stale record.

Until every requirement above is implemented and proven by commit-bound
evidence, the funding-authorisation surface is a model. It may be exercised in
tests and evidence code and may not be presented as a production gate.

## 5. Machine-checkable conformance

Ratification of this record requires the repository to carry an executable guard
that fails unless all of the following hold against the ratified bytes of this
record:

- the canonical transition list contains exactly 22 unique directed edges;
- the list equals the §3.2 enumeration exactly, with no additional, missing, or
  reordered destination for any origin;
- neither removed shortcut of §3.3 appears; and
- the participant cardinality is declared as exactly two distinct participants.

The guard validates normative data. It is not an implementation of the state
machine, the funding gate, the roster validator, or any protocol behaviour, and
ratification of this record authorises none of those.

## 6. What this record does not do

This record assigns no code. It does not implement or authorise the contract
state machine, funding authorisation, the refund or claim path, adaptor
signing, collaborative Bulletproof rounds, the off-chain envelope, the public
SDK, or any G-UX1 deliverable. It does not change the dependency pin, and it
does not alter the Master Specification or the Implementation Schedule.

Adjudicating the two ambiguities above closes them as normative questions. It
does not close any gate, and it does not convert an existing model into an
implementation.

## 7. Stop conditions

Stop without improvisation if:

- this document or its signature does not verify byte for byte;
- a participant set of any cardinality other than exactly two is admitted;
- either removed shortcut edge reappears, alone or beside the path it bypasses;
- the canonical table is observed with any count other than 22 unique directed
  edges;
- any edge is added, removed, or inferred without a new signed record;
- an edge is introduced that does not strictly increase the origin phase
  discriminant;
- a funding-authorisation surface backed by caller-supplied Booleans or a
  duplicable broadcast value is presented as production authority; or
- any change reaches consensus, existing wire, persisted blocks, genesis,
  network parameters, PoW, DL2P, Phase 2, mainnet, or real funds.

Preserve all valid local commits and evidence. Do not reset, clean, rebase,
amend, delete, or weaken a gate to produce a completion label.

## 8. Ratification and status

Ratification means only that the exact signed bytes become the controlling
assignment for the participant cardinality of §2, the canonical transition table
of §3, and the recorded model status of §4.

Ratification does not attest that implementation or tests exist. Gate status may
change only after commit-bound execution and independent review.

```text
DOCUMENT_ID = NAR-DC-P1-007
PARTICIPANT_CARDINALITY = EXACTLY_TWO_DISTINCT
N_OF_N = OUTSIDE_V1
CANONICAL_TRANSITION_EDGES = 22
SHORTCUT_TEMPLATESCOMMITTED_TO_REFUNDSIGNED = REMOVED
SHORTCUT_REFUNDSIGNED_TO_CLAIMPREPARED = REMOVED
REFUNDSIGNING_REACHABLE = ASSIGNED_AFTER_VALID_SIGNATURE
CLAIMSIGNING_REACHABLE = ASSIGNED_AFTER_VALID_SIGNATURE
REFUNDBROADCAST_REACHABLE = ASSIGNED_AFTER_VALID_SIGNATURE
READY_TO_FUND_BOOLEAN_CHECKS = MODEL_ONLY
FUNDING_AUTHORIZATION_ONE_TIME_ISSUANCE = NOT_PROVEN
BROADCAST_AUTHORIZATION_DUPLICABLE = INCOMPATIBLE_WITH_PRODUCTION
FUNDING_AUTHORIZATION_SURFACE = MODEL_NOT_PRODUCTION_AUTHORITY
MASTER_SPECIFICATION = NOT_ALTERED
DEPENDENCY_PIN = NOT_ALTERED
PHASE2 = NOT_AUTHORIZED
MAINNET = DISABLED
REAL_FUNDS = PROHIBITED
PRODUCTION = NOT_AUTHORIZED
G1A = NOT_CHANGED_BY_SIGNATURE_ALONE
G1B = NOT_CHANGED_BY_SIGNATURE_ALONE
G1_CONSOLIDATED = NOT_ADJUDICATED
```
