# DOM INTEROP — F6 ENGINEERING SPECIFICATION
## RFQ, Solver Selection and Relay Transport

```text
Version:   1.0
Date:      2026-08-10
Status:    ADOPTED — the operator adopted this specification in full as
           the F6 normative and execution authority on 2026-08-10
           ("APROVADO", recorded in chat and in the D-018 entry of the
           Foundation Document v0.10). A5 and A10 are RATIFIED with the
           decision texts embedded verbatim in §4.4 and §5.3. The
           adoption does not pre-ratify decisions reserved to F4, does
           not permit replacing the A5/A10 texts with paraphrases, and
           forbids silent material changes: any later change to wire
           format, digest, terms_hash, selection rule, binding
           semantics, bond reservation, roster identity or validation
           order requires a new version, a decision record and express
           ratification.
Authority: subordinate to the Foundation Document; where this document
           and §3.1/§4.6 of the Foundation Document diverge, the
           ratified A5/A10 texts prevail, then the Foundation Document.
Gate:      G-F6 — complete settlement with a solver; total loss of the
           Relay and its database does not prevent local claim or
           refund; ACK/dedup/byte-identical retransmission approved
           (Foundation Document §7, "F6")
History:   v0.1 DRAFT (2026-08-10, same day) presented A5/A10 as open
           options; the operator ratified both with corrections that
           this version incorporates: A5 gains the three-concept
           structure (admissible / binding / winner) and the
           best-net-outcome selection in place of lowest-fee; A10 gains
           the full-envelope digest, the roster-snapshot binding and
           the mandatory validation order.
           1.0.1 (2026-08-10): Addendum AD-1 (§9) — DOM centrality of
           the settlement unit and admissibility clarifications —
           added under the operator's composition directive of
           2026-08-10. RATIFIED: AD-1.1 carries the operator's own
           directive; AD-1.2 (fee-cap composition) and AD-1.4
           (self-tie refusal) were expressly ratified by the operator
           on 2026-08-10 ("APROVADO AD-1.2 e AD-1.4", recorded in
           chat); AD-1.3 records what the ratified modes entail. No
           wire format, digest, terms_hash commitment or ratified
           A5/A10 text changes.
           1.0.2 (2026-08-10): §5.6 added — the CLOSED Relay V1
           message-kind registry and the canonical role to kind
           authorization mapping, RATIFIED by D-019 (explicit operator
           decision, 2026-08-10). Fills the §5.4 step 6 gap the
           executor had reported and implemented behind a policy seam
           marked NOT RATIFIED. No wire format, digest, terms_hash
           commitment or ratified A5/A10 text changes.
           1.0.3 (2026-08-10): §6.1 amended and §6.6 added — the
           sequence domain is the ADDRESSED FLOW and the idempotency
           key distinguishes the recipient, RATIFIED by D-020 (explicit
           operator decision, 2026-08-10). A semantic amendment only:
           no wire format, encoding, digest domain, frozen vector or
           ratified A5/A10 text changes, and D-018 is untouched.
```

---

## 1. Scope

F6 turns the already-proven machinery into a market step:

- an **RFQ / intent** (what the initiating party wants settled) is
  published;
- **solvers** answer with **quotes** (offers to execute the
  counterparty leg under the F4 assurance discipline);
- a deterministic, auditable **selection** binds exactly one quote to a
  settlement, producing the terms the F2 engine already consumes;
- a **Relay** carries envelopes between participants without ever
  becoming a trusted party, a custodian, or a liveness dependency for
  claim/refund/compensation.

Out of scope for F6: any change to the cryptographic session (F1/F5
authority surfaces), the settlement state machine (F2 §6), the on-chain
legs (F3/F5), the assurance machine (F4 spec). F6 composes them; it
does not reopen them. The Kael experimental orderbook remains OUT
(Foundation Document §2; A11 unaffected).

## 2. Design constraints inherited (non-negotiable)

- **I7** — retransmission is byte-identical; nothing is re-signed or
  re-derived on resend. The Relay resends persisted envelope bytes.
- **I9** — only the owning adapter interprets chain bytes; the RFQ layer
  treats quotes' chain references as opaque bindings.
- **I12** — no privileged path: solver selection must be recomputable by
  any observer from the published inputs; Relay arrival order MUST NOT
  affect selection (ratified A5).
- **I13** — named refusals; every rejection of an RFQ, quote or envelope
  carries a typed reason.
- **I14** — caps precede allocation: quote books, envelope sizes and
  per-settlement message counts are bounded before anything is stored,
  and envelope size is checked before decoding (ratified A10 validation
  order, step 1).
- **I15** — single cryptographic authority: A10 reuses BIP340 over the
  D-013-pinned backend and the canonical roster keys; no new primitive.
- **F2 store discipline** — every F6 decision that can affect funds is
  journaled (append-before-effects) in a dedicated journal kind, and
  replay through the real transition function must reproduce the state
  (the F4 `DurableAssurance` precedent).

## 3. Objects (canonical, versioned, frozen by vectors)

All objects follow the established codec discipline: ASCII magic,
`u16` struct version, canonical field order, BLAKE2b-256
domain-separated hashes, golden vectors frozen in the first
implementation commit and never edited afterwards. All quantities are
normalized to one codec, unit, precision and rounding policy (ratified
A5); float is forbidden everywhere (the Annex M precedent).

```text
RfqV1           magic "DOMIRFQ1"
  rfq_id              : [u8;32]   (hash of the canonical encoding, excluding itself)
  initiator           : ParticipantId
  route               : RouteV1   (ordered legs: chain_id, asset, direction)
  mode                : ExactIn { input_amount, minimum_output }
                      | ExactOut { exact_output, maximum_input }
  fee_limit           : FeeLimitV1     (F2, ratified — quotes above it are inadmissible)
  timelock_domain     : TimelockSpec kind (single domain per settlement — F4 rule)
  quote_deadline      : TimelockSpec
  assurance_policy_ref: PolicyId       (the F4 policy quotes must satisfy)
  policy_version      : u32
  session_id          : [u8;32]

QuoteV1         magic "DOMIQTE1"
  quote_id            : [u8;32]
  rfq_id              : [u8;32]
  solver              : ParticipantId
  route               : RouteV1        (must equal the RFQ route exactly)
  net_output          : u128           (exact-in: what the user receives, all costs netted)
  total_input         : u128           (exact-out: what the user pays, all costs consolidated)
  total_fee           : u128           (consolidated; no cost may exist outside it)
  execution_deadline  : TimelockSpec
  bond_reservation_id : [u8;32]        (exclusive F4 reservation — §4.1)
  bond_policy_version : u32
  expiry              : TimelockSpec   (same domain as the RFQ)
  solver_signature    : BIP340 over the canonical unsigned quote (roster key)

AcceptanceV1    magic "DOMIACC1"
  terms_hash          : [u8;32]        (§4.2 — commits the full list ratified in A5)
  rfq_id / quote_id   : [u8;32]
  accepted_by         : ParticipantId
  persisted-by-both requirement: the acceptance exists only when both
  parties hold it durably (journal kind 0xF601, append-before-effects)

SelectionV1     magic "DOMISEL1"
  rfq_id              : [u8;32]
  winning_quote       : [u8;32]
  inputs_digest       : [u8;32]  (hash of the full candidate set — makes the
                                  selection recomputable and disprovable, I12)
```

## 4. A5 — solver selection (RATIFIED 2026-08-10)

### 4.1 Admissible quotes

A quote participates in selection only if ALL of the following hold
(each failure is a named refusal, I13):

1. it is canonically encoded and signed by a REGISTERED solver (roster
   membership at the applicable snapshot);
2. it is unexpired;
3. it matches the `rfq_id`, the route and the assets exactly;
4. it respects the RFQ's minimum-to-receive (`ExactIn`) or
   maximum-to-pay (`ExactOut`) bound, and the ratified `FeeLimitV1`;
5. all costs are consolidated in `total_fee` — no cost outside it;
6. it carries a VALID and RESERVED F4 bond (`bond_reservation_id`);
7. the bond covers the ECONOMIC EXPOSURE computed by the F4 policy for
   THIS quote — not a generic "bond >= value" rule: exposure coverage
   (haircut, volatility, route risk, execution time, collateral asset)
   is the F4 policy's to compute, so it can evolve without reopening A5;
8. the same bond capacity is not committed to any other operation
   (exclusive reservation — double-commitment is a refusal);
9. the solver is not suspended and not undergoing slashing;
10. the quote uses a policy version the session accepts.

### 4.2 Binding quotes

A solver signature alone proves authorship; it does NOT create an
executable obligation. A quote becomes binding only when the following
occur atomically (one journaled transition, crash-safe):

1. signature and admissibility validation;
2. exclusive reservation of the F4 bond;
3. acceptance of the quote by the protocol or the user;
4. creation of the `terms_hash`;
5. persistence of the acceptance by BOTH parties.

The `terms_hash` MUST commit at least:

```text
protocol_version, rfq_id, quote_id, route,
input_asset, input_amount, minimum_output or exact_output,
maximum_input, total_fee, solver_id,
bond_reservation_id, bond_policy_version,
execution_deadline, refund_deadlines, payout_commitments,
quote_expiry, session_id
```

After acceptance, ANY material change — price, fee, solver, payout,
route, deadline or bond policy — requires a new quote and a new
approval. The accepted `terms_hash` is carried into the settlement's
`SettlementTermsV1` so the F2 engine adjudicates under it. The carry's
field and exact encoding are RATIFIED by D-023 (Foundation Document
v0.13 §12.1): `metadata` holds exactly one record,
`DOM-INTEROP/F6-TERMS-CARRY/V1\0 || accepted_terms_hash`, as a
provenance COMMITMENT — metadata stays economically non-authoritative,
the composition root sources the value from the F6 journal alone, and a
divergent restore fails closed by name.

### 4.3 Winner selection

Lowest fee alone is NOT the criterion (a solver could advertise a low
fee and deliver a worse rate). The criterion is the best VERIFIABLE
ECONOMIC OUTCOME for the user:

1. `ExactIn` RFQs: the admissible quote with the GREATEST `net_output`
   wins;
2. `ExactOut` RFQs: the admissible quote with the LOWEST `total_input`
   wins;
3. economic tie: shortest `execution_deadline` wins;
4. still tied: greatest EXCESS of F4 coverage wins;
5. final tie: lexicographically smallest canonical `solver_id`,
   compared byte by byte.

All quantities are normalized (same codec, unit, precision, rounding)
before comparison. Arrival order MUST NOT be used anywhere — it would
hand the Relay an ordering lever (I12).

### 4.4 Ratified text (operator, 2026-08-10 — normative verbatim)

> A5 — RATIFIED. A quote is eligible only when it is canonically
> encoded, signed by an active solver, unexpired, compliant with the
> RFQ and backed by an exclusive F4 bond reservation satisfying the
> applicable exposure-coverage policy. A quote becomes binding only
> after deterministic validation, successful bond reservation,
> acceptance and persistence of the resulting `terms_hash`. For
> exact-input RFQs, the admissible quote with the greatest net output
> wins. For exact-output RFQs, the admissible quote with the lowest
> total input wins. Ties are resolved by the shortest execution
> deadline, then the greatest excess F4 coverage, then the
> lexicographically smallest canonical `solver_id`. Relay arrival order
> MUST NOT affect selection.

No new economic primitive: F4 remains the only punishment basis. The
F4-side interface this creates — an exclusive, exposure-priced bond
RESERVATION — is a consumer of the F4 policy objects, not a change to
the F4 machine (build order step 3).

## 5. A10 — envelope authentication (RATIFIED 2026-08-10)

### 5.1 Threat model

The Relay is untrusted transport. It may delay, repeat, reorder, omit,
misdeliver, and attempt byte substitution. It MUST NOT be able to
produce an envelope accepted as coming from an honest participant, and
it holds no signature-production or verification authority.

### 5.2 What is signed

Not the payload alone: the signature covers the COMPLETE canonical
envelope, excluding only the signature field itself. The digest commits:

```text
protocol_id, protocol_version, network_id, message_type,
session_id, route_id, sender_id, recipient_id, sender_role,
sequence, previous_transcript_hash,
payload_length, payload_hash, expiry, policy_version,
roster snapshot identifier (version or root)
```

```text
envelope_digest  = BLAKE2b-256("DOM-INTEROP/RELAY-ENVELOPE/V1",
                               canonical_unsigned_envelope)
sender_signature = BIP340_Sign(roster_signing_key, envelope_digest)
```

BLAKE2b-256 is the project's protocol-digest function and produces the
32 bytes BIP340 signs; the Bitcoin SHA-256 tagged-hash scheme is NOT
imported just because the signature is BIP340. Hash function and
framing are frozen by canonical vectors in the first implementation
commit. The roster snapshot identifier in the envelope keeps a later
key rotation from making historical message validity ambiguous.

### 5.3 Ratified text (operator, 2026-08-10 — normative verbatim)

> A10 — RATIFIED. Every Relay envelope MUST be authenticated with a
> BIP340 signature produced by the sender's canonical roster key over a
> domain-separated digest of the complete canonical unsigned envelope.
> The signed material MUST bind the protocol and network identifiers,
> version, message type, session, route, sender, recipient, sender
> role, sequence, previous transcript hash, payload length and hash,
> expiry, policy version and roster snapshot identifier. The Relay is
> untrusted and MUST NOT participate in signature production or
> verification authority. Recipients MUST validate canonical encoding,
> roster membership and role, signature, replay state, sequence and
> transcript continuity before processing the payload.

### 5.4 Mandatory validation order (recipient)

1. bound the size BEFORE allocating (I14);
2. decode canonically;
3. reject unknown versions, flags and types;
4. check `network_id`, `recipient_id`, session and expiry;
5. locate `sender_id` in the CORRECT roster snapshot;
6. confirm the sender's role permits this `message_type`, against the
   CLOSED registry and canonical mapping of §5.6 (D-019). The role is
   read from the ROSTER and never from a claim in the envelope. This
   lookup and check are NON-MUTATING and PROVISIONAL: no payload is
   delivered, no success ACK is emitted and no acceptance effect or
   state is produced before step 7 completes (D-019, as clarified by
   the operator on 2026-08-10 — the earlier phrase "only after
   authenticating" does not order step 7 ahead of step 6);
7. verify the BIP340 signature;
8. apply replay, gap and equivocation protection, within the D-020
   sequence domain of §6.6;
9. verify chaining via `previous_transcript_hash`;
10. only then deliver the payload to the state machine.

### 5.5 What A10 does and does not provide

Provides: authenticity, integrity, attribution to a roster member,
provable equivocation evidence. Does NOT provide: confidentiality,
network anonymity, delivery guarantees, fair ordering, Relay
availability. End-to-end encryption and the retransmission mechanism
remain separate concerns (retransmission stays byte-identical, I7).

### 5.6 Message-kind registry and role authorization (RATIFIED by D-019)

The §5.4 step-6 authorization, decided by the operator on 2026-08-10.

**The registry is CLOSED in V1:**

```text
0x0000          INVALID/RESERVED
0x0001          RfqV1
0x0002          QuoteV1
0x0003          AcceptanceV1
0x0004          SelectionV1
0x0005..0xffff  RESERVED/UNKNOWN in V1
```

**Canonical sender authorization:**

| role      | may emit                            |
|-----------|-------------------------------------|
| Initiator | `RfqV1`, `AcceptanceV1`, `SelectionV1` |
| Solver    | `QuoteV1`                           |
| Observer  | nothing — strictly non-emitting (Annex M §M.9.1) |

`RfqV1` is emitted by the initiator; `QuoteV1` by the solver;
`SelectionV1` is the adjudication emitted by the initiator, committing
the candidate set and the selected quote; `AcceptanceV1` is emitted by
the initiator and is the final acceptance of the selected quote and its
terms.

Unknown versions and unknown kinds FAIL CLOSED. The values 1-4 are
IMMUTABLE within V1: a new type requires explicit ratification and a
compatible normative version, never an inference.

**Production exclusivity.** The `MessageTypePolicy` seam stays
mandatory, but the production implementation is the canonical one and
only the canonical one: the production composition root instantiates
`CanonicalMessageTypePolicyV1` exclusively, and no permissive policy,
external configuration or caller-chosen implementation may reach a
production path. Mocks and alternative policies are confined to tests,
and `scripts/guards.sh` refuses them anywhere else — the same executable
discipline that keeps the F2 store failpoints out of production builds.

**Division of labour with the payload.** The Relay stays forbidden from
decoding payloads (§6.2): the policy authorizes the HEADER. The
recipient consumer decodes the payload and verifies that the inner
object corresponds to the `message_kind`, to the sender, to the
settlement and to the bindings. That check therefore lives outside the
Relay crate entirely, so the transport cannot link a payload decoder.

**Digest coverage (rectified by the operator, 2026-08-10).** D-019's
first wording listed `service`, `settlement_id`, `message_id` and
`payload_codec` among the fields the authenticated digest must cover.
None of the four exists in the `RelayEnvelopeV1` wire ratified by
D-018. The executor reported that adding them would be a wire change
requiring its own ratification, and the operator EXPRESSLY RECTIFIED
that wording the same day: the four fields are not to be added, the
encoding, digest domain and frozen vector are not to be altered, and
D-019 does not supersede, replace or modify D-018. The digest covers
exactly the fields §5.2 ratifies, and no others.

## 6. Relay semantics (normative)

Ported from Foundation Document §4.6 and made testable:

1. **At-least-once transport, exactly-once effects.** Idempotency key
   `(session_scope, sender_id, recipient_id, sequence)` — AMENDED by
   D-020; see §6.6 for the amendment and for the original wording it
   replaces. Same key + same bytes ⇒ same ACK (byte-identical, I7).
   Same key + different bytes ⇒ `Equivocation` — a named refusal (I13)
   that fails the session closed and journals BOTH conflicting digests
   plus the two signatures as third-party-verifiable evidence (A10
   makes equivocation provable).
2. **The Relay never decodes payloads.** It routes on the envelope
   header only.
3. **Relay-loss survivability (the gate's second clause).** Claim,
   refund and compensation read only local durable state and the
   chains. The G-F6 suite must kill the Relay (process AND database) at
   every protocol stage and prove the session still reaches its
   terminal state through local artifacts plus chain observation.
4. **Reconciliation.** A returning Relay reconciles by digest and
   idempotency key; re-delivered envelopes produce no second effect.
5. **Journal kind.** F6 decisions ride the F2 store as kind `0xF601`,
   append-before-effects, with the same crash-at-every-transition
   harness the F4 journal passed.

### 6.6 Sequence domain and fan-out (AMENDED by D-020)

D-020 (explicit operator decision, 2026-08-10) is a SEMANTIC amendment
to §6.1 and to the gap verification of §5.4 step 8. It does not modify
D-018, the wire, the encoding, the digest domain or the frozen vector,
and adds no envelope field.

**The sequence domain is the addressed flow:**

```text
sequence_domain = (session_scope, sender_id, recipient_id)
```

`session_scope` is the session scope that already exists in §6.1 and in
the implementation; it is not a new envelope field. `recipient_id` is
already a ratified header field of `RelayEnvelopeV1` (§5.2).

Within each domain:

- `sequence` starts at `0`;
- it grows contiguously;
- `previous_transcript_hash` references the immediately preceding
  envelope OF THE SAME DOMAIN;
- at `sequence = 0` it carries the canonical initial value already
  defined;
- **gaps remain forbidden**;
- there is NO mandatory total order between different recipients.

**The §6.1 idempotency key therefore distinguishes the recipient:**

```text
(session_scope, sender_id, recipient_id, sequence)
```

replacing the original `(settlement_id, sender_id, message_id |
sequence)`.

Consequences, as ratified:

- two recipients may legitimately receive `sequence = 0`;
- that is neither a collision nor equivocation;
- one sender keeps an independent contiguous chain per recipient;
- equivocation exists only when the SAME domain and the SAME
  authenticated sequence present incompatible bytes or digests;
- fan-out is represented by distinct envelopes, one per recipient;
- `message_id` is not required;
- no recipient suffers a gap because of messages addressed exclusively
  to another participant;
- causality between different flows, where needed, belongs to the
  consuming object/protocol and not to the Relay's counter.

## 7. Build order (unblocked by the A5/A10 ratification)

```text
1. Objects + canonical codecs + frozen vectors (RfqV1, QuoteV1,
   AcceptanceV1, SelectionV1, RelayEnvelopeV1 with the ratified digest
   fields and the envelope-digest vector).
2. f6-model: exhaustive checker over the selection function —
   determinism, admissibility (no unbonded winner, no double-reserved
   bond), the full ratified tie-break chain, I12 recomputability,
   arrival-order independence, cap enforcement. (The F4 step-1
   precedent: model first; it found a real machine defect there.)
3. Bond reservation interface over the F4 objects (exclusive,
   exposure-priced, journaled) + the atomic §4.2 binding transition
   with crash-per-transition tests.
4. Selection engine + journal kind 0xF601 over the F2 store.
5. Envelope authentication: BIP340 over the D-013 backend, the §5.4
   validation order as ordered named refusals, adversarial suite
   (byte substitution, misdelivery, replay, gap, reorder, equivocation,
   stale roster snapshot, role violation).
6. Relay reference implementation + equivocation/dedup/resend suite
   (byte-identical ACKs asserted at the byte level).
7. Relay-loss adversarial suite: kill Relay at every stage; assert
   local claim/refund/compensation terminality.
8. End-to-end: RFQ → quotes → selection → binding → F2 settlement →
   F3/F5 legs → F4 assurance, driven with the dom-sim seam (F7 swaps
   the real DOM).
9. Closure report + G-F6 adjudication package for ratification.
```

## 8. What this specification does not decide

- Exposure-coverage pricing internals (haircut tables, volatility
  inputs) — the F4 policy's domain, evolvable without reopening A5.
- Bond asset diversity (the F4 A5/A6 remainder).
- End-to-end payload encryption (explicitly outside A10).
- Relay deployment topology — operational, not protocol; the
  loss-survivability rule makes it non-load-bearing.
- Any F7 concern (real DOM eligibility, Scriptless P2–P6).

## 9. Addendum AD-1 — DOM centrality and admissibility clarifications
##    (2026-08-10; presented for ratification)

### AD-1.1 The settlement unit is DOM-centric (operator directive)

The operator's acceptance of the two-leg structure (2026-08-10) fixed
its meaning: the two legs are a SETTLEMENT UNIT — the F2-ratified
`dom_leg` + `counterparty_leg` shape — not a product limitation. An
external intent such as `ETH → BTC` executes as the DOM-centric
composition `ETH → DOM → BTC`: two settlement units, each containing
the DOM. Direct external-to-external settlement that bypasses the DOM
is FORBIDDEN.

The v1 wire (`RouteV1`) identifies legs by user direction and cannot
know which 32-byte registry id is the DOM — a registry value the codec
has no authority over. The enforcement point is therefore
ADMISSIBILITY, where the session's DOM chain identity is known:

> Every settlement unit's route MUST contain the session's DOM chain
> id on EXACTLY ONE leg. An RFQ or quote whose route excludes the DOM
> — or contains it on both legs — is refused by name
> (`RouteExcludesDom` / `InvalidRouteShape`), never repaired. The
> selection function takes the session's DOM chain id as an input and
> applies this check before any economic comparison; the f6-model
> checker proves no winner ever emerges from a DOM-less route.

Composition (`ETH → DOM → BTC`) is expressed as two RFQs/settlement
units and is NOT adjudicated inside one selection: each unit selects,
binds and settles under its own terms_hash, and the F2 engine
adjudicates each. A composed-intent orchestration object, if ever
wanted, is a new decision — nothing in v1 blocks it, and nothing in v1
permits bypassing the DOM.

### AD-1.2 Fee-limit composition over a consolidated fee

`FeeLimitV1` (F2, ratified) caps fees PER LEG (`dom_max`,
`counterparty_max`); the ratified A5 quote carries ONE consolidated
`total_fee`. The only comparison that neither invents a split nor
ignores a cap: the consolidated fee must not exceed the sum of the
two ratified caps —

> `total_fee <= dom_max + counterparty_max` (checked arithmetic;
> overflow refuses). Refusal name: `FeeAboveLimit`.

This is weaker than per-leg enforcement (a consolidated figure cannot
be attributed to legs without inventing an attribution rule) and is
flagged here for the operator's explicit ratification. A future
per-leg fee breakdown in the quote is a wire change (new version).

### AD-1.3 Mode exactness

Entailed by the ratified modes and recorded for the record: for an
`ExactIn` RFQ a quote's `total_input` MUST equal `input_amount`
(refusal `InputMismatch`); for an `ExactOut` RFQ a quote's
`net_output` MUST equal `exact_output` (refusal `OutputMismatch`).
The "exact" side is exact; the protected side is bounded
(`minimum_output` / `maximum_input`).

---

*A5 and A10 were ratified by the operator on 2026-08-10 with the
decision texts embedded verbatim in §4.4 and §5.3 (Foundation Document
registry entry D-018). The executor prepared this specification and
does not self-ratify it; its adoption as the F6 execution authority is
the operator's word.*


### AD-1.4 Self-tie refusal

The ratified tie chain ends at the lexicographically smallest
`solver_id`. Two DISTINCT admissible quotes from the SAME solver that
are equal on every ratified key (economic outcome, execution deadline,
excess coverage, solver id) therefore have no unique winner under the
ratified rule. The selection REFUSES by name (`TieUnresolved`) rather
than inventing an unratified tie-break; the initiator may re-issue the
RFQ. Flagged for the operator's word — the obvious cures (final
`quote_id` comparator, or one-admissible-quote-per-solver) are both
selection-rule changes requiring ratification. The f6-model checker
proves the refusal fires EXACTLY in this configuration and never
otherwise.
