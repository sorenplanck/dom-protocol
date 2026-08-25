# F6 BUILD-ORDER STEP 6 — REQUIREMENT → TEST → RESULT

```text
Phase:      F6 (RFQ / quotes / selection / binding)
Step:       6 — Relay reference implementation and the authenticated
            recipient pipeline
Authority:  DOM-Interop F6 Engineering Specification v1.0.3 §5, §6
            (A5/A10 ratified by D-018; the message-kind registry and
            role authorization ratified by D-019; the addressed-flow
            sequence domain and the recipient-distinguishing
            idempotency key ratified by D-020)
Date:       2026-08-10
Executor:   this report states results only; the GATE verdict is the
            operator's and is not claimed here.
```

---

## 1. What this step had to prove

Step 6 has two halves, and the ratified documents keep them apart on
purpose:

* **The Relay is transport, not authority** (§6.1-6.2). It stores and
  forwards under the ratified idempotency key, answers a byte-identical
  resend with a byte-identical ACK, fails closed on equivocation with
  evidence a third party can check, and never decodes a payload.
* **The recipient is the authority** (§5.4). Ten ordered steps, each a
  named refusal, over a BIP340 signature that covers the complete
  canonical unsigned envelope.

D-019 closed the one gap that remained open in that second half: §5.4
step 6 said "confirm the sender's role permits this `message_type`"
without any document defining the message kinds or the mapping. That
seam had been implemented behind a policy marked NOT RATIFIED in the
code and reported rather than filled. It is now ratified and
implemented.

---

## 2. D-019 — the twelve mandatory tests

Test numbering is the decision's own. Tests 1-10 and 12 are in
`crates/relay/tests/d019_message_type_policy.rs`; test 11 is in
`crates/f6-engine/tests/d019_consumer_payload.rs`, because the ratified
§6.2 rule forbids the Relay from decoding payloads and the `relay`
crate therefore does not depend on `rfq` at all.

| # | Ratified requirement | Test | Result |
|---|----------------------|------|--------|
| 1 | complete matrix of 3 roles × 4 kinds | `t01_the_full_three_roles_by_four_kinds_matrix` | PASS — 4 cells accepted, 8 refused `RoleNotPermitted` at step 6 |
| 2 | Observer rejected for all kinds | `t02_the_observer_is_refused_for_every_kind` | PASS — 4/4 refused |
| 3 | Initiator rejected for Quote | `t03_the_initiator_is_refused_for_quote` | PASS |
| 4 | Solver rejected for RFQ, Acceptance, Selection | `t04_the_solver_is_refused_for_rfq_acceptance_and_selection` | PASS — 3/3 refused |
| 5 | 0x0000, 0x0005 and 0xffff rejected | `t05_invalid_and_reserved_kinds_are_refused_for_every_role` | PASS — refused for all 3 roles; the registry predicate is exhaustively checked over the whole 16-bit space and admits exactly 4 values |
| 6 | role spoofing with an incompatible key | `t06_role_spoofing_with_an_incompatible_key_is_refused` | PASS — claimed role ≠ roster role refused at step 6 (`RoleMismatch`); correct header signed by the wrong roster key refused at step 7 (`InvalidSignature`) |
| 7 | sender absent from the roster | `t07_a_sender_absent_from_the_roster_is_refused` | PASS — 12 combinations, all `SenderNotInRoster` at step 5, i.e. before the policy and before the signature |
| 8 | an alternative policy is impossible on the production composition root | `t08_an_alternative_policy_cannot_reach_the_production_path` + `scripts/guards.sh` | PASS — a permissive policy visibly changes the outcome through the test-only seam (so the test is not vacuous) and the production entry point refuses the same bytes; the canonical policy is checked against the ratified mapping over all 65 536 kinds × 3 roles |
| 9 | altering `message_kind` after signing invalidates authentication | `t09_altering_the_message_kind_after_signing_breaks_authentication` | PASS — mutated RFQ→Acceptance (both permitted for the sender, so step 6 passes) and the refusal is step 7's |
| 10 | an undecodable payload is still routed when the header is valid | `t10_an_undecodable_payload_is_still_routed_when_the_header_is_valid` | PASS — 512 bytes of noise routed and delivered byte for byte |
| 11 | the consumer rejects a payload whose object does not correspond to the `message_kind` | `t11a`…`t11g` (7 tests) | PASS — see §3 |
| 12 | fan-out uses an addressed envelope with its own sequence, without colliding on the §6.1 key | `t12_1`…`t12_8` (8 tests) | PASS — see §2b; re-specified by D-020 |

## 2b. D-020 — the eight required fan-out proofs

D-020 (operator, 2026-08-10) resolved the contradiction the executor had
reported in test 12: it defines the sequence domain as the ADDRESSED
FLOW `(session_scope, sender_id, recipient_id)` and makes the §6.1
idempotency key distinguish the recipient. No wire change — `recipient_id`
was already a ratified header field of D-018's envelope, and the frozen
digest vector is untouched.

| # | Ratified proof | Test | Result |
|---|----------------|------|--------|
| 1 | two distinct recipients accept `sequence = 0` | `t12_1_two_recipients_both_accept_sequence_zero` | PASS — both accepted, as separate states and inside one shared state (the process-hosting-both case) |
| 2 | idempotency keys are distinct by `recipient_id` | `t12_2_idempotency_keys_are_distinguished_by_recipient` | PASS — session, sender and sequence asserted EQUAL and only the recipient different, so nothing else is doing the distinguishing |
| 3 | each recipient then accepts its own `sequence = 1` | `t12_3_each_recipient_continues_its_own_chain` | PASS |
| 4 | no gaps arise from fan-out | `t12_4_fan_out_to_others_opens_no_gap_but_real_gaps_still_refuse` | PASS — 12 envelopes addressed elsewhere between A's 0 and A's 1; A's next is 1, not 13. The same test asserts a genuine in-flow skip is still `SequenceGap` and a flow still cannot be joined mid-sequence |
| 5 | byte-identical retransmission yields the same ACK | `t12_5_a_retransmitted_leg_gets_the_identical_ack` | PASS — whole ACK compared, one stored entry, and the recipient names the redelivery `Duplicate` without moving the watermark |
| 6 | different bytes at the same key yield equivocation | `t12_6_different_bytes_at_one_key_are_still_equivocation` | PASS — fails closed at the Relay and at the recipient; the proof verifies independently and the conflicting bytes are not adopted |
| 7 | the same sequence at different recipients does not collide | `t12_7_the_same_sequence_at_different_recipients_does_not_collide` | PASS — 4 recipients × 3 sequences = 12 legs, 12 distinct keys, 3 per mailbox |
| 8 | `previous_digest` chains only within one domain | `t12_8_the_transcript_chains_only_within_one_domain` | PASS — cross-flow chaining refused `TranscriptDiscontinuity` in both directions and at flow open; each flow's own chain still works afterwards |

The gap refusal was NOT relaxed. What D-020 changed is what a flow IS;
a skip inside a flow is refused exactly as before, and proof 4 asserts
both halves in one test so the amendment cannot be read as a loosening.

## 3. Test 11 in detail — the consumer payload check

Every envelope in this suite is authenticated by the REAL §5.4 pipeline
with a real BIP340 signature first. Each refusal below is therefore a
payload the transport had every reason to accept — correct header, valid
signature, permitted role, clean sequence — so what is measured is the
consumer's own check and nothing borrowed from upstream.

| correspondence | test | result |
|----------------|------|--------|
| baseline (all four kinds, everything corresponding) | `t11a` | PASS — accepted, so the refusals below are not vacuous |
| kind: a well-formed object of another type | `t11b` | PASS — 7 substitutions, all `PayloadDecode` |
| sender: object names a participant other than the authenticated sender | `t11c` | PASS — quote, acceptance and RFQ variants, all `SenderMismatch` |
| settlement: object names another session | `t11d` | PASS — `SessionMismatch` |
| bindings: object bound to another RFQ | `t11e` | PASS — quote, acceptance and selection variants, all `RfqMismatch` |
| the payload D-019 test 10 routed | `t11f` | PASS — `PayloadDecode`; the two halves together are the §6.2 claim |
| object whose own content-derived id does not bind | `t11g` | PASS — `PayloadDecode(IdMismatch)` on wire-mutated bytes (the object API cannot even encode an unbound id) |

## 4. Step-6 work preserved (D-019 explicit requirement)

The decision required that everything already implemented in step 6 be
preserved in full. Each item still has its test, and each still passes:

| ratified rule | test | result |
|---------------|------|--------|
| §6.1 idempotency key | `a_resend_gets_a_byte_identical_ack_and_the_persisted_bytes` | PASS |
| byte-identical ACK | same test — the WHOLE ACK is compared, not selected fields | PASS |
| resend replays the persisted bytes | same test — `stored_bytes` compared to the submission | PASS |
| at-least-once transport, exactly-once effects | `at_least_once_delivery_becomes_exactly_once_at_the_recipient` | PASS — 3 delivery rounds, 1 effect, 2 named duplicates |
| equivocation fails closed | `equivocation_fails_closed_and_the_proof_verifies_independently` | PASS |
| `verify_equivocation` is third-party verifiable | same test — checked with the roster alone, nothing from the Relay | PASS |
| a fabricated proof does not stand | `a_fabricated_equivocation_proof_does_not_stand` | PASS — 3 fabrication shapes, 3 distinct verdicts |
| §6.2 opaque payload | `the_relay_routes_a_payload_it_cannot_possibly_interpret` | PASS |

## 5. The §5.4 order itself

The adversarial suite (`crates/relay/tests/auth_adversarial.rs`, 17
tests) is unchanged by D-019 and still passes. It asserts each refusal
BY NAME and AT ITS RATIFIED STEP, because "refused" alone would not
prove the order: a recipient that checked the signature before the
roster would still refuse, and would still be wrong.

## 6. Structural guarantees (not expressible as unit tests)

| guarantee | mechanism | result |
|-----------|-----------|--------|
| the production path cannot be handed another policy | `accept_envelope` takes no policy parameter; `guards.sh` fails if it ever does | PASS |
| the test-only seam cannot be called from production | `guards.sh` refuses `accept_envelope_with_policy` outside test trees | PASS (guard verified against a deliberate violation) |
| no alternative `MessageTypePolicy` outside tests | `guards.sh` refuses any other `impl`, and requires exactly one canonical impl in `auth.rs` | PASS (guard verified against a deliberate violation) |
| the Relay cannot decode an F6 object | `relay` does not depend on `rfq`; the consumer check lives in `f6-engine` | PASS — a fact about the dependency graph, not a discipline promise |

## 7. Totals

```text
crates/relay        7 unit + 17 adversarial + 18 D-019/D-020 +
                    8 transport                                       = 50
crates/f6-engine    9 unit +  7 D-019 consumer                        = 16
                                                              total    66
```

Full local CI (`scripts/ci_local.sh`): **PASS** — lockfile, fmt, clippy
`-D warnings`, workspace tests, store failpoints, doc tests, f2-model,
f4-model, f6-model, the 2000-case property suite, the independent terms
vector verifier, and all ten executable guards. Foundry is not on this
runner's PATH; the contracts job runs in CI.

---

## 8. Reported divergences — resolved by the operator

The executor reported three items of D-019 that could not be implemented
as written against the V1 wire, and implemented none of them by
inference. The operator resolved all three on 2026-08-10.

**(a) Four digest fields that do not exist on the wire.** D-019's first
wording listed `service`, `settlement_id`, `message_id` and
`payload_codec` among the fields the authenticated digest must cover;
none exists in the `RelayEnvelopeV1` ratified by D-018 (§5.2).
**Rectified:** the operator expressly withdrew that wording. The fields
are not added, the encoding, digest domain and frozen vector are
unchanged, and D-019 does not supersede, replace or modify D-018.

**(b) Test 12's per-recipient sequence space.** Without `message_id`,
two recipients "each at their own sequence 0" claimed ONE §6.1 key — the
collision the same decision forbade. **Resolved by D-020:** the sequence
domain is the addressed flow and the key distinguishes the recipient. No
wire change was needed, because `recipient_id` was already on the wire.
The eight required proofs are §2b above.

**(c) "The role from the roster only after authenticating."**
**Clarified:** this does not order step 7 ahead of step 6. The ratified
order stands — step 6 reads the role from the roster and checks the
role→kind authorization, step 7 verifies the signature — and the step-6
lookup and check are non-mutating and provisional: no payload delivered,
no success ACK, no acceptance effect or state before step 7 completes.
The implementation already satisfied this (the only writes in
`accept_envelope` happen after step 9); it is now documented at the call
site and in §5.4.

**AD-1.2 and AD-1.4** now have registry entries as D-021 and D-022, on
the operator's order, carrying the object, normative text, scope and
consequence exactly as they stand in the F6 specification. The AD-1.2
and AD-1.4 identifiers are preserved as historical references. Those
entries document decisions already taken and authorize no semantic
expansion.

## 9. Incompatibilities found while implementing D-020

None. `recipient_id` was already a ratified header field, so the
amendment cost no wire change, no re-freezing of the digest vector and
no change to any existing frozen test vector. The one code change with a
wider blast radius — keying `TranscriptStateV1` by the flow rather than
by the sender alone — was made structural rather than left to caller
discipline, because a single state object shared by two hosted
participants would otherwise have conflated two flows into one
watermark.
