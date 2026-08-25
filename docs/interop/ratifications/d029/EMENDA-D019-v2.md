# D-019 Amendment v2 — one additional Relay V1 message type

- Raised: 2026-08-17. **v2 issued 2026-08-19**, replacing the version signed
  on 2026-08-19T17:10:23Z. The signature on v1 is retained: its content was
  authorised and is unchanged here. v2 exists because v1 had three defects of
  form, none of content, and one of them caused a method failure downstream.
- Status: **NOT RATIFIED as v2.** This version needs its own signature.
- **Supersession of the signed v1, stated so no ambiguity of authority can
  survive this document.** v1 was signed by the operator with minisign on
  **2026-08-19T17:10:23Z** (verifiable against `dom-release.pub`,
  `RWTwnDDKlXoZdG3obVRiLPfVRHr17E0Fj2GN8IZ2rBkipRZvIIW6PLJ3`). Its §1 states
  the role mapping as prose; this version's §1 enumerates it. **The operative
  text therefore differs between two signed documents.** On the date v2 is
  signed, **v1 ceases to have effect** and is retained as history only. Where
  the two disagree, v2 governs; where v2 is silent, v1 does not fill the gap —
  the Foundation Document §12.1 does.

## 0. State of the tree at the time of writing — read this first

v1's header promised the value would stay inert until signed. **That promise
was broken before the signature, and this document says so rather than
repeating the promise.** The real state:

| Commit | Where | What it does |
| --- | --- | --- |
| `c7c8399` (2026-08-18) | `crates/relay/src/auth.rs` | added `ROUTE_TRANSPORT = 0x0005` to the registry and the role clause, marked NOT RATIFIED in the doc comments |
| `2c08283` (2026-08-19) | `crates/relay/src/auth.rs` | replaced those NOT RATIFIED markings with the ratification record — **comments only, no behaviour** |
| `2c08283` (2026-08-19) | `crates/relay/tests/d019_message_type_policy.rs` | **two edits to existing tests**: `t05`'s reserved-value probe `0x0005` → `0x0006` and its registry-size assertion `4` → `5`; and `ratified_permits`, the independent norm mirror, extended with `RouteTransportV1` for Initiator and Solver |

**What the suite asserts today:** a registry of five known kinds, with
`RouteTransportV1` emittable by Initiator and Solver. That is the amended
norm, asserted by the tests before the norm was recorded in §12.1.

**The method defect, disclosed:** `ratified_permits` carries the doc comment
*"The ratified mapping, written out independently of the implementation so the
test cannot agree with a bug by construction."* It was rewritten by reading
`auth.rs`, not by transcribing a normative text. Its content matches this
amendment, but its provenance is the object it exists to judge, so the
65,536-value sweep at line 419 that consumes it compared the implementation
with itself. **v1 §1 gave it nothing to transcribe from** — see §1 — which is
why §4 of the operator's order registers the decision in §12.1 first and only
then rewrites the mirror.

`is_known` was **not** changed by `2c08283`; the registry value has been in
the code since `c7c8399`.

Nothing is published. No commit reaches `origin/main`.

## 1. The decision requested

Amend D-019's registry and role mapping. **D-019's decision text is not
edited** — a ratified record is immutable and remains the record of what was
decided on 2026-08-10. The amendment is carried by a new decision, D-029,
which states the complete resulting registry and mapping in its own text, so a
norm mirror transcribes from one source rather than two stitched together.

The block below is byte-identical to the `Decision:` block of D-029 in
Foundation Document v0.19 §12.1. If they ever diverge, there are two norms and
the §12.1 text governs.

```text
Resulting registry, as amended by this decision:

0x0000 = INVALID/RESERVED
0x0001 = RfqV1
0x0002 = QuoteV1
0x0003 = AcceptanceV1
0x0004 = SelectionV1
0x0005 = RouteTransportV1
0x0006..0xffff = RESERVED/UNKNOWN in V1

Resulting sender authorization mapping:

Initiator: RfqV1, AcceptanceV1, SelectionV1, RouteTransportV1
Solver:    QuoteV1, RouteTransportV1
Observer:  no type; the observer emits no messages

D-019 is amended in this single respect. Its text is
unchanged and remains the record of what was decided on
2026-08-10.
```

**v1 said "opaque to the Relay, emittable by both roles that sign DSC1
rounds".** That is true and it is a paraphrase. D-019, which this amends,
enumerates its roles verbatim; an amendment less precise than the decision it
amends leaves a mirror nothing to copy — which is how `ratified_permits` came
to be derived from the implementation.

## 2. Why the laboratory cannot decide it

`crates/relay/src/auth.rs` carries a closed registry, in its own words:

> "The CLOSED message-kind registry of Relay V1, RATIFIED by D-019 (operator
> decision, 2026-08-10). The values 1-4 are IMMUTABLE within V1; 0 is invalid
> and 5..=0xffff are reserved and unknown, so both fail closed. A new type
> requires an explicit ratification"

Enforcement, by symbol rather than by line number — the line numbers cited in
v1 (`:337`, `:345`, `:421-424`) had already rotted:

| Enforcement | Symbol | Effect |
| --- | --- | --- |
| unknown types refused | `message_type::is_known`, consulted at the head of `CanonicalMessageTypePolicyV1::permits` | anything outside the registry fails closed |
| role restriction | the `SenderRoleV1::Solver` arm of `CanonicalMessageTypePolicyV1::permits` | pre-amendment, a Solver could emit only `QUOTE` |
| no injection point | the `MessageTypePolicy` trait's single production implementor | no configuration hook and no caller choice of policy |

A DSC1 signing message is not `RFQ`, `QUOTE`, `ACCEPTANCE` or `SELECTION`.
**No admissible (role, message_type) pair exists for it.**

## 3. What was refused, and why it matters here

**Manufacturing envelopes.** Emitting a parallel set of signed envelopes
purely so the Relay would have something to lose was considered and refused:
it would have made the evidence a statement about fabricated traffic.

**Labelling DSC1 messages as `QUOTE`.** This would have closed both rows
without any ratification. It was refused because the envelope would assert
that the message is something it is not, and every downstream authorization
decision would rest on that false declaration.

## 4. What the type does and does not carry

**Does not:** carry economic authority; cause the Relay to decode the payload;
displace the Contracts session store as the sole adjudicator of the message;
alter values `0x0001-0x0004` or the roles permitted to emit them.

**Does:** carry one canonical DSC1 signing message between the two route
participants, opaque to the Relay, with the byte-identity guard at the
compositor's `carry` call site ensuring a transport can never become a second
adjudicator.

## 5. The evidence this rests on

Five settled laboratory routes executed under this value **before**
ratification, each recorded in `F7_CONTINUATION_LEDGER.md`: relay process loss
(row 38, four consecutive settlements) and relay database loss (row 39), the
latter reconstructing a destroyed Relay database from participant-retained
envelopes through the authenticated recovery path.

That the rows ran before ratification is the irregularity §0 discloses, not a
merit of the evidence.

## 6. What happens after signature — step 0 is not optional

**0. Record this amendment as D-029 in section 12.1 of the Foundation
   Document**, in the D-019 format (Problem / Decision / …), carrying the
   §1 text VERBATIM, and issue v0.19 with the SUPERSEDED banner on v0.18.
   **D-019's decision text is left byte-identical**; it receives only a
   non-normative cross-reference outside the decision block, naming D-029.

   Until this exists, the normative text still says `0x0005..0xffff =
   RESERVED/UNKNOWN` (v0.18 line 1712) while the suite asserts otherwise.
   By the P.2 authority hierarchy a ratification lives in §12.1 and it is
   from there that a norm mirror transcribes.

1. Rewrite `ratified_permits` transcribing from **D-029** in v0.19 §12.1 —
   not from the implementation, not from this document, and not from D-019,
   whose text no longer states the mapping in force — citing D-029 and the
   section in its doc comment.
2. Independent third-party check of the pair (§12.1 text, rewritten
   function), line by line. Not the executor who derived the original.
3. Re-run the full gate over the resulting source.

## 7. If the answer is no

Four edits revert, not two as v1 claimed:

1. the registry value in `message_type`;
2. the role clause in `CanonicalMessageTypePolicyV1::permits`;
3. `t05`'s reserved-value probe and registry-size assertion;
4. `ratified_permits`'s Initiator and Solver arms.

The two Relay-loss rows return to `NOT_IMPLEMENTED` for a normative reason,
and the acceptance record states that the laboratory built the transport,
proved it settles, and did not receive authority to keep the value.

## Ratification

> Operator signature over this file (minisign), date in the trusted comment.
