# `ratified_permits` — rewritten by transcription, for independent checking

**Not applied to the tree.** This is the proposed text. Per the operator's
order §4, it may only be applied after D-029 exists in §12.1 of v0.19, and
only after an independent third party has checked it line by line against
that section. The executor who derived the original mirror from the
implementation must not be the checker.

## Provenance of every line below

Transcribed from `DOM-Interop-Foundation-Document-v0.19.md` §12.1, decision
**D-029**, `Decision:` block, "Resulting sender authorization mapping".

**Not** from `crates/relay/src/auth.rs`. **Not** from the amendment document.
**Not** from D-019, whose decision text is byte-identical to v0.18 and no
longer states the mapping in force — D-029 states the complete resulting
mapping precisely so there is one source. It is enumerated per role, so
transcription requires no inference.

## The normative text being transcribed

```text
Resulting sender authorization mapping:

Initiator: RfqV1, AcceptanceV1, SelectionV1, RouteTransportV1
Solver:    QuoteV1, RouteTransportV1
Observer:  no type; the observer emits no messages
```

## Proposed function

```rust
/// The ratified mapping, written out independently of the
/// implementation so the test cannot agree with a bug by construction.
///
/// Transcribed from the Foundation Document v0.19 section 12.1, decision
/// D-029, "Resulting sender authorization mapping". D-029 amends D-019 in
/// one respect — it admits RouteTransportV1 for the two roles that sign
/// DSC1 rounds — and states the complete resulting mapping in its own text.
/// Values 0x0001-0x0004 and their roles are unchanged.
///
/// This function must never be derived from `crates/relay/src/auth.rs`.
/// If the normative text and this function disagree, the normative text
/// is right and the implementation is the defect — that is the entire
/// purpose of writing it out twice.
fn ratified_permits(role: SenderRoleV1, kind: u16) -> bool {
    match role {
        // D-029: Initiator: RfqV1, AcceptanceV1, SelectionV1, RouteTransportV1
        SenderRoleV1::Initiator => {
            kind == message_type::RFQ
                || kind == message_type::ACCEPTANCE
                || kind == message_type::SELECTION
                || kind == message_type::ROUTE_TRANSPORT
        }
        // D-029: Solver: QuoteV1, RouteTransportV1
        SenderRoleV1::Solver => {
            kind == message_type::QUOTE || kind == message_type::ROUTE_TRANSPORT
        }
        // D-029: Observer: no type; the observer emits no messages
        SenderRoleV1::Observer => false,
    }
}
```

## Checklist for the independent checker

Each line of the mapping, against §12.1 and nothing else:

- [ ] Initiator arm lists exactly four kinds: RFQ, ACCEPTANCE, SELECTION,
      ROUTE_TRANSPORT — no more, no fewer
- [ ] Solver arm lists exactly two: QUOTE, ROUTE_TRANSPORT
- [ ] Observer arm returns `false` unconditionally
- [ ] No arm references `CanonicalMessageTypePolicyV1` or any symbol from
      `auth.rs` other than the `message_type` constants
- [ ] The `message_type::*` constants used resolve to the values §12.1
      enumerates: RFQ=0x0001, QUOTE=0x0002, ACCEPTANCE=0x0003,
      SELECTION=0x0004, ROUTE_TRANSPORT=0x0005
- [ ] §12.1 of v0.19 carries D-029 (if it does not, stop: there is nothing
      to transcribe from and the mirror cannot be written)
- [ ] D-019's decision text in v0.19 is byte-identical to v0.18, and its only
      addition is the non-normative cross-reference outside the decision block

## What this does not fix

The mirror is one function checked by one pair of eyes. It has no structural
guarantee of independence — nothing in the build prevents a future editor from
copying `auth.rs` into it again, exactly as happened. **A durable control would
be a check that the mirror's provenance comment names a §12.1 decision and
that the two texts are compared mechanically.** That is not proposed here
because it is out of the scope of the operator's order, and it is recorded so
the gap is not mistaken for closed.
