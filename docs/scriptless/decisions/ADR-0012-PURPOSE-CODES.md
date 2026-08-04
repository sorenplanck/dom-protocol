# ADR-0012 — Purpose codes and versioning

Status: **SUPERSEDED IN PART BY ADR-0018**. The byte assignments remain
accepted; ADR-0018 corrects Sponsor codec handling and the strict execution
policy.

## Context

Funding, claim-adaptor, refund, and sponsor flows require stable binary
discriminants. Master Specification Appendix E.6 provides an unambiguous V1
table.

## Evidence

- **NORMATIVE DOCUMENT:** Master Specification Appendix E.6 assigns
  `refund=1`, `claim_adaptor=2`, `funding=3`, and `sponsor=4`; sections 3.4 and
  6.6 bind the purpose into Scriptless transcripts.
- **MISSION DECISION:** the complete four-value codec registry is authoritative;
  strict Phase 1 execution supports Funding, ClaimAdaptor, and Refund while
  rejecting Sponsor until an authorized Sponsor flow exists.

## Decision

The byte assignments are `Refund=0x01`, `ClaimAdaptor=0x02`,
`Funding=0x03`, and `Sponsor=0x04`. All other bytes are invalid. The purpose
byte is mandatory in the defined preimages and provides logical separation
inside a versioned tag. Changing the table requires a new versioned type.

Sponsor is recognized by the codec but rejected by strict Phase 1 execution
policy. Codec recognition does not authorize a Sponsor flow.

## Erratum

Any earlier Phase 1 plan assigning `Funding=0x01`, calling `ClaimAdaptor`
merely `Claim`, or rejecting `Sponsor=0x04` as an unknown codec value is
incompatible with Appendix E.6 and is superseded.

## Alternatives considered

Strings, alphabetical order, three tags without a discriminant, and a fallback
variant were rejected because they do not match the authoritative table.

## Consequences

The V1 codec is closed over four exact bytes. Exhaustive matches will fail to
compile when a future source change adds a variant. Strict G1a entry points
must separately enforce Sponsor policy.

## Compatibility

This is a new versioned off-chain format. It does not change consensus or any
existing DOM wire format.

## Risks

The primary risk is confusing codec recognition with flow authorization or
using the generic name `Claim` instead of `ClaimAdaptor`.
