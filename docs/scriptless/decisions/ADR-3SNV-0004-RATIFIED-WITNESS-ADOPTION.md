# ADR-3SNV-0004 — Ratified witness protocol adoption

Status: **ACCEPTED**  
Date: 2026-08-04

## Context

The detached Minisign signature over `ADR-SNV-001-witness-and-aad.en.md` was
verified with release key ID `74197A95CA309CF0`. The authenticated source is
tracked by coordinator commit `6062f9adb6ddd1812c41b2fb66b9ec69a249f324`;
its content SHA-256 is
`3939df85814e8c2b1fad8ea6484492887000b38917c3b23e47d5d505311270c2`.
It supersedes the protocol-input blocker recorded by ADR-3SNV-0003.

The same ratification set authenticates NAR-001, which freezes the canonical
`PurposeV1` discriminants.

## Decision

The storage-independent contract uses exactly one closed purpose registry:

- `0x01 = Refund`;
- `0x02 = ClaimAdaptor`;
- `0x03 = Funding`;
- `0x04 = Sponsor`, codec-recognized and rejected by strict V1 policy.

The Wallet witness implementation must use the protocol bytes, DOM tagged hash,
DOM Schnorr signatures, privacy exclusions, and fail-closed behavior frozen by
ADR-SNV-001. There is no local-file production witness fallback.

## Incomplete normative input

ADR-SNV-001 requires `record_kind_u8` to come from a closed local vault record
registry, but it assigns no byte values to that registry. Consequently, the
123-byte production Vault AAD and transition-commitment preimage cannot be
constructed by production code without inventing bytes. This part remains
**BLOCKED** until a ratified assignment names every allowed record kind and its
byte.

## Consequences

The witness wire protocol can be implemented and tested independently. Vault
sealing may reuse the existing Wallet boundary only after the missing record
kind registry is assigned. No placeholder, enum-order discriminant, or default
is permitted.

## Compatibility and risks

This decision adds no consensus or existing wire format. The primary remaining
risk is accidental creation of a second purpose or record-kind authority during
cross-branch integration; exhaustive conversion and signed-source verification
are required.
