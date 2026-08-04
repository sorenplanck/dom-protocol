# G1a hash domains and purposes

Every tag uses `dom_crypto::blake2b_256_tagged`; no parallel BLAKE2b
instantiation is permitted. The authoritative backend is
`crates/dom-crypto/src/hash.rs::blake2b_256_tagged`: native unkeyed
`Blake2b<U32>`, no salt or personalization, over
`u16_le(tag_length) || tag_ascii || data`.

| Exact ASCII tag | Use | Source | Status |
|---|---|---|---|
| `DOM:kernel-sig:v1` | final DOM challenge | `TAG_KERNEL_SIG`, Master Specification | FROZEN |
| `DOM:kernel-msg:v1` | DOM kernel message | `TAG_KERNEL_MSG` | FROZEN |
| `DOM:scriptless-nonce-commit:v1` | public nonce commitment | Master Specification sections 3.4/6.6, ADR-0011 | FROZEN for the documented layout |
| `DOM:scriptless-sig-nonce-bind:v1` | collective binding | Master Specification sections 3.4/6.6, ADR-0011/0013 | FROZEN |
| `DOM:scriptless-transcript:v1` | cumulative session transcript | Master Specification sections 3.4/8.4 | tag/formula known; discriminants BLOCKED |

The mission-provided nonce KDF tag strings are recorded in ADR-0018 but are
not registered for production use while canonical context bytes remain
blocked. Candidate Bulletproof, transport, authentication, and session tags
are not promoted by this mission.

## Purposes v1

| Canonical name | Byte | Use | Source | Status |
|---|---:|---|---|---|
| `Refund` | `0x01` | refund signature | Master Specification Appendix E.6, ADR-0018 | FROZEN |
| `ClaimAdaptor` | `0x02` | claim adaptor pre-signature | Master Specification Appendix E.6, ADR-0018 | FROZEN |
| `Funding` | `0x03` | funding signature | Master Specification Appendix E.6, ADR-0018 | FROZEN |
| `Sponsor` | `0x04` | sponsor codec value | Master Specification Appendix E.6, ADR-0018 | FROZEN codec; strict execution rejected |

All other bytes are invalid. Purpose separation uses the mandatory byte inside
a versioned tagged preimage, not improvised per-purpose tags. Sponsor codec
acceptance does not authorize Sponsor signing.

## Blockers

- exact `DirectionV1` byte assignments;
- exact `PhaseV1` byte assignments;
- complete canonical context and therefore exact secret two-nonce derivation;
- independent vectors for the complete scheme.
