# Epic to DOM Adoption Matrix

This matrix governs properties and design strategies. It does not authorize source-code reuse.

| Reference strategy or property | DOM V3 decision | Required treatment |
|---|---|---|
| Small contracts between domain, storage, node access, lifecycle, and transport | `ADOPT_CONCEPTUALLY` | Define independent DOM-native traits and dependency direction. |
| Atomic persistence of input reservations, change, transaction records, and private context | `ADAPT_FOR_DOM` | Define one DOM durable unit of work and explicit crash points. |
| Private transaction context persisted before finalization | `ALREADY_PRESENT` | Preserve the DOM property and formalize its lifecycle and secret handling. |
| Canonical output reconciliation through a chain source | `ALREADY_PRESENT` | Preserve and strengthen with explicit canonical-view contracts. |
| Synchronization checkpoint containing height and block hash | `ADAPT_FOR_DOM` | Make `(height, block_hash)` the minimum canonical cursor identity. |
| Explicit transaction and output state machines | `ADOPT_CONCEPTUALLY` | Define DOM-specific states, transitions, invalid transitions, and recovery behavior. |
| Seed-only recovery through Epic rewind techniques | `REQUIRES_FORMAL_DESIGN` | Define recovery only from DOM derivation and consensus properties. |
| Chain-bound, versioned full backup | `ALREADY_PRESENT` | Preserve and strengthen the DOM V2 backup guarantees. |
| Owner and receiving privilege separation | `ADAPT_FOR_DOM` | Define DOM capability boundaries instead of inheriting Epic APIs. |
| Pluggable transaction transports | `REQUIRES_FORMAL_DESIGN` | Specify transport-neutral DOM contracts, replay protection, and limits. |
| Epic slate V2 and V3 compatibility | `REJECT_FOR_DOM` | Use only DOM transaction and slate formats. |
| Epic fee, weight, coinbase, maturity, kernel, commitment, and proof rules | `REJECT_FOR_DOM` | Use exclusively DOM consensus and economic rules. |
| Epic PBKDF2 seed protection | `REJECT_FOR_DOM` | Preserve the stronger DOM Argon2id, HKDF, and authenticated-encryption model where validated. |
| Epic Tor, Epicbox, and Keybase protocols | `REJECT_FOR_DOM` | Do not inherit project-specific transports automatically. |
| Database commit separated from an external transaction file | `REJECT_FOR_DOM` | Transaction state must not be split across non-atomic durability boundaries. |

## Decision requirement

Every adopted item must identify the protected property, the DOM-specific invariant, the independent implementation, and the tests that prove the property.
