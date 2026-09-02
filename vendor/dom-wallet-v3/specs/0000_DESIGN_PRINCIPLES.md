# DOM Wallet V3 Design Principles

**Status:** REVIEW
**Owner:** Soren Planck

## Scope, authority, and review boundary

These principles govern every foundational specification. DOM consensus and DOM cryptography are authoritative; external wallet material supplies engineering strategies only. Canonical state, durable operations, ChainId binding, non-reuse, least privilege, and deterministic evidence are required across the specification set.

1. DOM protocol rules are sovereign.
2. Correct and useful DOM V1/V2 properties must be preserved.
3. Epic may provide engineering strategies, never copied implementation.
4. The wallet must have one canonical state model.
5. Every state transition must define preconditions, postconditions, invalid transitions, durable effects, and tests.
6. Logical operations must be atomically durable.
7. Every persistent operation must define crash and restart behavior.
8. Retry, rescan, restore, and replay must be idempotent.
9. Chain identity must use height and block hash, not height alone.
10. Reorganization is expected protocol behavior.
11. Secret creation, storage, use, backup, zeroization, and destruction must be explicit.
12. Restore and migration must never reuse nonces, blindings, or derivation positions.
13. Seed-only recovery and full-backup recovery must have separate guarantees.
14. Interfaces must follow least privilege.
15. Time, randomness, node responses, storage faults, crashes, and reorganizations must be controllable in tests.
16. No feature is complete without failure-path and adversarial validation.
17. Real funds require completed internal gates and independent security review.

## Review Blockers

* DEC-CRYPTO-ENVELOPE-BINDING
* DEC-ECON-BLOCK-WEIGHT
