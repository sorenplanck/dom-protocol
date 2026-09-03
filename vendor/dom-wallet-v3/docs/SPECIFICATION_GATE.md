# Specification Gate

**Current gate:** Foundation and specification.

No functional wallet implementation may begin until the foundational specifications reach an accepted state.

## Required accepted specifications

1. Threat model.
2. Canonical wallet state model.
3. Transaction lifecycle.
4. Storage atomicity and crash recovery.
5. Chain-source and synchronization contract.
6. Reorganization and rollback behavior.
7. Key derivation and secret handling.
8. Backup and recovery.
9. DOM economic rules.
10. API and transport security.
11. Migration from DOM Wallet V2.
12. Testing and assurance.

## Required content for each specification

- protected properties;
- terminology;
- authoritative DOM sources;
- invariants;
- valid and invalid behavior;
- state or data model;
- persistence boundaries;
- crash and restart behavior;
- reorganization behavior where applicable;
- security considerations;
- compatibility and migration impact;
- required tests;
- acceptance criteria;
- explicitly resolved decisions.

## Implementation gate

The first production crate may be introduced only after:

- no critical design ambiguity remains;
- the relevant specifications are accepted;
- crate boundaries follow approved dependency direction;
- tests are defined before implementation;
- the implementation plan preserves DOM sovereignty;
- reference strategies are mapped by property rather than by source structure.

## Safety boundary

Specification completion does not authorize mainnet, real funds, or production use. Those require later implementation, verification, integration, and independent-security-review gates.
