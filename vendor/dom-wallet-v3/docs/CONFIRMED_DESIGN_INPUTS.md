# Confirmed Design Inputs

## DOM findings that must influence V3

### DOM-W2-SYNC-001 — canonical-tip freshness shortcut

**Verdict:** `CONFIRMED` in the comparative study.

The DOM Wallet V2 synchronization shortcut persists a tip hash but does not always compare that hash before treating the local wallet state as current. A same-height reorganization, or a canonical view that moves to a lower height, can therefore require reconciliation even when the normal height-only shortcut would skip it.

DOM Wallet V3 must:

1. identify a canonical cursor with at least `(height, block_hash)`;
2. compare both height and hash before skipping synchronization;
3. treat an unknown or changed hash as requiring reconciliation;
4. support canonical-height regression without manual repair;
5. define rollback before cursor advancement;
6. make reconciliation idempotent;
7. survive interruption at every rollback and replay boundary;
8. test same-height reorganization, lower-height canonical view, repeated reconciliation, restart, and partial failure.

## Validated DOM properties to preserve

- Argon2id-based password hardening where currently validated;
- HKDF-based domain separation where currently validated;
- authenticated encryption and chain-bound associated data;
- atomic encrypted-envelope writing;
- chain ID in wallet state and V2 backups;
- separate derivation domains;
- complete V2 backup capability;
- retained output records and canonical reconciliation;
- DOM-native slate and transaction formats;
- corruption and property-oriented tests already proven useful.

Each property must still be revalidated against the V3 specifications. Presence in V1 or V2 does not authorize blind migration.

## Epic hazards that V3 must avoid

- weak seed-password parameters;
- accepting malformed or corrupted nonce encodings;
- insufficient validation of change cardinality;
- splitting one logical operation between a database batch and an external transaction file;
- hard-coded passwords or API secrets in distributed examples.

These items are design warnings. Epic source code and formats remain outside the DOM Wallet V3 implementation.
