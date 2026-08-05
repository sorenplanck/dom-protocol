# Gate G1b — vault, budgets, and rollback resistance

Status: **NOT APPROVED**. This checklist controls G1b only. Documentation or
an implementation candidate does not constitute executed closure evidence. No
numeric budget value is selected by this gate.

- [ ] The `NonceVaultV1` trait is defined by `dom-adaptor` without a Wallet dependency.
- [ ] A transactional durable implementation is located in Wallet V3.
- [ ] Nonce reservation is durable before any session material is exposed.
- [ ] Nonce consumption is durable and irreversible across success, abort, crash, and retry.
- [ ] The global per-key budget is measured, ratified, and enforced.
- [ ] The secondary per-counterparty budget is measured, ratified, and enforced.
- [ ] The concurrent-session limit is measured, ratified, and enforced.
- [ ] The rolling-window limit is measured, ratified, and enforced.
- [ ] Aborts consume budget and never refund it.
- [ ] The chained append-only journal validates during reopen.
- [ ] The monotonic anchor is independent from backups and restorable state.
- [ ] The remote witness is the portable baseline with no silent local fallback.
- [ ] Signed receipts are verified and persisted before material is exposed.
- [ ] Idempotent retry is proved for reservation, transition, and receipt recovery.
- [ ] Crash recovery is proved at every durable boundary.
- [ ] Rollback, fork, and divergence are detected without resurrection.
- [ ] Restore cannot resurrect a consumed nonce, session, or budget unit.
- [ ] Restore on another device begins in `RESTORE_QUARANTINED`.
- [ ] Pseudonymous key/identity rotation and epoch closure are specified and tested.
- [ ] Windows, Linux, and macOS execute the persistence, crash, and restore matrix.
- [ ] A self-hosted witness mode is delivered as a product requirement.
- [ ] The witness receives only the pseudonymous chain, monotonic update, and minimum receipt data.
- [ ] The witness receives no identity, contract, value, address, purpose, or transaction hash.
- [ ] Residual timing and pseudonymous update-chain leakage is measured and documented.
- [ ] Adaptor sessions block exposure while required connectivity or receipts are unavailable.
- [ ] Ordinary transactions are proved not to consult budgets, anchors, or the witness.

Closing G1b does not close G1a. Production requires both gates to be formally
approved.

## Implementation evidence versus gate evidence

| Area | Ratified contract | Integrated implementation | Remaining executed evidence |
|---|---|---|---|
| Dependency direction and trait | ADR-P1-001 and the canonical `NonceVaultV1` interface | DOM contract integrated; Wallet conformance in a separate worktree | cross-repository harness and independent review |
| Transactional store and journal | NAR-002 and Wallet boundary documents | Wallet candidate exists | complete process-death and durability matrix |
| Budgets | semantics frozen; numeric values intentionally absent | caller-supplied validated policy candidate | measurement and ratified production values |
| Witness and receipts | ADR-SNV-001, ADR-SNV-002, and NAR-002 | client/service candidate exists | endpoint, recovery, privacy, and platform evidence |
| Restore and quarantine | fail-closed behavior ratified | Wallet candidate exists | rollback, remote-ahead, divergence, and restore matrix |
| Ordinary Wallet isolation | boundary ratified | implementation claims isolation | static graph and runtime zero-initialization evidence |

No box is checked merely because code or a focused unit test exists. Each box
requires exact commands, exit codes, artifact hashes, platform identity, and an
independent review where applicable.
