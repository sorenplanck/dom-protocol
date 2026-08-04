# Gate G1b — vault, budgets, and rollback resistance

Status: **NOT APPROVED**. This checklist controls G1b only. Documentation or a
contract interface does not prove a production implementation. No numeric
budget value is selected here.

- [x] The Nonce Vault trait is defined in `dom-adaptor` without a Wallet V3 dependency.
- [ ] A transactional persistent implementation is integrated in Wallet V3.
- [ ] Nonce reservation is durable before any session material is exposed.
- [ ] Nonce consumption is durable and irreversible across success, abort, crash, and retry.
- [ ] A measured and frozen global per-key budget is enforced.
- [ ] A measured and frozen secondary counterparty budget is enforced.
- [ ] A measured and frozen concurrent-session limit is enforced.
- [ ] A measured and frozen rolling-window limit is enforced.
- [ ] Aborts consume budget and never refund it.
- [ ] A chained append-only journal is validated at reopen.
- [ ] A monotonic anchor independent of backups is deployed.
- [ ] The remote witness is the portable baseline, with no silent local-file fallback.
- [ ] Signed receipts are validated and durable before material export.
- [ ] Reservation, anchor advancement, and receipt retry are proven idempotent.
- [ ] Crash recovery is proven at every durable boundary.
- [ ] Rollback, fork, and divergence are detected without resurrection.
- [ ] Restore cannot resurrect consumed nonce, session, or budget state.
- [ ] Restore on another device starts in `RESTORE_QUARANTINED`.
- [ ] Pseudonymous key rotation and epoch closure are specified and tested.
- [ ] Persistence, crash, and restore matrices pass on Windows, Linux, and macOS.
- [ ] A self-hosted witness mode is delivered as a product requirement.
- [ ] The witness receives only a pseudonymous chain, monotonic updates, and minimal receipt data.
- [ ] The witness receives no identity, contract, value, address, purpose, or transaction hash.
- [ ] Residual pseudonymous update timing and sequence leakage is documented and tested.
- [ ] Adaptor sessions block export while connectivity or a receipt is unavailable.
- [ ] Ordinary transactions are proven not to consult budgets, anchors, or the witness.

Closing G1b does not close G1a. Production requires both gates.

## Current evidence

| Area | Input/contract | Implementation | Validation still required |
|---|---|---|---|
| Dependency direction and trait | `dom-adaptor::NonceVault`, `crates/dom-adaptor/src/nonce_vault.rs`, ADR-0002/0016 | storage-independent contract committed in `3f91b4a8e594db47c1d600ae6057958cb2e92a07` | Wallet adapter against a future authoritative DOM pin |
| Lifecycle and typed errors | reserve, commit, authorize, retry, consume, abort, restore state | contract only | persistent conformance suite |
| Transactional store and journal | model frozen | implemented only on the separate Wallet branch | cross-repository integration and platform matrix |
| Budgets | semantics frozen; values deliberately absent | parameterized only on the Wallet branch | measurement and formal freeze |
| Witness and receipts | semantic boundary defined | production wire/authentication remains blocked | signed-receipt interoperability and self-hosted service |
| Restore and quarantine | fail-closed behavior defined | separate Wallet branch has Linux tests | Windows/macOS and end-to-end rollback matrix |
| Ordinary-transaction isolation | architectural boundary defined | separate Wallet crate has no consumers | integration-time negative call-path proof |

## 2026-08-04 safety-boundary correction

ADR-3SNV-0002 and the contract API now require the irreversible nonce
tombstone to be durable before any public bytes are returned. Witness
authorization alone is non-exporting; exact retries are available only from a
consumed record. The semantic purpose projection recognizes Refund,
ClaimAdaptor, Funding, and Sponsor, but exposes no competing byte codec;
Sponsor is rejected by strict V1 execution policy.

This input correction closes no additional checklist item. Wallet persistence,
production encryption, the signed remote witness, the complete crash matrix,
independent review, and platform execution remain required. ADR-3SNV-0003
records why production witness implementation is blocked rather than
provisional.

The checked trait item is supported by a public compile-tested API and unit
tests. It does not imply that any persistence, witness, or budget item is closed.
