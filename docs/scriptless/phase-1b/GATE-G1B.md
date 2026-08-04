# Gate G1b — vault, budgets, and rollback resistance

Status: **NOT APPROVED**. This checklist controls G1b only. Documentation or a
contract interface does not prove a production implementation. No numeric
budget value is selected here.

- [x] The Nonce Vault trait is defined in `dom-adaptor` without a Wallet V3 dependency.
- [ ] A transactional persistent implementation is integrated in Wallet V3.
- [x] Nonce reservation is durable before any session material is exposed.
- [ ] Nonce consumption is durable and irreversible across success, abort, crash, and retry.
- [ ] A measured and frozen global per-key budget is enforced.
- [ ] A measured and frozen secondary counterparty budget is enforced.
- [ ] A measured and frozen concurrent-session limit is enforced.
- [ ] A measured and frozen rolling-window limit is enforced.
- [x] Aborts consume budget and never refund it.
- [x] A chained append-only journal is validated at reopen.
- [ ] A monotonic anchor independent of backups is deployed.
- [x] The remote witness is the portable baseline, with no silent local-file fallback.
- [x] Signed receipts are validated and durable before material export.
- [x] Reservation, anchor advancement, and receipt retry are proven idempotent.
- [ ] Crash recovery is proven at every durable boundary.
- [x] Rollback, fork, and divergence are detected without resurrection.
- [x] Restore cannot resurrect consumed nonce, session, or budget state.
- [x] Restore on another device starts in `RESTORE_QUARANTINED`.
- [x] Pseudonymous key rotation and epoch closure are specified and tested.
- [ ] Persistence, crash, and restore matrices pass on Windows, Linux, and macOS.
- [x] A self-hosted witness mode is delivered as a product requirement.
- [x] The witness receives only a pseudonymous chain, monotonic updates, and minimal receipt data.
- [x] The witness receives no identity, contract, value, address, purpose, or transaction hash.
- [ ] Residual pseudonymous update timing and sequence leakage is documented and tested.
- [x] Adaptor sessions block export while connectivity or a receipt is unavailable.
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

## Ratified implementation evidence — 2026-08-04

The checked implementation items above are supported by the isolated Wallet
branch commits `d048b6799ec3c7318b5af4fa12a885071d911c20` through
`114efd4e73ec30898d025afcda7d12d8e6b80c05`, plus the ratified lifecycle and
measurement-harness commits recorded in the Wallet result report. In
particular, the evidence includes:

- exact NAR-002 codecs and signed request/receipt processing;
- the approved Wallet production sealer with canonical associated data;
- a TLS 1.3-only self-hosted service adapter with exact bounded endpoints;
- opaque implementation-owned permits for commitment, reveal, and partial
  signature export;
- durable spent-permit replay of byte-identical public artifacts;
- lifetime session and reservation tombstones preserved across successor
  epochs without resetting the complete budget ledger;
- signed restore-head comparison for current, remote-ahead, and divergent
  states; and
- Linux fail-closed tests for truncated journal, missing receipt, pending
  request, staging file, missing tombstone, and mutated spent permit.

G1b remains **NOT APPROVED**. The complete process-death and storage-fault
matrix at every write, file sync, directory sync, rename, witness, receipt,
authorization, export, and tombstone cut point has not executed. Numeric
production budget defaults remain deliberately unfrozen. Windows and macOS
have not executed, residual timing/sequence privacy measurements remain open,
the canonical DOM trait and Wallet implementation have not been conformance-
integrated against one published revision, and the complete ordinary-Wallet
runtime operation matrix has not executed.
