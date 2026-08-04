# ADR-3SNV-0001 — Nonce Vault contract shape

Status: **ACCEPTED** for the storage-independent DOM boundary. Production G1b
remains unapproved.

## Context

Phase 3-SNV requires the trait to belong to `dom-adaptor` while the durable
implementation belongs to Wallet V3. The witness receipt wire format and
operational budget values are not frozen.

## Evidence

- **NORMATIVE DOCUMENT:** Master Specification sections 5.5, 6.6, 8, 10, 18,
  and Appendix F define consume-before-export, monotonic nonce states, exact
  retries, durable tombstones, and fail-closed restore.
- **ENGINEERING ADR:** ADR-0002 and ADR-0016 fix the dependency direction;
  ADR-0003 and ADR-0006 through ADR-0008 require an independent witness and
  restrict online failure to adaptor sessions.
- **FROZEN TEST/IMPLEMENTATION EVIDENCE:**
  `crates/dom-adaptor/src/nonce_vault.rs` and its unit tests.

## Decision

`dom-adaptor` exposes opaque redacted identifiers, a closed purpose enum,
monotonic reservation states, byte-exact public exposure values, typed requests,
typed fail-closed errors, and a `NonceVault` trait with reserve, public-material
commit, witness authorization, retry, consume, abort, and restore-state methods.

The receipt is an associated type implementing a semantic `VaultReceipt`
interface. The contract does not choose receipt bytes, signatures, transport,
timeouts, retries, retention, or budget numbers.

## Alternatives considered

- Put the trait in Wallet V3: rejected because it inverts the required
  dependency direction.
- Put storage or transport in `dom-adaptor`: rejected because it couples pure
  protocol code to one wallet and one platform.
- Freeze an opaque receipt byte container as a protocol: rejected because the
  signed witness wire format remains blocked.
- Add numeric defaults: rejected because measurement and formal freeze are
  required first.

## Consequences

Wallet implementations can be developed independently and later adapted to one
authoritative contract. Exposure remains unavailable until a receipt type
verified by the Wallet has been persisted.

## Compatibility

The API is additive. It changes no consensus, wire, transaction serialization,
persisted block, genesis, network magic, or ordinary Wallet path.

## Risks

The concurrent G1a branch may introduce purpose or exposure types that should
replace local wrapper types during integration. The future Wallet adapter must
prove semantic equivalence and may require a deliberate API reconciliation.
