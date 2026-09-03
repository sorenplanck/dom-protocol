# DOM Wallet V3 API and Transport Security

**Status:** DRAFT
**Owner:** Soren Planck

## Purpose and scope

This specification defines capability-oriented API and transport boundaries for DOM Wallet V3. It governs authorization, request handling, redaction, delivery uncertainty, and adapter responsibilities. It does not define an Epic route, transport, authentication protocol, slate format, or node protocol.

## Authoritative sources and terminology

Authoritative inputs are Specifications 0000 through 0008, DOM Wire and RPC authority where applicable, DOM transaction and slate formats, and the DOM threat model. A **capability** is an explicitly authorized operation scope. A **request identifier** is a caller correlation value. An **idempotency key** binds one authenticated request fingerprint to its durable result. A **transport-neutral domain message** is opaque DOM-native participant material plus required identity, version, and replay bindings; it is not a transport envelope.

## Capabilities, trust boundaries, and assumptions

| Capability | Permitted authority | Prohibited authority |
|---|---|---|
| Read-only | Redacted state and provisional status | Unlock, selection, signing, backup export, administration |
| Receiving | Validated receive and replay-stable response | Spending, arbitrary state export, administration |
| Owner | Authorized lifecycle and account actions | Unscoped secret export or transport administration |
| Backup and recovery | Export, stage, restore, repair under confirmation | Spending unless separately authorized |
| Administration | Explicit configuration and capability management | Implicit remote exposure or unrestricted unlock |
| Node adapter | Bounded ChainSource and submission calls | Direct mutation of canonical state or local control |
| Transport adapter | Delivery of opaque messages and receipt evidence | Confirmation, signing, or capability escalation |

Callers, local process boundaries, node adapters, participant transports, secret stores, and support tooling are distinct trust boundaries. Source authentication does not establish canonical truth.

The API assumes an approved capability verifier and local secret store are available. No remote confidentiality or credential construction is assumed until the unresolved deployment policy is approved.

## State and data model

An authenticated request contains protocol version, WalletIdentity, ChainId, capability scope, request identifier, idempotency key where an effect is retriable, expiry, payload digest, and correlation identifier. A response contains the request identifier, redacted correlation identifier, typed result, retry class, and durable operation reference where present. Sessions carry scoped authority, issue and expiry evidence, WalletIdentity, ChainId, and explicit revocation or lock state.

## Invariants

1. Safe binding is local-only by default. Remote exposure requires an explicit administration action and a reviewed transport policy.
2. Every mutating request authenticates capability, ChainId, WalletIdentity, version, expiry, payload bounds, and replay binding before domain invocation.
3. Unlock authority is narrower than ownership, time- and capability-scoped, and never serialized into a response or log.
4. A request identifier is correlation only; idempotency uses the durable key plus authenticated request fingerprint.
5. Every parser enforces payload, nesting, collection, concurrency, work, rate, and timeout limits before allocation or deep decoding.
6. Domain messages bind version, ChainId, WalletIdentity where appropriate, participant role, phase, intent reference, expiry, and replay material before acceptance.
7. Transport delivery, ordering, duplication, delay, corruption, and receipt uncertainty are evidence only; adapters do not alter canonical state.

## Valid behavior

An endpoint MAY expose a transport-neutral message through an approved DOM-native adapter. It MUST negotiate only supported versions, use canonical parsing, reject unknown critical fields, apply rate and work limits, and return typed caller-correctable, retryable, denied, malformed, conflict, and RecoveryRequired errors. Error text MUST be redacted and MUST NOT distinguish secrets, passwords, or unverified ownership data.

Remote transport policy MUST explicitly select authentication and confidentiality suitable for the deployment. Where authoritative DOM Wire applies, its chain binding and version validation MUST be preserved. Where no DOM transport is authoritative, the deployment remains local-only until a reviewed policy selects the mechanism. TLS, proxying, or any named foreign transport is not assumed by this specification.

Examples MUST obtain credentials from an environment or approved secret store at runtime, use unmistakably non-secret sample values, and never embed passwords or API secrets. Support bundles include only redacted events and correlation identifiers.

## Invalid behavior

The API MUST reject an absent or expired scope, wrong ChainId or WalletIdentity, unsupported version, replay with different fingerprint, oversized or deeply nested payload, excess concurrent work, malformed canonical field, forbidden capability transition, or request past its expiry. It MUST NOT bind publicly by default, infer authorization from network location, grant unlock from read-only authority, log secrets, silently retry a non-idempotent external effect, or claim a delayed transport receipt is canonical confirmation.

## Persistence and atomicity

Mutating requests pass idempotency and capability evidence to the owning domain specification. The domain's 0004 durable unit records LocalIntent, DurableIntent, replay result, RecoveryEvent, and redacted AuditEvent as applicable. Adapter receipts and errors are persisted only through that unit. An API response is not proof of durability unless it carries the durable operation reference.

## Crash and restart behavior

On restart sessions are locked or revalidated according to their explicit policy; plaintext credentials and unlock authority are not restored. Durable idempotency records resolve repeated requests. A request whose external delivery may have happened is resumed through its DurableIntent and typed recovery, never by inventing a new request or transaction.

## Reorganization, concurrency, replay, and idempotency

Read-only replies MUST mark provisional state supplied during reconciliation. Reorganization is handled by 0006, not by an adapter. Concurrent mutations rely on expected Generation and return a conflict to losing callers. Duplicated or reordered messages use ReplayId and idempotency rules from 0003. Delayed or corrupted messages are rejected without lifecycle, ownership, confirmation, output, or reservation mutation; a bounded durable redacted audit or recovery uncertainty record MAY be created through its required DUW.

## Security, compatibility, and migration impact

Logs, metrics, traces, errors, and support bundles MUST redact secrets, private contexts, complete transaction links, and unnecessary ownership details. Compatibility negotiation is explicit and bounded; a peer cannot downgrade a security-relevant version. Migration interfaces are restricted to 0011 staging and require source provenance. Epic Owner and Foreign route names, Basic-auth behavior, API versions, file transport, Tor, Epicbox, Keybase, and related compatibility behavior are rejected.

## Required verification

| Test class | Required coverage |
|---|---|
| Unit tests | Capability matrix, scope expiry, chain and identity mismatch, parsing limits, redaction, and error taxonomy |
| Property tests | Replay stability, idempotency mapping, bounded parser work, and no capability escalation |
| Executable-model tests | Generated authorization, session, request, delivery-uncertainty, restart, and conflict commands |
| Integration tests | Local-safe binding, explicit remote policy, node and transport adapters, version negotiation, and redacted support bundle |
| Restart tests | Locked session, durable request replay, and uncertain delivery recovery |
| Reorganization tests | Provisional response handling and cursor-divergence gating before sensitive operation |
| Concurrency tests | Rate, work, request, and expected-Generation contention |
| Fault-injection tests | Authentication store, secret-store, timeout, adapter, and log sink failures |
| Fuzz targets | Canonical parsers, envelopes, nested collections, authorization tokens, headers, and malformed messages |

## Acceptance criteria for promotion from DRAFT to REVIEW

Promotion requires a reviewed credential and revocation construction, authorization matrix with tests, local and remote deployment policies, complete limit table, version-negotiation rules, and evidence that every mutating method reaches a durable domain contract. A successful request-response demonstration is insufficient.

## Dependencies and unresolved decisions

Dependencies are 0001, 0002, 0003, 0004, 0005, 0007, 0008, and 0012.

Credential format and revocation, remote transport policy, capability delegation, API version registry, concrete rate and work limits, and prolonged provisional-state presentation remain unresolved pending DOM and deployment evidence.

## Review Blockers

* DEC-API-DEPLOYMENT
