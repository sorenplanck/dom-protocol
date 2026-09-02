# ADR-F7-LAB-RELAY-CARRIES-ROUTE-TRANSPORT

Status: LAB CANDIDATE — proposed, not ratified
Date: 2026-08-17
Scope: F7 laboratory only. No normative byte, bound or check is changed.

## Context

Two acceptance rows have stood at `NOT_IMPLEMENTED` since this laboratory
began: `RelayProcessLoss` and `RelayDatabaseLoss`. They appear six times in the
canonical matrix — rows 38 and 39 of each claim group and 117 and 118 of each
refund group.

The cause is precise and is not a missing implementation of the relay. The
relay bridge is complete: `F7LiveRelayBridgeV1` creates, opens and reattaches a
scenario-bound production database, derives the route id from the immutable
manifest, validates envelope headers against the frozen route, submits
idempotently, and already implements both fault boundaries —
`submit_with_process_loss_boundary` and `destroy_database_with_boundary` — plus
`authenticate_recovery` and `reconstruct` for the recovery path.

What does not exist is the **input**. Every relay entry point requires a real
`RelayEnvelopeV1`, and the route compositor produces none: DSC1 messages are
handed straight to the Contracts store by `accept_transport_message`
(`crates/dom-leg/src/f7_wallet.rs:1786`, `:1936`, `:1961`), and never travel
over a relay. `F7RelayRouteTransportV1::unavailable()` exists to name that
absence honestly.

## The refusal that still stands

A previous executor considered emitting a parallel set of signed envelopes
purely so the relay would have something to lose, and **refused**. That refusal
is correct and is restated here as binding: evidence manufactured for a test
proves nothing about the route, and a passing row built on it would be worth
less than an honest `NOT_IMPLEMENTED`.

This ADR does not overturn that refusal. It removes its premise. The envelopes
proposed here are not parallel traffic; they are the route's own DSC1 messages,
carried by the relay because the relay is their transport.

## Decision

Introduce an **injectable transport seam** in the compositor, following exactly
the precedent already set by the DSC1 fault controller: the plain public entries
delegate to a `*_with_transport` entry supplied with a direct implementation, so
**default behaviour is byte-for-byte unchanged** and production keeps handing
messages straight to the store.

```rust
/// Carries one canonical DSC1 transport message from sender to recipient.
///
/// The default implementation hands the exact bytes to the session store, which
/// is what production does today. The laboratory injects an implementation that
/// carries the same bytes through a real Relay.
pub trait F7DomDsc1TransportV1 {
    fn deliver(
        &mut self,
        purpose: F7DomDsc1PurposeV1,
        signed_bytes: &[u8],
        successor: &SessionSuccessorV1,
        failed: Option<&SessionSuccessorV1>,
    ) -> Result<TransportAcceptanceV1, F7WalletCompositorError>;
}
```

The laboratory implementation performs a genuine round trip:

1. the sender wraps the exact `signed_bytes` as the **opaque payload** of a
   `RelayEnvelopeV1` and signs the envelope digest with its roster key;
2. the envelope is submitted through `F7LiveRelayBridgeV1::submit_route_transport`
   and is durable in the relay database;
3. the recipient **reads the envelope back from the relay**, verifies header,
   sequence, transcript chaining and signature, and extracts the payload;
4. only then are those bytes handed to `accept_transport_message`.

Step 3 is what gives the relay-loss rows meaning. If the relay database is
destroyed between 2 and 4, the recipient genuinely cannot obtain the message,
and the route must recover through `authenticate_recovery` / `reconstruct` from
participant stores and public-chain sources. Losing the relay loses route
progress, which is precisely the property the two rows claim to test.

## Envelope field mapping

Every field is derived from material the route already owns. Nothing is
invented, and no field is filled with a placeholder.

| Field | Source |
| --- | --- |
| `network_id` | `manifest.chain_policy().dom_chain_id()` / `bitcoin_chain_id()`, by leg |
| `session_id` | `manifest.session_id()` |
| `route_id` | `F7LiveRelayBridgeV1::derive_route_id(manifest)` |
| `sender_id` / `recipient_id` | the route's two participants |
| `sender_role` | the participant's roster role |
| `sequence` | per-(session, sender) monotonic, from the durable round |
| `previous_transcript_hash` | the accepted predecessor's digest; zero for the first |
| `payload` | the exact canonical DSC1 bytes, opaque to the relay |
| `expiry`, `policy_version`, `roster_snapshot` | frozen route policy |
| `signature` | BIP340 over `envelope_digest`, by the participant's roster key |

The relay never decodes the payload. The store remains the sole adjudicator of
the DSC1 message, so no check moves from the store to the relay.

## Consequences

**Enabled.** Rows 38, 39 (claims) and 117, 118 (refunds) become executable. The
claims rows cost minutes; the refund rows carry the refund outcome's own
height-lock cost and are not made cheaper by this change.

**Unchanged.** Production behaviour, because the default transport is the
current direct handoff. Every one of the twenty-one already-settled routes would
produce identical durable state under the default implementation, and that is
the property to verify before any row is claimed.

**New failure surface, deliberately.** A route using the relay transport can now
fail for relay reasons. That is the point, and those failures must be
distinguishable from route failures — the transport returns typed errors and
never collapses a relay fault into a generic one. The observability defect
recorded in `F-20260817T000106Z`, where a stalled wallet, a not-ready node and a
progressing wallet were indistinguishable at the caller, is the mistake this
seam must not repeat.

## Verification

1. **Non-regression first.** Re-run one already-settled claims route under the
   relay transport and require the durable record to be identical on every
   observable the evidence package carries: revision 10, state tag 11, one
   `Claims` terminal, ten journal events, three outbox effects at `attempts = 1`.
   A single divergence blocks the rows.
2. **The relay actually carried it.** The relay database must hold one retained
   envelope per DSC1 message, and the recipient's acceptance must be shown to
   have consumed the envelope read back from the relay rather than a local copy.
3. **Then the fault rows.** 38 and 39 first, because they are claims routes and
   cost minutes; 117 and 118 only alongside the refund terminal.
4. The full local CI gate over the final source, its exit code being the verdict.

## The blocker is normative, not engineering — found 2026-08-17

**This section supersedes the framing above.** The premise that the only missing
piece is envelope production is wrong, and building the transport would not have
revealed it — the relay refuses the envelope before any of that matters.

`crates/relay/src/auth.rs` enforces a **closed** message-kind registry:

> "The CLOSED message-kind registry of Relay V1, RATIFIED by D-019 (operator
> decision, 2026-08-10). The values 1-4 are IMMUTABLE within V1; 0 is invalid
> and 5..=0xffff are reserved and unknown, so both fail closed. **A new type
> requires an explicit ratification**"

Two enforcement points make this binding:

| Point | Effect |
| --- | --- |
| `auth.rs:337` | `if !message_type::is_known(message_type)` — anything outside 0x0001..0x0004 is refused |
| `auth.rs:345` | `SenderRoleV1::Solver => message_type == message_type::QUOTE` — a solver may emit **only** `QUOTE` |
| `auth.rs:421-424` | "the production path instantiates the canonical policy … **no configuration hook, and no caller choice**" |

A DSC1 signing message is none of `RFQ`, `QUOTE`, `ACCEPTANCE` or `SELECTION`.
**There is no admissible (role, message_type) pair for it**, and the policy is
not injectable on the production path.

That leaves exactly three ways forward, and two of them are refused here:

1. **Label DSC1 messages as `QUOTE`.** Refused. It would make the envelope
   declare the message to be something it is not, and every downstream
   authorization decision would rest on that false declaration. This is the same
   class of dishonesty as manufacturing envelopes, arrived at from the other
   direction.
2. **Add a message type to the registry.** This is the correct technical answer
   and it is **not the laboratory's to make**. D-019 is a ratified operator
   decision and the code says in terms that a new type requires explicit
   ratification. Standing order 1 forbids filling a normative gap silently.
3. **Leave the rows `NOT_IMPLEMENTED`** with the cause stated precisely, which
   is what this ADR now does.

**Recommendation to the operator.** Ratify one additional Relay V1 message type
for route transport — a single reserved value from 0x0005 upward, admissible for
the roles that sign DSC1 rounds — and the remaining work becomes the mechanical
list below, roughly a day, with rows 38 and 39 executing in about an hour. Until
that decision exists, the transport cannot be built honestly, and the correct
state of the two relay rows is `NOT_IMPLEMENTED` for a **normative** reason
rather than an engineering one.

This is a better answer than the one this ADR opened with. The refusal to
manufacture envelopes was right; the diagnosis of why they could not exist was
incomplete.

## Implementation state, 2026-08-17

**Done and compiling.** The compositor seam exists. `carry` is a defaulted
method on `F7DomDsc1FaultControllerV1` — the trait the laboratory already
injects — so no new parameter is threaded through five layers. Its default is
the identity, and `persist_stage_messages` compares the returned bytes against
the sender's own and fails closed on any difference. `cargo check -p dom-leg
--features f7-wallet-compositor-evidence-only` passes. Production behaviour is unchanged: with
the default, the bytes handed to `accept_transport_message` are the same bytes
as before.

**Remaining, and it is mechanical.** `F7LiveDomDsc1FaultAdapterV1`
(`crates/f7-runner/src/live_executor.rs:1860`) must gain the relay and the
manifest, and override `carry`:

1. Add two fields: `relay: Option<&'a mut F7LiveRelayBridgeV1>` and
   `manifest: Option<&'a F7RouteEconomicsManifestV1>`, plus a
   `with_relay_transport(boundary, scenario, relay, manifest)` constructor. The
   existing `new` keeps both `None`, so every route that does not carry a relay
   fault behaves exactly as it does today.
2. Override `carry`. With `None`, return the input unchanged. With the relay
   present, build a `RelayEnvelopeV1` whose `payload` is the canonical DSC1
   bytes and whose header comes from the sources in the field-mapping table
   above, sign the `envelope_digest` with the participant's roster key, submit
   through `submit_route_transport`, and return the canonical bytes only after
   the ACK is durable. A failed submission must surface as a typed relay error,
   never as a generic one — that is the observability defect
   `F-20260817T000106Z` records and this seam must not repeat.
3. Construct the adapter with `with_relay_transport` at the two sites that build
   it — `live_executor.rs:616` for the Funding round and `live_economic.rs:860`
   for the Claim round — but **only** when the scenario carries
   `RelayProcessLoss` or `RelayDatabaseLoss`.
4. Build with `--features relay-fault-injection`, re-freeze the worker, repin
   `WORKER_SHA` in `run_coverage.sh`.

**A limit to state plainly rather than paper over.** The bridge exposes
submission and recovery but no read-back of a retained envelope. Until one is
added, step 2 makes the relay a **mandatory durable hop** — the route cannot
proceed until the message is durable in the relay, and destroying the relay
fails the route into its recovery path — but it does not yet prove the recipient
*obtained* the message from the relay rather than from memory. Both relay-loss
rows are genuinely exercised by the mandatory-hop form; the stronger claim
requires a read-back API and must not be made before it exists.

## Out of scope

Making the relay a normative transport for the protocol. This ADR is a
laboratory capability that lets two acceptance rows execute against real
components. Whether DSC1 messages *should* travel over a relay in production is
a normative question for the Foundation Document and its ratified decisions, and
standing order 1 forbids this laboratory from settling it.
