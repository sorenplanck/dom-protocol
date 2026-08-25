# ADR-A12 — Dispatch of the `CounterpartyAdapter` async trait

```text
Status:      RATIFIED (operator decision, 2026-08-10, recorded in chat
             and in D-011 of the Foundation Document)
Question:    A12 (open since F0) — must the async CounterpartyAdapter
             trait be dyn-compatible?
Decision:    NO. Native `async fn` in trait + static dispatch, with an
             enum wrapper as the designated mechanism if uniform
             handling of multiple adapters ever becomes necessary.
             `#[async_trait]` (boxed futures) is rejected.
```

## Context

`counterparty_api::CounterpartyAdapter` uses `async fn` in trait (stable
since Rust 1.75), which makes the trait not dyn-compatible: `dyn
CounterpartyAdapter` cannot exist. A12 asked whether the project would
ever need `dyn` — and if so, whether to switch to `#[async_trait]`
(which boxes every future) or wrap adapters in an enum.

## Evidence gathered through F2

The question can now be answered from executed code instead of
speculation:

1. **Static dispatch carried two full phases.** The F1 chain suites and
   the entire F2 engine are generic over their ports
   (`SettlementEngine<S: SettlementStore, C: ChainSourceV1, K:
   EffectSinkV1>`). At no point did any component need to hold
   heterogeneous adapters behind one pointer: one settlement binds ONE
   DOM leg and ONE counterparty leg, both known at construction.
2. **The topology fixes the shape.** A settlement's legs are frozen in
   `SettlementTermsV1` (chain_id, mechanism, adapter_profile_hash)
   before any engine exists. Adapter selection is a creation-time
   decision, not a runtime polymorphism problem.
3. **The cost of `#[async_trait]` buys nothing here.** Boxing every
   `prepare_lock`/`observe`/`verify_evidence` future adds an allocation
   and a vtable indirection per call on the hot observation path, in
   exchange for a capability (runtime substitution of adapters behind
   one pointer) that no phase up to F2 needed and no phase through F5
   is expected to need.

## Decision

- The trait keeps native `async fn`; dyn-compatibility is NOT a
  requirement of this API and is not promised.
- If F3/F5 introduce a component that must hold "one of several adapter
  kinds" uniformly (e.g. a registry keyed by chain), the designated
  mechanism is a closed **enum wrapper** (`enum AnyAdapter { Evm(...),
  Btc(...), ... }`) implementing the trait by delegation. The enum is
  closed by design: the set of supported chains is a ratified decision
  (§4.3), never an open plugin surface — which also keeps I10
  capability negotiation exhaustive.
- `#[async_trait]` is rejected for this trait. Revisiting that requires
  a new decision superseding D-011.

## Consequences

- `#[allow(async_fn_in_trait)]` remains, now documented as a decision
  rather than a deferral; the trait doc no longer marks A12 open.
- Adapter authors implement plain `async fn` with no extra crate or
  boxing.
- No code change is required in F1/F2 components: everything already
  complies.
