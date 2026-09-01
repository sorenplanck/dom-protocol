# Architecture

```text
DOM canonical claim
    │
    │ adapter-dom-real verifies final adaptor signature and t·G == T
    ▼
Kaystra durable RequestClaimConsumption outbox effect
    │
    ▼
XmrClaimToSpendSink
    ├─ verifies revealed t against the DLEQ-certified secp+ed claim
    ├─ loads encrypted local XMR share and private view key
    ├─ reconstructs the combined XMR spend scalar
    ├─ asks the authenticated GPL sidecar to construct one exact sweep
    ├─ parses and hashes the raw Monero transaction independently (MIT)
    ├─ persists exact raw bytes before deleting recovery secrets
    └─ broadcasts/retransmits exactly those bytes
          │
          ▼
XMR multi-RPC observer → spend evidence → Kaystra ClaimConfirmed
```

Kaystra stores only public evidence references. No scalar is inserted into its
state, event envelope or outbox payload.

## Setup admission ordering

`validate_lab_against_terms` must be followed by a durable
`SqliteClaimRegistry::reserve` before any `RefundArmed` event can expose the
funding effect. The registry is not a second state machine; it is a setup
anti-replay precondition.
