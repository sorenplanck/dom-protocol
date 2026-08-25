# Architecture Boundaries

## Application separation

DOM Contracts and the ordinary DOM Wallet are independent self-custodial
applications. They do not share seeds, private keys, key derivation domains,
keystores, databases, nonce inventories, signing shares, permits, contract
state, or simultaneous control of an output. A transfer between them is an
ordinary DOM transfer.

DOM Contracts contains no miner and no embedded full node. The chain adapter
communicates with externally operated DOM nodes through an explicit RPC
boundary. It must not reinterpret peer-to-peer messages or duplicate consensus.

## Dependency direction

The intended product path is:

```text
dom-scriptless-types
        ^
dom-scriptless-crypto
        ^
dom-scriptless-protocol
        ^
dom-scriptless-wallet
```

The store, transport, and chain adapter are bounded application services
composed only by the specialized wallet, with one recorded exception below.
Cryptography cannot access a clock, database, filesystem, RPC client, or
transport. The store cannot calculate a DOM kernel challenge. The chain adapter
cannot interpret network messages.

### Recorded exception: the phase registry

`dom-scriptless-protocol` depends on `dom-scriptless-store` for one type,
`SessionPhaseV1`. The §9.1 phase discriminants are part of already-signed
canonical bytes and are owned by the store, the crate that owns the canonical
Contracts codecs; redeclaring them in the protocol crate would create a second
source of truth for them. NAR-DC-P1-007 §3 is stated over that registry, so the
adjudicated topology is expressed with the canonical type rather than a copy.

The dependency is type-only. The protocol crate opens no store, performs no
filesystem or process operation, and holds no store capability. Because
`dom-scriptless-transport` depends on the protocol crate, the store — and on
Linux its retained-capability dependencies — are now in the transport crate's
dependency closure. That is a build-graph consequence of reusing the registry,
not permission: no transport code may construct, open, or reach a store, and
the durable runtime remains Linux-gated and reachable only through the
composition root.

`dom-adaptor` remains owned by DOM Core. This workspace consumes the reviewed
public revision through one immutable full-revision pin:

```text
repository: https://github.com/sorenplanck/dom-protocol
revision: 6f2b230ebbec390040dbf0bff110efaf4bb0f101
```

Local conformance may use an external untracked harness, but tracked manifests
and lockfiles must never contain absolute or sibling-worktree paths.

## Phase boundary

This repository may implement only the Phase 1B minimum nonce-safety boundary
during the current mission. Funding, claim, refund, complete contract creation,
user transport, witness, watchtower, UI, mining, and mainnet activation remain
outside scope.
