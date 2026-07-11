# Wallet-safe RPC

This document defines the additive wallet-safe RPC surface used by DOM Wallet
V3. It exposes the node's existing canonical chain state; it does not create a
wallet spending API, a new chain identity, or a finality mechanism.

All public read endpoints use the normal read rate limit, have the global 30
second timeout, and return JSON. Hashes are lowercase fixed-length hexadecimal:
32-byte hashes are 64 characters and compressed commitments/kernel excesses are
33 bytes (66 characters). Invalid fixed-length hexadecimal input returns 400.
Chain-lock contention returns retriable 503. Responses never contain local
paths, credentials, bearer tokens, wallet passwords, private keys, or internal
backtraces.

## Canonical authorities

`ChainState::network_magic` and `ChainState::genesis_hash` are the authorities
for the chain identity. `dom_consensus::derive_chain_id(network_magic,
genesis_hash)` is the exact value used by `ChainState` validation contexts and
by node transaction admission. The identity endpoint does not substitute a
network name, an expected configuration value, network magic, or a genesis hash
for `chain_id`.

The height index and canonical block body store are the authorities for block,
scan, and ancestry observations. The endpoint reads its related values under
one non-blocking chain lock. When that lock cannot be acquired it returns 503;
it never returns a zero, stale, configured-only, or partial identity snapshot.

## Endpoints

### `GET /chain/identity`

Returns one coherent canonical snapshot:

```json
{
  "rpc_api_version": 1,
  "protocol_version": 1,
  "network": "regtest",
  "network_magic": "52454754",
  "chain_id": "…64 lowercase hex chars…",
  "genesis_hash": "…64 lowercase hex chars…",
  "tip_height": 0,
  "tip_hash": "…64 lowercase hex chars…",
  "max_scan_range": 1000
}
```

`rpc_api_version` is a wallet-safe HTTP contract version and is separate from
the consensus `protocol_version`. `genesis_hash` is the canonical height-zero
hash when available in storage, otherwise the existing authoritative
`ChainState` genesis hash. No source/node identifier is included because this
endpoint has no need to expose one.

### `GET /chain/ancestry`

Required query fields are `ancestor_height`, `ancestor_hash`,
`descendant_height`, `descendant_hash`, and `max_steps`. Heights are unsigned
integers; hashes are exactly 32 bytes of lowercase hexadecimal. The maximum is
`MAX_ANCESTRY_STEPS = 256`, and ranges larger than either `max_steps` or that
constant are rejected before inspection. `descendant_height < ancestor_height`
is also rejected.

The response verifies the supplied hashes against the canonical height index:

```json
{
  "canonical": true,
  "ancestor_match": true,
  "descendant_match": true,
  "steps_checked": 12,
  "bounded": true,
  "observed_ancestor_hash": "…",
  "observed_descendant_hash": "…",
  "is_finality_proof": false
}
```

This is bounded source evidence only. It is not finality, a StableView witness,
or a wallet-specific consensus rule. Same-height requests are canonical only
when both supplied hashes match the canonical hash at that height.

### `GET /chain/scan?from=<height>&to=<height>`

Scan responses remain backward compatible and add `kernel_excesses` to each
block. It contains the canonical compressed excess commitments in consensus
block order: coinbase kernel first, followed by each transaction and that
transaction's kernel order. Wallet V3 uses this paginated evidence to confirm
kernels. The scan remains the paginated, block-context confirmation mechanism.

The result is capped at `MAX_SCAN_RANGE = 1000` heights. A missing or zero
canonical hash, missing body, malformed body, body/height/hash mismatch, or
inconsistent tip is a fail-closed RPC error, never an emitted zero hash or a
silently gapped scan. `from > to` is invalid.

`GET /block/{height}` and `GET /block/{hash}` remain available and return the
canonical header fields (`height`, `hash`, `prev_hash`, timestamp, target).

### `GET /kernel/{excess}`

DOM already persists a `kernel_excess -> block_hash` index, so this endpoint
uses that efficient index directly and does not introduce an O(chain length)
lookup path. `excess` must be a 33-byte compressed commitment (66 lowercase
hexadecimal characters). A found response contains `found`, `excess`, and
`block_hash`; an unknown kernel returns 404 with `found: false`.

### `POST /tx/submit`

Submission is unchanged: it accepts `tx_hex` and returns `accepted`, `relayed`,
`tx_hash`, `warning`, and `error` as before. Admission remains the ordinary node
mempool admission path. Wallet V3 must not treat an accepted-but-not-relayed
transaction as durable propagation. `/wallet/spend` is explicitly outside the
Wallet V3 compatibility contract.

## Wallet V3 flow

1. Read `/chain/identity` and retain the canonical `chain_id` with its tip.
2. Page `/chain/scan` within the advertised range; require each block hash and
   compare kernel excesses with the wallet's transaction kernels.
3. Use `/chain/ancestry` only as bounded evidence when reconciling two observed
   canonical points. Do not label it finality.
4. Submit transaction bytes through `/tx/submit`; use `relayed` and `warning`
   for retry policy, without sending secrets or wallet contexts.
