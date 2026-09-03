# Node Configuration

Status: IMPLEMENTED_FOUNDATION

Node configuration is stored inside encrypted wallet state and is available to the desktop layer only through a redacted projection. A credential is represented by a backend-only reference, never a credential value. No configuration bypass disables network, chain-ID, or genesis-ID verification.

## Required fields

```text
endpoint_url: https://node.example.invalid/dom-rpc
expected_network: PRIVATE_TESTNET | PUBLIC_TESTNET | MAINNET
expected_chain_id: <32-byte authoritative value>
expected_genesis_id: <32-byte authoritative value>
source_identity: <configured responder identity>
api_compatibility_version: <positive version>
connect_timeout_ms: <positive bounded duration>
request_timeout_ms: <positive bounded duration>
poll_interval_ms: <positive bounded duration>
retry_ceiling: <positive bounded count>
max_backoff_ms: <duration no lower than poll interval>
stable_success_threshold: <positive count>
tls_required: true
credential_reference: <optional backend reference>
```

The current foundation permits a `https://` endpoint only when TLS is required. It does not hardcode a hostname, port, credential, chain ID, or genesis hash. The placeholder endpoint is deliberately invalid and is not a network default.

## Connection and probe behavior

Before scan data is accepted, the adapter must verify network, chain ID, genesis ID, API compatibility, source identity, and current tip height plus block hash. Authentication identifies a responder but does not prove canonicality. A wrong identity blocks synchronization. Transport, TLS, timeout, authentication, malformed-response, and compatibility failures are typed and redacted.

Reconnect uses a bounded exponential schedule with a stable-success threshold; one successful request does not immediately reset prior backoff. The live adapter checks `/health`, then `/chain/identity` (wallet-safe RPC and protocol version 1, lowercase fixed-width network magic, exact network, chain ID, genesis hash, nonzero coherent tip, and `max_scan_range` 1–1000) and cross-checks the tip with `/block/{height}`. Configuration alone is never identity evidence.

## ScanTarget policy

A scan uses `(target_height, target_block_hash, source_identity, scan_bounds, evidence_version)`. Every page is provisional. Before activation the adapter must prove the target hash remains canonical at its height, and, for a later tip, prove the target's ancestry within the configured bound. `GET /chain/ancestry` is bounded to 256 steps and is never finality evidence. Height alone, a changed/missing/unverifiable target hash, source change, inconsistent page, changed bounds, or exhausted bound fail closed and start reconciliation or full-rescan handling.

## Safe examples

Private-testnet, public-testnet, and mainnet use the same structure. Replace each placeholder only with an authoritative DOM deployment value:

```text
endpoint_url=https://PRIVATE_TESTNET_NODE.example.invalid/dom-rpc
expected_network=PRIVATE_TESTNET
expected_chain_id=AUTHORITATIVE_CHAIN_ID_REQUIRED
expected_genesis_id=AUTHORITATIVE_GENESIS_ID_REQUIRED
source_identity=CONFIGURED_SOURCE_IDENTITY
credential_reference=ENV:DOM_WALLET_NODE_CREDENTIAL
```

The environment may supply the referenced credential to a backend process. It must never be printed, copied to frontend state, or included in diagnostics.
