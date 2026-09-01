# Security model and gates

## Closed in code

- DLEQ uses one non-zero 252-bit integer in both groups.
- The secp claim is the exact DOM adaptor point `T`.
- The ed25519 claim is the remote Monero spend share.
- Profile hash commits chain, asset, amount, finality, destination, funding tx,
  both spend shares, combined spend key and DLEQ binding.
- Revealed `t` is checked against both public claims before use.
- Sidecar requests/responses are nonce-bound and HMAC authenticated.
- Sidecar raw transaction is independently parsed, canonicalized and hashed.
- Exact raw bytes are committed durably before secrets are deleted or broadcast.
- Identical replay is idempotent; divergent replay fails closed.
- Multi-node ties, duplicate node identities, future inclusion heights and
  conflicting block anchors fail closed.
- Economic terminals remain Kaystra's responsibility.

## Still open

- `sigma_fun`'s cross-curve extension is experimental and requires independent
  cryptographic audit.
- The live path must pass regtest/stagenet reorg, daemon-equivocation and
  kill-after-every-boundary tests.
- Kaystra V1 has no truthful mechanism variant for cross-curve shared spend.
  The V2 proposal is supplied but deliberately not auto-applied.
- No mainnet deployment is authorized by this artifact.

## DLEQ context and replay

The upstream Sigma proof authenticates equality of one 252-bit witness across
secp256k1 and ed25519. V6 does not claim that arbitrary settlement bytes were
injected into that library's Fiat-Shamir transcript. Instead, the complete
proof envelope is committed by the XMR profile hash in Kaystra terms, and
`xmr-claim-registry` atomically reserves each pair of public claims to exactly
one settlement before funding authorization. Reuse under another settlement
fails closed.
