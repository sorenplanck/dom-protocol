# DOM↔XMR — ratification sheet

**Superseded by implementation.** When V6 was delivered, this sheet listed two
protocol decisions that stood between the XMR crates and a production leg. Both
have since been implemented in `sorenplanck/dom-protocol` on `mainnetswap`, and
the decisions themselves are recorded for signature in

```
docs/specifications/normative/NAR-DC-P1-008-monero-counterparty-leg-mechanism-and-chain-kind.en.md
```

which is the authoritative document. This file remains only to say what
changed, so a reader holding the V6 zip is not left with a stale map.

## What was open, and what was done

| Was | Now |
|---|---|
| `LockMechanism` had no member describing Monero, so the leg travelled under the `SchnorrAdaptor` laboratory alias | `CrossCurveSharedSpend = 0x05` is implemented, with the decoder arm and vector tests |
| The proposal asked for a `TERMS_VERSION` bump | Not bumped, and a test proves the frozen terms hashes did not move. An unknown tag already fails closed, so the bump bought nothing and would have rehashed every Bitcoin and EVM settlement |
| `validate_production_v1` returned `MechanismUnratified` unconditionally | A real gate. Both gates share one implementation and neither accepts the other's terms |
| `ChainKindV1` had no Monero variant, so admission refused an XMR leg whatever tag it carried | `ChainKindV1::Monero`, `ChainDeploymentV1::Monero`, `ClockKindV2::Monero`, the codec, and an admission rule pairing Monero with the ratified mechanism and a block-height deadline |
| The Monero genesis was called underivable and left unratified | Derived with `monero-oxide` from the upstream `GENESIS_TX`/`GENESIS_NONCE`, corroborated against the daemon's own height-0 checkpoints, and held to the derivation by test |

## What is still the operator's

- Signing `NAR-DC-P1-008`. Unsigned bytes grant no authority.
- The timing bounds and finality policy of each Monero chain profile. Those are
  safety-critical configuration, ratified per network.
- Whether the GPL sidecar may be operated against any particular network.

Monero mainnet remains unrepresentable: `MoneroNetworkV1` has no mainnet
variant, by the same rule that keeps Bitcoin mainnet and EVM chain id 1 out.
