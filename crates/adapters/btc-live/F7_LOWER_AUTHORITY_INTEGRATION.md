# F7 Bitcoin lower-authority integration

This note fixes the exact boundary left after the bounded 2026-08-14 static
audit. It is not an authorization to weaken the existing typed blockers in
`f7-runner/src/live_bitcoin.rs`.

## FundingPlanAuthority

`btc-live` now persists an immutable authenticated `funding-summary.v1` before
Refund. `PreparedBitcoinFundingV1::funding_summary()` and the equivalent Armed
getter expose the canonical plan digest, Prepared and summary digests, funding
txid/wtxid, contract outpoint/amount, requested fee rate, selected-input total,
all-output total, exact fee, vsize, and a unit-tagged `BitcoinRefundDelayV1`.
The selected-input total is obtained from exact `gettxout` values while the
inputs are unspent; all remaining facts are rederived on every reopen.

The remaining blocker is exactly
`F7LiveBitcoinBridgeBlockerV1::FundingPlanAuthorityUnavailable`. The current
route manifest retains only an untagged `u64` documented as an absolute
Bitcoin refund lock and an M.8 policy digest. BIP68 is a relative, unit-tagged
delay. No funding anchor exists before the refund must be signed, so an
absolute value cannot be projected safely at this boundary.

The minimum authoritative input is one of:

1. a versioned manifest field containing `BitcoinRefundDelayV1` directly; or
2. the complete retained `M8TimingPolicyV1`, authenticated against the
   manifest M.8 digest and terms hash, whose route-selected Bitcoin offset is
   exactly `TimelockOffsetV1::BtcBlocks` or `BtcTime512s`.

The runner constructor must reject DOM offsets, zero delays, unknown units,
digest mismatch, or any attempt to infer a relative delay from the current
absolute `u64`. It then constructs the refund leaf with exactly
`delay.sequence()`, builds `BitcoinPrebroadcastPlanV1`, and binds
`plan.canonical_digest()`. After wallet selection it may mint the cost
authority only when every summary binding matches and
`summary.actual_fee_sat() <= manifest.economics().bitcoin_max_fee_sat()`.

## RefundSigningAuthority

The lower API is now:

```rust
pub trait RetainedBitcoinRefundSignerV1 {
    fn refund_key_xonly(&self) -> [u8; 32];
    fn sign_refund(
        self,
        request: BitcoinRefundSigningRequestV1,
    ) -> Result<BitcoinRefundSignatureV1, LiveBitcoinError>;
}

BitcoinPrebroadcastStoreV1::arm_refund_with_signer(prepared, signer)
    -> Result<ArmedBitcoinFundingV1, LiveBitcoinError>;
```

`btc-live` constructs the unsigned refund and exact BIP341 script-spend
sighash. The consuming request contains public bindings and the sighash, not a
raw transaction. The signer returns only a 64-byte default-sighash signature;
`btc-live` verifies it, creates the witness, and durably arms Refund internally.

The remaining blocker is exactly
`F7LiveBitcoinBridgeBlockerV1::RefundSigningAuthorityUnavailable`. The audited
`btc-vault` owns MuSig/adaptor claim nonce material, not the BIP340 refund key.
The official Wallet authorities own DOM payout outputs/excesses and expose no
Bitcoin refund key or signer. The minimum addition is one retained production
implementation of the trait whose owner binding includes route binding, plan
digest, Prepared digest, funding-summary digest, and refund x-only key. A lab
constant or a caller supplied raw secret is not an implementation.

The runner bridge must accept that concrete signer and call
`arm_refund_with_signer`; it must not recreate the current
`Zeroizing<Vec<u8>>` signed-refund capability.

## FundingLifecycleBridge

`ArmedBitcoinFundingV1::external_funding_custody()` now returns
`BitcoinExternalFundingCustodyV1`. This payload-free value commits to route,
plan, Prepared, summary and Refund digests; funding/refund txids; contract
outpoint/amount; actual fee; and vsize. It is stable across restart and across
the sole `btc-live` submit. `matches_broadcast_receipt` binds the later
`BitcoinFundingBroadcastReceiptV1` to the retained funding txid.

The remaining blocker is exactly
`F7LiveBitcoinBridgeBlockerV1::FundingLifecycleHandoffUnavailable`. The current
runner `record_funding_signed` requires `ExactChainArtifactV1` and inserts its
raw bytes into `durable_outbox`; `dispatch_ready_exact` can then invoke a second
Bitcoin broadcaster. The final verifier also requires that raw-payload effect
to have been leased and completed. `btc-live` cannot truthfully manufacture
that runner state.

The minimum runner/Store extension is:

```rust
record_external_bitcoin_funding_armed(
    settlement_id,
    custody: BitcoinExternalFundingCustodyV1,
    now_unix_ms,
) -> F7BitcoinFundingLifecycleHandoffV1;

record_external_bitcoin_funding_submitted(
    handoff,
    custody: BitcoinExternalFundingCustodyV1,
    receipt: BitcoinFundingBroadcastReceiptV1,
    dom_receipt,
    now_unix_ms,
) -> F7RouteStatusV1;
```

The first transition inserts an ExternalCustody Bitcoin-funding effect whose
commitment is `custody.custody_digest()` and whose txid is
`custody.funding_txid()`. It stores no raw transaction and is excluded from
`ready_outbox`/`dispatch_ready_exact`. The handoff is non-constructible outside
that transition. Only after consuming it may the bridge call
`btc-live::broadcast_armed_funding`.

The second transition requires the same custody digest, requires
`custody.matches_broadcast_receipt(&receipt)`, and atomically marks the external
effect completed while advancing FundingSigned to FundingBroadcast. Replays
must accept only the byte-identical custody digest and txid. The outbox summary
and final verifier must distinguish RunnerPayload from ExternalCustody, require
the external effect to be Completed with one or more recorded attempts, and
bind its custody digest/txid to authenticated runner context. The dispatcher
must never lease or submit an ExternalCustody effect.

The adapter receipt is non-constructible outside `btc-live` because it carries
a private authority field. Existing public fields remain source-compatible;
new composition should prefer `transaction_id()` and `already_known()`.
