# SettlementTermsV1 conformance corpus (terms-v1)

Frozen A3 vectors (F2 spec §15). Each `.hex` file is one lowercase-hex
encoding; each `.hash` file is `BLAKE2b-256("DOM-INTEROP/SETTLEMENT-TERMS/V1\0"
|| bytes)`. The Rust suite (`tests/terms_vectors.rs`) and the independent
Python verifier (`scripts/verify_terms_vectors.py`, no kaystra-core import)
must both accept this corpus. Regeneration is intentional only:
`cargo test -p kaystra-core regenerate_vectors -- --ignored`.

## Wire layout (version 1, all integers big-endian)

| Offset | Size | Field |
|---|---|---|
| 0 | 8 | magic `DOMITRM1` |
| 8 | 2 | version = 1 |
| 10 | 32 | settlement_id |
| 42 | 32 | session_id |
| 74 | 32 | intent_hash |
| 106 | 32 | solver_id |
| 138 | 32 | roster[0] |
| 170 | 32 | roster[1] |
| 202 | 195 | dom_leg |
| 397 | 195 | counterparty_leg |
| 592 | 33 | adaptor_point_sec1 (0x02/0x03 prefix) |
| 625 | 16 | fee_limit.dom_max |
| 641 | 16 | fee_limit.counterparty_max |
| 657 | 1 | recovery.refund_before_funding (0x00/0x01) |
| 658 | 8 | recovery.evidence_retention_blocks |
| 666 | 1+0/32 | assurance_policy_hash (0x00 absent / 0x01 + 32 bytes) |
| … | 4 | policy_version |
| … | 4 | metadata_len (≤ 4096) |
| … | var | metadata |

Leg layout (195 bytes): role u8 | chain_id 32 | asset_id 32 | amount u128 |
beneficiary 32 | refund_to 32 | mechanism u8 | timelock tag u8 + value u64 |
min_confirmations u32 | max_reorg_depth u32 | adapter_profile_hash 32.

## Valid vectors

### valid-minimal (675 bytes) — expected: decodes, roundtrips, hash matches

Empty metadata, no assurance policy. Field values: settlement_id = `a1`×32,
session_id = `a2`×32, intent_hash = `a3`×32, solver_id = `a4`×32,
roster = [`b1`×32, `b2`×32]. DOM leg: chain `c1`×32, asset `c2`×32,
amount 1, beneficiary `b2`×32, refund_to `b1`×32, mechanism
DomAdaptor2of2 (0x01), deadline BlockHeight 100, finality (1, 1),
profile `c3`×32. Counterparty leg: chain `d1`×32, asset `d2`×32, amount 1,
beneficiary `b1`×32, refund_to `b2`×32, mechanism ConditionLock (0x02),
deadline TimestampSeconds 1700000000, finality (1, 2), profile `d3`×32.
Point 0x02 + `e1`×32; fees (0, 0); recovery (true, 0); assurance absent;
policy_version 1.

### valid-full (749 bytes) — expected: decodes, roundtrips, hash matches

Same as valid-minimal except: settlement_id `a5`×32, dom amount u128::MAX,
dom mechanism SchnorrAdaptor (0x03), dom deadline BtcTime512s 144, dom
finality (6, 100), counterparty mechanism HashlockFallback (0x04), point
prefix 0x03, fees (u128::MAX, 1), recovery (false, u64::MAX), assurance
present `f1`×32, policy_version u32::MAX, metadata =
`"DOM-INTEROP F2 terms vector: full profile"` (41 bytes).

## Invalid vectors — every one MUST fail closed on decode

All are single-field mutations of valid-minimal:

| File | Mutation | Expected error |
|---|---|---|
| invalid-roster-equal | roster[1] := roster[0] | InvalidRoster |
| invalid-roster-unsorted | roster[0] ↔ roster[1] swapped | InvalidRoster |
| invalid-version | version := 2 | InvalidVersion |
| invalid-enum-tag | dom_leg role byte (offset 202) := 0x7f | UnknownTag |
| invalid-trailing-byte | one 0x00 appended | TrailingBytes |
| invalid-zero-amount | dom_leg amount := 0 | ZeroAmount |
| invalid-point-prefix | point prefix (offset 592) := 0x04 | NonCanonicalPoint |
| invalid-oversize-metadata | metadata_len := 4097, 4097 bytes appended | BoundsExceeded |
