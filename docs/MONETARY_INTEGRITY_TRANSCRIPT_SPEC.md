# DOM Monetary Integrity Transcript Specification

Status: Phase 1 specification
Change class: Documentation-only
Scope: Public monetary audit transcript, no private data

## 1. Purpose

This document defines the preliminary public transcript format for DOM monetary
integrity verification. The transcript is a deterministic, aggregate,
canonical-chain summary that external auditors can compare across independent
replay implementations.

This specification does not alter consensus, validation, RandomX, difficulty,
block format, serialization, node behavior, wallet behavior, RPC, explorer
behavior, or metrics.

## 2. Privacy Boundary

The transcript MUST include only aggregate canonical-chain monetary fields. It
MUST NOT include:

- addresses
- individual balances
- wallet balance
- wallet metadata
- sender identifiers
- receiver identifiers
- transaction graph data
- private keys
- seeds
- recovery phrases
- user data

The transcript is not a wallet report. Wallet state is never a monetary source
of truth for this transcript.

## 3. Transcript Fields

The public transcript MUST contain exactly these top-level fields in this
preliminary schema:

```json
{
  "network": "testnet",
  "genesis_hash": "hex-lower-32-byte-hash",
  "chain_tip_hash": "hex-lower-32-byte-hash",
  "chain_height": 0,
  "max_supply_noms": 3299999976900000,
  "cumulative_scheduled_subsidy_noms": 3300000000,
  "cumulative_claimed_coinbase_noms": 3300000000,
  "cumulative_non_coinbase_fees_noms": 0,
  "remaining_scheduled_subsidy_noms": 3299996676900000,
  "coinbase_outputs_seen": 1,
  "regular_outputs_seen": 0,
  "inputs_seen": 0,
  "live_utxo_count": 1,
  "live_coinbase_utxo_count": 1,
  "monetary_integrity_status": "valid",
  "transcript_hash": "hex-lower-32-byte-hash"
}
```

Field definitions:

- `network`: canonical network label for the replayed chain.
- `genesis_hash`: lowercase hex encoding of the canonical genesis hash.
- `chain_tip_hash`: lowercase hex encoding of the replayed canonical tip hash.
- `chain_height`: canonical tip height.
- `max_supply_noms`: `MAX_SUPPLY_NOMS`.
- `cumulative_scheduled_subsidy_noms`: checked sum of
  `block_reward(height).noms()` over canonical blocks included in the replay.
- `cumulative_claimed_coinbase_noms`: checked sum of each canonical
  `CoinbaseKernel.explicit_value`.
- `cumulative_non_coinbase_fees_noms`: checked sum of all non-coinbase kernel
  fees in replayed canonical blocks.
- `remaining_scheduled_subsidy_noms`: checked subtraction
  `MAX_SUPPLY_NOMS - cumulative_scheduled_subsidy_noms`.
- `coinbase_outputs_seen`: number of canonical coinbase outputs observed.
- `regular_outputs_seen`: number of non-coinbase outputs observed.
- `inputs_seen`: number of non-coinbase transaction inputs observed.
- `live_utxo_count`: final replayed live UTXO count.
- `live_coinbase_utxo_count`: final replayed live UTXO count where
  `is_coinbase == true`.
- `monetary_integrity_status`: `valid` only when all replay checks pass;
  otherwise a verifier MUST fail closed and SHOULD emit no authoritative
  transcript.
- `transcript_hash`: deterministic hash over the canonical transcript payload
  excluding this field.

## 4. Canonical JSON Rules

The canonical JSON transcript MUST use:

- UTF-8 encoding
- one JSON object at the top level
- exactly the fields listed in Section 3
- field order exactly as listed in Section 3
- lowercase hexadecimal hash strings without `0x`
- unsigned base-10 integers for numeric fields
- no floating-point numbers
- no insignificant whitespace in the hash preimage
- no locale-dependent formatting
- no map iteration order as an implicit ordering source

The hash preimage is the canonical JSON byte string with `transcript_hash`
omitted.

## 5. Hashing Rule

The preliminary transcript hash is:

```text
transcript_hash = BLAKE2b-256(
    "DOM_MONETARY_INTEGRITY_TRANSCRIPT_V1" || canonical_json_without_transcript_hash
)
```

`canonical_json_without_transcript_hash` MUST contain all Section 3 fields
except `transcript_hash`, in Section 3 order. The domain string is ASCII and is
included exactly as shown.

## 6. Deterministic Ordering

Any implementation that derives the transcript from intermediate collections
MUST order those collections deterministically before hashing or counting when
order can affect output.

Required deterministic order:

- canonical blocks by ascending height
- block contents in consensus serialization order
- UTXO summary material by commitment byte order if a digest is later added
- no iteration over unordered maps without explicit sorting

## 7. Failure Rules

A transcript implementation MUST fail closed on:

- overflow
- underflow
- missing block
- duplicate block
- height discontinuity
- parent hash discontinuity
- invalid canonical decode
- ambiguous canonical tip
- mismatched expected coinbase value
- impossible UTXO transition
- non-deterministic ordering requirement

Failure output MUST NOT be labeled `valid`.

## 8. Relationship to Replay Procedure

The transcript is the output format. The source procedure for deriving it is
defined in `docs/MONETARY_SUPPLY_REPLAY_PROCEDURE.md`.

## 9. Relationship to RFC-0015

RFC-0015 defines the monetary integrity layer. This document defines the public
transcript schema used by that layer. It is intentionally observational and does
not create new consensus semantics.
