# DOM Protocol — Fuzzing Guide

Doc 9 — fuzzing infrastructure built with cargo-fuzz (libFuzzer backend).

## Setup

Requires nightly Rust toolchain:

    rustup toolchain install nightly
    cargo install cargo-fuzz

## Targets

13 fuzz targets across 4 critical crates. All targets exercise untrusted
input boundaries — bytes received from the network, peer-supplied
payloads, attacker-controlled cryptographic material.

### dom-serialization (3 targets)
- fuzz_block_deserialize — Block::from_bytes
- fuzz_transaction_deserialize — Transaction::from_bytes
- fuzz_block_header_deserialize — BlockHeader::from_bytes

### dom-wire (6 targets)
- fuzz_wire_message — WireMessage::from_bytes (P2P framing entry)
- fuzz_hello_payload — HelloPayload::from_bytes (peer handshake)
- fuzz_headers_payload — HeadersPayload::from_bytes (IBD)
- fuzz_getheaders_payload — GetHeadersPayload::from_bytes (IBD locators)
- fuzz_getblockdata_payload — GetBlockDataPayload::from_bytes (body requests)
- fuzz_block_payload — BlockPayload::from_bytes (block relay)

### dom-consensus (1 target)
- fuzz_validate_block — end-to-end deserialize + validate_block

### dom-crypto (3 targets)
- fuzz_pedersen_commitment — Commitment::from_compressed_bytes
- fuzz_schnorr_signature_parse — SchnorrSignature::from_bytes
- fuzz_schnorr_verify — full schnorr_verify with arbitrary inputs

## Running

From each crate directory:

    cd crates/<crate-name>
    cargo +nightly fuzz run <target-name> -- -max_total_time=60

Example:

    cd crates/dom-serialization
    cargo +nightly fuzz run fuzz_block_deserialize -- -max_total_time=300

## Invariants

Every fuzz target enforces the same global invariant:

**Arbitrary input must NEVER panic.**

Acceptable outcomes:
- Ok(T) — input happened to parse as valid (rare for random bytes)
- Err(DomError) — input rejected with a typed error

Unacceptable outcomes:
- Panic (unwrap, expect, assert, arithmetic overflow in debug)
- Infinite loop
- Process abort

Any panic discovered by libFuzzer is saved under fuzz/artifacts/ and
must be triaged as a parser vulnerability (potential remote DoS vector).

## Initial Smoke Results (2026-05-23, WSL)

All 11 targets ran for ~25 seconds each. Aggregate ~55M random inputs
exercised. Zero panics, zero hangs, zero crashes.

| Target | Runs in 25s |
| --- | --- |
| fuzz_block_deserialize | 2,810,406 |
| fuzz_transaction_deserialize | 989,304 |
| fuzz_block_header_deserialize | 5,689,201 |
| fuzz_wire_message | 8,801,923 |
| fuzz_hello_payload | 13,312,810 |
| fuzz_headers_payload | 6,620,720 |
| fuzz_block_payload | 14,568,202 |
| fuzz_validate_block | 1,434,745 |
| fuzz_pedersen_commitment | 3,656,135 |
| fuzz_schnorr_signature_parse | 8,017,644 |
| fuzz_schnorr_verify | 118,508 |

Smoke runs are short. Real coverage requires hour-long runs per target,
ideally in CI. See follow-up work for CI integration.

## Triage Workflow

When libFuzzer finds a crash:

1. Crash input is saved to crates/<crate>/fuzz/artifacts/<target>/<id>.
2. Reproduce locally: cargo +nightly fuzz run <target> <artifact-path>.
3. File the crash as a DOM-FUZZ-<n> issue with severity assessment.
4. Add the artifact bytes to crates/<crate>/fuzz/corpus/<target>/ as a
   regression seed after the fix.
5. Re-run the target post-fix to confirm the crash is gone.

## Why these targets

Selected per audit-derived priority: every byte that enters DOM from an
untrusted source (network peer, RPC client, on-disk corrupted state)
passes through at least one of these parsers. A panic at any of these
points becomes a remote DoS vector.

Not yet covered (future work):
- Noise codec frame parser (NoiseCodec::decode)
- Bulletproof deserialization
- Wallet seed phrase / BIP-32 derivation parsers
- LMDB binary format edge cases (data corruption)
