# Bitcoin evidence V2 fuzzing

These standalone cargo-fuzz targets exercise only the production V2 Bitcoin
evidence APIs. They do not import the legacy evidence types or the F5 harness,
and no decoder falls back to the frozen V1 format.

`fuzz_bitcoin_evidence_decode` submits arbitrary bytes directly to the exact V2
decoder. It also mutates a constructor-produced canonical V2 container so the
fuzzer can reach bounded length fields, discriminants, full-block bytes,
confirmation headers, trailing-byte rejection, and canonical round trips
without relying on a stale corpus.

`fuzz_witness_parser` constructs a complete canonical Regtest block around a
bounded fuzz-generated witness, recomputes the SegWit commitment and transaction
Merkle root, mines the easy local headers, authenticates them through
`RegtestHeaderAuthorityV2`, and calls `verify_evidence_v2`. This keeps the full
block, mutation scan, 64-byte ambiguity check, exact witness commitment, txid,
wtxid, outpoint, and claim/refund witness-shape checks on the real V2 path.

Run bounded local campaigns from this directory with a cargo-fuzz-compatible
nightly toolchain:

```text
cargo fuzz run fuzz_bitcoin_evidence_decode -- -max_total_time=60
cargo fuzz run fuzz_witness_parser -- -max_len=2048 -max_total_time=60
```

A bounded campaign is evidence only for that platform, toolchain, and duration;
it does not replace the deterministic V2 vectors or full package tests.
