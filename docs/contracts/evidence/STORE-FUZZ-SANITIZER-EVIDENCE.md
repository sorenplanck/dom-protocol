# Store Parser Fuzz and Sanitizer Evidence

Date: 2026-08-05

Platform: Linux x86_64, kernel 7.0.0-28-generic

Source baseline: `39380dc283efd5c60fc91279b20f52b7e41b1b78`

Status: **HISTORICAL — BOUND TO A SUPERSEDED BASELINE**

The campaigns recorded below ran against the source baseline named above, a DOM
Protocol revision earlier than the currently pinned
`6f2b230ebbec390040dbf0bff110efaf4bb0f101`, and a two-target fuzz package. They
describe that baseline only. The renewal gate defined at the end of this file
governs the current candidate.

Original status line: bounded local evidence campaign; not a claim of
exhaustive fuzzing

## Toolchain

- `rustc 1.98.0-nightly (f46ec5218 2026-06-30)`
- LLVM 22.1.8
- `cargo-fuzz 0.13.2`
- libFuzzer with AddressSanitizer, sanitizer coverage, stack-depth coverage,
  debug assertions, and one code-generation unit

## Targets

`canonical_records` exercises every pre-existing structural Store decoder and
the authenticated `SessionClaimV1`, `AttemptRecordV1`, `ExposureRecordV1`, and
`TombstoneV1` decoders. It also submits arbitrary input as a prospective first
entry to `MinimalJournalV1::verify_next`.

`canonical_registries` exercises the closed one-byte and two-byte Store
registries with arbitrary input.

## Executed campaigns

The evidence root was outside the repository and is represented below as
`$EVIDENCE_ROOT`. Corpus and crash artifacts were not committed.

### Authenticated canonical records

```text
cargo +nightly fuzz run canonical_records "$EVIDENCE_ROOT/corpus/canonical_records" -- \
  -max_total_time=120 \
  -seed=1745309113 \
  -artifact_prefix="$EVIDENCE_ROOT/artifacts/canonical_records/" \
  -rss_limit_mb=4096
```

Result:

- build exit code: `0`;
- campaign exit code: `0`;
- elapsed campaign time: 121 seconds;
- executions: 5,108,022;
- final coverage counters: 1,074;
- final feature counters: 1,549;
- final corpus reported by libFuzzer: 608 inputs, approximately 105 KiB;
- persisted corpus after exit: 607 files, 107,837 bytes;
- relative corpus-manifest SHA-256:
  `fcdbfe194292c88b3334ef76ee8e2a8a2093fbcbe6a102c52537ef5ae8260587`;
- maximum resident memory reported by libFuzzer: 451 MiB;
- crash artifacts: 0.

The instrumented binary SHA-256 was
`4f707d554e0f293b73a321611a39bcef9e3c6aacb44843127e6618b785f0ddb6`.

### Closed canonical registries

The instrumented target was first built with `cargo fuzz`. The subsequent
Cargo launcher waited on a shared package-cache lock before starting the
campaign and was interrupted with exit code `130`; no fuzz execution from that
launcher is counted. The already-built, identically instrumented binary was
then run directly:

```text
canonical_registries \
  -max_total_time=60 \
  -seed=3119186405 \
  -artifact_prefix="$EVIDENCE_ROOT/artifacts/canonical_registries/" \
  -rss_limit_mb=4096 \
  "$EVIDENCE_ROOT/corpus/canonical_registries"
```

Result:

- build exit code: `0`;
- direct campaign exit code: `0`;
- elapsed campaign time: 61 seconds;
- executions: 18,763,237;
- final coverage counters: 14;
- final feature counters: 15;
- final in-memory corpus: one 1-byte input;
- persisted corpus after exit: empty;
- relative empty-corpus manifest SHA-256:
  `abcfa6a9d4df344d1781bc2560b5e4cdcae08b39ed303063535e7e1e926a304a`;
- maximum resident memory reported by libFuzzer: 618 MiB;
- crash artifacts: 0.

The instrumented binary SHA-256 was
`eaba858682ccfc0e1152bcd0f54681b25ae879c7521a6e5b7cb5e45cf4339fb4`.

## Adjudication boundary

These bounded campaigns provide executed Linux ASan/libFuzzer evidence for
the integrated parser surface. They do not establish complete fuzz coverage,
do not replace process-death tests, and do not count as Windows or macOS
execution. Any later change to the authenticated codecs or dependency graph
requires rebuilding and rerunning the affected targets.

## Current-candidate renewal gate

The historical campaign above predates the final authenticated journal,
backup, restore, and storage-envelope parser surface. It remains historical
evidence and is not relabeled as current-HEAD execution.

`.github/workflows/phase1-linux-fuzz-evidence.yml` renews the bounded campaign
on every `phase1-evidence` and `main` candidate. It uses the fixed
`nightly-2026-07-01` toolchain, `cargo-fuzz 0.13.2`, AddressSanitizer, fixed
seeds, and 100,000 executions for each current target:

- `canonical_records`;
- `canonical_registries`;
- `canonical_storage_envelopes`; and
- `journal_recovery`.

The workflow has read-only repository permission, persists no checkout
credential, uploads no artifact, and fails if a campaign rewrites either
lockfile. Its check must pass on the final candidate before the fuzz/sanitizer
row can be adjudicated as current.

### Coverage against the NAR-DC-P1-004 §20 enumeration

§20 enumerates eleven surfaces that require persistent fuzz targets. The four
targets are not four of eleven: each bundles several decoders, and together
they exercise ten of the eleven.

| §20 surface | Exercised by |
| --- | --- |
| budget policy | `BudgetPolicyV1::from_bytes` in `canonical_records` |
| budget charge | `BudgetChargeV1::from_bytes` in `canonical_records` and `journal_recovery` |
| permit retirement | `PermitRetirementV1::from_bytes` in `canonical_records` and `journal_recovery` |
| both extended journal kinds | `JournalEntryKindV1::try_from` over every byte in `canonical_registries`, plus `UnauthenticatedJournalEntryV1::parse_structural` |
| derivation-attempt wrapper | authenticated and structural parsers in `canonical_records` |
| path grammar | the ten `canonical_*` path functions in `canonical_records`, driven by successfully parsed records |
| journal recovery | `journal_recovery`, including deterministic replay of an authenticated prefix |
| secret envelope | `VaultObjectEnvelopeV1` in `canonical_storage_envelopes` |
| tombstone envelope | `TombstonePlaintextV1` in `canonical_storage_envelopes` |
| permit lookup | `permit_lookup_id_v1` in `journal_recovery` |

The eleventh surface, the four closed request types, is covered outside this
repository and cannot be covered inside it. Those types are deliberately
non-constructible outside `dom-adaptor` — §20 itself requires proof that an
application caller cannot construct a fresh, resume, derivation, or
later-stage request — so reaching them requires an in-crate entry point.
`dom-adaptor` now provides one, `fuzz_closed_request_types_v1`, selected only
by `cfg(fuzzing)` and absent from production feature resolution, driven by the
`closed_request_types` target and following the pattern of that crate's
NAR-006 runtime-binding harness.

Its reachability was measured rather than assumed, because a harness that
bounces off its first consistency check would exercise only the guards: at
least 32 of 64 probe seeds reach the reservation-binding constructor, so the
fresh, resume and derivation paths are genuinely entered. Campaign execution
for that target is adjudicated with G1A in the DOM Protocol repository.

With that harness in place the §20 enumeration is complete. Executed campaign
evidence on the final candidate commits remains a separate obligation for both
repositories.
