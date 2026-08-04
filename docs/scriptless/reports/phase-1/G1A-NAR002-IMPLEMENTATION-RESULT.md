# G1a NAR-002 implementation result

Status: **G1a NOT APPROVED — IMPLEMENTATION READY FOR INDEPENDENT COMPARISON**

Date: 2026-08-04

## Result

The signed NAR-002 omnibus closure was imported byte-identically and its
independently solvable G1a assignments were implemented. This work does not
approve G1a, integrate G1b, or authorize production use.

## Ratified input

- NAR-002 SHA-256: `b726c2e576833f843d0065a1e823e649ab9e7e28fd9cfedb0e6e06e6b1be87f5`
- detached signature SHA-256: `fd1f1155e48190913e0fae10770afcdac5bf01e4bc410a663327fce3881c64c2`
- Minisign result: valid under key ID `74197A95CA309CF0`
- trusted timestamp: `1785878139`
- coordinator provenance commit: `04fb4c86ce6107d41c97094af0c33021eda3a019`

## Implemented assignments

- authoritative chain ID wrapper over `dom_consensus::derive_chain_id`;
- test/fuzz-only synthetic chain ID constructor absent from default features;
- exact `DOM:scriptless-participant:v1` participant mapping;
- strict protocol-roster ordering and one-to-one identity/signing-key mapping;
- `ContractKindV1::WitnessOrTimeout = 0x0001`;
- OS-CSPRNG session ID generation with exact NAR-002 framing;
- authoritative `DOMSCTT1` template projection in `dom-consensus`;
- exact template and unchanged kernel-message digest adapters;
- transcript initialization, session-message digest, and update functions with
  NAR-002 names and framing, including the exact update tag
  `DOM:scriptless-transcript:v1`;
- canonical signing-roster ordering in collective binding;
- exact closed exposure-kind registry and 252-byte exposure permit;
- exact outbound digest framing and permit digest;
- distinct exact 65-byte cryptographic core and 162-byte session-bound adaptor
  pre-signature;
- session-bound ClaimAdaptor validation; and
- persistent fuzz parsing for the new closed registries, core pre-signature,
  context, permit record, and OS-randomized nonce derivation.

## Independent-audit corrections

Review of the first NAR-002 implementation commit found four safety-relevant
API issues and one exact-tag error. They were corrected without rewriting
history:

1. the transcript update tag was corrected to the exact signed NAR-002 value
   and protected by a literal independent-body test;
2. public permit parsing now returns validation only and cannot materialize an
   authorization capability;
3. commitment, reveal, and partial signature each require a distinct matching
   one-shot permit, and public export APIs remain crate-sealed pending G1b;
4. the production KDF owns OS CSPRNG input; deterministic auxiliary input is
   available only through the non-default `test-helpers` feature;
5. the authoritative nonce pair is opaque and its only partial-sign operation
   consumes the pair, removing the shared-reference double-sign path;
6. secret `k256::Scalar` temporaries in public-key derivation, signing,
   adaptation, and extraction are guarded by `Zeroizing` RAII; and
7. session generation rejects zero participant/session IDs and requires an
   injected storage-owned permanent uniqueness registry before returning a
   usable identifier.

The crate-sealed authorization code is intentionally not a production G1b
implementation. It becomes reachable only through deliberate integration with
the durable Wallet vault and witness boundary.

The existing production paths retain all three purpose equations: ClaimAdaptor
uses the aggregate nonce plus adaptor point, while Funding and Refund use the
untweaked aggregate nonce. All final signatures are checked by the unchanged
DOM verifier.

## Explicitly open requirements

- Agent 2 independent output commit and byte-by-byte intermediate comparison;
- independent constant-time and zeroization review;
- durable G1b issuance of separate commitment, reveal, and partial permits;
- consume-before-export and irreversible tombstone conformance;
- long-duration fuzz and repository-approved sanitizer evidence for the new
  parsers;
- Windows and macOS execution; and
- combined G1a/G1b integration validation.

No independent output was inspected while preparing this branch.

## Focused evidence

| Command | Result |
|---|---|
| `cargo test -p dom-adaptor --locked` | PASS: 28 tests, including all eight SCAD0 fixtures |
| `cargo test -p dom-consensus scriptless_template_projection --locked` | PASS: authoritative projection test |
| `cargo check -p dom-adaptor --locked` | PASS |
| `sha256sum --check docs/scriptless/source-guides/normative/MANIFEST.sha256` | PASS |
| Minisign verification of NAR-001, NAR-002, and KAT V2 | PASS |
| `cargo +nightly fuzz check --fuzz-dir crates/dom-adaptor/fuzz` | PASS: all persistent targets compile with ASan instrumentation |
| `cargo +nightly fuzz run nonce_derivation --fuzz-dir crates/dom-adaptor/fuzz -- -max_total_time=10 -print_final_stats=1` | PASS: 147,167 executions, zero crashes, peak RSS 114 MiB |

The complete focused validation commands and final commit IDs are appended
after the final validation run.

Correction commits:

- `1bb46ce` — `fix(scriptless): use ratified transcript update tag`
- `1cd4a20` — `fix(scriptless): seal nonce derivation and exposure lifecycle`
- `f4d35b9` — `test(scriptless): fuzz sealed nonce boundaries`

## Safety confirmation

- No official repository or other worktree was modified.
- No DL2P material was imported.
- No consensus, existing wire, persisted-block, genesis, network-magic, or PoW
  behavior changed.
- No push, merge, rebase, release, publication, or production activation was
  performed.
- No real funds were used or authorized.
