# G1a NAR-002 implementation result

Status: **G1a NOT APPROVED — G1b AUTHORIZATION INTEGRATION BLOCKER**

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
implementation. Raw nonce derivation, public nonce derivation, and partial
signing are therefore quarantined behind the non-default `test-helpers`
feature in both `dom-crypto` and `dom-adaptor`. Default production feature
resolution cannot reach those APIs. The helper feature preserves deterministic
and OS-randomized evidence only; it is not a production authorization boundary
and must not be enabled in release feature resolution. Production use remains
blocked until deliberate integration with the durable Wallet vault and witness
boundary.

The existing production paths retain all three purpose equations: ClaimAdaptor
uses the aggregate nonce plus adaptor point, while Funding and Refund use the
untweaked aggregate nonce. All final signatures are checked by the unchanged
DOM verifier.

## Explicitly open requirements

- **Code/integration blocker:** the default build now fails closed by omitting
  all raw nonce-pair derivation, public-export, and partial-signing APIs. Rust
  has no friend-crate visibility, so merely exposing those operations from
  `dom-crypto` would let another production crate bypass G1b. The quarantined
  helper-only implementation cannot serve production. Integration must either
  place the private arithmetic behind the durable authorization facade or make
  the authoritative lower boundary verify a ratified unforgeable G1b
  capability before any exposure or partial signing.
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
| `cargo check -p dom-crypto --no-default-features --locked` | PASS: raw nonce lifecycle APIs omitted |
| `cargo check -p dom-adaptor --no-default-features --locked` | PASS: production boundary remains fail-closed |
| `cargo clippy -p dom-crypto --no-default-features --locked -- -D warnings` | PASS |
| `cargo clippy -p dom-adaptor --all-targets --no-default-features --locked -- -D warnings` | PASS |
| `cargo test -p dom-crypto --lib scriptless --features test-helpers --locked` | PASS: 6 tests, including 10,000 real-verifier cycles |
| `cargo check --manifest-path crates/dom-adaptor/fuzz/Cargo.toml --locked` | PASS: evidence-only helper feature is explicit |
| `cargo doc -p dom-crypto --no-default-features --no-deps --locked` plus generated-HTML symbol search | PASS: quarantined types and signing method absent from default public API |
| `cargo tree -p dom-adaptor -e features,no-dev --locked` plus `test-helpers` search | PASS: helper feature absent from the default production graph |
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
- `e9fc073` — `fix(scriptless): close session retry and scalar cleanup`
- `f821937` — `fix(scriptless): quarantine nonce exports pending G1b`

The code comparison HEAD is
`f821937a8ff1712d5f9bafd58f152b82073538f2`. Independent comparison must cite
that exact code HEAD. The previously reported 311-field byte-perfect
comparison targeted `f4d35b968c563ce1bc09c269da90095240c33442`; the later
commits change session collision retry, scalar cleanup, and default API
availability, not normative cryptographic bytes, but evidence is not silently
carried forward.

The repository `preflight.sh` and `verify-isolation.sh` scripts reject a linked
worktree path by design because they require the coordinator clone path. Their
executions here returned 4 and 1 respectively; this is recorded rather than
misreported as success. `phase1-gate.sh` returned 1 as required for an open
gate.

## Safety confirmation

- No official repository or other worktree was modified.
- No DL2P material was imported.
- No consensus, existing wire, persisted-block, genesis, network-magic, or PoW
  behavior changed.
- No push, merge, rebase, release, publication, or production activation was
  performed.
- No real funds were used or authorized.
