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
  NAR-002 names and framing;
- canonical signing-roster ordering in collective binding;
- exact closed exposure-kind registry and 252-byte exposure permit;
- exact outbound digest framing and permit digest;
- distinct exact 65-byte cryptographic core and 162-byte session-bound adaptor
  pre-signature;
- session-bound ClaimAdaptor validation; and
- persistent fuzz parsing for the new closed registries, core pre-signature,
  context, and permit.

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
| `cargo test -p dom-adaptor --locked` | PASS: 27 tests, including all eight SCAD0 fixtures |
| `cargo test -p dom-consensus scriptless_template_projection --locked` | PASS: authoritative projection test |
| `cargo check -p dom-adaptor --locked` | PASS |
| `sha256sum --check docs/scriptless/source-guides/normative/MANIFEST.sha256` | PASS |
| Minisign verification of NAR-001, NAR-002, and KAT V2 | PASS |

The complete focused validation commands and final commit IDs are appended
after the final validation run.

## Safety confirmation

- No official repository or other worktree was modified.
- No DL2P material was imported.
- No consensus, existing wire, persisted-block, genesis, network-magic, or PoW
  behavior changed.
- No push, merge, rebase, release, publication, or production activation was
  performed.
- No real funds were used or authorized.
