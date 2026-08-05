# Independent Evidence Revalidation

Date: 2026-08-04

Status: **FROZEN EVIDENCE REVALIDATED — INTEGRATED CANDIDATE NOT INSPECTED**

Expectation-barrier commit:
`ab4110e7c0e6d3e6a1e28af42d84a6b1913c3a23`

Independent evidence commit:
`6b90e7a021541a63a728354910b323603da635b2`

Independent evidence tree:
`ec81b24ebd3d1463637e306f7142d274b6219336`

## 1. Boundary

This revalidation used a temporary `git archive` snapshot of the exact
independent evidence commit. It did not inspect either integrated DOM or Wallet
worktree and did not execute the production comparison harness. The comparison
remains deferred until the coordinator supplies exact candidate heads.

The snapshot was temporary and was not used as a production dependency. No
file from it was copied into an official repository or an integration
worktree.

## 2. Tools

| Tool | Executed version |
|---|---|
| Python | `3.12.3` |
| Minisign | `0.11` |
| rustfmt | `1.9.0-stable (31fca3adb2 2026-06-26)` |

## 3. Signature verification

Both detached signatures were freshly verified with public key
`RWTwnDDKlXoZdG3obVRiLPfVRHr17E0Fj2GN8IZ2rBkipRZvIIW6PLJ3`.

| Artifact | Content SHA-256 | Signature SHA-256 | Result |
|---|---|---|---|
| `NAR-002-phase-1-omnibus-normative-closure.en.md` | `b726c2e576833f843d0065a1e823e649ab9e7e28fd9cfedb0e6e06e6b1be87f5` | `fd1f1155e48190913e0fae10770afcdac5bf01e4bc410a663327fce3881c64c2` | signature and trusted comment verified, exit 0 |
| `kat_two_party_adaptor_inputs_v1.en.json` | `5e5063e819e7d64514039905c3c9fed0cb98c39f36c370fdb4c413751a08fac9` | `2f0fc550cda61ffb9377f1ce0055fbe9196bc9bcdf0406eb868cda89ce8df7ed` | signature and trusted comment verified, exit 0 |

The NAR-002 trusted comment timestamp was `1785878139`. The input-only fixture
trusted comment timestamp was `1785875781`.

## 4. Manifest and generator results

| Check | Result |
|---|---|
| normative source manifest | every listed source and detached signature passed, exit 0 |
| root Scriptless vector manifest | every listed artifact passed, exit 0 |
| independent local vector manifest | every listed artifact passed, exit 0 |
| independent local manifest SHA-256 | `b408c4826bcda2d25a0d431ced0cf48619974071c9667c5b6ec3bef05c3c47f2` |
| root vector manifest SHA-256 | `575b9be1dbb987cdc690c7524e518a057c9f5a82d416bc694443ed2a0be5fdb9` |
| generator Python compilation | passed without writing bytecode, exit 0 |
| generator reproducibility check | `full reference output verified`, exit 0 |
| comparison harness rustfmt check | passed, exit 0 |

The revalidated artifact hashes are:

| Artifact | SHA-256 |
|---|---|
| `generate_full_adaptor_reference.py` | `fa4e8347685e69489e5a85c11725896104a26fcfc3b4194f253e2ddcca808cf2` |
| `full_adaptor_reference_outputs_v1.json` | `68f7d9e9b202b2c4380fe913f69ab15ed5205871cc82c84e3ee78eaaf5762206` |
| `compare_production.rs` | `4d4df3e5d47f53c4acf1ce1b2c9e16ddb0a57c6bb43c7612ff5440433a6d63f0` |

The JSON structure contains exactly three positive purpose cases and fifty
negative cases:

| Class | Count |
|---|---:|
| purpose cases | 3 |
| signed supplemental rejections | 20 |
| participant identity rejections | 6 |
| commitment rejections | 8 |
| binding rejections | 10 |
| challenge, partial, and adaptation rejections | 6 |

## 5. Commands executed

The following commands were executed from an exact archive of the independent
commit. `$SNAPSHOT` denotes the temporary archive root.

```sh
sha256sum --check test-vectors/scriptless/two-nonce/independent/ratified-v1/MANIFEST.sha256
sha256sum --check test-vectors/scriptless/MANIFEST.sha256
PYTHONDONTWRITEBYTECODE=1 python3 test-vectors/scriptless/two-nonce/independent/ratified-v1/generate_full_adaptor_reference.py --check
python3 -c "from pathlib import Path; p=Path('test-vectors/scriptless/two-nonce/independent/ratified-v1/generate_full_adaptor_reference.py'); compile(p.read_text(), str(p), 'exec'); print('GENERATOR_COMPILE_OK')"
python3 -c "import json,pathlib; p=pathlib.Path('test-vectors/scriptless/two-nonce/independent/ratified-v1/full_adaptor_reference_outputs_v1.json'); d=json.loads(p.read_text()); counts=d['counts']; print('VECTOR_STRUCTURE_OK', counts, 'total_negative=', sum(v for k,v in counts.items() if k != 'purpose_cases'))"
rustfmt --check test-vectors/scriptless/two-nonce/independent/ratified-v1/compare_production.rs
minisign -Vm "$SNAPSHOT/docs/scriptless/source-guides/normative/amendments/NAR-002-phase-1-omnibus-normative-closure.en.md" -x "$SNAPSHOT/docs/scriptless/source-guides/normative/amendments/NAR-002-phase-1-omnibus-normative-closure.en.md.minisig" -P RWTwnDDKlXoZdG3obVRiLPfVRHr17E0Fj2GN8IZ2rBkipRZvIIW6PLJ3
minisign -Vm "$SNAPSHOT/test-vectors/scriptless/two-nonce/kat_two_party_adaptor_inputs_v1.en.json" -x "$SNAPSHOT/test-vectors/scriptless/two-nonce/kat_two_party_adaptor_inputs_v1.en.json.minisig" -P RWTwnDDKlXoZdG3obVRiLPfVRHr17E0Fj2GN8IZ2rBkipRZvIIW6PLJ3
```

Every command above exited zero. Command output was captured in the independent
review agent's execution record and summarized in the tables above.

## 6. Prepared Phase B execution

After the coordinator supplies clean exact integrated heads, the review will:

1. record the candidate branch, HEAD, tree, lockfile hash, and tracked status;
2. compare the candidates with their ratified bases and candidate provenance;
3. inventory public APIs, constructors, traits, unsafe code, features, and
   reverse dependencies;
4. materialize implementation-specific compile-fail probes for the already
   frozen API attack IDs;
5. run the unchanged 311-field comparison against the exact DOM candidate;
6. execute the applicable codec, lifecycle, witness, restore, retry, and
   ordinary-Wallet negative probes;
7. inspect fault, fuzz, sanitizer, and platform evidence without relabeling
   prepared or historical runs as fresh execution;
8. report the first cryptographic divergence and every security finding without
   editing production code.

The frozen expected outcomes remain in
`INDEPENDENT-INTEGRATION-EXPECTATIONS.md` and
`test-vectors/scriptless/integration-review/v1/attack-expectations.tsv`. This
revalidation does not modify them.
