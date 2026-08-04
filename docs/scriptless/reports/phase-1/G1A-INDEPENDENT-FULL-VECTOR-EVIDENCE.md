# G1a independent complete-vector evidence

Date: 2026-08-04

Status: **PRE-COMPARISON EVIDENCE COMPLETE — REAL DOM VERIFIER EXECUTION DEFERRED**

Branch: `test/phase-1-independent-vectors-ratified`

Independent baseline: `6062f9adb6ddd1812c41b2fb66b9ec69a249f324`

Normative-import HEAD before this evidence: `2b94653962850cd1f71ac727e43d39445dc3aafe`

## Independence statement

The complete reference implementation and all expected output bytes were
created without inspecting the G1a worktree, branch, source code, commits,
reports, or outputs. No production output was provided as a sanity value. The
implementation imports no DOM Rust crate and no production Scriptless module.

The implementation boundary is CPython 3.12.3, standard-library
`hashlib.blake2b`, and bounded pure-Python secp256k1 arithmetic already frozen
in the independent KDF evidence. There are no third-party Python dependencies.

NAR-002 §11.7 requires the independent expected outputs to be committed before
the real DOM Rust verifier is executed or production G1a is inspected. That
barrier is preserved by this evidence. The real-verifier field in every vector
is explicitly `DEFERRED UNTIL AFTER PRE-COMPARISON COMMIT`.

## Ratified source integrity

The generator rejects any source whose exact SHA-256 differs from the values
below.

| Artifact | Content SHA-256 | Detached signature SHA-256 |
|---|---|---|
| `NAR-002-phase-1-omnibus-normative-closure.en.md` | `b726c2e576833f843d0065a1e823e649ab9e7e28fd9cfedb0e6e06e6b1be87f5` | `fd1f1155e48190913e0fae10770afcdac5bf01e4bc410a663327fce3881c64c2` |
| `kat_two_party_adaptor_inputs_v1.en.json` | `5e5063e819e7d64514039905c3c9fed0cb98c39f36c370fdb4c413751a08fac9` | `2f0fc550cda61ffb9377f1ce0055fbe9196bc9bcdf0406eb868cda89ce8df7ed` |

Both detached signatures were verified with Minisign key ID
`74197A95CA309CF0` before generation. NAR-002 supplies the Refund and Funding
inputs and the participant identity assignments. The separately signed input-
only fixture supplies the ClaimAdaptor inputs. Neither artifact contains
expected cryptographic outputs.

## Frozen outputs

The generator is:

```text
test-vectors/scriptless/two-nonce/independent/ratified-v1/generate_full_adaptor_reference.py
SHA-256 fa4e8347685e69489e5a85c11725896104a26fcfc3b4194f253e2ddcca808cf2
```

The output is:

```text
test-vectors/scriptless/two-nonce/independent/ratified-v1/full_adaptor_reference_outputs_v1.json
SHA-256 68f7d9e9b202b2c4380fe913f69ab15ed5205871cc82c84e3ee78eaaf5762206
```

The local vector manifest SHA-256 is
`4aa040fdf8f7a6b879b95b03eca8026d00400d33dd3e73722ace193bf24ad1d1`.

The output freezes all bytes for these three purpose cases:

| Case | Purpose byte | Adaptor | Independent equation result |
|---|---:|---|---|
| `V1-Refund` | `01` | absent | pass |
| `V1-ClaimAdaptor` | `02` | present, `t=5` | pass |
| `V1-Funding` | `03` | absent | pass |

For each applicable case, the output records:

- canonical context bytes for both participants;
- complete tagged-hash inputs, mask, masked share, seed, four expansion
  digests, `W_1`, `W_2`, reduced `k1`, and reduced `k2`;
- `R_i1`, `R_i2`, commitment bodies and digests, and canonical commit/reveal
  payloads;
- binding body, tagged input, digest, and scalar;
- effective participant nonces, aggregate nonce, aggregate excess, and
  `R_hat`;
- complete DOM challenge body, tagged input, digest, and scalar;
- both participant partial scalars, payloads, and equation sides;
- aggregate `s_hat`, pre-signature equation sides, and the appropriate
  65-byte aggregate object;
- the canonical 162-byte ClaimAdaptor pre-signature;
- adapted scalar, final 65-byte signature, extracted scalar, and `t*G` for
  ClaimAdaptor;
- an independent parse and DOM-compatible Schnorr-equation result.

## Negative evidence

Fifty negative cases are recorded and rejected:

| Class | Count |
|---|---:|
| Signed supplemental input mutations | 20 |
| Participant identity and mapping mutations | 6 |
| Nonce-commitment field mutations | 8 |
| Collective-binding framing and ordering mutations | 10 |
| Challenge, participant binding, and adaptation mutations | 6 |

The output records the first rejection boundary or the failed verification
equation for every negative case. No negative case verifies successfully.

## Reproduction commands

Commands run from the repository root:

```text
PYTHONDONTWRITEBYTECODE=1 python3 -u test-vectors/scriptless/two-nonce/independent/ratified-v1/generate_full_adaptor_reference.py
PYTHONDONTWRITEBYTECODE=1 python3 test-vectors/scriptless/two-nonce/independent/ratified-v1/generate_full_adaptor_reference.py --check
python3 -m json.tool test-vectors/scriptless/two-nonce/independent/ratified-v1/full_adaptor_reference_outputs_v1.json
sha256sum --check test-vectors/scriptless/two-nonce/independent/ratified-v1/MANIFEST.sha256
sha256sum --check test-vectors/scriptless/MANIFEST.sha256
git diff --check
```

The first generation produced three purpose cases and 50 negative cases. The
reproducibility check returned exit 0 and reported that the full reference
output was verified. JSON parsing, Python source compilation, both vector
manifest checks, the normative manifest check, and `git diff --check` also
returned exit 0. No Python bytecode cache was created in the evidence directory.

## Gate boundary

- Independent complete output generation: **complete**.
- Independent output committed before production inspection: **required next
  repository action**.
- Production G1a inspected: **no**.
- Cross-implementation comparison performed: **no**.
- Real DOM Rust verifier executed against these frozen bytes: **no, deferred by
  NAR-002 §11.7 until after the evidence commit**.
- G1a approved by this artifact alone: **no**.
