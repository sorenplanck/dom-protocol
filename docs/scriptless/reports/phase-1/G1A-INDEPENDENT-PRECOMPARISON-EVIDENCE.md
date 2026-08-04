# G1a independent pre-comparison evidence

Date: 2026-08-04  
Status: **COMMITTED EVIDENCE PENDING CROSS-IMPLEMENTATION COMPARISON**  
Branch: `test/phase-1-independent-vectors-ratified`  
Baseline: `6062f9adb6ddd1812c41b2fb66b9ec69a249f324`

## Independence statement

This reference implementation and its expected outputs were produced without
inspecting the G1a implementation worktree, branch, source, commits, reports, or
outputs. No production G1a result was supplied as a sanity value. The first
production comparison must occur only after the commit containing this report,
the generator, and `reference_outputs_v1.json` exists.

The independent boundary is CPython 3.12.3, its standard-library native
`hashlib.blake2b`, and bounded pure-Python secp256k1 arithmetic. There are no
third-party Python dependencies and no imports from DOM Rust crates.

## Signed source verification

Ratification key:

```text
Key ID: 74197A95CA309CF0
Public key: RWTwnDDKlXoZdG3obVRiLPfVRHr17E0Fj2GN8IZ2rBkipRZvIIW6PLJ3
```

Exact source hashes:

| Artifact | SHA-256 | Signature SHA-256 | Result |
|---|---|---|---|
| `docs/scriptless/source-guides/normative/amendments/NAR-001-normative-assignment-record.en.md` | `eee087c808aeb4e6e745a5311d17ca5a63c5b5e5568218d20b1cbcdd7b6206dc` | `6d1ef078a7de411e11acb1873cb1742d968ebb1a7a44629be66035d086ad2691` | Minisign exit 0 |
| `test-vectors/scriptless/two-nonce/kat_inputs_v2.en.json` | `55642208968863a7b2c4773a82d9774f95f2a3b604b80a876d0bf031396b2a7d` | `1341e3ceecb55755f4321b47007fa2af624de92fcb5561bb8674cd640f2c6190` | Minisign exit 0 |

Commands:

```text
minisign -Vm docs/scriptless/source-guides/normative/amendments/NAR-001-normative-assignment-record.en.md -P RWTwnDDKlXoZdG3obVRiLPfVRHr17E0Fj2GN8IZ2rBkipRZvIIW6PLJ3
minisign -Vm test-vectors/scriptless/two-nonce/kat_inputs_v2.en.json -P RWTwnDDKlXoZdG3obVRiLPfVRHr17E0Fj2GN8IZ2rBkipRZvIIW6PLJ3
```

Both commands printed `Signature and comment signature verified`. The Minisign
version was 0.11.

## Authoritative public hash boundary

The independently transcribed definition is:

```text
H_tag(tag, data) = BLAKE2b-256(u16_le(len(tag_ascii)) || tag_ascii || data)
```

The source boundary is
`crates/dom-crypto/src/hash.rs::blake2b_256_tagged`, lines 23-42 at the
coordinator baseline. It uses native 32-byte BLAKE2b with no key, salt, or
personalization. The reference generator implements these bytes directly with
`hashlib.blake2b(..., digest_size=32)` and does not call the DOM function.

## Generated evidence

`reference_outputs_v1.json` contains:

- 3 accepted base cases;
- 13 accepted field mutations;
- 20 negative cases, all rejected with the expected fail-closed class;
- the canonical context bytes for every accepted case;
- complete tagged-hash input bytes, including tag length and tag bytes;
- mask, masked signing share, seed, all four wide-expansion digest halves,
  `W_1`, `W_2`, reduced `k1`, reduced `k2`, `R_i1`, and `R_i2`;
- explicit source, runtime, curve, hash, and independence metadata.

The generator validates closed discriminants, exact lengths, trusted chain ID,
nonzero session ID, strict roster ordering, duplicate rejection, canonical SEC1
points, participant index, `signing_share*G`, signer placement, canonical scalar
ranges, adaptor optionality, adaptor scalar/point correspondence when supplied,
and purpose/adaptor compatibility before nonce derivation.

Generation command:

```text
python3 test-vectors/scriptless/two-nonce/independent/ratified-v1/generate_reference.py
```

Reproducibility command:

```text
python3 test-vectors/scriptless/two-nonce/independent/ratified-v1/generate_reference.py --check
```

The vector manifest is
`test-vectors/scriptless/two-nonce/independent/ratified-v1/MANIFEST.sha256`
with SHA-256
`a7e8a4db10c88682e8eced2269a85aec5ffda599d5474835d10855c283b35575`.

## Supplemental adaptor evidence

No supplemental complete two-party/adaptor vector was generated. The signed KAT
provides one local signing share and one local auxiliary-randomness value per
case, but it does not supply the second participant's nonce-derivation inputs.
Inventing those bytes would violate the input-only independence boundary. This
does not affect the independent context/KDF/public-nonce evidence, but complete
binding, partial, aggregate, adaptation, and extraction comparison remains a
separate gate item.

## Pre-comparison state

- Production comparison performed: **no**.
- Production G1a inspected: **no**.
- Independent output modified to agree with production: **no**.
- Output ready for first byte-by-byte comparison after this commit: **yes**.
- G1a approved by this evidence alone: **no**.
