# DOM G1a Share PoK independent vectors v1

> **WARNING: PUBLIC AND INSECURE TEST VECTORS ONLY.** All scalar values,
> nonce scalars, and proof material in this directory are intentionally public.
> They MUST NEVER be used for production keys, nonces, wallets, funds, signing,
> or randomness.

This directory is a clean-room, Python-standard-library reference for the G1a
Schnorr proof of knowledge of a blinding share. It was generated before any
inspection, search, compilation, or execution of the production
`crates/dom-adaptor/src/share_pop.rs`, its Rust tests, or existing Share PoP
expected outputs.

The statement is exactly 196 bytes:

```text
chain_id_32
|| session_id_32
|| participant_id_32
|| role_u8
|| participant_index_u16_le
|| share_point_R_sec1_33
|| terms_hash_32
|| capsule_hash_32
```

The context and proof equations are:

```text
context = H_tag("DOM:scriptless-share-pop:v1", statement)
A = a*G
challenge_preimage = context || R || A
d0 = H_tag("DOM:scriptless-share-pop:v1", challenge_preimage || 0x00)
d1 = H_tag("DOM:scriptless-share-pop:v1", challenge_preimage || 0x01)
c = BE512(d0 || d1) mod n; reject c = 0
z = a + c*r mod n
proof = A_sec1_33 || z_be32
verify z*G == A + c*R
```

`H_tag` is native BLAKE2b with a 32-byte output over
`u16_le(tag_length) || tag_ascii || data`, with no key, salt, or
personalization. Point arithmetic is implemented directly over the published
secp256k1 constants, without a DOM or third-party cryptographic dependency.

## Normative-source boundary

The exact Share PoK statement and Schnorr equation come from Master
Specification v1.0 section 4.2, whose controlled source SHA-256 is
`5ad366d6b5c01c88bc88d4e9c016b447c32f24fbc24a32fa8b6946d7ff5dd6b5`.
NAR-001 (verified Minisign signature; SHA-256
`eee087c808aeb4e6e745a5311d17ca5a63c5b5e5568218d20b1cbcdd7b6206dc`)
fixes DOM `H_tag` and 512-bit big-endian reduction. NAR-002 (verified Minisign
signature; SHA-256
`b726c2e576833f843d0065a1e823e649ab9e7e28fd9cfedb0e6e06e6b1be87f5`)
preserves the existing `DOM:scriptless-share-pop:v1` assignment and adds the
participant/session closure rules used here.

The source says `H_to_scalar(tag, challenge_preimage)` but does not explicitly
freeze the two counter bytes or their position for this Share PoK. This
independent v1 reference freezes the suffix-counter expansion shown above
before inspecting production. Agreement with production cannot by itself cure
that normative ambiguity; a signed byte-exact assignment is still required.

## Reproduction

```bash
python3 generate_reference.py --check
sha256sum --check MANIFEST.sha256
```

Use `python3 generate_reference.py --write` only when intentionally
regenerating the committed expected output and manifest from the input-only
fixture.
