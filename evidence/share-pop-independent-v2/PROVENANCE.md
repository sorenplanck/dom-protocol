# Independent Share PoP V1 Evidence — Provenance

## Purpose and independence boundary

This directory is a clean-room, deterministic Share PoP V1 reference for the
fixed evidence inputs below. It was created on branch
`evidence/share-pop-independent-v2` from pre-G1A base
`a37f0bbeeb7c0ee5579154ae64476e8374d1dabb`.

Before the implementation and complete intermediate outputs were frozen in a
commit, the protocol author consulted only:

1. signed NAR-DC-P1-001, especially sections 5.1 through 5.5, its detached
   Minisign signature, and its ratification evidence;
2. the authoritative DOM tagged-hash implementation and the necessary
   dependency-version declarations;
3. the secp256k1 group order; and
4. the fixed inputs stated in the assignment and repeated below.

Repository instructions were read for procedure and scope, not as protocol or
expected-output sources. No production `share_pop.rs`, G1A implementation,
prior independent generator, prior independent output, prior report, or
expected vector was inspected before the precomparison freeze. Production is
not imported or invoked by this implementation.

## Normative and hash-source integrity

- NAR bytes SHA-256:
  `88586449d577038ac98e9463250821ed9b3d1e6c94f5b11abfaf036a93eec655`
- Detached signature SHA-256:
  `2f19ec266f05e440cb5de2b91bc4295b93b2629170adbf6d020505ebb2311ffc`
- Ratification-evidence SHA-256:
  `4301b510493718e5d9706d33b16f947003c1f5c38dcfae1f4dba1ccbe0a971aa`
- Ratification artifact commit:
  `65c5bf835f1199d7a245f67c8741de1715909609`
- Minisign public key:
  `RWTwnDDKlXoZdG3obVRiLPfVRHr17E0Fj2GN8IZ2rBkipRZvIIW6PLJ3`
- Minisign verification result: exit code 0; signature and trusted-comment
  signature verified.
- Trusted signature timestamp: `1785904289`
  (`2026-08-05T01:31:29-03:00` per the ratification evidence).
- Authoritative `crates/dom-crypto/src/hash.rs` source baseline:
  `769822562565f18ef55423dc992e7aa661206b4a`
- Tagged-hash file's last commit:
  `df2dbdc4db1268a7e73e1f40dc1a73300a61c914`
- Tagged-hash file SHA-256:
  `1d2afbf4c74ec8c015e026e4fca790edcdd198f6cf0d07c150bc3a9ab218ed71`
- Authoritative Rust hash dependency: `blake2 0.10.6`, registry checksum
  `46502ad458c9a52b69d4d4d32775c788b7a1b85e8bc9d482d92250fc0e3f8efe`.

The independent generator implements
`BLAKE2b-256(u16_le(tag length) || ASCII(tag) || data)` with
`hashlib.blake2b(digest_size=32)`. This is BLAKE2b configured for a 32-byte
digest, not truncation of a 64-byte BLAKE2b digest.

## Independent implementation stack

- CPython 3.12.3
- Python standard-library `_blake2` through `hashlib.blake2b`
- cryptography 41.0.7 only as a binding to named-curve EC operations
- OpenSSL 3.0.13 (30 Jan 2024) secp256k1 EC implementation

`environment.json` records the runtime-reported full versions. The generator
uses OpenSSL named-curve point parsing, compression, multiplication, combined
multiplication, identity testing, and equality. It does not copy curve field
or generator coordinates. Wide challenge reduction and response arithmetic
are Python integer arithmetic modulo the allowed secp256k1 group order:

```text
FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
```

## Fixed inputs

```text
chain_id                 = 11 repeated 32 bytes
session_id               = 22 repeated 32 bytes
roster participant IDs   = [21 repeated 32 bytes, 42 repeated 32 bytes]
roster order              = ascending bytewise
role                      = Initiator (01)
participant_index         = 0 (0000 little-endian)
signing_share             = 7 (32-byte big-endian scalar)
deterministic test nonce  = 9 (32-byte big-endian scalar)
terms_hash                = 33 repeated 32 bytes
recovery_binding_hash     = 44 repeated 32 bytes
```

The scalar 9 nonce is deterministic evidence only. It is not a production
nonce policy or production API.

## Reproduction and checks

From this directory:

```sh
python3 generate_share_pop_v1.py write
python3 generate_share_pop_v1.py check
sha256sum -c SHA256SUMS
```

The generated binaries expose every byte-bearing intermediate. `vector.json`
labels and repeats them in hexadecimal. `verification.json` records the
positive equation. `negative-mutations.json` records targeted failures and an
exhaustive one-bit mutation sweep over every statement and proof byte.

`SHA256SUMS` covers the generator, this provenance record, and every generated
artifact other than the manifest itself. It is intentionally frozen before
the production comparison; a later comparison report is separate evidence and
does not retroactively change this manifest.
