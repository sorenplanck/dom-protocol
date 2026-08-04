# NAR-001 — Phase 1 Cryptographic Assignment Record

Status: **FINAL CANDIDATE — EFFECTIVE ONLY AFTER VALID DETACHED RATIFICATION**  
Date: 2026-08-04  
Amends: *DOM Scriptless Contracts — Master Specification v1.0*  
Ratification authority: DOM release signing key, Minisign key ID `74197A95CA309CF0`  
Verification public key: `RWTwnDDKlXoZdG3obVRiLPfVRHr17E0Fj2GN8IZ2rBkipRZvIIW6PLJ3`

## 1. Authority and effect

This record assigns values that were absent or marked proposed in the Master Specification. It is not effective while unsigned. A valid detached Minisign signature over the exact bytes of this file makes the assignments below normative for DOM Scriptless Contracts V1.

Authority order after ratification:

1. explicit safety decisions in the Phase 1 completion mission dated 2026-08-04;
2. this ratified record;
3. binary-layout requirements in the Master Specification;
4. accepted engineering ADRs that do not conflict with items 1–3;
5. implementation plans, schedules, code, and tests.

An implementation or self-generated vector cannot override this record. Any incompatible future change requires a new versioned record and new versioned types. No V1 alias is permitted.

## 2. Authoritative DOM cryptographic backend

All Scriptless `H_tag(tag, data)` operations delegate to the authoritative DOM function:

```text
crates/dom-crypto/src/hash.rs::blake2b_256_tagged
```

At official DOM baseline `769822562565f18ef55423dc992e7aa661206b4a`, the byte definition is:

```text
H_tag(tag, data) = BLAKE2b-256(
    u16_le(length_in_bytes(tag_ascii)) || tag_ascii || data
)
```

Properties:

- the digest is native BLAKE2b with a 32-byte output;
- the tag is closed, ASCII, case-sensitive, and versioned;
- the tag length is the exact ASCII byte length and must fit in `u16`;
- no key, salt, or personalization parameter is used;
- fields inside `data` are concatenated exactly as specified by the calling construction;
- BLAKE2s-256, truncated BLAKE2b-512, SHA-256, BIP340 duplicated-tag hashing, and a parallel generic BLAKE2 implementation are forbidden;
- `dom-adaptor` must not instantiate BLAKE2 directly and must not depend directly on `k256`.

## 3. Closed PurposeV1 registry

Appendix E.6 is ratified with these exact bytes:

| Byte | Name | V1 codec | Strict Phase 1 execution |
|---:|---|---|---|
| `0x01` | `Refund` | accepted | accepted; adaptor point absent |
| `0x02` | `ClaimAdaptor` | accepted | accepted; adaptor point required |
| `0x03` | `Funding` | accepted | accepted; adaptor point absent |
| `0x04` | `Sponsor` | accepted | rejected until a separately ratified Sponsor flow exists |

Rules:

- `PurposeV1` is a closed `repr(u8)` registry.
- `0x00` and `0x05..0xff` are rejected.
- There is no unknown, default, fallback, or `non_exhaustive` variant.
- The earlier Phase 1 plan mapping `Funding=0x01`, `Claim=0x02`, `Refund=0x03` is revoked.
- The exact name is `ClaimAdaptor`, not `Claim`.
- A future incompatible registry is `PurposeV2`; `PurposeV1` is never extended.

## 4. Closed DirectionV1 registry

Direction is stable by protocol role, never by the observer's local/remote perspective.

| Byte | Name | Definition |
|---:|---|---|
| `0x01` | `Initiator` | party that creates the nonzero `session_id` and sends the first DSC1 session message |
| `0x02` | `Responder` | party that accepts that first DSC1 session message and sends the first response |

Every other byte is rejected. The same protocol message has the same direction byte at both honest peers.

## 5. Closed SigningPhaseV1 registry

The base session machine in Master Specification §9.1 remains unchanged. This record adds a signing-only `u16` subregistry. `SigningPhaseV1` is not a second encoding of the base session phase.

| u16 value | Little-endian bytes | Name |
|---:|---|---|
| `0x0100` | `00 01` | `SigNonceCommit` |
| `0x0101` | `01 01` | `SigNonceReveal` |
| `0x0102` | `02 01` | `SigBinding` |
| `0x0103` | `03 01` | `SigPartial` |
| `0x0104` | `04 01` | `SigAdapt` |
| `0x0105` | `05 01` | `SigExtract` |

Rules:

- only the six values above decode as `SigningPhaseV1`;
- `0x0106..0x01ff` are reserved and rejected;
- a value may be valid in the base §9.1 registry and still be rejected by `SigningPhaseV1`;
- declaration order or implicit Rust discriminants never define the bytes;
- `Created = 0x0000` is the mandatory negative fixture value that is valid in the base registry but invalid in this signing subregistry.

## 6. Canonical SessionContextV1

`SessionContextV1` is constructible only through a validating constructor. Every stored field is private and has immutable accessors only. Encoding is infallible after validation.

### 6.1 Byte layout

```text
canonical_context_v1 =
    context_version_u16_le
 || chain_id_32
 || session_id_32
 || purpose_u8
 || direction_u8
 || signing_phase_u16_le
 || template_hash_32
 || message_digest_32
 || transcript_hash_32
 || retry_counter_u64_le
 || participant_count_u16_le
 || participant_public_keys_33_each
 || participant_index_u16_le
 || adaptor_presence_u8
 || adaptor_point_33_if_present
```

| Offset | Field | Size | Encoding and validation |
|---:|---|---:|---|
| 0 | `context_version` | 2 | `u16` LE, exactly `0x0001` (`01 00`) |
| 2 | `chain_id` | 32 | exact trusted local DOM chain ID; all-zero rejected |
| 34 | `session_id` | 32 | exact bytes; all-zero rejected |
| 66 | `purpose` | 1 | §3 |
| 67 | `direction` | 1 | §4 |
| 68 | `signing_phase` | 2 | §5, `u16` LE |
| 70 | `template_hash` | 32 | §6.3 |
| 102 | `message_digest` | 32 | exact kernel message digest accepted by the real DOM verifier |
| 134 | `transcript_hash` | 32 | exact accepted session transcript hash |
| 166 | `retry_counter` | 8 | `u64` LE |
| 174 | `participant_count` | 2 | `u16` LE; inclusive range 2 through 16 |
| 176 | `participant_public_keys` | `33*n` | compressed canonical SEC1, strictly ascending bytewise |
| `176 + 33*n` | `participant_index` | 2 | `u16` LE; less than `n` |
| `178 + 33*n` | `adaptor_presence` | 1 | `0x00` absent or `0x01` present; every other byte rejected |
| `179 + 33*n` | `adaptor_point` | 0 or 33 | present only when `adaptor_presence=0x01` |

Total size is `179 + 33*n` bytes without an adaptor point and `212 + 33*n` bytes with one.

### 6.2 Participant validation

- Every public key is exactly 33-byte compressed SEC1 with prefix `0x02` or `0x03`.
- The authoritative DOM point parser must accept it as a nonidentity secp256k1 point.
- Re-encoding must reproduce the input bytes exactly.
- The roster is strictly ascending by unsigned lexicographic comparison of the 33 encoded bytes.
- Duplicate and out-of-order entries are distinct errors.
- `participant_index` is in range.
- The local public key equals `signing_share * G` through the authoritative DOM arithmetic boundary.
- That local public key occurs exactly once and at `participant_index`.

### 6.3 Template, message, and transcript bindings

```text
template_hash = H_tag(
    "DOM:scriptless-template:v1",
    complete_canonical_template_bytes
)
```

`complete_canonical_template_bytes` means every byte of the immutable transaction template supplied by the authoritative transaction-template component. No field may be omitted or normalized after hashing. This record does not redefine existing DOM transaction serialization. Production construction remains unavailable until the transaction-template component identifies its canonical serializer and proves byte identity between the committed template and the transaction submitted to the unchanged DOM codec.

`message_digest` is the exact 32-byte kernel message accepted by the real DOM consensus verifier. A parallel digest that omits fee, lock height, kernel features, excess, or any verifier-bound value is forbidden.

`transcript_hash` is the exact accepted hash from the session transcript. This record binds that 32-byte value into nonce derivation; it does not authorize Phase 3-SM to invent a transcript codec.

### 6.4 Purpose/adaptor compatibility

- `ClaimAdaptor` requires `adaptor_presence=0x01` and a valid canonical nonidentity adaptor point.
- `Refund`, `Funding`, and `Sponsor` require `adaptor_presence=0x00` and append no point bytes.
- No identity point, zero-filled pseudo-point, or fixed 33-byte sentinel represents absence.
- An absent required adaptor or unexpected adaptor is rejected before scalar arithmetic.

## 7. Secret two-nonce derivation V1

### 7.1 Closed domain tags

Exactly these three ASCII tags are assigned:

```text
DOM:scriptless-secret-nonce-aux:v1
DOM:scriptless-secret-nonce-seed:v1
DOM:scriptless-secret-nonce-wide:v1
```

The shorter competing strings `DOM:scriptless-nonce-aux:v1`, `DOM:scriptless-nonce-seed:v1`, and `DOM:scriptless-nonce-k:v1` are revoked drafts and must not be registered as aliases.

### 7.2 Definition

Let `x_be32` be the canonical nonzero 32-byte big-endian local signing scalar. Let `aux_rand_32` be fresh operating-system CSPRNG output owned by the derivation boundary.

```text
mask = H_tag(
    "DOM:scriptless-secret-nonce-aux:v1",
    aux_rand_32
)

masked_signing_share = x_be32 XOR mask

seed = H_tag(
    "DOM:scriptless-secret-nonce-seed:v1",
    masked_signing_share || canonical_context_v1
)
```

For `i=0x01` (`k1`) and `i=0x02` (`k2`):

```text
d_i_0 = H_tag(
    "DOM:scriptless-secret-nonce-wide:v1",
    seed || i || 0x00
)

d_i_1 = H_tag(
    "DOM:scriptless-secret-nonce-wide:v1",
    seed || i || 0x01
)

W_i = d_i_0 || d_i_1
k_i = scalar_from_wide_be(W_i)
```

`scalar_from_wide_be`:

```rust
pub fn scalar_from_wide_be(input: &[u8; 64]) -> Option<SecretScalar>
```

It interprets `input` as a 512-bit big-endian integer, reduces it modulo the secp256k1 group order through the authoritative constant-time `dom-crypto` arithmetic boundary, and returns `None` if the reduced scalar is zero. This is the only new public arithmetic function authorized by this KDF assignment. `dom-adaptor` must not import `k256` directly.

### 7.3 Retry behavior

- If either reduced scalar is zero, discard the complete pair.
- No public nonce, commitment, or derived public material may have been exported.
- Increment `retry_counter` with checked arithmetic.
- Re-encode `canonical_context_v1` with the incremented counter and recompute `seed`, both `W_i`, and both scalars.
- The same owned `aux_rand_32` remains bound to this reservation during a zero-scalar retry.
- Counter overflow is terminal and consumes the reservation.
- Retry never authorizes regeneration after any public material may have existed.
- A nonce pair is never derived from session data alone.

### 7.4 Randomness and secret ownership

- Production obtains `aux_rand_32` directly from the operating-system CSPRNG.
- CSPRNG failure is fatal and fail-closed.
- The application API cannot supply auxiliary randomness in production.
- Deterministic auxiliary bytes exist only behind a test-only feature absent from release feature resolution.
- Secret nonce pairs are opaque and one-shot; partial signing consumes the pair by value.
- Secret-bearing types do not implement `Clone`, `Copy`, `Debug`, `Display`, `Serialize`, `Deserialize`, `Eq`, or `Ord`.

RAII/guard cleanup must zeroize on success, ordinary error, validation failure, and unwind:

- canonical secret scalar exposure;
- `aux_rand_32` after ownership transfer;
- `mask`;
- `masked_signing_share`;
- `seed`;
- `d_i_0` and `d_i_1`;
- `W_1` and `W_2`;
- rejected zero scalars;
- every remaining secret nonce share.

## 8. Public two-nonce binding and adaptor equations

The existing Master Specification §6.6 construction remains normative:

```text
R_i = R_i1 + b * R_i2
R = sum(R_i)
R_hat = R + T
e = DOM_kernel_challenge(R_hat, X, chain_id, kernel_message)
s_i_hat = k_i1 + b*k_i2 + e*x_i
s_i_hat*G == R_i + e*X_i
s_hat = sum(s_i_hat)
s = s_hat + t
t = s - s_hat
t*G == T
```

The canonical commitment and binding transcripts are those frozen by accepted ADR-0013:

- commitment tag `DOM:scriptless-nonce-commit:v1`;
- binding tag `DOM:scriptless-sig-nonce-bind:v1`;
- participant lists are explicitly counted and ordered by participant index;
- ClaimAdaptor appends canonical `T`; Refund and Funding append zero bytes for the absent point;
- the 32-byte binding digest is interpreted directly as a big-endian scalar and accepted only in `[1,n-1]`; an invalid binding digest retires the session and nonces without retry.

The secret KDF wide reduction in §7 and the public binding-factor mapping above are intentionally different boundaries and must not be substituted for one another.

The final signature is the unchanged DOM 65-byte format `R_compressed[33] || s_be32[32]` and must pass the real DOM verifier. No x-only normalization or implicit point negation is permitted.

## 9. Required conformance evidence

Ratification freezes inputs; it does not approve G1a. G1a still requires:

- eight frozen SCAD0 signatures verified by the real DOM verifier;
- independent two-nonce and aggregation vectors;
- byte-by-byte comparison of context, every tag preimage, mask, masked share, seed, digest halves, wide values, scalars, points, commitment, binding, partials, aggregate pre-signature, adapted signature, and extraction;
- all 16 relevant SEC1 parity combinations;
- at least 10,000 reproducible closed-cycle property cases;
- malformed scalar and point coverage;
- mutation of every bound field;
- persistent fuzz targets with no panic or unbounded allocation;
- constant-time and compiler-visible zeroization review;
- proof that the final signature passes the unchanged real DOM consensus verifier.

Self-generated vectors are not independent.

## 10. Ratification

Expected detached signature file:

```text
NAR-001-normative-assignment-record.en.md.minisig
```

The signature must verify over the exact bytes of this file with the public key printed in the header. No inline signature text modifies these bytes after signing.
