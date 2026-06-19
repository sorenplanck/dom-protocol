# DOM RFC-0009 — Hash-to-Curve & Cryptographic Primitives Complete Specification

Status: **Normative**
Supersedes: DOM_RFC_0001 (extends, does not replace)
Depends on: RFC-0000, RFC-0001

---

## Motivation

The audit of DOM v6.1 identified three critical ambiguities in RFC-0001:

1. **Hash-to-Curve**: `expand_message_xmd` was specified without naming the hash function,
   making two independent implementations likely to produce different H generators.

2. **Schnorr R_x**: The challenge hash used `R_x` without specifying whether this is
   the 32-byte x-coordinate or the 33-byte SEC1 compressed encoding — a difference that
   breaks cross-implementation signature verification.

3. **MuSig2 nonce generation**: No deterministic nonce algorithm was specified, leaving
   implementations vulnerable to Wagner's generalized birthday attack via nonce correlation.

This RFC provides complete, unambiguous specifications for all three.

---

## 1. H Generator — Complete Specification

### 1.1 Algorithm

The H generator for DOM Pedersen commitments is derived via RFC9380 hash-to-curve
on secp256k1, with the following exact parameters:

```
curve:           secp256k1
method:          hash_to_curve (Simplified SWU with 3-isogeny, RFC9380 Appendix G.8.2)
hash_function:   SHA-256  ← CONSENSUS CRITICAL: not Blake2b, not SHA-512
DST:             b"DOM:h2c:secp256k1:v6.1"
msg:             b""  (empty — H is a static generator, not derived from data)
expand_message:  expand_message_xmd(SHA-256, DST, msg, L=48)
```

The use of **SHA-256** (not Blake2b-256) is intentional and follows the RFC9380
recommendation for secp256k1. The internal hashing for DOM transactions uses Blake2b-256,
but the hash-to-curve operation uses SHA-256 as specified by the RFC9380 secp256k1 suite.

### 1.2 Step-by-Step Derivation

```
1. u = hash_to_field(msg=b"", DST=b"DOM:h2c:secp256k1:v6.1", count=2)
   Using expand_message_xmd with SHA-256 and L=48 per field element.

2. Q0 = map_to_curve_simple_swu(u[0])   — maps to isogenous curve E'
3. Q1 = map_to_curve_simple_swu(u[1])   — maps to isogenous curve E'

4. R = iso_map(Q0) + iso_map(Q1)        — 3-isogeny to secp256k1, then add

5. H = clear_cofactor(R)                — cofactor = 1 for secp256k1, identity operation

6. H_compressed = SEC1_compress(H)     — 33-byte compressed encoding
```

### 1.3 Verification Requirements (Release Blocker)

Before testnet launch, the reference implementation MUST:

1. Generate H using the exact algorithm above
2. Verify H is a valid compressed SEC1 secp256k1 point
3. Verify H is not the point at infinity
4. Verify H is not equal to G (secp256k1 generator)
5. Independently reproduce H in at least two implementations
6. Record H_COMPRESSED_FINAL as a consensus constant in RFC-0006

**Known-answer test**: Once computed, the hex of H_COMPRESSED_FINAL MUST be
included as a hardcoded constant in every conforming implementation.
Any implementation that computes a different H is non-conforming.

### 1.4 Rust Implementation Reference

```rust
// Requires: sha2 = "0.10", secp256k1 (for point validation)
// For RFC9380 hash_to_curve, use the `elliptic-curve` crate with
// `hash2curve` feature, or implement expand_message_xmd directly.

use sha2::{Sha256, Digest};

const DST: &[u8] = b"DOM:h2c:secp256k1:v6.1";
const L: usize = 48; // ceil((log2(p) + k) / 8) = ceil((256 + 128) / 8) = 48

fn expand_message_xmd(msg: &[u8], dst: &[u8], len_in_bytes: usize) -> Vec<u8> {
    // RFC9380 Section 5.3.1
    let b_in_bytes = 32usize; // SHA-256 output length
    let ell = (len_in_bytes + b_in_bytes - 1) / b_in_bytes;
    assert!(ell <= 255, "len_in_bytes too large");
    assert!(dst.len() <= 255, "DST too long");

    let dst_prime: Vec<u8> = dst.iter()
        .chain(&[dst.len() as u8])
        .cloned()
        .collect();
    let z_pad = vec![0u8; 64]; // SHA-256 block size
    let l_i_b_str = [(len_in_bytes >> 8) as u8, len_in_bytes as u8];

    // b_0 = H(Z_pad || msg || l_i_b_str || 0x00 || DST_prime)
    let mut hasher = Sha256::new();
    hasher.update(&z_pad);
    hasher.update(msg);
    hasher.update(&l_i_b_str);
    hasher.update(&[0x00u8]);
    hasher.update(&dst_prime);
    let b0 = hasher.finalize();

    // b_1 = H(b_0 || 0x01 || DST_prime)
    let mut hasher = Sha256::new();
    hasher.update(&b0);
    hasher.update(&[0x01u8]);
    hasher.update(&dst_prime);
    let b1 = hasher.finalize();

    let mut uniform_bytes = b1.to_vec();

    let mut prev_b = b1;
    for i in 2..=ell {
        // b_i = H((b_0 XOR b_{i-1}) || i || DST_prime)
        let xored: Vec<u8> = b0.iter().zip(prev_b.iter()).map(|(a, b)| a ^ b).collect();
        let mut hasher = Sha256::new();
        hasher.update(&xored);
        hasher.update(&[i as u8]);
        hasher.update(&dst_prime);
        let bi = hasher.finalize();
        uniform_bytes.extend_from_slice(&bi);
        prev_b = bi;
    }

    uniform_bytes[..len_in_bytes].to_vec()
}
```

---

## 2. Schnorr Signature — Complete Specification

### 2.1 Challenge Hash (Corrected)

RFC-0001 specified `R_x` without defining its encoding. This RFC corrects that.

The Schnorr challenge hash is:

```
challenge = Blake2b-256(
  u16_le(len(tag)) ||    ← 2 bytes: length of tag as u16 little-endian
  tag ||                  ← b"DOM:kernel-sig:v1"
  R_compressed[33] ||    ← SEC1 compressed encoding of nonce point R (INCLUDES parity byte)
  P_compressed[33] ||    ← SEC1 compressed encoding of public key P (INCLUDES parity byte)
  chain_id[32]     ||    ← DOM network chain_id (anti-replay across networks)
  message                ← kernel message bytes (variable length)
)
```

**Critical**: `R_compressed` is the **33-byte SEC1 compressed** encoding of R (prefix 0x02 or 0x03
plus 32-byte x-coordinate). It is NOT the 32-byte x-coordinate alone.

**Critical**: `chain_id` is included in the **challenge hash** (not only in the RFC 6979 nonce).
This means `schnorr_verify` MUST receive `chain_id` as a parameter — signatures valid on
DOM mainnet are invalid on testnet and vice versa. See RFC-0009 §4.1 for chain_id derivation.

This was corrected from earlier versions which only included `chain_id` in the RFC 6979 nonce.
Any implementation that omits `chain_id` from the challenge will produce signatures
incompatible with the reference implementation.

Including the parity byte:
- Prevents ambiguity between R and -R
- Matches the point validation already required by all implementations
- Is consistent with the SEC1 encoding used everywhere else in the protocol

### 2.2 Kernel Message

The kernel message that is signed is:

```
kernel_message = Blake2b-256(
  "DOM:kernel-msg:v1" ||
  features[1] ||
  fee[8, little-endian] ||
  lock_height[8, little-endian] ||
  chain_id[32]
)
```

For coinbase kernels:
```
kernel_message = Blake2b-256(
  "DOM:kernel-msg:coinbase:v1" ||
  features[1] = 0x01 ||
  explicit_value[8, little-endian] ||
  chain_id[32]
)
```

The `chain_id` binds the signature to the DOM network, preventing replay attacks
on other Mimblewimble-based networks.

### 2.3 Schnorr Sign (Single-Signer)

```
Input:  secret_key sk (32 bytes), message msg (variable), chain_id (32 bytes)
Output: signature (R_compressed[33] || s[32])

1. Derive deterministic nonce via RFC 6979:
   k = RFC6979_HMAC_SHA256(
     x   = sk,
     msg = Blake2b-256(msg || chain_id),
     V0  = [0x01 * 32],
     K0  = [0x00 * 32]
   )
   
2. Compute R = k * G (point multiplication)
   If R == infinity: abort (should never occur with valid k)

3. R_compressed = SEC1_compress(R)  ← 33 bytes including parity

4. P = sk * G
   P_compressed = SEC1_compress(P)  ← 33 bytes

5. challenge = Blake2b-256(u16_le(17) || "DOM:kernel-sig:v1" || R_compressed || P_compressed || msg)
   c = challenge interpreted as big-endian 256-bit integer, reduced mod n

6. s = (k + c * sk) mod n
   s_bytes = s serialized as 32-byte big-endian

7. Return R_compressed || s_bytes  (65 bytes total)
```

### 2.4 Schnorr Verify

```
Input:  signature sig[65], public_key P_compressed[33], message msg
Output: valid (bool)

1. Parse: R_compressed = sig[0..33], s_bytes = sig[33..65]
2. Validate R_compressed is a valid SEC1 compressed secp256k1 point
3. Validate P_compressed is a valid SEC1 compressed secp256k1 point
4. Validate s_bytes as scalar in [1, n-1]

5. R = SEC1_decompress(R_compressed)
6. P = SEC1_decompress(P_compressed)

7. challenge = Blake2b-256(u16_le(17) || "DOM:kernel-sig:v1" || R_compressed || P_compressed || msg)
   c = challenge mod n

8. Verify: s * G == R + c * P
   (using secp256k1 point arithmetic)

9. Return true if equation holds, false otherwise
```

### 2.5 Signature Malleability

DOM Schnorr signatures are NOT malleable because:
- The challenge is bound to R_compressed (including parity), not just R_x
- The challenge is Blake2b-256 (collision-resistant)
- s is a unique scalar for a given (k, sk, message)

Validators MUST reject signatures where s == 0 or s >= n.
Validators MUST reject signatures where R is the point at infinity.

---

## 3. MuSig2 Nonce Generation — Complete Specification

### 3.1 Protocol Version

DOM uses MuSig2 as specified in: "MuSig2: Simple Two-Round Schnorr Multi-Signatures"
(Nick, Ruffing, Seurin, 2021). The 2-round variant ONLY. The 1-round variant is
NOT supported and MUST NOT be implemented.

### 3.2 Deterministic Nonce Generation

To prevent Wagner's generalized birthday attack via nonce correlation across
concurrent signing sessions, nonces MUST be generated deterministically:

```
For signer i with secret key sk_i, in session with session_id:

nonce_seed = HKDF-SHA256(
  ikm  = sk_i[32] || aggregated_pubkey[33] || session_id[32] || msg[32],
  salt = b"DOM:musig2-nonce:v1",
  info = b""
)

(k_{i,1}, k_{i,2}) = (nonce_seed[0..32] mod n, nonce_seed[32..64] mod n)

If k_{i,1} == 0: increment session_id and retry
If k_{i,2} == 0: increment session_id and retry
```

### 3.3 Session ID

The `session_id` is a 32-byte unique identifier for each signing session.
It MUST be:
- Different for every signing session involving the same key
- Generated as: `Blake2b-256(random_32_bytes || timestamp_u64_le || pubkey[33])`
- Never reused

Reusing a `session_id` with the same key leaks the private key. Implementations
MUST verify session_id uniqueness within a wallet's session store.

### 3.4 MuSig2 Transcript

The MuSig2 transcript binds all session parameters. The exact serialization order is:

```
transcript_hash = Blake2b-256(
  "DOM:musig2-transcript:v1" ||   ← 24 bytes tag (no length prefix — fixed)
  chain_id[32] ||
  n_signers[4, little-endian] ||  ← number of signers as u32
  sorted_pubkeys[n * 33] ||       ← all signer public keys sorted lexicographically
  session_id[32] ||
  nonce_commitments[n * 66] ||    ← each signer's (R1_compressed || R2_compressed)
  kernel_features[1] ||
  kernel_fee[8, little-endian] ||
  kernel_lock_height[8, little-endian] ||
  kernel_excess[33]
)
```

The public keys MUST be sorted in lexicographic order of their compressed SEC1 encoding
before being included. This ensures transcript is identical regardless of signer order.

### 3.5 Concurrent Session Limit

An implementation MUST NOT participate in more than one MuSig2 signing session
with the same key pair simultaneously, unless the session_ids are provably distinct.

Participating in two concurrent sessions with different messages but derived from
the same nonce seed is the basis of Wagner's attack.

---

## 4. chain_id Specification

The `chain_id` is a 32-byte identifier that uniquely identifies the DOM network.
It MUST be included in all kernel signatures to prevent replay attacks.

### 4.1 Derivation

```
chain_id = Blake2b-256(
  "DOM:chain-id:v1" ||
  NETWORK_MAGIC[4, big-endian] ||
  genesis_block_hash[32]
)
```

For mainnet: `NETWORK_MAGIC = 0x444F4D31` (ASCII "DOM1")
For testnet: `NETWORK_MAGIC = 0x444F4D54` (ASCII "DOMT")

The `genesis_block_hash` is defined in RFC-0006 (Release Blocker).

### 4.2 Availability

The `chain_id` is computable as soon as the genesis block hash is finalized.
It MUST be hardcoded as a consensus constant in the reference implementation.

### 4.3 chain_id in Noise Handshake

Per RFC-0005, the chain_id MUST be bound to the P2P transport via the Noise protocol prologue:

```
noise_prologue = "DOM" || u32_le(PROTOCOL_VERSION) || u32_le(NETWORK_MAGIC) || chain_id[32]
```

This ensures that any MITM modification to the prologue causes the Noise handshake MAC
to fail, making man-in-the-middle attacks on the P2P layer detectable.

---

## 5. Bulletproofs Binding to H

### 5.1 H Consistency Requirement

The H generator used in Bulletproofs range proofs MUST be the same H derived
via hash-to-curve (Section 1 of this RFC).

If a Bulletproof uses a different H internally, it does not prove that the commitment
encodes a value in the valid range — the range proof and the commitment are decoupled,
enabling inflation.

### 5.2 Bulletproof Transcript

The Bulletproof transcript MUST include the DOM domain separation tag:

```
transcript_label = "DOM:bulletproof:v1"
```

All Bulletproof generators (G_vec, H_vec for the inner product argument) MUST be
derived deterministically from this label using:

```
G_vec[i] = hash_to_curve(DST=b"DOM:bp-G:v1", msg=u64_le(i))
H_vec[i] = hash_to_curve(DST=b"DOM:bp-H:v1", msg=u64_le(i))
```

Using the same hash-to-curve algorithm (Section 1) and SHA-256.

### 5.3 Proof Format

A non-aggregated Bulletproof for a single DOM output in range [0, 2^52), as
produced by the grin `secp256k1zkp` backend used by this codebase (via the
audited FFI shim with the custom H_DOM generator), serializes to exactly
675 bytes. `MAX_PROOF_SIZE = 768` is the consensus cap: it admits the 675-byte
proof with ~93 bytes of headroom while keeping malformed proof payloads bounded.

Proofs are NOT aggregated across outputs in DOM v1.0. Each output has one independent
range proof.

---

## 6. Summary of Changes to RFC-0001

| Issue | RFC-0001 (Before) | RFC-0009 (After) |
|---|---|---|
| H hash function | Unspecified | SHA-256 (explicit) |
| R in Schnorr challenge | "R_x" (ambiguous) | R_compressed 33 bytes SEC1 |
| MuSig2 nonce | Unspecified | HKDF-SHA256 deterministic |
| chain_id derivation | Undefined | Blake2b-256(magic \|\| genesis_hash) |
| chain_id in Noise | "reject invalid chain_id" | Noise prologue binding |
| Bulletproof H binding | Implied | Explicit (same H as commitments) |
| Kernel message format | Undefined | Blake2b-256(tag \|\| fields \|\| chain_id) |
