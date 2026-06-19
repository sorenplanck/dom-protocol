# DOM RFC-0009 — Proof of the SEC1 ↔ zkp `is_square` Equivalence (AUDIT-002)

**Status:** Complete (proven for the stated domain, modulo the standard
number-theory facts explicitly INVOKED in §6).
**Scope:** Closes AUDIT-002 — the open item that the SEC1↔zkp commitment bridge
and its `is_square` oracle were *evidenced* (1000+ random samples, zero
mismatches) but not *proven*.
**Companion (machine-checkable):** `crates/dom-crypto/tests/is_square_equivalence_proof.rs`.

This document proves that DOM's `is_square` oracle (`k256` square root) computes
exactly the same predicate the grin/libsecp256k1-zkp Pedersen-commitment
serializer uses (`is_quad_var`), and that the resulting SEC1↔zkp bridge is a
bijection on valid secp256k1 points. Production code is unchanged; the bridge
already satisfied this equivalence — this proof confirms it. (Scope: this proves
the encoding equivalence/bijection only; it is not a claim that the range-proof
system as a whole is sound or secure.)

---

## 1. Objects, notation, and the exact domain `E`

- `p = 2^256 − 2^32 − 977` — the secp256k1 base-field prime (SEC2 §2.4.1). Its
  byte form ends `… FE FF FF FC 2F`. **`p` being prime is INVOKED** (I4, §6).
- `GF(p)` — the prime field. For `a ∈ GF(p)`, *`a` is a square* means
  `∃ z ∈ GF(p): z² ≡ a (mod p)`. By convention `0` is a square (`z = 0`).
- secp256k1: `y² = x³ + 7` over `GF(p)`, a cyclic group of **odd prime order `n`**.
  Because the order is odd, the group has **no element of order 2**, so **no curve
  point has `y = 0`**.
- **Domain `E`** (the set the bridge operates on, and over which we prove):
  `E := { (x, y) ∈ GF(p)² : y² = x³ + 7 }`, i.e. all affine secp256k1 points
  (compressed-serializable; the point at infinity has no 33-byte commitment form
  and is out of scope). Note `y ≠ 0` for every `P ∈ E`.

Three single-bit functions on a point `P = (x, y)`, each emitting a prefix byte
followed by the 32-byte big-endian `x`:

| name | prefix byte | defined by |
|---|---|---|
| `enc_sec1(P)` | `0x02 + (y mod 2)` | SEC1 compressed (y-parity) |
| `enc_zkp(P)`  | `0x09 ^ is_quad_var(y)` | libsecp/grin Pedersen serializer (`commitment/main_impl.h:41,74`) |
| DOM oracle `isq_DOM(y)` | `0x08` if square else `0x09`, i.e. `0x09 ^ isq_DOM(y)` | `sec1_zkp_bridge.rs:34-43` (`k256 FieldElement::sqrt(y).is_some()`) |

`is_quad_var(y) ∈ {0,1}` is the libsecp predicate (`field_impl.h:290`);
`isq_DOM(y) ∈ {true,false}` ≅ `{1,0}` is DOM's. The bridge produces the zkp prefix
as `0x09 ^ isq_DOM(y)` and the library produces it as `0x09 ^ is_quad_var(y)`, so
the two encodings coincide **iff** `isq_DOM ≡ is_quad_var` — Lemma **C1**.

> **Crucial non-claim.** The bridge does **not** assert "`y`-parity ⇔ is_square".
> That is *false*: `enc_sec1` and `enc_zkp` label the two points sharing an `x` by
> *different* rules (parity vs. quadratic residuosity). The `fixed_vectors` test
> (`sec1_zkp_bridge.rs:118`) exhibits SEC1 `0x03` mapping to *both* zkp `0x08` and
> `0x09`. Correctness comes from each direction reconstructing the real point and
> recomputing the target predicate — proven below — not from any parity↔QR law.

---

## 2. The three lemmas

- **C1 (oracle equivalence).** `∀ y ∈ GF(p): isq_DOM(y) = is_quad_var(y)`, and both
  equal the indicator `[y is a square in GF(p)]`.
- **C2 (`−1` is a non-residue).** `−1` is a quadratic non-residue mod `p`.
  Equivalently, `∀ P=(x,y) ∈ E: is_quad_var(y) ≠ is_quad_var(p − y)`.
- **C3 (bijection / round-trip).** On `E`, `sec1_to_zkp = enc_zkp ∘ parse` and
  `zkp_to_sec1 = enc_sec1 ∘ parse` are total and mutually inverse:
  `zkp_to_sec1(sec1_to_zkp(enc_sec1(P))) = enc_sec1(P)` and
  `sec1_to_zkp(zkp_to_sec1(enc_zkp(P))) = enc_zkp(P)` for all `P ∈ E`.

---

## 3. Lemma C1 — `isq_DOM == is_quad_var == [y is a square]`

### 3.1 The square-root addition chain computes `y^((p+1)/4)` (DERIVED)

Both `k256::FieldElement::sqrt` (`k256-0.13.4/.../field.rs:222-235`) and libsecp's
`secp256k1_fe_sqrt` (`grin_secp256k1zkp-0.7.15/depend/secp256k1-zkp/src/field_impl.h:56-128`)
run the **operation-for-operation identical** addition chain (`pow2k(e,k)` = `k`
squarings = exponent `·2^k`; `mul` = exponent `+`). Tracking exponents:

```
x2   = (1<<1)+1                       = 3        = 2^2  − 1
x3   = (x2<<1)+1                       = 7        = 2^3  − 1
x6   = (x3<<3)+x3, x9=(x6<<3)+x3, x11=(x9<<2)+x2 = 2^6−1, 2^9−1, 2^11−1
x22  = (x11<<11)+x11                              = 2^22 − 1
x44,x88,x176 = doubling-merge of the previous     = 2^44−1, 2^88−1, 2^176−1
x220 = (x176<<44)+x44                              = 2^220 − 1
x223 = (x220<<3)+x3                                = 2^223 − 1
res  = (((x223<<23)+x22)<<6 + x2) << 2
```

The final exponent is **`E = ((((2^223−1)·2^23 + 2^22−1)·2^6 + 3)·2^2)`**, and

```
E == (p+1)/4         (bit-exact: both 0x3fff…bfffff0c)
```

`(p+1)/4` is a 254-bit integer whose binary 1-blocks have lengths exactly
`{223, 22, 2}` — matching the chain's three blocks. The companion test
*computes `E` by replaying the chain in the exponent domain and asserts
`E == (p+1)/4`* (it does not restate this prose). So `res = y^((p+1)/4)`. **(D1)**

### 3.2 `isq_DOM(y) = [y is a square]` (DERIVED + INVOKED)

`k256` returns `Some` iff `res² == y` (`field.rs:237`:
`is_root = (y − res²).normalizes_to_zero()`). With `res = y^((p+1)/4)`:

```
res² = y^((p+1)/2) = y · y^((p−1)/2).
```

- For `y = 0`: `res = 0`, `res² = 0 = y` ⇒ `isq_DOM(0) = true`.
- For `y ≠ 0`: **by Euler's criterion (INVOKED, I1)** `y^((p−1)/2) ∈ {1, −1}`,
  equal to `1` iff `y` is a QR. Hence `res² = y ⇔ y^((p−1)/2) = 1 ⇔ y is a QR`.

Therefore `isq_DOM(y) = [y is a square]` for all `y ∈ GF(p)`. **(Part A)**

### 3.3 `is_quad_var(y) = [y is a square]` — the load-bearing `num_jacobi` step

`enc_zkp` is the **consensus encoder** (`commitment/main_impl.h:41,74`:
`output[0] = 9 ^ secp256k1_fe_is_quad_var(&ge.y)`). `is_quad_var` has two build
branches (`field_impl.h:290`); **both** compute `[y is a square]`:

**Default (GMP) branch — `return secp256k1_num_jacobi(y, p) >= 0`.** This is the
path the prose previously only gestured at, so we make it explicit:

1. `secp256k1_num_jacobi(y, p)` is GMP's `mpz_jacobi(y, p)` (`num_gmp_impl.h`):
   the **Jacobi symbol** `(y | p)`.
2. **INVOKED (I2):** for a *prime* lower argument `p`, the Jacobi symbol equals
   the **Legendre symbol** `(y / p)`.
3. **INVOKED (I1, Euler/definition of Legendre):** `(y / p) = +1` if `y` is a
   nonzero QR, `−1` if a QNR, `0` if `y ≡ 0`.
4. Hence `is_quad_var(y) = [ (y|p) ≥ 0 ] = [ y is a nonzero QR ∨ y ≡ 0 ] =
   [y is a square]`. **(Part B-default)**

This is a genuinely *different algorithm* from §3.2 (Jacobi recursion, not a
field exponentiation) — C1 is closed by reducing **both** sides to the common
predicate `[y is a square]` via Euler's criterion, **not** by observing that two
square-root routines look alike.

**`#else USE_NUM_NONE` branch — `return secp256k1_fe_sqrt(&r, y)`.** This is the
*same* `secp256k1_fe_sqrt` analysed in §3.1–3.2 (same `(p+1)/4` chain, same
`r² == y` check), hence `= [y is a square]`, hence identical to `isq_DOM`. So C1
holds **regardless of grin's build configuration**. **(Part B-nonum)**

### 3.4 C1 conclusion

Part A gives `isq_DOM(y) = [y is a square]`; Part B (either branch) gives
`is_quad_var(y) = [y is a square]`. Therefore

```
∀ y ∈ GF(p):  isq_DOM(y) = is_quad_var(y).            ∎ (C1)
```

**Representation note.** Both predicates consume the canonical reduced
representative `y ∈ [0, p)`: `k256::FieldElement::from_bytes` reads 32 big-endian
bytes and rejects `y ≥ p`; libsecp calls `secp256k1_fe_normalize_var` before use.
The bridge feeds `y` from a parsed valid point
(`sec1_zkp_bridge.rs:51-52`, `pk.serialize_uncompressed()[33..65]`), so `y < p`
always and the `.expect` at `bridge.rs:35-36` cannot fire. No endianness or
non-canonical-representative gap exists.

---

## 4. Lemma C2 — `−1` is a quadratic non-residue mod `p`

- **DERIVED (D2):** `p ≡ 3 (mod 4)` for secp256k1's `p` (companion asserts
  `(p+1) % 4 == 0`; equivalently the last byte `0x2F = 47 ≡ 3 mod 4`). Hence
  `(p−1)/2` is **odd**.
- **INVOKED (I1):** `−1` is a square mod `p` ⇔ `(−1)^((p−1)/2) ≡ 1`. Since
  `(p−1)/2` is odd, `(−1)^((p−1)/2) = −1 ≢ 1`. So **`−1` is a QNR**. **(D3;**
  companion asserts `modpow(p−1, (p−1)/2, p) == p−1`**)**
- **INVOKED (I3, Legendre multiplicativity):** `(−y / p) = (−1 / p)·(y / p) =
  −(y / p)`. For `P ∈ E` we have `y ≠ 0`, so `(y/p) = ±1` and therefore
  `(−y / p) = −(y / p)`: of the two points `(x, y)` and `(x, p−y)` sharing an `x`,
  **exactly one** is a QR. Via C1, `is_quad_var` distinguishes them:
  `is_quad_var(y) ≠ is_quad_var(p − y)`. ∎ (C2)

---

## 5. Lemma C3 — the bridge is a bijection (round-trip identity)

Fix `P = (x, y) ∈ E`; its negation is `P' = (x, p − y) ∈ E`. `enc_sec1(P)` and
`enc_zkp(P)` carry the **same** 32-byte `x`.

**`sec1_to_zkp(enc_sec1(P)) = enc_zkp(P)`.** `sec1_to_zkp`
(`bridge.rs:48-56`) parses `P` from its SEC1 bytes (the prefix fixes `y` by
parity), reads the true `y`, and emits prefix `0x09 ^ isq_DOM(y)`. By **C1** this
equals `0x09 ^ is_quad_var(y) = enc_zkp(P)[0]`; `x` is copied unchanged. ∎

**`zkp_to_sec1(enc_zkp(P)) = enc_sec1(P)`.** `zkp_to_sec1` (`bridge.rs:65-85`)
takes the zkp prefix `b = 0x09 ^ is_quad_var(y)` and tries SEC1 prefixes
`{0x02, 0x03}`. Each yields a candidate point; the two candidates are exactly `P`
(parity of `y`) and `P'` (parity of `p−y`) — and since `x` is a valid abscissa,
both parse. It returns the candidate whose `0x09 ^ isq_DOM(candidate_y) = b`.
By **C2** (one match) and **C1**, exactly one candidate satisfies this, and it is
the one with `is_quad_var(candidate_y) = is_quad_var(y)`, i.e. `P` itself. Thus the
returned prefix is `enc_sec1(P)[0]`; `x` unchanged. ∎

**Round-trip.** Composing:
`zkp_to_sec1(sec1_to_zkp(enc_sec1(P))) = zkp_to_sec1(enc_zkp(P)) = enc_sec1(P)`,
and symmetrically `sec1_to_zkp(zkp_to_sec1(enc_zkp(P))) = enc_zkp(P)`. So the two
maps are mutually inverse bijections `E ↔ E` on the encoding sets. **(D6)** ∎ (C3)

---

## 6. What is DERIVED vs what is INVOKED (read this before trusting the proof)

The proof does **not** stand on self-evidence. It rests on a small, explicit set
of standard facts. An auditor must see exactly which.

**DERIVED here (proven in this document and re-checked computationally by the
companion test):**

- **D1** — the `k256`/libsecp square-root addition chain has exponent exactly
  `(p+1)/4` (bit-exact, computed by replaying the chain).
- **D2** — `p ≡ 3 (mod 4)` for secp256k1's actual `p` (`(p+1) % 4 == 0`).
- **D3** — `−1` is a QNR mod `p` (`(−1)^((p−1)/2) ≡ p − 1`).
- **D4** — `isq_DOM(y) = [ (y^((p+1)/4))² == y ]` (from k256's source predicate).
- **D5** — the `#else` `is_quad_var` branch is the *same* routine as `isq_DOM`.
- **D6** — the C3 round-trip identity, given C1 + C2.

**INVOKED as known (classical number theory / standard library correctness — NOT
re-proven here):**

- **I1 — Euler's criterion:** for prime `p` and `a ≢ 0`,
  `a^((p−1)/2) ≡ ±1 (mod p)`, with `+1` iff `a` is a quadratic residue.
- **I2 — Jacobi = Legendre for prime modulus:** `(a | p) = (a / p)` when `p` is
  prime.
- **I3 — Legendre multiplicativity:** `(ab / p) = (a / p)(b / p)`.
- **I4 — `p` is prime** (secp256k1's standardized field prime; not re-verified).
- **I5 — arithmetic correctness of the underlying primitives:** GMP's `mpz_jacobi`
  correctly computes the Jacobi symbol, and `k256`/libsecp field `mul`/`sqr`
  correctly implement `GF(p)` arithmetic. This is the same trust base every use of
  these libraries already assumes. The companion test exercises the **real**
  `k256::FieldElement::sqrt`, giving direct empirical assurance of I5 for the DOM
  side over a structured set including edge values.

The equivalence is therefore **proven over `E`, conditional on I1–I5**. There is
no hidden gap between D1–D6 and the conclusion; the only external dependencies are
the four textbook facts I1–I4 and the primitive-arithmetic correctness I5.

---

## 7. Domain assumption and where consensus relies on this

- **Domain.** C1 is proven for all of `GF(p)`; C2/C3 for all of `E` (valid curve
  points). **Malformed inputs are out of scope** and never reach the oracle: they
  are rejected upstream by parse-rejection — `Secp256k1PublicKey::from_slice`
  (`bridge.rs:49`) in `sec1_to_zkp`, and `PedersenCommitment::from_slice`
  (`bridge.rs:69`) in `zkp_to_sec1`. The `y = 0` algebraic edge is handled
  consistently by both oracles (both → `0x08`) but is **vacuous**: no secp256k1
  point has `y = 0` (§1).
- **Consensus reliance (call sites).** The bridge is the single source of truth
  for both range-proof backends; the **consensus-active** path is bp2
  (`crate::bulletproof_bp`, exported as `bp2_prove`/`bp2_verify`, `lib.rs:41`):
  - `bp2_verify` → `sec1_to_zkp(commitment_sec1)` at
    **`crates/dom-crypto/src/bulletproof_bp.rs:480`** — converts the SEC1
    commitment stored in a `TransactionOutput` into zkp form for grin's verifier.
  - `bp2_prove` / `bp2_prove_with_nonce` → `zkp_to_sec1` at
    `bulletproof_bp.rs:417` / `:458` — canonicalize grin's commitment to SEC1 for
    output/coinbase commitments.
  - Legacy borromean path (`crate::bulletproof`, same bridge, not consensus-wired):
    `bulletproof.rs:179`, `:218`, `:277`.

  Conditional on C1–C3 (hence on I1–I5), the commitment a verifier reconstructs
  (`sec1_to_zkp`) is byte-identical to the one the prover/coinbase emitted
  (`zkp_to_sec1`), for every valid point — so a validly-generated proof is never
  rejected for an encoding-prefix mismatch, and the encoding is injective (two
  distinct valid points never share a SEC1/zkp encoding). This is a statement
  about the encoding layer only — it is not a soundness claim about the range
  proof itself.

---

## 8. Companion test (reproducible / auditable)

`crates/dom-crypto/tests/is_square_equivalence_proof.rs` (test-only; no production
code) computationally verifies the DERIVED facts:

- **(a)** replays the addition chain in the exponent domain and asserts the
  built exponent `== (p+1)/4` (D1), plus each block `xN == 2^N − 1`;
- **(b)** `(p+1) % 4 == 0` (D2);
- **(c)** `(−1)^((p−1)/2) ≡ p − 1` mod `p` — `−1` is a QNR (D3);
- **(d)** the **real** `isq_DOM` (`k256::FieldElement::sqrt(a).is_some()`) agrees
  with Euler's criterion `[a^((p−1)/2) == 1]` on a structured set including
  `0`, `1`, `p−1`, `(p−1)/2`, known QRs (`b²`) and QNRs (I5 assurance for k256 +
  empirical C1 for the DOM oracle).

A reader who accepts I1–I5 and reruns the companion has a complete, reproducible
verification.
