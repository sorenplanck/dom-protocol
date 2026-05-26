# DOM — Constant-Time Audit (Phase 2.3)

Status: snapshot 2026-05-25 after Phase 2.3 hardening.

## Threat model

Side-channel attackers who can observe wall-clock time, instruction
counts, or cache-miss patterns of `dom-crypto` operations that touch
secret material. The relevant attack vectors:

* **Signing-side timing leak** of the RFC6979 nonce or the secret key
  scalar `k + c*sk`.
* **Verification-side timing leak** of a parsed scalar — *not* a
  threat for DOM because verification inputs are public, but the
  same helpers are reused on the signing side.
* **Pedersen commit timing leak** of the blinding factor or value.

## Layer-by-layer stance

| Layer | Implementation | CT claim | Source |
|---|---|---|---|
| Scalar arithmetic | `k256::Scalar` add / mul | constant-time | k256 docs ("All scalar/field operations are constant-time") |
| Point arithmetic | `k256::ProjectivePoint` + secp256k1 | constant-time | k256 + libsecp256k1 docs |
| `secp256k1::SecretKey` operations | libsecp256k1 (C) | constant-time | libsecp256k1 README |
| HMAC-SHA256 (RFC6979 nonce derivation) | `hmac` + `sha2` crates | constant-time per RustCrypto docs | `hmac::Hmac` |
| SEC1 point encoding | `k256::EncodedPoint::compress()` | constant-time over secret-derived points | k256 |
| DOM `is_scalar_valid` (zero + < n check) | **Pre-Phase-2.3: NOT CT** — see below. **Post-fix: CT via `subtle`.** | Hardened in commit 26ded50 + this commit | `crates/dom-crypto/src/schnorr.rs` |
| DOM `bytes_lt` (256-bit BE compare) | **Pre-Phase-2.3: NOT CT** — short-circuit on first differing byte. **Post-fix: CT via per-byte `Choice` accumulator.** | Hardened in this commit | same |

## Findings & fixes

### F1 — `is_scalar_valid` short-circuit (HARDENED)

**Pre-fix code:**
```rust
fn is_scalar_valid(bytes: &[u8; 32]) -> bool {
    if bytes.iter().all(|&b| b == 0) {
        return false;
    }
    bytes_lt(bytes, &SECP256K1_N)
}
```

`bytes.iter().all(|&b| b == 0)` returns as soon as it finds a
non-zero byte, leaking the position of the first non-zero byte. For
a uniformly random 32-byte scalar this gives the high-byte distribution
across timing.

**Impact:** The same helper is used inside `rfc6979_nonce`'s
rejection-sampling loop. The candidate nonce `v` is HMAC-derived
from `(secret_key, message_hash)`. An attacker measuring the timing
of `is_scalar_valid(&v)` for the accepted nonce learns its high-byte
shape, which directly biases the lattice attack on `s = k + c*sk`
recovery. Over `O(2^32)` signatures, this is a known precondition
for full-key recovery.

**Fix:** Replaced both the zero-check (now `bytes_eq_zero_ct` using
`subtle::ConstantTimeEq::ct_eq` over the full 32-byte buffer) and
the `bytes_lt` byte-compare (now `bytes_lt_ct` accumulating `Choice`
across all 32 byte positions without short-circuit).

### F2 — `bytes_lt` early-return loop (HARDENED — same commit as F1)

**Pre-fix code:**
```rust
fn bytes_lt(a: &[u8; 32], b: &[u8; 32]) -> bool {
    for i in 0..32 {
        if a[i] < b[i] { return true; }
        if a[i] > b[i] { return false; }
    }
    false
}
```

Variable iteration count depending on the byte position of the
first divergence — same timing-leak class as F1, exploited via the
same RFC6979 path.

**Fix:** see F1.

## Residual concerns / explicit deferrals

* **Empirical CT validation via `ctgrind` / `dudect`** — both
  tools require a non-trivial environment (Valgrind + Cachegrind
  for ctgrind, statistical timing harness for dudect). These are
  tracked under RB-CT-INSTRUMENTATION in RELEASE_BLOCKERS; the
  current Phase 2.3 commit relies on static review + the upstream
  CT claims of `k256`, `libsecp256k1`, and `subtle`. A regression
  in any of those upstream crates is detected indirectly by the
  Phase 2.1 differential tests.

* **Cache-side-channel resistance** is OUT OF SCOPE for Phase 2.3.
  Mitigation against cache-timing attacks requires either constant-memory-pattern
  algorithms or hardware mitigation (Intel CET / equivalent); both
  are upstream-library concerns, not DOM-specific code.

* **Power analysis / EM emanation** is OUT OF SCOPE — DOM nodes
  run on commodity hardware in operator-controlled environments.

## What is NOT yet hardened

None as of Phase 2.3 — the F1 / F2 issues were the only DOM-specific
non-CT code in the signing or commitment path. The Phase 2.3 audit
covers `dom-crypto::schnorr`, `dom-crypto::pedersen`,
`dom-crypto::keys`, and `dom-crypto::bulletproof`. The wallet's
HD-derivation paths use `secp256k1::SecretKey::add_tweak` which
libsecp256k1 documents as constant-time.

## Confidence

* **Confirmed (post-fix):** `is_scalar_valid` and `bytes_lt` no longer
  short-circuit. The 89-test dom-crypto suite continues to pass
  after the change, so the CT rewrite is functionally equivalent.
* **Likely:** End-to-end CT of `schnorr_sign` and `Commitment::commit`,
  given the upstream CT claims plus the F1/F2 fix. The path is
  audit-traceable; no remaining DOM-specific non-CT code on the
  signing surface.
* **Theoretical until empirical instrumentation runs:** absolute
  CT across all microarchitectural channels. The `ctgrind` /
  `dudect` campaigns (Phase 8.2 fuzzing-window candidate) are the
  empirical confirmation.
