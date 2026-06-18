# DOM Protocol — Known Issues

## CRITICAL: Pedersen / Bulletproof commitment format mismatch

> **✅ RESOLVED — see the "Resolution" section below.** The H-generator
> unification + SEC1↔zkp bridge closed this (2026-05-15), and it remains
> resolved under the later Bulletproof migration (grin `secp256k1zkp`, custom
> H_DOM generator; commitments byte-identical to Pedersen). The "Open" status
> line that follows is the original point-in-time record.

**Status:** Open, blocks production use.
**Discovered:** May 2026, during Etapa 2 defensive integration.
**Severity:** Consensus-blocking.

### Symptom

`dom_crypto::pedersen::Commitment::commit(value, &r)` returns a 33-byte SEC1
compressed point (starts with 0x02 or 0x03).

`dom_crypto::bulletproof::prove(value, &r)` also returns 33 bytes, but in
secp256k1_zkp::PedersenCommitment format (starts with 0x08 or 0x09).

The two formats are not byte-equal. A TransactionOutput.commitment built
from Commitment::commit() cannot be verified by bp_verify() using the proof
from bp_prove(), and vice-versa.

### Reproduction

Add this test to crates/dom-crypto/src/bulletproof.rs and run
`cargo test -p dom-crypto pedersen_and_bulletproof_use_same_generator`:

  let r = BlindingFactor::random();
  let pedersen = Commitment::commit(1_000_000_000, &r);
  let (_, bp_bytes) = prove(1_000_000_000, &r).unwrap();
  assert_eq!(pedersen.as_bytes(), &bp_bytes);

Observed: left[0]=0x02, right[0]=0x08. Coordinates differ entirely.

### Root cause hypothesis

Pedersen H is derived via k256 + RFC 9380 with DST "DOM:h2c:secp256k1:v6.1".
Bulletproof H is derived via secp256k1_zkp::Generator::new_unblinded with
Tag::from(H_DOM_X). These two derivations may produce different points, or
the same point in different serialization formats.

### Why 45 dom-crypto tests pass

All tests exercise Pedersen and Bulletproof in isolation. No test crosses
the boundary by using bp_prove()'s commit output as a Commitment.

### Impact

Etapa 3 (miner produces signed coinbase + real range proof) cannot proceed.
Etapa 2 defensive keeps the node mining placeholder blocks in warn-only mode
so the bug does not crash anything, but no real transaction can be built.

### Resolution options

1. Migrate Commitment::commit() to use secp256k1-zkp (Grin's approach).
   ~50 call sites across 6 crates need review.
2. Write SEC1 ↔ zkp format converter. Smaller code change but undocumented
   zkp serialization makes it risky.
3. Reimplement Bulletproof in pure k256. Largest project.

Recommendation: Option 1. Mimblewimble standard is secp256k1-zkp for both.

### Do NOT



### Resolution

**Date:** 2026-05-15  
**Status:** ✅ RESOLVED

**Root Cause:**  
Divergent H generator implementation between Pedersen (k256 via hash2curve) and Bulletproof (secp256k1-zkp via `Tag::from`). `Tag::from(H_DOM_X)` re-derives via hash instead of reconstructing the point from X, producing a different generator.

**Solution Phase 1 — H Generator Unification:**  
Modified `dom_generator()` in `bulletproof.rs` to use `Generator::from_slice(&[0x0a, H_DOM_X])` instead of `Tag::from(H_DOM_X)`. This reconstructs the canonical H point that matches Pedersen's k256-derived generator.

**Validation Phase 1:**  
X coordinates now match byte-for-byte between Pedersen and Bulletproof commitments. Test `pedersen_and_bulletproof_use_same_generator` validates mathematical equivalence.

**Solution Phase 2 — SEC1↔zkp Format Bridge:**  
Implemented `sec1_to_zkp()` and `zkp_to_sec1()` conversion functions (~70 lines) using `k256::FieldElement::sqrt()` as is_square oracle. The zkp format encodes `is_square(y)` in the prefix (0x08/0x09), while SEC1 encodes y-parity (0x02/0x03). These properties are mathematically independent on secp256k1, requiring point reconstruction with validation.

**Key Technical Findings:**
- y-parity (even/odd) and is_square (quadratic residue) are independent properties: 50/50 distribution, no correlation
- `k256::FieldElement::sqrt()` provides perfect is_square oracle: 0/100 mismatches in empirical tests
- Loop in `zkp_to_sec1` is mathematically necessary: zkp doesn't expose Y parity, so both SEC1 prefixes must be tested against is_square validation

**Validation Phase 2:**  
200/200 roundtrip tests pass (100 SEC1→zkp→SEC1, 100 zkp→SEC1→zkp). Full workspace: 203/203 tests. Clippy clean. No new production dependencies (only `expose-field` feature flag for k256).

**Files Modified:**
- `bulletproof.rs`: `dom_generator()`, `sec1_to_zkp()`, `zkp_to_sec1()`, `prove()`, `verify()`
- `Cargo.toml`: added `expose-field` feature to k256
- Test additions: 2 roundtrip tests, 1 regression test

---
- Do not launch testnet until resolved.
- Do not change H_COMPRESSED_FINAL in h_generator.rs (consensus-critical).
- Do not partial-fix (sign without fixing format) — produces silently invalid
  blocks.

## ibd_two_node t1/t7: RandomX-throughput timeouts + serial SIGSEGV (PRE-EXISTING)

**Status:** Open, low priority. Test-harness/hardware issue, NOT a protocol bug.
**Discovered:** 2026-06-17, during the Bulletproof migration (Phase 2, sub-step 5b).
**Severity:** Flaky integration test on resource-constrained machines. Does not
affect consensus, node, or wallet correctness.

### Symptom

In `crates/dom-integration-tests/tests/ibd_two_node.rs`, two tests intermittently
fail with timeouts (never a logic/range-proof error — block height advances
steadily, just not fast enough):

- `t1_ibd_through_randomx_epoch_boundary_via_three_real_nodes` — must mine past
  the RandomX seed boundary (height 2060) within a 300s budget.
- `t7_ibd_restart_resume_after_interruption` — must mine ~200 blocks across a
  restart within its budget.

Under full `cargo test --workspace` parallelism, `t2`/`t3` can also time out from
CPU contention. Additionally, the `ibd_two_node` binary has been observed to
crash with **SIGSEGV (signal 11)** when run serially (`--test-threads=1`) under
sustained heavy native RandomX load.

### Root cause

These tests perform **real RandomX proof-of-work mining** of many blocks. RandomX
is deliberately memory-hard and slow; this machine sustains only ~1.9 blocks/s,
so 2060 blocks (t1) / 200 blocks (t7) cannot be produced within the 300s test
budgets. The failures are CPU/throughput-bound, not algorithmic.

### Proven PRE-EXISTING and orthogonal to the Bulletproof migration

- Reproduced on `main` (commit 1c143ad, borromean — none of the bp2 changes
  present): `t1` fails the same way and the binary SIGSEGVs under `--test-threads=1`.
- The bp2 range proof is **faster** than borromean (measured ~34.8 ms vs ~67.7 ms
  per prove+verify), so the migration cannot have caused or worsened mining time.
- All failures are timeouts with valid proofs (height advances; zero
  "range proof verification failed"). `t2/t3/t4/t5/t6` pass in isolation.

### Mitigation / how to run

- Run the heavy IBD tests in isolation with adequate CPU, e.g.
  `cargo test -p dom-integration-tests --test ibd_two_node` on a machine that can
  sustain the required RandomX block rate; or raise/parameterize the per-test
  height targets and timeouts for CI hardware.
- Investigate the serial SIGSEGV separately (likely native RandomX/dataset
  memory pressure under back-to-back runs) — tracked here, not yet root-caused.

### Do NOT

- Do not attribute these timeouts to the range-proof backend — they predate it.
- Do not "fix" by weakening any range-proof or consensus assertion.
