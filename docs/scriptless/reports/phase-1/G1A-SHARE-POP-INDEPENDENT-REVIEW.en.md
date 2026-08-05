# G1a Share PoK independent review — authority-input conflict report

Date: 2026-08-05  
Starting DOM revision: `67fe11c441c2b7801b6f70809ab58caa4804c22a`  
Independent pre-comparison anchor: `fce85fa7af614ed8d99419045ea3fb5ce26981e2`  
Disposition: **STOP — the frozen reference selected a lower-precedence source;
no production-code divergence was found**

> **WARNING: PUBLIC AND INSECURE TEST VECTORS ONLY.** Every scalar, nonce,
> point, and proof discussed here is deliberately public test material. It
> MUST NEVER be used for production keys, nonces, wallets, funds, signing, or
> randomness.

## Executive result

The independence barrier was real: the Python reference, three positive
vectors, 20 negative mutations, and expected bytes were committed before
`crates/dom-adaptor/src/share_pop.rs`, its Rust tests, or any Share PoK output
was inspected. The final clean pre-comparison tree is commit
`fce85fa7af614ed8d99419045ea3fb5ce26981e2`, committed at
`2026-08-05T07:38:48-03:00`.

That frozen reference is not conformant. It followed Master Specification
v1.0 section 4.2's 196-byte body and its unresolved `H_to_scalar` wording.
After the barrier, a separately stored, higher-precedence signed record was
identified:

```text
/home/leonardov/dom-scriptless-dev/dom-contracts/docs/specifications/normative/
NAR-DC-P1-001-omnibus-gap-closure.en.md
```

The record's valid detached Minisign signature makes its express assignments
effective under its §§1, 13, and 14, despite the pre-signing status text left
in the signed document header. Its §§5.1–5.5 explicitly freeze the second
challenge tag, 202-byte `DSPO` framing, prefix selectors, `u32_le` retry
counter, nonzero statement digests, and zero-inclusive response scalar.
Production follows those assignments byte for byte.

Therefore:

- the byte comparison correctly stops at its first mismatch;
- the mismatch is **not** evidence of a production defect;
- it is evidence that the independent run received or selected an incomplete
  authority set;
- the frozen files are retained unchanged as negative provenance evidence;
- they must not be promoted as conformance vectors; and
- a new genuinely independent run, starting with NAR-DC-P1-001, is still
  required to close the Share PoK independent-vector gate.

## Authority and provenance

| Artifact | SHA-256 / verification | Use in this review |
|---|---|---|
| NAR-002 Phase 1 omnibus closure in the starting DOM tree | `b726c2e576833f843d0065a1e823e649ab9e7e28fd9cfedb0e6e06e6b1be87f5`; Minisign verified | Read before the barrier |
| NAR-001 Phase 1 assignment from `test/phase-1-independent-vectors-ratified` | `eee087c808aeb4e6e745a5311d17ca5a63c5b5e5568218d20b1cbcdd7b6206dc`; Minisign verified | Read before the barrier |
| Master Specification v1.0 controlled DOCX | `5ad366d6b5c01c88bc88d4e9c016b447c32f24fbc24a32fa8b6946d7ff5dd6b5` | Lower-precedence Share PoK §4.2 used by the frozen reference |
| Signed two-nonce input-only fixture | `55642208968863a7b2c4773a82d9774f95f2a3b604b80a876d0bf031396b2a7d`; Minisign verified | Public test scalar and participant inputs |
| Authoritative DOM `H_tag` | `crates/dom-crypto/src/hash.rs::blake2b_256_tagged` | Read before the barrier |
| NAR-DC-P1-001 | `88586449d577038ac98e9463250821ed9b3d1e6c94f5b11abfaf036a93eec655`; Minisign verified | Higher-precedence Share PoK assignment discovered after the barrier |
| NAR-DC-P1-001 signature | `2f19ec266f05e440cb5de2b91bc4295b93b2629170adbf6d020505ebb2311ffc` | Trusted comment timestamp `1785904289` (`2026-08-05T01:31:29-03:00`) |

The NAR-DC signature predates the independent freeze by approximately six
hours. It was not a later rule change. The starting DOM tree does not contain
that record, and its NAR-002 copy does not identify NAR-DC-P1-001. The record
was located after comparison in the separate `dom-contracts` repository.
NAR-DC-P1-001 §12.1 itself requires importing the signed record into the
normative amendments directory before dependent implementation work. This
distribution/source-discovery break is the process cause of the conflict.

## Independence timeline

1. The worktree was clean on branch `evidence/share-pop-independent-v1` at
   exact head `67fe11c441c2b7801b6f70809ab58caa4804c22a`.
2. NAR-002, its detached signature, NAR-001, the controlled Master
   Specification block, signed input-only fixtures, the DOM `H_tag` function,
   and public secp256k1 constants were inspected. Production Share PoK remained
   unopened and unsearched.
3. Commit `565d779482949c6727500eb9a331d2b76fb12ed5` at
   `2026-08-05T07:38:00-03:00` first froze the generator and expected outputs.
4. Commit `fce85fa7af614ed8d99419045ea3fb5ce26981e2` at
   `2026-08-05T07:38:48-03:00` removed an accidentally staged Python bytecode
   cache, added ignore rules, and became the final clean pre-comparison anchor.
   No reference formula or expected output changed in that cleanup.
5. Only after `fce85fa…` was recorded was production Share PoK opened.
6. Production first diverged from the frozen reference at statement byte zero.
7. NAR-DC-P1-001 was then supplied from the separate authoritative repository,
   its file hashes and detached signature were independently verified, and the
   result was reclassified from suspected production drift to an
   authority-input conflict.

The frozen pre-comparison manifest is:

```text
MANIFEST.sha256 file SHA-256:
6a2308121c15a285c1b9d7b01dbbe16c55c02ca267483361a60e906028514d3b

expected_outputs_v1.json SHA-256:
cd6d1d44d2a6d397b82aedb7142092aa04b93834f3b45af430ae515da74c847c
```

## Exact comparison

The first positive case, `SP1-initiator-index-zero`, establishes the first
divergence and all downstream consequences:

| Intermediate | Frozen lower-precedence reference | NAR-DC / production | Result |
|---|---|---|---|
| Statement | 196 bytes; begins `aaaaaaaaaaaa…` | 202 bytes; begins `4453504f0100…` (`DSPO || 0100`) | Mismatch at byte 0; STOP |
| Complete context-tag input | 225 bytes | 231 bytes | Mismatch at byte 29, the first statement byte |
| Share point `R_i` | `02989c0b76cb5639…96e05f6f` | same | Match |
| Context digest | `18c3c11127134035…26fc5302` | `b2c2e4fc0c02030f…c664d9e9` | Mismatch |
| PoK nonce point `A` | `0256b328b30c8bf5…2b2920967` | same | Match |
| Challenge preimage | `context_ref || R_i || A` | `context_prod || R_i || A` | Mismatch at byte 0 |
| First digest | `293c151938bddf2f…82e6c7ac` | `fc9924d40d75aac6…b38a84b3` | Mismatch |
| Second digest | `b3d34868cf137d2b…fc4be4b7` | `cd8df03f9fb6aede…f418837a` | Mismatch |
| Wide digest | reference digests above | production digests above | Mismatch |
| Reduced challenge | `8d4daba232355fc6…d1744fa8` | `6fee39639915d2d7…5fab4804` | Mismatch |
| Response `z` | `f66f77e2f504e9ef…51e32567` | `92b6ee062370b0e4…d7491c90` | Mismatch |
| Proof | commitment matches, response differs | commitment matches, response differs | First mismatch at proof byte 33 |
| Native verification | accepted under frozen profile | accepted through production API | Both internally valid |
| Cross-profile verification | production proof rejected under frozen profile | frozen proof rejected under production profile | Correctly rejected |

`SP2-responder-index-one` has the same field-level result. The frozen `SP3`
case deliberately uses an all-zero terms hash; the lower-precedence reference
accepted it, while NAR-DC §5.2 and production reject it before statement
construction.

The checked JSON records every full byte string and first differing offset in:

- `test-vectors/scriptless/share-pop/independent-v1/production_trace_v1.json`;
- `test-vectors/scriptless/share-pop/independent-v1/comparison_results_v1.json`.

## Production-to-authority review

The inspected production implementation matches NAR-DC-P1-001 §§5.1–5.5 on
every assigned item:

| Assigned item | Production result |
|---|---|
| Context tag | Exact `DOM:scriptless-share-pop:v1` |
| Challenge tag | Exact `DOM:scriptless-share-pop-challenge:v1` |
| Statement magic/version/length | Exact `DSPO || 0100`, 202 bytes |
| Statement offsets | Exact offsets 6, 38, 70, 102, 103, 105, 138, and 170 |
| Context digest | DOM `H_tag(context_tag, statement_202)` |
| Challenge input | Exact `context_32 || R_33 || A_33 || counter_u32_le` |
| Digest halves | Exact prefix bytes `0x00` and `0x01` under the challenge tag |
| Scalar mapping | Exact 512-bit big-endian reduction with checked retry on zero |
| Proof codec | Exact 65-byte `A_33 || z_be32` |
| Response domain | Canonical `[0,q-1]`, including zero |
| Verification | Authoritative `zG == A + cR_i` boundary |
| Fixed-field policy | Nonzero chain, session, participant, terms, and recovery binding |
| Roster policy | 2–16, strict order, no duplicates, index in range |

No production source file was changed.

## Negative and mutation results

The frozen reference records 20 exact negative mutations. All are rejected by
that profile. Because every frozen statement is 196 bytes, production rejects
each combined statement/proof case first at its exact 202-byte statement
length boundary. Proof-only parser classifications agree on wrong length,
malformed announcement, and response `>= q`. One intentional profile mismatch
is preserved: mutation `M15-response-zero` is rejected by the frozen reference
but accepted by the production proof codec, exactly as NAR-DC §5.5 requires;
the zero-response proof still fails the equation for this fixture.

## Reproduction and executed checks

From the DOM worktree root:

```bash
python3 test-vectors/scriptless/share-pop/independent-v1/generate_reference.py --check
python3 test-vectors/scriptless/share-pop/independent-v1/compare_production.py --check
(cd test-vectors/scriptless/share-pop/independent-v1 && sha256sum --check MANIFEST.sha256)
(cd test-vectors/scriptless/share-pop/independent-v1 && sha256sum --check POSTCOMPARISON-MANIFEST.sha256)
cargo run --locked --manifest-path test-vectors/scriptless/share-pop/independent-v1/production-probe/Cargo.toml -- \
  test-vectors/scriptless/share-pop/independent-v1/production_trace_v1.json
cargo test -p dom-adaptor share_pop --lib
cargo fmt --manifest-path test-vectors/scriptless/share-pop/independent-v1/production-probe/Cargo.toml -- --check
git diff --check
```

The detached NAR-DC verification command also exited zero:

```bash
minisign -Vm /home/leonardov/dom-scriptless-dev/dom-contracts/docs/specifications/normative/NAR-DC-P1-001-omnibus-gap-closure.en.md \
  -x /home/leonardov/dom-scriptless-dev/dom-contracts/docs/specifications/normative/NAR-DC-P1-001-omnibus-gap-closure.en.md.minisig \
  -P RWTwnDDKlXoZdG3obVRiLPfVRHr17E0Fj2GN8IZ2rBkipRZvIIW6PLJ3
```

Final command results and the post-comparison commit are recorded in the
handoff accompanying this report.

## STOP disposition

This evidence set must stop at **AUTHORITY_INPUT_CONFLICT**. Production is
consistent with the verified higher-precedence assignment, but the frozen
independent expected outputs are not. They cannot be corrected after
comparison and still be called independent.

Required closure is a fresh independent implementation by an unexposed
reviewer or environment that receives NAR-DC-P1-001 before implementation,
freezes new outputs before production inspection, and reproduces all
NAR-DC-defined intermediates and negative cases. Separately, the signed record
should be imported into the DOM normative source directory so future evidence
runs cannot silently select only the older source chain.
