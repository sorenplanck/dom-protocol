# Independent Share PoP V1 — Post-Freeze Production Comparison

## Verdict

**FULL MATCH.** The independently frozen Share PoP V1 reference matches the
production implementation at published commit
`67fe11c441c2b7801b6f70809ab58caa4804c22a` for every requested byte-bearing
intermediate, the response and proof, the verification equation, and the
tested rejection policies. The first differing byte is `none`; discrepancies
are `0`.

This conclusion is scoped to the fixed deterministic evidence case and the
exact commits recorded below. It does not turn the deterministic nonce into a
production API, approve production or mainnet use, or replace separate
zeroization, side-channel, fuzzing, audit, and release gates.

## Chronology and contamination control

The reference was developed on branch `evidence/share-pop-independent-v2`
from base `a37f0bbeeb7c0ee5579154ae64476e8374d1dabb`, which intentionally predates
the production G1A implementation.

The implementation, all intermediates, positive verification, negative
results, provenance, and SHA-256 manifest were frozen before any production or
prior independent material was inspected:

| Freeze property | Exact value |
|---|---|
| Precomparison commit | `1b76d18a8ac6499a768d363d9dc784eb1ef74b1f` |
| Precomparison tree | `45be5ea99c3172c74ed59974eb6ddb1b1e51d9ad` |
| Commit time | `2026-08-05T08:43:34-03:00` |
| Commit subject | `evidence: freeze independent Share PoP V1 vector` |
| `SHA256SUMS` SHA-256 | `bdb8db408f13dadc3c6b781a73b1a7fb569d2afa2c4de5775ed6ed9798a50801` |

The freeze identifier, time, tree, and manifest hash were sent to the
coordinator before opening production. The worktree was clean at that point.
The frozen files were not changed during comparison.

Post-freeze, the review inspected the specified production source and test.
Historical comparison material was also opened only after the independent
commit existed, to confirm a non-mutating external-probe pattern; it supplied
no bytes to the already frozen reference.

## Authorities and implementation stacks

The independent side used signed NAR-DC-P1-001 sections 5.1 through 5.5,
authoritative `H_tag`, the secp256k1 order, and the assigned fixed inputs. Its
runtime stack was:

- CPython 3.12.3;
- standard-library `_blake2` through `hashlib.blake2b(digest_size=32)`;
- cryptography 41.0.7; and
- OpenSSL 3.0.13 secp256k1 named-curve operations.

The production side was pinned and checked as follows:

| Production property | Exact value |
|---|---|
| Commit | `67fe11c441c2b7801b6f70809ab58caa4804c22a` |
| Tree | `4fd42e057d20dd55853f7829778b9fb3f89921d6` |
| Commit time | `2026-08-05T06:12:18-03:00` |
| `Cargo.lock` SHA-256 | `f8045a5847f972b2c3b4d305a5acedb5c308c2d714bd1b5b119d912d5dc6bbd5` |
| `share_pop.rs` blob-content SHA-256 | `58c8f997600062d86bf1a074305f9f5b2fab84ce080a645cd0ffcb5357609f1b` |
| `dom-crypto/scriptless.rs` blob-content SHA-256 | `fdb2e904f58a847b5718d70e0aef3a1550eb54055d2cd07c7d4753e66d30113e` |
| `dom-crypto/hash.rs` blob-content SHA-256 | `1d2afbf4c74ec8c015e026e4fca790edcdd198f6cf0d07c150bc3a9ab218ed71` |
| Rust compiler | `rustc 1.96.1 (31fca3adb 2026-06-26)`, LLVM 22.1.2 |
| Cargo | `cargo 1.96.1 (356927216 2026-06-26)` |

The exact production worktree reported the required commit and no tracked
changes before or after the checks. No production file was edited.

## Comparison method

The comparison used three mutually reinforcing checks:

1. The production source at the published commit was reviewed byte boundary by
   byte boundary. Tags and constants are at `share_pop.rs` lines 13–18; the
   statement serializer is at lines 78–88; strict statement parsing is at
   lines 102–140; the proof codec is at lines 182–211; proof generation and
   verification are at lines 225–278; and challenge construction is at lines
   280–309.
2. The production crate was rebuilt using its own locked dependency graph and
   the exact crate-local deterministic test was run. Lines 353–375 use exactly
   the assigned inputs, construct the real `SharePoPStatementV1`, invoke the
   private `prove_with_nonce` with scalar 9, and call the high-level production
   verifier. The test passed. Its statement/proof round trips and byte
   mutations at lines 376–415 also passed.
3. The post-freeze Rust probe in `production-probe/` was linked to the freshly
   built production `dom-adaptor`, `dom-crypto`, and `zeroize` artifacts. It
   invoked production point derivation, tagged hash, wide reduction,
   multiply-add response construction, proof parser/serializer, and scalar
   response verifier. Every produced byte slice was compared with `assert_eq!`
   against the frozen binaries. It reported
   `matched_checks=24`, `discrepancies=0`.

The trusted-chain fixture constructor is deliberately absent from downstream
production dependency resolution. Consequently, the external probe lays out
the statement using the exact inspected production offsets, while the
crate-local test independently executes the actual production statement
constructor and private deterministic prover. This preserves the production
API boundary without patching or instrumenting production.

## Every byte-bearing intermediate

Each row below is a complete slice comparison, not a digest-only comparison.
The SHA-256 column identifies the exact common bytes after the production
probe asserted equality. Full lowercase hexadecimal is preserved in
`vector.json`; the named binary is the byte-exact artifact.

| Field | Length | Common SHA-256 | Result |
|---|---:|---|---|
| `statement.bin` | 202 | `060e30b84fc181856039742c52270cee2b425ba1e39dffeef21f07506669645f` | MATCH |
| `share-point.bin` | 33 | `a2039429ca2d2f2bcc0725a1682aeeeb3ac1b8e77248c34fa57fcdef29d01c53` | MATCH |
| `nonce-commitment.bin` | 33 | `23dc97287c16143cb43a0799e67cd97a862013643287374fe91c62c6dccd9757` | MATCH |
| `context-preimage.bin` | 231 | `b1e452bb525a99df64eb6697e35115f875a91e142933e6eb10a6b7e85e3bfb8b` | MATCH |
| `context-digest.bin` | 32 | `7f87e98119401ea3515fb5c9abf5a5a6290fd7bf6ade3ab7270a7445d0c08f84` | MATCH |
| `challenge-input.bin` | 102 | `809b330e00445549a9960c8aec22e2c8e7483035eb0de61ffc1c10b18992dd2d` | MATCH |
| `challenge-counter-u32-le.bin` | 4 | `df3f619804a92fdb4057192dc43dd748ea778adc52bc498ce80524c014b81119` | MATCH |
| `challenge-d0-data.bin` | 103 | `9866d5baeae39e5b5dbcae76ac98a67ea796853757c22933f0a746d974af2121` | MATCH |
| `challenge-d0-preimage.bin` | 142 | `ca78402e10a67c3dc589007085983b8118619273b82cbf34e2ff8c67fd6c9f32` | MATCH |
| `challenge-d0.bin` | 32 | `8807a835b233b04c9955ef35fda0062aaf803d37f4242a9bf29cc6adb8b884ec` | MATCH |
| `challenge-d1-data.bin` | 103 | `9e767c746aa2cc6096edd685fcf2f9d7e4a7f4f5bc8a618f87302a1b29ba74fd` | MATCH |
| `challenge-d1-preimage.bin` | 142 | `b978013414f788185d0bb4db7ec2a111db4557df1d1865698a6b248f941107f8` | MATCH |
| `challenge-d1.bin` | 32 | `9e1ac177f11499c4fe225137aca75bd530f585f3a4401b735216b1898635e5a2` | MATCH |
| `challenge-wide.bin` | 64 | `5309a5d92a43aa2986cd6f536bf4b8c2182df70fcdda9434f81c982b04c1727e` | MATCH |
| `challenge-scalar.bin` | 32 | `0ad2c4758846520f0d6a0d442f9b0a187c8b573ae23ad4f878c2181e164d271c` | MATCH |
| `response.bin` | 32 | `316937054ff9ab52ea794b39f04bbb80d7449170555cba2c1d58c6f325a872db` | MATCH |
| `proof.bin` | 65 | `5804a283a3ba0e3b5771ea511ebdcad17683a13e1706dba78ebf3e86b74e57f8` | MATCH |

The decisive compact values are:

```text
R_i = 025cbdf0646e5db4eaa398f365f2ea7a0e3d419b7e0330e39ce92bddedcac4f9bc
A   = 03acd484e2f0c7f65309ad178a9f559abde09796974c57e714c35f110dfc27ccbe
context_digest = cb3ed7cb1a6cc24102d364176505b7d7d89b0ddcee68835f3818f7b1cded9024
counter_u32_le = 00000000
d0 = 1301574d62c498c37ce7d8feeb90222c39a9030040fc97e0160ac27e677ec475
d1 = 460f79fe0c516828dd4f4b3c27be75fee38efe7f39a5a21132e6eb0322f5f260
c  = 2c3c5b20580ef31ee3910062250129aced05fa8ac160f1cfc7d4e70265f78664
z  = 35a67de26868a5d838f702af030823bbc07afce49a5dfc72b6fff283f98e6b84
proof = 03acd484e2f0c7f65309ad178a9f559abde09796974c57e714c35f110dfc27ccbe35a67de26868a5d838f702af030823bbc07afce49a5dfc72b6fff283f98e6b84
```

Production and reference both accepted the proof. Both verification forms
agreed:

```text
zG = A + cR_i
zG compressed = A + cR_i compressed
              = 02ec5a4a067f8ea4c7add372fd8a9f4c5209bea05a00ee082f89bf77805cb89661
zG + (q-c)R_i = A
```

## Negative and codec comparison

The frozen independent implementation rejected all 31 targeted negative
cases. These cover exact lengths, magic/version, zero and wrong fixed fields,
roster/index/role mismatches, malformed and alternate valid points, malformed
and alternate valid nonce commitments, zero/wrong/noncanonical responses,
duplicates, and ordering.

It also flipped each of eight individual bits at every byte offset:

| Artifact | Mutations | Independent | Production profile probe |
|---|---:|---:|---:|
| 202-byte statement | 1,616 | 1,616 rejected | 1,616 rejected |
| 65-byte proof | 520 | 520 rejected | 520 rejected |
| Total | 2,136 | 2,136 rejected | 2,136 rejected |

The exact production crate-local test independently rejected its one-bit-per-
byte statement and proof sweeps. The production proof codec accepted a
32-byte zero response as structurally canonical and still rejected it under
the equation for this proof. It rejected a response equal to the secp256k1
group order, matching NAR-DC-P1-001 and the independent implementation.

## Reproduction

The independent artifacts remain reproducible without production:

```sh
python3 generate_share_pop_v1.py check
sha256sum -c SHA256SUMS
```

After separately placing the published production commit in the recorded
sibling worktree, the exact backend comparison is:

```sh
production-probe/run_exact_backend_probe.sh
```

The wrapper refuses a wrong commit or tracked production changes, runs the
locked exact production unit test, links the external probe to those freshly
built artifacts, and executes all comparisons. The captured decisive output
is `production-probe-output.txt`.

## Discrepancies and repository impact

- Byte discrepancies: **none**.
- Behavioral discrepancies in the tested positive/negative profile: **none**.
- Frozen-reference changes after production inspection: **none**.
- Production edits: **none**.
- Remote operations: **none**.
- Official-repository edits: **none**.
